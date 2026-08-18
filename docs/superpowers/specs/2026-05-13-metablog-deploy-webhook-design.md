<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer Deploy Webhook — Design

**Date:** 2026-05-13
**Author:** Gandalf (CyberMind), with Claude
**Status:** Draft for approval
**Issue:** [#113](https://github.com/CyberMind-FR/secubox-deb/issues/113) (sub-project E of [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49))
**Depends on:**
- [#97](https://github.com/CyberMind-FR/secubox-deb/pull/97) (sub-B, merged) — 166 metablog-* repos ingested into Gitea, each site dir has a `.git` cloned from Gitea
- [#102](https://github.com/CyberMind-FR/secubox-deb/pull/102) (sub-C, merged) — `site.json` schema + `_load_site_json()` enrichment
- [#112](https://github.com/CyberMind-FR/secubox-deb/pull/112) (sub-C/D/E support, merged) — `load_sites()` cache with `_invalidate_sites_cache()`

## Context

After sub-B, every `metablog-<name>` site directory on the MOCHAbin contains a `.git` directory cloned from `https://gitea.gk2.secubox.in/gandalf/metablog-<name>`. Today, a `git push` from the operator's workstation lands in Gitea, but the live site at `<name>.gk2.secubox.in` keeps serving the pre-push content until someone SSHes in and runs `git pull` or `scripts/metablog-ingest.sh`.

Sub-E closes that gap.

## Goal

A push to the default branch of any `metablog-*` repo on Gitea updates the live site at `<name>.gk2.secubox.in` within seconds, with no manual step on the MOCHAbin.

## Non-goals

- **Streamlit** repos. Sub-F already has `streamlitctl --from-gitea`; auto-deploying Streamlit is a separate iteration.
- **Tag-based releases**. We deploy whatever is on the default branch. Tag pushes are ignored. The dashboard's "Version" column already shows `git describe` output, which picks up tags automatically.
- **Rollback UI**. The `git reset --hard` is reversible from the operator's workstation by pushing a revert commit; in-UI rollback is out of MVP.
- **Cron safety net**. We rely on Gitea redelivering failed webhooks. If a webhook permanently fails, the operator notices in the dashboard's "Updated" column drifting away and re-runs `scripts/metablog-ingest.sh` manually.
- **Auto-clone unknown repos**. If a webhook fires for a `metablog-newthing` site that doesn't exist on disk, we return `200 + skip=unknown-site`. Fresh repos go through `scripts/metablog-ingest.sh`.
- **Per-PR previews**, **drafts**, or other branch-based deploys. Only the default branch.

## Decisions taken in brainstorming

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Trigger | Gitea webhook → HTTP POST | Responsive (~seconds); minimal infrastructure |
| Events | Default-branch push only | YAGNI for tags/branches; dashboard already reflects tags via `git describe` |
| Auth | HMAC-SHA256 via `X-Gitea-Signature` | Standard, resists LAN spoofing, secret stays out of URLs |
| Deploy strategy | `git fetch + git reset --hard` in place | Site dir is already a clone; no extra disk, simple |
| Scope | metablog-* only (no Streamlit) | Streamlit has its own deploy path; separate concern |
| Webhook registration | Per-repo via Gitea API in an idempotent shell script | 166 repos = manual UI registration is unworkable; org-wide webhooks aren't available since `gandalf` is a user, not an org |

## Architecture

### Component 1 — Webhook endpoint

New module `packages/secubox-metablogizer/api/webhook.py`. Single public function used by `main.py`:

```python
async def handle_webhook(request: Request) -> dict: ...
```

Signature flow (called from `@app.post("/webhook")` in `main.py`):

1. Read raw body bytes.
2. Read `X-Gitea-Signature` header.
3. Compute `hmac.new(secret, body, sha256).hexdigest()`. Constant-time compare via `hmac.compare_digest`.
4. On mismatch: `raise HTTPException(401)`. No body, no detail.
5. Parse body JSON. On malformed: 400.
6. Extract `payload["repository"]["name"]` and `payload["ref"]`.
7. If `name` doesn't start with `metablog-`: 200 + `{"skip": "non-metablog", "name": name}`.
8. Compute default branch ref: `payload["repository"]["default_branch"]`. If `ref != f"refs/heads/{default}"`: 200 + `{"skip": "non-default-ref", "ref": ref}`.
9. Strip prefix → `site_name = name[len("metablog-"):]`.
10. Resolve `site_dir = SITES_ROOT / site_name`.
11. If `site_dir / ".git"` not present: 200 + `{"skip": "no-git-dir", "site": site_name}`.
12. Acquire per-site lock (see Component 3), then call `git_pull(site_dir, default_branch)` (Component 4).
13. Compare new `site.json:domain` against old (read before/after via `_load_site_json`). If different: reload nginx by calling existing `regenerate_nginx_config()` helper.
14. `_invalidate_sites_cache()` so the dashboard sees the new version immediately.
15. Record entry in deploy ring buffer (Component 5).
16. Return 200 + `{"deployed": site_name, "from": old_sha, "to": new_sha, "duration_ms": ...}`.

### Component 2 — Secret loader

`packages/secubox-metablogizer/api/webhook.py:load_secret()` reads `/etc/secubox/metablogizer-webhook.secret` (chmod 600, owner `secubox`). The file is created on the host post-install by the operator running:

```bash
sudo install -o secubox -g secubox -m 600 /dev/stdin /etc/secubox/metablogizer-webhook.secret <<< "$(openssl rand -hex 32)"
```

The webhook module caches the secret in module-level state at first read (no per-request file I/O). Missing or unreadable secret file → `HTTPException(503, "webhook secret not configured")`. Operator sees this in browser/Gitea webhook log and provisions the file.

### Component 3 — Per-site async lock

```python
_site_locks: dict[str, asyncio.Lock] = {}
_locks_master = asyncio.Lock()

async def _site_lock(name: str) -> asyncio.Lock:
    async with _locks_master:
        if name not in _site_locks:
            _site_locks[name] = asyncio.Lock()
        return _site_locks[name]
```

Two rapid pushes to the same repo serialize; pushes to different repos run concurrently. The master lock around dict access avoids the "two requests both create a fresh lock" race.

### Component 4 — Git helper

```python
def git_pull(site_dir: Path, branch: str) -> tuple[str, str]:
    """Returns (old_sha, new_sha). Raises subprocess.TimeoutExpired or RuntimeError on git failure."""
    old = subprocess.run(["git", "-C", str(site_dir), "rev-parse", "HEAD"],
                        capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    subprocess.run(["git", "-C", str(site_dir), "fetch", "--quiet", "origin", branch],
                   timeout=60, check=True)
    subprocess.run(["git", "-C", str(site_dir), "reset", "--hard", f"origin/{branch}"],
                   timeout=10, check=True)
    new = subprocess.run(["git", "-C", str(site_dir), "rev-parse", "HEAD"],
                        capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    return old, new
```

Synchronous because uvicorn's single worker is async — wrapping each git op in `loop.run_in_executor` keeps the event loop responsive. The webhook handler calls this via `await loop.run_in_executor(None, git_pull, site_dir, branch)`.

### Component 5 — Deploy ring buffer

In-memory list, capped at 50 entries, FIFO eviction:

```python
_deploys: list[dict] = []
_DEPLOYS_MAX = 50

def _record_deploy(entry: dict) -> None:
    _deploys.append(entry)
    if len(_deploys) > _DEPLOYS_MAX:
        _deploys.pop(0)
```

Each entry: `{site, from, to, duration_ms, timestamp, source: "webhook"|"manual"}`. Exposed via:

```python
@app.get("/deploys", dependencies=[Depends(require_jwt)])
async def list_deploys():
    return {"deploys": list(reversed(_deploys)), "count": len(_deploys)}
```

(Reversed so most recent first.) Not persisted — restart clears the buffer. The journalctl logs are the durable record.

### Component 6 — Webhook installer script

`scripts/metablog-webhook-install.sh`:

```
Usage:
  scripts/metablog-webhook-install.sh \
    --gitea-url https://gitea.gk2.secubox.in \
    --gitea-token <admin-token> \
    --webhook-url https://admin.gk2.secubox.in/api/v1/metablogizer/webhook \
    --secret-file /etc/secubox/metablogizer-webhook.secret \
    [--owner gandalf] \
    [--dry-run]
```

Flow:
1. Read secret from `--secret-file` (or stdin if `-`).
2. `GET /api/v1/users/<owner>/repos?limit=50&page=N` → loop pages → collect all repo names starting with `metablog-`.
3. For each repo:
   - `GET /api/v1/repos/<owner>/<name>/hooks` — look for existing hook with target URL == `--webhook-url`.
   - If found and config matches: print `skip <name> already-hooked`.
   - Otherwise: `POST /api/v1/repos/<owner>/<name>/hooks` with payload:
     ```json
     {
       "type": "gitea",
       "config": {"url": "...", "content_type": "json", "secret": "..."},
       "events": ["push"],
       "active": true
     }
     ```
4. Summary line: `installed=N skipped=M failed=K`.

Companion `scripts/metablog-webhook-uninstall.sh` does `DELETE /api/v1/repos/<owner>/<name>/hooks/<id>` for any hook matching the webhook URL.

Both scripts are idempotent. The install can be re-run after adding new sites.

### Component 7 — HAProxy / nginx routing

The endpoint is reachable at `https://admin.gk2.secubox.in/api/v1/metablogizer/webhook` — same routing as the rest of the metablogizer API (nginx `/etc/nginx/secubox-routes.d/metablogizer.conf` proxies `/api/v1/metablogizer/` to the unix socket).

No new routing changes. Gitea (10.100.0.40 in LXC) reaches `admin.gk2.secubox.in` through HAProxy → mitmproxy → nginx → socket. The WAF in mitmproxy must allow the POST — which it does by default for known SecuBox API paths.

## File-level changes

| Action | Path | Purpose |
|--------|------|---------|
| Create | `packages/secubox-metablogizer/api/webhook.py` | HMAC verify, git pull, lock pool, ring buffer |
| Modify | `packages/secubox-metablogizer/api/main.py` | Mount `POST /webhook` and `GET /deploys`, wire to webhook.py |
| Create | `packages/secubox-metablogizer/api/tests/test_webhook.py` | HMAC, ref filter, repo filter, lock semantics |
| Create | `scripts/metablog-webhook-install.sh` | Gitea API registration (idempotent) |
| Create | `scripts/metablog-webhook-uninstall.sh` | Reverse |
| Create | `tests/scripts/test-metablog-webhook.sh` | Bash smoke (3 gates: GET=405, POST without sig=401, POST with sig=200) |
| Modify | `packages/secubox-metablogizer/README.md` | Document webhook + secret provisioning |
| Modify | `.claude/WIP.md`, `.claude/HISTORY.md` | Session 166 entry |

## Validation gate

Done when:

1. `bash tests/scripts/test-metablog-webhook.sh` reports all 3 gates green on a dev host (uses the local FastAPI app + a test site).
2. `PYTHONPATH=api python3 -m pytest api/tests/test_webhook.py -v` → all tests pass.
3. On MOCHAbin: `bash scripts/metablog-webhook-install.sh --dry-run` lists the expected 166 repos (or close — count varies as repos are added).
4. After non-dry install: a probe push to one test repo (`metablog-zkp`) triggers a deploy within 5 seconds. Verified via:
   - `journalctl -u secubox-metablogizer | grep '^deploy '`
   - `GET /api/v1/metablogizer/deploys` shows the entry
   - The site's "Updated" column in the dashboard refreshes to a recent timestamp

## Error handling

| Failure | Detection | Response |
|---------|-----------|----------|
| Missing `X-Gitea-Signature` header | Header read | 401, no body |
| HMAC mismatch | `compare_digest` | 401, no body |
| Malformed JSON | `json.loads` | 400, `{"error": "invalid-json"}` |
| Missing `repository.name` or `ref` | dict lookup | 400, `{"error": "malformed-payload"}` |
| Repo name doesn't match `metablog-*` | substring check | 200, `{"skip": "non-metablog"}` |
| Ref isn't the default branch | string compare | 200, `{"skip": "non-default-ref"}` |
| Site dir doesn't exist | `Path.exists` | 200, `{"skip": "unknown-site"}` |
| No `.git/` in site dir | `Path.exists` | 200, `{"skip": "no-git-dir"}` |
| `git fetch` times out (60s) | `subprocess.TimeoutExpired` | 504, `{"error": "git-timeout"}` + log |
| `git fetch` non-zero exit | `subprocess.CalledProcessError` | 500, `{"error": "git-failed", "stderr": …}` + log |
| Secret file missing | First read | 503, `{"error": "secret-not-configured"}` |
| Concurrent push same site | per-site `asyncio.Lock` | Serialized — second push waits, then runs |

## Testing

### pytest (`api/tests/test_webhook.py`)

- `test_hmac_valid` — handler accepts a payload signed with the correct secret
- `test_hmac_invalid` — wrong signature → 401
- `test_hmac_missing_header` → 401
- `test_repo_filter_skips_streamlit` — `streamlit-foo` → 200 skip
- `test_repo_filter_skips_unrelated` — `other-repo` → 200 skip
- `test_ref_filter_skips_tag` — `refs/tags/v1.0.0` → 200 skip
- `test_unknown_site_skips` — `metablog-doesnotexist` → 200 skip
- `test_lock_serializes_concurrent_same_site` — two concurrent calls on same site; assert git_pull called sequentially (mock the git fn, count entries, verify ordering)
- `test_lock_parallel_different_sites` — two concurrent calls on different sites can overlap (mock + barrier)

The git ops themselves are mocked. The unit under test is the dispatcher + lock + filter logic — not git.

### Bash smoke (`tests/scripts/test-metablog-webhook.sh`)

Three gates against a running service (the dev box or MOCHAbin):

1. `curl https://admin.gk2.secubox.in/api/v1/metablogizer/webhook` (GET) → 405 (endpoint exists, POST-only)
2. `curl -X POST .../webhook -d '{}'` (no signature) → 401
3. `curl -X POST .../webhook -H "X-Gitea-Signature: $(echo -n payload | openssl dgst -sha256 -hmac $SECRET)" -d "$payload"` → 200 with `{"skip": "unknown-site"}` (we use a fake repo name so we don't actually deploy anything in the smoke)

Gate 3 verifies the full HMAC chain works without touching real sites.

## Open questions

None blocking. The deferred items (Streamlit auto-deploy, rollback UI, cron safety net, deploys-page UI surface) are listed as non-goals.

## Licensing

CMSD-1.0. New `webhook.py` carries the standard SecuBox SPDX header. Scripts get the `set -euo pipefail` + SPDX comment pattern.
