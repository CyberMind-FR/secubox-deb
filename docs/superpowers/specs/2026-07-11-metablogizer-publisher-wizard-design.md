<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer Publisher Wizard — Design

**Date:** 2026-07-11
**Status:** Approved (design), pending spec review
**Author:** Claude (brainstormed with Gérald Kerma)

## Goal

A guided, multi-step **Publish** wizard inside `secubox-metablogizer` that takes a
static site from raw content to a fully-reachable HTTPS site: upload → version in
gitea → route through the WAF → provision a certificate → and hand back a portable
backup file. It replaces today's broken, half-manual publish path (the reason
`zem.gk2.secubox.in` answers a bare `421`).

## Context — what exists today and what is broken

The publish ecosystem spans several modules, all serving as user `secubox`:

- **`secubox-metablogizer`** — manages static "sites" served by host nginx on
  `BASE_PORT 8900`, hostname-multiplexed. Already has: per-site docroot, single-file
  upload (`POST /site/{name}/upload`), gitea versioning (`git_commit_push` in
  `api/webhook.py`), nginx vhost regeneration (`regenerate_nginx_config`), and a
  route-sync (`sync_mitmproxy_routes`).
- **`secubox-publish`** — an orchestrator *hub* (`_call_module`) fronting
  metablogizer / droplet / streamlit / streamforge, with its own webui (`/publish/`).
- **`secubox-droplet`** — drag-and-drop static uploads.

Three concrete, verified defects make publishing fail:

1. **Route target drift (the `421`).** `metablogizer.sync_mitmproxy_routes` writes
   `/srv/mitmproxy/haproxy-routes.json` **inside the retired mitmproxy LXC**
   (backend `10.100.0.1:8900`). The live WAF is Go **sbxwaf**
   (`/usr/local/bin/sbxwaf-shadow`), which reads the **host** file
   `/etc/secubox/waf/haproxy-routes.json` (backend `192.168.1.200:8900`). Anything
   metablogizer "publishes" lands in the dead file → sbxwaf has no route → `421`.
2. **Unprivileged config mutation.** `secubox-publish` writes
   `/etc/haproxy/haproxy.cfg` + `/etc/nginx/...` and runs `systemctl reload haproxy`
   **directly as `secubox`** (`api/main.py:849–882`). Those paths are `root:root`;
   the reload needs root. Every publish that touches routing fails on permission.
3. **Config ownership.** `/etc/secubox/droplet.toml` shipped `root:root 0600`; the
   `secubox`-run daemon can't read/write it → `PermissionError`.
   (Already hot-fixed live to `secubox:secubox 0640`; the source fix is folded in.)

### Privilege model (the governing constraint)

`secubox` has NOPASSWD sudo **only** for a curated set of root helpers
(`streamlitctl`, `appstorectl`, `nextcloudctl`, `macroctl`, `nft list`, `lxc-*`, and
nginx reload via the `secubox-nginx` sudoers drop-in). There is **no** path for
`haproxyctl`, `certbot`, or the sbxwaf route file. The correct pattern in this
codebase is: privileged work goes through a **dedicated root `*ctl` helper** with a
tight sudoers entry — never direct root-file writes from the FastAPI process. The
wizard follows this pattern; fixing defect #2 means routing all privileged steps
through such a helper.

## Architecture

The wizard lives in **metablogizer** and orchestrates five steps. All privileged
operations go through **one new root helper, `secubox-publishctl`**, invoked with
`sudo -n` and gated by a tight `/etc/sudoers.d/secubox-publish-wizard` entry. The
FastAPI process (user `secubox`) never writes root-owned config directly.

```
 secubox-metablogizer (FastAPI, user=secubox)
   └── api/routers/publish.py     ← wizard orchestration + backup endpoints
         ├── api/publish/content.py   safe zip/html extraction → docroot   (secubox)
         ├── api/webhook.py           gitea commit+push+tag (existing)      (secubox)
         ├── api/publish/routing.py   builds route requests, calls ↓
         ├── api/publish/certs.py     wildcard-detect / cert requests, ↓
         └── api/publish/backup.py    .sbxsite git-bundle + manifest        (secubox)
                     │  sudo -n secubox-publishctl <verb> …
                     ▼
 /usr/sbin/secubox-publishctl  (root helper, shipped by metablogizer)
   ├── vhost-add <domain>       haproxyctl vhost add  → mitmproxy_inspector (=sbxwaf)
   ├── waf-route <domain> <port> write /etc/secubox/waf/haproxy-routes.json + reload sbxwaf
   ├── vhost-del <domain>       haproxyctl vhost del + remove waf route + reload
   ├── cert <domain>            wildcard-noop for *.gk2 | certbot HTTP-01 for custom
   └── (validates every input; never eval; refuses non-vhost-shaped args)
```

Traffic path after publish (unchanged, correct chain):
`HAProxy (TLS, per-host ACL → mitmproxy_inspector backend = sbxwaf:8085)`
`→ sbxwaf (routes by Host via the host route file) → 192.168.1.200:8900 host nginx`
`→ site by hostname`. **No WAF bypass** — every published host is inspected.

## The five steps (data flow + interfaces)

### Step 1 — Content (`api/publish/content.py`)
Accept a `.zip` or a single `.html`/asset via `UploadFile`.
- `.zip` → extract into the site docroot with **path-traversal guarding** (reject
  entries whose resolved path escapes the docroot; reject absolute paths and `..`).
  A zip **replaces** the docroot content (fresh publish); the previous content is
  captured by the gitea commit in Step 2, so nothing is lost.
- single `.html` → written as `index.html`; other single asset → kept by name.
- Interface: `extract_upload(site_dir: Path, upload: UploadFile) -> ContentResult`
  (`{files: int, bytes: int, index_present: bool}`); raises `ContentError` on unsafe
  archive.

### Step 2 — Version (`api/webhook.py`, existing `git_commit_push`)
Ensure the site's gitea repo exists (create via the Gitea API if missing — one repo
per site; "fork" is read as *dedicated per-site versioned repo*), stage all, commit
with a wizard message, **tag** a version (`v<n>` monotonic), push. Gitea failure is
non-fatal (commit kept local) — same contract as today.
- Interface: `version_site(site_dir, message) -> {version, commit, pushed: bool}`.

### Step 3 — Route (`api/publish/routing.py` → `secubox-publishctl`)
- Regenerate host nginx (existing `regenerate_nginx_config`, `sudo -n` reload).
- `sudo -n secubox-publishctl vhost-add <domain>` → `haproxyctl vhost add` (ACL →
  `mitmproxy_inspector` backend, i.e. sbxwaf). Additive (drift-guard friendly).
- `sudo -n secubox-publishctl waf-route <domain> 8900` → merge
  `<domain>: ["192.168.1.200", 8900]` into `/etc/secubox/waf/haproxy-routes.json`,
  **validate JSON, then reload sbxwaf**; roll back the entry if reload fails.
- **This replaces `sync_mitmproxy_routes`** (dead LXC target) entirely.
- Interface: `publishctl("waf-route", domain, "8900")` etc. Helper returns JSON
  `{ok, detail}`; the router surfaces `route_ok` in the wizard result.

### Step 4 — Certificate (`api/publish/certs.py` → `secubox-publishctl cert`)
- `*.gk2.secubox.in` subdomain → the existing wildcard cert already fronts it →
  **no-op**, reported as `cert: wildcard`.
- Custom external domain → `certbot` HTTP-01 (webroot/standalone via the helper),
  assemble `fullchain+privkey` into `/etc/haproxy/certs/<domain>.pem`, reload haproxy.
  Failure is **non-fatal**: the site is up (Step 3 succeeded), status `cert: pending`
  with the certbot error surfaced.
- Interface: `publishctl("cert", domain) -> {mode: "wildcard"|"issued"|"pending", detail}`.

### Step 5 — Backup (`api/publish/backup.py`)
Produce a portable **`<name>.sbxsite`** the operator can download and re-import on any
SecuBox:
- `git bundle create` of the site's gitea repo (full history) → `repo.bundle`.
- `manifest.json`: `{name, domain, gitea_remote, version, vhost, waf_route,
  cert: {mode, ref}, base_port, created_at, checksums}`.
- Packed as a single `tar` (`repo.bundle` + `manifest.json`).
- **Restore** (`POST /publish/import`): unpack → `git clone repo.bundle` into a new
  site docroot → replay Steps 3–4 from the manifest (idempotent). Content survives
  even with the origin gitea offline.
- Interface: `export_site(name) -> Path(.sbxsite)`; `import_site(bundle_path) -> {name}`.

## Components (files)

Inside `packages/secubox-metablogizer`:

- `api/routers/publish.py` — **new** router: `POST /publish/wizard` (single call that
  runs steps 1–5 with per-step status), plus granular `POST /publish/{content,route,
  cert}`, `GET /publish/export/{name}`, `POST /publish/import`. Mounted under the
  existing app.
- `api/publish/content.py` — **new** — safe archive extraction.
- `api/publish/routing.py` — **new** — route request builders; the single call site
  for `secubox-publishctl vhost-add`/`waf-route`. Deletes/retires
  `sync_mitmproxy_routes`.
- `api/publish/certs.py` — **new** — wildcard detection + cert request.
- `api/publish/backup.py` — **new** — `.sbxsite` pack/unpack.
- `sbin/secubox-publishctl` — **new** root helper (bash, `set -euo pipefail`,
  strict input validation; a vhost/domain must match a strict regex; a port must be
  numeric; refuses anything else). Verbs: `vhost-add`, `vhost-del`, `waf-route`,
  `cert`.
- `debian/secubox-publish-wizard.sudoers` (installed to
  `/etc/sudoers.d/secubox-publish-wizard`, mode 0440) — `secubox ALL=(root) NOPASSWD:
  /usr/sbin/secubox-publishctl`.
- `debian/postinst` — install the helper + sudoers; **fix**: ensure any wizard config
  under `/etc/secubox` is `secubox:secubox` (mirror the droplet.toml class of fix).
- `www/metablogizer/index.html` — **new** wizard UI (hybrid-dark, 5-step stepper;
  reuses `sbx_token`, `/shared/sidebar.js`).

Inside `packages/secubox-publish`:

- `api/main.py` — **remove** the direct `/etc/haproxy` + `/etc/nginx` writes and
  `systemctl reload` (defect #2). The hub's publish action **delegates** to
  metablogizer's `POST /publish/wizard` via `_call_module`. The hub remains the
  cross-backend overview UI.

Inside `packages/secubox-droplet`:

- `debian/postinst` — create `/etc/secubox/droplet.toml` (if absent) `secubox:secubox
  0640` so the daemon can read/write it (source fix for defect #3).

## Error handling / rollback / security

- **Idempotent + rollback-aware (4R spirit).** Steps are ordered so a late failure
  never strands the box: content+version first (reversible), then route (validate
  nginx & sbxwaf JSON before reload; roll back the route entry on reload failure),
  then cert (non-fatal). The wizard returns a per-step status map; a failed step
  reports `ok:false` with detail and the site's partial state.
- **Never `waf_bypass`.** Every published host routes through the
  `mitmproxy_inspector`(=sbxwaf) backend. The helper refuses to write a route that
  points anywhere but the host nginx `8900` unless an explicit reviewed backend is
  given.
- **Input safety.** `secubox-publishctl` validates every argument (domain regex,
  numeric port) and never `eval`s. Zip extraction is path-traversal-guarded.
- **Least privilege.** The sudoers entry grants exactly one binary
  (`secubox-publishctl`); the FastAPI process holds no other new privilege.
- **Config ownership.** All module config under `/etc/secubox` owned
  `secubox:secubox` (parent stays `0755`, secrets `0700`) — no root-owned files a
  secubox daemon must write.

## Testing

- **Unit (pytest, per package):**
  - `content.py`: rejects `../`/absolute/zip-slip entries; accepts a clean zip;
    single-html → index.html.
  - `routing.py`: builds the correct `waf-route` args; the route-file merge writes
    the **host** file with backend `192.168.1.200:8900` and is additive/idempotent.
  - `certs.py`: `*.gk2` → `wildcard` (no certbot call); custom → `issued`/`pending`.
  - `backup.py`: `export → import` round-trip recreates docroot + manifest; a git
    bundle clones without the origin.
  - `secubox-publishctl`: argument validation (rejects `a b; rm`, non-numeric port,
    non-vhost domain).
- **Live (gk2):** publish a throwaway `zem`-style site end-to-end → expect **200,
  not 421** through `https://<name>.gk2.secubox.in/`; download the `.sbxsite`, import
  it under a second name, verify it serves. Clean up both.

## Global constraints (copied verbatim from project rules)

- **Never `waf_bypass`; nftables DEFAULT DROP.** All traffic through
  mitmproxy/sbxwaf.
- **JWT on every endpoint** via `Depends(require_jwt)`; Unix socket only.
- **`/etc/secubox` parent `0755`, secrets `0700`, module config `secubox:secubox`.**
- **No root-owned config a `secubox` daemon must write.**
- **Privileged ops via a dedicated `*ctl` root helper + tight sudoers — never direct
  root-file writes from FastAPI.**
- **sbxwaf route file:** `/etc/secubox/waf/haproxy-routes.json`, backend
  `192.168.1.200:8900`, hot-reload after write.
- **No mass daemon restart on gk2.** Reload only the touched service (sbxwaf, nginx,
  haproxy) with validate-before-reload.
- **No Claude Code references in commits/PRs.**

## Out of scope (YAGNI / follow-ups)

- Streamlit/streamforge publish paths (the hub keeps calling them unchanged).
- Multi-node federation of published sites (mesh/annuaire) — the existing exposure
  engine already handles federation; the wizard is single-node reach.
- Rewriting the `secubox-publish` UI beyond removing the broken provisioning writes
  and delegating to the wizard.
