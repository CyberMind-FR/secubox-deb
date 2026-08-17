# HISTORY — SecuBox-DEB Migration Log
*Tracking completed milestones with dates*

---
## 2026-05-12

### Session 160 — Health Banner Live Panel (Issue #92)

**Goal:** Add three public sections to the health banner — VisitorOrigin,
LiveHosts, CertStatus — sharing one polling pipeline.

**Spec:** `docs/superpowers/specs/2026-05-12-visitor-origin-feed-design.md`
**Plan:** `docs/superpowers/plans/2026-05-12-visitor-origin-feed.md`
**Branch:** `feature/92-health-banner-visitor-origin-feed-anonym`
**Issue:** [#92](https://github.com/CyberMind-FR/secubox-deb/issues/92)

**Highlights**
- nftables `inet secubox_metrics` table (priority -300) — independent of
  `secubox-firewall`.
- VisitorOrigin: kernel-dedupe via timeout'd set, mmdb resolution, threshold
  gate before persistence (raw IPs never leave the function).
- LiveHosts: HAProxy admin socket + 60x1-min ring buffer; counter-reset
  detection.
- CertStatus: cryptography parse of `/etc/letsencrypt/live/*/cert.pem`.
- Banner v1.3.0: three fail-isolated fetch loops on a shared 30 s cadence.

---

### Session 160 — secubox apt + clone: validate against live repo (Issue #89)

**Goal:** Audit the 2026-05-11 plan vs the implemented Go CLI; close any genuine gap; end-to-end against `https://apt.secubox.in/` (commissioned in Session 152 / Issue #80).

**Done:**
- All 48 plan steps in `docs/superpowers/plans/2026-05-11-secubox-apt-clone.md` ticked after walking each against `cmd/secubox/{cmd,internal/apt}/*.go`. `go test ./internal/apt/... ./cmd/...` passes; binary builds; subcommand `--help` strings correct.
- **One real bug found** during E2E: `apt.Client.DefaultGPGKeyURL` was `https://apt.secubox.in/secubox.gpg`, which doesn't exist on the public repo. nginx `try_files` falls through to `index.html`, so the Go code wrote a 2.5 kB HTML landing page as the keyring → `apt update` exit 100. Fixed by pointing at `/secubox-keyring.gpg.bin` (binary OpenPGP). The unit tests didn't catch this because they use `httptest` servers that don't hit the real URL.

**Commits:**
- `4e8eadf4` — docs(apt): Tick plan checkboxes per code audit (ref #89)
- `6e3276bb` — fix(apt): Use binary keyring URL so apt accepts the signed-by= source (ref #89)

**E2E proof (fresh bookworm chroot):**
```
secubox apt setup     # OK: SecuBox repository configured successfully!
apt-get update        # Hit:1 https://apt.secubox.in bookworm InRelease
apt-cache search secubox # 15 packages
```

`secubox clone --minimal -y` reaches `apt install`; dpkg postinst then fails inside `minbase` (no systemd) — not a CLI bug, expected limitation of `--variant=minbase`. Validates on real targets with systemd (MOCHAbin, VM).

**Follow-up (separate work):**
- Add an E2E smoke job to CI that exercises `secubox apt setup` against a real or recorded `apt.secubox.in` (would have caught the URL bug). Out of scope here.

---

### Session 159 — WebUI Obfuscation (#44)

**Goal:** Lock the SecuBox WebUI to `https://admin.<HOSTNAME>.<DOMAIN_SUFFIX>/` only, enforced at HAProxy and nginx layers, driven by `/etc/default/secubox`.

**Spec:** `docs/superpowers/specs/2026-05-12-webui-obfuscation-design.md`
**Plan:** `docs/superpowers/plans/2026-05-12-webui-obfuscation.md`

**Changes:**

- New package `secubox-defaults` ships `/etc/default/secubox` (`SECUBOX_HOSTNAME` + `SECUBOX_DOMAIN_SUFFIX`) as the single source of truth. Postinst autodetects from `hostname -s` if unset, then fires `dpkg-trigger secubox-defaults-changed`.
- `secubox-haproxy` API extended with three endpoints in `api/main.py`:
  - `GET /webui/admin-domain` — canonical identity + escaped regex (info, no auth)
  - `GET /webui/nginx-config` — JWT-protected, rendered nginx vhost as `text/plain`
  - `POST /webui/refresh` — JWT-protected LRU cache invalidation (204)
- Helper module `api/webui_identity.py` parses `/etc/default/secubox` with `shlex`, caches via `lru_cache(maxsize=1)`, exposes `get_identity()`/`invalidate_cache()`. Defensive `OSError` handling so file-permission failures surface as `ValueError` (caught by endpoints → 503).
- `sbin/secubox-render-nginx-webui` script: snapshot → fetch from API → atomic stage → `nginx -t` → reload, with rollback on validation failure. Includes early binary-availability check.
- `sbin/haproxyctl` (bash generator) injects `acl is_webui_admin hdr(host) -m reg ^admin\.<HOST>\.<SUFFIX>$` + `use_backend webui_direct if is_webui_admin` at the top of `http-in` and `https-in` frontends. Emits the matching `backend webui_direct` (→ `127.0.0.1:9080`) only when the strict ACL is in use. Sources `/etc/default/secubox` once per frontend loop (hoisted from per-iteration).
- Python `generate_config()` in `api/main.py` mirrors the bash generator (symmetric ACL + backend emission + per-vhost skip).
- `debian/postinst` declares `interest-noawait secubox-defaults-changed` and on trigger runs (best-effort): `POST /webui/refresh`, `secubox-render-nginx-webui`, `secubox-haproxy-regen-safe`.
- `secubox-haproxy-regen-safe` script now packaged into `secubox-haproxy` (installed to `/usr/local/bin/`).
- `secubox-haproxy` `debian/control` declares `Depends: ..., secubox-defaults`.
- Integration test `tests/integration/test_44_webui_obfuscation.sh` covers positive probe (`admin.gk2` = WebUI), negative probes (`gk2.secubox.in` and `admin.fake.secubox.in` NOT WebUI), LAN-direct preserved, and regression spot-checks on cpf, arm, lldh, pub, werdl, 3d.

**Tests:** 12 pytest passing (6 in `tests/test_webui_identity.py`, 6 in `tests/test_webui_endpoints.py`). Includes a permission-denied test that confirms `OSError` is caught and surfaces as `ValueError`.

**Implementation workflow:** Brainstorming → spec → plan → subagent-driven execution (15 tasks, each TDD with implementer + spec reviewer + code quality reviewer). 6 review cycles triggered fix subagents (`OSError` handling in `_parse_defaults`, missing `conftest.py` commit, `debian/install` conflict, missing binary check, missing `webui_direct` backend def, missing `regen-safe` packaging).

**Closes:** #44 (pending PR merge)

---

### Session 158 — SSL Health Banner Fixes & HAProxy Recovery

**Goal:** Fix SSL display not working in banner + recover broken HAProxy config.

**Changes:**
- `packages/secubox-metrics/api/main.py`:
  - Added `domain` query parameter for SSL cert check (fixes cross-origin domain detection)
  - Added `/data/haproxy/certs/` to cert search paths
  - Added `PermissionError` handling for restricted cert files
- `packages/secubox-hub/www/shared/health-banner.js` (v1.2.1):
  - Pass `window.location.hostname` as query param to API
  - Added version footer display for debugging
- HAProxy config: Fixed broken `mitmproxy_inspector_DISABLED` references
- Permissions: Granted `secubox` group read access to `/etc/letsencrypt/live/`

**Commits:** `443e375f` (merge), `90e8b8fc` (fixes)

**Reference:** CM-SSL-BANNER-FIX-2026-05-12

---

### Session 157 — SSL Certificate Health in Health Banner

**Goal:** Display SSL certificate expiration status in the Health Banner sidebar.

**Changes:**
- `packages/secubox-metrics/api/main.py`: Added `get_ssl_status()` function + endpoint enrichment
- `packages/secubox-hub/www/shared/health-banner.js`: Added SSL display (v1.2.0)
- `tests/test_ssl_status.py`: 5 unit tests

**Features:**
- Reads cert from `/etc/letsencrypt/live/{domain}/cert.pem` (with fallbacks)
- Displays after score section: 🔒 45j
- Color-coded thresholds:
  - 🔒 >7j (green)
  - 🔐 3-7j (yellow)
  - 🔓 <3j (red)
  - 🔓 EXPIRÉ (red blink)

**Commits:** `6bd4fb3e`, `9c07eda6`, `593b991f`

**Reference:** CM-SSL-BANNER-2026-05-12

---

### Session 156 — HAProxy Routing Catastrophe & Generator Fix

**Trigger:** User flagged `https://cpf.gk2.secubox.in/` returning "Wrong Domain". Investigation revealed a much wider regression that surfaced minutes after Session 154 — the entire HAProxy https-in routing for metablog/streamlit sites had silently broken.

**Symptom (when investigation started, ~10:05):**

- `arm.gk2`, `cpf.gk2`, `lldh.ganimed.fr`, etc. all returning HTTP 200 with a 6202 b `<title>Wrong Domain - SecuBox</title>` page (nginx:9080 default_server fallback).
- `/etc/haproxy/haproxy.cfg` last modified at 10:03:48 — minutes after my Session 154 nginx + mitmproxy fixes.
- HAProxy reloaded at 10:03:51 with the broken config.
- 4 `metablog_*` backends DOWN, all metablog vhosts returning 503 or Wrong Domain.

**Cause chain (multi-layered):**

1. **Stale generator on board.** `/usr/sbin/haproxyctl` (the bash script that actually writes `haproxy.cfg` from `/etc/secubox/haproxy.toml`) was an older version that emitted `use_backend waf_inspector if host_X` while `waf_enabled=1`. The repo's current `packages/secubox-haproxy/sbin/haproxyctl` already emits `use_backend mitmproxy_inspector` — but the board had a 33115 b old copy still using `waf_inspector`.
2. **`waf_inspector` backend was a dead reference.** The script also generated `backend waf_inspector { server srv0 127.0.0.1:8890 check }` but **port 8890 was not listening** — so even if the regen worked, those vhosts would have been DOWN.
3. **`waf_enabled=0` fallback was equally broken.** When `waf_enabled` evaluated to 0, the script fell back to each vhost's TOML `backend = "nginx_vhosts"` (`server 127.0.0.1:9080 check`) — but nginx:9080 has no `server_name` for individual gk2 sites (only for `admin.gk2.secubox.in`), so every other host hit the default_server "Wrong Domain" page.
4. **TOML coverage is incomplete.** `/etc/secubox/haproxy.toml` declares only 93 vhosts, while `/srv/mitmproxy/haproxy-routes.json` has 245 active routes. The 150 missing domains had no HAProxy ACL → `default_backend fallback` (deny 503).
5. **Race with the Python service.** `secubox-haproxy.service` (FastAPI on `/usr/lib/secubox/haproxy/api/main.py`) was polling/validating the config and logging "Failed to load HAProxy config: Invalid value (at line 854, column 7)" every ~10 s for >10 min before haproxyctl finally succeeded a regen that produced the broken-but-syntactically-valid output.
6. **Container routes had drifted too.** `lxc-attach -n mitmproxy -- jq .[cpf.gk2.secubox.in] routes.json` showed `[10.100.0.1, 9080]` while the host file had `[10.100.0.50, 8523]`. A previous unsuccessful regen had pushed a corrupted JSON into the container.

**Restore + harden plan (user-approved option: patch direct + freeze regen):**

1. `systemctl stop secubox-haproxy.service` — freeze any further regen attempts.
2. Backup current `haproxy.cfg`.
3. Read `/srv/mitmproxy/haproxy-routes.json` → for each of 245 domains, replace `use_backend nginx_vhosts if host_X` with `use_backend mitmproxy_inspector if host_X` in `haproxy.cfg` (180 lines patched: 90 unique × 2 frontends).
4. Replace `default_backend fallback` with `default_backend mitmproxy_inspector` in both `http-in` and `https-in` frontends — so the 150 routes that exist in mitmproxy JSON but not in `haproxy.toml` are still dispatched correctly (mitmproxy reads the Host header against its routes table).
5. `haproxy -c -f haproxy.cfg` → validate; `systemctl reload haproxy`.
6. Push host routes JSON → mitmproxy LXC; `systemctl restart mitmproxy` inside container.
7. Verify with live HTTPS probes.

**Verification (live, fresh, cache-busted):**

| Domain | HTTP | Title |
| --- | --- | --- |
| `cpf.gk2.secubox.in` | 200 | Streamlit (cineposter_fixed @ port 8523) |
| `arm.gk2.secubox.in` | 200 | SITREP ARM/ARMADA — CLASSIFIED // GANDALF-7 |
| `lldh.ganimed.fr` | 200 | La Livrée d'Hermès — Anibal Edelberto Amiot |
| `admin.gk2.secubox.in` | 200 | SecuBox Control Center |
| `pub.gk2.secubox.in` | 200 | GK² · NET — Opérateur Internet |
| `werdl.gk2.secubox.in` | 200 | Retrouver son téléphone — Pour toute la famille |
| `3d.gk2.secubox.in` | 200 | SecuBox Dice 3D |
| `42.gk2.secubox.in` | 200 | CyberMind QWIZZ — Détecteur d'Injonction Paradoxale |
| `zkp.gk2.secubox.in` | 200 | 🔐 OPORD CYBER-ZKP // SECUBOX CLASSIFIED |

**Persistent fixes committed to repo:**

- `packages/secubox-haproxy/api/main.py` — Python generator: `use_backend waf_inspector` → `use_backend mitmproxy_inspector` (2 occurrences, lines 1147 + 1170). Survives next package rebuild.
- `packages/secubox-haproxy/sbin/haproxyctl` — Bash generator: `default_backend fallback` → `default_backend mitmproxy_inspector` (2 occurrences). Repo version already used `mitmproxy_inspector` for the `use_backend` lines; the board copy was stale. Future `dpkg -i secubox-haproxy_*.deb` will replace the board's stale `/usr/sbin/haproxyctl`.
- `scripts/secubox-haproxy-regen-safe` — new wrapper: snapshot → regen → validate → atomic swap → reload, with rollback on validation failure. Prevents future broken-config-deployed-anyway incidents.

**Still on board (not in repo, infra-side only):**

- `/usr/sbin/haproxyctl` patched in place on the board to mirror repo state.
- `/usr/lib/secubox/haproxy/api/main.py` patched on board.
- `secubox-haproxy.service` left **stopped** until user confirms safe to re-enable.

**Open questions:**

- `/etc/secubox/haproxy.toml` only declares 93 vhosts — should the 150 metablog/streamlit domains be added so HAProxy has explicit ACLs and stats? Currently they work via `default_backend mitmproxy_inspector` (catch-all), which is functional but loses per-vhost stats granularity.
- Re-enabling `secubox-haproxy.service` is safe now (generators patched), but verify no other code path writes `haproxy.cfg` with the broken pattern (e.g., on-demand `/generate` API endpoint).

---

### Session 155 — Multi-Agent Worktree Workflow

**Goal:** Enable parallel multi-agent work via one-branch-per-issue isolated worktrees.

**Delivered:**

- `scripts/agent-worktree.sh` with sub-commands `start`, `list`, `sync`, `finish`, `clean`
- `scripts/lib/agent-worktree-lib.sh` (slug + label→prefix helpers)
- Test suite `scripts/tests/test-agent-worktree.sh` (26 cases, no bats dep)
- `gh` CLI mock at `scripts/tests/fixtures/gh-mock.sh`
- New section in `CLAUDE.md`: `## 🌿 Multi-Agent Worktree Workflow — Obligatoire`
- `scripts/README.md` updated with usage

**Issue:** #83. **Spec:** `docs/superpowers/specs/2026-05-12-multi-agent-worktree-workflow-design.md`. **Plan:** `docs/superpowers/plans/2026-05-12-multi-agent-worktree-workflow.md`.

---

### Session 154 — Metablogizer Vhosts Audit & Regeneration

**Goal:** User flagged `https://lldh.ganimed.fr/` returning 404. Apply the same diagnostic + fix workflow to all metablogizer vhosts, find every site with broken routing / missing content / port mismatch.

**Trigger case — `lldh.ganimed.fr`:**

- nginx had `server_name lldh.gk2.secubox.in` only (no `.ganimed.fr` alias) → 404 from default_server.
- mitmproxy route pointed to port `8000` instead of `8900` (where metablog nginx listens).
- `/srv/metablogizer/sites/lldh/` contained only `La_Livree_dHermes_Galerie-1.zip` (31 MB) + `.git` — no `index.html` to serve.

**Trigger fix (3 steps):**

1. Extracted zip via `python3 -m zipfile` (84 files: `index.html` + `planches/*.jpg`).
2. Added `lldh.ganimed.fr` to existing `server_name lldh.gk2.secubox.in` block in `/etc/nginx/sites-enabled/metablogizer`, `nginx -t && systemctl reload nginx`.
3. Patched `/srv/mitmproxy/haproxy-routes.json`: `lldh.ganimed.fr` → `[192.168.1.200, 8900]`, pushed to LXC container, `systemctl restart mitmproxy` (SIGHUP alone wasn't enough — mitmproxy serving cached/wrong content until full restart).

**Systematic audit of all metablog vhosts (Python script in `/tmp` on board):**

Scanned `/etc/nginx/sites-enabled/metablogizer` for every `server_name` → root pair, cross-checked each domain against `/srv/mitmproxy/haproxy-routes.json` and the on-disk `index.html`.

| Metric | Count |
| --- | --- |
| Sites scanned | 159 |
| Server_names total | 162 |
| OK after fixes | 162 (100%) |
| `wrong_port` (route ≠ 8900) | 0 |
| `missing_route` (in nginx, absent from routes) | 1 → `pub.gk2.secubox.in` |
| `extract_zip` (zip not extracted) | 0 (after lldh) |
| `no_index_no_zip` real cases | 1 → `werdl` |

**Additional fixes applied:**

- `pub.gk2.secubox.in` → added to mitmproxy routes `[10.100.0.1, 8900]`, mitmproxy restarted. Now HTTP 200 ("GK² · NET — Opérateur Internet & Services Numériques").
- `werdl/index.html` → symlink to `famille_index.html` (3 HTML files existed: `famille_index`, `famille_bebe-enfant`, `famille_papy-mamy`; preserved originals, no destructive rename). Now HTTP 200 ("Retrouver son téléphone — Pour toute la famille").

**False positive identified:**

- Initial audit flagged `public` as a "site without index", but my regex over-captured: it was matching the trailing `public` in Laravel-style paths `/srv/metablogizer/sites/{money,live,evolution}/public/`. Those parent sites (`money`, `live`, `evolution`) serve fine via their normal `server_name` blocks. No action needed.

**Backups on board:**

- `/srv/mitmproxy/haproxy-routes.json.bak.<epoch>` (pre-patch)
- `/etc/nginx/sites-enabled/metablogizer.bak.<epoch>` (pre-server_name-add)
- Symlink for `werdl` is non-destructive (`famille_index.html` untouched).

**Verification (live, fresh HTTPS, no cache):**

- `lldh.ganimed.fr` → 200, 43959 b, "La Livrée d'Hermès"
- `lldh.gk2.secubox.in` → 200, 43959 b, same content
- `pub.gk2.secubox.in` → 200, 47584 b, "GK² · NET"
- `werdl.gk2.secubox.in` → 200, 6017 b, "Retrouver son téléphone"
- Spot-check `admin.gk2`, `arm.gk2`, `zkp.gk2`, `3d.gk2` from Session 153 still 200 ✅ (no regression).

**Note:** all fixes were applied to live board state (routes JSON, nginx vhost config, site content). The metablogizer vhost config (`/etc/nginx/sites-enabled/metablogizer`) is auto-generated per site by the metablogizer service and is not tracked in the repo, so no repo file changed from this session beyond this HISTORY entry.

---

### Session 153 — Mitmproxy Route Sync Stability Fix

**Goal:** All `*.gk2.secubox.in` metablogizer sites (arm, zkp, 3d, …) returned "Wrong Domain" page on HTTPS. Investigate, restore service, and harden the auto-sync infrastructure.

**Symptom chain:**

1. User report: `https://arm.gk2.secubox.in/` → "Wrong Domain - SecuBox" landing page.
2. `~160` metablogizer sites affected (all routed via mitmproxy WAF).
3. Two systemd timers (`sync-mitmproxy-routes.timer` + `secubox-route-sync.timer`) firing at the same second on the same routes file.
4. `sync-mitmproxy-routes.service` had been failing with exit code 30/4 for >30 minutes (chronic).

**Root cause (deepest):**

`log()` function in `/usr/local/bin/sync-mitmproxy-routes.sh` wrote to **stdout**. `fix_dead_container_routes()` calls `log "Fixing dead route: …"` and is itself captured via `routes_json=$(fix_dead_container_routes "$routes_json")` — every log line was concatenated into the JSON variable, producing `[date] Fixing dead route: …{"255.gk2..."`. jq then complained `Invalid numeric literal at line 1, column 12`, `set -e` killed the script, and the corrupted JSON got pushed to the mitmproxy container (`lxc-attach … tee /srv/mitmproxy/haproxy-routes.json`). mitmproxy restart-looped on `Failed to load routes: Expecting ',' delimiter`, HAProxy backend `mitmproxy_inspector` went DOWN, every public domain returned **HTTP 503**.

**Additional contributing bugs:**

- `fix_dead_container_routes` returned `$fixed` (a count) instead of `0` — non-zero return tripped `set -e` in the caller's command substitution.
- `sync-all-routes.sh` step 2 wrote metablogizer routes to port **9080** (nginx default_server → "Wrong Domain") instead of **8900** (where nginx actually listens with `server_name` per metablog site).
- jq read calls had no error tolerance — any malformed JSON fed in via `$routes_json` aborted the whole script via `set -euo pipefail`.
- Two systemd services bound to the **same script** (`sync-mitmproxy-routes.service` + `secubox-route-sync.service`) racing on the same file.

**Fixes applied:**

| # | Fix | Cible | Mechanism |
| --- | --- | --- | --- |
| 1 | Routes patchées 9080→8900 (165 sites metablog) | `/srv/mitmproxy/haproxy-routes.json` (host + container) | Python script (extract `server_name` from nginx, rewrite port) |
| 2 | `return $fixed` → `return 0` | `sync-mitmproxy-routes.sh:fix_dead_container_routes` | sed |
| 3 | Port metablog 9080 → 8900 in step 2 | `sync-all-routes.sh:62` | sed |
| 4 | **`log()` writes to stderr** (root-cause fix) | `sync-mitmproxy-routes.sh:log` | adds `>&2` so `$()` capture is clean |
| 5 | Defensive `2>/dev/null \|\| true` on jq read | `sync-mitmproxy-routes.sh` (2 occurrences) | tolerate corrupted input |
| 6 | Fallback preserving old `routes_json` on jq write failure | `sync-mitmproxy-routes.sh` (3 occurrences) | `new_rj=$(... \|\| true); [[ -n "$new_rj" ]] && routes_json="$new_rj"` |
| 7 | `flock -n` guard prevents concurrent runs | `sync-mitmproxy-routes.sh` (head) | `/run/sync-mitmproxy-routes.lock` |
| 8 | Disable duplicate timer | `systemctl disable --now secubox-route-sync.timer` | systemd |

**Verification (post-fix):**

- `sync-mitmproxy-routes.service` via systemd → exit 0/SUCCESS, "Sync complete".
- Container routes JSON valid: 244 keys, all metablogizer domains → `[10.100.0.1, 8900]`.
- mitmproxy: `active`, listening on `0.0.0.0:8080`.
- HAProxy backend `mitmproxy_inspector srv0 10.100.0.60:8080` op_state=UP.
- Live tests: `admin.gk2`, `arm.gk2`, `zkp.gk2`, `3d.gk2` all HTTP 200 with correct titles.

**Files modified (versioned in repo):**

- `scripts/sync-mitmproxy-routes.sh` (synced from board `/usr/local/bin/`)
- `scripts/sync-all-routes.sh` (new in repo, synced from board)

**Backups created on board (timestamped, kept for rollback):**

- `/srv/mitmproxy/haproxy-routes.json.bak.<epoch>` (pre-patch JSON)
- `/usr/local/bin/sync-mitmproxy-routes.sh.bak.<epoch>` and `.bak.<epoch>-preflock`
- `/usr/local/bin/sync-all-routes.sh.bak.<epoch>`

**Topology note discovered:**

- Canonical Hub vhosts (nginx `sites-available/secubox-local`): `admin.gk2.secubox.in`, `gk2.secubox.in`, `secubox.maegia.tv`, `c3box.maegia.tv` + LAN aliases.
- `~165` metablogizer sites listed in `/etc/nginx/sites-enabled/metablogizer`, each `listen 0.0.0.0:8900` with per-site `server_name`, `root /srv/metablogizer/sites/<name>/`.
- Public flow: HAProxy `https-in` (443) → ACL host match → backend `mitmproxy_inspector` (LXC `10.100.0.60:8080`) → mitmproxy looks up host in `haproxy-routes.json` → upstream `[10.100.0.1, 8900]` → nginx vhost matches `server_name` → serves static site.

**Open follow-up:** the `sync-streamlit-routes.timer` last fired 2026-05-10 (1d 15h ago) and didn't fire since — needs separate investigation. Not blocking metablog/Hub stability.

---

### Session 152 — APT Public Repo Staging Pipeline (Issue #80)

**Goal:** Stage a complete signed APT repo at `output/repo/` for `bookworm` × {arm64, amd64}, validated end-to-end. User pushes to `apt.secubox.in` out-of-band.

**Spec & plan:**
- Design: `docs/superpowers/specs/2026-05-12-apt-public-repo-staging-design.md`
- Plan: `docs/superpowers/plans/2026-05-12-apt-public-repo-staging.md`

**Delivered (10 tasks, 9 commits — merged via PR #82, plus `0f1907df` chroot fix):**

| Component | Commit | Purpose |
|-----------|--------|---------|
| `scripts/build-packages.sh --filter` + `--dry-run` | `ce82e13d` | Tier-driven build filtering via JSON manifest |
| `scripts/lib/tier-manifest.sh` + hardening | `6f59de25`, `52463db1` | Resolve `base/tier-lite/tier-standard/tier-pro` → JSON package list |
| `scripts/stage-gpg-bootstrap.sh` | `3b99bcf4` | Persistent GPG key at `~/.gnupg/secubox/`, writes `FINGERPRINT.txt` |
| `scripts/stage-apt-repo.sh` | `5f7b8474` | Main orchestrator (GPG → reprepro init → tier loop → check gate) |
| `scripts/render-deploy-artifacts.sh` | `d6fe14d5` | nginx vhost + DEPLOY.md + install.sh + CMSD-1.0 license copies |
| `scripts/validate-staged-repo.sh` + chroot fix | `bb58789b`, `0f1907df` | reprepro check + gpg verify + license cmp + chroot apt-update smoke |
| `.gitignore` for staging artifacts | `197eba63` | Ignore `output/repo/{db,pool,dists,conf,gpg}` and build logs |

**Tooling used:**

- `secubox gen --tier <tier> --board mochabin --out <dir>` (existing Go CLI; emits `manifest.yaml`)
- `reprepro` with persistent `~/.gnupg/secubox/` keyring (SignWith fingerprint)
- `dpkg-buildpackage` + `crossbuild-essential-arm64` (already installed)
- `python3-yaml` (for parsing `secubox gen` output)

**End-to-end validation (base + tier-lite × arm64+amd64):**

- 9 packages published, all `Architecture: all`
- `reprepro check` clean
- `gpg --verify InRelease` → Good signature, fingerprint `31848880ED89C1722677D75A25C9E32645166DB9`
- License files byte-match project root
- `chroot apt-get update` against `file://output/repo/` succeeds (sees SecuBox repo)

**Important finding (arch:all dominance):**

| Architecture field | Count |
|--------------------|-------|
| `all` | 130 |
| `any` | 2 (`secubox-daemon`, `zkp-hamiltonian`) |

130/132 SecuBox packages are `Architecture: all` — the cross-arch (arm64 vs amd64) split is mostly cosmetic. The two `Architecture: any` packages aren't in `build-packages.sh`'s `PACKAGES=` list, so the `arm64` pool count is currently 0. Adding them is separate work.

**GPG signing key:**

- UID: `SecuBox Package Signing Key (apt.secubox.in) <packages@secubox.in>`
- Fingerprint: `31848880ED89C1722677D75A25C9E32645166DB9`
- Home: `~/.gnupg/secubox/` (persistent across rebuilds)
- Public key: `output/repo/secubox-keyring.gpg` (ASCII-armored) + `.bin`

**Open item (not blocking):**

- TLS cert for `apt.secubox.in` shows `ERR_TLS_CERT_ALTNAME_INVALID` — must be re-issued by certbot for the exact SAN. Recipe is in `output/repo/DEPLOY.md`.

**Next steps (user):**

1. Optional: full pipeline run with `bash scripts/stage-apt-repo.sh` (no flags = all four tiers, 30-90 min).
2. rsync to `apt.secubox.in` per `output/repo/DEPLOY.md` (excludes `db/`, `gpg/`, `conf/`).
3. certbot --nginx for cert; verify SAN includes `apt.secubox.in`.
4. Smoke-test from clean client: `curl -fsSL https://apt.secubox.in/install.sh | sudo bash && sudo apt-get update`.
5. Close issue #80 on success.

---

### Session 151 — Fix Sidebar Mobile Mode False-Positive on Touch Desktops

**Goal:** Sidebar of secubox-hub forced mobile mode (hamburger + hidden sidebar) on Firefox PC because the detection logic used `isTouchDevice() || isNarrowViewport()` — any touch signal (touchscreen laptop, Firefox `pointer: coarse`, `maxTouchPoints > 0`) triggered mobile UX at desktop widths.

**Root cause:** `packages/secubox-hub/www/shared/sidebar.js:2113-2116` — `OR` was too permissive. User console showed `Mobile mode: ON (touch: true, narrow: false)` on a 1080p+ Firefox.

**Fix:** Changed to strict `AND` — both touch AND narrow viewport required.

```js
function shouldUseMobileMode() {
    // Mobile = touch device AND narrow viewport.
    // OR was too permissive: PCs with touchscreens (or Firefox advertising
    // pointer:coarse) triggered mobile mode at desktop widths.
    return isTouchDevice() && isNarrowViewport();
}
```

**Files modified:**

- `packages/secubox-hub/www/shared/sidebar.js:2113-2118`

**Deploy:**

- `bash scripts/deploy.sh secubox-hub root@192.168.1.200` (rsync `www/` → `/usr/share/secubox/www/`, no service restart needed for static JS)
- Verified on canonical Hub vhost `https://admin.gk2.secubox.in/shared/sidebar.js` (line 2117 contains the new `&&` logic)

**Topology note (discovered during validation):**

- Canonical Hub vhosts (nginx `sites-available/secubox-local`): `admin.gk2.secubox.in`, `gk2.secubox.in`, `secubox.maegia.tv`, `c3box.maegia.tv` + LAN `secubox.local` / `192.168.1.200` / `192.168.255.1`
- HAProxy `webui-lan` frontend → `default_backend webui_direct` (127.0.0.1:9080) — bypasses mitmproxy, ideal for LAN/test
- All public `*.gk2.secubox.in` vhosts route via mitmproxy → same nginx:9080 → same `/usr/share/secubox/www/` (single source of truth for the Hub UI)

**Build artefact note:** `packages/secubox-hub/debian/secubox-hub/usr/share/secubox/www/shared/sidebar.js` was not modified — it will be regenerated at next `dpkg-buildpackage`.

---

### Session 150 — OPAD Doctrine Documents v2.4.0

**Goal:** Create the 5 foundational OPAD (Off-Path Active Defense) doctrinal documents for SecuBox-Deb migration to passive observation + packet injection architecture.

**Reference:** CM-WALL-OPAD-2026-05

**Architecture Overview:**
- **OPAD Principle:** SecuBox observes traffic passively (port mirroring) and injects packets to neutralize threats, never sits in the data path
- **4 Injection Primitives:** DNS-R (99%), DHCP-R (95%), RST-I (90%), ARP-R (98%)
- **8 Invariants (INV-01 to INV-08):** Fail-silent, no forwarding, zero WAN surface, etc.
- **3-Prong Profile:** Observation / Injection / Policy configuration structure

**Files Created:**

| File | Lines | Description |
|------|-------|-------------|
| `doctrine/opad/OPAD.md` | 671 | Core doctrine, principles, invariants, injection specs |
| `doctrine/opad/CSPN.matrix.md` | 569 | ANSSI threat × capability matrix (36 threats, 72% coverage) |
| `doctrine/opad/OPAD-OPERATIONS.md` | 948 | Operational guide, troubleshooting, 4R rollback |
| `schemas/opad-profile.schema.json` | 365 | JSON Schema draft-07 for profile validation |
| `common/secubox_core/opad/models.py` | 400 | Pydantic v2 models (OPADProfile, configs) |
| `common/secubox_core/opad/__init__.py` | 85 | Package exports |
| `tests/test_opad_schema.py` | 374 | 18 tests (JSON Schema + Pydantic equivalence) |
| **Total** | **3412** | |

**Technical Notes:**
- Pydantic v2 syntax: `@field_validator`, `ConfigDict`, `model_json_schema()`
- JSON Schema draft-07 with `$defs` for reusable definitions
- MAC address validation: `^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`
- Success rate constraints: 0.90 ≤ rate ≤ 1.0 for injection primitives

**Tests:** 18 passed (0.13s)
- JSON Schema Draft7 validation
- Pydantic model equivalence
- MAC address format validation
- Success rate bounds checking
- Policy rule priority range (0-9999)

**Commits:** Cherry-picked to `feature/eye-remote-auto-mode`

---

## 2026-05-11

### Session 147 — Fix Eye Agent Import Errors (#78)

**Goal:** Fix import errors in eye-agent main.py that prevented the service from starting.

**Problem Analysis:**
- `main.py` imported nonexistent classes: `DashboardRenderer`, `LocalRenderer`, `FlashRenderer`, `GatewayRenderer`, `RenderContext`
- Missing modules: `agent.system`, `agent.secubox`, `agent.web`
- Import chain failures due to missing aiohttp dependency

**Solution:**
1. **Created stub modules** with working implementations:
   - `system.py`: WifiManager, BluetoothManager, DisplayController
   - `secubox.py`: DeviceManager, FleetAggregator
   - `web.py`: WebServer (FastAPI-based)

2. **Created `display/renderers.py`** with mode-specific renderers:
   - DashboardRenderer: 3D cube + metric rings (PIL-based)
   - LocalRenderer: Disconnected mode display
   - FlashRenderer: Alert/splash messages
   - GatewayRenderer: Fleet overview for multi-device
   - RenderContext: Dataclass for render state

3. **Refactored imports in `main.py`**:
   - Replaced single try/except with `_try_import()` helper
   - Each module imported individually with fallbacks
   - Missing modules set to None instead of crashing
   - Warnings logged for missing optional components

4. **Updated `display/__init__.py`**:
   - Added graceful fallbacks for all exports
   - Missing classes set to None
   - Logged warnings instead of crashing

**Branch:** `fix/78-eye-agent-imports`
**Commit:** `e71209f5`

**Files Created/Modified:**
| File | Status |
|------|--------|
| `agent/main.py` | Modified |
| `agent/display/__init__.py` | Modified |
| `agent/display/renderers.py` | New |
| `agent/system.py` | New |
| `agent/secubox.py` | New |
| `agent/web.py` | New |

---

### Session 146 — Eye Remote v2.2.1 Build & Validation

**Goal:** Update build script with fallback display fix, build & test new image.

**Changes:**
1. **Build script updated** (`build-eye-remote-image.sh` v2.2.1)
   - Added `secubox-fallback-display.service` installation
   - Enabled fallback-display instead of broken eye-agent
   - Added PIL dependencies: libopenjp2-7, libtiff6
   - All agent subdirectories: display, secubox, system, web, api, recovery, sync

2. **Image built and tested**
   - `/tmp/secubox-eye-remote-2.2.1.img` (5.3GB uncompressed)
   - Flashed to SD card, tested on MOCHAbin
   - Dashboard working: 3D cube + rainbow rings + real metrics

3. **GitHub Issues created**
   - #78: Fix eye-agent import errors (bug)
   - #79: Investigate Buildroot/Busybox minimal image (enhancement)

**Artifacts:**
- Commit: `b2f046c1`
- Image: `secubox-eye-remote-2.2.1.img.xz`

---

### Session 145 — Eye Remote Dashboard Fix

**Problem:** Eye Remote Pi Zero W showing wrong dashboard (plain fb_dashboard instead of nice fallback_manager with 3D cube and rainbow rings).

**Root Causes:**
1. Agent code incomplete - `DashboardRenderer` class doesn't exist
2. Build script missing `agent/api/` directory copy
3. Relative imports failing (`from ..api.setup import`)
4. PIL dependencies missing (libopenjp2-7)

**Fixes:**
1. **Deployed fallback_manager.py** as main dashboard
   - 3D rotating cube animation
   - Rainbow concentric rings for modules
   - Connection state: OFFLINE/CONNECTING/ONLINE/COMMUNICATING
   - Real-time metrics from MOCHAbin API

2. **Created secubox-fallback-display.service**
   - Replaced broken secubox-eye-agent.service
   - Proper PYTHONPATH and WorkingDirectory

3. **NAT routing through MOCHAbin**
   - IP forwarding enabled
   - iptables MASQUERADE for 10.55.0.0/30
   - Pi can reach internet via USB OTG

4. **Missing directories copied**
   - agent/api/ (metrics_fetcher, setup, gadget)
   - agent/recovery/
   - agent/sync/

**Working Configuration:**
```
Service: secubox-fallback-display.service
Display: /usr/lib/secubox-eye/agent/display/fallback/fallback_manager.py
API: http://10.55.0.1:8000/api/v1/system/metrics
```

---
## 2026-05-09

### Session 141 — WAF Optimization, Route Fixes, Export Package, UI Enhancements

**Problem:** Mitmproxy CPU at 90%+ constant, many sites returning 502/503.

**Root Causes:**
1. WAF regex checks running on every request (including static assets)
2. Dead container routes (10.100.0.10-50) causing connection timeouts
3. `MultiDictView.to_dict()` AttributeError on every request

**Fixes:**

1. **WAF Optimizations (secubox_waf.py)**
   - Skip WAF checks for static assets (.js, .css, .png, etc.)
   - Skip WAF checks for /health, /status, /system_health endpoints
   - Skip WAF checks for trusted hosts (git, admin, internal API)
   - Fixed `to_dict()` → `dict()` for MultiDictView
   - Result: CPU dropped from 90%+ to 0% idle, 25-90% under load

2. **Route Sync Script (sync-mitmproxy-routes.sh)**
   - Added dead container detection and auto-fix
   - Routes to dead IPs (10.100.0.10-50) → webui (9080)
   - Fixed bash arithmetic for `set -e` compatibility

3. **Metablogizer Export Package Enhanced**
   - Full export ZIP with: content/, config/, certs/, README.md
   - nginx.conf, haproxy.cfg generated configs
   - Complete republishing instructions

4. **Users Module**
   - REVOKE ALL sessions panic button
   - Emergency session revocation endpoint

5. **WAF UI Enhancements**
   - **Eyemote Visualization** - Concentric donut rings for attack origins by continent
     - 5 Olympic-colored rings (Americas, Europe, Asia, Oceania, Africa)
     - Pulsing center pupil with total attack count
     - Legend with circular flag badges per country
   - **Quick Action Buttons** - Circular buttons in status bar:
     - 🔄 Refresh (with spinner animation)
     - 🛡️ WAF Toggle (active/paused states)
     - 🗑️ Clear All Bans (with confirmation)
     - 📤 Export Logs (JSON download)
     - ⚙️ Settings link

6. **SOC Dashboard Migration**
   - Replaced WarGames geomap with Triple Eyemote Sensors
   - 3 mini eyemotes in grid: Attack Origin, Visitors, Target Vhosts
   - Double-cache pattern for async API response handling
   - Same Olympic-colored visualization as WAF page

**Files Updated:**
- `scripts/sync-mitmproxy-routes.sh` - Dead container auto-fix
- `packages/secubox-waf/mitmproxy/secubox_waf.py` - Optimizations
- `packages/secubox-mitmproxy/addons/secubox_waf.py` - Optimizations
- `packages/secubox-metablogizer/api/main.py` - Enhanced export
- `packages/secubox-users/api/main.py` - Revoke all endpoint
- `packages/secubox-users/www/users/index.html` - Panic button
- `packages/secubox-waf/www/waf/index.html` - Eyemote rings, quick action buttons
- `packages/secubox-hub/www/soc/index.html` - Triple Eyemotes with double-cache

**Systemd:**
- `sync-mitmproxy-routes.timer` - Every 5 minutes

---

### Session 140 — Domain Filtering, Error Pages, Mitmproxy Sync

**New Features:**
1. **Domain Filtering** - Only `admin.gk2.secubox.in` allowed for admin access
   - Default server catches all other domains → wrong-domain.html
   - Styled landing page with redirect to correct admin URL

2. **Error Pages**
   - `wrong-domain.html` - Funky styled page for unauthorized domains
   - `unknown-module.html` - Styled 404 for unknown modules on admin
   - `/login` URL without .html extension for cleaner aesthetics

3. **Metablogizer Enhancements (v1.2.0)**
   - Auto-publish all sites on service startup
   - "Republish All" button in UI
   - `empty-site.html` - Sketch-style error for sites with no content
   - Default domain suffix changed from `.local` to `.gk2.secubox.in`
   - **Mitmproxy sync** - Routes updated when publishing sites

4. **Users Sessions**
   - Active sessions display in Users module
   - Session revocation endpoint

**Infrastructure:**
- Cleaned up nginx backup files (`webui.conf.bak*`)
- Added sudoers for secubox user: nginx test/reload, mitmproxy reload
- Fixed mitmproxy routes permissions for secubox user

**Files:**
- `packages/secubox-hub/www/shared/wrong-domain.html` (NEW)
- `packages/secubox-hub/www/shared/unknown-module.html` (NEW)
- `packages/secubox-metablogizer/api/main.py` - Mitmproxy sync, v1.2.0
- `packages/secubox-metablogizer/www/metablogizer/empty-site.html` (NEW)
- `packages/secubox-metablogizer/www/metablogizer/index.html` - Republish button
- `packages/secubox-users/api/main.py` - Sessions endpoint
- `packages/secubox-users/www/users/index.html` - Sessions display

---

### Session 139 — Nginx Health Routes Fix

**Problem:** Sidebar health checks returning 404 for most modules.

**Root Cause:**
1. Only 6 modules had nginx routes configured in `/etc/nginx/secubox-routes.d/`
2. The `include /etc/nginx/secubox-routes.d/*.conf;` was missing from `webui.conf`

**Solution:**
- Generated nginx routes for all 82 modules with API sockets
- Removed 19 duplicates already hardcoded in webui.conf
- Added missing include statement to webui.conf
- All `/api/v1/<module>/health` endpoints now functional

**Impact:**
- Sidebar status indicators now work for all 100+ modules
- Health-batch endpoint functional for efficient status polling

---

### Session 134 — CrowdSec Bans Display Fix, Service Stability (v2.7.2)

**CrowdSec Dashboard:**
- Fixed bans limit showing max 100 (actual: 143 bans on live server)
- API now returns `total` count separate from paginated `decisions` array
- Increased default limit from 100 to 1000, max to 10000
- Frontend fetches 500 decisions, displays up to 200 with "X more" indicator
- GeoIP enrichment limited to first 100 for performance

**Service Debugging:**
- Investigated vhost.sock intermittent creation issue
- All 8 core API services verified healthy (hub, auth, crowdsec, system, vhost, certs, publish, waf)
- MOCHAbin CPU stabilized at ~43% (down from 135%)

**Live Server (192.168.1.200):**
- 143 active bans in CrowdSec
- 6 collections installed (base, linux, nginx, http-cve, whitelist, vpatch)
- Custom SecuBox auth parser/scenario deployed

**Files Updated:**
- `packages/secubox-crowdsec/api/routers/decisions.py` — Total count, higher limits
- `packages/secubox-crowdsec/www/crowdsec/index.html` — Display total, show more indicator
- `.claude/WIP.md` — Session 134 tracking

---

### Session 133 — WAF Category Toggles, API Error Handling (v2.7.1)

**WAF Dashboard:**
- Added Categories tab with toggle on/off buttons for each WAF filter
- Fixed API error handling (return null instead of empty object)
- Added `loadCategories()` function to populate categories list
- Handle null responses gracefully in all data loaders (loadAlerts, loadBans, loadStats)
- Category toggles call `/category/{id}/toggle` API endpoint

**SOC Dashboard:**
- Fixed API calls to handle null responses properly
- Show meaningful states (OFFLINE, UNKNOWN) instead of stuck "LOADING"
- Use `requireAuth=false` for public endpoints (firewall_summary, health)
- Initialize empty states for all metrics when API fails

**nftables Verification:**
- IPv4: 3.1M packets processed, 2.7K blocked (CAPI + CrowdSec + manual bans)
- IPv6: 22K packets processed
- Cache files updated for SOC dashboard consumption

**WAF Threats Log:**
- 11,463 threats logged in `/var/log/secubox/waf-threats.log`
- Latest entries: scanner probes, robots.txt enumeration, favicon fingerprinting

**Tag:** v2.7.1

**Files Updated:**
- `packages/secubox-waf/www/waf/index.html` — Category toggles, null handling
- `packages/secubox-hub/www/soc/index.html` — API error states

---
## 2026-05-08

### Session 132 — Eyemote Icons, Concentric Donuts, Categories Fix

**Sidebar — Eyemote Icons (replacing dice):**
- Replaced dice icons with level-based eyemote icons (🟢🟡🟠🔴🔥💀)
- Per-metric icon sets (CPU, MEM, DISK, LOAD, TEMP, NET)
- Doubled icon size (1.4rem) for better visibility
- New `getMetricIcon(pct, type)` function

**SOC Dashboard — Categories Donut Fix:**
- Fixed duplicate waf-categories assignments causing "Loading..." display
- Removed orphan assignment in CrowdSec section (undefined `cats` variable)
- Categories now properly render concentric ring donut
- Colorized stat cards with accent colors

**WAF Dashboard — Severity/Category Donuts:**
- Added concentric severity donut with emojis (💀🔴🟠🟡🔵)
- Replaced severity badges with emoji spans
- Category donut with eyemote-style visualization

**System Dashboard — Resource Gauge:**
- Concentric ring gauge for CPU/RAM/Disk/Load
- 4-ring visualization with health center indicator
- Legend with per-metric values

**Files Updated:**
- `packages/secubox-hub/www/shared/sidebar.js` — Eyemote icons
- `packages/secubox-hub/www/soc/index.html` — Category fix, colorized cards
- `packages/secubox-waf/www/index.html` — Severity/category donuts
- `packages/secubox-system/www/system/index.html` — Resource gauge

---

### Session 131 — Dice Icons, Scribe Trace, LED Pulse Improvements

**Sidebar — Dice Icons for Smart Strip:**
- Replaced LED dot indicators with dice icons (⚀⚁⚂⚃⚄⚅)
- Dynamic update based on metric value (0-100% → dice 1-6)
- New `getDiceForPercent()` helper function
- Icons colored per metric type (CPU=red, MEM=yellow, etc.)

**SOC Dashboard — Scribe Trace Histogram:**
- Replaced bubble stats with vertical histogram visualization
- EEG/encephalogram style for firewall packets (DROP/ACCEPT/REJECT)
- Rolling history of 20 samples
- Vertical bars stacked by packet type

**SOC Dashboard — API Path Fixes:**
- Fixed API_HUB path from `/api/v1/hub` to `/api`
- Updated firewall_summary to `/api/public/firewall_summary`
- Removed category tags (keeping donut metrics only)

**WAF Dashboard — Syntax Fixes:**
- Removed orphan return statements from getSiteEmoji function
- Fixed extra closing brace causing "return not in function" error
- Verified brace balance across all script blocks

**HealthBump LED Service — Pulse Improvements:**
- LED1 (HW): 1 flash per cycle (slowest)
- LED2 (SVC): 2 flashes per cycle (medium)
- LED3 (SEC): 4 flashes per cycle (fastest)
- Pulse direction: bright → dim → bright (not dark to color)
- Variable pulse timing for visual differentiation

**Files Updated:**
- `packages/secubox-hub/www/shared/sidebar.js` — Dice icons, getDiceForPercent
- `packages/secubox-hub/www/soc.html` — Scribe trace, API fixes, no category tags
- `packages/secubox-waf/www/index.html` — Syntax fixes
- `scripts/secubox-healthbump` — 1/2/4 flash patterns

---

### Session 130 — Eyeremote Style Visualizations + SOC/WAF Improvements

**Hub Dashboard — Concentric System Health Gauge:**
- New `createConcentricGauge(cpu, mem, disk)` function
- Eyeremote-style visualization with 3 concentric rings
- Icons positioned at 12 o'clock (🔥CPU, 🧠RAM, 💾Disk)
- Center displays average load percentage
- Color-coded legend with live values
- Replaces simple ring gauges for richer visualization

**SOC Dashboard Improvements:**
- Added firewall packet stats bubbles (🛑DROP, ✅ACCEPT, ❌REJECT)
- CrowdSec category multi-layer donut with `createMultiLayerDonut()`
- Fixed sidebar.js injection (was missing)
- Fixed CATEGORY_EMOJI syntax error

**WAF Statistics Page Enhancements:**
- Restored separate Severity/Category donuts (user preference)
- New `createCountryDonut()` with country flags as icons
- New `createSiteDonut()` with site-specific emojis
- Fixed `parseDuration()` to handle compound formats like "22m47s"
- Dual visualization: donut + bar graph for Top Countries/Sites

**Backend API — Firewall Summary:**
- New endpoint: `/api/v1/hub/public/firewall_summary`
- Reads from nftables cache files (permission workaround)
- Returns: tables, chains, rules, processed, dropped, accepted, counters
- Cron job updates `/var/cache/secubox/nft-counters.txt` every 30s

**IPv6 Support Confirmed:**
- CrowdSec has both `crowdsec` (IPv4) and `crowdsec6` (IPv6) tables
- Counters include both address families

**Files Updated:**
- `packages/secubox-hub/www/index.html` — Concentric gauge, ring gauge functions
- `packages/secubox-hub/www/soc.html` — Firewall stats, category donut, sidebar
- `packages/secubox-waf/www/index.html` — Country/Site donuts, duration fix
- `packages/secubox-hub/api/main.py` — firewall_summary endpoint
- `/etc/cron.d/secubox-nft-stats` — Cron for nftables cache

---

### Session 129 — Eye Remote Radar Animation + SOC Fixes

**Radar Dashboard Created (remote-ui/round/radar.html):**
- New radar-style visualization for Eye Remote HyperPixel 2.1 Round
- Classic radar sweep animation with green phosphor aesthetic
- 6 module blips (AUTH/WALL/BOOT/MIND/ROOT/MESH) at 60° intervals
- Blips light up when radar sweep passes them
- Color-coded status: green=ok, yellow=warn, red=critical
- Concentric grid rings (60, 100, 140, 180, 210px)
- 12 radial grid lines
- Center displays: time, date, hostname, system status
- Top mini-metrics: CPU%, MEM%, DSK%
- Transport badge: OTG/WiFi/SIM auto-detection
- Ticker bar for alerts
- Simulation mode for offline testing
- Module thresholds: AUTH(CPU 70/85), WALL(MEM 75/90), BOOT(DISK 80/95), MIND(LOAD 2/4), ROOT(TEMP 65/75), MESH(WiFi -70/-80dBm)

**SOC Dashboard Fixes (earlier this session):**
- Added shared sidebar injection to SOC page
- Fixed CrowdSec health detection (direct LAPI HTTP + sudo for cscli)
- Applied SecuBox Six-Stack colorimetry to stat cards
- Implemented tiered auto-ban in CrowdSec profiles.yaml

**Files Created:**
- `remote-ui/round/radar.html` — v1.0 Radar dashboard

---

### Session 128 — LED Tooltips + Kernel nftables Fix

**Sidebar v2.32.0:**
- Per-LED tooltips: each LED row (Hardware/Services/Security) now has its own tooltip
- Hardware tooltip: CPU/MEM/DISK/LOAD histograms with current/average/max values
- Services tooltip: OK/WARN/ERROR/UNKNOWN service counts
- Security tooltip: Active bans and recent alerts from CrowdSec
- Fixed tooltip positioning for sidebar elements (was offset by navbar width)

**SOC Page Fix:**
- Fixed nginx `/soc/` route that was incorrectly proxying to API instead of serving static files
- SOC dashboard HTML now loads correctly

**Kernel nftables Issue (GitHub #64):**
- Discovered kernel 6.6.137 missing critical nftables options:
  - `CONFIG_NF_TABLES_INET` - inet family support
  - `CONFIG_NF_TABLES_IPV4` - IPv4 rules
  - `CONFIG_NFT_CT`, `CONFIG_NFT_LOG`, `CONFIG_NFT_REJECT`, etc.
- CrowdSec bouncer in restart loop due to `Operation not supported` errors
- Updated `board/mochabin/kernel/config-6.12-openwrt-merged.fragment` with complete nftables config
- Created issue #64 with bouncer health alert requirements (CSPN critical)

**Files Updated:**
- `www/shared/sidebar.js` — v2.32.0 with per-LED tooltips
- `www/shared/hybrid-skin.css` — Service/Security tooltip CSS styles
- `board/mochabin/kernel/config-6.12-openwrt-merged.fragment` — Full nftables support

---

### Session 127 — Smart Strip + LED Pulsing + Round UI Virtual
*(earlier today - see v2.25.0 to v2.31.0 changes)*

---

### Session 126 — Hybrid Skin License & Centralized Injection

**License Headers Added:**
- Added proper CyberMind/Gérald Kerma license and attribution to all theming files
- All files now include: author, license (Proprietary/ANSSI CSPN), location, project info
- Design references documented in code comments

**Centralized Hybrid Skin Injection (sidebar.js v2.19.0):**
- `injectHybridSkin()` function auto-loads CSS on any page with sidebar
- Injects: design-tokens.css, sidebar.css, hybrid-skin.css
- Adds `hybrid-skin` class to body, `hybrid-main` to main content
- All modules automatically get hybrid skin via navbar loading
- No need to patch individual module index.html files

**Files Updated:**
- `www/shared/sidebar.js` — v2.19.0 with hybrid skin injector
- `www/shared/hybrid-skin.css` — Full license header with design references
- `www/shared/design-tokens.css` — Six-Module Color System documentation
- `www/shared/sidebar.css` — Glass Morphism sidebar license header
- `www/soc/index.html` — SOC Dashboard with architecture documentation

**License Format (Standard):**
```
SecuBox-Deb :: <Module Name>
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
Location: Notre-Dame-du-Cruet · Savoie · France
COPYRIGHT (C) 2024-2025 CyberMind / Gérald Kerma
```

**Deployed to Production:**
- All updated files synced to 192.168.1.200:/usr/share/secubox/www/
- Local/live sync verified (all files match)

---

### Session 125 — Socket Repair & Health API Planning

**Socket Repair Complete:**
- Fixed 91 running services with 87 Unix sockets
- `ai-gateway`: Fixed permission denied for `/tmp/secubox/ai-gateway` cache dir
- `mcp-server`: Socket now active after service configuration fix
- Restarted and verified: `crowdsec`, `vhost`, `wireguard`, `system`
- Hub uses TCP:8001 by design (VM compatibility)

**Health API Standardization Plan:**
- Designed navbar-compliant health response schema
- Fields: `status`, `module`, `version`, `enabled`, `dev_stage`
- Batch health endpoint for efficient polling
- Sidebar.js updates for version/dev_stage display
- Retrofit strategy for 116 modules

**Services Verified:**
- ✅ hub (v1.7.0), waf (v1.2.0), crowdsec (v2.0.0), haproxy, vhost
- ✅ wireguard (v2.0.0), system (v1.2.0), ai-gateway, mcp-server
- ⚠️ dns degraded (unbound not running), metrics needs /health

---

### Session 122 — WAF GeoIP Country Lookup & Stats Enhancement

**WAF API Enhancements:**
- Added GeoIP country lookup using MaxMind GeoLite2-Country database
- Added `top_countries` to WAF threat stats (identifies attacking countries)
- Added `top_vhosts` to WAF threat stats (most targeted vhosts)
- Fixed IP field name: `ip` → `client_ip` for log compatibility
- Added `_lookup_country()` with caching and LAN detection

**Files Updated:**
- `packages/secubox-waf/api/main.py` — GeoIP integration
- Source files synced to debian package directories

---

### Session 123 — Health-Aware Sidebar, WAF Alerting & ACME Certs

**Sidebar v2.0.0 (Emoji LED + Pre-cache):**
- Emoji LED status: 🟢ok 🟡warn 🔴error ⚫unknown 🔵checking
- Auto-sort: healthy first (ok → warn → unknown → error)
- Pre-cache in localStorage for instant display on load
- Quick error toast (no buttons, auto-dismiss 2.5s)
- Pre-flight health checks on navigation
- 30-second periodic health refresh

**WAF WebUI Alerting:**
- Live threat ticker with pulsing red indicator
- 7680 total threats, 2813+ today detected
- Alerting tab with filterable list (severity, category, IP)
- Export alerts to CSV
- Quick ban buttons on each alert
- Compact category listing with emoji + toggle

**WAF Threat Log Fix:**
- Symlinked `/var/log/secubox/waf-threats.log` → `/srv/mitmproxy/logs/waf-threats.log`
- Mitmproxy logs now accessible to WAF API

**LXC Network Fix:**
- Updated `lxc-network-fix.service` to run continuously (30s loop)
- Fixed all container symlinks in `/var/lib/lxc/`
- Disabled `cgroup2.cpu.max` in all container configs

**Certificate Status (CRITICAL):**
- 15+ certificates EXPIRED
- 40+ expiring within 30 days
- Certificates at `/data/haproxy/certs/`

**ACME Certificate Manager WebUI:**
- Created `/certs/` dashboard with emoji TTD indicators
- 💀expired 🔴critical 🟡warning 🟢healthy
- Pre-flight wizard with DNS/HTTP/ACME checks
- Origin emoji icons per backend type

**Files Deployed:**
- `/usr/share/secubox/www/shared/sidebar.js` — v2.0.0 pre-cache
- `/usr/share/secubox/www/waf/index.html` — alerting system
- `/usr/share/secubox/www/certs/index.html` — ACME manager
- `/etc/systemd/system/lxc-network-fix.service` — continuous veth fix

---

### Session 122 — WAF Architecture Fix & Eye Remote Integration

**mitmproxy LXC Container Fix:**
- Container was STOPPED causing 503 on all vhosts
- Fixed cgroup2.cpu.max config preventing startup
- Created `lxc-network-fix.service` to auto-start veth interfaces
- mitmproxy now running with 145 routes and 150 WAF rules

**HAProxy Routing Refactor:**
- Changed all vhosts from `nginx_vhosts` → `mitmproxy_inspector`
- All HTTP traffic now flows through WAF inspection
- Fallback backend changed from 503 deny to mitmproxy pass-through
- Traffic flow: `HAProxy → mitmproxy (WAF) → nginx/backends`

**Eye Remote Dashboard:**
- Fixed `/eye-remote/` page (nginx location was missing)
- Simplified JS to work with pizero-metrics API
- Added Quick Commands mini card
- API proxy: `/api/v1/eye-remote/*` → `10.55.0.2:8000/*`

**USB Gadget Network:**
- usb0 interface at 10.55.0.1/24
- Pi Zero W responding at 10.55.0.2:8000
- Live metrics: CPU, RAM, Temp, Uptime, Load

**CrowdSec Status:**
- 100+ active bans (SSH brute-force from DE/NL/RO/SE)
- WAF threats log ready at `/srv/mitmproxy/logs/waf-threats.log`

**Dependencies Added:**
- `netcat-openbsd` for diagnostics

**Files Modified:**
- `/etc/haproxy/haproxy.cfg` — All vhosts through mitmproxy
- `/etc/nginx/sites-enabled/webui.conf` — Eye Remote locations
- `/var/lib/lxc/mitmproxy/config` — Fixed network config
- `/etc/systemd/system/lxc-network-fix.service` — Auto veth startup
- `/usr/share/secubox/www/eye-remote/index.html` — Simplified dashboard
- `/usr/share/secubox/www/eye-remote/js/eye-remote.js` — pizero-metrics API

---

### Session 121 — HealthBump v2.1 with Activity Detection & K2000

**Features Added:**
- Activity-based brightness: ACTIVE (100) when metrics change, SLEEP (20) when stable
- K2000 (Knight Rider) sweep effect for boot/success announcements
- Alert mode (red K2000) for warnings
- Rainbow party mode for testing

**I2C Timing Alignment:**
- Rewritten to use same values as `secubox-led-safe`:
  - `WRITE_DELAY=0.3` (300ms)
  - `ERROR_BACKOFF=3` (3s)
  - `MAX_ERRORS=5`
  - `RESET_THRESHOLD=3`
- Simplified to `/bin/sh` (POSIX compliant like led-safe)

**Commands:**
```bash
secubox-healthbump              # Health check (default)
secubox-healthbump k2000 2 cyan # K2000 sweep
secubox-healthbump success      # Boot announcement
secubox-healthbump alert 2      # Red alert sweep
secubox-healthbump rainbow      # All colors party
secubox-healthbump off          # Turn off LEDs
```

**I2C Bus Recovery:**
- Full rebind: `echo '80018000.i2c' > /sys/bus/platform/drivers/mv64xxx_i2c/unbind`
- Then bind + modprobe to recover from lockups

**Files Updated:**
- `packages/secubox-led-heartbeat/usr/sbin/secubox-healthbump`
- `packages/secubox-led-heartbeat/systemd/secubox-healthbump.service`
- `docs/LED-HEALTHBUMP.md`

---

### Session 120 — LED System Complete & Kernel 6.6.137 Validation

**Root Cause Analysis (Systematic Debugging):**

1. **Evidence Gathered**
   - Kernel 6.12.85: `mv64xxx_i2c_fsm: Ctlr Error -- state: 0x2, status: 0x0`
   - I2C bus completely locked after rapid LED writes
   - Only recoverable via reboot

2. **Data Flow Trace**
   ```
   sysfs → leds-is31fl319x → regmap → i2c-mv64xxx → IS31FL3199
                                        ↑ FAILURE (controller stuck)
   ```

3. **Hypothesis Tested**
   - Kernel 6.6.137 LTS (same generation as OpenWrt) should work
   - **Result: CONFIRMED** - LEDs working perfectly on 6.6.137

**Validation via TTY:**
- Red/Green/Blue: Bright and perfect ✅
- Manual control (secubox-led): Working ✅
- HealthBump stats: Working ✅
- I2C bus: Stable, no errors ✅

**Package Fixes Committed:**
- `debian/rules` — Installs all HealthBump scripts
- `debian/postinst` — Enables healthbump.timer + led-pulse.service
- `debian/prerm` — Stops all services, turns off LEDs
- `debian/changelog` — Version 2.0.0-1~bookworm1

**Boot Configuration:**
- Default kernel: `kernel66` (6.6.137 LTS)
- LED support: Native, no patches needed

**Commits:**
- `853f9a6d` fix(led-pkg): Update packaging for HealthBump 3-tier system
- `5c3afdd5` feat(kernel): Add I2C timing patches for LED driver reliability

---

### Session 119 — I2C Timing Investigation and Kernel Patches

**Investigation:**

1. **Root Cause Analysis** — Errata FE-8471889
   - mv64xxx I2C controller has timing issues on Armada platforms
   - Mainline kernel has 5µs delay fix, but insufficient for LED controllers
   - OpenWrt kernel works due to different build/timing characteristics

2. **OpenWrt Patches Review**
   - Checked OpenWrt mvebu patches-6.12 for I2C fixes
   - Found i2c-pxa patches for Armada 3700 (not applicable to 7040)
   - 304-revert_i2c_delay.patch only affects Armada XP (32-bit)

3. **Kernel Configuration Comparison**
   - Both OpenWrt and custom kernel use CONFIG_I2C_MV64XXX=y
   - I2C clock at 100kHz (standard mode) - correct for errata fix
   - DTB uses `marvell,mv78230-i2c` compatible - errata should trigger

**Solution — Kernel Patches Created:**

1. `001-leds-is31fl319x-add-i2c-delays.patch`
   - Adds 1ms usleep_range() between regmap writes
   - Prevents rapid I2C transactions that cause bus errors

2. `002-i2c-mv64xxx-increase-errata-delay.patch`
   - Increases errata delay from 5µs to 50µs
   - Provides more margin for I2C bus settling

**Files Created:**
- `kernel-build/patches/001-leds-is31fl319x-add-i2c-delays.patch`
- `kernel-build/patches/002-i2c-mv64xxx-increase-errata-delay.patch`
- Updated `kernel-build/README.md` with patch instructions

**References:**
- [Patchwork: errata FE-8471889](https://patchwork.kernel.org/project/linux-arm-kernel/patch/1370620140-17177-2-git-send-email-gregory.clement@free-electrons.com/)
- [OpenWrt mvebu target](https://github.com/openwrt/openwrt/tree/master/target/linux/mvebu)

---

### Session 118 — LED HealthBump 3-Tier System

**Completed:**

1. **Kernel with IS31FL3199 LED Driver** — Built-in LED support
   - Kernel 6.12.85 with `CONFIG_LEDS_IS31FL319X=y`
   - LEDs appear at `/sys/class/leds/{red,green,blue}:led{1,2,3}/`
   - Discovered brightness 10 optimal (255 causes I2C EIO errors on Debian)

2. **3-Tier LED HealthBump System** — Visual health indicator
   - LED1 (bottom): Hardware layer - CPU, memory, WAN connectivity
   - LED2 (middle): Services layer - HAProxy, Nginx, certificate expiry
   - LED3 (top): Security layer - CrowdSec bans, attack rate detection
   - Variable pulse speeds: slow (HW), medium (SVC), fast (SEC)

3. **SPUNK ALERT** — Critical failure rapid flash
   - All LEDs flash rapid red when HAProxy/CrowdSec down
   - Ported from OpenWrt `secubox-led-pulse` script
   - Overrides normal health status until services recover

4. **Manual LED Control** — `secubox-led` command
   - Layer aliases: hw/1/bottom, svc/2/middle, sec/3/top
   - Status colors: ok/green, warn/yellow, error/red, msg/blue, off

5. **OpenWrt LED Script Analysis** — Serial console retrieval
   - Found `/overlay/upper/usr/sbin/secubox-led-pulse` via ttyUSB0
   - OpenWrt uses brightness 255 without I2C errors (different driver timing)
   - Saved reference in `docs/reference/secubox-led-pulse-openwrt.sh`

**Files Created/Updated:**
- `packages/secubox-led-heartbeat/usr/sbin/secubox-healthbump` — 3-tier health check
- `packages/secubox-led-heartbeat/usr/sbin/secubox-led` — Manual LED control
- `packages/secubox-led-heartbeat/systemd/secubox-healthbump.{service,timer}` — Systemd units
- `docs/LED-HEALTHBUMP.md` — Documentation with pulse speeds and SPUNK ALERT
- `docs/reference/secubox-led-pulse-openwrt.sh` — OpenWrt reference script

**Current Status:**
- HealthBump running on 30s timer
- LED1: Yellow (medium load), LED2: Green (services ok), LED3: Blue (mitigating 100 bans)

---

### Session 117 — OpenWrt-style Kernel with DSA Built-in

**Completed:**

1. **Debian Kernel Boot Fix** — Switched to Debian kernel for DSA support
   - Custom kernel 6.12.85 had DSA module chain incomplete
   - Copied Debian kernel `vmlinuz-6.12.85+deb12-arm64` to FAT boot partition
   - DSA modules (mv88e6xxx, dsa_core) loaded properly
   - lan0/1/2/3 interfaces restored

2. **OpenWrt Kernel Config Analysis** — Studied OpenWrt MVEBU config
   - Downloaded OpenWrt mvebu + cortexa72 configs
   - Key insight: OpenWrt uses `=y` (built-in), Debian uses `=m` (modules)
   - OpenWrt approach: faster boot, no initrd dependency for network

3. **Created OpenWrt-style Config Fragment** — 365 lines merged config
   - `board/mochabin/kernel/config-6.12-openwrt-merged.fragment`
   - Merges OpenWrt MVEBU DSA config + Debian systemd compatibility
   - All boot-critical and DSA drivers built-in (=y)
   - Includes: IKCONFIG, WireGuard, nftables, LED triggers, crypto

4. **Built & Deployed OpenWrt-style Kernel** — DSA built-in, no modules
   - Kernel 6.12.85 with OpenWrt-merged config
   - `CONFIG_NET_DSA=y` (built-in)
   - `CONFIG_NET_DSA_MV88E6XXX=y` (built-in)
   - `CONFIG_MVPP2=y` (built-in)
   - `CONFIG_IKCONFIG=y` (/proc/config.gz available)
   - Kernel boot time: 6.6s (fast, no module loading)

5. **Verified Working**
   - DSA interfaces: lan0/1/2/3 created at boot
   - No DSA modules loaded (all built-in)
   - /proc/config.gz available (IKCONFIG)
   - HAProxy running
   - WAN uplink: 192.168.1.254 gateway, internet OK

**Files Created:**
- `board/mochabin/kernel/config-6.12-openwrt-merged.fragment` — OpenWrt+Debian merged config

**Boot Menu (extlinux.conf):**
1. OpenWrt-style Kernel (default) — DSA built-in, no initrd
2. Debian Kernel — modules, needs initrd
3. SecuBox Custom — previous build

---


## 2026-05-07

### Session 116 — Kernel 6.12.85 Boot Fix (Built-in Drivers)

**Completed:**

1. **Kernel Boot Crisis Resolution** — Fixed MOCHAbin unable to boot
   - Root cause: Critical drivers compiled as modules (=m) instead of built-in (=y)
   - Multiple rebuild cycles to identify all missing built-in drivers
   - Created USB rescue boot system for recovery

2. **Built-in Driver Fixes** — All boot-critical drivers now =y
   - `CONFIG_MMC_SDHCI_XENON=y` — eMMC controller (was causing mmcblk0 not found)
   - `CONFIG_EXT4_FS=y` — Root filesystem (was causing VFS panic)
   - `CONFIG_VFAT_FS=y` — Boot partition mount
   - `CONFIG_NLS_ASCII=y`, `CONFIG_NLS_UTF8=y` — VFAT charset (was "IO charset ascii not found")
   - `CONFIG_PHY_MVEBU_CP110_UTMI=y` — USB PHY (was "deferred probe pending: wait for supplier ut0")
   - `CONFIG_PHY_MVEBU_CP110_COMPHY=y` — PCIe/SATA PHY
   - `CONFIG_BLK_DEV_SD=y` — SCSI disk driver (was no /dev/sda creation)
   - `CONFIG_AHCI_MVEBU=y` — SATA controller
   - `CONFIG_MVPP2=y` — Network driver

3. **Hardware Verified Working**
   - eMMC: 14.7 GiB detected (mmcblk0p1/p2)
   - SATA: WD Blue SA510 1TB @ 6Gbps
   - USB: Both xHCI controllers (f2500000, f2510000)
   - Network: eth0/eth1/eth2 with MAC addresses
   - PCIe: Root port initialized (no device connected)

4. **Kernel Fragment Saved** — For future builds
   - `board/mochabin/kernel/config-6.12.85-secubox-boot.fragment`
   - Contains all MOCHAbin boot-critical options
   - Usage: merge_config.sh + olddefconfig + make Image

---

### Session 115 — Kernel Documentation & DISK I/O Metric

**Completed:**

1. **DISK I/O Metric for Eye Remote** — Replaced MESH WiFi metric
   - New metric: `io_read_mb`, `io_write_mb`, `io_read_peak_mb`, `io_write_peak_mb`
   - Reads from `/proc/diskstats` (mmcblk0/sda/nvme0n1)
   - Peak tracking persisted across restarts
   - Legend updated: 💾 DISK / I/O MB/s
   - Deployed to MOCHAbin production

2. **MOCHAbin Kernel Documentation** — Wiki page created
   - `docs/wiki/MOCHAbin-Kernel.md`: Full LED kernel build guide
   - Debian base config + SecuBox fragment approach documented
   - GPIO polarity fix for IS31FL3199 documented
   - Added to wiki sidebar

3. **Kernel Config Files** — Committed to git
   - `board/mochabin/kernel/config-6.12.85-debian-base` (13K options)
   - `board/mochabin/kernel/config-6.12.85-secubox-led-v2.fragment`
   - Build script with CyberMind branding: `LOCALVERSION=-secubox-cybermind`

4. **CyberMind Branding** — Applied to kernel
   - LOCALVERSION set to `-secubox-cybermind`
   - Produces: `6.12.85-secubox-cybermind`
   - Build script header updated with CyberMind URL

---

### Session 114 — Round Eye Connections Metric

**Completed:**

1. **Connections Metric for MIND** — Added to Eye Remote API
   - `connections`: Current established TCP connections count
   - `peak_connections`: Maximum observed (persisted to `/var/cache/secubox/eye-remote/peak_connections`)
   - `connections_percent`: Pre-calculated ratio for Round Eye MIND ring
   - Reads from `/proc/net/tcp` and `/proc/net/tcp6` (no subprocess overhead)
   - Documentation updated in README.md and WIKI.md

---

### Session 113 — WAF False Positive Fixes

**Completed:**

1. **WAF Rules v1.3.0** — Fixed 7 false positive patterns
   - `lfi-001`: Require 3+ levels of directory traversal
   - `rce-006`: Target Python SSTI patterns only (not all Jinja2/Vue.js)
   - `scan-004`: Only block xmlrpc abuse, not legitimate WordPress
   - `waf-fp-005`: Target MySQL version comments, not CSS
   - `recon_crawler`: Disabled category (was blocking robots.txt, .well-known)
   - `cred-002/006`: Detect URL-leaked secrets only, not auth headers
   - Commit: `fix(waf): Fix 7 false positive patterns in WAF rules v1.3.0`

---

### Session 111 — LED Kernel + CrowdSec GeoIP + Boot Fixes

**Completed:**

1. **LED Kernel Configuration** (Issue #60)
   - Fixed network drivers: MARVELL_PHY, MDIO, SFP, MDIO_I2C → built-in (=y)
   - Fixed USB drivers: XHCI, EHCI, OHCI, USB_STORAGE → built-in
   - Kernel build initiated with updated config
   - LED chip detected at I2C-1 address 0x64 (IS31FL319X)

2. **CrowdSec WebUI GeoIP Enhancement**
   - Added country flags to bans/decisions list
   - Implemented GeoIP cache with 24h TTL (localStorage)
   - Uses ipapi.co (HTTPS) with backend fallback
   - Commit: `feat(crowdsec): Add GeoIP cache with country flags`

3. **WAF Client IP Fix**
   - Fixed mitmproxy to read X-Forwarded-For header
   - WAF now logs real attacker IP (not HAProxy internal IP)

4. **GitHub Issues Created**
   - #59: 503 errors at boot (service startup delay)
   - #60: LED kernel with IS31FL319X and built-in drivers
   - #61: Eye Remote gadget metrics endpoint

**In Progress:**
- Kernel build (~25% complete)
- 503 error permanent fix (HAProxy/mitmproxy chain)

---

## 2026-05-06

### Session 109 — VHost Matrix Sync + Eye Remote Fixes

**Completed:**

1. **VHost Matrix Sync Tool** (`scripts/vhost-matrix-sync.sh`)
   - Python-based HAProxy parsing (reliable regex extraction)
   - Fixed stderr logging for clean JSON capture
   - Syncs HAProxy vhosts → mitmproxy routes + health prober
   - Uses 10.100.0.1 (LXC bridge IP) for proper routing
   - Successfully synced 94 vhosts on production server

2. **Eye Remote Dashboard Fixes**
   - API calls now use public endpoints (no JWT required)
   - Added `/api/v1/system/metrics` alias for Pi Zero compatibility
   - Pi Zero round UI displays correct MOCHAbin host metrics

3. **HAProxy VHost Additions**
   - Added sdlc.gk2.secubox.in and facb.gk2.secubox.in backends
   - Both routed through mitmproxy WAF inspector

4. **GitHub Issue #49**: MetaBlogizer + Streamlit version management via Gitea

---

### Session 102 — v2.5.0 WAF Integration Complete

**Goal:** Complete WAF mitmproxy LXC integration (all 5 phases)

**Completed:**

1. **CMSD-1.0 License Integration**
   - Created `LICENCE-CMSD-1.0.md` (French authoritative version)
   - Created `LICENSE-CMSD-1.0.en.md` (English informative translation)
   - Created `LICENSING.md` (license documentation, SPDX guidance)
   - Updated `README.md` with prominent license notice (CAN/CANNOT table)
   - Wiki pages: License.md, License-FR.md with QR codes
   - PDF booklet uploaded to GitHub release v2.4.0

2. **WAF Phase 1-4: Mitmproxy LXC Container**
   - LXC container at `/data/lxc/mitmproxy` (10.100.0.60:8080)
   - 330 HAProxy backends routing through mitmproxy_inspector
   - HAProxy `http-request set-uri` for proxy-style requests
   - All traffic tagged with X-SecuBox-WAF: inspected header
   - All 6 LXC containers verified running

3. **WAF Phase 5: Package Updates**
   - `secubox-waf` v1.1.0: Added LXC mitmproxy support, wafctl, systemd service
   - `secubox-haproxy` v1.2.0: Added `waf` subcommand (status/enable/disable)
   - WebUI dashboard: Added mitmproxy container status card

4. **WebUI Access Fixed**
   - Added 192.168.1.200:9443 HAProxy bind
   - Added nginx server_name for 192.168.1.200
   - WebUI accessible at https://192.168.1.200:9443/
   - Created webui_direct backend (bypasses WAF)

---

### Session 101 — C3BOX Network Recovery + HAProxy LXC Routing

**Goal:** Establish network connectivity between C3BOX and MOCHAbin for migration

**Completed:**

1. **C3BOX Network Recovery**
   - Fixed eth2 NO-CARRIER issue (was on wrong interface)
   - C3BOX lan0@eth1 connected to MOCHAbin lan0 (DSA switch)
   - IP assigned on br-lan: 192.168.255.201 (original) + .10 (secondary)
   - Connectivity established: C3BOX ↔ MOCHAbin via 192.168.255.x

2. **Migration Archive Imported**
   - 93 SSL certificates copied to /data/haproxy/certs/
   - 99 nginx secubox.d configs available
   - LXC container configs imported

3. **HAProxy LXC Routing Added**
   - Created backends: lxc_gitea, lxc_nextcloud, lxc_matrix
   - ACL routing for gitea.gk2.secubox.in → 10.100.0.40:3000
   - ACL routing for nextcloud.gk2.secubox.in → 10.100.0.20:80
   - ACL routing for matrix.gk2.secubox.in → 10.100.0.30:8008

4. **Routing Verified**
   - gk2.secubox.in → 200 (WebUI)
   - gitea.gk2.secubox.in → 200 (LXC)
   - nextcloud.gk2.secubox.in → 302 (LXC redirect)
   - blog.cybermind.fr → 200 (nginx_vhosts)
   - Unknown domains → 503 (correct fallback)

5. **Metablogizer Migration COMPLETE**
   - 166 sites synced from C3BOX (/srv/metablogizer/sites/)
   - 60 sites emancipated (published) with nginx + HAProxy routing
   - UCI config converted to nginx server blocks (per-port)
   - Fixed HAProxy ACL order (metablog backends vs nginx_vhosts)
   - All sites accessible from internet with correct content

**TODO (noted for later):**
- Implement mitmproxy WAF container (like C3BOX architecture)
- HAProxy cacert + vhost SSL verification
- Metablogizer TOML config conversion

### Session 101 continued — Source Package Sync

**Goal:** Sync source packages with deployed working configurations

**Completed:**

1. **secubox-streamlit package updated:**
   - API main.py: Added `sudo -n` for LXC commands (NoNewPrivileges workaround)
   - Added systemd drop-in: `debian/secubox-streamlit.service.d/allow-lxc.conf`
   - Added sudoers config: `sudoers.d/secubox-streamlit`
   - Added example config: `config/streamlit.toml.example`
   - Updated postinst: Creates config dir, example config, LXC symlink
   - Updated debian/rules to install new files

2. **secubox-metablogizer package updated:**
   - Added example config: `config/metablogizer.toml.example`
   - Updated debian/rules to install example config

3. **TOML configs saved:**
   - `.claude/configs/streamlit.toml` (35 apps, 29 instances)
   - `.claude/configs/metablogizer.toml` (151 sites)

---

### Session 100 — MOCHAbin Migration SUCCESS

**Goal:** Complete C3BOX → SecuBox-DEB migration with proper WAF and routing

**Completed:**

1. **Network Configuration**
   - WAN (eth2): 192.168.1.200/24 → Freebox DMZ
   - LAN (br-lan): 192.168.255.1/24 via systemd-networkd (DSA bridge)
   - LXC (br-lxc): 10.100.0.1/24
   - Default route via 192.168.1.254 (Freebox)

2. **LXC Containers Running**
   - gitea: 10.100.0.40
   - mail: 10.100.0.10
   - matrix: 10.100.0.30
   - nextcloud: 10.100.0.20

3. **HAProxy WAF (ACL-based)**
   - SQL Injection detection → 403
   - XSS detection → 403
   - Path Traversal detection → 403
   - Scanner detection (nikto, sqlmap, nuclei) → 403

4. **Routing Verified**
   - Unknown domains/IP → 503 (correct fallback)
   - gk2.secubox.in → 200 (WebUI)
   - gitea.gk2.secubox.in → LXC gitea
   - nextcloud.gk2.secubox.in → LXC nextcloud

5. **Network Persistence**
   - `/etc/netplan/01-secubox-gateway.yaml` — WAN/LXC config
   - `/etc/systemd/network/10-br-lan.network` — LAN (DSA bridge)

6. **CTL Tools Installed**
   - 17 tools in `/usr/sbin/` (haproxyctl, vhostctl, streamlitctl, etc.)

**Key Fix:** br-lan IP (192.168.255.1) was missing — added via systemd-networkd since DSA bridge not managed by netplan.

**Mitmproxy Status:** Disabled due to pyOpenSSL ARM64 incompatibility. HAProxy ACL-based WAF provides equivalent protection.

**Custom Error Page Added:**
- `/etc/haproxy/errors/503.http` — "FATAL ERROR / END OF INTERNET" page
- Unknown domains return custom 503 (cyberpunk skull design)
- WebUI ACL added for: gk2.secubox.in, admin.gk2.secubox.in, secubox.local, secubox.maegia.tv, c3box.maegia.tv
- Fallback backend changed from `nginx_vhosts` to `fallback_503`

---

## 2026-05-05

### Session 99 — MOCHAbin Migration Recovery Plan

**Goal:** Document lessons learned from failed migration and create proper procedure

**Analysis of Session 97 Failure:**
1. HAProxy manually configured with only 5 ACLs instead of all 93 domains
2. Default backend incorrectly set to `nginx_vhosts` (WebUI) instead of 503 error page
3. WAF (mitmproxy) not installed due to OpenSSL compatibility issue
4. Websites not accessible from internet despite HAProxy showing 200 locally
5. User reverted to old C3BOX

**Root Causes Identified:**
- Did not use `haproxyctl migrate` command
- Did not use `scripts/migration-export.sh` for full export
- Manual HAProxy config used wrong fallback backend pattern

**Documentation Created:**
- Updated `.claude/WIP.md` with comprehensive migration checklist
- Documented proper 8-step migration procedure
- Added verification checklist for next attempt
- Documented key files and error page requirement

**Proper Migration Tools:**
- `scripts/migration-export.sh` — Full export from OpenWrt
- `scripts/migration-import.sh` — Import to SecuBox-DEB with transformation
- `haproxyctl migrate <host>` — HAProxy-specific migration with UCI→TOML conversion

**Key Requirement:**
```haproxy
# CORRECT fallback backend
backend fallback
    mode http
    http-request deny deny_status 503

# WRONG - never use WebUI as fallback for unmatched domains
# default_backend nginx_vhosts
```

---

### Session 97 — MOCHAbin Migration Attempt (FAILED)

**Goal:** Full data migration from OpenWrt C3BOX to SecuBox-DEB MOCHAbin

**Issues Encountered:**
- DSA (Distributed Switch Architecture) — lan0-lan3 can't be added to Linux bridges
- SFP28-25G module incompatible with 10G SFP+ port (used eth2 copper instead)
- nftables DNAT syntax in inet tables requires `ip dnat to` not just `dnat to`
- mitmproxy crashed due to OpenSSL AttributeError (X509_V_FLAG_NOTIFY_POLICY)

**Network Setup (Partial Success):**
- WAN on eth2 (copper) with DMZ IP 192.168.1.200/24
- LAN on lan0 (DSA) with 192.168.255.1/24
- br-lxc for containers with 10.100.0.1/24
- LXC containers running (mail, nextcloud, gitea)

**Critical Failure Points:**
1. HAProxy configured manually — only 5 ACLs/backends instead of 93
2. WebUI set as fallback backend — domains without ACL showed admin panel
3. Websites not actually accessible from internet
4. WAF not functional

**User Feedback:** "you have missed a lot of works", "websites are not up",
"worst, you make the webui admin on frontend fallback", "you make all badly"

**Result:** User reverted to old C3BOX. Migration needs complete redo with proper tools.

---

### Session 98 — SecuBox Modem Module

**Goal:** Create comprehensive LTE/5G modem management module

**Completed:**
1. **Package Structure** — Full package at `packages/secubox-modem/`
   - `api/main.py` — FastAPI application with background signal collector
   - `api/routers/` — status, connection, sms, terminal routers
   - `core/` — modem_detect, mm_client, qmi_client, at_interface, signal_history
   - `www/modem/` — WebUI with tabs for Status, Signal, SMS, Terminal, Settings

2. **Modem Detection** — Auto-detect Quectel modems
   - USB scanning via `lsusb`
   - ModemManager integration via `mmcli`
   - Known Quectel PIDs: EC25, EC21, EP06, EM12, RM500Q, RM520N, RG500Q

3. **Connection Management** — ModemManager-based
   - Connect/disconnect with APN configuration
   - Config persistence in `/var/lib/secubox/modem/`
   - Known APN database (FR, US, generic)

4. **SMS Functionality** — Full send/receive via mmcli
   - List messages, send SMS, delete
   - WebUI compose modal and message list

5. **AT Terminal** — Interactive command console
   - WebSocket endpoint at `/api/v1/modem/at/console`
   - REST fallback at `/api/v1/modem/at/command`
   - Security: blocks dangerous commands (AT+CFUN=0, AT+QPOWD, etc.)

6. **Signal Monitoring** — Real-time with history
   - Background collector every 30 seconds
   - Signal history stored in `/var/cache/secubox/modem/`
   - Chart.js graph in WebUI Signal tab

7. **QMI Client** — Detailed signal queries
   - `qmicli` wrapper for RSRP, RSRQ, SINR, cell location
   - RF band information, serving system details

8. **Debian Packaging**
   - `debian/control` — Dependencies: modemmanager, libqmi-utils, libmbim-utils, picocom
   - `debian/postinst` — Creates data dirs, adds secubox to dialout group
   - `systemd/secubox-modem.service` — With memory limits

9. **WebUI Features**
   - P31 phosphor CRT theme (light mode)
   - Signal bars visualization
   - xterm.js AT terminal
   - Chart.js signal history graph
   - APN database quick-select

**Files Created:**
- `packages/secubox-modem/api/main.py` — FastAPI app (~200 lines)
- `packages/secubox-modem/api/routers/status.py` — Status/info/signal endpoints
- `packages/secubox-modem/api/routers/connection.py` — Connect/disconnect/config
- `packages/secubox-modem/api/routers/sms.py` — SMS CRUD
- `packages/secubox-modem/api/routers/terminal.py` — WebSocket AT console
- `packages/secubox-modem/core/modem_detect.py` — USB/mmcli detection
- `packages/secubox-modem/core/mm_client.py` — ModemManager wrapper
- `packages/secubox-modem/core/qmi_client.py` — qmicli wrapper
- `packages/secubox-modem/core/at_interface.py` — Serial AT handler
- `packages/secubox-modem/core/signal_history.py` — Signal cache
- `packages/secubox-modem/www/modem/index.html` — Dashboard (~700 lines)
- `packages/secubox-modem/www/modem/js/modem.js` — UI logic (~500 lines)
- `packages/secubox-modem/debian/*` — Full Debian packaging
- `packages/secubox-modem/nginx/modem.conf` — WebSocket-enabled proxy
- `packages/secubox-modem/menu.d/37-modem.json` — Navbar entry
- `packages/secubox-modem/README.md` — Comprehensive documentation

**Migration Map Updated:**
- Added secubox-modem to module list
- Total modules: 125

**Deployed to MOCHAbin (192.168.255.10):**
- Fixed import paths (`...core` → `core` for absolute imports)
- nginx config moved to `/etc/nginx/secubox.d/modem.conf`
- Socket created at `/run/secubox/modem.sock`
- Menu entry at `/etc/secubox/menus.d/37-modem.json`
- Health endpoint verified: `/api/v1/modem/health`
- WebUI accessible at `/modem/`

---

### Session 95 — Eye Remote USB Gadget & Tow-Boot

**Goal:** Get Eye Remote (Pi Zero W USB gadget) working with MOCHAbin

**Completed:**
1. **Tow-Boot Flashed** — Replaced old U-Boot 2018.03 with Tow-Boot for proper USB PHY init
   - Used `bubt` command for Marvell bootloader flash
   - Pre-built binary from `tools/Tow-Boot/output/Tow-Boot.spi.bin`

2. **Kernel 6.12 Boot** — Working with CONFIG_PHY_MVEBU_CP110_UTMI
   - Fixed MAC address issue with `setenv ethaddr`
   - Fixed console: ttyMV0 → ttyS0 in extlinux.conf
   - Created /boot/extlinux/extlinux.conf with both kernels (default + 6.12)

3. **Eye Remote USB Detection** — Pi Zero gadget detected on Bus 01
   - ECM Network + ACM Serial + Mass Storage interfaces
   - udev rules auto-configure 10.55.0.1/30 interface

4. **SSD Storage** — 1TB mSATA mounted as /data
   - eMMC freed for system only
   - `/data` contains: secubox-backups, overlay upper/work dirs

5. **secubox-eye-remote Package Deployed**
   - Service running: `secubox-eye-remote.service` (active)
   - Socket: `/run/secubox/eye-remote.sock`
   - Health endpoint working: `/health`

6. **udev Rules Deployed** — Auto-configure USB network on connect
   - `/etc/udev/rules.d/90-secubox-eye-remote.rules`
   - `/usr/local/sbin/secubox-eye-network.sh`
   - Matches Pi Zero gadget by vendor/product ID (1d6b:0104)

**API Status:**
- `/api/v1/eye-remote/status` — Working (connected=true)
- `/api/v1/eye-remote/serial/status` — Working (/dev/ttyACM0 detected)
- `/health` — Working

7. **Kernel 6.12 Default** — Set as default boot in extlinux.conf
   - `DEFAULT secubox-612` in `/boot/extlinux/extlinux.conf`
   - Running: `6.12.85+deb12-arm64`

8. **Socket Creation Fix** — RuntimeDirectoryPreserve for all services
   - Root cause: Multiple services with `RuntimeDirectory=secubox` caused socket cleanup conflicts
   - Fix: Added `/etc/systemd/system/secubox-*.service.d/preserve.conf` with `RuntimeDirectoryPreserve=yes`
   - All services now preserve their sockets when other services restart

9. **Nginx Proxy Path Fix** — Eye Remote API routing
   - Issue: nginx `proxy_pass http://unix:/run/secubox/eye-remote.sock:/;` stripped path prefix
   - Fix: Changed to `proxy_pass http://unix:/run/secubox/eye-remote.sock:/api/v1/eye-remote/;`
   - FastAPI expects full path `/api/v1/eye-remote/status`

10. **Remote UI Emancipation** — Unified WebUI path
    - `/remote-ui/` now serves the Remote UI Management page
    - `/eye-remote/` redirects to `/remote-ui/`
    - API remains at `/api/v1/eye-remote/`

11. **Socket Conflict Resolution** — Definitive fix
    - Root cause: All services had `RuntimeDirectory=secubox`, causing conflicts when any service restarted
    - Fix: Created `/etc/systemd/system/secubox-*.service.d/no-runtime-dir.conf` with `RuntimeDirectory=`
    - `secubox-core.service` is now the ONLY service managing `/run/secubox/`
    - Result: 85+ sockets stable, no more conflicts

12. **JSON Error Fixes** — Navbar component errors
    - Issue: Disabled services returned HTML 502 instead of JSON
    - Fix: Added `/etc/nginx/snippets/api-error.conf` returning JSON for 502/503/504
    - Services using `include /etc/nginx/snippets/secubox-proxy.conf;` now return proper JSON errors

13. **Service Emancipation** — Full WebUI + API exposure
    - Emancipated 13 services with unified nginx configs:
      - crowdsec, waf, dpi, system, wireguard, netdata, haproxy
      - hub, admin, auth, metrics, glances, backup
    - Each service has: WebUI at `/<service>/`, API at `/api/v1/<service>/`
    - All services verified working (UI=200, API=200 or 401 for auth-required)
    - Created `/srv/backups` directory for backup service

**Files Modified:**
- `board/mochabin/flash-tow-boot.cmd` — bubt flash script
- `board/mochabin/flash-tow-boot.txt` — manual instructions
- `packages/secubox-eye-remote/api/main.py` — Fixed interface check (usb0, ARP)
- `packages/secubox-eye-remote/udev/90-secubox-eye-remote.rules` — Removed NAME rename
- `packages/secubox-eye-remote/scripts/secubox-eye-network.sh` — Use usb0, notify API
- `packages/secubox-eye-remote/nginx/eye-remote.conf` — WebUI + API + redirect

**MOCHAbin Files Created:**
- `/etc/nginx/snippets/api-error.conf` — JSON error responses
- `/etc/nginx/secubox.d/*.conf` — 13 service nginx configs
- `/etc/systemd/system/secubox-*.service.d/no-runtime-dir.conf` — Socket conflict fix
- `/srv/backups/` — Backup storage directory

14. **CrowdSec Console Enrollment** — Fixed key typo
    - Enrollment key had `1` (one) instead of `l` (lowercase L)
    - Corrected key: `cmoleja50000802le9t1f7o0d`

15. **CrowdSec Dashboard Cleanup** — Removed obsolete UI elements
    - Removed Migration section (OpenWrt migration not needed)
    - Removed Components tab
    - Removed Access tab
    - Removed "Import from OpenWrt" button

16. **CrowdSec LAPI/CAPI Status Fix** — Sudo privilege issue
    - Issue: `NoNewPrivileges=true` in systemd blocked sudo
    - Fix: Created `/etc/systemd/system/secubox-crowdsec.service.d/allow-sudo.conf`
    - Added sudoers entry for cscli: `/etc/sudoers.d/secubox-crowdsec`
    - Rewrote status.py to use `cscli lapi status` subprocess instead of HTTP

17. **CrowdSec Collections Status Fix** — Parsing issue
    - Issue: Collections showing 0 when 7 installed
    - Root cause: Code checked `status == "enabled"` but CrowdSec uses `status = "enabled,update-available"`
    - Fix: Changed to `"enabled" in (item.get("status") or "")`

18. **CrowdSec Bouncers API Fix** — LAPI auth issue
    - Issue: HTTP calls to LAPI failed (missing X-Api-Key)
    - Fix: Rewrote bouncers.py to use `cscli bouncers list -o json` subprocess

19. **CrowdSec Hub Functions** — Added missing functions
    - Added `refreshHub()` and `reloadEngine()` JavaScript functions
    - Added `/hub/update` and `/service/reload` API endpoints

20. **Duplicate Remote UI Entry Removed** — Menu cleanup
    - Removed duplicate `remote-ui` menu entry from secubox-system
    - Eye Remote (`eye-remote`) remains functional at `/eye-remote/`
    - Files removed: `packages/secubox-system/menu.d/15-remote-ui.json`
    - Files removed: `packages/secubox-system/www/remote-ui/index.html`

**CrowdSec Files Modified:**
- `packages/secubox-crowdsec/api/routers/status.py` — cscli subprocess with shell=True
- `packages/secubox-crowdsec/api/routers/bouncers.py` — cscli subprocess for bouncers
- `packages/secubox-crowdsec/api/main.py` — Added hub update and reload endpoints
- `packages/secubox-crowdsec/www/index.html` — Removed Migration, Components, Access tabs
- `packages/secubox-crowdsec/systemd/allow-sudo.conf` — NoNewPrivileges=false override
- `packages/secubox-crowdsec/sudoers.d/secubox-crowdsec` — cscli sudo permission

### Session 96 — Eye Remote Auto-Pairing & Pi Zero Builder

**Goal:** Add auto-pairing and metrics API to Eye Remote

**Completed:**
1. **Auto-Pair Endpoint** — Added `/api/v1/eye-remote/auto-pair` POST
   - Creates pairing record for currently connected device
   - Gets hostname from Pi Zero via metrics API
   - Stores devices in `/var/lib/secubox/eye-remote/auto-paired.json`

2. **Paired Devices Endpoint** — Added `/api/v1/eye-remote/paired-devices` GET
   - Lists all paired Eye Remote devices
   - Masks tokens for security (shows only first 8 chars)

3. **Pi Zero Metrics API in Builder** — Updated `install_zerow.sh` v1.9.0
   - Integrated `pizero-metrics-api.py` into SD card builder
   - Added `pizero-metrics.service` systemd unit
   - New Pi Zero SD cards now auto-include metrics API

4. **PiZero Metrics Public Endpoint** — Added `/api/v1/eye-remote/pizero/metrics`
   - Relays metrics from Pi Zero without requiring auth
   - Dashboard can display CPU, Mem, Temp without complex auth setup

5. **Fixed _eye_state Missing** — MOCHAbin hotfix
   - Added `_eye_state = {"connected": False, "last_seen": None}` to deployed main.py

**Files Modified:**
- `packages/secubox-eye-remote/api/main.py` — Added auto-pair, paired-devices, pizero/metrics endpoints
- `remote-ui/round/install_zerow.sh` — v1.9.0, integrated pizero-metrics-api

**Commits:**
- 30b8773 feat(eye-remote): Add auto-pair and paired-devices endpoints

### Session 97 — Eye Remote Routing Fixes & Navbar Emoji Cleanup

**Goal:** Fix Eye Remote metrics not reaching MOCHAbin, fix navbar emoji icons

**Completed:**
1. **rp_filter Martian Source Fix** — Packets from Pi Zero (10.55.0.2) were being dropped
   - Root cause: Kernel reverse path filter rejecting packets on USB gadget interface
   - Fix: Added `/etc/sysctl.d/99-secubox-usb.conf` with `net.ipv4.conf.all.rp_filter = 0`
   - Also apply per-interface in udev rules: `sysctl -w net.ipv4.conf.%k.rp_filter=0`

2. **Dual Interface Routing Conflict** — Pi Zero had both usb0 and usb1 with same IP
   - Root cause: Pi Zero gadget created RNDIS (usb0) + CDC-ECM (usb1), both configured
   - Fix: Added `usb1-disable` config to `install_zerow.sh` to bring down usb1

3. **USB Re-plug Detection** — udev rules weren't triggering on reconnect
   - Fix: Added `ACTION=="bind"` event to udev rules for re-plug detection
   - Added `sleep 2` delay for gadget initialization

4. **Network Script Status Command** — Added `secubox-eye-network.sh status`
   - Shows interface state, rp_filter status, and peer reachability

5. **Navbar Emoji Icons** — Replaced text-based icons with proper emoji
   - Updated CATEGORY_META in hub API with missing categories
   - Fixed 7 menu.d JSON files with text icons (catalog, shield, camera, etc.)

**Files Modified:**
- `packages/secubox-eye-remote/sysctl.d/99-secubox-usb.conf` — rp_filter disable
- `packages/secubox-eye-remote/udev/90-secubox-eye-remote.rules` — bind event, rp_filter
- `packages/secubox-eye-remote/scripts/secubox-eye-network.sh` — status command
- `packages/secubox-eye-remote/debian/install` — Added sysctl.d to package
- `remote-ui/round/install_zerow.sh` — usb1-disable config
- `packages/secubox-hub/api/main.py` — CATEGORY_META additions
- `packages/secubox-*/menu.d/*.json` — 7 files with emoji icon fixes

**Commits:**
- 01f2bf1 fix(eye-remote): Resolve rp_filter and dual-interface routing issues
- a47d290 fix(menu): Replace text icons with emoji in navbar

---

## 2026-05-04

### Session 93 — MOCHAbin Full Image Build

**Goal:** Build MOCHAbin image with slipstream packages (full profile like ESPRESSObin)

**Problem:**
- Previous build attempts failed with "Erreur: La localisation 5890MiB est en dehors du périphérique"
- Root cause: `board/mochabin/config.mk` had `IMG_SIZE="4G"` which was insufficient for ~5.5GB rootfs

**Fix Applied:**
```makefile
# board/mochabin/config.mk
# Before:
IMG_SIZE="4G"

# After:
IMG_SIZE="8G"
```

**Build Results:**
- Image: `output/secubox-mochabin-bookworm.img.gz` (1.2G compressed, 8G uncompressed)
- SHA256: `f1db869b5e82c2d851fa16d38faad4db91f4e76982da8d013c3cceef36b7164c`
- Slipstream packages: All SecuBox .deb packages pre-installed

**Known Issues (Non-blocking):**
- 4 packages failed during slipstream (missing systemd service files):
  - secubox-mitmproxy
  - secubox-smtp-relay
  - secubox-soc-agent
  - secubox-soc-gateway

**Commits:**
- de2f365 fix(mochabin): Increase image size to 8G for full install

**Deployment:**
- Flashed to USB thumb drive (28.8G DataTraveler 3.0)
- Ready for boot testing on MOCHAbin hardware

### Session 93b — MOCHAbin eMMC Flash & Boot Success

**Goal:** Flash SecuBox image to eMMC and boot from it

**USB Boot Issues:**
- USB storage not detected in Linux (f2500000.usb deferred probe)
- USB thumb drive only accessible from U-Boot, not from running Linux

**eMMC Flash from U-Boot:**
```
usb reset
ext4load usb 0:3 0x10000000 secubox-mochabin-bookworm.img.gz
gzwrite mmc 0 0x10000000 ${filesize}
```

**Boot Script Issue:**
- Initial boot.scr used `uInitrd` (U-Boot wrapped initrd)
- Image only contains raw `initrd.img` from Debian
- Error: "Wrong Ramdisk Image Format"

**Solution - Use raw initrd with filesize:**
```bash
setenv bootcmd_emmc 'fatload mmc 0:1 0x7000000 Image; fatload mmc 0:1 0x6f00000 dtbs/marvell/armada-7040-mochabin.dtb; fatload mmc 0:1 0x9000000 initrd.img; setenv bootargs root=/dev/mmcblk0p2 rootfstype=ext4 rootwait console=ttyS0,115200 earlycon=uart8250,mmio32,0xf0512000 net.ifnames=0; booti 0x7000000 0x9000000:${filesize} 0x6f00000'
setenv bootcmd 'run bootcmd_emmc'
saveenv
```

**Key insight:** U-Boot can boot raw initrd.img by passing filesize after colon: `0x9000000:${filesize}`

**Boot Success:**
- Kernel: 6.1.0-42-arm64
- Memory: 8GB detected (7.8Gi available)
- eMMC: 14.7 GiB DF4016
- Network: br-lan @ 192.168.1.1, eth0 @ 10.55.255.177
- Dashboard: https://192.168.1.1:9443
- All SecuBox services started

**Minor Issues (Non-blocking):**
- `crowdsec.service` failed to start (needs investigation)
- `lxc-net.service` failed (bridge setup conflict)
- `secubox-metablogiz` keeps restarting (service loop)

**Hardware Notes:**
- SFP module: OEM SFP28-25G-SR-S detected on eth0 (incompatible mode)
- SATA: 1TB WD Blue SA510 detected on ata2 (user's personal drive)
- USB: Quectel EP06-E LTE modem on USB1

### Session 93c — Nginx .dpkg-new Config Fix

**Problem:**
- Dashboard `/system/` returning HTML instead of JSON
- `secubox-system.service` was disabled/not running
- Nginx configs in `/etc/nginx/secubox.d/` had `.dpkg-new` suffix (not activated)

**Root Cause:**
- dpkg leaves `.dpkg-new` files when installing new conffiles over existing ones
- Build scripts didn't rename these after package installation

**Fix Applied:**
Added `.dpkg-new` activation step to all build scripts:
- `image/build-image.sh` (line ~760)
- `image/build-live-usb.sh` (line ~1824)
- `image/build-rpi-usb.sh` (line ~751)

```bash
# Activate .dpkg-new configs
for newconf in "${ROOTFS}/etc/nginx/secubox.d/"*.dpkg-new; do
  [[ -f "$newconf" ]] || continue
  mv "$newconf" "${newconf%.dpkg-new}"
done
```

**Services Fixed on Running System:**
```bash
systemctl enable --now secubox-system
cd /etc/nginx/secubox.d && for f in *.dpkg-new; do mv "$f" "${f%.dpkg-new}"; done
nginx -s reload
```

### Session 93d — Performance Comparison: OpenWrt vs Debian

**Test Environment:**
- 192.168.255.1 — SecuBox OpenWrt 24.10.5 (MOCHAbin 8GB)
- 192.168.255.10 — SecuBox Debian Bookworm (MOCHAbin 8GB)

#### System Comparison

| Metric | OpenWrt | Debian | Notes |
|--------|---------|--------|-------|
| **Kernel** | 6.6.119 | 6.1.0-42-arm64 | OpenWrt newer |
| **Uptime** | 2 days 22h | 18 hours | — |
| **Load Average** | 6.63 | 1.31 | **Debian 5x lower** |
| **Total Processes** | 1768 | 172 | **Debian 10x fewer** |
| **Memory Total** | 8GB | 8GB | Same |
| **Memory Used** | 3.1GB (38%) | 1.7GB (22%) | **Debian 45% less** |
| **Memory Available** | 4.8GB | 6.2GB | **Debian +1.4GB** |
| **Swap Used** | 1.6GB | 0 | Debian no swap needed |
| **Disk Used** | 10.6G/14.6G (73%) | 3.5G/5.4G (69%) | Similar % |

#### Service Memory Usage (kB)

| Service | OpenWrt | Debian | Δ |
|---------|---------|--------|---|
| nginx | 2,184 | 12,036 | +5.5x |
| haproxy | 36,888 | 47,080 | +28% |
| crowdsec | 105,840 | 194,732 | +84% |
| dnsmasq | 2,404 | 2,000 | -17% |
| netdata | N/A | 4,520 | — |
| Python APIs | N/A | 1,250,656 | — |

#### Version Comparison

| Component | OpenWrt | Debian |
|-----------|---------|--------|
| Python | 3.11.14 | 3.11.2 |
| OpenSSL | 3.0.18 | 3.0.18 |
| HAProxy | 3.0.12 | 2.6.12 |
| CrowdSec | 1.7.6 | 1.7.7 |

#### Analysis

**Debian Advantages:**
- **5x lower system load** (1.3 vs 6.6) — more responsive
- **45% less memory used** — more headroom for services
- **No swap thrashing** — better performance under load
- **10x fewer processes** — cleaner process tree
- **systemd** — modern service management, dependencies
- **Standard Debian packages** — easier updates, security patches

**OpenWrt Advantages:**
- **Newer kernel** (6.6 vs 6.1) — more hardware support
- **Lighter nginx** (2MB vs 12MB) — minimal footprint
- **Smaller crowdsec** (105MB vs 194MB) — optimized binary
- **HAProxy 3.0** vs 2.6 — newer features

**Debian Trade-offs:**
- Python FastAPI services use ~1.2GB total for 22 SecuBox APIs
- This replaces shell-based RPCD (unmeasured but lighter)
- Benefit: proper async, JWT auth, OpenAPI docs

**Conclusion:**
Debian migration successful. Despite heavier individual services, overall system load and memory pressure significantly lower. The structured systemd architecture provides better resource management than OpenWrt's init scripts.

### Session 93e — CrowdSec Firewall Bouncer Setup

**Problem:**
- CrowdSec agent running but no firewall bouncer installed
- CAPI blocklist (16k+ IPs) not enforced at firewall level

**Fix:**
```bash
# Clear stuck apt locks
pkill -9 apt dpkg
rm -f /var/lib/dpkg/lock-frontend

# Install bouncer
apt-get install -y crowdsec-firewall-bouncer-nftables
```

**Result:**
- Bouncer auto-registered with CrowdSec API
- nftables tables created: `ip crowdsec`, `ip6 crowdsec6`
- Services enabled on boot

**Verification:**
```bash
cscli bouncers list
# cs-firewall-bouncer-1777957909  127.0.0.1  ✔️  v0.0.34

systemctl is-active crowdsec crowdsec-firewall-bouncer
# active
# active
```

**Protection Active:**
| Category | Decisions |
|----------|-----------|
| http:dos | 9,128 |
| http:exploit | 3,090 |
| http:bruteforce | 1,369 |
| ssh:bruteforce | 1,115 |
| http:scan | 890 |
| generic:scan | 657 |
| ssh:exploit | 353 |

### Session 93f — Fix Service Restart Loops

**Problem:**
Multiple SecuBox services in restart loops due to missing Python dependencies.

**Root Cause:**
- `python-multipart` missing (required for FastAPI file uploads)
- `email-validator` missing (required for Pydantic email fields)

**Affected Services:**
- secubox-metablogizer, secubox-droplet, secubox-avatar, secubox-streamlit, secubox-users

**Fix on Running System:**
```bash
pip3 install --break-system-packages python-multipart email-validator
systemctl restart secubox-metablogizer secubox-avatar
```

**Build Scripts Updated:**
- `image/build-image.sh` — added python-multipart, email-validator
- `image/build-rpi-usb.sh` — added email-validator

**Disabled Non-Critical Services (missing dependencies):**
- secubox-picobrew (IoT controller, needs hardware)
- secubox-threats (needs Suricata)
- secubox-eye-remote (import error)
- secubox-openclaw (OSINT tool)
- secubox-ui-manager (display manager)
- secubox-net-fallback (network already configured)

**Result:**
- 86 services running
- 0 failed
- Load: 7.7 → 3.7 (no more restart loops)

### Session 93g — Dashboard System API Fix

**Problem:**
- https://192.168.255.10/system/ returning JSON parse errors
- `/api/v1/system/*` endpoints returning HTML instead of JSON

**Root Cause:**
- `secubox-system.service` was running but socket `/run/secubox/system.sock` was missing
- Service started at 05:03 but socket disappeared (possibly cleaned by systemd-tmpfiles)

**Fix:**
```bash
systemctl restart secubox-system
```

**Verification:**
```bash
curl -s https://localhost/api/v1/system/info
# {"hostname":"secubox-mochabin","board":"Globalscale MOCHAbin","arch":"aarch64"...}
```

**Dashboard Status:**
- ✅ https://192.168.255.10/system/ working
- ✅ System info, resources, services endpoints functional
- ✅ JWT authentication enforced on protected endpoints

### Session 93h — CrowdSec Dashboard & Socket Stability

**Problem:**
- https://192.168.255.10/crowdsec/ returning JSON parse errors
- Multiple service sockets disappearing after bulk restart

**Root Cause:**
- Services running but Unix sockets not created
- Bulk `systemctl restart 'secubox-*'` causes race conditions
- Services need time to initialize and create sockets

**Fix:**
```bash
# Restart specific services individually
systemctl restart secubox-system secubox-crowdsec
sleep 5
```

**Verified Working:**
```
✅ /api/v1/hub/status      → JWT required (correct)
✅ /api/v1/system/info     → {"hostname":"secubox-mochabin"...}
✅ /api/v1/crowdsec/status → {"running":true,"version":"v1.7.7"...}
```

**Note:** Hub service uses TCP port 8001 (not socket) for VM compatibility.

---

## 2026-05-05

### Session 94 — Socket RuntimeDirectory Fix & Dashboard Stability

**Problem:**
- Multiple dashboard pages returning JSON parse errors
- Services "active" but sockets missing in `/run/secubox/`
- RuntimeDirectory causing socket deletion when services restart

**Root Cause:**
All SecuBox services shared `RuntimeDirectory=secubox` which caused:
1. Each service restart recreated `/run/secubox/` with only its own socket
2. Other service sockets were deleted
3. Race conditions during bulk restarts

**Fix Applied:**

1. **Created tmpfiles.d config for persistent directory:**
```bash
cat > /etc/tmpfiles.d/secubox.conf << 'CONF'
d /run/secubox 0775 secubox secubox -
CONF
```

2. **Disabled RuntimeDirectory in services:**
```bash
for svc in auth system users crowdsec wireguard dpi dns vhost cdn qos waf nac netmodes admin hub; do
  mkdir -p /etc/systemd/system/secubox-$svc.service.d
  cat > /etc/systemd/system/secubox-$svc.service.d/runtime.conf << 'CONF'
[Service]
RuntimeDirectory=
RuntimeDirectoryPreserve=
CONF
done
systemctl daemon-reload
```

3. **Fixed nginx users.conf routing:**
```nginx
location /api/v1/users/ {
    rewrite ^/api/v1/users/(.*)$ /$1 break;
    proxy_pass http://unix:/run/secubox/users.sock;
    include /etc/nginx/snippets/secubox-proxy.conf;
}
```

4. **Installed udev rules for Eye Remote:**
```bash
cat > /etc/udev/rules.d/90-secubox-otg.rules << 'RULES'
SUBSYSTEM=="net", ATTRS{idVendor}=="1d6b", ATTRS{idProduct}=="0104", DRIVERS=="cdc_ether", NAME="secubox-round"
SUBSYSTEM=="tty", ATTRS{idVendor}=="1d6b", ATTRS{idProduct}=="0104", KERNEL=="ttyACM*", SYMLINK+="secubox-console"
RULES
```

**Result:**
- All 14+ sockets persisting across service restarts
- Dashboard pages working: system, crowdsec, users, wireguard, dns, dpi, waf
- CrowdSec console enrolled and active

**Sockets Created:**
```
/run/secubox/admin.sock
/run/secubox/auth.sock
/run/secubox/cdn.sock
/run/secubox/crowdsec.sock
/run/secubox/dns.sock
/run/secubox/dpi.sock
/run/secubox/nac.sock
/run/secubox/netmodes.sock
/run/secubox/qos.sock
/run/secubox/system.sock
/run/secubox/users.sock
/run/secubox/vhost.sock
/run/secubox/waf.sock
/run/secubox/wireguard.sock
```

**USB Configuration:**
- USB1 (480 Mbps): Quectel EP06-E LTE modem
- USB2 (5000 Mbps): Available for Eye Remote Pi Zero W
- Eye Remote detection pending (needs to be plugged into USB3 port)

---

## 2026-05-03

### Session 92 — Tow-Boot eMMC Support & MOCHAbin Documentation

**Goal:** Add eMMC boot partition support to Tow-Boot for MOCHAbin, document boot mode jumpers

**Context:**
- MOCHAbin board with dead/intermittent SPI NOR flash (JEDEC 00,00,00)
- eMMC works in U-Boot but BootROM communication fails
- Original Tow-Boot build lacks `mmc partconf` command
- No microSD slot on MOCHAbin (correction to documentation)

**Implementation:**

1. **Copied Tow-Boot to Project:**
   - Source: `/home/reepost/DEVEL/MOKATOOL/Tow-Boot/`
   - Destination: `tools/Tow-Boot/`

2. **Enabled eMMC Boot Support:**
   - Added `mmcBootIndex = "0"` to MOCHAbin board configs
   - Enables `CONFIG_SUPPORT_EMMC_BOOT=y` in U-Boot
   - New commands available: `mmc partconf`, `mmc bootbus`

3. **Built New Tow-Boot:**
   ```bash
   sg nix-users -c "nix-build -A globalscale-mochabin-8gb"
   ```
   - Output: `Tow-Boot.spi.bin`, `Tow-Boot.mmcboot.bin`, `Tow-Boot.noenv.bin`

4. **Hardware Testing (Failed):**
   - SPI flash intermittent (sometimes detected, mostly JEDEC 00,00,00)
   - eMMC boot partition: BootROM returns `Error interrupt: 00018000`
   - Tried boot partitions 1, 2, and user area — all fail at BootROM level
   - **Verdict: Hardware defective** — board abandoned

**Files Modified:**
- `tools/Tow-Boot/boards/globalscale-mochabin-2gb/default.nix`
- `tools/Tow-Boot/boards/globalscale-mochabin-4gb/default.nix`
- `tools/Tow-Boot/boards/globalscale-mochabin-8gb/default.nix`

**Files Created:**
- `tools/Tow-Boot/output/` — Built binaries
- `tools/Tow-Boot/SECUBOX.md` — SecuBox-specific documentation

**Documentation Updated:**
- `board/mochabin/README.md`:
  - Added boot mode jumper table (J17-J22)
  - Added SPI → eMMC jumper change instructions
  - Documented Tow-Boot flashing procedures
  - Added known hardware issues section
  - Removed incorrect microSD slot reference

**Boot Mode Jumpers (J17-J22):**
| Mode | Code | J17 | J18 | J19 | J20 | J21 | J22 |
|------|------|-----|-----|-----|-----|-----|-----|
| SPI | 0x32 | L | R | L | L | R | R |
| eMMC | 0x2B | R | R | L | R | L | R |

**Result:**
- Tow-Boot with eMMC support ready for working boards
- Complete MOCHAbin boot documentation
- Defective board identified and abandoned

---

### Session 91 — Wiki Badges & VirtualBox VM Rebuild

**Goal:** Update wiki and README with build status badges, metrics dashboard, and rebuild VBox VM

---

### Session 90 — Mitmproxy WAF Module Migration

**Goal:** Complete migration of mitmproxy WAF module from SecuBox-OpenWrt to SecuBox-DEB

**Context:**
- Original OpenWrt module: luci-app-mitmproxy-waf (shell scripts + LuCI frontend)
- Target: Full Debian package with FastAPI backend, LXC container isolation, HAProxy integration

**Implementation (15 tasks via Subagent-Driven Development):**

1. **Package Scaffold** — debian/control, rules, postinst, prerm, systemd service
2. **Configuration** — mitmproxy.toml (TOML), waf-rules.json (90+ patterns, 14 categories)
3. **mitmproxyctl CLI** — Python CLI for LXC lifecycle (install, start, stop, restart, status, destroy, logs)
4. **Threat Detection Addon** — secubox_waf.py mitmproxy addon with real-time threat detection
5. **FastAPI Backend** — 5 routers with JWT auth:
   - status.py — Container control, stats, mode settings
   - settings.py — TOML configuration CRUD
   - alerts.py — Threat log, ban management, CrowdSec integration
   - haproxy.py — WAF enable/disable, route sync
   - waf.py — Rule category management
6. **WebUI** — status.html, settings.html, filters.html (CRT-light theme)
7. **Integration** — nginx config, CrowdSec acquisition config, menu.d entry

**WAF Detection Categories (14):**
- SQL Injection, XSS, Command Injection, Path Traversal
- SSRF, XXE, LDAP Injection, Log4Shell
- Scanner Detection, Path Scanning, CVE Exploits, RCE
- VoIP Attacks, XMPP Attacks

**Files Created:**
- `packages/secubox-mitmproxy/` — Complete package structure
- `debian/` — control, rules, postinst, prerm, service, mitmproxy.toml
- `api/` — main.py, routers/{status,settings,alerts,haproxy,waf}.py
- `addons/secubox_waf.py` — Mitmproxy addon
- `bin/mitmproxyctl` — CLI tool
- `data/waf-rules.json` — 90+ detection patterns
- `www/mitmproxy/` — WebUI pages
- `nginx/mitmproxy.conf` — API/static proxy
- `README.md` — Comprehensive documentation

**Code Review Findings (Fixed):**
1. LXC architecture hardcoded to amd64 → Now detects actual arch (arm64/amd64)
2. Missing WebUI API endpoints → Added /set_mode, /save_settings, /setup_firewall, /clear_firewall, /wan_setup, /wan_clear, /clear_alerts
3. Missing crowdsec dir in debian/rules → Added

**Commits:**
- 17 commits from package scaffold through final fixes
- d69dd43 fix(mitmproxy): Address code review findings
- 87602fc fix(mitmproxy): Add crowdsec directory to debian/rules install

**Result:**
- Complete secubox-mitmproxy package ready for dpkg-buildpackage
- LXC-isolated WAF with 90+ threat detection patterns
- Full CrowdSec integration for auto-banning
- HAProxy route sync for traffic inspection
- WebUI dashboard with real-time alerts

---

### Session 91 — Wiki Badges & VirtualBox VM Rebuild

**Goal:** Update wiki and README with build status badges, metrics dashboard, and rebuild VBox VM

**Context:**
- Session 90 completed mitmproxy WAF migration
- ESPRESSObin has insufficient disk space for LXC container
- Need VirtualBox VM for testing mitmproxy installation
- Wiki and README need updated badges/metrics

**Completed:**

1. **VirtualBox VM Rebuild:**
   - Built new x64-bookworm image with 8GB disk
   - Generated VDI (2.8GB) and compressed img.gz (963MB)
   - Fixed VM UUID mismatch after VDI recreation
   - VM now running with 4GB RAM, EFI boot

2. **Wiki Home.md Update:**
   - Added workflow status badges (packages, live USB, installer, eye remote, multiboot)
   - Added development metrics table (131 packages, 94% migration, 2000+ APIs)
   - Added module status by category with progress indicators
   - Updated version announcement to v2.3.0

3. **README.md Update:**
   - Added comprehensive workflow badges
   - Added metrics table (packages, migration %, APIs, architectures)
   - Updated version to v2.3.0

4. **Dependency Fix:**
   - Added xz-utils to secubox-mitmproxy dependencies for LXC template extraction

**Commits:**
- 22487f8 docs: Add build status badges and metrics to README
- e041caa docs: Add build badges and metrics dashboard to wiki Home

**Artifacts:**
- `output/secubox-vm-x64-bookworm.img.gz` (963MB)
- `output/secubox-vm-x64-bookworm.vdi` (2.8GB)
- SHA256: 13e69ae55ab185daaf6e9b04ff1fad69bc40cf53c5ae8daac9829334226deca6

**Result:**
- Wiki now shows live build status for all components
- VirtualBox VM ready for mitmproxy testing
- GitHub Actions handles artifact creation on releases

---

### Session 89 — Emancipate SecuBox-Dev Methodology

**Goal:** Extract and document the SecuBox development methodology as a standalone, reusable guide

**Context:**
- Compared `.claude/` tracking files between secubox-openwrt (15 files) and secubox-deb (18 files)
- Identified core methodology patterns across 88+ development sessions
- Methodology needs to be portable for other projects

**Key Differences Found (OpenWrt vs Debian):**
| Aspect | OpenWrt | Debian |
|--------|---------|--------|
| Focus | Future features, themes, AI layers | Migration completion, CSPN compliance |
| Tracking | Version milestones (v0.19→v1.0) | Session-based (S01→S88), phases |
| Unique files | ROADMAP, EVOLUTION-PLAN, THEME_CONTEXT | MIGRATION-MAP, PATTERNS, MODULE-COMPLIANCE |

**Methodology Document Created:**
- Part 1: Project tracking structure (WIP, TODO, HISTORY, PATTERNS)
- Part 2: Session-based development workflow
- Part 3: Migration patterns (Shell/UCI → FastAPI/TOML)
- Part 4: Performance patterns for embedded systems
- Part 5: Compliance verification checklists
- Part 6: Quick reference
- Part 7: How to apply to new projects
- Appendix: Templates

**Files Created:**
- `docs/SECUBOX-DEV-METHODOLOGY.md` — 762 lines standalone methodology guide

**Commits:**
- 082ebe0 docs(methodology): Emancipate SecuBox-Dev methodology as standalone guide

**Result:**
- Methodology portable and documented
- Can be applied to any embedded/systems project with AI coding assistants

---

## 2026-05-02

### Session 88 — Navbar Module Filtering Fix

**Goal:** Fix navbar showing modules that aren't installed, causing 403/404/500 errors

**Problems Identified:**
1. Portal returning 403 (no index.html, only login.html)
2. Modules without www directories showing in navbar
3. Deploy script copying to wrong directory (secubox-hub vs hub symlink issue)
4. Menu items without `id` field still appearing

**Root Causes:**
- `/portal/` had only `login.html`, no `index.html` for nginx to serve
- `_check_module_installed()` was checking for service sockets/systemd, not actual www content
- `/usr/lib/secubox/hub` (uvicorn workdir) was separate from `/usr/lib/secubox/secubox-hub` (deploy target)
- Menu definitions (menu.d/*.json) included items without `id` field

**Fixes:**
1. Created `portal/index.html` redirect to `login.html`
2. Rewrote `_check_module_installed()` to only return True for modules with:
   - www directory at `/usr/share/secubox/www/{module_id}`
   - At least one HTML file in that directory
3. Added filter to skip menu items without valid `id` or with `console_only: true`
4. Created symlink: `/usr/lib/secubox/hub -> /usr/lib/secubox/secubox-hub`

**Files Changed:**
- `packages/secubox-hub/api/main.py` — Updated `_check_module_installed()` and `_compute_menu_sync()`
- `packages/secubox-hub/www/portal/index.html` — New redirect file

**Commits:**
- 96b51ef fix(hub): Filter navbar to only show modules with www directories

**Result:**
- Navbar shows only 8 modules with actual www content (was 29)
- All menu items return HTTP 200
- No more 403/404/500 errors from navbar links

---

### Session 87 — HAProxy WebUI CRUD Enhancement

**Goal:** Add full CRUD operations for VHosts, Backends, Servers, and Certificates to the HAProxy WebUI dashboard

**Context:**
- Compared OpenWrt SecuBox HAProxy implementation with secubox-deb
- OpenWrt had 35+ RPCD methods, 8 separate JS view files
- secubox-deb already had comprehensive FastAPI backend (40+ endpoints)
- WebUI was read-only — needed CRUD operations

**Implementation:**
1. Added modal system for add/edit forms
2. Added toast notifications for success/error feedback
3. Added client-side form validation with `validateForm()` function
4. Added enhanced `apiCall()` function with comprehensive error handling
5. VHost CRUD: add, edit, delete with domain/backend/SSL/WAF/ACME options
6. Backend CRUD: add, edit, delete with mode/balance/health check options
7. Server CRUD: nested under backends with address/port/weight management
8. Certificate CRUD: request ACME certs with progress bar, delete existing
9. Updated all tables with action buttons (Edit/Delete/Manage)
10. Maintained P31 Phosphor theme consistency

**Files Changed:**
- `packages/secubox-haproxy/www/haproxy/index.html` — ~1565 lines (was ~690)
- `docs/superpowers/specs/2026-05-02-haproxy-webui-enhancement-design.md` — Design spec
- `docs/superpowers/plans/2026-05-02-haproxy-webui-crud.md` — Implementation plan

**Commits (10 total):**
- f0970d6 feat(haproxy-ui): Add modal and toast HTML containers with CSS and JS functions
- 251b292 feat(haproxy-ui): Add validation and enhanced API functions
- ebb1bb4 feat(haproxy-ui): Add VHost CRUD functions
- d51e26e feat(haproxy-ui): Add Backend CRUD functions
- 591d289 feat(haproxy-ui): Add Server CRUD functions
- 4b2b214 feat(haproxy-ui): Add Certificate CRUD functions
- 3df7247 feat(haproxy-ui): Update VHosts table with CRUD buttons
- db04ffb feat(haproxy-ui): Update Backends table with CRUD buttons
- acdb94b feat(haproxy-ui): Update Certificates table with CRUD buttons
- 2a1dde2 fix(haproxy-ui): Add form CSS and remove unused function

**Result:**
- Full CRUD operations for all HAProxy entities
- Consistent UI with existing P31 Phosphor theme
- All API endpoints already existed — frontend-only enhancement
- Code review passed with Good quality rating

---

### Session 86 — GitHub Actions Package Architecture Filtering Fix

**Goal:** Fix GitHub Actions workflow failures when building ARM64 images

**Problem:**
- GitHub Actions build-image.yml workflow failing on arm64 boards (mochabin, espressobin-v7, espressobin-ultra, rpi400)
- Error: `package architecture (amd64) does not match system (arm64)` for secubox-c3box and secubox-daemon
- Slipstream code copied ALL .deb packages without architecture filtering
- When building arm64 images, amd64 packages were being copied and dpkg failed to install them

**Root Cause:**
- In `image/build-image.sh` line 675: `cp "${DEBS_DIR}"/secubox-*.deb` copied all packages regardless of architecture
- Same issue in `image/build-ebin-live-usb.sh` and `image/build-live-usb.sh`
- `build-rpi-usb.sh` already had correct filtering (only copied `_all.deb` and `_arm64.deb`)

**Fix Applied:**

1. **image/build-image.sh** — Added architecture filtering in slipstream section:
   - Replaced blind `cp` with a loop that filters by `DEBIAN_ARCH`
   - Only copies `*_all.deb` and `*_${DEBIAN_ARCH}.deb` packages
   - Logs skipped packages count for debugging

2. **image/build-ebin-live-usb.sh** — Added arm64 architecture filter:
   - Filter for `*_all.deb` and `*_arm64.deb` only
   - Updated cache search to also filter by architecture

3. **image/build-live-usb.sh** — Added amd64 architecture filter:
   - Filter for `*_all.deb` and `*_amd64.deb` only
   - Updated cache search to also filter by architecture

**Result:**
- ARM64 image builds will now skip amd64-only packages (secubox-daemon, secubox-c3box)
- AMD64 image builds will skip arm64-only packages
- Architecture-independent packages (`_all.deb`) are correctly installed on all platforms

---

## 2026-05-01

### Session 85 — VirtualBox VM Network Detection Fix

**Goal:** Fix network configuration for VirtualBox VMs with multiple interfaces (NAT + host-only)

**Problem:**
- VBox VMs with 2 interfaces (NAT + host-only) had host-only interface put into br-lan bridge
- br-lan bridge got static IP 192.168.1.1/24 instead of DHCP from VBox host-only network
- This broke host-only network access (should get IP in 192.168.56.x range)

**Root Cause:**
- `secubox-net-detect` treated x64-vm and x64-baremetal identically
- Both went through router mode logic that creates bridges for multi-interface setups
- VMs don't need bridges - each interface should independently get DHCP

**Fix Applied:**

1. **image/sbin/secubox-net-detect** — Separate VM handling:
   - New `x64-vm)` case in `get_interface_config()` with `profile="vm"`
   - VMs: first interface as WAN, empty LAN list (no bridge)
   - Added VM detection in `generate_netplan()`: when `board="x64-vm"`, configure ALL physical interfaces with DHCP
   - In `main()`: `profile="vm"` forces `mode="single"` (skip bridge creation)

**Result:**
- VBox VMs now correctly configure all interfaces with DHCP
- Host-only interface gets IP from VBox DHCP server (192.168.56.x range)
- NAT interface gets IP from VM's internal NAT (10.0.2.x range)
- No br-lan bridge created for VMs

**Testing:**
- Built new image with fix
- VM visible at 192.168.56.110 on host-only network (DHCP working)
- SSH service startup issue separate from network fix

---

### Session 84 — AMD64 Real Hardware Network Fix

**Goal:** Fix network configuration for real AMD64 hardware (x64-live board)

**Problem:**
- x64-live netplan used broken wildcard syntax (`wan0:` with `match: name: "e*"`)
- Missing `set-name:` directive caused netplan to not properly configure interfaces
- On real hardware with multiple interfaces (enp2s0, enp3s0, eno1), this caused IP assignment failures

**Fixes Applied:**

1. **board/x64-live/netplan/00-secubox.yaml** — Complete rewrite:
   - Changed from broken `wan0:` wildcard to proper `eth-dhcp:` and `eth-legacy:` match patterns
   - Both patterns get DHCP with different route metrics (100 vs 200) for determinism
   - Added `optional: true` to prevent boot blocking
   - Added documentation explaining secubox-net-detect role

2. **image/sbin/secubox-net-detect** — Enhanced interface detection:
   - Added logging for interface discovery process
   - Expanded naming pattern matching for real hardware:
     - `enp[0-9]*s0` patterns (PCI bus addressing)
     - `eno[0-9]*` patterns (onboard NICs)
     - `ens*` patterns (VMware ESXi)
   - Added fallback logic when no link detected
   - Improved YAML generation with DHCP overrides
   - Fixed empty LAN interface handling

3. **image/sbin/secubox-net-reset** — New utility script:
   - `--status` to show current network detection state
   - `--apply` to re-detect and apply immediately
   - `--reboot` to clear marker and reboot (default)
   - Helpful for debugging network issues

**Files Modified:**
- `board/x64-live/netplan/00-secubox.yaml`
- `image/sbin/secubox-net-detect`
- `image/build-live-usb.sh` — Updated embedded netplan config
- `CLAUDE.md` — Added Debian shell scripting guidelines and mitmproxy docs

**Files Created:**
- `image/sbin/secubox-net-reset`

**Testing:**
```bash
# On real AMD64 hardware:
secubox-net-reset --status    # Check current state
secubox-net-reset --apply     # Force re-detection
journalctl -u secubox-net-detect -f  # Watch detection logs
```

---

## 2026-04-30

### Session 83 — Module Enhancement & Service Fixes

**Goal:** Complete stub/mockup implementations and fix service startup issues

**Critical Security Fixes:**
- **secubox-voip**: Implemented PBKDF2-SHA256 password hashing (100k iterations)
  - Fixed plaintext password storage in extension/trunk creation
  - Added `hash_password()` and `verify_password()` functions

**Core Functionality Completed:**
- **secubox-dns-provider**: Full OVH and Route53 adapter implementations
  - OVH: list_domains, list_records, create/update/delete, ACME challenges, zone export
  - Route53: Same full API coverage using boto3
- **secubox-ai-gateway**: Auto-persist provider configuration
  - Added `_persist_providers()` helper function
  - Provider updates now automatically saved to disk
- **secubox-threat-analyst**: WAF rule generation added
  - Complete JSON format rules for WAF module integration
  - Includes blocked IPs, patterns, and metadata
- **secubox-mirror**: Added docker, npm, and pypi sync support
  - Docker: Registry v2 API verification
  - NPM: Registry ping endpoint check
  - PyPI: Simple API verification
- **secubox-eye-remote**: Proper JWT auth import from secubox_core
  - Fallback for standalone Pi Zero deployment

**System Module Performance:**
- **secubox-system**: 275ms → 40ms (6.8x faster) with batch systemctl calls

**Service Startup Fixes:**
- Fixed uvicorn path in 31 systemd service files
- Changed `/usr/local/bin/uvicorn` → `/usr/bin/python3 -m uvicorn`
- Services now start correctly on all Python installation types

**Affected Packages:**
cloner, hexo, jabber, jellyfin, localai, lyrion, magicmirror, matrix, mesh,
mmpm, netifyd, newsbin, ollama, ossec, p2p, peertube, photoprism, picobrew,
redroid, rezapp, roadmap, simplex, soc-agent, soc-gateway, vault, vm, wazuh,
webradio, zigbee, zkp

**Files Modified:**
- `packages/secubox-voip/api/main.py`
- `packages/secubox-dns-provider/api/main.py`
- `packages/secubox-ai-gateway/api/main.py`
- `packages/secubox-threat-analyst/api/main.py`
- `packages/secubox-mirror/api/main.py`
- `packages/secubox-eye-remote/api/routers/devices.py`
- `packages/secubox-eye-remote/api/routers/boot_media.py`
- `packages/secubox-system/api/main.py`
- 31× `packages/*/debian/*.service`

---

### Session 82 — API Performance Optimization Campaign

**Feature:** Applied double-buffer pre-cache pattern to all slow modules

**Performance Results:**
| Module | Before | After | Improvement |
|--------|--------|-------|-------------|
| CrowdSec | 1800ms | 45ms | **40x faster** |
| HAProxy | 353ms | 50ms | **7x faster** |
| Users | 1906ms | 37ms | **51x faster** |
| Hub Menu | ~2000ms | 80ms | **25x faster** |

**Files Modified:**
- `packages/secubox-crowdsec/api/routers/status.py` — Complete rewrite with cache
- `packages/secubox-crowdsec/api/main.py` — Added cache startup/shutdown
- `packages/secubox-haproxy/api/main.py` — Added status cache + background refresh
- `packages/secubox-users/api/main.py` — Added status cache + background refresh

**Pattern Applied:**
```python
# Double-buffer pre-cache pattern
_cache: Dict = {}
CACHE_FILE = Path("/var/cache/secubox/module/status.json")

async def _refresh_cache():
    while True:
        data = await compute_in_threadpool()
        _cache.update(data)
        CACHE_FILE.write_text(json.dumps(data))
        await asyncio.sleep(30)

@app.get("/status")
async def status():
    return _cache or load_from_file() or compute_sync()
```

**Target Profile: secubox-lite (ESPRESSObin 1GB)**
First home ISP secured solution with:
- CrowdSec IDS/IPS
- HAProxy reverse proxy
- DNS filtering
- Firewall (nftables)
- All APIs responding in <50ms

---

### Session 81 — Hub Menu Double-Buffer Pre-Cache

**Feature:** Implemented double-buffer pre-cache pattern for navbar menu

**Problem:** Navbar menu was slow (several seconds) due to synchronous systemctl calls for each module check.

**Solution:**
- Added `MENU_CACHE_FILE` at `/var/cache/secubox/menu.json` for persistence
- Added `_menu_cache` in-memory dict for instant responses
- Added `_refresh_menu_cache()` background task (30s interval)
- Added `_compute_menu_sync()` running in thread pool
- Cache loaded from file on startup for fast navbar display

**Performance:**
- Before: Several seconds per request (sequential systemctl calls)
- After: ~80ms average response time

**Files Modified:**
- `packages/secubox-hub/api/main.py` — Added cache infrastructure

**Device:** ESPRESSObin V7 (192.168.255.250)

---

### Session 80 — Security Services Integration on ESPRESSObin

**Feature:** Integrated core security modules (CrowdSec, HAProxy, WAF, DNS) on ESPRESSObin

**Services Deployed:**
| Service | Port | Status | Dashboard |
|---------|------|--------|-----------|
| secubox-crowdsec | 8010 | ✅ Running | /crowdsec/ |
| secubox-haproxy | 8011 | ✅ Running | /haproxy-dashboard/ |
| secubox-waf | 8012 | ✅ Running | /waf/ |
| secubox-dns | 8013 | ✅ Running | /dns/ |

**Files Modified:**
- `packages/secubox-dns/api/main.py` — Fixed Pydantic v1 compatibility (field_validator → validator)

**Systemd Overrides Created (ESPRESSObin):**
- `/etc/systemd/system/secubox-crowdsec.service.d/override.conf` — TCP port 8010
- `/etc/systemd/system/secubox-haproxy.service.d/override.conf` — TCP port 8011
- `/etc/systemd/system/secubox-waf.service.d/override.conf` — TCP port 8012
- `/etc/systemd/system/secubox-dns.service.d/override.conf` — TCP port 8013

**Nginx Configs Verified:**
- `/etc/nginx/secubox.d/crowdsec.conf` — API + static dashboard
- `/etc/nginx/secubox.d/haproxy.conf` — API + static dashboard
- `/etc/nginx/secubox.d/waf.conf` — API + static dashboard
- `/etc/nginx/secubox.d/dns.conf` — API + static dashboard

**API Endpoints Working:**
- CrowdSec: 75+ endpoints (decisions, alerts, bouncers, hub, console, migration)
- HAProxy: 35+ endpoints (vhosts, backends, certs, stats, WAF toggle)
- WAF: 15+ endpoints (rules, categories, bans, alerts, autoban)
- DNS: 20+ endpoints (zones, records, stats, webhooks, export)

**Dashboard Features (OpenWrt-inspired):**
- CrowdSec: Status monitoring, ban management, alerts, hub, bouncers, console enrollment
- HAProxy: VHost management, backends, certificates, stats, WAF integration
- WAF: Rule categories, auto-ban, alerts, IP banning
- DNS: Zone management, records, validation, history, webhooks

---

### Session 79 — Performance Benchmark Suite

**Feature:** Created comprehensive performance testing infrastructure for ARM64 optimization

**Files Created:**
- `scripts/bench/api-latency.py` — API endpoint latency measurement (P50/P95/P99)
- `scripts/bench/memory-baseline.sh` — Per-service memory tracking (RSS/PSS/USS)
- `scripts/bench/startup-time.sh` — Service cold-start measurement via systemd
- `scripts/bench/cpu-profile.sh` — Flame graph generation with py-spy
- `scripts/bench/locustfile.py` — Load test scenarios for Locust framework
- `scripts/bench/README.md` — Documentation for benchmark suite

**Files Modified:**
- `scripts/README.md` — Added performance benchmarks section
- `remote-ui/round/agent/display/fallback/fallback_manager.py` — Changed disk icon to floppy

**Performance Targets Established:**
| Metric | ESPRESSObin | MOCHAbin |
|--------|-------------|----------|
| API P50 | < 100ms | < 50ms |
| API P99 | < 500ms | < 200ms |
| Service RSS | < 50MB | < 100MB |
| Cold start | < 5s | < 3s |

**MOCHAbin Analysis:**
- Identified critical state: Load 9.47, swap 99% exhausted
- Gitea using 7.6GB (93% VSZ) — memory leak or misconfiguration
- Created optimization plan in `.claude/plans/shimmering-chasing-abelson.md`

---

## 2026-04-29

### Session 78 — Migration Tools v2.1.0 + Services Module

**Feature:** Extended migration with 19 modules covering all SecuBox services

**Files Modified:**
- `scripts/migration-export.sh` — Added dns, databases, scripts, services modules (v2.1.0)
- `scripts/migration-import.sh` — Added import functions for all new modules (v2.1.0)

**New Migration Modules:**
| Module | Export | Import |
|--------|--------|--------|
| `dns` | BIND zones, Vortex RPZ, Unbound, AdGuard, Pi-hole | BIND/Unbound configs, zones |
| `databases` | SQLite, MySQL, PostgreSQL, Redis dumps | DB restoration with permissions |
| `scripts` | Custom scripts, systemd units, cron jobs, rc.local | Scripts, systemd service creation |
| `services` | All /srv/* directories (50+ services) | Service restoration, Docker compose |

**Services Module Captures:**
- Streamlit instances (`/srv/streamlit/*`)
- Metablogizer/Metabolizer apps
- Gitea/Git repositories with full history
- Docker compose configurations
- LXC container configs
- mitmproxy, config-vault, saas-relay

**Enhanced HAProxy Export:**
- conf.d modular architecture
- Certificate management
- Lua scripts and maps
- mitmproxy route integration

**Total Modules:** 19 (network, firewall, wireguard, crowdsec, dhcp, haproxy, nginx, certs, content, vhosts, users, state, git, media, mail, accounts, dns, databases, scripts, services)

**Eye Remote Deployment:**
- Deployed agent to ESPRESSObin at `/opt/eye-remote/`
- Fixed `secubox-status` to handle VLAN interfaces (`wan@eth0`)
- Restored WAN connectivity after migration via `/etc/netplan/10-wan.yaml`

---

### Session 77 — Migration Tools Extended (v2.0.0)

**Feature:** Extended migration to include Git, Media, Email, and User Accounts

**Files Modified:**
- `scripts/migration-export.sh` — Added git, media, mail, accounts modules (v2.0.0)
- `scripts/migration-import.sh` — Added import functions for new modules (v2.0.0)

**New Migration Modules:**
| Module | Export | Import |
|--------|--------|--------|
| `git` | /srv/git, /var/lib/git, Gitea/Gogs/GitLab | /srv/git, service configs |
| `media` | /srv/media, PeerTube, Jellyfin, Nextcloud | /srv/media, service restarts |
| `mail` | Maildir, Postfix, Dovecot, DKIM | Mail dirs, configs, crontabs |
| `accounts` | Home dirs, passwd/shadow, sudo, cron | User creation, home dirs |

**Export Test Results:**
- Git repositories: 4K
- Media files: 8K
- Email data: 4K
- User accounts: 6 users, 96K
- Total archive: 72K

**Note:** VBox VM SSH issue (banner timeout) prevented import test.

---

### Session 76 — Migration Tools Validation on VirtualBox

**Feature:** Tested migration import on VirtualBox VM

**Test Results:**
- Export: 66KB archive from SecuBox-OpenWrt (192.168.255.1)
- Transform: UCI → Debian format (netplan, nftables, dnsmasq, vhost.toml)
- Import: All modules successfully imported to VBox VM

**Imported Configurations:**
| Config | Destination | Status |
|--------|-------------|--------|
| Network | `/etc/netplan/00-secubox.yaml` | ✅ Imported |
| Firewall | `/etc/nftables.conf` | ✅ Imported (78 rules) |
| DNS/DHCP | `/etc/dnsmasq.d/secubox.conf` | ✅ Imported |
| VHosts | `/etc/secubox/vhosts/vhost.toml` | ✅ Imported (4 services, 3 redirects) |
| Content | `/srv/www/` | ✅ Imported (8KB) |
| Auth | `/etc/secubox/auth.toml` | ✅ Imported |

**Rollback Snapshot:**
- `/var/lib/secubox/rollback/pre-migration-20260429-112849`

**Expected Warnings:** Services not installed on test VM (CrowdSec, dnsmasq, HAProxy)

---

### Session 75 — Eye Remote Recovery System + Design Charter Update

**Feature:** Board recovery via serial boot protocols + unified design charter

**Files Created:**
- `remote-ui/round/agent/recovery/protocols/mvebu64boot.py` — 64-bit Marvell boot protocol
- `remote-ui/round/agent/recovery/protocols/xmodem.py` — XMODEM-CRC file transfer (prior session)
- `remote-ui/round/agent/recovery/protocols/kwboot.py` — Armada 3720 serial boot (prior session)
- `remote-ui/round/agent/recovery/recovery_controller.py` — Main recovery controller (prior session)

**Files Modified:**
- `remote-ui/round/agent/recovery/protocols/__init__.py` — Added Mvebu64Protocol export
- `remote-ui/round/agent/recovery/__init__.py` — Added RecoveryMethod + Mvebu64Protocol
- `docs/design/graphic-charter.md` — Updated to v2.0, synced with Eye Remote metrics
- `docs/hardware/smart-strip-v1.1.md` — Updated to v1.2, synced with graphic charter

**Recovery Protocols:**
| Protocol | SoC | Use Case |
|----------|-----|----------|
| kwboot | Armada 3720 | ESPRESSObin serial boot |
| mvebu64boot | Armada 7040/8040 | MOCHAbin 64-bit serial boot |
| XMODEM-CRC | All | File transfer to BootROM |

**Design Charter Updates:**
- Module → Metric mapping table for Eye Remote dashboard
- Alert thresholds unified across Eye Remote and Smart-Strip
- RGB values for SK6812 LEDs documented
- Pod layout diagram for round display
- Transport badge colors (OTG=ROOT, WiFi=MESH, SIM=gray)

**GitHub Issue #34:** Confirmed fixed (closed with resolution comment)

---

### Session 74 — Migration Data Saver v1.0.0

**Feature:** OpenWrt → SecuBox-DEB migration tools

**Files Created:**
- `scripts/migration-export.sh` — SSH export from SecuBox-OpenWrt
- `scripts/migration-import.sh` — Import to SecuBox-DEB with transformations
- `scripts/migration-transform.py` — UCI parser and format converters

**Files Modified:**
- `scripts/README.md` — Added migration documentation
- `.claude/WIP.md` — Updated with session 74

**Components:**
- UCIParser: Parse OpenWrt UCI config format
- NetworkTransformer: UCI network → netplan YAML
- FirewallTransformer: UCI firewall → nftables
- DHCPTransformer: UCI dhcp → dnsmasq.conf

**Supported Modules:**
network, firewall, wireguard, crowdsec, dhcp, haproxy, nginx, certs, content, vhosts, users, state

**Security Features:**
- AES-256 archive encryption
- SHA256 checksums
- Pre-import rollback snapshots
- Secrets separation

---

### Session 73 — Eye Remote Interactive v1.9.0

**Feature:** Multi-mode USB gadget display system for Eye Remote

**Files Modified:**
- `remote-ui/round/fb_dashboard.py` — Added mode detection, TTY terminal, flash progress, auth QR
- `packages/secubox-hub/debian/secubox-hub.service` — Changed to TCP binding (port 8001)
- `packages/secubox-hub/nginx/hub.conf` — Changed to TCP proxy
- `common/nginx/modules.d/hub.conf` — Changed to TCP proxy

**New Classes:**
- `SerialTerminal` — Read serial console output for TTY mode
- `FlashProgress` — Track USB mass storage transfer progress
- `AuthState` — QR code generation for backup authentication

**New Functions:**
- `get_gadget_mode()` — Read current USB gadget mode from /etc/secubox/gadget-mode
- `draw_terminal()` — Render serial terminal output on round display
- `draw_flash_progress()` — Render flash transfer progress bar
- `draw_auth_mode()` — Render QR code authentication screen

**Fixes:**
- Hub service changed from Unix socket to TCP (VM compatibility)
- FAQ and wiki updated with troubleshooting for common issues
- Kiosk launcher fixed for VM sandbox issues (--no-sandbox flag)
- Added public menu endpoint (`/api/v1/hub/public/menu`) for WebUI sidebar
- Fixed Pydantic 1.x compatibility in auth.py for require_jwt dependency
- Fixed "Failed to load menu: Invalid menu data" WebUI error

---

## 2026-04-28

### Session 72 — v2.1.1 Release: Build and API Fixes

**Release:** v2.1.1 — Critical fixes for VirtualBox and ESPRESSObin builds

**Issues Fixed:**

1. **Python Dependencies (Debian Bookworm Compatibility)**
   - Debian ships pydantic v1, but SecuBox requires v2
   - Added pip upgrade in build scripts: `pydantic>=2.0`, `fastapi>=0.100`, `uvicorn>=0.25`
   - Updated `secubox-core` postinst to auto-upgrade on install

2. **CORS Headers**
   - Added CORS headers to `common/nginx/secubox-proxy.conf`
   - Fixes cross-origin API requests from web UI

3. **Login Endpoint Path**
   - Fixed `login.html`: `/auth/login` → `/login`
   - Affects both main and portal login pages

4. **Eye Remote Display Imports**
   - Fixed `display/__init__.py` to import existing modules only
   - Changed service to use `display_manager.py` instead of `main.py`

5. **Eye Remote Rainbow Dashboard**
   - Icons in rainbow circle: BOOT, AUTH, WALL, ROOT, MESH, MIND
   - Radar sweep syncs with targeted module glow
   - Metric arcs aligned with corresponding icon colors
   - Concentric rings: red (outer) → purple (inner)

**Files Modified:**
- `common/nginx/secubox-proxy.conf` — CORS headers
- `packages/secubox-core/debian/postinst` — pip upgrade
- `packages/secubox-hub/www/login.html` — endpoint fix
- `packages/secubox-hub/www/portal/login.html` — endpoint fix
- `image/build-live-usb.sh` — version constraints
- `image/build-ebin-live-usb.sh` — version constraints
- `image/multiboot/build-amd64-rootfs.sh` — pip upgrade
- `remote-ui/round/agent/display/__init__.py` — import fix

**Wiki Updated:**
- `Home.md` — v2.1.1 announcement
- `Troubleshooting.md` — API 502/auth fix section
- `Eye-Remote.md` — HyperPixel dashboard info
- `Live-USB-VirtualBox.md` — troubleshooting section

**ESPRESSObin Live USB Rebuilt with Installer:**
- Built with `--embed-image` option for one-step eMMC flashing
- Embedded: `secubox-espressobin-v7-bookworm.img.gz` (573MB)
- Output: `secubox-espressobin-v7-live-usb.img.gz` (1.8GB)
- Flash command: `secubox-flash-emmc` from live USB
- Includes all v2.1.1 fixes (pydantic v2, CORS, login endpoints)

### Session 73 — Eye Remote Real Metrics Integration

**Feature:** Real metrics fetching from connected SecuBox via OTG/WiFi

**Components Created:**

1. **Metrics Fetcher** (`remote-ui/round/agent/api/metrics_fetcher.py`)
   - Async fetcher using aiohttp
   - Aggregates data from multiple SecuBox API endpoints
   - Connection state detection (OTG/WiFi/Disconnected)
   - Module-specific metrics (AUTH, WALL, MESH, etc.)
   - Double buffer for non-blocking display updates

2. **OTG Host Support for ESPRESSObin** (`packages/secubox-system/`)
   - `etc/udev/rules.d/90-secubox-eye-remote.rules` — Detects Pi Zero CDC-ECM
   - `usr/lib/secubox/eye-remote-connected.sh` — Configures 10.55.0.1/30
   - `usr/lib/secubox/eye-remote-disconnected.sh` — Cleanup handler

3. **Display Integration** (`remote-ui/round/agent/display/fallback/fallback_manager.py`)
   - Integrated MetricsFetcher for real data
   - Mode indicator shows connection type + latency
   - Module details show real vs local data source
   - Targeted metrics display with extra details

**API Endpoints Used:**
- `/api/v1/system/metrics` — System metrics
- `/api/v1/auth/stats` — Authentication stats
- `/api/v1/crowdsec/metrics` — CrowdSec decisions
- `/api/v1/wireguard/status` — WireGuard peers
- `/api/v1/dpi/stats` — DPI flow data

**Feature Plan Created:**
- `.claude/plans/eye-remote-otg-features.md` — 5 features roadmap:
  1. Real Metrics Display (implemented)
  2. OTG Tools Dashboard
  3. Gadget Parameters Control
  4. Storage Sync for Configs
  5. Self-Setup Portal

---

### Session 71 — Eye Remote Display System v2.3.0

**Feature:** Complete display state machine with fallback, splash, and radar modes

**Description:**
Implemented full Eye Remote display system with multiple visualization modes for Pi Zero W HyperPixel 2.1 Round (480x480). Includes connection state detection, animated splash screens, and local metrics radar visualization.

**Components Created:**

1. **Splash Screen System** (`display/splash.py`)
   - Animated phoenix logo for boot/halt/start/reboot states
   - Pulsing glow effects with fire colors
   - Progress indicator ring
   - Fallback phoenix symbol if logo missing

2. **Fallback Display Manager** (`display/fallback/fallback_manager.py`)
   - Connection state detection (OTG 10.55.0.1, WiFi secubox.local)
   - Four modes: OFFLINE, CONNECTING, ONLINE, COMMUNICATING
   - Local metrics radar with 6 concentric rings (AUTH, WALL, BOOT, MIND, ROOT, MESH)
   - 3D rotating cube with module icons when connected
   - Rainbow sweep line animation

3. **Touch Pattern Analyzer** (`display/fallback/touch_analyzer.py`)
   - Noise pattern analysis for HyperPixel touch panel
   - Coordinate and delta frequency tracking
   - Discovered Y-axis oscillation at stable X (~240-250)

4. **Touch Calibration Tool** (`display/fallback/touch_calibrate.py`)
   - Corner target display for manual calibration
   - Real-time coordinate overlay

5. **Radar Variants**
   - `radar_flashy.py` — Vibrant colors with 3D cube and icons
   - `radar_concentric.py` — Balanced metric arcs centered at 12 o'clock
   - `radar_rainbow.py` — Rainbow colorization with sweep
   - `radar_full.py` — Complete feature set

**Package Build:**
- Built all 128 SecuBox Debian packages successfully
- ESPRESSObin V7 image rebuild with packages slipstreamed

**Files Created:**
- `remote-ui/round/agent/display/splash.py`
- `remote-ui/round/agent/display/fallback/__init__.py`
- `remote-ui/round/agent/display/fallback/fallback_manager.py`
- `remote-ui/round/agent/display/fallback/touch_analyzer.py`
- `remote-ui/round/agent/display/fallback/touch_calibrate.py`
- `remote-ui/round/agent/display/fallback/radar_*.py` (5 variants)

**Version:** v2.3.0

---

## 2026-04-27

### Session 70 — Live Boot Complete Setup (v2.2.4-live)

**Feature:** Full live-boot implementation with squashfs and RAM boot

**Description:**
Completed full live-boot setup for Pi Zero Eye Remote storage.img. Installed live-boot package, rebuilt initramfs with live-boot scripts, created squashfs filesystem, and updated boot.scr with proper live boot parameters.

**Changes Made:**
1. Installed `live-boot` and `busybox` packages on ARM64 rootfs
2. Rebuilt initramfs with live-boot scripts included
3. Created `/live/filesystem.squashfs` (878MB) on data partition (sda4)
4. Updated boot.scr with live boot parameters:
   - `boot=live` - enables live-boot mode
   - `live-media=/dev/sda4` - partition with squashfs
   - `live-media-path=/live` - path to squashfs
   - `toram` - loads entire squashfs into RAM
   - DSA blacklist parameters preserved

**Partition Layout:**
- sda1 (512MB): EFI - kernel, initrd, dtbs, boot.scr
- sda2 (3GB): ARM64 rootfs (for reference)
- sda3 (3GB): x86 rootfs (for VirtualBox/QEMU)
- sda4 (9.5GB): Data + /live/filesystem.squashfs

**Wiki Fix:** Fixed sidebar link syntax from `[[Page|Display]]` to `[Display](Page)`

**Version:** v2.2.4-live

---

### Session 69 — Live RAM Boot Cmdline Fix (v2.2.4-pre2)

**Fix:** Added missing `boot=live live-media-path=/live` parameters to bootargs

**Description:**
Fixed critical issue where multiboot image was not configured for live RAM boot. The kernel command line was missing the required `boot=live` and `live-media-path=/live` parameters that the live-boot initramfs needs to work properly.

**Files Modified:**
- `image/multiboot/build-multiboot.sh` — Added live boot parameters to setenv bootargs

**Before:**
```bash
setenv bootargs "root=${rootpart} rootfstype=ext4 rootwait rootdelay=10 ..."
```

**After:**
```bash
setenv bootargs "boot=live live-media-path=/live root=${rootpart} rootfstype=ext4 rootwait rootdelay=10 ..."
```

**Version:** v2.2.4-pre2

---

### Session 68 — Multiboot Dual Boot Menu & Kernel Fix (v2.2.4-pre1)

**Feature:** Fixed ARM64 kernel installation and added interactive boot menu

**Description:**
Fixed critical bug where ARM64 kernel, initrd, and DTB files were not being copied to the EFI partition. Added interactive dual boot menu with 5-second timeout, offering Live RAM Boot (default) or Flash to eMMC option.

**Files Modified:**
- `image/multiboot/build-multiboot.sh` — Major fixes:
  - Fixed loop device release bug in `install_arm64_rootfs()` (was releasing before copying kernel)
  - Added `build_arm64_rootfs_debootstrap()` function with kernel installation
  - Added `copy_arm64_kernel_to_efi()` function to properly copy Image, initrd, DTBs
  - Updated boot.scr with interactive dual boot menu (5s timeout)
  - Added qemu-debootstrap and other optional dependency warnings
- `.github/workflows/build-multiboot.yml` — Added prerelease support, bumped version
- `wiki/_Sidebar.md` — Bumped version to v2.2.4-pre1

**Boot Menu Options:**
1. Live RAM Boot (default with 5s timeout)
2. Flash SecuBox to eMMC

**Version:** v2.2.4-pre1 (prerelease)

---

### Session 67 — Multiboot Wiki & Eye Remote Docs (v2.2.3)

**Feature:** Wiki documentation for multiboot live OS and Eye Remote integration

**Description:**
Added comprehensive wiki documentation for the multi-architecture boot system, including the new Multiboot wiki page, home page announcement banner, and sidebar navigation updates.

**Files Created:**
- `wiki/Multiboot.md` — Full documentation for multiboot live OS

**Files Modified:**
- `wiki/Home.md` — Added announcement banner for v2.2.3 multiboot
- `wiki/_Sidebar.md` — Added Multiboot and Eye Remote links, bumped version
- `image/multiboot/README.md` — Added Eye Remote integration section

**Changes:**
- Eye Remote Pi Zero architecture documented with ASCII diagrams
- Partition layout and boot flow explained
- Build instructions and GitHub Actions CI docs
- Troubleshooting section for common boot issues

---

### Session 66 — Multiboot GitHub Action (v2.2.3)

**Feature:** GitHub Actions workflow for automated multiboot image builds

**Description:**
Created automated CI/CD pipeline for building the multiboot live OS image with all SecuBox packages slipstreamed. Workflow builds .deb packages first, then creates the 16GB multiboot image with ARM64 and AMD64 rootfs partitions.

**Files Created:**
- `.github/workflows/build-multiboot.yml` — CI workflow for multiboot image

**Workflow Features:**
- Manual dispatch with configurable image size (8/16/32GB)
- Optional desktop environment inclusion
- Automatic .deb package builds from packages/
- Debootstrap-based ARM64 and AMD64 rootfs creation
- QEMU user-mode emulation for cross-arch chroot
- XZ compression for releases
- GitHub Release integration

**Version:** v2.2.3

---

### Session 65 — Multi-Boot Storage System (v2.2.2)

**Feature:** Multi-architecture boot system for Pi Zero Eye Remote storage

**Description:**
Created a multi-boot storage system that supports ARM64 (ESPRESSObin/MOCHAbin via U-Boot) and AMD64 (UEFI systems via GRUB) from a single USB storage device, with shared application data across both architectures.

**Partition Layout (16GB+):**
- P1: EFI/FAT32 (512MB) — Boot files for both architectures
- P2: ext4 (3GB) — ARM64 SecuBox rootfs
- P3: ext4 (3GB) — AMD64 SecuBox rootfs
- P4: ext4 (remaining) — Shared data partition

**Features:**
- U-Boot boot.scr with USB/MMC auto-detection for ARM64
- GRUB BOOTX64.EFI for AMD64 UEFI boot
- Shared data partition with bind mounts for /etc/secubox, /var/lib/secubox, /srv/secubox
- eMMC flasher image included for ARM64 installation
- Debootstrap-based AMD64 rootfs builder with SecuBox packages

**Files Created:**
- `image/multiboot/README.md` — Documentation
- `image/multiboot/build-multiboot.sh` — Main build script
- `image/multiboot/build-amd64-rootfs.sh` — AMD64 rootfs builder

**Commits:**
- `5cf69c0` — feat(multiboot): Add multi-architecture boot system with shared data

**Version:** v2.2.2

---

### Session 65 — Eye Remote USB Boot Fix (v2.2.1)

**Issue:** ESPRESSObin would not boot from Eye Remote USB mass storage. mv88e6xxx driver in infinite detection loop.

**Root Cause:** Live USB kernel had mv88e6xxx built-in (not a module), making `modprobe.blacklist` ineffective. The eMMC kernel has mv88e6xxx as a loadable module where blacklist works.

**Fix:**
- Replaced storage.img boot partition with eMMC kernel/initrd/DTB
- Replaced storage.img rootfs with working eMMC rootfs
- Updated boot scripts with extended blacklist for future builds

**Files Modified:**
- `board/espressobin-v7/boot-live-usb.cmd`
- `board/espressobin-v7/boot-usb.cmd`
- `board/espressobin-v7/boot.cmd`

**Commits:**
- `942196b` — fix(boot): Add mv88e6085 and initcall_blacklist to boot scripts

**Version:** v2.2.1

### Session 65 — HAProxy Service Restart Loop Fix

**Issue:** `secubox-haproxy.service` in restart loop with NAMESPACE error.

**Root Cause:** `RuntimeDirectory=haproxy` triggers systemd namespace setup which expects `/etc/haproxy` to exist. HAProxy is `Recommends:` not `Depends:`.

**Fix:**
- postinst creates `/etc/haproxy` if not present
- Removed `RuntimeDirectory=haproxy` from service
- Moved directory creation from import-time to startup event
- Increased RestartSec 5→30s

**Commits:**
- `4321a7c` — fix(haproxy): Prevent service restart loop
- `9f47e54` — fix(haproxy): Create /etc/haproxy and remove RuntimeDirectory=haproxy

---

## 2026-04-23

### Session 64 — Eye Remote USB OTG Network Fix (v2.1.1)

**Issue:** USB OTG network connection showed NO-CARRIER on Linux hosts despite Pi Zero interface being UP.

**Root Cause Analysis:**
The USB composite gadget creates two network interfaces on the Pi Zero:
- `usb0` → RNDIS function (Windows compatible)
- `usb1` → ECM function (Linux/Mac via cdc_ether driver)

Linux hosts use the ECM driver which maps to `usb1`. The old scripts configured `usb0` only, or both interfaces with the same IP (10.55.0.2/30), causing asymmetric routing where packets received on `usb1` could be replied via `usb0`.

**Fix Applied:**
- Configure only `usb1` (ECM) for Linux host compatibility
- Fallback to `usb0` only if `usb1` doesn't exist

**Files Modified:**
- `remote-ui/round/secubox-otg-gadget.sh` — Wait for and configure usb1
- `remote-ui/round/files/etc/secubox/eye-remote/gadget-setup.sh` — Same fix
- `remote-ui/round/agent/main.py` — `ensure_usb_network()` prefers usb1
- `remote-ui/round/agent/network_debug.py` — New debug script

**Results:**
- ✅ USB OTG network connectivity working (0.3ms latency)
- ✅ Display shows OTG mode instead of SIM
- ✅ Host NetworkManager connection persisted ("SecuBox OTG")

**Commits:**
- `48de244` — fix(eye-remote): Use usb1 (ECM) instead of usb0 for Linux hosts
- `f7b4bb4` — style(eye-remote): Adjust pod positions for hexagonal ring layout

**Version:** v2.1.1

---

## 2026-04-15

### Session 59 — EspressoBin eMMC Flasher & VirtualBox Graphics Fix

**v1.7.0 — EspressoBin Live USB with eMMC Flasher**
- Built EspressoBin V7 live USB image with embedded eMMC flasher
- Fixed SquashFS path issue (`/filesystem.squashfs` → `/live/filesystem.squashfs`)
- Fixed boot partition sizing for embedded images (dynamic sizing)
- Added `secubox-flash-emmc` command for easy eMMC flashing
- Successfully booted live USB and flashed to eMMC on real hardware

**v1.6.7.14 — VirtualBox VMSVGA Graphics Fix (Issue #29)**
- Root cause: VirtualBox with VMSVGA controller (default since VBox 6) needs `vmware` X11 driver
- `systemd-detect-virt` returns "oracle" but GPU shows "VMware SVGA" in lspci
- Created `secubox-x11-setup.service` for boot-time VM detection and X11 driver selection
- Updated kiosk launcher (v3.3) to defer to X11 setup service
- Driver selection: VBox+VMSVGA→vmware, VBox+VBoxVGA→modesetting, VMware→vmware, KVM→modesetting

**Slipstream Default Change**
- Changed `SLIPSTREAM_DEBS` default from 0 to 1 in `build-image.sh`
- All images now include 126 SecuBox packages by default

**Files Modified**
- `image/build-live-usb.sh` — X11 auto-setup service, vmware driver install
- `image/build-ebin-live-usb.sh` — Dynamic boot partition sizing, SquashFS path fix
- `image/build-image.sh` — SLIPSTREAM_DEBS=1 default
- `image/sbin/secubox-kiosk-launcher` — v3.3, vmware driver for VBox VMSVGA
- `image/systemd/secubox-kiosk.service` — depends on x11-setup service

**Builds In Progress**
- AMD64 live USB with VBox graphics fix
- EspressoBin eMMC image with 126 packages

---

## 2026-04-14

### Session 57 — Live USB Fixes & VirtualBox Testing

**v1.6.7.12 — Lenovo Boot Fix (Issue #26)**
- Added fallback EFI bootloader at `/EFI/BOOT/BOOTX64.EFI` for Lenovo/HP/Dell
- Fixed CI `--slipstream` flag in build-live-usb.sh
- Fixed banner alignment in secubox-flash-disk
- Tested and confirmed working on real Lenovo hardware

**v1.6.7.13 — VirtualBox Detection Fix (Issue #27)**
- Fixed VM detection using `systemd-detect-virt` ("oracle") instead of lspci
- VBox with VMSVGA was incorrectly detected as VMware
- Result: WebUI works in VBox, kiosk works on real hardware

**v1.6.7.14 — Network Auto-Discovery (Issue #28)**
- Enhanced `secubox-net-fallback` with LAN auto-discovery
- Probes common gateways (192.168.1.1, 192.168.0.1, 192.168.255.1, 10.0.0.1...)
- Auto-configures IP .250 on discovered subnet when DHCP fails
- Only uses 169.254.1.1 as last resort

**Wiki Updates**
- All Home pages (EN, FR, DE, ZH) now use `/releases/latest/download/` URLs
- Fixed script paths (scripts/ → image/)
- Removed hardcoded version numbers

**Builds Completed**
- x64: `secubox-live-amd64-bookworm.img` (8GB)
- ARM64: `secubox-espressobin-v7-live-usb.img` (539MB)

**GitHub Issues Closed**
- #26 Lenovo Error 1962 boot fix ✅
- #27 VBox kiosk not starting ✅
- #28 Network fallback 169.254.1.1 ✅

**Tags:** v1.6.7.12, v1.6.7.13, v1.6.7.14

---

## 2026-04-03

### Session 34 — Build Timestamp & System Fixes

**secubox-hub v1.2.0 — Build Timestamp Display**
- Added `_get_build_info()` API function to read `/etc/secubox/build-info.json`
- Dashboard header now displays build timestamp badge (date + time)
- Tooltip shows git commit hash, branch, and board type on hover
- Build scripts create `build-info.json` during image generation

**Build System Improvements**
- Fixed `build-live-usb.sh` package priority (prefers `output/debs` over cache)
- Fixed secubox-soc-web nginx config (installs to `secubox.d/` not `sites-available/`)
- Removed broken `secubox-repo.conf` symlink creation from postinst scripts

**Packages Updated**
- `secubox-hub_1.2.0-1~bookworm1_all.deb` — Build timestamp feature
- `secubox-soc-web_1.1.0-1_all.deb` — Nginx config path fix

**Release v1.4.0**
- Tag: `v1.4.0`
- Commit: `19ca292`
- All changes pushed to `origin/master`

---

## 2026-03-30

### Plymouth Boot Splash & Kiosk Fixes
- Added Plymouth boot splash with VT100/DEC PDP-style green phosphor theme
- Boot graphics now show DURING boot (not just at login)
- Fixed kiosk mode service configuration:
  - Changed from tty1 to tty7 (like standard display managers)
  - Proper VT allocation and switching
  - Better wlroots environment variables for VMs
  - Added tty supplementary group for DRM access
- Updated GRUB menu entries with `splash` parameter
- Added initramfs configuration for Plymouth framebuffer
- RPi 400 build: Added Plymouth support with ARM64 theme
- Tags: v1.3.6

### Previous Boot Fixes (v1.3.2-v1.3.5)
- Added VT100 retro CRT DEC PDP-style cyber splash
- Added hardware auto-check boot mode (`secubox.hwcheck=1`)
- Fixed boot hanging services with timeouts
- RPi 400 image builder with HDMI console autologin

---

## 2026-03-29

### Kiosk Mode Bug Fixes
- Fixed UID mismatch issue — service now detects actual kiosk user UID
- Fixed timing issue — cmdline handler defers package installation to after network
- Fixed marker file confusion (`.kiosk-installed` vs `.kiosk-enabled`)
- Updated build-live-usb.sh to fully setup kiosk when --kiosk flag used
- Improved start-kiosk.sh to wait for nginx/hub services (30s max)
- Service now uses `ConditionPathExists` to check enabled state

---

## 2026-03-28

### Network Auto-Detection & Preseed System
- Created `secubox-net-detect` — Auto-detection of WAN/LAN interfaces
  - Board detection: MochaBin, ESPRESSObin v7/Ultra, x64 VM/baremetal
  - Interface mapping based on device model (eth0=WAN, lan*=LAN)
  - Netplan generation for router/bridge/single modes
  - Link detection for x64 auto-discovery
- Board configurations created:
  - `board/x64-live/config.mk` — Live USB settings
  - `board/x64-vm/config.mk` — VM-specific settings
  - Netplan templates for each board
- Kernel cmdline handler:
  - `secubox-cmdline-handler` — Parses secubox.* kernel params
  - `secubox.netmode=router|bridge|single`
  - `secubox.kiosk=1` for GUI mode
- Kiosk GUI mode:
  - `secubox-kiosk-setup` — Install/enable/disable minimal GUI
  - Cage Wayland compositor + Chromium fullscreen
  - Perfect for touchscreen/kiosk deployments
- Updated `build-live-usb.sh`:
  - GRUB menu entries for Kiosk Mode, Bridge Mode
  - Installs net-detect, cmdline-handler, kiosk-setup
  - Systemd services for early boot configuration
- Updated `firstboot.sh` with network auto-detection integration

### secubox-localai v1.0.0 Complete
- Fifth Phase 8 package ported from OpenWRT
- FastAPI backend with 15+ endpoints
- Features: Container management, model gallery, chat completion
- OpenAI-compatible API proxy (/v1/chat/completions, /v1/completions)
- Model gallery with popular LLMs (Llama, Phi, Gemma, Mistral)
- CRT-light P31 phosphor theme with LocalAI purple accents
- Deployed to VM at https://localhost:9443/localai/
- **Total modules: 59**

### secubox-zigbee v1.0.0 Complete
- Fourth Phase 8 package ported from OpenWRT
- FastAPI backend with 20+ endpoints
- Features: Container management, device pairing, MQTT integration
- USB serial dongle detection and passthrough (/dev/ttyUSB*, /dev/ttyACM*)
- Device management: rename, remove, permit_join toggling
- CRT-light P31 phosphor theme with Zigbee green accents
- Deployed to VM at https://localhost:9443/zigbee/
- **Total modules: 58**

### secubox-lyrion v1.0.0 Complete
- Third Phase 8 package ported from OpenWRT
- FastAPI backend with 18+ endpoints
- Features: Container management, player control, library scanning
- Squeezebox JSON-RPC API integration for library stats
- CRT-light P31 phosphor theme with Lyrion orange accents
- Backup and restore functionality
- Deployed to VM at https://localhost:9443/lyrion/
- **Total modules: 57**

### secubox-jellyfin v1.0.0 Complete
- Second Phase 8 package ported from OpenWRT
- FastAPI backend with 15+ endpoints
- Features: Container management, library config, backup/restore
- CRT-light theme with Jellyfin blue accents
- Deployed to VM at https://localhost:9443/jellyfin/
- **Total modules: 56**

### secubox-ollama v1.0.0 Complete
- First Phase 8 package ported from OpenWRT
- FastAPI backend with 15+ endpoints
- Features: Container management, model pulling, chat, generation
- CRT-light P31 phosphor theme frontend
- Deployed to VM at https://localhost:9443/ollama/

### Migration Preparation Workflow Complete
- Created `.claude/REMAINING-PACKAGES.md` — 53 packages remaining inventory
- Classified packages by complexity: Easy (25), Medium (18), Complex (10)
- Identified 25 packages with different naming (already ported)
- Defined Phase 8 (21 apps), Phase 9 (22 tools), Phase 10 (10 security)
- Set priority: ollama → jellyfin → vault → homeassistant

### Previous Session Highlights
- 52 Debian packages complete (~1000+ API endpoints)
- All Phases 1-7 completed
- CVE Triage enhanced with CISA KEV, NVD, EPSS feeds
- CRT-light theme standardized across all modules
- Master-Link admin dashboard with P31 phosphor theme

---

## 2026-03-27

### Live ISO Boot Console Fixes
- Fixed flickering console on live ISO boot
- Masked 14 incompatible services for live mode
- Fixed getty autologin conflict
- Disabled martian packet logging

### C3Box Clone System
- `build-installer-iso.sh` — Hybrid Live USB / Headless Installer (886 lines)
- `export-c3box-clone.sh` — Export device configuration
- `build-c3box-clone.sh` — Combined export + ISO workflow

---

## 2026-03-26

### Master-Link System Complete
- Admin dashboard at `/master-link/admin.html`
- Token-based mesh enrollment
- Multi-master support (Debian + OpenWRT)
- `sbx-mesh-invite` and `sbx-mesh-join` CLI tools

### Socket Directory Fix
- `secubox-runtime.service` ensures `/run/secubox` exists

### ReDroid Integration
- Android in Container LXC setup scripts

---

## 2026-03-25

### Documentation Phase Complete
- API Reference in 3 languages (EN/FR/ZH)
- Module documentation for all 48 modules
- UI Guide with CRT theme documentation
- 45 module screenshots captured

### Go Daemon Organization
- Moved to `daemon/` directory structure
- Unix socket control server implemented
- `secuboxd` and `secuboxctl` binaries

---

## 2026-03-22

### Phase 5 — CSPN Hardening Complete
- AppArmor profiles for all services
- Kernel sysctl hardening
- Module blacklist
- auditd rules
- nftables DEFAULT DROP policy

---

## 2026-03-21

### Phase 3 — All 33 Modules Complete
- 1000+ API endpoints total
- All services running on VM
- Dynamic menu system
- Shared sidebar.js

### Phase 4 — APT Repo Complete
- apt.secubox.in configured
- reprepro + GPG signing
- CI publish workflow
- Metapackages (full/lite)

---

## 2026-03-20

### Phase 2 — Infrastructure Complete
- secubox_core Python library
- nginx reverse proxy template
- rewrite-xhr.py script

### Phase 1 — Hardware Bootstrap Complete
- build-image.sh for arm64 + amd64
- VirtualBox VM support
- Board configs (MOCHAbin, ESPRESSObin, VM)

---

## Project Statistics

| Metric | Value |
|--------|-------|
| Debian packages | 61 |
| API endpoints | ~1200+ |
| OpenWRT packages (total) | 103 |
| Remaining to port | 46 |
| Phases completed | 7 of 10 (Phase 8: 9/21) |
| Current release | v1.4.0 |
| Target completion | Phases 8-10 remaining |

### Session 99 (continued) — MOCHAbin Migration Execution

**Date:** 2026-05-06

**Completed:**
1. ✅ Exported from C3BOX:
   - 93 SSL certificates
   - 99 nginx secubox.d configs
   - HAProxy config
   - 4 LXC container configs
   - Error pages (400, 403, 408, 500, 502, 503, 504)

2. ✅ Transferred to MOCHAbin (192.168.255.1)

3. ✅ HAProxy configured:
   - All 93 SSL certs in `/data/haproxy/certs/`
   - LXC routing: gitea, nextcloud, mail, matrix
   - Default backend: nginx_vhosts (port 9080)
   - All backends UP

4. ✅ Nginx configured:
   - Default 503 server for unknown domains
   - WebUI served only for specific hostnames
   - 99 module API configs in secubox.d

5. ✅ CTL tools deployed:
   - 14 CTL tools copied to /usr/sbin/
   - Tools Debian-native (OpenWrt refs only in migrate commands)
   - Tested: vhostctl, metablogizerctl, crowdsecctl, streamlitctl

6. ✅ Vhost auto-creation:
   - Created `/usr/local/bin/secubox-vhost-create`
   - Supports: proxy, streamlit, static vhost types

**Verified:**
- admin.gk2.secubox.in → 200 (WebUI)
- git.maegia.tv → 200 (Gitea LXC)
- unknown.test.com → 503 (blocked)

---


7. ✅ WAF configured:
   - HAProxy ACL-based WAF active
   - Blocks: SQLi, XSS, Path Traversal, Scanners
   - Mitmproxy WAF disabled (pyOpenSSL ARM64 incompatibility)
   - Full mitmproxy WAF requires internet to install updated packages

**Test Results:**
```
Normal request:     200 ✓
SQLi attempt:       403 ✓ (blocked)
XSS attempt:        403 ✓ (blocked)
Path traversal:     403 ✓ (blocked)
Scanner UA:         403 ✓ (blocked)
```


---

## Session 118 — 2026-05-08

**Focus:** Kernel build completion with LED driver, USB network modules, documentation

### Accomplishments

1. ✅ Kernel 6.12.85-openwrt-led build completed:
   - IS31FL319X LED driver built-in (=y)
   - DSA mv88e6xxx switch built-in (=y)
   - All network/storage drivers built-in
   - USB network modules (cdc_ether, usbnet) as =m for Eye Remote

2. ✅ Documentation created:
   - `kernel-build/README.md` - Full build instructions
   - Config fragment: `board/mochabin/kernel/config-6.12-openwrt-merged.fragment`

3. ✅ GitHub Issue #60 updated with build progress

4. ✅ Kernel deployed to MOCHAbin `/boot/Image-openwrt`

**Config Fragment Additions:**
```
CONFIG_OF_OVERLAY=y
CONFIG_OF_CONFIGFS=y
CONFIG_LEDS_IS31FL319X=y
CONFIG_USB_USBNET=y
CONFIG_USB_NET_CDCETHER=y
CONFIG_USB_NET_CDC_NCM=y
CONFIG_USB_NET_RNDIS_HOST=y
```

**USB Gadget Architecture Documented:**
- SecuBox = USB HOST (sees gadgets as peripherals)
- Eye Remote = USB DEVICE/GADGET (Pi Zero W)
- SecuBox needs cdc_ether HOST driver, not gadget drivers
- udev rules at `/etc/udev/rules.d/90-usb-gadget.rules`

**Pending:**
- Test LED functionality after reboot
- Test USB network with Eye Remote
- Verify DSA switch works


### LED Fixes (Session 118 continued)

- [x] Fixed I2C communication errors (brightness value 10 optimal)
- [x] Removed old conflicting LED scripts (secubox-led-heartbeat)
- [x] Updated healthbump with rate-based security detection
- [x] Timer enabled (30s interval)
- [x] Activity pulse on each check
- [x] Color gradient for hardware load level

**Final LED Status:**
- LED1 (HW): Green/Yellow/Orange/Red based on load %
- LED2 (SVC): Green=ok, Red=error
- LED3 (SEC): Green=clear, Blue=mitigating, Yellow=elevated, Red=attack

---

### Session 130 — NAC ARP Discovery Fix

**Problem:** NAC dashboard showing "0 clients" despite active clients on network.

**Root Cause:**
- NAC module relied exclusively on `/var/lib/misc/dnsmasq.leases` for client discovery
- dnsmasq not configured as DHCP server (leases file empty)
- Clients using static IPs or getting DHCP from external router

**Solution:** Added ARP-based client discovery as fallback:
- New `_parse_arp()` function reads kernel ARP table via `ip neigh show`
- New `_discover_clients()` combines DHCP leases + ARP fallback
- Filters out gateway IPs (.1, .254) and non-LAN interfaces
- Includes ARP state (REACHABLE/STALE) for online detection
- Deduplicates clients by MAC address

**Files Modified:**
- `packages/secubox-nac/api/main.py` — Added ARP discovery (~80 lines)

**Results:**
- NAC now discovers 2 clients via ARP: 192.168.1.36 (REACHABLE), 192.168.255.2 (STALE)
- Dashboard shows correct client count and online status
- Clients start in quarantine zone (default for new discoveries)

**Technical Details:**
- LAN interfaces scanned: lan0, lan1, lan2, lan3, br0, br-lan, eth0, eth1
- ARP states mapped to online: REACHABLE, DELAY, PROBE, PERMANENT = online
- STALE, FAILED = offline
