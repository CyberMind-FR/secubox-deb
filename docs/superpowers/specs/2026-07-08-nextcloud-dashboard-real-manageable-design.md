# Nextcloud Dashboard — Real Data + Manageable Users — Design

**Date:** 2026-07-08
**Module:** `packages/secubox-nextcloud`
**Status:** Design — pending user review

---

## Goal

Make the Nextcloud admin dashboard (`admin.gk2.secubox.in/nextcloud/`) show **real
data** and be **fully manageable**, fixing the root causes behind today's wrong
output, plus a cosmetics/robustness pass:

- **A. Real LXC status** — no more false "not running" (the unprivileged
  `lxc-info` gotcha).
- **B. Real URLs** — the WAF-fronted vhost, not `localhost:8080`.
- **C. Real users, synced + fully manageable** — live `occ user:list` + full CRUD
  (add / delete / enable / disable / quota / reset-password) from the WebUI.
- **D. Cosmetics + robustness** — loading/empty/error states, storage quota bar,
  toasts, auto-refresh, responsive; XSS-escape, confirm destructive ops,
  fail-safe fetch, 401→login.

---

## Root causes (diagnosed on the live board)

1. **Privilege path.** The module is served in-process by `secubox-aggregator`
   (user `secubox`, `NoNewPrivileges=no`, so sudo *is* available). But
   `api/main.py` shells `lxc-info` / `lxc-attach` **directly** and `secubox`'s
   sudoers has **no** entry for them → every container op silently fails →
   `running=false` (false red), empty `occ`, empty user list, no version.
2. **URLs are hard-coded** `http://localhost:{http_port}` in `/status` and
   `/connections`. The real user-facing URL is the vhost
   `https://nc.gk2.secubox.in` (HAProxy TLS → nginx `:9080` →
   container `10.100.0.21:80`).
3. **User management is reset-password only** (`POST /user/password`); no
   add/delete/enable/disable/quota.

`sbin/nextcloudctl` already runs privileged container ops correctly
(`lxc_running` with `-P $LXC_PATH`, an `occ` passthrough, `user {add|del|list}`),
so the fix is to **route the API through `sudo nextcloudctl`** (a sanctioned
helper, like `secubox-appstorectl`) rather than raw `lxc-*`.

---

## A. Real LXC status

- **New helper `ctl(subcmd, ...) -> (ok, out, err)`** in `api/main.py` that runs
  `sudo -n /usr/sbin/nextcloudctl <subcmd> …`. All container ops (`lxc_running`,
  `occ_cmd`, user ops, ssl) route through it. Raw `lxc-info`/`lxc-attach` calls
  are removed.
- **`lxc_running()`** → `sudo nextcloudctl status --json` (add a `--json`/machine
  mode to `cmd_status`, OR parse its existing output) returning
  `{running, installed, version, user_count}`. Authoritative + privileged.
- **Reachability port-probe** — in addition, `/status` does a short TCP connect
  to the container (`10.100.0.21:80`, from config `container_ip`/`http_port`) and
  reports `reachable: bool`, so "running but not serving" is distinguishable from
  "serving". Fail-safe (timeout 1.5s → `reachable:false`, never raises).
- **`/status` gains** `running` (from ctl), `reachable` (probe), keeps
  `installed`, `version`, `user_count`, `disk_used`.

**Packaging — sudoers drop-in** (`debian/`): install
`/etc/sudoers.d/secubox-nextcloud`:
```
secubox ALL=(root) NOPASSWD: /usr/sbin/nextcloudctl
```
`0440 root:root`, `visudo -cf` checked in `postinst`. (Security note: this grants
`secubox` full `nextcloudctl` incl. its `occ` passthrough — admin-JWT-gated at
the API, and consistent with the existing `secubox-appstorectl` NOPASSWD grant.)

## B. Real URLs

- Config/env gains `public_url` (default derived: `https://<domain>` where
  `domain=nc.gk2.secubox.in`) and `container_ip` (`10.100.0.21`).
- **`/connections`** returns `base_url = public_url` (the vhost), with correct
  `webdav`/`caldav`/`carddav`/`davx5`/`desktop` URLs on it, plus a
  `lan_url` fallback (`http://<board-lan-ip>:<vhost-port>` when known). No more
  `localhost`.
- **`/status.web_url`** = `public_url`.
- The `<username>` placeholders in dav URLs stay (they are per-user templates) —
  the UI labels them clearly and, on a selected user row, can substitute the uid.

## C. Real users, synced + manageable

**`sbin/nextcloudctl` — extend the `user` dispatch** (currently `add|del|list`):
- `user list` → switch to `occ user:list:detailed --output=json` (gives
  `enabled`, `quota`, `displayname`, `last_login`, `email` per uid). Fall back to
  `user:list --output=json` if `:detailed` unsupported.
- `user enable <uid>` → `occ user:enable <uid>`
- `user disable <uid>` → `occ user:disable <uid>`
- `user quota <uid> <quota>` → `occ user:setting <uid> files quota <quota>`
  (quota like `5GB`, `none`, `default`).
- `user setpass <uid>` (env `SECUBOX_USER_PASSWORD`) — already exists as
  `user-provision`/reset; expose a thin `user setpass` alias for the API.
Each validates the uid (`^[A-Za-z0-9._@-]+$`) before interpolation (injection
guard — these run in a shell inside the container).

**`api/main.py` — new/updated endpoints** (all `Depends(require_jwt)`, all via
`ctl`):
- `GET  /users` → the detailed list (uid, displayname, enabled, quota, last_login).
- `POST /user` `{uid, display_name, password}` → `nextcloudctl user add …`.
- `DELETE /user/{uid}` → `nextcloudctl user del <uid>`.
- `POST /user/{uid}/enable` / `POST /user/{uid}/disable`.
- `POST /user/{uid}/quota` `{quota}`.
- `POST /user/password` `{uid}` (existing) — kept.
Server-side uid validation mirrors the ctl guard; the container-not-running case
returns a clean 409, not a 500.

## D. Frontend rework (`www/nextcloud/index.html`, P31 skin kept)

- **Status pill** — color-coded running / stopped / not-installed / unreachable,
  driven by `running`+`reachable`+`installed`.
- **Storage** — quota bar (used vs total, %), not just a number.
- **Users card** — real table (uid, name, enabled toggle, quota, last login) with
  an **Add user** form and per-row **enable/disable, set quota, reset password,
  delete** (typed confirm for delete).
- **Connection URLs** — the real vhost URLs, copy-to-clipboard buttons.
- **Surfaced API** (from the earlier scope): Logs viewer (`/logs`), occ console
  (`/occ`, confirm), Update (`/update`), SSL card (`/ssl/*`), Config editor
  (`/config`), guarded **Uninstall** (Danger zone, typed confirm).
- **UX:** per-card loading/empty/error states; pausable auto-refresh of
  status/storage; `toast()` on every action; responsive card grid.
- **Robustness:** `esc()` on every backend string rendered into innerHTML (uids,
  names, log lines, occ output, URLs) — closes the XSS surface; fail-safe `api()`
  (status-aware errors, never stuck); `401 → login redirect`; disable
  container-ops buttons when not running; JWT from `localStorage.sbx_token`
  (existing pattern).

---

## Error handling

- Every `ctl` call is fail-safe: non-zero exit → structured error surfaced as a
  toast, never an unhandled 500; container-not-running → 409 with a clear message.
- Port-probe bounded (1.5s), never raises.
- Frontend: each card renders an error state on `api()` failure; destructive ops
  require confirm (typed for delete-user/uninstall).
- uid/quota inputs validated both client- and server-side + in `nextcloudctl`.

---

## Testing

- **`nextcloudctl`** — `bash -n` syntax check; on the board (nextcloud running):
  `sudo nextcloudctl user list` returns detailed JSON; `user enable/disable/quota`
  round-trip on a throwaway test uid; uid-validation rejects `a;rm` etc.
- **API** — against the live board via the aggregator: `/status` shows
  `running:true, reachable:true`; `/connections.base_url == https://nc.gk2.secubox.in`;
  `/users` non-empty + detailed; create→list→disable→enable→quota→delete a test
  user round-trips; a bad uid → 400/409 not 500.
- **Frontend** — extract inline `<script>` + `node --check`; manual pass on the
  live dashboard: status pill correct, real URLs, user CRUD works, logs/occ/ssl/
  config/uninstall panels function, toasts + confirms fire, XSS payload in a
  display name renders escaped.
- **sudoers** — `visudo -cf /etc/sudoers.d/secubox-nextcloud` clean; `secubox`
  can `sudo -n nextcloudctl status`.

---

## Files

- `packages/secubox-nextcloud/api/main.py` — `ctl` helper + privilege routing;
  port-probe status; real URLs; user CRUD endpoints; 409 on not-running.
- `packages/secubox-nextcloud/sbin/nextcloudctl` — `user enable|disable|quota`,
  detailed `user list`, `user setpass` alias, uid validation, machine-readable
  `status --json`.
- `packages/secubox-nextcloud/debian/` — `sudoers.d/secubox-nextcloud` install +
  `postinst` `visudo` check; `conf/nextcloud.toml.example` gains
  `public_url`/`domain`/`container_ip`.
- `packages/secubox-nextcloud/www/nextcloud/index.html` — the rework.

---

## Out of scope

- Changing the NC container itself, HAProxy/nginx vhost, or Authelia gating.
- Per-user dav-URL substitution beyond showing the template + selected-uid fill.
- Backend user *sync to* other modules (this reads NC as source of truth).
