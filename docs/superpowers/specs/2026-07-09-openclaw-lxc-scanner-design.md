<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# OpenClaw — Dedicated-LXC OSINT + Active Scanner — Design

**Date:** 2026-07-09
**Module:** `packages/secubox-openclaw`
**Status:** Design — pending user review

---

## Goal

Turn `secubox-openclaw` into a **working** OSINT + active-scan module whose scan
toolchain runs in a **dedicated, sandboxed LXC container**, following the
`secubox-nextcloud` pattern (privileged `*ctl` helper + sudoers + `ctl()`
routing + single-flight/stale-while-revalidate cache + plain-`def` handlers).
Today the module has a 1043-line OSINT API but: the scan handlers are
`async def` running `subprocess` (would block the shared aggregator loop — the
same SPOF just fixed in nextcloud), the frontend is a non-wired stub, and no
container exists. This design fixes all three and adds active (nmap) scanning
under a safe target policy.

---

## Root problems (diagnosed on the live board)

1. **No isolation.** Scan tools (`dig`/`whois`/port-scan) run on the host. A
   scanner is exactly the kind of tool to sandbox (exploitable parsers, targets
   that attack back).
2. **Aggregator-loop SPOF.** `openclaw` is mounted in-process by
   `secubox-aggregator` (`aggregator.toml` line 69; nginx `/api/v1/openclaw/`
   → `aggregator.sock`). 32 `async def` handlers call blocking subprocess /
   `asyncio.create_subprocess_exec`. A multi-minute `nmap` (or even a slow
   `whois`) on the shared loop freezes all ~110 modules → board-wide 502s.
3. **Stub frontend.** `www/openclaw/index.html` has the scan UI shell but almost
   no `fetch` wiring; buttons call undefined/placeholder handlers.

---

## Architecture: container = stateless sandboxed tool-runner

A persistent **`openclaw` LXC** provides the tools; **orchestration, storage,
and policy stay host-side** in the module.

- **Container:** debootstrap `--variant=minbase` bookworm rootfs at
  `/data/lxc/openclaw/rootfs`, veth on `br-lxc`, static IP **`10.100.0.41/24`**,
  gateway `10.100.0.1`, SecuBox DNS — identical bootstrap to `nextcloudctl`.
  Installed toolchain: `nmap` (+ its NSE scripts), `dnsutils` (`dig`), `whois`,
  `curl`, `ca-certificates`. No app data lives in the container; it is a pure
  tool-runner invoked per scan via `lxc-attach`.
- **Host module (aggregator-mounted):** the FastAPI app validates input,
  enforces target policy, spawns/reads scan jobs, stores results, serves the
  dashboard. Reachable at `/api/v1/openclaw/` via the aggregator socket
  (unchanged); the dedicated `secubox-openclaw.service`/`openclaw.sock` stays
  present but unused (aggregator serves it), matching nextcloud.

Container IP `10.100.0.41` is free (nextcloud=`.21`; `.30` unused).

---

## Control plane: `openclawctl` + sudoers (mirrors `nextcloudctl`)

`sbin/openclawctl` (bash, `set -euo pipefail`) is the ONLY privileged surface:

- `install` — debootstrap rootfs, write LXC config, install the toolchain,
  start the container. Idempotent (`lxc_exists` guard). Long-running →
  driven detached by the API (like `nextcloudctl install`).
- `start` / `stop` — `lxc-start`/`lxc-stop -n openclaw -P /data/lxc`.
- `status --json` — `{running, installed, tools:{nmap,dig,whois,curl}, ip}`.
  Authoritative + privileged; used by the module's `lxc_running()`/status.
- `scan <type> <target> <scan_id>` — `openclawctl` runs **on the host** and
  `lxc-attach`es the appropriate tool(s) **inside the container**, capturing
  their stdout on the host; it then parses and writes the raw+parsed result JSON
  to the host path `/var/lib/secubox/openclaw/scans/<scan_id>.json`, updating
  status `running`→`completed`/`failed`. No bind-mount — the container stays a
  stateless tool-runner; all result I/O is host-side.
- `selftest` — `lxc-attach openclaw -- nmap --version` etc., for CI/verify.

**Injection guards** (defense in depth, mirrors nextcloud `_valid_uid`): every
`type`, `target`, and `scan_id` is validated against a strict charset
(`^[A-Za-z0-9._:@/-]+$` for targets, hostname/IP/CIDR-shaped; `^[a-f0-9]{8}$`
for scan_id) **before** any shell/`lxc-attach` interpolation; targets are passed
as positional args to the inner `sh -c '…"$1"'`, never string-interpolated.

**Privilege routing:** API `ctl(subcmd) = sudo -n /usr/sbin/openclawctl …` +
`debian/secubox-openclaw.sudoers`:
`secubox ALL=(root) NOPASSWD: /usr/sbin/openclawctl` (`0440 root:root`, `visudo
-cf` checked in `postinst`, removed-on-invalid, never aborts install).

---

## Scan execution — async job model (no request-path blocking)

`nmap` runs for minutes, so a scan NEVER runs on the request path:

1. `POST /scan/{domain,ip,email}` (body `{target, authorized?: bool}`):
   validate target + enforce **target policy** (below) → write a `pending` scan
   record to `scans/<id>.json` → spawn a **detached worker**
   (`subprocess.Popen(["sudo","-n","/usr/sbin/openclawctl","scan",type,target,id])`,
   fully detached like `nextcloudctl install`) → return `{scan_id, status:
   "started"}` immediately.
2. The worker (running as the privileged helper, off the aggregator entirely)
   `lxc-attach`es the tools, parses output, writes `running`→`completed`/`failed`
   with results.
3. `GET /scan/{id}` reads the file; `GET /scans` lists records (newest first);
   `DELETE /scan/{id}` removes one (id-validated, no path traversal).

**Quick lookups** (`/dns/{domain}`, `/whois/{target}`, `/certs/{domain}`,
`/ports/{ip}`) are short (<~5s) → run **synchronously in-container** via
`ctl(["scan","dns",domain,…])`-style calls in a plain `def` handler (FastAPI
threadpool — off the loop). `/status` uses the single-flight +
stale-while-revalidate cache ported verbatim from nextcloud (15s TTL).

**All handlers become plain `def`.** The existing `async def` + `asyncio`
subprocess machinery (`_run_scan`, `_whois_lookup`, `_port_check`,
`create_subprocess_exec`, …) is removed/replaced by the ctl + async-job path.
No handler blocks the loop; no scan ties up a threadpool thread for minutes.

---

## Target policy + audit (CSPN)

- **Passive OSINT** (dns, whois, certs, subdomains, reputation, cert-transparency)
  — unrestricted (external targets allowed).
- **Active scans** (`nmap` port/service/NSE) — allowed by default only when the
  target is **RFC1918/LAN** or a **box-owned domain** (resolved against
  `/etc/secubox/waf/haproxy-routes.json` + first-party list, same source
  nextcloud/exposure use). An external active target is refused with **409**
  unless the request carries `authorized: true`.
- **Audit:** every active scan writes an append-only line to
  `/var/log/secubox/audit.log`: `ts, operator(sub from JWT), type, target,
  authorized, scan_id`. Never truncated (respects the
  `/var/log/secubox` 0755 traversal + append-only rules).

Target classification is a small pure helper (`_is_local_or_owned(target)`),
unit-tested.

---

## Frontend rework (`www/openclaw/index.html`, keep skin)

Wire the existing shell to the API, mirroring the nextcloud dashboard's
robustness:

- **Status pill** — container running / installed / reachable, driven by
  `/status`; an **Install** action (Danger-zone-adjacent) when not installed
  (calls `/install`, polls status).
- **Scan launcher** — one target box + auto-detected type (domain/IP/email/CIDR);
  active-scan of an external target shows an **"I am authorized"** typed confirm
  before POST (sets `authorized:true`).
- **Scan history** — real table from `/scans` (id, type, target, status, time)
  with per-row **View** (renders `/scan/{id}` results) and **Delete** (typed
  confirm). Auto-refreshes running scans until terminal.
- **Quick lookups** — DNS / whois / certs / ports panels calling the sync
  endpoints, results rendered inline.
- **Config** — Shodan/Censys/VirusTotal/SecurityTrails keys (`/config`),
  integrations status (`/integrations`).
- **Robustness** — `esc()` on every rendered backend string (targets, tool
  output, hostnames — closes XSS), fail-safe `api()` (401→login), `sbx_token`
  from `localStorage`, per-panel loading/empty/error states, no
  `onclick`-with-interpolated-data (data-attrs + delegated listeners, per the
  nextcloud XSS fix).

---

## Data / files

- `/data/lxc/openclaw/` — container rootfs + config (created by `openclawctl
  install`).
- `/var/lib/secubox/openclaw/scans/<id>.json` — scan records (host-side, owner
  `secubox`; the module mkdir's it at import like other modules, honoring the
  0755 parent traversal rule).
- `/etc/secubox/openclaw.toml` — config (API keys via
  `/etc/secubox/secrets/` if sensitive, chmod 600; non-secret options in TOML).
- `/var/log/secubox/audit.log` — active-scan audit (append-only).

---

## Error handling

- Every `ctl()` call fail-safe → `(ok,out,err)`, never raises; container-not-
  installed / not-running → clean **409** (not 500), surfaced as a dashboard
  toast with an Install/Start hint.
- Detached worker wraps the scan in try/except → writes `failed` + error into
  the scan record; the dashboard shows it. A worker crash never wedges the API.
- Target-policy refusal → 409 with a clear message; bad target charset → 400.
- Port-probe / reachability bounded (≤1.5s), never raises.

---

## Testing

- **`openclawctl`** — `bash -n`; on the board after install: `openclawctl
  selftest` (nmap/dig/whois present in container); a `scan dns example.com`
  round-trip writes a valid record; injection strings (`a;rm`, newlines)
  rejected by the guards.
- **API (pytest, stub `ctl`)** — target-policy matrix (LAN allowed, external
  active refused without `authorized`, external active allowed with it, passive
  always allowed); async-job lifecycle (POST returns id + pending → worker
  writes completed → GET returns it); `def`-handler + single-flight cache
  (ported nextcloud tests); 409 when container down; bad target → 400.
- **Frontend** — extract inline `<script>` + `node --check`; live pass on gk2:
  status pill correct, LAN IP scan + domain recon render, history/quick-lookups
  work, external-active confirm gate fires, XSS payload in tool output renders
  escaped.
- **Live e2e (gk2)** — `install` builds the container; scan a LAN IP (`nmap`) and
  a domain (recon); results render; other modules stay responsive during a
  multi-minute scan (no aggregator-loop block — the whole point).

---

## Files

- `packages/secubox-openclaw/api/main.py` — rewrite: `ctl()` privilege routing,
  plain-`def` handlers, async-job scan model, target policy + audit, ported
  single-flight/stale-while-revalidate `/status` cache; delete the async/asyncio
  subprocess machinery.
- `packages/secubox-openclaw/sbin/openclawctl` — new privileged helper
  (install/start/stop/status/scan/selftest + guards).
- `packages/secubox-openclaw/debian/` — `secubox-openclaw.sudoers` +
  `postinst` `visudo` check; `control` Depends add `debootstrap`, `lxc`
  (container tooling on host; the scan tools live in the container, not host
  deps); `conf/openclaw.toml.example`.
- `packages/secubox-openclaw/www/openclaw/index.html` — wire + harden the UI.
- `packages/secubox-openclaw/systemd/secubox-openclaw.service` — leave as the
  unused dedicated fallback (aggregator serves it); ensure it is not enabled by
  postinst.

---

## Out of scope

- Changing the aggregator mount, nginx routing, or HAProxy for openclaw.
- Distributed/scheduled scans, scan queueing beyond the detached-worker model,
  or a scan-results database (flat JSON files suffice at this scale).
- Replacing the container base or bridging scheme (reuse nextcloud's).
- Building NSE scripts; we ship stock nmap NSE only.

---

## Open decisions for the plan

1. **Result storage:** host-side flat JSON (chosen) vs a bind-mount into the
   container. Host-side keeps the container stateless and avoids unprivileged-
   LXC read issues — lock this in the plan.
2. **Quick-lookup execution:** sync-in-container `def` (chosen, ≤5s) vs folding
   them into the async-job model. Keep sync for snappy UX; revisit only if a
   lookup proves slow.
