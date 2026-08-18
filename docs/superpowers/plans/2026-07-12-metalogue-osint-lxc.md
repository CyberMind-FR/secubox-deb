<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# metalogue OSINT — LXC Modules Implementation Plan (P1 + P2)

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development
> to implement this plan task-by-task. Steps use checkbox (`- [ ]`) tracking.

**Goal:** Ship two self-hosted OSINT LXC modules on gk2 — `secubox-maigret`
(identity collector) and `secubox-spiderfoot` (automation engine + interim
Maltego-style correlation graph) — each SecuBox-integrated (WAF-routed, navbar,
status probe). OpenCTI graph hub is Phase 3 (deferred, separate node) — out of
scope here. Tracks #845.

**Architecture:** Each module = one unprivileged LXC container (10.100.0.x) running
the tool as a systemd unit, fronted by a host `api/main.py` (FastAPI on a
`/run/secubox/<mod>.sock`) that proxies/controls it and exposes a status probe;
nginx `secubox.d/<mod>.conf` routes the vhost **through sbxwaf** (no bypass); a
`menu.d` entry adds the navbar tile; a `<mod>ctl` root helper + `sudoers.d` do
container lifecycle. Mirrors the existing **openclaw** module exactly.

**Tech Stack:** Debian bookworm arm64, LXC (unprivileged, 10.100.0.x like existing
containers), Python 3.11 + FastAPI + uvicorn (host wrapper), Maigret (pip),
SpiderFoot (git/pip), nginx + sbxwaf, systemd.

## Global Constraints

- **No WAF bypass** — every vhost routes through sbxwaf; add routes additively to
  `haproxy-routes.json` (both files), reload mitmproxy/sbxwaf. (CLAUDE.md)
- **Status probe MUST probe the daemon port**, not `sudo lxc-info` (NNP blocks it →
  false red). Green = the in-container service answers on its port.
- **Least privilege**: `<mod>ctl` + `sudoers.d/secubox-<mod>` grant only the exact
  lxc-start/stop/attach lines needed; daemon runs as `secubox` on the host side.
- **Never chown shared dirs**: `/run/secubox` (1777 root), `/var/log/secubox`
  (0755), `/etc/secubox` parent (0755). RuntimeDirectoryPreserve=yes on units.
- **Packaging**: `secubox-<mod>` arch:all, compat 13, Standards-Version 4.6.2,
  postinst provisions the LXC idempotently and never mass-restarts daemons.
- **Master users** `gk2` / `admin` supported; security actions audited to
  `/var/log/secubox/audit.log`.
- **CSPN guardrails on collectors**: conservative default rate limits, no unbounded
  crawls, opt-in only for aggressive sources.

---

### Task 1: Reference-extract the openclaw module skeleton

**Files:**
- Read: `packages/secubox-openclaw/{debian/*,api/main.py,sbin/openclawctl,nginx/*,menu.d/*,www/openclaw/index.html}`

- [ ] **Step 1:** Catalogue every openclaw file and its role (control, rules,
  postinst LXC provisioning, sudoers, ctl helper, api probe, nginx secubox.d,
  menu.d, www panel). Produce a one-file-per-line mapping to reuse as the
  scaffold for both new modules.
- [ ] **Step 2:** Note the exact status-probe implementation in
  `openclaw/api/main.py` (how it decides up/down without sudo) — this is the
  pattern both modules copy.
- [ ] **Step 3:** Note openclaw's container name, IP, and how postinst creates
  the LXC (base image, network) — the two new containers follow the same recipe
  with new names/IPs (`maigret` 10.100.0.42, `spiderfoot` 10.100.0.43 — verify
  free with `lxc-ls -f`).

---

### Task 2: `secubox-maigret` — package scaffold + host FastAPI wrapper

**Files:**
- Create: `packages/secubox-maigret/{debian/control,debian/rules,debian/changelog,debian/postinst,debian/prerm,debian/compat|debhelper-compat}`
- Create: `packages/secubox-maigret/api/main.py` (host wrapper: status probe + job API)
- Create: `packages/secubox-maigret/sbin/maigretctl`
- Create: `packages/secubox-maigret/debian/secubox-maigret.sudoers`
- Test: `packages/secubox-maigret/tests/test_api.py`, `tests/test_maigretctl_guards.sh`

**Interfaces:**
- Produces: `GET /api/v1/maigret/status` → `{running: bool, container: str}`;
  `POST /api/v1/maigret/lookup {username}` → `{job_id}`;
  `GET /api/v1/maigret/jobs/{id}` → `{state, results?}` (async — Maigret lookups
  are slow; queue + poll, never block the loop; run the CLI via
  `lxc-attach` in a thread/subprocess with a timeout + kill-on-timeout).

- [ ] **Step 1 (test):** `test_api.py` — status returns down when the probe socket
  refuses; `POST /lookup` returns a job_id and `GET /jobs/{id}` transitions
  pending→done with parsed results (mock the container-exec layer).
- [ ] **Step 2 (impl):** host wrapper (FastAPI on `/run/secubox/maigret.sock`,
  aggregator-served or own unit — match openclaw). Probe = TCP connect to the
  container service port (or `lxc-attach ... pgrep`), never `sudo lxc-info`.
  Job store = in-memory dict + a bounded worker; lookups run
  `maigretctl lookup <user>` with a hard timeout and process-group kill.
- [ ] **Step 3 (test):** `test_maigretctl_guards.sh` — the ctl helper rejects
  usernames with shell metacharacters / path traversal; only the whitelisted
  lxc verbs are allowed.
- [ ] **Step 4 (impl):** `maigretctl` — `start|stop|status|lookup <user>` via the
  exact `lxc-*` lines in `sudoers.d`; validate `<user>` against
  `^[A-Za-z0-9_.-]{1,64}$` before use.
- [ ] **Step 5:** run tests green; commit.

---

### Task 3: `secubox-maigret` — LXC provisioning (postinst) + in-container service

**Files:**
- Modify: `packages/secubox-maigret/debian/postinst` (idempotent LXC create + Maigret install)
- Create: in-container unit template (installed by postinst into the container)

- [ ] **Step 1:** postinst: if container `maigret` absent, `lxc-create` (same base
  as openclaw), assign 10.100.0.42, `apt install python3-venv`, `pip install
  maigret` inside; idempotent (guard on existence). Fail soft with a printed
  remediation line (billets/openclaw pattern), never abort the dpkg run.
- [ ] **Step 2:** ship a tiny in-container HTTP shim (or rely on `lxc-attach`
  exec from the host wrapper) so the host probe has a port to check. Decide:
  exec-over-attach (no in-container port) vs a minimal FastAPI in the container.
  Prefer exec-over-attach for Maigret (no long-running daemon needed) — the
  status probe then checks `lxc-info -s` **via the host wrapper's own cached
  attach**, not sudo. Document the chosen probe.
- [ ] **Step 3:** verify a real `maigretctl lookup <user>` inside the container
  returns parseable JSON (`--json`), bounded by timeout.
- [ ] **Step 4:** commit.

---

### Task 4: `secubox-maigret` — nginx WAF route + navbar + panel

**Files:**
- Create: `packages/secubox-maigret/nginx/maigret.conf` (→ `etc/nginx/secubox.d/`)
- Create: `packages/secubox-maigret/menu.d/710-maigret.json`
- Create: `packages/secubox-maigret/www/maigret/index.html` (guideline panel: cyan/Courier Prime/emoji, per WEBUI-PANEL-GUIDELINES.md — a lookup form + results + status)

- [ ] **Step 1:** nginx `secubox.d/maigret.conf` proxying `/api/v1/maigret/*` +
  `/maigret/` panel to the host socket; add the vhost to sbxwaf
  `haproxy-routes.json` (both files) additively; reload.
- [ ] **Step 2:** `menu.d/710-maigret.json` — 🔎 tile, Security category (near
  openclaw 708).
- [ ] **Step 3:** panel `index.html` to the WebUI guideline (status pill, username
  field, results list; `sbx_token` bearer; `esc()` on all injected values).
- [ ] **Step 4:** commit; build `.deb`; verify contents.

---

### Task 5: `secubox-spiderfoot` — package + LXC + native web/REST behind WAF

**Files:**
- Create: `packages/secubox-spiderfoot/{debian/*,api/main.py,sbin/spiderfootctl,nginx/spiderfoot.conf,menu.d/711-spiderfoot.json,www/spiderfoot/index.html}`
- Test: `packages/secubox-spiderfoot/tests/`

**Interfaces:**
- SpiderFoot ships its OWN web UI + REST on a port inside the container — the host
  wrapper mainly does the status probe + proxies; the WAF route fronts SpiderFoot's
  UI directly (WAF-gated, SecuBox-auth in front).

- [ ] **Step 1:** postinst provisions container `spiderfoot` 10.100.0.43, installs
  SpiderFoot (git clone + pip in a venv), a systemd unit inside running
  `sf.py -l 127.0.0.1:5001`; idempotent.
- [ ] **Step 2:** host `api/main.py` status probe = TCP connect to the container's
  5001; `GET /api/v1/spiderfoot/status`. Never sudo-lxc-info for red/green.
- [ ] **Step 3:** nginx `secubox.d/spiderfoot.conf` proxies `/spiderfoot/` to the
  container UI; add WAF route (both files) additively; reload. Ensure SpiderFoot
  runs behind SecuBox auth (WAF gate) — do NOT expose its unauthenticated UI.
- [ ] **Step 4:** `menu.d/711-spiderfoot.json` 🌀 tile; minimal launcher panel
  (status + "open" — SpiderFoot has its own UI).
- [ ] **Step 5:** `spiderfootctl start|stop|status` + sudoers; guards test.
- [ ] **Step 6:** tests green; commit; build `.deb`; verify.

---

### Task 6: Interconnect note + deploy + verify (both modules)

- [ ] **Step 1:** Document the collector→hub bridge: Maigret/openclaw findings →
  SpiderFoot (as the interim correlation hub) via SpiderFoot's API/import; leave a
  stub `metalogue-bridge` note for the Phase-3 OpenCTI connector. (No heavy build.)
- [ ] **Step 2:** Deploy both `.deb`s to gk2; run postinst LXC provisioning;
  confirm both containers up (`lxc-ls -f`), both status probes green, both panels
  render behind the WAF, both navbar tiles appear.
- [ ] **Step 3:** Live smoke: `maigret lookup <known-username>` returns a dossier;
  SpiderFoot UI loads a scan. Confirm memory headroom on gk2 stays healthy
  (`free -h` — both are light; abort/roll back if free RAM drops dangerously).
- [ ] **Step 4:** Update `.claude/HISTORY.md`, `MIGRATION-MAP.md`, WIP; comment
  #845 with progress (do not close). Adversarial review before merge.

---

## Deferred (Phase 3 — separate issue/plan)
- **OpenCTI** graph hub on the amd64 mesh node / dedicated hardware; connectors
  from SpiderFoot + Maigret + openclaw; migrate the hub role from SpiderFoot to
  OpenCTI; cross-mesh WAF route to the gk2 navbar.
