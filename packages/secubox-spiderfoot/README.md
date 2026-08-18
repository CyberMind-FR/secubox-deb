<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🌀 SecuBox SpiderFoot

SpiderFoot OSINT automation engine for the SecuBox appliance — **200+ passive
OSINT modules and a correlation graph**, the interim **Maltego-style
correlation hub**. Runs [SpiderFoot](https://github.com/smicallef/spiderfoot)
(FOSS, MIT) inside a dedicated LXC sandbox.

**Category:** OSINT / auth

## Model

Unlike a CLI wrapper, SpiderFoot ships its **own web UI + REST API**. This
module therefore only does **LXC lifecycle + a status probe + reverse-proxies
the container UI** behind the SecuBox WAF/auth front — it does **not** wrap
scans (scans are driven inside SpiderFoot's own UI).

```
aggregator (user: secubox)  ──imports──▶  api/main.py  (mounted in-process)
        │  sudo -n /usr/sbin/spiderfootctl …        (the ONLY privileged surface)
        ▼
   spiderfootctl ──lxc-attach──▶ spiderfoot container (10.100.0.43, debootstrap bookworm)
        │                          in-container systemd: spiderfoot.service
        │                          /opt/spiderfoot/venv/bin/python sf.py -l 10.100.0.43:5001
        ▼
   SpiderFoot's OWN web UI + REST  ──nginx reverse-proxy──▶  /spiderfoot-ui/ (WAF/auth-fronted)
```

- **Sandboxed** — SpiderFoot runs in a dedicated LXC container (memory cap
  1536M), never on the host.
- **Bound to the container IP** — `sf.py -l 10.100.0.43:5001` so the host nginx
  can reach it. It is **never** bound to a host port or exposed un-gated.
- **Lifecycle only, detached install** — `/install` is a fully-detached worker
  (`start_new_session=True`); `/start`, `/stop`, `/restart-ui` are short
  bounded `ctl()` calls. Every API handler is plain `def`, so nothing blocks
  the aggregator's shared event loop.
- **HOST-side UI probe** — `ui_up` is the truth of "the SpiderFoot UI answers",
  measured by a bounded `curl http://10.100.0.43:5001/` from the host (not
  `lxc-info`).

## API Endpoints (`/api/v1/spiderfoot`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Liveness check |
| GET | `/status` | — | Module/sandbox status (cached 15 s) — `{module,enabled,running,installed,ip,port,ui_up}` |
| POST | `/install` | JWT | Build the sandbox (debootstrap + git clone + pip), detached; 400 if already installed |
| POST | `/start` | JWT | Start the container |
| POST | `/stop` | JWT | Stop the container |
| POST | `/restart-ui` | JWT | Restart the in-container `spiderfoot.service` |

The **SpiderFoot web UI itself** is served at `/spiderfoot-ui/` (nginx reverse
proxy → container `10.100.0.43:5001`), reachable only through the SecuBox
WAF/auth front.

## Security

- **JWT-gated**: every mutating endpoint (install/start/stop/restart-ui)
  requires a valid token (`secubox_core.auth.require_jwt`).
- **Audit**: every lifecycle action is appended to `/var/log/secubox/audit.log`
  (append-only) with the operator (JWT `sub`) and action.
- **Sandboxed**: SpiderFoot runs in a dedicated LXC container.
- **UI only via the WAF front**: SpiderFoot binds to the container LAN IP and is
  reachable only through the auth-fronted nginx `/spiderfoot-ui/` location —
  never a host port.
- **Least privilege**: the aggregator drives everything through one sudoers
  entry — `secubox ALL=(root) NOPASSWD: /usr/sbin/spiderfootctl`. No secrets in
  code; no user target ever reaches a shell.

## Configuration

`/etc/secubox/spiderfoot.toml` (copy from `spiderfoot.toml.example`):

```toml
enabled = true
container_name = "spiderfoot"
lxc_ip = "10.100.0.43"
sf_port = 5001
```

## Installation

```bash
sudo apt install secubox-spiderfoot
```

Then open the **SpiderFoot OSINT** panel and click *Install sandbox* to build
the container (debootstrap + `git clone` + `pip install -r requirements.txt`).
When the UI is up, use **🌀 Open SpiderFoot** to reach the full UI.

## Deploy note

SpiderFoot generates **absolute URLs** for its own assets and links, so serving
it under a stripped subpath (`/spiderfoot-ui/` → `/`) may need adjusting at
deploy time — either configure SpiderFoot's own root/base path (its `-l` /
config supports a URL prefix) or front it on a dedicated subdomain. The nginx
`/spiderfoot-ui/` location shipped here is the validated **baseline**; the exact
subpath-proxy behaviour must be **validated live**.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
