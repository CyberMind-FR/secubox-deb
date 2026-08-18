<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔎 SecuBox Maigret

Username / identity OSINT collector for the SecuBox appliance. Wraps the
[Maigret](https://github.com/soxoj/maigret) CLI inside a dedicated LXC sandbox:
given a **username**, Maigret searches 3000+ sites for matching accounts and
produces a dossier.

**Category:** OSINT / auth

## Model

```
aggregator (user: secubox)  ──imports──▶  api/main.py  (mounted in-process)
        │  sudo -n /usr/sbin/maigretctl …          (the ONLY privileged surface)
        ▼
   maigretctl  ──lxc-attach──▶  maigret container (10.100.0.42, debootstrap bookworm)
        │                              maigret <username> --json simple …
        ▼
   /var/lib/secubox/maigret/lookups/<id>.json   (record: id, username, status, results.raw)
```

- **Passive only** — Maigret discovers accounts; it never actively probes the
  target, so there is no active-scan authorization gate (unlike OpenClaw).
- Lookups run as **detached workers** (`start_new_session=True`) — nothing
  blocks the aggregator's shared event loop; every API handler is plain `def`.
- The username is **never interpolated into a shell string** — it is passed as
  a positional `$1` to `lxc-attach … sh -c` and validated with a strict
  `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` guard on both the API and ctl sides
  (an alphanumeric first char blocks flag-injection).

## API Endpoints (`/api/v1/maigret`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Liveness check |
| GET | `/status` | — | Module/sandbox status (cached 15 s) |
| POST | `/lookup` | JWT | Start a username lookup → `{lookup_id}` |
| GET | `/lookups` | JWT | Last 200 lookup records (newest first) |
| GET | `/lookup/{id}` | JWT | One lookup record |
| DELETE | `/lookup/{id}` | JWT | Delete a lookup record |
| POST | `/install` | JWT | Build the sandbox (debootstrap + maigret), detached |

## Security

- **JWT-gated**: every lookup, list, read, delete and install requires a valid
  token (`secubox_core.auth.require_jwt`).
- **Audit**: every lookup is appended to `/var/log/secubox/audit.log`
  (append-only) with the operator (JWT `sub`), username and lookup id.
- **Sandboxed**: Maigret runs in a dedicated LXC container, never on the host.
- **Least privilege**: the aggregator drives everything through one sudoers
  entry — `secubox ALL=(root) NOPASSWD: /usr/sbin/maigretctl`. No secrets in code.

## Configuration

`/etc/secubox/maigret.toml` (copy from `maigret.toml.example`):

```toml
enabled = true
container_name = "maigret"
lxc_ip = "10.100.0.42"
```

## Installation

```bash
sudo apt install secubox-maigret
```

Then open the **Maigret OSINT** panel and click *Install sandbox* to build the
container (debootstrap + `pip install maigret`).

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
