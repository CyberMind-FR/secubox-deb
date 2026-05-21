# 🔐 secubox-certs

ACME / TLS certificate manager for the SecuBox HAProxy frontend.

**Category (Charte SecuBox):** AUTH (`#C04E24` orange — identity & access)

## What it does

- Watches `/data/haproxy/certs/*.pem` (the canonical cert bundle directory
  HAProxy reads at `bind *:443 ssl crt /data/haproxy/certs/`).
- Drives `certbot` renewals via the existing systemd timer.
- Reports cert expiry / renewal state / WAF-side threat origin to the
  SecuBox WebUI dashboard at `/certs/`.

## Files

| Path | Role |
|------|------|
| `/usr/lib/secubox/certs/api/main.py` | FastAPI control plane (uvicorn on `/run/secubox/certs.sock`) |
| `/usr/share/secubox/www/certs/index.html` | WebUI dashboard |
| `/etc/nginx/secubox.d/certs.conf` | nginx snippet — `/certs/` alias + `/api/v1/certs/` proxy |
| `/usr/share/secubox/menu.d/36-certs.json` | navbar entry (category=auth, order=118) |
| `/etc/systemd/system/secubox-certs.service` | uvicorn unit |

## API endpoints

- `GET /api/v1/certs/` — list all `*.pem` in `/data/haproxy/certs/`
- (See `api/main.py` for the full surface — reconstructed from the running
  gk2 deployment.)

## History

Reconstructed source-side in v1.0.0 (#306 follow-up). The module existed
on the running boards as a ghost — installed by an out-of-tree script —
but had no `packages/secubox-certs/` source, so reinstalls / migrations
lost the module entirely. This package owns those files cleanly now.
