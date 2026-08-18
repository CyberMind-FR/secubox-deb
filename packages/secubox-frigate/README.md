<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📹 Frigate NVR

Frigate NVR (frigate.video) running as the official podman container inside a
dedicated Debian LXC on the amd64 node.

**Category:** Security / Media

## Status

Foundation scaffold (#821). This is the package skeleton only — the LXC/podman
provisioning, API shim, host service, and WAF exposure land in follow-up tasks
of the same plan. The full C3BOX dashboard is a separate sub-project.

## Features (Foundation scope)

- OpenVINO CPU detector
- go2rtc demo source (no real camera yet)
- Storage + retention on `/data/frigate`
- `/api/v1/frigate/*` shim
- Cross-node exposure through gk2's WAF (mitmproxy — no bypass)

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-frigate
```

## Configuration

Configuration file: `/etc/secubox/frigate/config.yml` (seeded from
`frigate.config.yml.example` on first install, never clobbered).

## API Endpoints

- `GET /api/v1/frigate/status` - Module status
- `GET /api/v1/frigate/cameras` - Camera list
- `GET /api/v1/frigate/events` - Recent events
- `GET /api/v1/frigate/storage` - Storage usage
- `GET /api/v1/frigate/stats` - Sidebar stats (`cameras`, `events`, `fps`)

## Sidebar wiring (applied separately, in secubox-hub)

Add to `packages/secubox-hub/www/shared/sidebar.js` PAGE_METRICS map:

```
'/frigate/': { metrics: ['cameras','events','fps'], api: '/api/v1/frigate/stats' },
```

## Cross-node WAF exposure (deploy-time, run on gk2 — NOT part of the package)

```bash
# gk2: front the amd64 Frigate UI through the WAF (NO bypass)
haproxyctl vhost add frigate.gk2.secubox.in          # backend defaults to mitmproxy_inspector
# add to BOTH /srv/mitmproxy/haproxy-routes.json AND /srv/mitmproxy-in/haproxy-routes.json:
#   "frigate.gk2.secubox.in": ["10.100.0.140", 5000]   # amd64 frigate LXC over the mesh
systemctl restart mitmproxy
```

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
