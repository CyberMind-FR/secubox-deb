<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🎨 Streamlit

Streamlit app platform

**Category:** Apps

## Screenshot

![Streamlit](../../docs/screenshots/vm/streamlit.png)

## Features

- App hosting
- Deployment
- Management
- Logs

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-streamlit
```

## Configuration

Configuration file: `/etc/secubox/streamlit.toml`

## API Endpoints

- `GET /api/v1/streamlit/status` - Module status
- `GET /api/v1/streamlit/health` - Health check
- `GET /api/v1/streamlit/apps/audit` - Fleet-wide inventory (disk/declared/running), feeds the Mosaïque tab, cached every 5 min (lecture gardée : jeton, cookie de session ou tableau de bord LAN)
- `POST /api/v1/streamlit/apps/{name}/wake` - Wake an idle-stopped app without blocking: answers `running` or `waking` within 25 s, the wall re-polls until `running`; the failure of a background wake is returned once (404/504) on the next poll; also fires a lazy thumbnail capture if stale
- `GET /api/v1/streamlit/apps/{name}/screenshot` - Serve the conserved thumbnail (lecture gardée depuis #1776 — the wall's `<img>` carries the session cookie; no longer public)
- `POST /api/v1/streamlit/apps/{name}/recapture` - Manually trigger a thumbnail recapture (detached, returns immediately)

App names reaching `streamlitctl` must match `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`
(400 otherwise) — checked before any `sudo`.

Thumbnails are captured on event only (first registration, source update,
or a manual recapture) — never on a timer, and never for an app that isn't
already running. See `api/shots.py` for the capture orchestration and
`sbin/streamlit-shotter` for the detached capture process.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
