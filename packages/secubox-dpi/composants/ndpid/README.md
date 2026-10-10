<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔬 nDPId

nDPI daemon for traffic analysis

**Category:** Monitoring

## Screenshot

![nDPId](../../docs/screenshots/vm/ndpid.png)

## Features

- Protocol detection
- Flow tracking
- JSON API
- Real-time

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-ndpid
```

## Configuration

Configuration file: `/etc/secubox/ndpid.toml`

## API Endpoints

- `GET /api/v1/ndpid/status` - Module status
- `GET /api/v1/ndpid/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).

## Sources des données (#2240)

Quand la base locale est vide, l'API lit d'abord **sbxdpi** (nDPId → nDPIsrvd → sbxdpi, `/run/secubox/dpi-live.sock`) : protocoles, applications, risques nDPI, empreintes JA4, sessions d'usage. Ce sont des **cumuls depuis le démarrage de sbxdpi** : les risques sont des compteurs par type (source et destination « — »), sans le bruit de gravité basse ; il n'y a pas de JA3. À défaut, le collecteur d'ndpiReader (wg-toolbox, fenêtres de 60 s). Le moteur de capture est l'unité `secubox-ndpid-engine.service` (paquet `secubox-ndpid-engine`).

