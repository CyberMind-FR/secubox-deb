<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ⚙️ System Hub

System configuration and management

**Category:** System

## Screenshot

![System Hub](../../docs/screenshots/vm/system.png)

## Features

- Settings
- Logs
- Services
- Updates

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-system
```

## Configuration

Configuration file: `/etc/secubox/system.toml`

## API Endpoints

- `GET /api/v1/system/status` - Module status
- `GET /api/v1/system/health` - Health check
- `POST /api/v1/system/settings` `{"hostname"?, "timezone"?}` (`require_jwt`) — nom de la box par l'unité root
  `secubox-systeme-renommer@<nom>.service` (root, bac à sable : système en lecture seule sauf `/etc`, `/run`,
  `/var/log/secubox`) → `/usr/sbin/secubox-renommer` (secubox-core >= 1.8.10 : hosts, secubox.conf,
  hostnamectl, Avahi, audit, retour arrière) ; le code de sortie est relu (`ExecMainStatus`) et rendu : 400 nom invalide
  ou réservé, 409 nom déjà pris au maillage, 500 écriture ou audit impossible, 502 hostnamectl en échec, 504 délai,
  503 systemctl absent ; chaque démarrage audité (`service_control`). Fuseau : `timedatectl set-timezone`, permis par
  la règle polkit au seul sujet `secubox-system.service` ; échec rendu en 502 (#3242). Jamais de `{"success": true}`
  muet.
  Le nom actuel (comparé à `gethostname()`, sans casse) n'est pas un renommage : un fuseau seul passe même sur une box
  nommée `secubox` (réservé). La page n'envoie `hostname` que s'il a changé. Règle polkit : l'unité
  `secubox-systeme-renommer@<nom>` n'est que démarrée (`start`), pour une instance au motif DNS seulement.
  Reportés de la relecture de la tâche 5 (R-L2-36) : M5, M7, M8, M11 (non corrigés dans ce tour).

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
