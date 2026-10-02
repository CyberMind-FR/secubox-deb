<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 📡 API Reference — Eye-Remote Boot Media (v2.1.0+)

### Boot Media API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/eye-remote/boot-media/state` | Boot media state |
| POST | `/api/v1/eye-remote/boot-media/upload` | Upload to shadow |
| POST | `/api/v1/eye-remote/boot-media/swap` | Swap active/shadow |
| POST | `/api/v1/eye-remote/boot-media/rollback` | Rollback swap |
| GET | `/api/v1/eye-remote/boot-media/tftp/status` | TFTP status |

### Systemd Services

| Service | Description |
|---------|-------------|
| `secubox-eye-gadget.service` | USB gadget (ECM+ACM+mass_storage) |
| `secubox-eye-serial.service` | Serial console via xterm.js |
| `secubox-eye-websocket.service` | WebSocket API server |

---

