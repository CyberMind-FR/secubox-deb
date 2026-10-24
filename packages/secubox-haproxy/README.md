<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ⚡ HAProxy

Load balancer with TLS 1.3

**Category:** Network

## Screenshot

![HAProxy](../../docs/screenshots/vm/haproxy.png)

## Features

- Backend management
- Stats
- ACLs
- SSL termination
- Health checks

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-haproxy
```

## Configuration

Configuration file: `/etc/secubox/haproxy.toml`

### Onion du webui (#3112)

`haproxyctl generate` émet toujours le frontal `onion-webui`, lié à `127.0.0.1:<onion_webui_port>`
(clé facultative de `haproxy.toml`, défaut **9180** ; jamais 9080). C'est la cible du service onion
« webui » (`HiddenServicePort 80 127.0.0.1:9180`), à la place de nginx :9080 en direct.

Ce frontal efface `X-Forwarded-For`, `Forwarded`, `X-Real-IP`, `X-Client-IP`, `X-Forwarded-Host` et
tout `X-SecuBox-*` du client, pose l'adresse marqueur **192.0.2.80** (TEST-NET-1, RFC 5737,
« client onion », hors de toute plage LAN) par `set-src` et `X-Forwarded-For`, ajoute
`X-SecuBox-Onion: 1`, puis passe par `sbxwaf_inspector`. nginx voit donc 192.0.2.80, et
`$lan_client` vaut 0. sbxwaf route le Host `<onion>.onion` vers le webui (nginx :9080) : route posée
par le composant exposure via `secubox-waf-route`. Les frontaux publics `http-in` et `https-in`
refusent (404) un Host `.onion` venu d'ailleurs que la boucle locale.

## API Endpoints

- `GET /api/v1/haproxy/status` - Module status
- `GET /api/v1/haproxy/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
