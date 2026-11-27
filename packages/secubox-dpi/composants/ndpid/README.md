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


## Couches de menace par source externe (#4010)

`GET /api/v1/ndpid/couches-menaces?limit=20` (`require_jwt`) — agrégats sans adresse, calculés au plus toutes les 60 s hors de la boucle depuis le
relevé de sbxdpi (`/run/secubox/sbxdpi/couches-menaces.json`) et la fin de `waf-threats.log` (lecture incrémentale) :

- `services` : par `Proto/port`, nombre de sources et de flux, `hors_waf` quand ce n'est pas HTTP/TLS sur 80/443 ;
- `raisons` : risques nDPI par nombre de sources, `bruit` pour les risques connus comme bruit ;
- `agents` : verdict par source — `outil_probable` (UA navigateur déclaré au WAF, JA4 de forme « bibliothèque »), `outil_declare`,
  `client_bibliotheque` (JA4 bibliothèque, jamais vu par le WAF), `coherent`, `indetermine` ; table dans `api/couches_menaces.py` ;
- `sources` : les plus marquantes, sous une référence opaque salée par démarrage (jamais l'adresse).

Le relevé complet (adresses comprises) est écrit en double tampon dans `/var/cache/secubox/dpi/couches-menaces.json` (0640) pour les populations
(#4005). Section « Sources externes — couches de menace » sur la page Risques.
