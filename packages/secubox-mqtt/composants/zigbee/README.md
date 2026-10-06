<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📡 Zigbee Gateway

Zigbee2MQTT gateway

**Category:** IoT

## Screenshot

![Zigbee Gateway](../../docs/screenshots/vm/zigbee.png)

## Features

- Device pairing
- MQTT
- Groups
- OTA updates
- **Device list and on/off control** (`/devices`), and a Hall cardlet built on it

## Architecture

```
carte du Hall  ──►  /api/v1/zigbee/…  ──►  zigbee.sock  ──►  mosquitto_sub/pub
(LAN + jeton)       (relais nginx)         (ce module)       │
                                                             ▼
console z2m    ◄──  zigbee.gk2.secubox.in                MQTT 10.100.0.110:1883
(appairage,         (vhost, LAN-only)                         │
 réseau maillé)                                               ▼
                                                    zigbee2mqtt (LXC 10.100.0.111)
                                                              │
                                                              ▼
                                                     coordinateur USB /dev/secubox-zgb
```

Ce module est un **plan de contrôle sur l'hôte** : zigbee2mqtt tourne dans son
conteneur, le courtier MQTT dans un autre. Rien n'est réimplémenté ici — on
interroge le pont par MQTT et on lui transmet les ordres.

## API Endpoints

| Méthode | Route | Garde | Rôle |
|---|---|---|---|
| `GET` | `/api/v1/zigbee/status` | lecture | état global vert/jaune/rouge |
| `GET` | `/api/v1/zigbee/components` | lecture | LXC · radio · démon · pont |
| `GET` | `/api/v1/zigbee/access` | lecture | points d'accès (console, MQTT) |
| `GET` | `/api/v1/zigbee/devices` | lecture | **les appareils, avec leur état** |
| `POST` | `/api/v1/zigbee/devices/{nom}/set` | **jeton** | `{"etat": "ON"\|"OFF"\|"TOGGLE"}` |
| `GET` | `/api/v1/zigbee/backups` | lecture | sauvegardes du réseau maillé |
| `POST` | `/api/v1/zigbee/backup` · `/restore` | **jeton** | sauver / restaurer |
| `GET` | `/api/v1/zigbee/healthz` | — | sonde de vie |

« lecture » = `require_lecture` : jeton, **ou** mode tableau de bord depuis le
LAN si l'opérateur l'a armé dans `/etc/secubox/secubox.conf`. Par défaut, fermé.

### Ce que `/devices` rend, et pourquoi

```json
{"pont": "online",
 "appareils": [{"nom": "INTER-BUR", "genre": "switch", "modele": "HG06337",
                "etat": "OFF", "luminosite": null, "qualite": 255,
                "joignable": true}]}
```

**`etat: null` quand l'appareil n'a pas répondu — jamais `"OFF"`.** Une lampe
hors de portée n'est pas une lampe éteinte, et les confondre ferait cliquer dans
le vide en croyant agir. `joignable` porte la distinction.

**L'état est DEMANDÉ, pas attendu.** Le topic retenu `zigbee2mqtt/<nom>` peut
être vide — après un redémarrage du pont, ou si le conteneur a été gelé. Le
module publie un `/get` sur chaque appareil et écoute la réponse, en une seule
écoute pour tous.

**Le nom est validé par liste blanche**, jamais par expression régulière : il
devient un segment de topic MQTT (`zigbee2mqtt/<nom>/set`). Un nom simplement
« bien formé » permettrait d'écrire dans un topic arbitraire du courtier —
`bridge/request/…` compris, qui pilote le pont lui-même. Seuls les noms que le
pont a lui-même annoncés sont acceptés.

## La carte du Hall

`secubox-webos` sert `/cardlets/zigbee.html` : la liste des appareils, un petit
bouton emoji par ligne. Elle appelle le module par un relais de même origine
(la CSP du Hall impose `connect-src 'self'`).

**LAN deux fois.** La carte est masquée aux clients WAN (`lan:true` → `data-lan`),
et le relais nginx refuse **aussi** côté serveur (`$lan_client`). Le premier
n'est que de l'affichage ; sans le second, il suffirait d'appeler l'API à la main
depuis l'extérieur pour éteindre les lumières de la maison.

**La carte envoie `TOGGLE`**, pas un `ON`/`OFF` calculé depuis ce qu'elle
affiche : entre son dernier rafraîchissement et le clic, quelqu'un a pu toucher
l'interrupteur mural. Envoyer « ON » en croyant la lampe éteinte ne ferait rien
de visible, et passerait pour une panne.

Cliquer la carte ouvre la **console z2m en pleine page**, embarquée dans le Hall
— appairage, réseau maillé, OTA. La carte fait le geste d'une seconde ; la
console fait le reste.

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-zigbee
```

## Configuration

Configuration file: `/etc/secubox/zigbee.toml`

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
