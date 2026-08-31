<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# sbxdpi — couche Go qui émancipe nDPId

`sbxdpi` est la couche SecuBox au-dessus de **nDPId** (moteur C libre, nDPI 5.x).
nDPId classe les flux sur le fil et pousse du JSON encadré à **nDPIsrvd** (son
distributeur C) ; `sbxdpi` **compose** ce distributeur en lecture seule, applique
notre **filtrage go-level déclaratif**, agrège des compteurs sans PII, et sert
une API RO `/api/v1/dpi/*` que la carte DPI du Hall consomme (via nginx).

Même dessin modulaire que `cmd/sbx-sentinel` : consommateur de flux sur socket,
config par variables d'environnement, idiomes fail-safe.

## Chaîne

```
nDPId (capture, nDPI 5.x) → nDPIsrvd (distributeur) → sbxdpi (Go)
     → /run/secubox/dpi-live.sock (/api/v1/dpi/*) → nginx Hall → carte DPI
```

`nDPId`/`nDPIsrvd` sont fournis par le paquet **`secubox-dpi-engine`** (séparé).
`aggregator.sock` est la **passerelle API maîtresse** du parc — surtout PAS un
socket DPI ; `sbxdpi` a le sien (`dpi-live.sock`).

## Cadrage nDPIsrvd (important)

Chaque message est préfixé de **5 chiffres ASCII = longueur du CORPS** qui suit
(JSON + `\n`), PAS le total incluant les chiffres. La trame suivante commence à
`offset = 5 + préfixe`. (Vérifié sur le fil contre nDPIsrvd 1.7 ; c'était le bug
de framing initial.)

## Configuration — `/etc/secubox/dpi.env` (`DPI_*`)

| Variable | Défaut | Rôle |
|----------|--------|------|
| `DPI_DISTRIBUTOR_SOCK` | `/run/secubox/ndpi/distributor.sock` | socket nDPIsrvd (dial) |
| `DPI_API_SOCK` | `/run/secubox/dpi-live.sock` | socket API servi (listen) |
| `DPI_STATS_CACHE` | `/data/secubox/sbxdpi/stats.json` | snapshot atomique, **sur le SSD** |
| `DPI_FLUSH_INTERVAL` | `30s` | cadence du flush |
| `DPI_DENY_FILE` | `/etc/secubox/dpi/app-deny.txt` | apps/protos/hosts à écarter |
| `DPI_ALLOW_FILE` | `/etc/secubox/dpi/app-allow.txt` | épingles (priment sur deny) |
| `DPI_RISK_MUTE` | `/etc/secubox/dpi/risk-mute.txt` | risques nDPI à taire |
| `DPI_BOX_DOMAINS` | `/etc/secubox/waf/haproxy-routes.json` | exemption 1ʳᵉ partie |

Les `*.txt` sont des conffiles hot-reload (mtime), style `sbx-sentinel/c2allow`.

**Le snapshot va sur le SSD `/data`, jamais l'eMMC racine** (15 Go, vite pleine).

## API (GET, sans PII, JWT au niveau nginx/FastAPI)

`/api/v1/dpi/health` · `/stats` · `/top_protocols` · `/top_apps` ·
`/top_categories` · `/talkers` · `/risks` (`?limit=`).

## Build / unité

Construit par `debian/rules` (`go build ./cmd/sbxdpi`), livré `/usr/sbin/sbxdpi`,
unité `sbxdpi.service` (DARK à l'install). Voir aussi `secubox-dpi-engine`.
