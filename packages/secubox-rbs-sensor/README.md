<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-rbs-sensor

SecuBox RBS Sensor — Rogue Base Station sensor (WALL layer).

Host-resident module that drives a Quectel EP06-E mPCIe LTE modem as a cellular telemetry sensor for false-base-station detection. Follows the SecuBox OPAD doctrine (Off-Path Active Defense, OODA loop):

OBSERVE — broadcast cell identifiers + own-modem RX measurements only. ORIENT  — local verdict engine scores LIKELY_ROGUE / SUSPECT / OK. DECIDE  — operator policy or auto-mitigation. ACT     — local off-path mitigation: RAT lock (refuse 2G), RF detach.

The sensor NEVER captures third-party subscriber identifiers (IMSI/TMSI). The CellObservation / NeighbourObservation dataclasses have no fields that could carry such data — proof verifiable via `GET /api/v1/rbs-sensor/status` which returns `captures_subscriber_identifiers: false`.

v0.1.0 is a scaffold: framework + EP06 driver shape + AT command allowlist + service plumbing. The full LTE/GSM cell parser and verdict engine land in v0.2 once a real EP06 is connected.

Paquet Debian : version `0.1.4-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `conf/` : configuration livrée
- `lib/` : fichiers du module
- `nginx/` : route nginx
- `sbin/` : exécutables
- `tests/` : tests
- `udev/` : fichiers du module

## Exécution

Socket Unix : `/run/secubox/aggregator.sock`, `/run/secubox/rbs-sensor.sock`.
- `secubox-rbs-sensor.service` : SecuBox RBS Sensor — host control plane API (WALL layer) (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/status` | require_lecture |
| `GET` | `/components` | require_lecture |
| `GET` | `/access` | require_lecture |
| `GET` | `/servingcell` | require_lecture |
| `GET` | `/neighbours` | require_lecture |
| `POST` | `/mitigate/lte-only` | require_jwt |
| `POST` | `/mitigate/rf-off` | require_jwt |
| `POST` | `/restore` | require_jwt |
| `GET` | `/healthz` | aucune |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

1 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-rbs-sensor`.
