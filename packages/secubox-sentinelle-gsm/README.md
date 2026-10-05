<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-sentinelle-gsm

SecuBox SENTINELLE-GSM — passive rogue-BTS sensor (MIND layer).

Host-resident module that drives an RTL-SDR USB dongle as a passive GSM broadcast receiver for false-BTS (IMSI-catcher) detection. Follows the SecuBox OPAD/MIND doctrine: off-path by construction (RX only, no RF emission, no traffic decryption), feeds alerts into WALL/OPAD for correlation + reaction.

Privacy-by-design (spec §6.2): subscriber identifiers (IMSI/IMEI/TMSI), when present in flight, are HMAC-SHA256-truncated using a locally generated key (PROD mode, default). Plaintext observation is gated behind explicit PROD→LAB mode flip + consent acknowledgement + audit log, intended only for owned SIMs / consented devices.

The dataclass that flows from the GSMTAP parser into the scoring engine has NO field that could carry a plaintext IMSI. Auditor-visible via `GET /api/v1/sensor/gsm/status` returning `captures_plaintext_imsi_in_prod: false` and `rx_only: true`.

v0.1.0 ships the privacy framework + 8/8 invariant tests + service plumbing. The GSMTAP listener + the 8 scoring heuristics + gr-gsm orchestration land in v0.2 once an RTL-SDR is connected.

Paquet Debian : version `0.4.5-1~bookworm1`, architecture `arm64`.

## Contenu

- `api/` : API FastAPI
- `bin/` : exécutables
- `conf/` : configuration livrée
- `lib/` : fichiers du module
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `sbin/` : exécutables
- `tests/` : tests
- `udev/` : fichiers du module
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/sentinelle-gsm.sock`.
- `secubox-sentinelle-gsm.service` : SecuBox SENTINELLE-GSM — passive rogue-BTS analyzer (MIND layer) (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/status` | require_lecture |
| `GET` | `/components` | require_lecture |
| `GET` | `/access` | require_lecture |
| `GET` | `/cells` | require_lecture |
| `GET` | `/alerts` | require_jwt |
| `GET` | `/alerts/stream` | require_jwt |
| `POST` | `/alerts/test` | require_jwt |
| `GET` | `/trusted` | require_jwt |
| `POST` | `/trusted` | require_jwt |
| `DELETE` | `/trusted/{phone_id}` | require_jwt |
| `GET` | `/journal/stream` | require_jwt |
| `POST` | `/mode` | require_jwt |
| `POST` | `/scan/start` | require_jwt |
| `POST` | `/scan/stop` | require_jwt |
| `POST` | `/scan/auto` | require_jwt |
| `GET` | `/scan/auto/jobs/{job_id}` | require_jwt |
| `GET` | `/scan/auto/jobs` | require_jwt |
| `GET` | `/scan/auto/status` | require_jwt |
| `GET` | `/scan/status` | require_jwt |
| `GET` | `/observations` | require_jwt |
| `GET` | `/baseline` | require_jwt |
| `POST` | `/baseline/learn` | require_jwt |
| `GET` | `/scoring/thresholds` | require_jwt |
| `POST` | `/scoring/thresholds` | require_jwt |
| `GET` | `/healthz` | aucune |
| `POST` | `/rds/start` | require_jwt |
| `POST` | `/rds/stop` | require_jwt |
| `GET` | `/rds/status` | require_jwt |
| `GET` | `/rds/stations` | require_jwt |
| `POST` | `/rds/sweep` | require_jwt |
| `GET` | `/rds/sweep/jobs/{job_id}` | require_jwt |
| `GET` | `/rds/sweep/jobs` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

20 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-sentinelle-gsm`.
