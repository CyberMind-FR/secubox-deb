<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-aggregator

SecuBox API gateway — master ASGI process.

Mounts SecuBox module FastAPIs as sub-apps under /api/v1/<module>, eliminating the duplicated Python interpreter overhead of running each module as its own uvicorn process.

Pilot mounts (per /etc/secubox/aggregator.toml) save ~30 MB RAM per migrated module versus a per-module systemd unit. Full migration of the ~100 SecuBox modules would free ~3 GB on a typical install.

Paquet Debian : version `0.5.0-1~trixie1`, architecture `all`.

## Démarrage (#3216)

La socket écoute en quelques secondes : `/health`, `/` et le relais vers les sockets dédiées répondent tout de suite.
Les modules d'`aggregator.toml` se montent ensuite un par un, `auth`, `hub`, `sbxid`, `portal` et `users` d'abord.
Un module pas encore monté répond `503` avec `Retry-After`. Un module en échec reste isolé dans `failed`.

`GET /health` garde ses clés (`status`, `mounted`, `failed`, `total_mounted`, `total_failed`) et ajoute :

| Clé | Sens |
|---|---|
| `pret` | `true` quand tous les modules ont été traités (montés ou en échec) |
| `a_monter` | modules qui restent à monter, dans l'ordre |
| `duree_montage_s` | durée du montage complet, `null` avant la fin |

## Contenu

- `aggregator/` : fichiers du module
- `sbin/` : exécutables
- `systemd/` : unités systemd
- `tests/` : tests

## Exécution

Socket Unix : `/run/secubox/aggregator.sock`.
- `secubox-aggregator-watchdog.service` : SecuBox aggregator auto-heal watchdog, lance `secubox-aggregator-watchdog.sh`
- `secubox-aggregator-watchdog.timer` : Probe + auto-heal secubox-aggregator every 2 min
- `secubox-aggregator.service` : SecuBox API gateway (master ASGI uvicorn) [Phase 7 #496] (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/` | aucune |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

2 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-aggregator`.
