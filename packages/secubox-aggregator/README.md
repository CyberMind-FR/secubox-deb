<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-aggregator

SecuBox API gateway — master ASGI process.

Mounts SecuBox module FastAPIs as sub-apps under /api/v1/<module>, eliminating the duplicated Python interpreter overhead of running each module as its own uvicorn process.

Pilot mounts (per /etc/secubox/aggregator.toml) save ~30 MB RAM per migrated module versus a per-module systemd unit. Full migration of the ~100 SecuBox modules would free ~3 GB on a typical install.

Paquet Debian : version `0.5.4-1~trixie1`, architecture `all`.

## Démarrage (#3216)

La socket écoute en quelques secondes : `/health`, `/` et le relais vers les sockets dédiées répondent dès ce moment.
Les modules d'`aggregator.toml` se montent ensuite un par un sur la boucle, `auth`, `hub`, `sbxid`, `portal` et
`users` d'abord. Pendant l'import d'un module, la boucle est occupée (quelques secondes sous swap) ; entre deux
imports, elle sert les requêtes en attente au moins aussi longtemps (de 50 ms à 2 s). Un module pas encore monté
répond `503` avec `Retry-After`. Un module en échec, même sur un `sys.exit()` à l'import, reste isolé dans `failed`.
`vault`, `actor` et `radio` ne sont jamais montés, même cités dans le TOML : le relais les garde.
`pilotage-canal` (canal des box du pilotage, #3126) n'est ni monté ni relayé : `/api/v1/pilotage-canal/…` rend `404` sans ouvrir
la socket, que seul l'écouteur nginx du tunnel joint (il pose l'identité de la box et le marqueur `X-SecuBox-Pilotage-Tunnel`).
`X-SecuBox-Pilotage-Relais` (#3126, L5) est effacé de toute requête, quelle qu'en soit la casse, avant tout module monté
ou relayé : seul le relais local du pilotage le pose, directement sur la socket d'un module.

`GET /health` garde ses clés (`status`, `mounted`, `failed`, `total_mounted`, `total_failed`) et ajoute :

| Clé | Sens |
|---|---|
| `pret` | `true` quand tous les modules ont été traités (montés ou en échec) |
| `a_monter` | modules qui restent à monter, dans l'ordre |
| `duree_montage_s` | durée du montage complet, `null` avant la fin |
| `interrompu` | motif si la tâche de montage s'est arrêtée sur une exception (les modules restants répondent 503), sinon `null` |

`secubox-aggregator-migrate` attend `pret` (900 s au plus) avant de lire `mounted`.
`cache` donne l'état du précache des lectures (entrées, octets, recalculs en cours, compteurs).

## Précache des lectures en double tampon (#4037)

Actif par défaut (`aggregator/cache.py`, intermédiaire ASGI placé sous l'effaceur d'en-têtes internes) :
chaque GET `/api/v1/<module>/…` reçoit tout de suite le dernier calcul complet, recalculé derrière.

| État (`X-SBX-Cache`) | Quand | Effet |
|---|---|---|
| `frais; age=N` | âge < TTL | servie |
| `perime; age=N` | TTL ≤ âge < `perime_max` | servie aussitôt, un recalcul en arrière-plan par clé (au plus `recalculs_max`) |
| `perime` / `frais` | âge ≥ `perime_max` ou écriture sur le module | recalcul attendu `delai_synchrone` s, sinon la vieille |
| `absent; age=0` | aucune entrée | calcul relayé en flux, copie gardée si 200 JSON |

En-têtes aussi posés : `X-SBX-Cache-Age` (s), `X-SBX-Cache-Date` (RFC 3339 UTC), `Age`.
Le client peut forcer un calcul par `X-SBX-Cache: contourner`.

- **Clé** : chemin + requête + SHA-256 de `Authorization`, `Cookie`, `Host`, `X-Real-IP`, `X-Forwarded-For`,
  `Accept-Language`. Jamais la réponse d'un porteur à un autre ; le recalcul rejoue la requête du porteur, sa garde
  est réévaluée ; un 401/403 au recalcul retire l'entrée.
- **Double tampon** : seule une réponse 200 `application/json` sans `Set-Cookie` ni `no-store`/`private`,
  ≤ `entree_octets_max`, remplace l'entrée ; erreur, 5xx, délai dépassé ne l'écrasent jamais.
- **Écriture** (POST/PUT/PATCH/DELETE) : invalide les entrées du module, avant et après ; un recalcul lancé
  avant l'écriture n'est pas rangé.
- **Jamais en cache** : modules `auth`, `vault`, `pilotage`, `pilotage-canal` ; chemins contenant un segment
  de flux, téléchargement, export, santé, jeton ou session (`health`, `stream`, `events`, `sse`, `ws`, `flux`,
  `download`, `export`, `backup`, `login`, `token`, `qr`, `me`, `refresh`, `scan`, `probe`…, liste `SEGMENTS_EXCLUS_DEFAUT`).
- **TTL par défaut** : 15 s ; dernier segment `status`/`etat` 5 s, `stats`/`metrics`/`summary` 30 s,
  `rapports`/`reports`/`categories`/`history`/`config`/`settings` 60 s, `info` 120 s, `version` 300 s.
- **Mémoire** : LRU, 2000 entrées et 64 Mio au plus.

Réglages dans `/etc/secubox/aggregator.toml` (voir `aggregator.toml.example`, section `[cache]`) ; un TTL
de 0 exclut la route, le préfixe le plus long gagne.

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

Lancer : `python3 -m pytest packages/secubox-aggregator` (précache : `tests/test_cache_lecture_4037.py`).
