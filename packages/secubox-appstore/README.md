<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-appstore

SecuBox App Store — module catalog & lifecycle (Phase A).

Categorized, tiered, searchable catalog of SecuBox modules with live install/run state, served as a hub web UI. Phase A is read-only; install, enable/disable, preferences and profiles arrive in later phases via a privileged worker.

Paquet Debian : version `0.4.23-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `sbin/` : exécutables
- `scripts/` : scripts
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/appstore.sock`.
- `secubox-appstore.service` : SecuBox App Store — module catalog API (utilisateur `secubox`), lance `python3`

## API

`install`, `remove` (confirmation : `?confirmer=<nom complet>`) et `repair` sont des **tâches de fond** (202 puis `GET /jobs`), car HAProxy coupe à 30 s ; une seule à la fois (409 sinon). Les autres verbes sont synchrones.

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/categories` | require_lecture |
| `GET` | `/catalog` | require_lecture |
| `GET` | `/mesh-catalog` | require_lecture |
| `GET` | `/module/{name}` | require_lecture |
| `GET` | `/module/{name}/check` | require_lecture |
| `GET` | `/groupes` | require_lecture |
| `GET` | `/metapaquets` | require_lecture |
| `GET` | `/profils` | require_lecture |
| `POST` | `/module/{name}/action/{verb}` | require_jwt |
| `GET` | `/jobs` | require_lecture |
| `GET` | `/module/{name}/config` | require_lecture |
| `PUT` | `/module/{name}/config` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Boutique client (#3148)

`/appstore/boutique.html` : vitrine simple pour les usagers (onglets Aujourd'hui, Apps, Fonctionnalités, Installées),
sur les mêmes routes que la page d'administration. `www/appstore/boutique-fiches.json` donne à un paquet un nom, un résumé,
une catégorie et un détail grand public (`"cacher": true` le masque) ; sans fiche, la page affiche le nom du paquet, et
seules les catégories grand public (médias, courrier, communication, publication, IA, objets, outils) sont proposées.
`?demo=1` affiche des données d'exemple sans aucun appel d'écriture.
