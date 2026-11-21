<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# secubox-datascope

SBXOS DataScope V0.1 (#3853) : cockpit réseau en lecture seule. Un collecteur (minuterie 60 s) lit trois sources
locales — appareils du NAC, débits des interfaces, santé des modules — et tient à jour un graphe d'entités
(`node`, `network`, `interface`, `device`, `ip`, `service`) et de relations (`BELONGS_TO`, `CONNECTS_TO`,
`HOSTED_ON`, `OBSERVED_BY`) observées ou rapportées, jamais inférées. Aucun nom de domaine n'est stocké.

## Contenu du paquet (tâche 1 : squelette)

| Élément | Rôle |
|---|---|
| `secubox-datascope.service` | API FastAPI/Uvicorn sur `/run/secubox/datascope.sock` (`0660`, groupe `secubox`) |
| `secubox-datascope-collect.{service,timer}` | passe de collecte, minuterie 60 s, `Nice=10`, `CPUQuota=25%`, I/O idle |
| `nginx/datascope.conf` | route `/api/v1/datascope/` vers la socket (routes WAF : `/etc/nginx/secubox-routes.d/`) |
| `apparmor/secubox-datascope` | profil `enforce` : lecture des sources, écriture base, cache et socket |
| `conf/datascope.toml` | `/etc/secubox/datascope.toml` (`[stockage]`, `[sources]`) |

## API (`/api/v1/datascope/`)

| Route | Garde | Réponse |
|---|---|---|
| `GET health` | publique | `{"status": "ok", "module": "datascope", "version": "0.1.0"}` |
| `GET status` | `require_lecture` | `{"module", "base": "ok"\|"absente", "derniere_passe"}` |
| `GET overview` | `require_lecture` | `overview.json` + `perime` (`verifie_le`, à défaut `genere_le`, > 180 s) ; cache absent ou corrompu : `{"disponible": false, "motif"}` |
| `GET sources` | `require_lecture` | état des curseurs (`source`, `etat`, `motif`, `vu_le` ; l'empreinte n'est jamais rendue) |
| `GET entities?type=&q=&page=&par_page=` | `require_jwt` | liste paginée (50 par défaut, 200 au plus) |
| `GET entities/{id}` | `require_jwt` | une entité |
| `GET entities/{id}/context` | `require_jwt` | `{entity, summary, relationships, recent_events: null, history: null, motifs, available_actions, source_provenance}` ; sections non livrées : `null` + `motifs` « non livré en V0.1 » |
| `GET entities/{id}/neighbors` | `require_jwt` | voisins, au plus 500 nœuds et 1 500 arêtes, `tronque` |
| `GET graph?type=` | `require_jwt` | sans filtre : `graph.json` — box, interfaces, zones et services, puis 60 appareils par interface (les plus récemment vus), jamais d'`ip` (`ip_hors_vue` les compte) ; rebornée à 500 nœuds et 1 500 arêtes ; avec filtre : requête bornée (500 nœuds, 1 500 arêtes) |

Erreurs en JSON : identifiant ou type invalide 400, inconnu 404, base illisible 503. Aucune route mutante.
Base ouverte en lecture seule (`mode=ro`) par requête, dans `asyncio.to_thread`. Chaque entité ou nœud rendu porte
`etat_source` (état du curseur de sa source ; `nac` relève de `network`) ; hors `ok`, l'`overall` d'un service est rendu
`unknown`. `available_actions` : liens `{libelle, href}` seulement (appareil : `/nac/`, service : `/<module>/` si le nom vérifie `^[a-z0-9_-]{1,64}$`, sinon aucun lien).

## Configuration

Ordre de priorité : variables d'environnement (`SECUBOX_DATASCOPE_DB`, `_CACHE`, `_NAC_DB`, `_NETSTATS`,
`_MODULES`) > `/etc/secubox/datascope.toml` > défauts. Le postinst choisit
`/data/secubox-datascope/datascope.db` si `/data` est un point de montage, sinon
`/var/lib/secubox-datascope/datascope.db`.

Depends : `python3-fastapi`, `python3-uvicorn`, `secubox-core`. Compte `secubox-datascope`, groupe `secubox`.
