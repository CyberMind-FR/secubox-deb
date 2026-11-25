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
| `GET health` | publique | `{"status": "ok", "module": "datascope", "version": "0.3.0"}` |
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

## Vue « Paysage » (0.2.0, #3921)

Troisième vue de la page DataScope : le graphe des menaces tiré du relevé des populations du WAF
(`/var/lib/secubox/waf/populations.json`, clé `populations`). Populations, réseaux, classes, cibles, CVE et pays
sont posés en colonnes ; les compteurs (réseaux, adresses, bannies) sont des **cumuls par population** (une adresse
dans deux populations compte deux fois). Une barre de compteurs à histogrammes (24 h ou 7 j), une fiche avec
tendance par population, une synthèse et un fil des changements accompagnent le graphe. Le collecteur écrit un
instantané à chaque **nouveau** relevé ; l'**Enregistreur** rejoue l'historique (lecture, pause, pas, vitesses
×1/×4/×16, fenêtre 48 h ou 30 j, comparaison 24 h, 7 j ou date) avec badges apparu, disparu, hausse, baisse et
fantômes. Toutes les routes sont en lecture seule, gardées par `require_jwt`, base ouverte en `mode=ro`.

### Vue « Carte » (0.3.0, #3921, #3945)

Même instantané et même enregistreur que le Paysage, vus par pays. Valeur d'un pays = somme, sur les populations, de
`adresses × part` (arêtes `ORIGINE`). C'est une **estimation incomplète**, et la page l'écrit :

- le relevé ne donne que les **trois premiers pays** de chaque population, en parts entières ; le reste (autres pays, en
  nombre inconnu, ou adresses non localisées) est compté à part ; une part arrondie à 0 s'affiche « moins de 1 % » ;
- un pays non rendu est **non mesuré, jamais 0** ; il peut entrer (✚) ou sortir (✖) du relevé sans avoir changé ;
- populations sans origine, populations repliées et pays sans position sur la carte sont comptés et nommés ;
- le relevé ne relie aucun réseau à un pays : la fiche d'un pays liste ses populations, puis les réseaux de ces
  populations, tous pays confondus.

L'enregistreur pilote la carte. En direct et au repos seulement (rien de choisi, relevé complet), `pouls.js` la fait reculer sur
les relevés complets des 24 dernières heures (un par tranche de 2 h, soit 12 `GET paysage/instantane/{ts}` au plus, un à la
fois, une fois chacun) ; `prefers-reduced-motion` : rien ne bouge. `pouls.js` (secubox-hub) et `carte-monde.js` (`carte.js` de
secubox-live) sont des copies identiques, vérifiées par test ; absents, la liste des pays reste complète.

### Routes du paysage

| Route | Réponse |
|---|---|
| `GET paysage` | dernier instantané : `{disponible, epoch, age_s, instantane, difference_24h, motif_difference_24h}` ; sans instantané `{"disponible": false}` |
| `GET paysage/chronologie?de=&a=&differences=N` | en-têtes des instantanés (époques ; défaut 48 h, au plus 31 j, 1 500 lignes, `tronque`) ; `differences=N` (1 à 24) ajoute les N dernières différences stockées, sans graphe |
| `GET paysage/instantane/{ts}` | un instantané complet (`ts` au format stocké `YYYY-MM-DDTHH:MM:SS.ffffffZ`) et sa différence |
| `GET paysage/difference?de=<ts>&a=<ts>` | `{apparus, disparus, hausses, baisses, rotation_levee, rotation_tombee, tronque}` (listes à 300 au plus) |
| `GET paysage/tendance/{id}?jours=7` | `{id, points: [{ts, epoch, adresses, bans, reseaux}], illisibles}` ; `jours` de 1 à 30 ; un point par heure |

Champs à connaître :

- `difference_24h.reference_partiel` : la référence de comparaison est un relevé partiel (à lire avec réserve) ;
  sans référence assez ancienne (12 h), `difference_24h` est `null` et `motif_difference_24h` le dit.
- `difference.sans_precedent` : `"premier"` (aucun instantané avant) ou `"illisible"` (le précédent est
  indéchiffrable) ; la page n'affiche alors aucun badge « apparu » : tout paraîtrait nouveau.
- `illisibles` (tendance) : instantanés dont le graphe stocké est illisible, omis de la courbe et comptés ;
  un graphe illisible demandé seul rend 503, jamais un graphe vide.
- Erreurs : 400 paramètre invalide, 404 instantané inconnu, 503 base absente ou illisible.

### Instantanés, rétention, budget

Un instantané (graphe compressé zlib + compteurs + différence avec le précédent) par nouveau relevé, soit toutes
les **30 min** (période de `populations.json`). Au-delà de **48 h**, un seul par heure est gardé ; au-delà de
**30 jours**, plus aucun ; le tout dans un budget de **60 Mio** (les plus anciens partent d'abord, le dernier jamais).
Migration `migrations/0002-paysage.sql`, repères partagés `www/datascope/reperes.js`, tous deux installés par
`debian/rules`. Un relevé absent, refusé, illisible, futur ou d'un mauvais type ne donne aucun instantané et jamais un graphe vide :
le collecteur publie l'état et le motif (« relevé absent », « droit refusé », « relevé illisible », « relevé daté dans
le futur »…) sous la source `paysage` des curseurs (`GET sources`, `overview.json`), hors de `complet` ; la page les
affiche à la place du graphe, ou à côté du dernier instantané s'il y en a un. Un relevé simplement ancien n'est pas une
panne de source : la page le marque « périmé » au-delà de 2 h. Le détail d'une erreur interne reste au journal.

### Cibles et hébergement

Une cible est un hôte, ou un compte masqué tel que le WAF l'écrit (`ger…`, identifiant `cible:compte:ger`) ; le nombre
de cibles est celui du relevé. `HEBERGE` (cible → `infra:<box>`) n'est tracée que si le nom de la cible est exactement
celui d'un service que la topologie de DataScope rattache à la box (`HOSTED_ON`) : le nom d'hôte visé vient de
l'attaquant et ne prouve rien. La colonne « Infrastructure » peut donc être vide ; elle disparaît alors.

### Droits de lecture (populations.json)

Sur la box, `/var/lib/secubox/waf` est `0770 secubox-waf:secubox-waf` ; `populations.json` y est
`secubox:secubox 0640`, et le groupe `secubox` est celui de `secubox-datascope` : seule la **traversée** du dossier
manque. Le `postinst` pose à chaque configure `setfacl -m u:secubox-datascope:--x /var/lib/secubox/waf` (silencieux
si le dossier ou `setfacl` est absent ; `Recommends: acl`), rien d'autre ; `prerm remove` la retire. Si `secubox-waf-ng`
refait `chmod 0770` (tmpfiles), le masque ACL redevient `rwx` et l'entrée `--x` reste effective ; un `chmod 0700` la
neutraliserait (le paysage resterait alors vide, « droit refusé » affiché). Côté confinement : `ProtectSystem=strict` laisse la
lecture, aucun `InaccessiblePaths` ; le profil AppArmor n'autorise que `/var/lib/secubox/waf/populations.json r,`.

### Limites connues

Au démarrage de `secubox-waf-ng`, son `ExecStartPre` rend `/var/lib/secubox/waf` à `secubox-waf:secubox-waf`,
`populations.json` compris : le fichier (`0640`) est alors illisible pour DataScope (« droit refusé », le dernier
instantané reste affiché) jusqu'au relevé suivant, soit 30 min au plus ; il se rétablit seul. Correction prévue dans
`secubox-waf-ng` (exclusion du fichier).

Un instantané toutes les 30 min : la lecture d'un événement plus fin n'est pas possible. L'historique est court au
début (rien avant la mise en place de 0.2.0) ; les compteurs et l'enregistreur disent « historique non chargé » ou
« non mesuré » plutôt que d'inventer.
