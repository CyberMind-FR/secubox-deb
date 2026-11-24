# DataScope — paysage des menaces, tendances et enregistreur — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** une vue « Paysage » dans DataScope — populations d'attaquants, réseaux sources et cibles en graphe typé —
avec instantanés horodatés, différentiels, histogrammes de tendance et un enregistreur à rembobinage.

**Architecture :** le collecteur existant lit le relevé `populations.json` de #3919 et écrit un instantané compressé
du paysage dans une table dédiée (migration 0002), avec son budget et son éclaircissement. L'API sert le dernier
instantané, la chronologie, un instantané donné, une différence et la tendance d'un nœud. La page dessine le paysage
en SVG écrit à la main (colonnes déterministes), comme l'arbre existant.

**Tech Stack :** Python 3.13 (sqlite3, zlib, json), FastAPI, SVG + JS sans bibliothèque (règle Aurora §1), Debian.

**Spec :** `docs/superpowers/specs/2026-11-24-datascope-paysage-menaces-design.md` (#3921). **Dépend de #3919** :
format de `populations.json` défini dans `docs/superpowers/plans/2026-11-24-populations-rotation.md` tâche 5
(branche de #3919). Chemins relatifs à la racine du worktree ; `DS` = `packages/secubox-datascope`.

**Écart assumé à la spec (décision de plan)** : pas de Cytoscape. `.claude/AURORA-REFERENCE.md` §1 interdit toute
bibliothèque et aucune exception n'y est écrite ; le paysage étant en colonnes (réseaux → populations → cibles →
infrastructure), le SVG à la main suffit, comme `rendreArbre`. Coût si c'est faux : reprendre le rendu de la tâche 5.

## Global Constraints

- DataScope reste en lecture seule ; aucune route mutante ; nouvelles routes sous `require_jwt`.
- Source unique : le fichier `/var/lib/secubox/waf/populations.json` (clé de config `[sources] populations`, variable
  `SECUBOX_DATASCOPE_POPULATIONS`) ; aucun appel HTTP, aucun réseau (`IPAddressDeny=any` inchangé).
- Instantané : horodatage = `genere_le` du relevé ; écrit seulement si `genere_le` a changé ; relevé `complet: false`
  → instantané marqué `partiel`.
- Rétention : pas de 10 min gardés 48 h ; au-delà, un instantané par heure, gardé 30 jours ; budget propre **60 Mo**,
  éviction des plus anciens ; ≤ 30 Ko compressé visé par instantané.
- Plafonds de lisibilité : 12 populations, 8 réseaux par population (reste replié dans `classe_reseau`), 60 cibles,
  20 CVE, graphe rendu ≤ 400 nœuds ; au-delà, nœud « + N autres ».
- Différence notable : écart > 20 % **et** > 10 unités.
- Aucune adresse IP d'attaquant dans les instantanés ; comptes déjà masqués par #3919 (`ger…`).
- Emoji toujours accompagné de son texte ; repères = copie identique de `packages/secubox-waf-ng/www/actor/reperes.js`
  (#3919 tâche 6), vérifiée par test.
- Collecteur dans ses quotas (`MemoryMax=128M`, `TimeoutStartSec=60`, `CPUQuota=25%`) ; un instantané < 2 s.
- Animations de l'enregistreur : `prefers-reduced-motion` → changements instantanés.
- Page : un seul bloc `<script>` en ligne (règle de `test_page.py`), SPDX, mode `?demo=1` sans réseau, `?embed=1`.
- Version : `secubox-datascope` 0.2.0-1~trixie1 ; en-tête SPDX CMSD-1.0 sur tout fichier créé.
- Tests : `python3 -m pytest packages/secubox-datascope/tests -q` ; horloge `NOW = 1795000000.0` comme les tests existants.

## Review Focus

1. `populations.json` absent, illisible, plus ancien que le dernier instantané, ou produit par une version de #3919
   sans certains champs (`cves`, `campagne_actord`, `id`) : pas d'instantané faux, pas d'exception ; champs manquants
   = vides — tests tâche 2.
2. `genere_le` qui recule ou saute dans le futur (horloge de gk2 corrigée) : aucun instantané en double ni hors
   d'ordre dans la chronologie — test tâche 3.
3. Budget de 60 Mo atteint alors que les instantanés récents sont gros : on évince les plus anciens, jamais le
   dernier, et la topologie V0.1 continue — test tâche 1.
4. Enregistreur sur une fenêtre avec des trous (collecteur arrêté) ou des instantanés partiels : le curseur saute les
   trous sans planter et signale « partiel » — test tâche 7.
5. Plus de 12 populations ou une population à 300 réseaux : graphe plafonné avec « + N autres », jamais > 400 nœuds —
   test tâche 2.

---

### Task 1 : stockage des instantanés (migration 0002 + store)

**Files :**
- Create : `DS/migrations/0002-paysage.sql`, `DS/secubox_datascope/paysage_store.py`
- Test : `DS/tests/test_paysage_store.py`

**Interfaces :**
- Produces (dans `paysage_store.py`) :
  - table `paysage_instantanes(ts TEXT PRIMARY KEY /* ISO UTC = genere_le */, epoch REAL NOT NULL, partiel INTEGER NOT NULL, graphe BLOB NOT NULL /* zlib(JSON) */, compteurs_json TEXT NOT NULL, difference_json TEXT NOT NULL DEFAULT '{}', octets INTEGER NOT NULL)`, index sur `epoch`.
  - `BUDGET_OCTETS = 60*1024*1024`, `FENETRE_FINE_S = 48*3600`, `RETENTION_S = 30*86400`
  - `def ecrire(db, epoch: float, partiel: bool, graphe: dict, compteurs: dict, difference: dict) -> bool` (False si `ts` existe déjà ou si `epoch` ≤ dernier époque)
  - `def dernier(db) -> dict | None` ; `def lire(db, ts: str) -> dict | None` (graphe décompressé)
  - `def chronologie(db, de: float, a: float) -> list[dict]` (`ts, epoch, partiel, compteurs`, sans graphe)
  - `def eclaircir(db, maintenant: float) -> int` (au-delà de 48 h, garde le premier instantané de chaque heure ;
    supprime au-delà de 30 j ; puis évince les plus anciens tant que `SUM(octets) > BUDGET_OCTETS`, jamais le dernier)
- [ ] **Step 1 : tests qui échouent** :
  - `test_migration_0002_appliquee` : `store.ouvrir(tmp)` crée `paysage_instantanes` ; version `0002` dans `schema_migrations`.
  - `test_ecrire_lire_aller_retour` : graphe `{"noeuds":[...],"aretes":[...]}` relu identique ; `octets` = taille compressée.
  - `test_ecrire_refuse_doublon_et_recul` : même `ts` → False ; `epoch` antérieur au dernier → False.
  - `test_eclaircir_horaire` : 6 instantanés à 10 min d'intervalle il y a 50 h → 1 seul reste ; ceux d'il y a 1 h restent tous.
  - `test_eclaircir_retention` : instantané de 31 j supprimé.
  - `test_budget_evince_anciens` : `BUDGET_OCTETS` abaissé par monkeypatch, 10 instantanés → les plus anciens partent,
    le dernier reste toujours.
- [ ] **Step 2 : vérifier l'échec** — `python3 -m pytest packages/secubox-datascope/tests/test_paysage_store.py -q` → FAIL.
- [ ] **Step 3 : implémenter.** Ne pas toucher aux CHECK de `entities`/`relationships` (le paysage n'y va pas).
- [ ] **Step 4 : vérifier** — toute la suite du paquet → PASS.
- [ ] **Step 5 : commit** — `feat(datascope): table des instantanés du paysage, budget et éclaircissement (ref #3921)`.

### Task 2 : connecteur « paysage » (relevé → graphe typé)

**Files :**
- Create : `DS/secubox_datascope/connecteurs/paysage.py`
- Modify : `DS/secubox_datascope/config.py`, `DS/conf/datascope.toml` (clé `populations`)
- Test : `DS/tests/test_connecteur_paysage.py`

**Interfaces :**
- Consumes : forme du relevé (plan #3919 tâche 5) : `genere_le`, `complet`, `populations[]` (`id`, `famille`,
  `cibles`, `adresses`, `reseaux`, `une`, `le3`, `classes`, `pays_top`, `reseaux_top[{asn,org,classe,adresses}]`,
  `serie`, `bans`, `rotation`, `etat`, `campagne_actord`, `cves`), `recouvrement`.
- Produces :
  - `Config.populations: Path` (défaut `/var/lib/secubox/waf/populations.json`, variable `SECUBOX_DATASCOPE_POPULATIONS`)
  - `@dataclass class Paysage: epoch: float; partiel: bool; graphe: dict; compteurs: dict`
  - `def lire(chemin: Path, hote: str) -> Paysage | None` (None si absent, illisible, ou sans `genere_le`)
  - Graphe : `{"noeuds": [{"id","type","libelle","famille"?,"classe"?,"metriques":{...}}], "aretes": [{"de","vers","type","poids"}]}`
    - types de nœud : `population`, `campagne`, `reseau_source`, `classe_reseau`, `cible`, `cve`, `pays`, `infra`
    - identifiants : `pop:<id>`, `camp:<signature>`, `asn:<n>`, `classe:<pop>:<classe>`, `cible:<nom>`, `cve:<id>`,
      `pays:<code>`, `infra:<hote>`
    - arêtes : `SOURCE_DE` (asn→pop, poids = adresses), `VISE` (pop→cible), `MEMBRE_DE` (camp→pop), `EXPLOITE`
      (pop→cve), `ORIGINE` (pop→pays), `HEBERGE` (cible→`infra:<hote>`)
  - Compteurs : `populations`, `rotation`, `reseaux`, `adresses`, `cibles`, `bans`, `cves`.
- [ ] **Step 1 : tests qui échouent** (relevé JSON écrit dans `tmp_path`) :
  - `test_lire_absent_ou_illisible` : fichier absent, JSON tronqué, sans `genere_le` → None.
  - `test_graphe_types_et_aretes` : relevé de 2 populations → nœuds `pop:famille:collecte`, `asn:212238`,
    `cible:gitea.gk2.secubox.in`, `infra:<hote>`, arêtes `SOURCE_DE` et `VISE` présentes ; compteurs exacts.
  - `test_champs_manquants` : population sans `cves`, `campagne_actord` ni `pays_top` → aucun nœud `cve`/`camp`/`pays`, pas d'exception.
  - `test_plafonds` : 15 populations dont une à 300 réseaux → 12 populations + nœud `+ 3 autres`, 8 `asn:` pour la
    grosse + un `classe:` par classe repliée, total nœuds ≤ 400.
  - `test_aucune_adresse_ip` : aucune chaîne du graphe sérialisé ne correspond à une adresse IPv4/IPv6.
  - `test_partiel` : `complet: false` → `Paysage.partiel is True`.
- [ ] **Step 2 : vérifier l'échec.**
- [ ] **Step 3 : implémenter.** Fonction pure ; le nom d'hôte de gk2 vient de l'appelant (`hote`, comme `network.lire`).
- [ ] **Step 4 : vérifier** — PASS.
- [ ] **Step 5 : commit** — `feat(datascope): connecteur du paysage des menaces (ref #3921)`.

### Task 3 : intégration au collecteur et différentiel

**Files :**
- Modify : `DS/secubox_datascope/collecte.py` (`passe` l.155, après les connecteurs existants l.174-177)
- Create : `DS/secubox_datascope/difference.py`
- Test : `DS/tests/test_collecte_paysage.py`, `DS/tests/test_difference.py`

**Interfaces :**
- Consumes : `paysage.lire` (tâche 2) ; `paysage_store.ecrire/dernier/eclaircir` (tâche 1).
- Produces :
  - `def difference(avant: dict | None, apres: dict) -> dict` →
    `{"apparus": [id], "disparus": [id], "hausses": [{"id","metrique","de","a"}], "baisses": [...], "rotation_levee": [id], "rotation_tombee": [id]}` ;
    métriques comparées : `adresses`, `bans`, `reseaux` des nœuds `population` ; seuil : écart > 20 % et > 10.
  - `passe` renvoie en plus `sources["paysage"] = {"etat": "ok"|"inaccessible"|"inchange", "motif"?, "ecrit": bool}`.
- [ ] **Step 1 : tests qui échouent** :
  - `test_difference_apparus_disparus_seuil` : 100→115 (15 %, +15) n'est pas une hausse ; 100→130 (+30) en est une ;
    5→16 (+11, 220 %) en est une ; 5→14 (+9) non.
  - `test_difference_sans_avant` : `avant=None` → tous `apparus`.
  - `test_passe_ecrit_un_instantane` : relevé présent → un instantané, `sources["paysage"]["ecrit"] is True`.
  - `test_passe_inchange` : deux passes avec le même `genere_le` → un seul instantané, état `inchange`.
  - `test_passe_genere_le_recule` : `genere_le` antérieur au dernier → rien d'écrit, pas d'exception.
  - `test_passe_sans_relevé` : fichier absent → état `inaccessible`, la topologie V0.1 est écrite comme avant
    (`graph.json` publié).
- [ ] **Step 2 : vérifier l'échec.**
- [ ] **Step 3 : implémenter.** Le pas du paysage ne doit jamais faire échouer la passe : toute erreur est capturée
  et rendue dans `sources["paysage"]`. `eclaircir` appelé à chaque passe qui écrit.
- [ ] **Step 4 : vérifier** — toute la suite → PASS.
- [ ] **Step 5 : commit** — `feat(datascope): instantanés du paysage à chaque nouveau relevé, différentiels (ref #3921)`.

### Task 4 : routes API du paysage

**Files :**
- Modify : `DS/api/main.py` (routes avant l.320), `DS/tests/test_conformite_gardes.py` (liste `TOPOLOGIE`)
- Test : `DS/tests/test_api_paysage.py`

**Interfaces :**
- Consumes : `paysage_store` (tâche 1), `difference` (tâche 3).
- Produces (toutes `require_jwt`, via `_lire_base` + `asyncio.to_thread`) :
  - `GET /paysage` → `{"disponible", "instantane": {ts, epoch, partiel, graphe, compteurs}, "difference_24h": {...}}`
    (`difference_24h` = `difference(instantané le plus proche de il y a 24 h, dernier)`) ; aucun → `{"disponible": False}`.
  - `GET /paysage/chronologie?de=&a=` (époques ; défaut : 48 h) → `{"instantanes": [...]}` ; `a - de` > 31 j → 400.
  - `GET /paysage/instantane/{ts}` → instantané complet ; `ts` hors format ISO → 400 ; inconnu → 404.
  - `GET /paysage/difference?de=&a=` (deux `ts`) → `difference(...)` ; inconnu → 404.
  - `GET /paysage/tendance/{id}?jours=7` → `{"id", "points": [{"ts", "adresses", "bans", "reseaux"}]}` (lu dans les
    graphes des instantanés horaires de la période) ; `id` hors `^[a-z_]+:[A-Za-z0-9:._…-]{1,160}$` → 400 ; `jours` ≤ 30.
- [ ] **Step 1 : tests qui échouent** (`TestClient`, `dependency_overrides` comme `test_api.py`) : un test par route
  pour le cas nominal et chaque erreur listée ; `test_conformite_gardes` mis à jour échoue tant que les routes manquent.
- [ ] **Step 2 : vérifier l'échec.**
- [ ] **Step 3 : implémenter.**
- [ ] **Step 4 : vérifier** — toute la suite → PASS.
- [ ] **Step 5 : commit** — `feat(datascope): routes du paysage, chronologie, différence et tendance (ref #3921)`.

### Task 5 : vue « Paysage » (graphe SVG, légende, inspecteur)

**Files :**
- Modify : `DS/www/datascope/index.html` (bouton `#vuePaysage` à côté de `#vueBulles`/`#vueArbre`, `choisirVue` l.484,
  `rendreTopo` l.473, nouvelle fonction `rendrePaysage(box)`, inspecteur `inspecter` l.540, données de démo)
- Create : `DS/www/datascope/reperes.js` (copie identique de `packages/secubox-waf-ng/www/actor/reperes.js`)
- Test : `DS/tests/test_page_paysage.py`

**Interfaces :**
- Consumes : `GET /paysage` (tâche 4) ; `window.SbxReperes` (`CLASSES`, `FAMILLES`, `ETATS`, `drapeau`, `nomCarte`, `puce`).
- Produces : `rendrePaysage(box, instantane, difference)` réutilisée par les tâches 6 et 7.

- [ ] **Step 1 : tests qui échouent** (statiques, comme `test_page.py`) :
  - `test_reperes_identiques` : `DS/www/datascope/reperes.js` == `packages/secubox-waf-ng/www/actor/reperes.js` octet pour octet
    (sauter avec raison explicite si le fichier de #3919 n'est pas encore sur la branche).
  - `test_vue_paysage_presente` : `#vuePaysage`, `rendrePaysage(`, `SbxReperes.` présents ; un seul `<script>` en ligne
    (le chargement de `reperes.js` se fait comme `/shared/sidebar.js`, par `createElement`).
  - `test_demo_paysage` : `DEMO_DONNEES` contient un instantané de paysage sans adresse IP réelle.
- [ ] **Step 2 : vérifier l'échec.**
- [ ] **Step 3 : implémenter.** Disposition en 4 colonnes (réseaux sources | populations et campagnes | cibles |
  infrastructure repliée) ; formes : population = hexagone, campagne = losange, réseau = rond, classe repliée = rond
  creux, cible = rectangle, CVE = triangle, pays = drapeau (replié par défaut) ; libellé visible sous chaque forme ;
  épaisseur d'arête ∝ `poids` (1 à 6 px) ; halo 🌀 sur les populations en rotation ; légende en bas à gauche avec
  cases à cocher par type ; clic = `selectionner` + inspecteur (fiche, liens vers `/actor/`, `/waf/`, `/garde/`,
  `/nac/`) ; état vide « relevé des populations indisponible ».
- [ ] **Step 4 : vérifier** — suite → PASS ; contrôle visuel `?demo=1` à 1280 px et 400 px (pas de barre
  horizontale de page ; le SVG défile dans son conteneur).
- [ ] **Step 5 : commit** — `feat(datascope): vue Paysage du graphe des menaces (ref #3921)`.

### Task 6 : barre de compteurs à histogrammes, tendance de nœud, synthèse et fil

**Files :**
- Modify : `DS/www/datascope/index.html`
- Test : `DS/tests/test_page_paysage.py` (ajouts)

**Interfaces :**
- Consumes : `GET /paysage/chronologie`, `GET /paysage/tendance/{id}` (tâche 4) ; `rendrePaysage` (tâche 5).
- Produces : `rendreCompteurs(chronologie, maintenantTs)`, `rendreTendance(noeud, points)`, `rendreSynthese(instantane, difference)`.

- [ ] **Step 1 : tests qui échouent** : présence des trois fonctions ; bascule `24 h | 7 j` ; synthèse construite
  uniquement à partir de `difference` (pas de texte libre venu du serveur) ; histogrammes avec `<title>` par barre
  (valeur et heure) ; flèche de tendance accompagnée de l'écart chiffré.
- [ ] **Step 2 : vérifier l'échec.**
- [ ] **Step 3 : implémenter.** Barre en bas : 7 compteurs (populations, rotation, réseaux, adresses, cibles, bans,
  CVE), chacun avec sa valeur, sa flèche ▲/▼ et l'écart, et son histogramme (24 barres d'1 h ou 7 barres d'un jour,
  une seule teinte, barre courante accentuée). Inspecteur : histogramme de tendance du nœud sélectionné. Panneau de
  droite sans sélection : synthèse déterministe (« N populations, dont R en rotation ; apparues depuis 24 h : … ;
  en hausse : … ») et fil des changements (différences des 12 derniers instantanés, du plus récent au plus ancien).
- [ ] **Step 4 : vérifier** — PASS ; contrôle visuel `?demo=1`.
- [ ] **Step 5 : commit** — `feat(datascope): compteurs à histogrammes, tendance, synthèse et fil des changements (ref #3921)`.

### Task 7 : mode évolution et enregistreur

**Files :**
- Modify : `DS/www/datascope/index.html`
- Test : `DS/tests/test_page_paysage.py` (ajouts), `DS/tests/test_page_playwright.py` (un scénario, marqué `playwright`)

**Interfaces :**
- Consumes : `GET /paysage/instantane/{ts}`, `GET /paysage/difference`, `GET /paysage/chronologie` (tâche 4) ;
  `rendrePaysage`, `rendreCompteurs` (tâches 5-6).
- Produces : objet `Enregistreur` (`aller(ts)`, `lecture()`, `pause()`, `pas(+1|-1)`, `rembobiner()`, `direct()`,
  `vitesse(1|4|16)`), cache borné de 60 instantanés, préchargement par lots de 12.

- [ ] **Step 1 : tests qui échouent** :
  - statiques : boutons ⏮ ◀◀ ▶/⏸ ▶▶ ⏭ avec `aria-label` en clair ; sélecteur de fenêtre `48 h (10 min) | 30 j (1 h)` ;
    sélecteur de comparaison `24 h | 7 j | date` ; badges ✚ ✖ ▲ ▼ avec texte ; `prefers-reduced-motion` présent ;
    bandeau « lecture du … » ; cache plafonné à 60.
  - Playwright (si disponible) : en `?demo=1`, ⏮ puis ▶▶ trois fois affiche le 4e instantané de démo ; un
    instantané `partiel` affiche le mot « partiel » ; un trou dans la chronologie est sauté.
- [ ] **Step 2 : vérifier l'échec.**
- [ ] **Step 3 : implémenter.** Pendant la lecture, transitions SVG (apparition, disparition en fantôme grisé,
  croissance) sur 300 ms, aucune boucle de travail > 100 ms (le rendu d'un pas se fait en une passe) ; ⏭ revient au
  direct et retire le bandeau.
- [ ] **Step 4 : vérifier** — suite → PASS (Playwright sauté s'il est absent) ; contrôle visuel `?demo=1`.
- [ ] **Step 5 : commit** — `feat(datascope): mode évolution et enregistreur à rembobinage (ref #3921)`.

### Task 8 : AppArmor, paquet, documentation

**Files :**
- Modify : `DS/apparmor/secubox-datascope` (après l.167 : `/var/lib/secubox/waf/populations.json r,` ; en-tête l.5-7),
  `DS/debian/changelog` (0.2.0-1~trixie1), `DS/README.md` (vue Paysage, routes, clé `populations`, instantanés)
- Test : `DS/tests/test_paquet.py` (ajouts)

- [ ] **Step 1 : tests qui échouent** : le profil contient la règle de lecture ; `migrations/0002-paysage.sql` et
  `www/datascope/reperes.js` sont installés par `debian/rules` (déjà couverts par les copies récursives : le test le
  vérifie sur le paquet construit ou sur `debian/rules`) ; README mentionne les 5 routes.
- [ ] **Step 2 : vérifier l'échec**, puis modifier.
- [ ] **Step 3 : vérifier** — suite → PASS ; `cd DS && dpkg-buildpackage -us -uc -b` → paquet ; `dpkg-deb -c` contient
  `usr/lib/secubox/datascope/migrations/0002-paysage.sql` (ou le chemin réel des migrations) et `reperes.js`.
- [ ] **Step 4 : commit** — `chore(datascope): profil, paquet 0.2.0 et documentation du paysage (ref #3921)`.

### Task 9 : déploiement (contrôleur, après le déploiement de #3919)

- [ ] Prérequis : #3919 déployé sur gk2, `populations.json` présent et lisible par le groupe `secubox-datascope`.
- [ ] Publier puis installer `secubox-datascope` sur gk2 (`systemd-run`, sans délai ; `uptime`/`free -m` avant ;
  couture vérifiée après).
- [ ] Vérifier : `sources["paysage"]` à `ok` après 10 min ; `/api/v1/datascope/paysage` ; vue Paysage dans
  `https://admin.gk2.secubox.in/datascope/` ; après 2 h, chronologie de ≥ 12 instantanés et enregistreur fonctionnel ;
  taille des instantanés ≤ 30 Ko ; collecteur dans ses quotas (`systemctl show -p MemoryPeak`).
- [ ] `.claude/HISTORY.md`, `.claude/WIP.md`, issue #3921.
