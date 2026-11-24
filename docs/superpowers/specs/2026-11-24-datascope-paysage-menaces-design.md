# DataScope — paysage des menaces, tendances et enregistreur — conception

Issue #3921 · 2026-11-24 · dépend de #3919 (populations, campagnes enrichies, réseaux typés) · lien #3920 (pilotage)

## 1. Intention

DataScope V0.1 (#3853) montre l'infrastructure de gk2 (box, réseaux, interfaces, appareils, services) en topologie
SVG. Le propriétaire veut que ses vues de topologie deviennent un **graphe de renseignement** façon « knowledge
graph » (référence montrée : entités typées par forme et couleur, légende, barre de compteurs, synthèse et fil en
direct), centré sur **le paysage des attaquants** et ce qu'ils visent chez lui, avec :

- l'**état actuel** et l'**évolution** (ce qui apparaît, disparaît, monte, baisse) ;
- des **histogrammes de tendance** ;
- un **enregistreur** : lecture, retour en arrière, rembobinage, déplacement libre dans le temps.

Décisions du propriétaire (24/11) : données **observées par SecuBox, enrichies** (CVE suivies) « et plus si
pertinent » ; **paysage** au centre ; état actuel **et** évolution ; historique tenu par **DataScope lui-même**
(option 1) ; histogrammes de tendance ; enregistreur avec rembobinage.

## 2. Buts, non-buts, anti-buts

**Buts**
- Une perspective « Paysage » dans DataScope : graphe typé populations/campagnes ↔ réseaux sources ↔ cibles chez soi.
- Instantanés horodatés du paysage, différentiels calculés côté serveur.
- Barre de compteurs avec histogrammes de tendance ; histogramme par nœud dans l'inspecteur.
- Enregistreur temporel (lecture, pause, pas à pas avant/arrière, rembobinage, vitesse, curseur).
- Panneau de droite : synthèse déterministe + fil des changements.

**Non-buts**
- Aucune action depuis le graphe (DataScope reste en lecture seule : liens vers Actor, garde, WAF, NAC).
- Pas de renseignement externe non relié à une observation locale (pas de base mondiale de groupes APT).
- Pas de carte du monde (le Radar a déjà tranché : un classement se lit plus juste).
- Pas de nouvelle base de vulnérabilités : les CVE viennent du module existant `secubox-security-posture/composants/cve-triage`
  (CLI `secubox-cvectl`), via le champ `cves` des populations (#3919).
- Pas de synthèse IA dans ce lot (elle recréerait la dépendance gk2 → gk3 écartée en §3) : synthèse déterministe seule.
- Pas d'autres box du maillage comme cibles dans ce lot : DataScope V0.1 est local (`IPAddressDeny=any`) ; la vue
  multi-box viendra avec le transport du maître.

**Anti-buts**
- Un lien inventé : une CVE n'est reliée à un service que si une campagne a réellement sondé ce service sur un
  chemin ou une signature liée à cette CVE (filtres IA/Nuclei appliqués, catégories `ia_filtres_*`), jamais par
  simple présence du logiciel.
- Un graphe illisible (plat de spaghetti) : plafonds de nœuds, regroupements, repli par défaut.
- Une page lourde qui fige le navigateur ou charge gk2 : instantanés précalculés, différentiels côté serveur.

## 3. Approches

1. **DataScope collecte et garde des instantanés** (retenue). Le collecteur existant (minuterie 60 s) lit aussi les
   relevés de #3919 et écrit un instantané du paysage ; différentiels serveur ; rendu Cytoscape vendoré (déjà prévu
   en V0.2). Cohérent avec « collecteur par box, vue sur le maître ».
2. La page assemble le graphe à partir des API WAF/Actor. Aucune histoire : l'évolution et l'enregistreur sont
   impossibles. Écartée.
3. Lire l'historique de SecuBox AI (gk3). Dépendance gk2 → gk3, historique taillé pour le Radar. Écartée.

## 4. Conception

### 4.1 Modèle du paysage (entités et relations)

Nouveaux types d'entité (s'ajoutent à `node`, `network`, `interface`, `device`, `ip`, `service`) :

| Type | Forme / repère | Source | Clé |
|---|---|---|---|
| `population` | hexagone, emoji de famille (📚 ✉️ 🚪 🕷️), halo 🌀 si rotation | `/api/v1/waf/populations` (#3919) | `id` du relevé |
| `campagne` | losange | `/api/v1/actor/campaigns` (#3919, enrichi) | signature |
| `reseau_source` | rond, emoji de classe (🔁 🏢 🏠 🛰️ 🌐 🕶️ 🔬 ❔) | `reseaux_top` des populations | `AS<n>` |
| `classe_reseau` | rond creux (regroupe les `reseau_source` repliés) | idem | nom de classe |
| `cible` | rectangle : vhost, service, compte masqué, leurre | `cibles` des populations | nom normalisé |
| `cve` | triangle | champ `cves` de la population (#3919 : CVE des filtres `ia_filtres_*` déclenchés par ses adresses) | identifiant CVE |
| `pays` | drapeau (replié par défaut) | `pays_top` | code ISO |

Relations : `SOURCE_DE` (réseau → population), `VISE` (population → cible), `MEMBRE_DE` (campagne → population,
quand `campagne_actord` les relie), `EXPLOITE` (population → cve, seulement si la population a déclenché un filtre
lié à la CVE), `HEBERGE` (cible → service/box existants de la topologie V0.1), `ORIGINE` (population → pays).

Plafonds de lisibilité : 12 populations, 8 réseaux par population (le reste replié dans `classe_reseau`), 60 cibles,
20 CVE ; au-delà, nœud « + N autres ». Graphe rendu ≤ 400 nœuds.

### 4.2 Collecte et instantanés

- Nouveau connecteur `secubox_datascope/connecteurs/paysage.py` dans le collecteur existant. **Source unique** (choix
  du concepteur) : le **fichier** de cache `/var/cache/secubox/waf/populations.json` (#3919), lu directement — pas
  d'appel HTTP, donc pas de jeton : le collecteur n'a pas de JWT et les routes sont gardées. Le paquet waf-ng donne la
  lecture de ce fichier au groupe `secubox-datascope` (ACL), le profil AppArmor de DataScope l'autorise en lecture.
  Les campagnes d'actord arrivent par le champ `campagne_actord` des populations ; les CVE par leur champ `cves`.
  La topologie déjà en base fournit les nœuds `service`/`node` auxquels se raccrochent les cibles.
- **Identité stable** d'une population (pour différentiels, badges, tendances) : l'`id` du relevé #3919, défini là-bas
  comme `famille:<famille>`, `rotation:<8 hex>` ou `profileur:<signature>`.
- **Horodatage** d'un instantané = `genere_le` du relevé ; un nouvel instantané n'est écrit que si `genere_le` a changé
  (le collecteur tourne à 60 s, le relevé toutes les 10 min) ; un relevé `complet: false` est enregistré marqué
  `partiel` et l'enregistreur l'affiche comme tel.
- **Instantané** = le graphe du paysage sérialisé (JSON compact, compressé) + les compteurs :
  - toutes les **10 min**, gardés **48 h** (rembobinage fin) ;
  - toutes les **heures**, gardés **30 jours** (la rétention déjà décidée) ;
  - éclaircissement automatique : passé 48 h, seuls les instantanés horaires restent.
- Taille visée : ≤ 30 Ko compressé par instantané (≈ 288 × 30 Ko + 720 × 30 Ko ≈ 30 Mo). Stockage dans une **table à
  part** avec son **propre budget de 60 Mo** et une éviction des plus anciens (choix du concepteur) : le plafond
  global de 200 Mo de la base, qui **arrête** toute la passe de collecte quand il est atteint (`store.py`), ne doit
  jamais être atteint à cause des instantanés ; la topologie V0.1 n'est pas touchée.
- Budget du collecteur : `MemoryMax=128M` et `TimeoutStartSec=60` gardés si les mesures le permettent ; sinon
  `MemoryMax=192M`, mesuré et consigné.
- **Différentiel** calculé à l'écriture entre l'instantané et son prédécesseur de même pas : nœuds apparus, disparus,
  métriques en hausse ou en baisse (> 20 % et > 10 unités), rotation levée ou tombée ; stocké avec l'instantané.

### 4.3 API (lecture seule, `require_jwt` comme `/graph`)

- `GET /paysage` : dernier instantané + différentiel avec celui d'il y a 24 h.
- `GET /paysage/chronologie?de=&a=` : liste des instantanés disponibles (horodatage, pas, compteurs) — alimente le
  curseur et les histogrammes, sans les graphes.
- `GET /paysage/instantane/{ts}` : un instantané complet (pour l'enregistreur).
- `GET /paysage/difference?de=&a=` : différentiel entre deux instantanés quelconques.
- `GET /paysage/tendance/{id}?jours=7` : série d'un nœud (adresses, événements, bans par pas).

### 4.4 Perspective « Paysage » (page)

- **Graphe** Cytoscape vendoré (exception Aurora décidée le 21/11 pour la seule perspective Graph, **à inscrire**
  dans `.claude/AURORA-REFERENCE.md` avec son test, comme la spec du 21/11 le prévoyait), disposition en colonnes :
  réseaux sources à gauche, populations au centre, cibles à droite, infrastructure repliée à l'extrême droite ;
  formes et repères du §4.1 ; emoji toujours avec texte ; épaisseur d'arête = volume.
- **Légende** des types (en bas à gauche), avec cases à cocher pour masquer un type.
- **Barre de compteurs** (en bas) : populations, campagnes en rotation, réseaux, adresses, cibles touchées, bans,
  CVE sondées ; **chaque compteur porte son histogramme** des 24 dernières heures (barres de 1 h) ou des 7 derniers
  jours (barres d'un jour), au choix, et sa flèche de tendance avec l'écart chiffré.
- **Inspecteur** (droite, sur sélection) : fiche du nœud, histogramme de tendance du nœud (`/paysage/tendance`), liens
  vers les pages où l'on agit (Actor, garde, WAF, NAC).
- **Panneau de synthèse** (droite, sans sélection) : synthèse déterministe (« 2 populations en rotation, 1 nouvelle
  depuis hier : … ») et **fil des changements** (différentiels récents, du plus récent au plus ancien).
- **Mode évolution** : badges sur les nœuds — ✚ apparu, ✖ disparu (fantôme grisé), ▲ en hausse, ▼ en baisse ;
  comparaison « maintenant vs il y a 24 h / 7 j / date choisie ».
- **Enregistreur** (barre au-dessus des compteurs) : ⏮ rembobiner au début de la fenêtre, ◀◀ pas arrière, ▶/⏸
  lecture/pause, ▶▶ pas avant, ⏭ retour au direct ; vitesse ×1/×4/×16 (1 pas = 1 instantané) ; curseur temporel
  déplaçable ; fenêtre 48 h (pas de 10 min) ou 30 j (pas d'1 h). Pendant la lecture, le graphe s'anime : nœuds qui
  apparaissent, disparaissent, grossissent ; la barre de compteurs et ses histogrammes suivent le temps lu ; un
  bandeau « lecture du 22/11 04:10 » rappelle qu'on n'est plus en direct.
- Préchargement : l'enregistreur télécharge les instantanés par lots de 12 en avance, en mémoire bornée (≤ 60).

### 4.5 Ce qui est « en plus, si pertinent »

Retenu parce que la donnée existe déjà et que le lien est observé :
- **Leurres** (`leurre:*`) comme cibles distinctes : montrent ce que les scanners croient trouver.
- **Bans** : épaisseur ou anneau sur la population = part bannie ; le verdict reste dans la page WAF.

Écarté : pays en nœuds dépliés par défaut, groupes APT nommés, carte du monde, géolocalisation fine.

## 5. Contraintes

- Règles AGENTS.md (lecture seule, socket, `require_jwt`, tâche de fond + cache, AppArmor enforce : le profil de
  DataScope autorise la lecture de `/var/cache/secubox/waf/populations.json`, rien d'autre de nouveau).
- Le collecteur garde ses limites (`Nice=10`, `CPUQuota=25%`, I/O idle) ; un instantané se calcule en < 2 s sur gk2.
- Cytoscape vendoré dans le paquet (pas de CDN : la page d'administration n'appelle aucun tiers).
- Accessibilité : chaque forme a aussi son libellé ; l'animation de l'enregistreur respecte `prefers-reduced-motion`
  (bascule en changements instantanés).
- Données personnelles : comptes masqués, aucune adresse IP d'attaquant dans les instantanés (réseaux, compteurs et
  populations seulement) ; les adresses restent dans les pages WAF/Actor.

## 6. Critères d'acceptation

1. Sur gk2, après 2 h, la perspective Paysage affiche les populations du relevé #3919, leurs réseaux et leurs cibles,
   avec des chiffres identiques au relevé.
2. Les histogrammes de la barre de compteurs et de l'inspecteur correspondent aux instantanés stockés.
3. L'enregistreur rembobine 48 h au pas de 10 min et 30 j au pas d'1 h ; chaque pas affiche l'instantané exact ;
   aucun gel du navigateur (pas > 100 ms de travail continu) sur un portable moyen.
4. Le différentiel « 24 h » signale l'apparition de la population collecte Gitea si on rejoue les instantanés de part
   et d'autre de son apparition.
5. Base DataScope ≤ 200 Mo après 30 jours ; collecteur dans ses quotas.

## 7. Laissé au constructeur

- Format exact de sérialisation et de compression des instantanés ; schéma SQL.
- Disposition fine de Cytoscape et animations ; palette, dans les tokens de DataScope.
- Choix d'une version précise de Cytoscape (pinnée, vendorée).
