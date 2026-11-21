<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

> **Statut (21/11/2026)** : analyse de conception, avant spec. Décision du propriétaire sur la question 6 :
> **OSINT = intégration profonde ou remplacement complet par des outils SBX équivalents** — SecuBox possède son
> moteur (graphe, enrichissement, transforms) ; Maltego n est jamais une dépendance, au mieux un format d échange.
> Questions 1 à 5 en attente.

# SBXOS DataScope — analyse de conception (21/11/2026)

Analyse en lecture seule du dépôt (`master` b8cec8cf2). Aucun code écrit, aucun fichier du dépôt modifié.
Entrée : `datascope-osint-specs-proprietaire.md` (DataScope validé, OSINT non tranché).
Règles opposables : `AGENTS.md`, `.claude/RULES-CODE.md`, `.claude/MODULE-COMPLIANCE.md`,
`.claude/WEBUI-PANEL-GUIDELINES.md`, `.claude/AURORA-REFERENCE.md`, `.claude/reference/PERF-CACHE.md`.
Les chemins sont relatifs à la racine du dépôt. « À vérifier au banc » signale ce qui ne se déduit pas du code.

## 0. Résumé

- Le produit validé (cockpit, six perspectives, modèle canonique, connecteurs) est compatible avec le dépôt.
  Ce qui ne l'est pas, c'est son **emballage technique** : port TCP, venv `/opt`, Vite/TypeScript, proxy nginx
  propre. Chacun a un équivalent maison déjà éprouvé ; `secubox-status` est le gabarit le plus proche.
- Trois points ne sont pas de simples substitutions et demandent un arbitrage du propriétaire :
  1. le moteur de graphe validé (Cytoscape en canvas, Sigma en WebGL, bibliothèques tierces) contredit la lettre
     d'Aurora § 1 (« aucune bibliothèque, pas de canvas ») ;
  2. un index transversal des événements DNS par appareil croise une donnée **nominative** que les modules
     protègent aujourd'hui chacun de leur côté ;
  3. l'ingestion de fond n'a pas d'appelant dont retransmettre le jeton : il faut soit lire des fichiers, soit
     créer un compte de service.
- Une bonne part du « graphe » et de l'« index d'événements » existe déjà : `sbx-actord` (graphe d'acteur,
  preuves, événements), la veille de `secubox-ai` (événements à curseurs, dossiers, campagnes, rétention 30 j),
  le magasin d'appareils du NAC. DataScope doit les **référencer**, pas les recopier.
- V0.1 recommandée : paquet `secubox-datascope`, socket Unix, collecteur minuté qui ne lit que des caches,
  deux connecteurs (**Network** par le NAC, **Status** par Status Live), page Aurora sans bibliothèque
  (topologie SVG déterministe). Le moteur hybride arrive en V0.2, avec son exception écrite.

## A. Conflits entre le spec et les règles, et résolution proposée

| # | Le spec propose | La règle | Résolution |
|---|---|---|---|
| A1 | API sur `127.0.0.1:8790` | `AGENTS.md` § API : « Socket `/run/secubox/<module>.sock`, jamais un port TCP direct » ; `MODULE-COMPLIANCE.md:196-198` | `/run/secubox/datascope.sock`, propriétaire le service, groupe `secubox`, `0660`. Unité calquée sur `packages/secubox-status/debian/secubox-status.service` : `ExecStartPre=+/bin/rm -f …sock`, `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`. Jamais `RuntimeDirectory=secubox` (`MODULE-COMPLIANCE.md:564-567`). |
| A2 | venv dans `/opt`, SQLAlchemy | Les modules s'installent sous `/usr/lib/secubox/<module>/` et tournent avec le `python3` du système (`packages/secubox-soc/debian/rules:6-7`, `secubox-soc.service` : `ExecStart=/usr/bin/python3 -m uvicorn … --uds`) | Pas de venv. `Depends: python3-fastapi, python3-uvicorn, secubox-core` comme `packages/secubox-status/debian/control`. SQLite par `sqlite3` de la bibliothèque standard, comme le NAC (`packages/secubox-nac/api/store.py:72`), Status et la veille. Les seuls venv du dépôt sont des cas à part (`secubox-billets/debian/postinst`, services dans des LXC de `secubox-ytsas`). |
| A3 | Frontend TypeScript/Vite | Aurora § 1 : « un HTML autonome, CSS et JS en ligne, aucune bibliothèque, aucun `<script src>` », « pas de canvas, pas de bibliothèque de graphes » | Voir A4. Une filière Vite existe (`scripts/construire-front.sh`, `packages/secubox-sbxos/debian/rules:5-16` : `debian/rules` ne lance jamais npm, il vérifie `dist/.construit`), mais elle sert la PWA publique du Hall (React), pas un panneau d'administration. Ne pas l'ouvrir pour V0.1 : page Aurora en JS simple. À réexaminer seulement si le code du cockpit dépasse ce qu'un fichier tient lisiblement. |
| A4 | Cytoscape.js + Sigma.js + Graphology (validé) | Aurora § 1 (ci-dessus). La CSP des vhosts est `script-src 'self' 'unsafe-inline'` (`packages/secubox-webos/nginx/hall.vhost.conf:117`) : un script **de même origine** passe, un CDN non | Exception **écrite** dans `AURORA-REFERENCE.md` § 1 (« DataScope : bibliothèques de graphe vendorées, même origine, chargées à la demande »), avec son test. Précédents de vendorisation : `packages/secubox-toolbox/www/toolbox/d3.v7.min.js` chargé par `conf/social_view.html.j2:16`, `secubox-webos/www/hall/hls.min.js`, `secubox-vault/www/pgp/openpgp.min.js`. Le reste d'Aurora (jetons, squelette, container queries, vérité des données, tests) s'applique tel quel. **Arbitrage propriétaire** (question 2). |
| A5 | Proxy nginx propre | `MODULE-COMPLIANCE.md:432-462` : route **API seule** livrée dans `/etc/nginx/secubox-routes.d/` (et `secubox.d/`), jamais d'édition de `webui.conf`, pas d'`alias` statique, pas d'`error_page` sur une route d'API | `nginx/datascope.conf` : une `location /api/v1/datascope/` vers la socket, sur le modèle de `packages/secubox-status/nginx/status.conf`. Les statiques sont servis par le `root` du vhost depuis `/usr/share/secubox/www/datascope/`. Pas de vhost propre, donc aucune exposition nouvelle ni bypass WAF ; la chaîne HAProxy → `sbxwaf` → nginx reste celle du vhost d'administration. |
| A6 | « Service séparé de l'agrégateur » | Par défaut un module est monté dans l'agrégateur, sur **une seule boucle** partagée (`RULES-CODE.md` § 6 ; `packages/secubox-aggregator/README.md:5-7`) | Le spec a raison ici, et c'est conforme : socket dédiée avec sa propre route nginx (comme Status), **non citée** dans `aggregator.toml`. Un module à base SQLite et collecteur ne doit pas vivre deux fois : c'est l'incident NAC #3178 (`packages/secubox-aggregator/aggregator/main.py:243-244`). |
| A7 | Gardes non précisées | Toute route porte une garde ; `require_jwt` pour « journaux, sessions, **topologie** », `require_lecture` pour l'affichage (`MODULE-COMPLIANCE.md:165-176`) ; `tests/test_conformite_jwt.py` | `GET /health` public. `GET /status`, `/overview`, `/sources` (compteurs, états) : `require_lecture`. Tout ce qui porte des entités, relations, voisins, graphe, événements, contexte : **`require_jwt`**. Toute route mutante (vues sauvegardées, tâches, V1.0) : `require_jwt`. En cas de doute, `require_jwt`. |
| A8 | SSE `/stream` + WebSocket optionnel | Garde obligatoire ; `EventSource` n'envoie pas d'en-tête `Authorization` | Flux par `fetch` en lecture continue avec le jeton `sbx_token`, ou cookie de session de même origine. Précédent SSE : `packages/secubox-pilotage/pilotage/diffusion.py`. WebSocket : retiré du périmètre (rien ne le justifie devant un SSE). Pas avant V0.3. |
| A9 | Utilisateur et confinement non précisés | `AGENTS.md` : AppArmor `enforce` et utilisateur dédié `secubox-<module>` ; socle systemd `RULES-CODE.md` § 10 | `User=secubox-datascope`, `Group=secubox`, profil `apparmor/secubox-datascope` livré dans `/etc/apparmor.d/` (modèle `packages/secubox-status/apparmor/secubox-status`), socle § 10 complet, `UMask=0027`. Lecture seule sur les données des autres modules ; écriture sur sa base, son cache et `audit.log` seulement. |
| A10 | Base dans `/var/lib/secubox/datascope/` | `systemd-tmpfiles` refuse `/var/lib/secubox/<module>/` (« unsafe path transition », #3172, note de mémoire) | `StateDirectory=secubox-datascope` → `/var/lib/secubox-datascope/datascope.db`, comme Status (`StateDirectory=secubox-status`). Cache : `/var/cache/secubox/datascope/`. Sur gk2 la racine est à 91 % (note de mémoire) : garde d'espace avant écriture, voir C. |
| A11 | Connecteurs « events indexés » pour DNS, DPI, WAF | Chaque module garde ses lectures (`require_lecture_ai` sur `/bans` et `/menaces/flux` du WAF, `require_jwt` sur `/clients` du NAC). SADE « ne forge ni ne conserve aucun jeton », il retransmet ceux de l'appelant (`packages/secubox-soc/api/defense.py:14-15`, `:104-114`) | Un collecteur de fond n'a pas d'appelant. Trois voies conformes : (a) lire des **fichiers ou bases en lecture seule** (`mode=ro`), comme Status et comme le NAC sur la base d'ad-guard (`packages/secubox-nac/api/dnsevidence.py:34`) ; (b) sockets sans garde applicative (`actor.sock`, protégée par le groupe, `packages/secubox-soc/tests/donnees/substrat/RELEVE.md:23-25`) ; (c) **compte de service** Ed25519 à portée de lecture, sur le modèle `ai-lecture` (`common/secubox_core/compte_service.py:6-9`, `:37-40`). La voie (c) touche `common/` : publier `secubox-core` d'abord et versionner le `Depends` (note de mémoire). V0.1 se limite à (a). Ne jamais frapper un jeton HS256 depuis le service. |
| A12 | Index commun incluant DNS par appareil | La lecture DNS par appareil est **nominative** (`require_lecture_nominative`, `packages/secubox-ad-guard/api/dnstv_routes.py:108`) ; le NAC s'interdit de connaître l'historique de navigation (`packages/secubox-nac/api/dnsevidence.py:8-10`) ; le détail ligne à ligne est réservé à l'administrateur (`dnstv_lot3_routes.py:130-131`) | L'index DataScope ne stocke **aucun** couple appareil × domaine. Le connecteur DNS reste en mode « requête à la demande », avec les identifiants de l'appelant, et ne rend que ce que la route d'origine accorde. Seuls des agrégats sans appareil (volume, taux de blocage) peuvent être indexés. **Arbitrage propriétaire** (question 3). |
| A13 | Actions de défense depuis le menu contextuel | Décision de sécurité auditée dans `/var/log/secubox/audit.log` ; privilèges par `ctl` confiné (`MODULE-COMPLIANCE.md:202`) ; Aurora § 8 : confirmation intégrée, jamais `confirm()` | DataScope **n'exécute rien**. Une action de défense est un renvoi vers le module propriétaire, avec les identifiants de l'appelant : `POST /approve` de SADE (`packages/secubox-soc/api/defense.py:977`) ou `POST /ban` du WAF (`RELEVE.md`, § 2). L'audit est écrit par l'exécutant. Pas de sudoers, pas de `ctl` pour DataScope. Cohérent avec le spec (« défense = validation humaine »). |
| A14 | MapLibre (perspective Map) | CSP : `connect-src 'self'`, `img-src 'self' data:` : aucune tuile distante | Reporté (V0.4). Le SOC a déjà une carte SVG à fond de continents (`packages/secubox-soc/tests/test_carte_fond.py:10-11`) et les pays viennent d'actord (`/overview`, `top_pays`). Réutiliser avant d'ajouter une troisième bibliothèque et un jeu de tuiles local. |
| A15 | Tabulator / AG Grid (perspective Dataset) | Aurora § 3 : tableaux écrits à la main, tri, filtre et recherche côté client | Reporté (V0.4), tableaux Aurora d'abord. Aucune de ces bibliothèques n'est dans le dépôt. |
| A16 | Tâches répétitives et continues, coût, historique | Budget CPU de gk2 (C) ; `PERF-CACHE.md` | Reporté à V1.0. En V0.1 la seule « tâche » est le collecteur minuté. Pas d'ordonnanceur maison : minuteries systemd. |
| A17 | Manifeste `secubox.yaml` | Conforme : `debian/secubox.yaml` existe (`packages/secubox-soc/debian/secubox.yaml`, produit par `scripts/generate-secubox-yaml.py`) | Livrer aussi : `menu.d/<ordre>-datascope.json` (`MODULE-COMPLIANCE.md:138-152`, exemple `packages/secubox-status/menu.d/705-status.json`), et le manifeste de cycle de vie `/etc/secubox/modules.d/datascope.toml` (`MODULE-COMPLIANCE.md:101-105`). `capabilities.d` ne concerne pas DataScope : ce sont les actions `postMessage` du Hall (`packages/secubox-radio/capabilities.d/`). |
| A18 | « Panneau de SBXOS Hall » | Le Hall est la porte **publique**, l'administration reste interne (`packages/secubox-sbxos/nginx/sbxos.conf:7-11`) ; la topologie relève de `require_jwt` | Page servie par le vhost d'administration (`/datascope/`). Au plus une entrée de menu ou une carlette qui y renvoie. **Arbitrage propriétaire** (question 1). |
| A19 | Plafonds `MemoryMax` / `CPUQuota` | Conforme, déjà pratiqué (`MemoryMax=128M` sur Status, `256M` sur la veille : `packages/secubox-ai/systemd/secubox-ai-veille.service:29`) | Garder, valeurs en C. |
| A20 | Secrets | `/etc/secubox/secrets/`, jamais dans un TOML versionné | DataScope V0.1 n'a aucun secret. Les clés d'API d'OSINT iront dans `/etc/secubox/secrets/osint/`, remises par `LoadCredential`. |

Conformité courante à ne pas oublier : version `0.1.0-1~trixie1`, `debian/compat` 13, `Standards-Version: 4.6.2`,
`Architecture: all`, en-têtes SPDX CMSD-1.0 (`scripts/license-headers.py` ignore déjà `vendor` et `*.min.js`,
lignes 85 et 90), `postinst` `systemctl enable --now`, `prerm` `systemctl stop`, README du paquet, routes
`GET /health` et `GET /status` (`MODULE-COMPLIANCE.md:158-163`), dates UTC RFC 3339 (`RULES-CODE.md` § 8),
aucune E/S bloquante dans un `async def` (§ 6).

## B. Carte de réutilisation

### B.1 Où vivent déjà les données de chaque connecteur

| Connecteur | Paquet | Comment la donnée est lue aujourd'hui | API de lecture ? | Mode conseillé |
|---|---|---|---|---|
| **network** (appareils) | `packages/secubox-nac` | Collecteur de fond toutes les 30 s (`api/collector.py:41`, `:61`) → SQLite `devices`, `device_history`, `device_groups` (`api/store.py:72-90` : mac, ip, hostname, interface, type, zone, risque, première et dernière vue, provenance). A absorbé device-intel et iot-guard (`api/main.py:871-876`). Service à socket dédiée (`aggregator/main.py:250`). | Oui : `GET /clients`, `/client/{mac}`, `/history`, `/zones` (`api/main.py:863`, `:944`, `:1298`, `:996`), `require_jwt`. | Index : lecture `mode=ro` de `/var/lib/secubox/nac/devices.db`. Précédent : ad-guard le fait (`packages/secubox-ad-guard/api/dnstv_appareils.py:12`, `:39`). Détail à la demande par la socket. |
| **network** (interfaces, débits) | `packages/secubox-hub` | Collecteur → `/var/lib/secubox/hub/netstats.json` et `netstats.db` (`api/netstats.py:16-17`). | Oui : `GET /netstats/summary`, `/netstats/series` (`api/main.py:1293`, `:1300`), `require_jwt`. | Lecture du fichier d'instantané. |
| **network** (maillage) | `packages/secubox-p2p`, `secubox-soc` | État en mémoire du service p2p ; `wg_mesh.json` (`packages/secubox-soc/api/sade_auto.py:50`). | Oui : `GET /masterlink/topology` (`packages/secubox-p2p/api/main.py:3722`), `GET /mesh/peers`, `/mesh/tree` du SOC (`packages/secubox-soc/api/main.py:664`, `:726`), `require_lecture`. | À la demande. |
| **status / system** | `packages/secubox-status` | Minuterie 60 s qui **ne lit que des caches** : `/var/cache/secubox/health/status.json`, `modules.json`, relevé de profil, `/proc`, `/sys` ; historique SQLite 90 j (`README.md`, § « Ce que fait le paquet »). | Oui : `GET /status`, `/summary`, `/history` (`api/main.py:52-64`, `require_lecture`), `/admin/snapshot`, `/admin/sources` (`:80-85`, `require_jwt`). | Index par les fichiers de cache de santé ; historique à la demande. |
| **system** (unités, LXC) | `packages/secubox-system`, `secubox-metrics` | Commandes à la demande : `lxc-info`, `lxc-ls`, `systemctl` (`packages/secubox-metrics/api/main.py:426`, `:488`), signalées comme lourdes (`:133`, `:652-665`). | Oui : `GET /services`, `/network` (`packages/secubox-system/api/main.py:539`, `:545`), `/api/v1/metrics/overview` (`:658`). | **À la demande seulement**, jamais en boucle. Préférer `modules.json` de la santé. |
| **dns** | `packages/secubox-ad-guard` (TV Privacy, `dnstv`), `packages/secubox-dns` | Base `/var/lib/secubox/ad-guard/dnstv/dnstv.db` (`packages/secubox-nac/api/dnsevidence.py:23`) ; journal des décisions agrégé. | Oui : `GET /protection/evenements`, `/protection/journal` (`api/dnstv_lot3_routes.py:127`, `:346`), `/clients/vus`, `/serie`, `/live` (`api/dnstv_routes.py:294`, `:546`, `:534`), toutes **nominatives** ; zones : `packages/secubox-dns/api/main.py:323`. | À la demande, identifiants de l'appelant (A12). Pas d'index par appareil. |
| **dpi** | `packages/secubox-dpi` (sbxdpi, composant ndpid) | Collecteur Go → `/var/lib/secubox/dpi/cumulative.json`, `state.json` (`api/main.py:382-384`) ; flux vivant sur `/run/secubox/dpi-live.sock` (`:361`). | Oui : lectures agrégées `/pub/stats`, `/pub/usage`, `/pub/sessions`, `/pub/clients`, `/pub/countries` (`api/main.py:878-936`, `require_lecture`). Aurora § 6 demande de préférer `/pub/…`. | Agrégats seulement. **Ne jamais se brancher sur `dpi-live.sock`.** Le DPI n'est pas dans le profil `lite` (`packages/secubox-soc/debian/control`, commentaire #3218) : source optionnelle. |
| **waf** | `packages/secubox-waf-ng` | nft et journal de menaces, servis par l'API du WAF sur `/run/secubox/waf.sock`. | Oui : `GET /bans`, `/stats`, `/menaces/flux` à **curseur** `?depuis=<inode>:<octet>` (`composants/waf/api/main.py:1707`, `:1609`, `:1948`, `require_lecture_ai`), `/bans/history` (`:1799`, `require_lecture`). | Événements indexés par curseur, **après** création d'un compte de service (A11). |
| **acteurs** (Actor Intelligence) | `packages/secubox-toolbox-ng/cmd/sbx-actord` | Graphe en mémoire + registre de preuves (`internal/actor/graph`, `evidence`, `store`). Lecture sur `/run/secubox/actor.sock`, sans garde applicative. | Oui : `/actors`, `/actors/{id}`, `/campaigns`, `/overview`, `/radar`, `/proposals`, `/evidence/{id}`, `/actors/{id}/timeline`, **`/actors/{id}/graph`**, `/events` (`server.go:289-303`). | À la demande, par un lecteur du type `packages/secubox-soc/api/substrat.py:20`, `:55`. |
| **firewall** | `secubox-waf-ng` (bans), `secubox-netmodes`, `secubox-ipblock`, `secubox-metrics` | Pas de module unique : `nft` est appelé par plusieurs API (`packages/secubox-metrics/api/main.py`, `secubox-ipblock/api/main.py`, `secubox-netmodes/api/main.py`). | Partielle : les bans par le WAF ; pas de lecture unifiée des règles. | Hors V0.x. Les bans passent par le connecteur waf. Un connecteur « firewall » demanderait d'abord une API de lecture côté propriétaire. |
| **mirrornet** | `packages/secubox-mirrornet`, `secubox-annuaire`, `secubox-threatmesh` | Base propre à chaque service. | Oui : `GET /services`, `/datasets`, `/datasets/{id}/versions`, `/datasets/{id}/lignee` (`packages/secubox-mirrornet/api/main.py:243`, `:273`, `:298`, `:709`) ; annuaire `GET /log`, `/services`, `/subscriptions` (`packages/secubox-annuaire/api/main.py:238`, `:514`, `:590`) ; threatmesh `GET /peers`, `/decisions` (`packages/secubox-threatmesh/api/main.py:152`, `:157`). | À la demande. La perspective Dataset peut s'appuyer sur `/datasets` de MirrorNet plutôt que sur une table `datasets` propre. |
| **soc / SADE** | `packages/secubox-soc` | Façade en lecture au-dessus d'actord, du WAF et de threatmesh (`api/substrat.py:19-23`) ; état dans `/var/lib/secubox/soc/defense.db`. | Oui : `/defense/status`, `/threats`, `/threats/{id}`, `/actions`, `/mesh`, `/incidents`, `/proposals` (`api/defense.py:293-499`, `:1009`, `require_lecture`). | À la demande. Source des `available_actions` de défense. |
| **veille IA** | `packages/secubox-ai/veille` (gk3) | Second processus, seul écrivain de `veille.db` : tables `curseurs`, `evenements`, `campagnes`, `incidents`, `incident_preuves`, `dossiers`, `dossier_evenements`, `acteurs_adresses` (`migrations/0001-socle.sql:12-74`, `0003-dossiers.sql:11-42`) ; rétention 30 j par lots de 1000 (`veille/retention.py:12-15`). Lit gk2 par le compte `ai-lecture`. | Oui : `/menaces/releve`, `/menaces/chaine`, `/menaces/series`, `/menaces/pays` (`api/menaces.py:568`, `api/radar.py:343-357`). | Référence. Tourne sur gk3, pas sur gk2 : à relier par le maillage, pas à dupliquer. |

### B.2 Fonctions de graphe et de relation déjà présentes (à ne pas refaire)

| Existant | Où | Ce que DataScope en fait |
|---|---|---|
| Graphe d'un acteur (adresses, ASN, pays, cibles, pairs de campagne, événements) | `packages/secubox-toolbox-ng/cmd/sbx-actord/analyse.go:139-162` (`analysis.ConstruireGraphe`) | Le connecteur traduit cette réponse en entités et relations canoniques, `evidence_type=reported`, provenance `actord`. Aucune corrélation recalculée. |
| Campagnes (acteurs visant le même jeu de cibles) | `cmd/sbx-actord/api.go:284` ; page `packages/secubox-waf-ng/www/actor/index.html:506` | `CORRELATED_WITH` marqué « rapporté par actord », jamais « inféré par DataScope ». |
| Registre de preuves et événements | `GET /evidence/{id}`, `/events` (`server.go:298`, `:303`) | « Clic arête = preuve et provenance » : renvoi vers la preuve d'actord. |
| Chaîne d'attaque, dossiers d'attaquant | `packages/secubox-ai/api/radar.py:158-245` ; page `packages/secubox-ai/www/ai/index.html:186-187` | L'entité `investigation` du spec recouvre le « dossier » de la veille : référencer, ne pas créer un second objet. |
| Graphe de forces d3 (sites et traqueurs par client) | `packages/secubox-toolbox/www/toolbox/social.js:253-259` | Précédent technique de bibliothèque vendorée ; pas la même donnée. |
| Étoile du maillage, arbre du maillage | `packages/secubox-p2p/www/p2p/index.html:154` ; `GET /mesh/tree` du SOC | Perspective Network côté maillage : même source. |
| Courbes réseau | `packages/secubox-soc/www/soc/reseau.html` (lit `/api/v1/hub/netstats/*`) | Aurora § 9 : une seule source, on **encadre** la page, on ne la copie pas. |
| Regroupement « un appareil = un seul item, nom déduit » | `packages/secubox-ad-guard/api/dnstv_appareils.py` (inventaire du NAC + repli) | La clé de l'entité `device` suit cette règle : une entité par appareil, toutes ses adresses en entités `ip` reliées. |

Conséquence pour le modèle : la table `events` de DataScope ne doit pas devenir une troisième copie des
événements de sécurité (actord et la veille les tiennent déjà). Elle n'indexe que ce qu'aucun module n'historise
de façon exploitable : changements d'état des entités (apparition, disparition, changement d'adresse ou de zone,
passage d'un module de `operational` à `degraded`).

## C. Budget de performance sur gk2

Contexte : MOCHAbin, 4 cœurs, 8 Go, pression CPU de 74 % avant le correctif #3850, environ 35 % après. La racine
est à 91 %. L'agrégateur porte une centaine de modules sur une seule boucle.

### C.1 Ce que DataScope ne doit pas faire

- Se brancher sur un flux : `dpi-live.sock`, journal d'Unbound, flux de `sbxdpi`. Aucune copie de flux DPI.
- Lancer des commandes en boucle : `lxc-info`, `lxc-ls`, `systemctl`, `nft list`, `ip neigh`. Le NAC et la
  santé le font déjà ; on relit leur résultat.
- Interroger les API des modules toutes les quelques secondes. Chaque appel à un module monté dans
  l'agrégateur occupe la boucle commune.
- Être monté dans l'agrégateur, ou tourner deux fois (incident NAC #3178).
- Calculer une disposition de graphe côté serveur, ou servir un graphe non borné.
- Ouvrir un sondage par spectateur pour le SSE.
- Proposer des tâches « continues » en V0.x.
- Écrire sans garde d'espace disque, ou garder un daemon résident quand une minuterie suffit.

### C.2 Stratégie d'ingestion recommandée

| Sujet | Recommandation |
|---|---|
| Forme | Deux unités, comme Status : API (`secubox-datascope.service`, socket) et collecteur **oneshot minuté** (`secubox-datascope-collect.timer`). L'API ne collecte jamais ; elle relit base et cache. |
| Cadence | 60 s pour network et status. Le NAC rafraîchit à 30 s, Status à 60 s : aller plus vite ne montre rien de plus. `RandomizedDelaySec` pour ne pas tomber sur la même seconde que `secubox-status-collect`. |
| Mode | Lecture de fichiers et de bases en `mode=ro` avec délai court (2 s, comme `dnsevidence.py:34`). Source illisible ou verrouillée : état « temporairement inaccessible », l'index précédent reste. |
| Différentiel | Comparer `last_seen` (ou l'empreinte de l'instantané) au curseur de la source ; n'écrire que les changements. Table `curseurs` sur le modèle de la veille (`migrations/0001-socle.sql:12`), `INSERT OR IGNORE` pour l'idempotence (`veille/collecte.py:26`). |
| Événements (V0.3) | Par curseur, jamais par relecture : le WAF offre déjà `?depuis=<inode>:<octet>&max=`. Lots bornés par passe. |
| Plafonds d'index | Départ : 5 000 entités, 20 000 relations, 30 j d'observations, base ≤ 200 Mo, purge par lots de 1000. Au plafond : refus d'insertion signalé dans `/sources`, jamais une purge silencieuse des plus récents. |
| Plafonds de réponse | `/graph` et `/neighbors` : 500 nœuds et 1 500 arêtes par défaut, champ `tronque` explicite, expansion par voisinage (double-clic) plutôt que graphe entier. `/entities` paginé. |
| Disque | Garde avant écriture, sur le modèle `veille/service.py:19-20` (seuil d'octets libres) ; au-dessous, la passe s'abstient et le dit. Emplacement de la base sur gk2 : question 6. |
| Limites systemd | API : `MemoryMax=128M`. Collecteur : `Nice=10`, `MemoryMax=128M` (valeurs de `secubox-status-collect.service:23-24`), plus `CPUQuota=25%` et `IOSchedulingClass=idle`. |
| Cycle de vie | `lifecycle = "on-demand"` pour l'API si le pilote de scale-to-zero s'y prête (`MODULE-COMPLIANCE.md:101-118`) : un cockpit n'a pas à tourner quand personne ne le regarde. Le collecteur reste minuté. |
| Navigateur | Actualisation 15 à 60 s et seulement si l'onglet est visible (Aurora § 6). Disposition calculée dans le navigateur. |

### C.3 Où le patron « tâche de fond + cache fichier » est obligatoire

`PERF-CACHE.md` : toujours pour un tableau de bord de statistiques, toujours quand la route lit des journaux ou
calcule des agrégats, jamais pour une action temps réel.

| Route | Traitement |
|---|---|
| `/overview`, `/sources` | Cache `/var/cache/secubox/datascope/overview.json` écrit par le collecteur. |
| `/graph` (vue par défaut, sans filtre) | Cache fichier ; une vue filtrée interroge la base indexée (requête courte). |
| `/timeline`, statistiques de `/datasets` (V0.3-V0.4) | Agrégats par tranche précalculés par le collecteur. |
| `/entities/{id}/context` | Pas de cache fichier : lecture indexée + appels à la demande, bornés par un délai (3 s, comme `substrat.lire`) et un petit cache en mémoire de quelques secondes. Sections manquantes annoncées. |
| Actions | Jamais mises en cache. |

Double tampon (#3011, note de mémoire) : une passe dégradée n'écrase jamais le dernier relevé complet ; le cache
porte `genere_le` et la page affiche l'état « données périmées » d'Aurora § 5 au-delà d'un seuil.

Mesure d'acceptation au banc puis sur gk2 : durée CPU d'une passe du collecteur, mémoire résidente des deux
unités, et pression CPU (`/proc/pressure/cpu`, `avg60`) relevée 30 min avec puis sans le paquet. Seuils à fixer
avec le propriétaire ; proposition : passe < 2 s de CPU, écart de pression non mesurable.

## D. Périmètre V0.1 recommandé

### D.1 Les deux connecteurs

1. **network**, par le magasin du NAC (`devices.db` en `mode=ro`) et l'instantané `netstats.json` du hub.
2. **status**, par les caches de santé que Status Live lit déjà, et son API pour l'historique.

Écart avec le spec, qui nomme « Network et System » : le connecteur *system* direct supposerait `lxc-info` et
`systemctl` en boucle, ou une dépendance au service root `secubox-system`. Status donne modules, services et
ressources sans une seule commande. Les deux se lisent par fichiers : pas de compte de service en V0.1 (A11).
À vérifier au banc : que `secubox-datascope` (groupe `secubox`) peut lire `/var/lib/secubox/nac/devices.db` et
`/var/lib/secubox/hub/netstats.json` sous son profil AppArmor ; sinon, ajouter une lecture dédiée côté NAC.

### D.2 Sous-ensemble du modèle

| Élément | V0.1 | Plus tard |
|---|---|---|
| Entités | `node` (la box), `network` (zone), `interface`, `device`, `ip`, `service` (module) | `domain`, `flow`, `container`, `process`, `event`, `dataset`, `task`, `investigation`, `location` |
| Relations | `BELONGS_TO` (appareil → zone, ip → appareil), `CONNECTS_TO` (appareil → interface), `HOSTED_ON` (service → box), `OBSERVED_BY` (entité → source) | `RESOLVES_TO`, `DEPENDS_ON`, `ROUTES_THROUGH`, `CORRELATED_WITH`, `REPEATS`, `LOCATED_AT`, `DERIVED_FROM`, `GENERATED_BY` |
| Champs de relation | tous ceux du spec dès V0.1 : provenance, date, `evidence_type`, confiance, justification | — |
| `evidence_type` | `observed` (vu par le collecteur du module) et `reported` (affirmé par un module) | `inferred`, `imported`, `manual` |
| Tables | `entities`, `relationships`, `observations`, `curseurs`, `schema_migrations` | `events` (V0.3), `saved_views`, `tasks`, `task_runs` (V1.0) |

Identifiants stables et lisibles : `device:<mac>`, `ip:<adresse>`, `service:<module>`, `network:<zone>`.
L'enveloppe `context` est complète dès V0.1 (clés du spec), une section non fournie étant `null` avec son motif,
jamais une liste vide qui se lirait comme « rien à signaler ».

API V0.1, toutes en `GET` : `/health`, `/status`, `/overview`, `/sources`, `/entities`, `/entities/{id}`,
`/entities/{id}/context`, `/entities/{id}/neighbors`, `/graph`. Aucune route mutante.

### D.3 Page : Network Cockpit en Aurora

Un fichier `packages/secubox-datascope/www/datascope/index.html`, autonome, modèle
`packages/secubox-waf-ng/composants/waf/www/waf/vue.html`.

| Zone | Largeur ≥ 1100 px | < 900 px ou `?embed=1` |
|---|---|---|
| `.tete` | marque, pastille d'état des sources, heure, Rafraîchir | idem |
| Gauche | Sources par catégorie, activables, état de chacune (`.pan`) | tiroir repliable |
| Centre | Topologie **SVG à disposition déterministe** : box → interfaces → zones → appareils (Aurora § 1 l'autorise) | pleine largeur, défilement dans son conteneur |
| Droite | Inspecteur : propriétés, relations avec preuve et provenance, actions applicables | tiroir repliable |
| Bas | Frise : **absente** en V0.1 (pas de panneau vide ni de série inventée, Aurora § 5) | — |

- Grille par container queries sur `.cadre`, jamais `min-height:100vh` ; hauteur postée par `sbxVue` + `onglet`.
- Sélection : un seul objet d'état dans la page (`{id, type, source}`), que toutes les zones lisent. C'est la
  pièce à réussir en V0.1 : le moteur de graphe de V0.2 s'y branchera sans la changer.
- Clic = sélection et inspecteur ; clic sur une arête = preuve et provenance. Double-clic et menu contextuel : V0.2.
- `?demo=1` avec bandeau orange, adresses RFC 5737 ; sans session : bandeau « session requise » et « — ».
- Lecture seule. Les seules « actions » de V0.1 sont des liens vers la page du module propriétaire.
- Menu latéral `/shared/sidebar.js` hors `?embed=1` ; entrée `menu.d`.

### D.4 Vendorisation du moteur de graphe (V0.2, sous réserve de l'exception A4)

| Bibliothèque | Licence | Version à geler | Rôle |
|---|---|---|---|
| Graphology | MIT | branche 0.26 | modèle canonique côté navigateur, toujours chargé |
| Cytoscape.js | MIT | branche 3.x | moteur jusqu'au seuil bas (≤ 2 000 nœuds) |
| Sigma.js | MIT | branche 3.x | moteur au-delà du seuil haut (> 5 000), WebGL |

Les numéros exacts sont à relever au moment du gel : cette analyse n'a consulté aucun service extérieur.
À vérifier alors : que chaque paquet publie bien un fichier unique utilisable sans empaqueteur (c'est le cas
connu de Cytoscape et de Graphology ; à confirmer pour Sigma 3), et si une disposition pour Sigma est
nécessaire (`graphology-layout-forceatlas2`, MIT), ce qui ferait une quatrième bibliothèque.

Règles de vendorisation proposées, sur le précédent d3 du Toolbox :

- Fichiers sous `www/datascope/vendor/`, nom portant la version (`cytoscape-3.x.y.min.js`), jamais modifiés.
- `vendor/VERSIONS.json` : nom, version, URL d'origine, SHA-256, licence ; texte de chaque licence MIT à côté ;
  entrées dans `debian/copyright`. Un test pytest recalcule les empreintes.
- Chargement par `<script src="/datascope/vendor/…">` de même origine, **à la demande** : Graphology avec la
  perspective Graph, puis un seul moteur. Jamais les deux moteurs sur le même graphe (règle du spec), et Sigma
  n'est téléchargé que si le seuil est franchi.
- Bascule : le modèle Graphology et l'objet de sélection survivent ; le moteur est détruit puis recréé.
  Entre 2 000 et 5 000 nœuds, le moteur courant est conservé (hystérésis), la densité d'arêtes tranche.
- Le test statique Aurora est adapté pour cette page : `<script src=` admis seulement vers `/datascope/vendor/`.
- Repli : WebGL indisponible ou bibliothèque absente → la topologie SVG de V0.1 reste la vue servie.

### D.5 Tests d'acceptation V0.1

1. **Paquet** : construction `0.1.0-1~trixie1`, lintian sans erreur, `sh -n` sur les scripts `debian/*`.
2. **Socket** : `/run/secubox/datascope.sock` en `0660`, groupe `secubox` ; `ss -tlnp` ne montre aucun port
   nouveau ; `systemctl show … -p RuntimeDirectory --value` vide.
3. **Confinement** : `aa-status` montre le profil en `enforce` ; processus sous `secubox-datascope` ; aucun refus
   AppArmor dans le journal après une passe complète.
4. **Gardes** : `tests/test_conformite_jwt.py` passe ; sans jeton, 401 sur `/entities`, `/graph`, `/context` ;
   un jeton non administrateur est refusé sur les routes `require_jwt` ; `/health` répond 200.
5. **Route** : `dpkg -S /etc/nginx/secubox-routes.d/datascope.conf` nomme le paquet ; erreurs en JSON ;
   vérification par le chemin public du vhost d'administration, pas par la socket (note de mémoire).
6. **Connecteur network** : sur une base NAC de test, autant d'entités `device` que de lignes ; un appareil à
   deux adresses = une entité et deux `ip` ; base absente ou verrouillée → source « temporairement
   inaccessible », index conservé, API toujours 200.
7. **Connecteur status** : cache périmé → état `unknown`, jamais `operational` ni panne.
8. **Idempotence** : deux passes sans changement n'écrivent aucune ligne ; rétention et plafonds testés.
9. **Provenance** : toute relation a provenance, date, `evidence_type`, confiance et justification ; aucune
   relation `inferred` en V0.1 (test qui échoue si une apparaît).
10. **Vie privée** : aucun nom de domaine dans la base après une passe (test sur le contenu).
11. **Page** : test statique Aurora § 11 (SPDX, `sbxVue`, `demo`, aucun script externe, aucun `confirm(`,
    aucun `POST`) ; captures Playwright 1400×900 et 420 px lues ; cas sans session sans erreur JS.
12. **Sélection** : choisir un appareil dans la topologie met à jour l'inspecteur et survit à un rafraîchissement.
13. **Performance** : mesures de C.3 au banc (maître de test gk6), puis gk2 sur accord.
14. **Déploiement** : par `apt` depuis `apt.secubox.in`, sans redémarrage de l'agrégateur.

## E. OSINT et DataScope

### E.1 Un paquet ou deux

**Deux paquets**, `secubox-datascope` puis `secubox-osint`, OSINT se présentant à DataScope comme un connecteur
parmi les autres (même contrat `health / entities / relationships / events / context`).

| Critère | DataScope | OSINT |
|---|---|---|
| Réseau | aucun : `AF_UNIX` seul, `IPAddressDeny=any` | sortant vers des tiers (DNS, RDAP, CT, flux CTI) |
| Secrets | aucun | clés d'API dans `/etc/secubox/secrets/osint/` |
| Données | références et relations locales | données de tiers, avec `redistribution_allowed` et `retention_policy` |
| Risque | lecture locale | fuite de ce que la box cherche, quotas, licences, cadre légal |
| Profil AppArmor | sans réseau | réseau sortant borné |

Les fusionner donnerait au cockpit un accès Internet et des secrets dont il n'a pas besoin. Les mêmes
substitutions qu'en A s'appliquent à OSINT (socket au lieu du port 8780, pas de venv, pas de SQLAlchemy).

### E.2 Recouvrements à traiter avant d'écrire OSINT

- **Veille de `secubox-ai`** : enrichissement pays et ASN, dossiers d'attaquant, campagnes, corrélation
  déterministe (`packages/secubox-ai/veille/correlation.py`, `dossiers.py`, `pays.py`). Le « graphe
  d'investigation » d'OSINT doit s'articuler avec les dossiers, pas en créer un second.
- **threatmesh** : flux et décisions partagés (`packages/secubox-threatmesh/api/main.py:157`, `:169`).
- **MirrorNet** : les jeux de données versionnés portent déjà licence, provenance, classe et drapeau de données
  personnelles (`packages/secubox-mirrornet/api/main.py:798`). C'est le véhicule naturel des IOC signés.
- **SADE** : toute proposition de blocage issue d'OSINT entre par la file de propositions existante, avec
  validation humaine. Le spec exclut déjà le blocage automatique sur réputation externe.
- XML et flux externes (STIX/TAXII, GraphML) : `defusedxml` obligatoire (`RULES-CODE.md` § 5), TLS vérifié (§ 4).

### E.3 Séquencement proposé

1. DataScope V0.1 (fondation, network + status) puis V0.2 (moteur de graphe, connecteur acteurs à la demande).
2. Compte de service de lecture dans `secubox-core`, puis connecteur waf par curseur (DataScope V0.3).
3. `secubox-osint` cœur : DNS et RDAP, sans Maltego, branché à DataScope par le contrat.
4. Flux CTI, puis propositions vers SADE et partage par MirrorNet.
5. Pont Maltego en dernier, limité à l'import-export de fichiers tant que la licence du SDK n'est pas levée.

La direction d'OSINT (hybride, natif, intégration profonde) n'a pas à être tranchée pour lancer DataScope :
les étapes 1 et 2 sont les mêmes dans les trois cas.

### E.4 Questions que seul le propriétaire peut trancher

1. **Où DataScope tourne et où il s'affiche.** Sur gk2, où sont les données mais où le CPU est compté ? Ou sur
   le maître, en vue distante (vision « remote controller »), chaque box ne portant que son collecteur ? Et
   confirmez-vous qu'il reste sur le vhost d'administration, le Hall n'offrant qu'un lien ?
2. **Exception Aurora pour le moteur de graphe.** Acceptez-vous des bibliothèques vendorées en canvas et WebGL
   pour la seule perspective Graph, et que V0.1 sorte sans elles (topologie SVG), le moteur hybride arrivant
   en V0.2 ?
3. **DNS par appareil.** L'index transversal peut-il contenir des couples appareil × domaine ? Proposition :
   non, lecture à la demande seulement, avec les droits de l'appelant.
4. **Connecteurs de V0.1.** Network + Status (lecture de caches, aucun compte de service) plutôt que
   Network + System : d'accord ? Et accord de principe pour un compte de service de lecture en V0.3 ?
5. **Rétention et emplacement.** 30 jours et 200 Mo au plus conviennent-ils, et la base va-t-elle sur le SSD
   `/data` de gk2 plutôt que sur la racine ?
6. **OSINT.** Paquet séparé, cœur natif d'abord, Maltego réduit à l'import-export : est-ce la direction, ou
   voulez-vous l'intégration profonde dès le départ ?


---

## Annexe — specs du propriétaire (résumé fidèle)

# Specs fournies par le propriétaire (21/11/2026) — résumé fidèle des points décidés

## A. SBXOS DataScope (configuration VALIDÉE par le propriétaire)

- Produit : « SBXOS DataScope », panneau transversal d'observation et d'exploration de SBXOS Hall. Ne remplace ni les
  modules SecuBox ni leurs bases : il les rend lisibles ensemble. Règle : « une seule sélection, plusieurs perspectives ».
- Interface validée : **Network Cockpit** (vues simultanées) : sources à gauche (Network, OSINT, DPI, DNS, WAF, MirrorNet,
  activables par catégorie), graphe/topologie au centre, inspecteur à droite (propriétés, relations, historique, actions),
  flux d'événements et timeline (1h/24h/7d/perso) en bas. Mobile : panneaux en tiroirs, graphe tactile.
- Six perspectives : Network (topologie), Graph (relations), Stream (temps réel), History (historique, répétitions,
  changements), Dataset (tables, statistiques), Map (géographie).
- Interactions : clic = sélection + inspecteur ; double-clic = développer voisins ; clic arête = relation + preuve et
  provenance ; clic droit / appui long = menu contextuel dynamique (seulement les actions applicables) ; changement de
  perspective ou de moteur conserve la sélection.
- Moteur de graphe validé : **hybride Cytoscape.js + Sigma.js**, modèle canonique Graphology ; jamais les deux moteurs
  sur le même graphe ; bascule transparente (sélection, filtres, position logique). Seuils de départ : ≤ 2000 nœuds
  Cytoscape, > 5000 Sigma (densité d'arêtes compte plus que le nombre de nœuds).
- Modèle canonique : entités (network, device, interface, ip, domain, service, container, process, flow, event,
  dataset, task, investigation, location), relations (CONNECTS_TO, RESOLVES_TO, HOSTED_ON, DEPENDS_ON, BELONGS_TO,
  OBSERVED_BY, GENERATED_BY, CORRELATED_WITH, LOCATED_AT, DERIVED_FROM, REPEATS, ROUTES_THROUGH). Chaque relation :
  provenance, date, `evidence_type` (observed, reported, inferred, imported, manual), confiance 0-1 + justification ;
  une relation inférée est marquée comme telle ; une corrélation statistique ne déclenche jamais une règle de sécurité.
- Chaque module reste propriétaire de ses données ; DataScope stocke un index commun, des références, des relations
  normalisées, des observations. Connecteurs par module (network, dns, dpi, waf, firewall, osint, mirrornet, system,
  status) : contrat health / entities / relationships / events / datasets / context ; deux modes : requête à la demande
  et événements indexés ; source indisponible = « temporairement inaccessible », l'historique indexé reste.
- Stockage proposé : SQLite WAL `/var/lib/secubox/datascope/datascope.db` (tables entities, relationships, observations,
  events, datasets, tasks, task_runs, saved_views). Rétention configurable (30 j proposé).
- API proposée `/api/v1/datascope` : overview, sources, entities, entities/{id}, entities/{id}/context (enveloppe
  normalisée : entity, summary, relationships, recent_events, history, available_actions, source_provenance),
  neighbors, graph, events, timeline, datasets, tasks (+ run, runs), maps, stream (SSE avec reprise par identifiant),
  ws/events optionnel.
- Tâches : unique, répétitive (planifiée), continue (temps réel) ; historique d'exécution, coût, erreurs.
- Actions classées : lecture/analyse immédiates ; organisation selon droits ; automatisation avec confirmation ;
  défense = validation humaine obligatoire.
- Le spec propose : service séparé de l'agrégateur, paquet `secubox-datascope`, API + worker systemd, frontend
  TypeScript/Vite, MapLibre, Tabulator/AG Grid, port TCP 127.0.0.1:8790, venv dans /opt, nginx proxy, manifeste
  secubox.yaml, plafonds MemoryMax/CPUQuota. Plates-formes : MOCHAbin ARM64 8 Go (profil Lite), RPi 5, N100, x86.
- Jalons proposés : V0.1 fondation (paquet, API, SQLite, shell cockpit, registre de sources, inspecteur, connecteurs
  Network et System) ; V0.2 graphe (Graphology, adaptateurs Cytoscape/Sigma, bascule, expansion, menu) ; V0.3 flux et
  historique ; V0.4 datasets et carte ; V1.0 tâches, vues sauvegardées, suggestions, corrélation OSINT/DPI.
  Ordre recommandé : contrat de données et sélection d'abord, cartes et IA en dernier. IA locale : explications et
  résumés seulement, calculs et relations déterministes et vérifiables.

## B. SecuBox OSINT Hybrid (proposé, direction stratégique NON tranchée par le propriétaire)

- Service `secubox-osint` : enrichissement d'IP, domaine, URL, certificat (DNS, RDAP, Certificate Transparency,
  réputation, flux CTI STIX/TAXII autorisés), graphe d'investigation, corrélation avec la télémétrie SecuBox (DNS, WAF,
  firewall, DPI), import/export Maltego (GraphML, CSV ; transforms via SDK `maltego-transforms` sous réserve de licence),
  IOC validés proposés au DNS/WAF/pare-feu, partage d'IOC signés sur MirrorNet.
- Hors périmètre : surveillance de personnes, données privées sans base légale, copie des bases Maltego, blocage
  automatique sur réputation externe, scan actif de tiers sans autorisation.
- Données : champs `redistribution_allowed` et `retention_policy` obligatoires par source ; score de confiance distinct
  du score de dangerosité. SQLite `/var/lib/secubox/osint/osint.db`. STIX 2.1 comme format d'échange, pas de stockage.
- Proposé : FastAPI port 8780 TCP, venv /opt, SQLAlchemy, API + worker. Jalons V1.0 cœur + DNS/RDAP, V1.1 pont
  Maltego, V1.2 graphe/CTI, V1.3 défense et maillage.
- Choix ouvert présenté par l'auteur : hybride / 100 % natif / intégration profonde (recommandée par l'auteur).
