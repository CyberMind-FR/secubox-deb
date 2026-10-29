<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Pilotage distant — Livraison L5 « Box légère, interface headless care-safe » : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal :** une box légère (ESPRESSObin 1 Go, RPi400 en minimal strict) ne garde que ses API et ses services ; ses
pages d'administration sont servies par le maître sous `admin.<box>.secubox.in`, et leurs appels `/api/v1/…`
atteignent la box par le canal du pilotage, sous les règles care-safe (lecture seule sous mains liées, écriture sur
une box cliente seulement pendant un support accepté, tout audité). Mesure avant et après sur gk5 et gk4.

**Architecture :** sur le maître, nginx sert les fichiers `www/` **de la version installée sur la box** (extraits
des `.deb` du dépôt apt hébergé par le maître) et envoie `/api/v1/` au contrôleur, qui transmet la requête à
l'agent par le canal (message `HTTP`). Sur la box, l'agent remet la requête à un **relais local**
`sbx-pilotage-relais` (Go, utilisateur `secubox`, socket Unix réservée à l'agent) qui frappe un jeton délégué de
60 s signé avec le secret JWT de la box, puis appelle la socket du module. L'agent, exposé au réseau, ne détient
jamais ce secret. `secubox_core.auth` reconnaît ce porteur délégué, borné et tracé.

**Tech Stack :** Go 1.22 stdlib (relais, agent), Python 3 / FastAPI (`secubox_core.auth`, contrôleur), nginx,
haproxyctl + route WAF déclarative, SQLite, systemd, AppArmor.

**Spec :** `docs/superpowers/specs/2026-10-28-pilotage-distant-design.md` (décisions 4, 10, 12, 13, 14 ; D5 ;
E1, E4 ; choix « page d'état statique locale » ; L5). **Prérequis :** L1 et L2 livrés ; profils minimal et lite
allégés (#3218) ; groupes avec veille (`secubox-groupd --veille`, #3191).

## Global Constraints

- Celles des plans L1 et L2.
- Pages : servies sur le maître par la chaîne normale **HAProxy TLS 1.3 → sbxwaf → nginx**, vhost
  `admin.<box>.secubox.in` déclaré par `haproxyctl` et `secubox-waf-route` ; jamais de contournement du WAF.
- Versions : une page ne parle qu'à l'API de **sa** version. Les `www/` servis pour une box sont ceux de la
  version de chaque paquet que la box déclare (`Device.X_SECUBOX_Packages`) ; servir ceux du maître à une API plus
  ancienne est exclu (spec, D5).
- Jeton délégué : HS256, signé avec le `jwt_secret` de la box, **durée ≤ 60 s**, `aud` = nom de la box,
  `sub` = `pilotage:<admin>@<maître>`, réclamation `pilotage = {"acteur", "maitre", "portee": "lecture"|"admin"}` ;
  frappé **uniquement** par `sbx-pilotage-relais` ; reconnu par `secubox_core.auth` **seulement** quand la requête
  arrive par la socket du relais (en-tête `X-SecuBox-Pilotage-Relais` posé par le relais et effacé partout
  ailleurs par nginx et l'agrégateur, comme les en-têtes `X-SecuBox-*` aujourd'hui).
- Portée : mains liées → `lecture` (toute méthode autre que GET/HEAD refusée par le relais, 423) ; box cliente →
  `admin` seulement pendant un support accepté (L2), sinon `lecture` ; box du propriétaire → `admin`.
- Box légère : **aucun interpréteur Python résident ajouté** ; nginx limité à la page d'état locale `/etat`
  (statique, LAN) ; ni `secubox-portal`, ni haproxy, ni nginx d'administration ; budget mesuré par
  `scripts/bench/mesure-box.sh`, critère « utilisable » de la spec (RAM dispo ≥ 250 Mo, swap ≤ 50 %, CPU au repos
  ≤ 25 %, aucun service en boucle, démarrage ≤ 3 min).
- Relais de noms : `secubox-relais-maillage` lit les noms ET ports déclarés par l'agent (inventaire du contrôleur,
  `Device.X_SECUBOX_Exposure`) au lieu de `webos/public/noms` et `webos/public/ports` (E4).

## Review Focus

- Page servie dont la version ne correspond plus (box mise à niveau entre deux chargements) : la page reçoit 409
  « version changée, rechargez » au lieu d'appels incohérents. Test : `test_relais_refuse_une_version_perimee` (Task 5).
- Requête relayée volumineuse (envoi d'un fichier de configuration, téléchargement d'une sauvegarde) : bornée à
  8 Mio dans les deux sens, 413 au-delà, sans saturer la mémoire de l'agent. Test : `TestRelaisBorneLeCorps` (Task 2).
- Maître absent : la box continue de filtrer, la page `/etat` locale reste servie, aucune boucle de reconnexion
  agressive. Test : `test_etat_local_sans_maitre` (Task 7).
- En-tête `X-SecuBox-Pilotage-Relais` forgé par un client externe : effacé par nginx et l'agrégateur, jeton délégué
  refusé hors socket du relais. Test : `test_entete_relais_forge_refuse` (Task 1).
- Mains liées posées pendant qu'une page est ouverte : l'écriture suivante est refusée (423) avec un message lisible
  dans la page. Test : `TestRelaisMainsLieesEnCours` (Task 2).

---

### Task 1 : `secubox_core.auth` — porteur délégué du pilotage

**Files :** Modify `common/secubox_core/auth.py` (`_validate_token`, `porteur_reconnu`, `est_admin_reel`,
`_trace_delegation`) ; nginx commun et agrégateur (effacement de l'en-tête) ; Test
`common/tests/test_auth_pilotage_3126.py`.

**Interfaces :** `def jeton_pilotage_valide(payload: dict, request: Request) -> bool` — vrai seulement si
l'en-tête du relais est présent, `aud` = nom de la box, `exp - iat ≤ 60`, `sub` commence par `pilotage:` ;
`portee == "lecture"` → `require_lecture` passe, `require_jwt` refuse toute méthode d'écriture ; chaque usage est
tracé (`_trace_delegation`) avec l'acteur.

- [ ] Tests : `test_jeton_pilotage_accepte_par_la_socket_du_relais`, `test_entete_relais_forge_refuse`,
  `test_jeton_pilotage_trop_long_refuse`, `test_portee_lecture_refuse_l_ecriture`, `test_trace_avec_acteur`.
  FAIL → impl → suite `common` verte → relecture de sécurité (agent `relecteur-securite`) → commit.

### Task 2 : relais local `sbx-pilotage-relais`

**Files :** Create `packages/secubox-pilotage-agent/cmd/sbx-pilotage-relais/main.go`, `internal/relais/` (+ tests),
`systemd/secubox-pilotage-relais.service`, AppArmor.

**Interfaces :**
- Socket `/run/secubox/pilotage-relais.sock` (0660, groupe `secubox-pilotage`) ; le relais vérifie
  `SO_PEERCRED` = uid de `secubox-pilotage`, sinon ferme.
- Entrée : `{"methode", "chemin", "entetes", "corps_b64", "acteur", "maitre", "portee", "version_page"}` ;
  `chemin` doit être `/api/v1/<module>/…` avec un module dont la socket `/run/secubox/<module>.sock` existe ;
  en-têtes retenus : `Content-Type`, `Accept`, `If-*` seulement.
- Sortie : `{"statut", "entetes", "corps_b64"}` ; corps ≤ **8 Mio** dans les deux sens (413) ; délai **30 s**.
- Lit le `jwt_secret` de la box (seul lecteur avec les modules) ; frappe le jeton délégué (Global Constraints).

- [ ] Tests : `TestRelaisFrappeUnJetonCourt`, `TestRelaisRefuseUnAutreUid`, `TestRelaisRefuseUnModuleInconnu`,
  `TestRelaisBorneLeCorps`, `TestRelaisMainsLieesEnCours` (portée lecture → 423 sur POST). FAIL → impl → PASS → commit.

### Task 3 : message `HTTP` dans le canal

**Files :** agent `internal/canal/client.go` (type `HTTP`) ; contrôleur `pilotage/files.py`, `api/canal.py` ; tests.

**Interfaces :** requête canal `{"msg_id", "type": "HTTP", "body": <entrée du relais>}` → réponse
`{"msg_id", "type": "HTTP_RESP", "body": <sortie du relais>}` ; la portée est **recalculée par l'agent** (mains
liées, support accepté) : celle envoyée par le maître ne peut que réduire, jamais élargir.

- [ ] Tests : `TestAgentReduitLaPortee`, `test_canal_transporte_une_requete_http`. FAIL → impl → PASS → commit.

### Task 4 : `www/` de la version de la box, extraits sur le maître

**Files :** Create `packages/secubox-pilotage/sbin/secubox-pilotage-www` (root, ctl borné) + tests.

**Interfaces :** `secubox-pilotage-www extraire <paquet> <version>` → `.deb` lu dans le dépôt apt local
(`/srv/apt/pool/…`, vérifié par sa somme dans `Packages`), seuls les fichiers sous le chemin `www/` du paquet copiés
vers `/var/lib/secubox/pilotage/www/<paquet>/<version>/` (lecture seule pour nginx) ; idempotent ; purge des
versions qu'aucune box ne déclare plus depuis 7 jours.

- [ ] Tests : extraction limitée à `www/`, refus d'un `.deb` dont la somme ne correspond pas, chemins `..` refusés,
  purge. FAIL → impl → PASS → commit.

### Task 5 : vhost `admin.<box>` sur le maître

**Files :** contrôleur `pilotage/vhosts.py` + gabarit nginx, appels `haproxyctl` et `secubox-waf-route` par un ctl
root ; tests.

**Interfaces :** pour chaque box légère (réglage `interface = "distante"` dans l'inventaire, posé par le profil
léger), un `server` nginx `admin.<box>.secubox.in` : `/` → arborescence composée des `www/` des versions de la box,
`/api/v1/auth/` → **auth du maître** (l'administrateur se connecte avec ses identifiants du maître), `/api/v1/` →
`/run/secubox/pilotage.sock` route `/relais/{box}/…` qui exige `require_jwt` du maître puis transmet par le canal ;
en-tête `X-SecuBox-Version-Page` posé par nginx et comparé par le contrôleur (409 si la box a changé de version).
Le nom public est déclaré par `haproxyctl` (certificat, vhost) et sa route WAF par `secubox-waf-route`, comme
`secubox-relais-maillage relayer`.

- [ ] Tests : `test_vhost_par_box_legere`, `test_auth_du_maitre_sur_le_vhost`, `test_relais_refuse_une_version_perimee`,
  `test_pas_de_bypass_waf` (la route passe par sbxwaf). FAIL → impl → PASS → commit.

### Task 6 : relais de noms et de ports sans webos (E4)

**Files :** Modify `packages/secubox-p2p/sbin/secubox-relais-maillage` (`cmd_synchroniser`) ; tests.

**Interfaces :** pour un pair connu du contrôleur, les noms et ports viennent de
`GET /api/v1/pilotage/boxes/{nom}` (`Device.X_SECUBOX_Exposure.Names|Ports`) lu sur la socket locale du
contrôleur ; repli sur `webos/public/noms|ports` si le pilotage est absent. Mêmes contrôles qu'aujourd'hui (DNS,
domaine du pair, exclusions).

- [ ] Tests : box minimal sans webos → noms relayés ; pilotage absent → ancien chemin. FAIL → impl → PASS → commit.

### Task 7 : profil léger et page d'état locale

**Files :** `packages/secubox-profiles/profiles/minimal.toml` (variante « distante », coordonnée avec #3218) ;
agent `internal/etat/` qui écrit `/run/secubox/pilotage/etat.html` (statique : nom, maître joignable ou non,
mains liées, mémoire, services en échec) toutes les 60 s ; gabarit nginx `etat` (LAN seulement, une page) ; tests.

**Interfaces :** profil léger = minimal sans nginx d'administration, `secubox-portal`, haproxy ; modules Python
regroupés dans un seul `secubox-group@` avec `--veille` ; agrégateur en relais pur ; agent + relais actifs.

- [ ] Tests : `test_profil_leger_sans_front_web`, `test_etat_local_sans_maitre`, `TestEtatSansSecret`.
  FAIL → impl → PASS → commit.

### Task 8 : banc gk5 et gk4

- [ ] Mesure avant (`mesure-box.sh --duree 300 --etiquette avant-l5`) sur gk5 et gk4.
- [ ] Passage au profil léger (`secubox-profilectl apply --profile minimal --yes`, instantané R1 pour retour).
- [ ] `https://admin.gk5.secubox.in/` et `https://admin.gk4.secubox.in/` servis par gk2 : connexion avec les
  identifiants du maître, pages Système, NAC, ad-guard, Freebox fonctionnelles ; écriture refusée (423) après
  `secubox-pilotage mains-liees on` en local.
- [ ] Mesure après : critère « utilisable » tenu sur les deux box (sinon, rapport des écarts et ce qu'il faut encore
  retirer) ; ports d'écoute de la box : seulement `/etat` sur le LAN.
- [ ] Publication, HISTORY.md, WIP.md, PR vers master.
