<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Pilotage distant des box par le maître : installation, préparation, administration, interface (#3126, #3203, #3218, #3233)

Un seul système, quatre volets : **télé-installation** (le maître flashe une box), **préparation automatique**
(le maître lui donne identité, profil et modules), **télé-administration** TR-369/USP (le maître la supervise et agit
sur elle pendant toute sa vie), **interface distante** (une box légère garde ses API, le maître sert ses pages).

Ce document prend la suite du projet 3 annoncé dans `2026-10-24-maillage-association-automatique-design.md` (plan de
gestion TR-369/USP) et l'élargit à l'installation et à la préparation, à la demande du propriétaire.

Convention : ce que le propriétaire a dit est donné comme tel ; **« supposition »** marque ce qu'il n'a pas dit ;
**« choix de Claude »** marque une décision prise ici pour lui, à confirmer à la relecture.

## Intention

Préparer une box aujourd'hui, c'est empiler cinq mécanismes nés séparément :
- `secubox-firstboot` (`image/firstboot.sh`) ;
- `secubox-premier-pas` (`profil.toml`, assistant, panneau maître « Boxes à préparer ») ;
- Auto-Load (`secubox-autoload` sur l'infrastructure, `secubox-autoload-agent` sur la box, jetons `gk2_`) ;
- le lot de flash de `sbx-netflash --nom` (code de jonction et ancre déposés après l'écriture) ;
- `automesh` (`secubox-automesh.timer`, `automesh.code`).

S'y ajoutent les gestes à la main : console série, `usersctl`, `sbx-mesh-join` collé à la console, `hostnamectl`.

Le banc du 2026-10-28 sur l'ESPRESSObin v7 (devenue gk5) a montré le prix de cet empilement. Il a fallu trois heures
de console série pour obtenir ce qu'un maître aurait dû faire seul :
- mot de passe admin inconnu ;
- renommage cassé ;
- jonction au maillage sous le mauvais nom ;
- nDPIsrvd redémarré 391 fois en 31 min sans que personne ne le voie ;
- relevé de performance collé à la main.

Le propriétaire veut :
- **un pilotage standard depuis le maître** (« TR-069 … à mettre en place et remplacer au maximum nos essais de
  firstboot, preparebox, autoload, et autres first prepare customizer ») ;
- avec la liberté de **repartir de zéro si c'est plus propre, et supprimer les travaux équivalents** ;
- **mais un assistant de personnalisation reste** (« il nous faut tout de même un wizard de custom personnalisation »).

Résultat attendu, dans ses mots : « tu publies une image sur le serveur, tu déclenches le flashage depuis SBXOS, et la
box se configure toute seule jusqu'à son retour en ligne ».

## Décisions du propriétaire

1. **TR-069/TR-369 est la voie** (2026-10-28) pour remplacer firstboot, premier-pas, Auto-Load et les préparations à la
   main. Repartir de zéro est permis ; ce qui fait double emploi disparaît ensuite.
2. **Un assistant de personnalisation reste** (2026-10-28). Il a deux visages, comme dans la vision Auto-Load du
   2026-10-11, qui fait foi :
   - le maître compose la proposition ;
   - la personne devant la box la voit, la personnalise et la valide ;
   - un **délai de repli automatique** applique sans réponse, au démarrage ET avant l'application finale ;
   - pré-rapport, délai de grâce et refus possible, comme Auto-Load aujourd'hui.
3. **`sbx-netflash --auto` piloté par le maître** (2026-10-28, texte du propriétaire) :
   - détection automatique de la carte et de son eMMC ;
   - téléchargement de l'image officielle par HTTP ;
   - vérification préalable de la signature, du SHA-256, de la taille et de la capacité ;
   - écriture en flux sans charger l'image en RAM, à tampons bornés pour 1 Go ;
   - vérification après écriture, synchronisation, contrôle des partitions ;
   - redémarrage automatique ;
   - confirmation du premier démarrage remontée au maître ;
   - le tout journalisé de bout en bout, sans intervention à la console série.

   « Autonome, mais pas aveugle » :
   - une erreur de téléchargement ne déclenche jamais d'effacement ;
   - une écriture incomplète n'est jamais annoncée réussie ;
   - A/B avec retour arrière là où la carte le permet ;
   - une stratégie de récupération distincte pour l'ESPRESSObin sans A/B.
4. **Box légère, client lourd** (2026-10-28, #3218) : « client léger sur gk5, client lourd sur gk2 », « relay remote
   headless », « si ça peut permettre l'usage des ESPRESSObin 1 Go ». La box légère garde ses API et ses services ;
   les pages sont servies par le maître, qui appelle les API par le maillage. Idée d'origine (2026-10-28) : « un
   remoteui kiosk like pour éviter de surcharger un device avec des modules d'interfaces et les rendre remoteui par
   API et mesh ».
5. **La télé-administration doit couvrir ce que le banc a fait à la main** (2026-10-28, commentaire de #3126) :
   relever performances et services, détecter une boucle de redémarrage, suivre une mise à niveau, sans SSH.
6. **nDPId sort du profil `minimal`** (2026-10-28, #3218) : « ndpid prend tout le CPU et devait être retiré de minimal ».
   `secubox-dpi` dépend de `secubox-ndpid-engine` et sort avec lui.
7. **Mot de passe par défaut** : celui du maître, `secubox`, est permis (#3203, décision du propriétaire). Note CSPN
   portée dans #3203 : prévoir au moins l'invitation à le changer.
8. **Fuite de secrets dans les images (#3243)** : le propriétaire a choisi une issue publique complète et un outil
   livré d'abord (`secubox-renouvelle-secrets`), puis la rotation sur gk5, gk1, gk3, gk4 (faite le 2026-10-28).
9. **Périmètre de la télé-administration** (2026-10-28) : « le tr69 pour la préparation et l'administration et le
   support et les actions temps réel remote ». Le **support** (session d'assistance) et les **actions en temps réel**
   font partie du canal, au même titre que l'administration.
10. **Priorité** (2026-10-28) : « puis et surtout les interfaces remote headless care safe », puis « next sur
    l'interface headless et le remote tr ». L'interface distante headless et la télé-administration passent **avant**
    la télé-installation et la préparation. « Care-safe » est lu ici (supposition, question Q0) comme : sûre par
    défaut pour la box et pour qui l'administre — lecture seule par défaut, confirmation explicite des actions qui
    coupent ou effacent, consentement de la box pour une session de support, tout audité, et la box continue de
    protéger si le maître ou le canal tombe.

## Constats du banc gk5 (2026-10-28), devenus exigences

Mesure de référence sur gk5 (ESPRESSObin v7, 951 Mo, minimal alpha.19 + `apt upgrade`, nDPIsrvd en boucle) :

| Mesure | Valeur |
|---|---|
| Services en marche | 44 (25 SecuBox) |
| Interpréteurs Python | 23, **962 Mo** de mémoire propre (PSS + swap) sur 1 208 Mo pour l'ensemble des services |
| RAM disponible | 270 Mo |
| Swap | 865 Mo utilisés sur 950 |
| CPU | 50 % occupé, dont `/sbin/init` à 10 % (relances de nDPIsrvd) |
| API qui répondent | 21, latence médiane 7 ms |
| Premier octet du front web | 69 ms |
| Démarrage | userspace 7 min 52 s, dont `secubox-firstboot` 2 min 10 s |

Front web dans ces relevés : `secubox-portal` 46 Mo, `haproxy` 41 Mo (deux processus, présent malgré #2849 : à
expliquer), nginx sous le seuil des 20 plus lourds.

Exigences tirées du banc :
- **E1.** La box légère ne porte pas d'interpréteur Python résident de plus. L'agent est en C ou en Go. Le levier
  mémoire principal est le nombre d'interpréteurs (#3218 : un seul `secubox-group@` avec `--veille`, agrégateur relais
  pur), pas le front web (environ 90 Mo).
- **E2.** Une boucle de redémarrage remonte seule au maître. nDPIsrvd y était depuis le premier démarrage (#3240).
- **E3.** Le renommage passe par un seul chemin, qui marche. Celui de la page Système échoue en silence (#3242), et la
  jonction garde le nom du moment (gk5 est entrée en `secubox-espressobin-v7`).
- **E4.** Les noms publics d'une box relayée ne dépendent pas de webos. `secubox-relais-maillage synchroniser` lit
  `/api/v1/webos/public/noms` sur le pair. Le minimal est en `Conflicts: secubox-webos`, donc aucun nom de gk5 n'a été
  relayé automatiquement ; `admin.gk5.secubox.in` a été posé par `secubox-relais-maillage relayer`.
- **E5.** Aucun secret n'est fabriqué à la construction de l'image (#3243). Les secrets observés dans l'image publique :
  - clés d'hôte SSH ;
  - `oidc/signing.pem` ;
  - `tls/key.pem` ;
  - `p2p/wg-ephemeral.key` ;
  - `p2p/pair.token` ;
  - `machine-id` ;
  - un admin au nom du runner de CI.

  Leur génération appartient au premier démarrage piloté, sur la box.
- **E6.** Le SSH de la box reste fermé côté LAN, et on n'y ajoute jamais de clé (règle des ESPRESSObin). La
  télé-administration est le chemin d'accès normal ; la console série reste le secours.
- **E7.** Un téléchargement HTTP long doit survivre aux vidages de l'eMMC (banc #3233 : coupure à 51 %, `send_timeout`
  porté à 900 s, écriture directe).

## Objectifs

- **O1.** Depuis le maître, l'opérateur choisit une box (vue en DHCP ou déjà connue), une image et une proposition de
  préparation, puis clique. La box est flashée, redémarre, se prépare et apparaît « prête » dans la Flotte, sans console
  série. (Décision 3.)
- **O2.** Chaque étape est visible sur le maître et journalisée des deux côtés : téléchargement en %, écriture,
  vérification, redémarrage, premier contact, préparation, prête. (Décision 3.)
- **O3.** Une box préparée est supervisée en continu par le maître :
  - mémoire, CPU, processus ;
  - services en échec ou en boucle ;
  - versions ;
  - alertes poussées.

  (Décision 5.)
- **O4.** Depuis le maître, sur une box : redémarrer, mettre à jour, arrêter ou démarrer un service, prendre un relevé
  de performance, renommer. Chaque action est gardée (`require_jwt`) et journalisée. (Décision 5.)
- **O5.** Sur une box légère, l'administration se fait par les pages servies par le maître, sans serveur web ni
  interpréteur d'interface sur la box. (Décision 4.)
- **O6.** Une ESPRESSObin de 1 Go est utilisable en production avec le profil léger, mesurée avant et après par le même
  outil que le banc. (Décision 4, #3218.)
- **O7.** À la fin, `secubox-firstboot`, le mode silencieux de premier-pas, Auto-Load (service et agent), le lot de
  flash et `automesh` ont disparu ou ne sont plus que des enveloppes du nouveau chemin. (Décision 1.)

## Non-objectifs

- Sauvegarde, restauration et clonage par composant : vision Auto-Load, plus tard.
- Liens et partages entre pairs : projet 2 (#3133), inchangé.
- Mise à jour du chargeur de démarrage (U-Boot usine, overlay Tow-Boot) : doctrine de `secubox-netboot/CLAUDE.md`,
  hors de ce document.
- Gestion de box tierces ou d'un ACS d'opérateur : la compatibilité CWMP est une question ouverte, pas un objectif.
- Box sans aucun lien réseau avec un maître : elles gardent l'assistant local.

## Anti-objectifs (échec même si ça « marche »)

- Un appareil inconnu est flashé, préparé ou enrôlé sans clic du propriétaire sur le maître (doctrine du 2026-10-24
  maintenue).
- L'agent écoute sur le WAN ou sur le LAN. Il ne parle qu'en sortant, par le tunnel du maillage.
- Une page ou une API de box passe par le maître en contournant le WAF : chaîne HAProxy TLS 1.3 → `sbxwaf` → nginx,
  jamais de bypass hors `waf_bypass` déclaratif.
- Un secret transite en clair dans une URL, un journal, `images.txt`, le squashfs du live ou l'image publiée :
  - mot de passe, ou son empreinte hors du lot signé ;
  - jeton d'enrôlement ;
  - code de jonction ;
  - clé.
- Un téléchargement raté efface une box, ou une écriture incomplète est annoncée réussie (décision 3).
- La box légère gagne un interpréteur Python résident ou un conteneur Docker (LXC seulement, AGENTS.md).
- On garde deux chemins de préparation vivants qui divergent. Chaque livraison retire ce qu'elle remplace.

## Ce qui existe (relevé dans le code le 2026-10-28)

**Installation**
- `packages/secubox-netboot/installer/sbx-netflash` (live) :
  - lit `images.txt` ;
  - refuse une image plus grande que l'eMMC ;
  - écrit en flux par `image/sbin/secubox-flash-emmc` (`ecrit_flux_verifie` : signature et SHA-256 du flux
    compressé calculés pendant l'écriture, tête de 2 Mio écrite en dernier, cible invalidée sur échec ou signal) ;
  - avec `--nom`, demande au maître un lot signé (`GET /lot-flash?nom=`, `api/main.py`) et dépose le code de jonction,
    l'ancre et `profil.toml` sur l'eMMC.
- `installer/sbx-autoflash` et `sbx-autoflash.service` (clé USB finale, `scripts/build-cle-finale.sh`) : annonce la
  cible, puis un compte à rebours qu'une touche à la console annule (confirmation de l'opérateur).
- API netboot :
  - `GET /boards`, `GET /live`, `GET /vues` (baux DHCP par OUI) ;
  - `GET /flashs` (suivi d'un flash par `ss` et le journal d'accès) ;
  - `POST /flash/prepare` (24 h, `require_jwt`) ;
  - `GET /lot-flash`.
- Cartes : `packages/secubox-netboot/board/{mochabin,espressobin-v7}/live.env`, lus comme des données
  (`scripts/live-env.sh`).
- Live léger ESPRESSObin : `scripts/build-live-leger.sh`.
- Anti-brique documenté pour l'overlay MOCHAbin (`README.md` du paquet) : `bootcount` et `altbootcmd`.
- Le U-Boot d'usine de l'ESPRESSObin (2021.10) n'a ni `wget` ni vérification de signature. Le netboot y passe par TFTP
  (noyau, DTB, initrd), puis le squashfs est récupéré en HTTP. Le chargement du live se tape aujourd'hui à la console
  (« aucun bootcmd automatique ne le charge », en-tête de `sbx-autoflash`).

**Préparation**
- `secubox-premier-pas` :
  - `premier_pas/moteur.py` : `plan()` = nom (`_renomme` + `hostnamectl` + Avahi), horloge, admin (empreinte argon2),
    réseau, services (`secubox-profilectl apply`), maillage, mises à jour ;
  - `premier-pasctl appliquer|silencieux|appliquer-demande` ;
  - panneau maître `premier_pas/maitre.py` et `www/premier-pas-maitre/`.
- `image/firstboot.sh` : secret JWT, admin par défaut (`/boot/admin_password` ou `secubox`), `users.json`,
  `secubox.conf`.
- Auto-Load : `packages/secubox-autoload` (enrôlement, tunnel WireGuard sortant, pré-rapport, refus) et
  `packages/secubox-autoload-agent`.
- Maillage :
  - `secubox-p2p` : `sbin/secubox-automesh`, `scripts/sbx-mesh-join`, `scripts/sbx-mesh-invite --code --nom` ;
  - ancre `/etc/secubox/p2p/ancre-maitre.json` ;
  - renommage au retour d'un pair (#3213, audit `pair_renomme`).
- Relais : `secubox-relais-maillage relayer|synchroniser` (TLS et WAF sur le maître, HTTP vers `<ip-maillée>:9080`).

**Supervision et action à distance**
- Rien de TR-069 ou TR-369 dans le dépôt : ni agent, ni contrôleur (vérifié le 2026-10-28).
- Points d'appui :
  - `secubox-assist` : démon WebSocket lié à l'adresse du maillage, catalogue borné d'actions → argv de ctl, audit,
    sessions sous consentement ;
  - page Flotte (`packages/secubox-annuaire/www/fleet/`) ;
  - annuaire (port 8799 sur l'adresse maillée) ;
  - `secubox-majauto` (mises à jour automatiques).
- Agrégateur : `ESSENTIELS = ("auth","hub","sbxid","portal","users")` ; `secubox-groupd` accepte `--veille` et
  `--veille-modules`.
- Outils de banc : `scripts/bench/memory-baseline.sh` et `README.md` (cibles ESPRESSObin 1 Go, MOCHAbin 8 Go). Le
  relevé `mesure-box.sh` du 2026-10-28 est hors dépôt pour l'instant (suivi #3233).

## Conception

### D0. Architecture : un contrôleur sur le maître, un agent sur chaque box

- **Agent** : un binaire unique sur la box, en C ou en Go (E1, #3126).
  - Il ouvre la connexion vers le contrôleur et la garde, en sortant, **par le tunnel du maillage** (`wg-mesh`).
  - Il n'écoute rien.
  - Il expose le modèle de données (D4) et exécute les actions par des ctl root bornés (patron sudoers à argv exact, ou
    unité `.path`). Il ne tourne jamais en root lui-même pour servir le réseau.
- **Contrôleur** : sur le maître.
  - API FastAPI sur socket Unix `/run/secubox/<module>.sock`, routes `GET|POST /api/v1/<module>/…`, `require_jwt`.
  - Pages dans la charte Aurora.
  - Chaque action journalisée dans `/var/log/secubox/audit.log`.
  - Il reprend la page Flotte comme vue d'ensemble (choix de Claude).
- **Protocole** : TR-369/USP (décision 1 et #3126). Messages `Get`, `Set`, `Operate`, `Notify`, `GetSupportedDM`.
  - Transport : le tunnel du maillage chiffre déjà sur le fil. Le choix du MTP USP (WebSocket ou MQTT, en local au
    maillage) est laissé au bâtisseur.
  - Contrainte : l'agent n'ouvre aucun port.
- **Un seul canal pour les quatre volets** : la confirmation de flash, la préparation, la supervision et les appels de
  l'interface distante passent par la même relation agent ↔ contrôleur (choix de Claude). Pas un tuyau par fonction.

### D1. Identité et confiance

- **Le maître** : l'ancre existante (`ancre-maitre.json`, clé publique WireGuard du maître, signée par la clé netboot au
  flash) reste la racine de confiance de la box. L'agent refuse un contrôleur qui n'est pas joignable par le pair maître
  ancré.
- **La box** : son identité est générée **sur elle, au premier démarrage** (E5) :
  - clé de l'agent ;
  - clé WireGuard du maillage ;
  - clés d'hôte SSH ;
  - TLS ;
  - OIDC ;
  - `machine-id`.

  L'image n'en porte aucune. L'outil `secubox-renouvelle-secrets` (#3243) est la brique qui les crée au premier
  démarrage et les renouvelle sur une box existante.
- **Enrôlement** : jeton à usage unique lié au nom prévu, déposé par le flash piloté (comme le lot signé d'aujourd'hui),
  ou bien remis après un clic sur le maître pour une box non flashée par lui (D5 du document du 2026-10-24 : code
  affiché par la box). Aucun appareil n'entre sans ce clic.

### D2. Télé-installation : `sbx-netflash --auto`

Le déroulé ci-dessous est la décision 3 ; le reste est marqué.

1. **Déclenchement sur le maître.** L'opérateur choisit la box (bail DHCP vu par `/vues`, ou box déjà enrôlée), l'image
   (catalogue de `/live`) et une proposition de préparation (D3). Le maître crée un **ordre de flash** :
   - lié à l'adresse MAC, à l'image (empreinte), au nom prévu et à une durée de validité ;
   - à usage unique ;
   - signé par la clé netboot (comme le lot et les images) ;
   - journalisé.

   Ce clic **est** la confirmation de l'opérateur exigée par la doctrine netboot (choix de Claude : la confirmation
   quitte la console pour le maître ; voir question Q2).
2. **Mise en netboot de la box.**
   - Box déjà enrôlée : l'agent reçoit `Operate` « réinstaller », écrit dans l'environnement U-Boot un démarrage
     réseau à usage unique (`fw_setenv`, avec repli sur l'eMMC), puis redémarre.
   - Box neuve : un démarrage réseau doit déjà être dans son environnement U-Boot. Supposition : une préparation
     d'usine ou une première fois à la console (question Q5).
3. **Le live** (léger sur ESPRESSObin) détecte la carte (modèle du device-tree, `board/<carte>/live.env`) et son eMMC
   (taille réelle), puis demande au maître **son** ordre de flash par sa MAC.
   - Pas d'ordre valide, signature fausse ou ordre expiré : le live ne fait rien de destructif et le dit.
   - Il reste alors dans le mode interactif d'aujourd'hui.
4. **Vérifications avant écriture** :
   - signature de l'ordre ;
   - présence et signature de l'image ;
   - taille décompressée inférieure à la capacité de l'eMMC (déjà fait) ;
   - empreinte attendue égale à celle de l'ordre.
5. **Écriture en flux** par `secubox-flash-emmc` (existant) :
   - tampons bornés ;
   - écriture directe ;
   - signature et SHA-256 vérifiés pendant l'écriture ;
   - tête écrite en dernier ;
   - progression remontée au maître (au minimum ce que `/flashs` lit déjà).
6. **Vérification après écriture** : relecture de la zone écrite et comparaison avec l'empreinte de l'image
   **décompressée**. Supposition : `images.txt` gagne cette empreinte ; aujourd'hui seule celle du flux compressé est
   publiée. Puis `sync`, puis contrôle des partitions (table GPT, étiquettes `boot`, `rootfs`, `data`).
7. **Dépôt** de l'enrôlement (jeton, ancre) et de la proposition sur la racine écrite, puis redémarrage. Même mécanique
   que le lot de flash d'aujourd'hui, avec le contenu de D1 et D3.
8. **Confirmation** : au premier contact de l'agent, le contrôleur marque l'ordre « installé ». Sans contact dans le
   délai, l'ordre passe « à vérifier », jamais « réussi ».

**« Une erreur de téléchargement ne déclenche jamais d'effacement »** sur une carte sans A/B : voir la question Q3.
Le flux d'aujourd'hui écrit au fil du téléchargement. Une coupure au milieu laisse donc l'ancien système écrasé en
partie : l'eMMC est invalidée, jamais annoncée réussie, et la box reste récupérable par le netboot. C'est conforme à
« jamais annoncée réussie », pas à « jamais d'effacement ». Les options sont dans Q3.

**A/B** : là où l'eMMC le permet (MOCHAbin 8 Go, supposition), écriture sur la racine inactive, bascule, puis retour
arrière automatique si le premier démarrage ne confirme pas (`bootcount` / `altbootcmd`, déjà documentés pour
l'overlay). Sur l'ESPRESSObin de 4 Go, l'image minimal (3 Go) ne laisse pas de place pour deux racines (constat
#3238) : la récupération est le netboot depuis le maître (question Q3).

### D3. Préparation automatique et assistant à deux visages

- **Composition sur le maître** (premier visage) : le maître compose une **proposition** :
  - nom, domaine, fuseau ;
  - profil de services (`minimal`, `lite`, `isp`, `full`, variante légère) et modules ;
  - mot de passe admin, transmis seulement sous forme d'empreinte argon2 ;
  - maillage, mises à jour, gabarit (« une association reçoit un modèle, un FAI local reçoit des applications »,
    vision Auto-Load).

  Les gabarits forment la « matrice » de distribution de cette vision.
- **Sur la box** (second visage) : la personne devant la box voit la proposition, la personnalise dans les limites
  fixées par le maître, puis valide. **Sans réponse, le délai de repli applique la proposition** (décision 2).
  - Box à écran : kiosque.
  - Box sans tête : page web servie par le maître pour cette box (D5), annoncée en mDNS (vision Auto-Load).
  - Ce que la personne peut changer elle-même n'est **pas encore dit** : question Q1.
- **Application** : l'agent exécute la proposition validée, localement, par les ctl root, et remonte chaque étape au
  maître. Le moteur d'actions de premier-pas (`moteur.plan()`) est le point de départ naturel (choix de Claude). Il
  tourne une fois, en ponctuel, et ne laisse aucun interpréteur résident (E1).
- **Renommage unique** : nom d'hôte, `/etc/hosts`, `secubox.conf`, Avahi, puis nom côté maître dans les trois
  registres du maillage. Une seule fonction, utilisée par la préparation, l'action « renommer » (D4) et la page
  Système (#3242).

### D4. Télé-administration TR-369/USP

Modèle de données : TR-181 `Device:2`, plus une extension SecuBox. Le minimum vient du commentaire de #3126 du
2026-10-28 ; les noms exacts sont à vérifier contre la version du modèle retenue.

| Objet | Contenu |
|---|---|
| `Device.DeviceInfo` | fabricant, modèle, numéro de série, version logicielle, `UpTime` |
| `Device.DeviceInfo.MemoryStatus` | `Total`, `Free` (et disponible, swap : extension) |
| `Device.DeviceInfo.ProcessStatus` | `CPUUsage`, `Process.{i}` |
| Extension SecuBox | unités systemd (état, nombre de relances, en échec), paquets SecuBox et versions, profil actif, noms publics exposés (E4), état du maillage |
| `Device.DeviceInfo.FirmwareImage.{i}` | image installée, et slots A/B là où ils existent (supposition) |

Actions (`Operate`), toutes derrière `require_jwt` sur le contrôleur et journalisées des deux côtés :
- `Reboot()` ;
- mise à niveau des paquets (équivalent de `Download()` / `ScheduleDownload()`) ;
- arrêt, démarrage et redémarrage d'un service ;
- relevé de performance (l'équivalent de `mesure-box.sh`, rendu au maître) ;
- renommer (D3) ;
- réinstaller (D2) ;
- renouveler les secrets (#3243).

Notifications (`Notify` : `ValueChange`, `Event`) :
- service en boucle (seuil de relances, E2) ;
- mémoire disponible sous un seuil ;
- swap saturé ;
- fin d'une mise à niveau ;
- premier démarrage.

**Support et temps réel** (décision 9) :
- **Session de support** : ouverte depuis le maître, acceptée sur la box (consentement, durée bornée, révocable),
  journalisée des deux côtés. Elle donne accès aux actions du catalogue et à une vue en direct ; un shell, s'il est
  un jour offert, reste non root et sous double consentement (patron `secubox-assist`, console pty non câblée à ce
  jour).
- **Temps réel** : la page de la box sur le maître s'abonne aux `Notify` (état des services, mémoire, CPU, progression
  d'une mise à niveau ou d'un flash) au lieu d'interroger en boucle ; une action lancée affiche sa progression et son
  résultat en direct.

**Ce que ça remplace** : la console série et le SSH pour l'exploitation courante (E6). Le catalogue borné de
`secubox-assist` est un précédent direct (argv bornés, audit) : soit l'agent le reprend, soit `assist` devient un
client du contrôleur. Ce choix est laissé au bâtisseur, à condition de ne pas garder deux catalogues.

### D5. Interface distante pour une box légère

- La box légère garde ses API sur sockets Unix et ses services. Elle perd :
  - le front web : nginx d'administration, `secubox-portal`, `haproxy` ;
  - les paquets `www/`, ou bien elle les garde sans les servir (laissé au bâtisseur).
- Le maître sert les pages de la box sous `admin.<nom>.secubox.in`, par la chaîne normale : HAProxy TLS 1.3 →
  `sbxwaf` → nginx du maître.
  - Les appels `/api/v1/<module>/…` partent vers la box **par le canal agent ↔ contrôleur** (choix de Claude : un
    seul canal, D0).
  - On n'utilise pas un nginx de la box sur le port 9080, comme le fait le relais d'aujourd'hui.
- **Versions** : une page du maître doit parler à l'API de la version installée sur la box. Le bâtisseur choisit entre :
  - servir les `www/` de la version de la box (fournis par l'agent ou par le dépôt apt) ;
  - négocier une version d'API.

  Servir les pages de la version du maître à une API plus ancienne est exclu (choix de Claude).
- **Identité des appels** : un administrateur authentifié sur le maître agit sur la box. La box vérifie que l'appel
  vient de son contrôleur ancré et porte l'identité de l'administrateur, pour l'audit. Elle n'accepte pas un JWT
  d'un autre secret. Le mécanisme est laissé au bâtisseur.
- **Maître absent** (supposition, piste notée dans #3218) : la box garde une page d'état statique locale, ou la console
  série, et continue de filtrer. Rien de ce qui la protège ne dépend du maître.
- **Noms publics** (E4) : l'agent déclare les noms exposés ; le relais du maître ne lit plus `webos/public/noms`.

### D6. Journal d'audit

- Maître : ordre de flash créé, servi, consommé, expiré ; progression et résultat ; proposition émise ; validation ou
  repli ; enrôlement ; actions ; notifications reçues.
- Box : ordre vérifié ou refusé ; écriture, relecture, résultat ; premier démarrage ; secrets générés ou renouvelés
  (sans valeur) ; proposition appliquée étape par étape ; actions reçues et leur résultat.
- Jamais un mot de passe, un jeton, un code ou une clé (anti-objectifs).

## Contraintes (AGENTS.md et dépôt)

- Un module = un paquet `packages/secubox-<module>/`. FastAPI sur socket Unix pour le contrôleur, `require_jwt` partout.
- Utilisateur dédié, AppArmor `enforce`. Actions root par ctl confinés : l'API délègue, elle n'exécute pas.
- nftables `DEFAULT DROP`. L'agent n'ouvre aucun port ; le canal ne vit que sur `wg-mesh`.
- Tout le trafic public passe par HAProxy puis `sbxwaf` ; aucun contournement.
- Aucun secret dans le code, un TOML versionné, l'image ou une URL. Les secrets vont dans `/etc/secubox/secrets/`,
  générés sur la box.
- Configuration sensible en double tampon (ombre → validation → bascule atomique) et retour arrière 4R. La proposition
  appliquée par l'agent en relève.
- LXC seulement. Debian trixie, version `X.Y.Z-N~trixie1`, version montée à chaque changement déployé.
- Déploiement par paquet et `apt.secubox.in`, jamais d'édition à chaud. Le SSH des ESPRESSObin ne reçoit jamais de clé.
- Doctrine netboot (`packages/secubox-netboot/CLAUDE.md`) : intégrité par signature et non par transport, confirmation
  explicite de l'opérateur pour tout flash, audit append-only dans `/var/log/secubox/netboot/audit.log`, tout par carte
  (`board/<carte>/`).
- Budget de la box légère : aucun interpréteur Python résident ajouté. Mesure avant et après par le même outil.

## Livraisons proposées

Ordre fixé par la décision 10 : **L1 Voir → L2 Agir (administration, support, temps réel) → L5 Box légère
(interface headless care-safe) → L4 Préparer → L3 Installer**. Le tableau garde la numérotation d'origine.

Prérequis déjà ouverts, hors de ce document :
- #3243 (secrets de construction : outil, nettoyage de l'image, premier démarrage) ;
- #3240 (nDPIsrvd sans toolbox) ;
- #3242 (renommage de la page Système) ;
- sortie de nDPId et de DPI du méta-paquet `secubox-minimal` (décision 6).

| Livraison | Contenu | Ce qui disparaît |
|---|---|---|
| **L1. Voir** | Agent (lecture seule) et contrôleur. Inventaire D4, notifications, page Flotte enrichie. Relevé de performance à la demande. Banc : gk5. | Les relevés à la console ; `mesure-box.sh` hors dépôt. |
| **L2. Agir** | Actions D4 : redémarrer, mettre à niveau, services, renommer (fonction unique de D3), renouveler les secrets. | Le renommage de la page Système (il appelle la fonction unique). Un des deux catalogues (`assist` ou l'agent). |
| **L3. Installer** | `sbx-netflash --auto` (D2) : ordre signé, live sans console, relecture, confirmation au premier contact. | Le compte à rebours à la console de `sbx-autoflash` pour les flashs pilotés (le mode clé USB interactif reste comme secours). Les invites de `sbx-netflash` en mode piloté. |
| **L4. Préparer** | Proposition, assistant à deux visages, délai de repli (D3) ; enrôlement par le contrôleur (D1). | `image/firstboot.sh` (hors génération des secrets, reprise par #3243), le mode silencieux et `profil.toml` de premier-pas, Auto-Load (service d'enrôlement et `autoload-agent`), le code `automesh` et le lot de flash, le panneau « Boxes à préparer » (fondu dans le contrôleur). |
| **L5. Box légère** | Interface distante (D5), profil léger (un seul groupe Python avec veille, agrégateur relais pur, sans front web), noms déclarés par l'agent. Mesure sur gk5 avant et après. | Le front web sur les box légères ; la dépendance du relais à `webos/public/noms`. |

L1 vient d'abord parce qu'elle ne touche à rien, sert tout de suite le banc d'allègement et pose le canal dont les
quatre autres dépendent. L2 y ajoute le support et les actions en temps réel (décision 9). L5 suit, avant la
préparation et l'installation (décision 10).

## Décisions du propriétaire après la relecture (2026-10-28)

11. **Box clientes Auto-Load : dans le périmètre, tout de suite.** Dès L1, le canal agent ↔ contrôleur passe aussi par
    l'étoile `wg-autoload` (10.64.0.0/16) des box clientes, cloisonné par client (un client ne voit ni n'atteint
    jamais un autre client ni le maillage du propriétaire) ; l'identité d'une box cliente reste son adresse source dans
    le tunnel, comme Auto-Load aujourd'hui. Abonnements (actif, suspendu, révoqué), lots et séries préenregistrées sont
    repris par le contrôleur ; les box déjà enrôlées (au moins `lgm-ebin`, 10.64.0.9) migrent **sans reflash**, par
    mise à jour de paquets. D0 est corrigé en ce sens : `wg-mesh` pour les box du propriétaire, `wg-autoload` pour les
    box clientes, un seul agent.
12. **Consentement : le maître agit librement sur les box du propriétaire**, avec confirmation sur le maître pour ce
    qui coupe ou efface. L'accord de la box est exigé pour une session de support. Choix de Claude, à confirmer : sur
    une **box cliente**, toute action qui coupe, efface ou change la configuration exige aussi l'accord de la box (le
    détenteur), la lecture et les relevés restant libres dans le cadre de l'abonnement.
13. **TR-369 : forme USP, agent Go.** Get/Set/Operate/Notify et noms TR-181 sur un protocole léger maison ; agent Go
    mince (budget ≤ 20 Mo) ; un seul canal, qui porte aussi les appels de l'interface headless (D5). Pas de CWMP. Une
    passerelle vers l'USP standard reste possible plus tard, hors périmètre.
14. **Care-safe = la lecture de la décision 10, plus un mode « mains liées »** réglable SUR la box : tant qu'il est
    actif, le maître ne peut que voir (lecture, relevés, notifications), aucune action ni session de support ; seule
    la box (console locale ou page locale authentifiée) le lève, et chaque bascule est auditée des deux côtés.

## Corrections après la relecture « bâtisseur » (2026-10-28)

- `sbx-netflash --auto` **existe déjà** et veut dire « sans confirmation » (saute la saisie de « FLASH ») : le mode
  piloté de D2 s'appellera autrement (`--pilote`, choix de Claude), et cette dérogation existante à la doctrine de
  confirmation est à revoir en L3.
- L'effacement commence **avant** l'écriture : `ecrit_flux_verifie` remet à zéro la tête de l'eMMC et la GPT de secours
  avant le premier octet ; tout échec après le début du flux rend la box non amorçable. Le mode flux ne sert que si la
  RAM manque : sur MOCHAbin, l'image est téléchargée et vérifiée en tmpfs avant d'écrire. Q3 ne concerne que
  l'ESPRESSObin.
- Le contrôle de capacité n'a lieu que si `images.txt` porte sa 4ᵉ colonne et que l'eMMC est détectée.
- E4 : le relais lit aussi `/api/v1/webos/public/ports` (#3154) sur le port 9080 ; retirer nginx et le 9080 d'une box
  légère casse aussi le relais des ports. L'agent déclarera noms ET ports.
- Profils : `isp` est un méta-paquet (`secubox-isp`), pas un profil de `secubox-profilectl` (profils : `full`, `lite`,
  `media-lab`, `minimal`, `secure-gateway`).
- Auto-Load est plus large que décrit : multi-clients (abonnements actif/suspendu/révoqué, lots, séries
  préenregistrées, jetons 90 à 365 jours, inscription publique en HTTPS), étoile `wg-autoload` (10.64.0.0/16) où les
  clients ne se voient pas, et `secubox-autoload-agent` est une dépendance de `secubox-minimal`. Le maillage `wg-mesh`
  (10.10.0.0/24, liens entre pairs #3133) est celui des box du propriétaire. Voir Q-A.
- La phrase « aucun bootcmd automatique ne le charge » vise `autoflash.scr` de la clé USB ; le live netboot se charge
  lui aussi à la console (README du paquet).

## Choix de Claude après la relecture (à contester à la lecture)

- **Seuils « utilisable en production » (O6)**, sur 24 h d'une box légère en service : RAM disponible ≥ 250 Mo, swap
  ≤ 50 %, CPU au repos ≤ 25 %, aucun service en boucle, démarrage complet ≤ 3 min ; budget de l'agent ≤ 20 Mo de
  mémoire propre. Mesurés par le relevé de L1.
- **Q7** : invitation à changer le mot de passe par défaut au premier accès (pas d'obligation à chaque préparation).
- **Q8** : la box légère garde une page d'état statique locale quand le maître est absent.
- **Questions de L3 et L4 mises de côté** jusqu'à ces livraisons (l'ordre de la décision 10 les place après L5) :
  confiance du LAN pendant une installation pilotée et repli réseau permanent dans `bootcmd` ; « jamais d'effacement »
  sur ESPRESSObin (support externe, image assez petite pour deux racines, ou accepter l'eMMC invalidée) ; ce que
  promet « réinstaller » (image disque entier qui efface `/data` et l'identité, contre images de racine seule et A/B) ;
  réinstallation d'une box hors du LAN du maître ; preuve de présence devant une box sans écran pour le second visage
  de l'assistant.

## Questions ouvertes pour le propriétaire (ajout du 2026-10-28)

- **Q0.** « Care-safe » : la lecture de la décision 10 (lecture seule par défaut, confirmation explicite des actions
  qui coupent ou effacent, consentement de la box pour le support, audit, box autonome si le maître tombe) est-elle
  la bonne, ou manque-t-il quelque chose (par exemple un mode « mains liées » où le maître ne peut rien changer) ?

## Laissé au bâtisseur

- Agent : `obuspa` (implémentation de référence BBF, en C) ou agent maison en Go parlant USP. Contrainte :
  binaire unique, sans interpréteur, budget mémoire mesuré sur gk5.
- Contrôleur : USP maison derrière FastAPI, ou composant existant. GenieACS (Node.js + MongoDB) paraît hors budget
  (supposition).
- MTP USP sur le maillage, format exact de l'ordre de flash, seuils des notifications, noms des paquets et des CLI.
- Comment un `Operate` « réinstaller » écrit l'environnement U-Boot sur chaque carte, avec repli sur l'eMMC.
- Mise en forme des pages (charte `.claude/WEBUI-PANEL-GUIDELINES.md`, `.claude/AURORA-REFERENCE.md`).

## Questions ouvertes pour le propriétaire

La plus importante d'abord.

- **Q1.** Que doit pouvoir choisir **la personne devant la box** elle-même, que le maître ne lui impose pas ? Par
  exemple son mot de passe, le nom, le Wi-Fi, des modules en plus ou en moins, ou refuser la proposition. La question
  a été posée le 2026-10-28 et est restée sans réponse. Elle fixe le second visage de l'assistant (D3).
- **Q2.** Le clic sur le maître suffit-il comme confirmation pour **effacer une box déjà installée** sans personne
  devant elle ? La doctrine netboot exige une confirmation explicite de l'opérateur, aujourd'hui une touche à la
  console. Faut-il un second facteur pour une box qui porte déjà un système, par exemple une validation sur la box ou
  une confirmation renforcée sur le maître ?
- **Q3.** ESPRESSObin sans A/B : « une erreur de téléchargement ne doit jamais déclencher un effacement » et « flash en
  flux sans charger l'image en RAM » ne tiennent pas ensemble au sens strict. Que retenir ?
  - (a) Accepter qu'une coupure en cours d'écriture laisse l'eMMC invalide, mais récupérable par le netboot, et jamais
    annoncée réussie.
  - (b) Deux passes : télécharger et vérifier sans écrire, puis écrire. Le transfert double (environ 6 min de plus
    pour 1 Go compressé à 3 Mo/s, d'après le banc).
  - (c) Une zone de dépôt locale (partition `data` ou clé USB), là où elle existe.
- **Q4.** TR-369/USP seul, ou aussi CWMP (TR-069) pour qu'un ACS d'opérateur puisse gérer une box ? #3203 parle de
  TR-069, #3126 de TR-369.
- **Q5.** Box neuve, jamais démarrée : qui pose son premier démarrage réseau dans l'environnement U-Boot ? Préparation
  d'usine, une fois à la console, ou clé USB ? Sans cela, la première installation n'est pas pilotable de bout en bout.
- **Q6.** Box hors du réseau local du maître (chez un client) : comment trouve-t-elle son contrôleur ? Adresse gravée
  dans l'image, le maître public de projet 2, ou une option DHCP ? Le parcours proposé le 2026-10-28 (option DHCP sur
  le LAN du maître, adresse fixe ailleurs) n'a été ni confirmé ni corrigé.
- **Q7.** Mot de passe par défaut `secubox` (#3203) : le contrôleur l'impose-t-il à chaque préparation, ou
  l'invitation à le changer au premier accès suffit-elle pour la cible CSPN ?
- **Q8.** Box légère : garde-t-elle une page d'état locale quand le maître est absent, ou la console série suffit-elle ?
