<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WIP — Work In Progress
*Mis à jour : 2026-08-31*

---

## 2026-08-31 — DPI vivant, sweep spicy, Lyrion, Agenda NC (déployé gk2)

### ✅ Fait — déployé live
- **DPI vivant** : `secubox-dpi-engine` (nDPId+nDPIsrvd, nDPI 5.x) + **`sbxdpi`**
  (daemon Go dans secubox-toolbox-ng) → carte DPI réelle (fin du démo). Snapshot
  **sur SSD /data** (pas l'eMMC). Voir memory `dpi-live-sbxdpi`, README `cmd/sbxdpi/`.
- **Spicy + slicers** : Radio (0.1.62), PeerTube (5 vues + Chaînes/Playlists),
  MetaNews (0.1.32, slicer par section via `/categories`).
- **Nextcloud** : onglet 📅 Agenda (CalDAV : PROPFIND+REPORT, parsing iCal maison).
- **Lyrion** : ⚠️ L'ancien LMS s'était **planté** (runaway, 6 h CPU) sous la
  charge de mes tests de flux — service `lyrionmusicserver` DANS le conteneur
  `lyrion`, redémarré, stable (2 lecteurs).
  - **2026-09-01 — CARDLET LYRION RETIRÉE DU HALL** (ref #1247, `feature/hall-cardlet-ux`) :
    entrée registre + `cardlets/lyrion.html` + relais nginx `/api/v1/lyrion/` +
    token CSP `lyrion.gk2`. Paquet/vhost `secubox-lyrion` intact.
  - Avant ça, lecteur web 🎧 « SBX-Web » décommissionné (cardlet + backend :
    unité `sbx-lyrion-webplayer.service`, conffile `lyrion-webplayer.env`, dép.
    `squeezelite`, relais nginx `/lyrion-stream.mp3`).
- **Bus média** : pastille du viewer qui reste (dockLocal/viewerCmd) ; diffusions
  persistées dans le menu profil (survol) + badge de non-vues sur l'avatar ;
  carte sans vhost → pseudo /mega (drapeau `noVhost`).

### ⬜ Next Up — à finir
- **secubox-dpi-engine** : le formaliser en paquet source cross-build (aujourd'hui
  construit natif sur la box) ; nettoyer `/opt/nDPId` après build.
- Idées notées (memory) : cardlet SqueezeRadio/Lyrion émulateur, accès Zigbee.

---


## 2026-08-30 — ZIA Hall : préparation de la grosse session d'implémentation (#1245)

### ✅ Fait — design & préparation

**ZIA** = l'IA locale d'AletheiaVox/SBXOS, interface humaine du **bus d'objets** du Hall.
Elle ne possède pas les données : elle interprète et orchestre les objets déjà exposés
(le bus reste la source de vérité). Trois niveaux : Lite (local) / VHOST (spécialisé) /
Remote (escalade optionnelle). **Design validé, prêt à implémenter.**

- **Issue #1245** créée (roadmap P0–P5 en checklist).
- **Docs** : `docs/design/ZIA-HALL-POC.md` (référence + FAQ), `docs/design/zia-hall.html`
  (visuel AletheiaVox), `docs/design/zia-chat-cardlet.html` (maquette cardlet Chat P3).
- **Wiki** : page [[ZIA-Hall]] + entrée Sidebar (section MIND).
- **README paquet** : `packages/secubox-zia/README.md` (structure cible, interfaces,
  runtime, roadmap, DoD).
- **Maquettes artefacts** validées : ZIA Hall (référence) + ZIA Chat cardlet (P3).

### ✅ Livré — `secubox-zia` P1–P5 (30/08, déployé gk2)

**`secubox-zia` 0.1.2 + `secubox-webos` 1.0.206.** Le daemon FastAPI (`/v1/chat`,
`/health`, `/metrics`) tourne en local : répondeur **heuristique** (n'invente jamais
d'objet) + hook `llm_url` pour brancher un GGUF. Outils lecture d'abord ; bus =
seed + adapters **MetaNews** (topics) et **Registre** (services) → **186 objets** réels
sur gk2 ; policy/ACL hors modèle. Cardlet Chat (`www/zia/{index,micro}.html`) + entrée
FEATURED Hall + registre Système (online). **P4** : délégation exécutée (bascule ZIA·X +
objets liés). **P5** : `remote.py` sous politique + budget + timeout + circuit breaker +
rédaction des secrets + repli local (désactivé par défaut). Vérifié : recherche vidéo WAF,
liste des topics MetaNews, délégation WAF, objets service ouvrables.

### ✅ P0 RÉSOLU — off-box (30/08)

Le **build** llama.cpp sur la box la saturait (OOM du parc). Écarté : paquet
**`secubox-zia-llm`** (arm64) livre un llama.cpp **statique cross-compilé hors box**
(aucune dépendance glibc). `secubox-zia-getmodel` télécharge **Qwen2.5-0.5B Q4** (pas de
build) et démarre le serveur capé. **Mesuré sur gk2** : `llama-server` **~331 Mo RSS**,
box **1429 Mo libres**, load qui redescend, parc intact — ZIA en `engine: llm`.
**Le POC ZIA P0–P5 est COMPLET et tourne sur le modèle local.**

_Historique de l'ordre suivi (commencer minuscule, sans enfermer l'archi) :_

1. **P1 d'abord (sans matériel)** — daemon FastAPI `api/main.py` : `POST /v1/chat`,
   `GET /health`, `GET /metrics` sur socket `/run/secubox/zia.sock` (patron secubox,
   comme `secubox-devwatch`). `runtime.py` = **répondeur heuristique** (intention +
   appels d'outils) tant qu'aucun GGUF n'est chargé. `tools.py` (schémas + dispatch),
   `bus.py` (mock puis adapters), `policy.py` (visibilité).
2. **P3 en parallèle** — cardlet `www/zia/{index,micro}.html` (rendre la maquette réelle),
   branchée sur `/v1/chat`, rendu des objets `sbx://` + actions. Entrée FEATURED Hall.
3. **Packaging** — debian/systemd/nginx/menu.d/conf (modèle `secubox-devwatch`).
4. **P2** — adapters réels (MetaNews, PeerTube, BBS, Radio) → 20–50 objets, QA sans
   inventer d'objet.
5. **P0** — sur MOCHAbin : llama.cpp ARM64 + GGUF, benchmark (RAM/CPU/tokens·s), brancher
   `runtime.py` sur `llama-server`.
6. **P4/P5** — délégation VHOST ; remote optionnel sous politique + fallback.

> ⚠️ Le **modèle** se choisit APRÈS benchmark MOCHAbin (P0). D'ici là, le répondeur
> heuristique appelle quand même le bus → « pas d'objet inventé ». Outils **lecture
> d'abord** ; écriture après validation des permissions. Le LLM n'est jamais une autorité.

---


## 2026-08-28 — WAF anti-FP, routes, unification média viewer/barre, polish Hall

### ✅ Fait — déployé sur gk2

**WAF — un vrai visiteur ne se fait plus bannir (#1266).**
- **Première partie jamais bannie** (`secubox-waf-ng` 1.7.6) : un Host sous NOS
  suffixes (`gk2.secubox.in`, `secubox.in`, `gk2.net`, …) non routé → `detect`,
  jamais de ban. Cause vécue : l'appli Nextcloud iOS sur `nextcloud.gk2.secubox.in`
  (non routé) faisait bannir l'IP **Free Mobile** du téléphone → en CGNAT le
  navigateur tombait avec (`ERR_CONNECTION_ABORTED` sur hall.gk2.net).
  `estPremierePartie()` + test. IP Free Mobile débannies (nft + `unban` persistant).
- **Fix all WAF routes** : 21 vhosts `nginx_vhosts` présents dans HAProxy mais
  absents de `/etc/secubox/waf/haproxy-routes.json` → ajoutés → `192.168.1.200:9080`
  (pdf/hermes/osint/… servent en 200 au lieu d'être host-anomaliés).
- **`nextcloud.gk2.secubox.in` câblé** : alias `server_name` nginx + route WAF →
  WebDAV 401 (défi d'auth attendu) au lieu de 421. L'appli iOS marche telle quelle.
- **router-goform** (waf-rules 1.4.2) : alternance groupée `/goform/.*(\$\(|`|;)`
  (sans parenthèses, `;` matchait tout UA → tous les navigateurs bannis). Undrift.

**Surf/BiB — plus de JS cassé (#1266).** `reecris_html` passait ses réécritures
d'URL sur le CORPS des `<script>` : un `url("+x+")` concaténé cassait la page
(« missing ) after argument list » sur Google). On masque le corps des scripts
pendant la réécriture HTML puis on le restitue intact (`secubox-surf` 1.0.17).

**Unification média viewer ↔ barre (#1266)** (`secubox-webos` 1.0.185, `secubox-radio` 0.1.57).
- « Agrandir » un flux de la barre le PROMEUT dans le viewer, seule instance qui
  joue (plus de doublon). Radio (service audio) → `/micro` embarqué en viewer MINI
  « lecteur » (`data-embarque` → anti-doublon met la carte en pause, un seul son,
  synchro) ; à la fermeture, main rendue à la carte. Vidéo (peertube) → viewer joue
  à la position, carte en vitrine. `faireZoom()` partagé (pastille/bouton/`{sbx:'zoom'}`).
- Détach radio ⧉ → viewer mini au lieu d'une fenêtre. Pop-up radio mini : croix,
  pas de plein écran. Radio **muette par défaut à la 1ʳᵉ visite** (préf. retenue ensuite).

**Polish Hall (#1266)** (`secubox-webos` 1.0.186).
- Ordre par défaut mosaïque : radio, metanews, podcaster, peertube, puis le reste.
- Titre « Services principaux / N services » retiré. Menu mégabar dédoublonné
  (une entrée par destination).
- Tranches de cumul : ligne du bas partagée — l'URL de la couche (torrent/depot/ytsas)
  et le bouton « Ouvrir » (mail/cloud/photos/social) descendent sur la ligne des
  points ; les cartes embarquées masquent leur propre chrome bas (`embed=1`).
- Radio cardlet : barre « Proposer » ancrée en bas, titre borné 2 lignes (ellipse),
  boîte agrandie, zone messages resserrée. MetaNews : l'auto-rotation ne parasite
  plus l'aperçu manuel au survol (`mouseenter`/`leave` sur `.mw`, sans capture).

Versions : secubox-waf 1.10.25 · secubox-waf-ng 1.7.6 · secubox-webos 1.0.186 ·
secubox-radio 0.1.57 · secubox-metanews 0.1.28 · secubox-surf 1.0.17.

### ⬜ Non résolu (reporté) — voir TODO
- Générateur de routes WAF : vérifier que `haproxyctl generate` / wafgen ré-émet
  les 22 routes ajoutées à la main (sinon dérive au prochain regen).
- Podcaster pas encore câblé au zoom-viewer (pas de champ `lecteur`).
- 4 vhosts test backend `mitmproxy_inspector` (wiztest2/3, shiptest, mail.maegia.tv)
  laissés hors routes WAF volontairement.
- Reprise vidéo horodatée à la fermeture (peertube n'expose pas sa position) —
  « déplacement » seulement ; radio a la reprise complète.
- Endpoint public `torrent/etat`/stats (le résumé chiffré de la carte torrent est
  `action non autorisée` en invité ; la liste, elle, est publique).

---


## 2026-08-26 (nuit) — SBXOS : le BiB (Browser-in-Browser) et la matrice surf

### ✅ Fait — déployé sur gk2

**LE PROXY SURF EST EN LIGNE** (`secubox-surf`, hors chaîne d'inspection).
- URL par site : `surf-<hôte-aplati>.gk2.secubox.in` (wildcard, HAProxy route
  `surf-*` par `hdr_beg` en bypass, générateur #1217). Serveur ASGI 9082.
- **Navigateur dans le Hall** (webos) : carte + overlay avec barre d'adresse,
  ◄ back, 🏠 home, ⟳, ⧉, ✕. La barre de recherche du Hall surfe une adresse
  (Entrée). Barre unique double-ligne, hauteur d'une seule, metrics + statut
  inline.
- **Confidentialité** : pisteurs coupés à la source (liste + motifs + labels
  exacts), auto-consentement (didomi/OneTrust + clic « accepter »), contenus
  « Sponsorisé » cachés, popups + **notifications** interceptées, cookies JS
  forcés `SameSite=None` (contexte tiers), anti-adblock CIBLÉ (jamais global —
  le clic global cassait tout), meta-refresh neutralisé, sandbox iframe.
- **Saut de portail de consentement** : first-id.fr (bloqué par le DNS box)
  redirige BFM → on lit l'URL de retour (`redirectHost`+`redirectUri`) et on
  saute au bon chemin ; réécriture des portails dans le HTML **et le JS**.
- **Barre de metrics** : 🎯 traqueurs · 📢 pubs · 🧩 tiers · 🍪 cookies · 🔔
  notifs · 🚫 popups · 🛡️ % pisté.

**LA MATRICE SBXOS** : dans le Hall, tout lien reste dans le Hall.
- MetaNews : sources externes → surf (overlay). Liens du cartouche BBS → le
  BON sujet (`#<id>`, plus global) et **restent embarqués** (`sbx:'ouvre-hote'`).
- BBS embarqué : liens externes → surf, liens box → service embarqué ;
  standalone → liens directs.

**Divers** : miniatures PeerTube stables (réutilisation, plus de teardown) ;
fin de vidéo retire rangée+pastille ; **vol/muet des barres média
persistants** ; « ordre actuel = défaut » pour les favoris ; session Roundcube
8 h ; carte Dépôt qui dépose (glisser/coller/choisir) ; Torrent/YTSaS sans
boutons redondants ; bandeau Hall sur une ligne au téléphone.

**MetaNews clustering** : fraîcheur multiplicative + garde de contenu +
acronymes en tête + **jours/mois/mots communs exclus des entités** (l'aimant
« Lundi » qui mêlait tornade et préservatif). Sources : 16 → 28 (Mediapart,
Reporterre, Basta!, L'Huma, Le Point, Slate, Courrier Inter, France Culture,
Alter-Éco, AFP Factuel, TV5Monde, France Inter).

**Bug critique corrigé** : réassignation de `const d` (ev.data) dans
l'arbitrage média cassait TOUT le handler de messages → clics du Hall « qui
merdaient ». Et la règle « audio cède à la vidéo » bloquait la radio
(retirée).

### ⬜ Next
1. **WAF — hostnames inconnus en top-10** (noms non routés) dans le tableau du
   Hall. Demandé, non fait.
2. **Re-clustering MetaNews** : les sujets DÉJÀ fusionnés à tort ne se défont
   pas seuls ; écrire une passe qui réévalue le rattachement des articles avec
   les nouvelles règles et détache ce qui ne colle plus.
3. Guide cardlets : ajouter les leçons surf (portails, sandbox, injection,
   clic global).

### 📄 Documenté
- `docs/POC-SURF.md` — mesures, murs, décision, montage vivant.
- `docs/CARDLET-GUIDELINES.md` — inchangé cette nuit (à compléter, cf. Next 3).

---

## 2026-08-26 (soir) — SBXOS : les cartes AGISSENT, et le guide qui en sort

### ✅ Fait — déployé sur gk2 (secubox-webos 1.0.99 → 1.0.104)

**Le dépôt dépose pour de vrai** (#1328, corrigé #1329). La carte listait et
retirait, mais ne déposait pas — elle parlait d'un service sans savoir faire ce
pour quoi il existe. Elle était de surcroît câblée sur le **mauvais verbe** :
`/upload` publie un site et demande un compte ; `/depot` **reçoit** un fichier,
public, sans compte, et rien n'est publié. La carte porte désormais la phrase
du service mot pour mot. Glisser, coller, choisir — trois gestes, un chemin ;
la carte **entière** est la cible du glisser. Corps relayé **en flux** (2 Go
acceptés : les tamponner tuerait l'API d'un seul envoi), **adresse d'origine
transmise** pour que le limiteur du service compte encore par machine, plafonds
**demandés** et non recopiés.

**Le lecteur PeerTube ne plante plus** (#1324 puis #1330 — deux diagnostics, un
seul vrai). Le message « player is not compatible with your web browser » ne
parle pas du navigateur : le lecteur installe
`window.onerror = displayIncompatibleBrowser`, donc **toute** erreur JS s'y
affiche. On répondait `params:'pong'`, une chaîne, là où son jschannel lit
`params.publish.length` — la réponse attendue est un objet
`{type:'publish-reply', publish:[]}`. Trouvé en lisant le bundle servi, après
deux hypothèses fausses fondées sur le seul message.

**Ses assets sont servis à la racine** (#1322) : la page d'embarquement
référence `/client/…` et `/plugins/…` en absolu, sans savoir qu'elle est servie
sous `/pt/`. Ces requêtes tombaient dans le `location /` du Hall, **qui
répondait 200 avec son index.html** — du HTML là où le navigateur attendait du
JavaScript. Un 404 aurait été plus lisible qu'un 200 de la mauvaise nature.

**Favoris** (#1323 → #1327), en **bande horizontale**. Deux versions jetées
avant la bonne : élargir la carte (`column-span`) remettait son aperçu à
l'échelle et le faisait paraître zoomé de travers ; la remonter « en tête »
d'une mosaïque en **colonnes** l'empilait à gauche. Le favori ne change que
l'**ordre**. On y glisse pour entrer, sortir et réordonner ; placer une carte à
la main retire son favori, sinon les deux gestes se contredisent.

**Le bandeau tient sur une ligne au téléphone** (#1325). La cause n'était pas
le contenu mais un `flex-wrap:wrap` sous 960 px : la barre se **repliait** au
lieu de s'alléger. Le repli est borné aux tablettes ; sous 720 px on **retire**
— « SbX », que le médaillon dit déjà, et « Identité locale », dont la place est
au menu profil. Les pastilles restent : c'est la seule information vivante du
bandeau.

**Divers** : YTSaS perd deux boutons qui menaient au même endroit en plus loin
(#1320) ; kbin ne s'embarque plus (#1321) — un forum entier tassé dans 280 px
ne montre rien qu'on puisse lire, il garde sa carte donc son accès ; le jeton
de l'appelant est relayé aux modules qui protègent leurs routes de lecture
(même personne, même box, même domaine d'authentification).

### 📌 Ce que la journée a appris, et qui sert maintenant de règle

- **Un message d'erreur tiers désigne rarement sa cause.** Un `window.onerror`
  global les rend tous identiques. Lire le code qui lève avant de croire le
  texte : ici un `grep` sur le bundle a tranché en une commande.
- **Un 200 de la mauvaise nature est pire qu'un 404.** Le Hall rendait son
  index.html à des requêtes de JavaScript ; c'est ce qui a rendu la panne
  opaque.
- **Ne pas inventer à un service des fonctions qu'il n'a pas** — ni lui en
  retirer celle pour laquelle il existe.
- **Éviter un rechargement d'iframe est un bon réflexe, pas au prix de
  déformer la carte.** Quand les deux s'opposent, changer la fonctionnalité.

### 📄 Documenté

- **`docs/CARDLET-GUIDELINES.md` (NOUVEAU, ~370 lignes)** — non pas comment une
  carte devrait marcher, mais **ce qui a réellement cassé** en la construisant,
  le symptôme exact que ça produisait, et la règle qui en découle. Commence par
  « ce service mérite-t-il une carte ? » et finit par une liste de contrôle en
  16 lignes. Référencé depuis `MODULE-GUIDELINES.md` §8quater et
  `WEBOS-DESIGN.md` §5bis.

### ⬜ Next — demain, avec le POC

1. **#1216 — corréler les sessions de nos propres services, sans les
   cloisonner.** Le lecteur PeerTube ne s'authentifie plus dans le Hall :
   contexte tiers, stockage cloisonné, jar vide. **Corréler n'est pas
   cloisonner** — le cloisonnement vise les traqueurs, l'appliquer aux témoins
   nécessaires de nos services casse notre propre SI. Les deux mécanismes
   restent **séparés** : le proxy de surf exige une origine PAR site, la
   corrélation exige l'inverse. Préalable : démêler les noms d'hôte entre
   `admin` et `gk2`. À traiter **avec** le POC §0bis ci-dessous.
2. **Radio (#1201)** : playlist affichée → retirer le morceau en cours de la
   liste, réduire de moitié le précédent. Un back, le courant, deux next.
3. **BBS et SocialRelay** : vignettes et miniatures manquantes.
4. **Podcaster** : sélection ou diaporama des flux sources, deux derniers de
   chaque — lecture de livre audio *vs* nouveau podcast.
5. **BBS (#1198)** : liens YouTube attrapés et re-référencés vers PeerTube,
   avec vignette embarquée. Les validations sont maintenant distribuées dans le
   BBS, ce qui rend la chose utile.
6. **SocialRelay (#1192)** : contenu du bouton « Sources » déplacé dans la
   mégabarre de droite du Hall.
7. **Torrent** : barre de progression en contour de l'item.
8. **WAF embarqué** : corriger le clignotement clair/sombre du statut.

### ❓ Question ouverte, posée et non tranchée

**La radio ne persiste pas au rafraîchissement** — et n'a jamais persisté : sa
cardlet ne contient aucun `localStorage`, vérifié sur le fichier servi par la
box. C'est PeerTube qui retient sa position. Reste à décider si on lui donne la
même reprise.

---

## 2026-08-26 (après-midi) — SBXOS : les services habitent le Hall

### ✅ Fait — déployé sur gk2

**Sept services servent LEUR carte** (#1236 → #1265) : pare-feu, radio,
podcaster, billets, MetaNews, BBS, SocialRelay. Les neuf autres affichent
l'**aperçu vivant** — leur vraie page mise à l'échelle — plutôt qu'un portrait
générique. Le Hall prend toujours le degré le plus élevé disponible et bascule
seul quand un service apprend à se résumer.

**Les services tiers acceptent le cadre** (#1257) : PeerTube, Nextcloud,
PhotoPrism, Mastodon, webmail. En-têtes réécrits **au proxy**, opt-in par vhost
(`cadrable`), cookies séparément (`cookies_tiers`). Le diagnostic le plus cher
de la série : conditionner un `http-response` sur une ACL d'en-tête de *requête*
ne matche pas — règles générées, config valide, rechargement propre, et rien ne
bouge, sans un mot.

**Aucune exclusion WAF ne subsiste** : les 7 `waf_bypass` sont à `false`.
Quatre rendaient 503 — absents de `haproxy-routes.json`, jamais ajoutés
puisqu'ils n'y passaient pas.

**Mes identités** au menu profil (#1272) : où une session est ouverte, et depuis
quand. Ni valeur ni empreinte — le registre RGPD n'en garde pas.

**Divers** : barre média repliable en pastilles + volume par flux ; clic dans
une carte qui reste dans le Hall ; ordre par défaut au degré de la carte ;
YTSaS et Torrent ajoutés ; thème propagé à TOUS les cadres ; MetaNews et
SocialRelay dotés d'une palette claire.

### 📌 Trois pannes payées comptant

- **`Partitioned`** cloisonnait la session au couple (Hall, service) : deux
  sessions webmail, « non concordance de témoin ». Retiré.
- **CSP du BBS** : `style-src 'self'` bloquait le `<style>` en ligne de la
  carte — HTML brut, « aucun fil ». Feuille et script sortis dans `/static/`.
- **`LARGEUR_PAGE` en `const`** après son appel : zone morte, `ReferenceError`,
  et tout le rendu s'arrêtait — menus, barre média et pastilles disparus d'un
  coup. **Troisième fois** dans ce fichier.

### 📄 Documenté

- `docs/WEBOS-DESIGN.md` — contrat d'une carte, les quatre pièges de
  l'encadrement, ce qui reste ouvert.
- `wiki/WebOS-FR.md` — page utilisateur.

### ⬜ Next

0quater. ~~**Actions réelles de Torrent et Dépôt**~~ **fait (#1314)** : la carte
   Torrent liste, met en pause, reprend et accepte un magnet. Tout passe par
   une route webos **sous jeton** avec une **liste close** d'actions —
   l'API d'administration répond `400` et non `401` sans jeton, donc elle n'est
   pas authentifiée et la relayer aurait ouvert l'ajout à tout le LAN.
   **YTSaS aussi (#1315)** : une URL, un bouton. Sa route n'était pas
   introuvable, elle vit sur **son** vhost et non sur la console
   d'administration — chaque module déclare désormais son hôte.

0bis. **POC proxy Tor + relais MITM — le morceau qui compte.** L'objectif tel
   que posé : anti-censure, « SaaS inversé », gestion des traqueurs, blocage
   transparent des publicités avec apprentissage, et pseudo-témoins rejoués
   pour que le service distant croie ses publicités affichées — donc perte du
   traçage à distance.
   **Ce que la journée a déjà mesuré**, et qui doit cadrer le POC : le relais
   `/pt/` a échoué exactement là où ces projets échouent — le lecteur demandait
   ses ressources à la **racine** (`/client/…`), pas sous le préfixe. Réécrire
   le HTML ne suffit pas : CSS `url()`, imports dynamiques, `fetch`, service
   workers — et ceux dans le JS sont indécidables.
   **Le piège structurant** : une origine unique = un contexte de sécurité
   unique. Bon pour NOS services (§4bis), **dangereux** pour du surf arbitraire
   — une page relayée lirait le stockage de Nextcloud. Le proxy de surf exige
   donc **une origine par site** (`<empreinte>.proxy…`, certificat générique).
   **Trois mesures suffisent à décider** : un site statique, un site applicatif
   (Nextcloud), un SaaS moderne hostile au proxy.

0. **Cartes Mail, Nextcloud, Mastodon, PhotoPrism** : l'ossature de délégation
   est **complète** (#1288 → #1290) — demande → file → validation → jeton
   stocké, classée par personne, aucune route publique, compte nommé. Nextcloud
   par Login Flow v2, Mastodon par OAuth2, les autres par identifiant dédié en
   popup. **Reste à écrire les cartes qui la consomment** : bouton « demander
   l'accès » quand il n'y en a pas, contenu quand il y en a un — OCS/WebDAV,
   `/api/v1/timelines/home`, IMAP vers 10.100.0.10. Jamais de scraping.
   *(ancienne note ci-dessous)*
   L'ossature de délégation est posée (#1288,
   demande → file → validation → mot de passe d'application stocké). Reste à
   écrire les deux cartes qui l'utilisent — bouton « demander l'accès » quand
   il n'y en a pas, contenu quand il y en a un. Le contenu passera par OCS/
   WebDAV pour Nextcloud et par IMAP (Dovecot, conteneur 10.100.0.10) pour le
   mail : **jamais de scraping**.
1. ~~**PeerTube**~~ **fait (#1273)** : vignettes en rotation, « lire ici » qui
   pose le lecteur d'embarquement amont, relais de même origine pour l'API, les
   vignettes et le lecteur. Vérifié que seul le public est relayé — `users/me`
   retombe sur la page du Hall. *Reste* : la position de lecture n'est pas
   annoncée à la barre (le lecteur amont ne la donne pas sans son API de
   fenêtre) ; `stop` est le seul ordre honoré.
2. **SocialRelay** : média occupant toute la carte, avec rotation.
3. **Nextcloud / Roundcube** : *pas de scraping*. Nextcloud a OCS+WebDAV ;
   Roundcube n'a pas d'API mais Dovecot **est** l'API. Le blocage n'est pas
   l'accès aux données, c'est l'identité → coffre avatar.
4. **Proxy navigateur + Tor onion** : rendrait tout même origine et
   supprimerait les quatre pièges d'un coup. **À maquetter et mesurer avant
   toute inclusion.**
5. **Alpha 3** sur les releases GitHub.

---

## 2026-08-22 → 26 — Sortie de CrowdSec, WAF autonome, hors-HTTP, WebOS

Marathon en trois mouvements : le WAF cesse de dépendre d'un tiers, il apprend à
voir autre chose que HTTP, et l'accueil devient un bureau.

### ✅ Fait — déployé sur gk2, paquets construits

**Le WAF bannit vraiment (#1216, #1220)**
- Cause du silence : `Ensure()` créait la table et les ensembles nft, **mais ni
  chaîne ni règle**. `waf_ban` existait, plein, et *n'était référencé nulle
  part* — bannir revenait à tenir une liste sans portier. Ajout de la chaîne
  `waf_drop` (hook input, priorité -100) et des deux règles `@waf_ban` /
  `@waf_ban6`. `flush chain` avant les `add rule` : `add rule` n'est pas
  idempotent, sans cela chaque démarrage empilait un doublon.
- Preuve mesurée aujourd'hui sur gk2 : **115 IPv4 + 2 IPv6 bannies**,
  **12 545 paquets / 878 Ko jetés par le noyau**. La question posée en séance —
  « ces 421 sont silencieux mais le WAF bloque-t-il les sources ? » — a
  désormais une réponse chiffrée : oui.
- Garde-fou sur les adresses privées dans `Ban()`. Les plages réellement
  dangereuses sont énumérées plutôt que confiées à `is_private`, qui range
  203.0.113.0/24 (réseau de documentation) parmi les privées et rendait l'outil
  intestable.
- Le bouton « Ban » du webui appelait `cscli` et **avalait ses erreurs** : il ne
  faisait rien, en silence. Repointé sur `sudo -n wafctl ban|unban`, erreurs
  propagées jusqu'à l'interface.

**Anti-robots par vhost (#1216)**
- 48 robots nommés (moteurs, moissonneurs d'IA, SEO) + motifs génériques.
  `\b` ne convenait pas : « NewSpider » n'a pas de frontière avant « Spider »,
  et les téléphones `CUBOT_X19` seraient passés pour des robots.
- `/robots.txt`, `/favicon.ico` et `/.well-known/` restent toujours servis :
  bloquer robots.txt empêche le robot d'apprendre qu'il n'est pas le bienvenu.

**CrowdSec retiré du chemin**
- Service arrêté, démarrage automatique désactivé. Les satellites
  `secubox-blacklist-sync` et `secubox-threatmesh-bridge` sont liés par
  `Requisite=` : sans CrowdSec ils ne partent pas, au lieu d'échouer en boucle.
- Charge de la box : **15–22 → 5–7**.
- Le paquet `crowdsec` reste installé mais inactif — dépose, pas purge.

**Hors-HTTP : `sbx-authwatch` (première version)**
- 9 modules, **43 tests**. Lit SSH, SMTP et IMAP — journal *et* fichiers —
  et alimente **le même ensemble nft et le même journal de menaces** que le WAF :
  c'est la corrélation perdue avec CrowdSec qui est reconstruite ici.
- Motifs écrits depuis de **vraies lignes de gk2**, jamais depuis la
  documentation amont. Le format passwd-file de dovecot impose de couper sur
  `:` — sinon l'empreinte du mot de passe devient le nom du compte.
- Détection de campagne (clé : le compte visé) et de compte inexistant. Les
  tentatives sur `@gk2.net`, domaine dont l'exploitant ne se sert pas, sont donc
  des agressions et non des erreurs de frappe.
- **10 ports leurres**. Un leurre n'imite jamais le protocole : il note et se
  tait. Imiter, c'est offrir une surface.
- Filtres par service déclaratifs (`/etc/secubox/authwatch/services.json`) :
  gitea et nextcloud actifs sur motifs vérifiés ; peertube et mastodon inactifs
  avec `_pourquoi_inactif` écrit noir sur blanc, plutôt qu'un motif deviné.
- Nextcloud journalisait l'IP du relais : `192.168.1.200` manquait dans
  `trusted_proxies`. Sans ce correctif, le filtre n'aurait su bannir que la box
  elle-même.

**Tableau de bord WAF + vhost dédié (#1237)**
- Page `waf.gk2.secubox.in`, LAN seulement : histogramme empilé et barres
  d'efficacité en SVG inline, sans bibliothèque externe.
- Métriques ajoutées : pays, **noms non résolus par les vhosts existants**,
  détections comportementales, comptes visés, leurres touchés, efficacité.
  Chacune avec une relecture complète unique à la migration.
- Deux corrections d'honnêteté : « Unknown » partout venait de ce que
  l'agrégat renvoie `categories` (une liste) là où l'interface lisait
  `scenario` ; et `robots` affiché à 0 % d'efficacité venait de ma propre
  métrique, qui comptait un refus 403 comme simple observation.

**WebOS — l'accueil devient un bureau (#1234 → #1248)**
- Chaque service **sert sa propre carte** (`/micro`) : le hall ne dessine plus
  de maquette de ce qu'il ne connaît pas.
- Mosaïque en colonnes (`break-inside:avoid`) : les cartes n'ont plus à
  partager une hauteur commune.
- Cartes déplaçables, mémorisées **par profil**, avec réinitialisation au menu.
- Barre média persistante + **pastilles** dans la mégabarre : le son survit à la
  navigation d'un service à l'autre.
- Thème propagé **par `postMessage`**, jamais en réécrivant `iframe.src` : ma
  première version rechargeait le cadre, ce qui coupait la lecture en cours.
- **#1248 (aujourd'hui)** : la barre média, fixée en bas, recouvrait les
  dernières cartes et le bas des services encadrés — rien ne pouvait les
  dégager. Sa hauteur réelle est désormais mesurée et publiée en `--dock-h` ;
  l'accueil l'ajoute à sa marge basse, la vue encadrée la retire de la hauteur
  du cadre. `secubox-webos 1.0.55`, déployé.

**Panneau Vhost corrigé**
- Le fichier de routes avait déménagé : `/srv/mitmproxy/…` n'existait plus,
  **281 routes disparaissaient en silence**.
- URLs courtes fausses sur **91 vhosts sur 100** : `/access` utilisait
  `conf_file.stem` au lieu du FQDN.
- `depot` n'est pas `repo` : deviner d'après le nom l'aurait mal attribué. Sa
  socket nginx a révélé une gouttière d'agrégation.

### ⬜ TODO — file réelle, par ordre de coût

0ter. **X-Forwarded-Proto : posé, mais perdu en route (#1269).** HAProxy le pose
   désormais sur ses deux frontends (vérifié, lignes 40 et 375 de la config
   générée) et les vhosts nginx le transmettent au lieu d'écraser avec
   `$scheme`. **L'application est correcte** : interrogée directement sur sa
   socket avec l'en-tête, Billets émet bien `https://`. Il se perd donc entre
   HAProxy et nginx — le seul intermédiaire est **sbxwaf**, dont le
   `NewSingleHostReverseProxy` devrait pourtant préserver l'en-tête. Non
   élucidé. Conséquence résiduelle : les permaliens des cartes restent en
   `http://`, donc le Hall embarque la racine du service au lieu de la page
   exacte. Le reste (cookies `SameSite`) n'est plus affecté depuis que
   `Partitioned` a été retiré.
   *Attention* : les vhosts nginx sont des **conffiles**, et `--force-confold`
   conserve l'ancien — après upgrade, comparer avec le `.dpkg-dist`.

0bis. **Exclusions WAF levées — à surveiller (#1257).** Les **sept**
   `waf_bypass` sont passés à `false` : lyrion, torrent, jellyfin, ytsas,
   matrix, photoprism, peertube passent désormais par sbxwaf. Quatre
   répondaient 503 : ils étaient **absents de `haproxy-routes.json`**, jamais
   ajoutés puisqu'ils n'y passaient pas — corrigé par
   `secubox-publishctl waf-route`. Les sept répondent, **mais seule la page
   d'accueil a été testée** : ces exclusions existaient pour les téléversements
   volumineux, WebDAV, la diffusion média et la fédération. À éprouver sur un
   gros téléversement PhotoPrism et une lecture Jellyfin soutenue. Sauvegarde :
   `/etc/secubox/haproxy.toml.avant-waf-total`.

0. **Masque ACL de `/etc/secubox/secrets` — à étendre (#1255).** Corrigé dans
   bbs, radio et socialrelay : leur postinst pose désormais `m::x` en même
   temps que l'entrée nommée. Le fond reste fragile — **une dizaine de paquets
   font `install -d -m 0700` sur ce dossier partagé**, et tout chmod écrase le
   masque à `---`, ce qui rend chaque entrée nommée `#effective:---` sans que
   rien ne le signale ; le service ne peut plus traverser et refuse de
   démarrer. Reste à traiter : **`secubox-meshtastic`**, qui possède
   `secrets/meshtastic/` mais n'a **aucune entrée ACL** — latent, le service
   est inactif aujourd'hui. À vérifier pour tout module futur tournant sous
   son propre utilisateur. Le correctif de fond serait `0710 root:secubox` sur
   le parent, qui rend l'ACL inutile, mais touche une dizaine de postinst.

1. **#1210 non clos.** Les appels `cscli` sont passés de 50 à 25 par 3 min,
   mais `secubox-aggregator` en engendre encore et **son source ne contient
   aucun `cscli`** : l'appelant n'est pas localisé. Neuf modules SecuBox
   invoquent cscli, sept sont inactifs. Piste : un garde partagé
   `crowdsec_actif()`.
2. **BBS — audio ininterrompu.** Seule l'étape 1 est faite (dock extrait en un
   `dock.html` unique, doublon déjà divergent supprimé). L'extraction du lecteur
   depuis `newsroom.js` (~110 lignes, attaches spécifiques au newsroom) reste à
   faire, puis navigation PJAX échangeant `<main class="feed">`.
3. **`/micro` manquants** : bbs, peertube, nextcloud, photoprism, metanews,
   mastodon, billets, depot.
4. **MetaNews** : faire défiler le contenu des vignettes en bouclant sur les
   sources agrégées (#1189, #1200).
5. **Miroir du wiki GitHub → gitea** : gitea ne recopie que le code, le wiki est
   un dépôt séparé.
6. `repo.toml` ne déclare aucun `portal.domain`.
7. ~26 tickets ouverts plus anciens (#1180 → #1215).

### 📌 Historique — pourquoi CrowdSec est parti

Ce n'est pas un rejet technique. CrowdSec a rendu service, et le dire compte :
la détection communautaire a couvert des mois de production. Trois raisons ont
fait pencher la balance — la dépendance à un tiers dans le chemin de décision,
le coût en charge sur un ARM contraint, et le fait que la mutualisation n'était
plus réciproque dans la durée. `sbxwaf` est plus efficace **et** plus modulaire :
la règle vit dans le noyau, la politique dans un fichier lisible, et le hors-HTTP
rejoint le même ensemble de bannissement au lieu d'un second système parallèle.

Deux notes de séance rédigées : *Sortir de CrowdSec* et *Le WAF autonome*.

---

## 2026-08-21 (soir) — #1120 vignettes-snapshot d'URL FERMÉ (e2e), alias domaines

### ✅ Fait — déployé + apt-synchronisé
- **#1120 vignette-snapshot d'URL — FERMÉ, e2e prouvé** (bbs 0.28.50, toolbox-ng
  0.1.45, core 1.3.2, PRs #1125/#1126). Proxy CONNECT d'égress interne
  (`secubox-toolbox-egress-proxy` :8090, CA publiée), og:image + fallback
  chromium via égress SPKI-épinglée. Voir [[project_toolbox_egress_connect_proxy]].
- **/mp/annuaire + /p/{id}/edit** au skin newsroom (#1121). Médaillon SVG logo
  (bbs + billets). Alias : secubox.in→3d, all.gk2.net→all (cert+HTTPS),
  anibal-amiot.com canonique, ganimed.fr→301.

### ⬜ Next Up
- **/c/emissions cassé** — page catégorie BBS en erreur (à diagnostiquer ;
  régression probable skin newsroom/carrousel).
- **ytsas téléchargements bloqués (SABR)** — yt-dlp à jour ; média googlevideo
  throttlé 0% ; fallback DASH-https/PO-token à câbler (radio 403 idem).
- **urlshot** — garde de charge 4.0 vs board chargée (captures aux creux) ;
  éditeur : miniature live sur collage d'un lien (phase 2).

## 2026-08-21 — BBS médias publics + newsroom, carrousel, kbin, nextcloud

### ✅ Fait — déployé + synchronisé sur apt.secubox.in

- **secubox-bbs 0.28.46** (#1114, PRs #1115/#1116/#1117) — médias publics pour
  anonymes ; skin newsroom sur `/t/` `/mp` `/compte` + alerte MP + médaillon SVG ;
  fiche fichier PDF ; carrousel réparé (doublon 🎬, tuiles vides → mosaïque, et
  le vrai bug : `<a>` imbriqué) ; corps root:root intraversables réparés
  (writeBody adopte le dossier + postinst self-heal).
- **secubox-billets 0.8.3** (PR #1118) — même médaillon BBS en logo.
- **kbin / toolbox 504** (config live) — `10.99.0.1` mort → `127.0.0.1` dans les
  3 consommateurs ; sbxwaf remis sous `secubox-waf-ng.service`.
- **nextcloud nc.gk2** (config live) — réveil scale-to-zero réparé (manifeste
  `nc.gk2` + `secubox-wakectl` sync + symlink `sites-enabled`).

### ⬜ Next Up — file de la session, non traitée

- **Bascule public ⇄ privé d'un fil BBS** — il n'existe AUCUN contrôle pour
  rendre un fil local→public (le bouton « Publier en billet » exige déjà public).
  À ajouter : store `BasculeVisibiliteThread` (+ propagation fichiers, et REVERT
  des fichiers non cités ailleurs quand on repasse local — pas de fuite), route
  `/t/{id}/visibilite` (sysop+CSRF), bouton dans thread.html.
- **radio 403 Forbidden** — yt-dlp `HTTP 403` sur clips YouTube (cookies/IP).
- **Alias de domaines** — `secubox.in`→`3d.gk2.secubox.in`,
  `all.gk2.net`→`all.gk2.secubox.in` (ACL HAProxy + route WAF + certs/DNS).
- **Vignette-snapshot d'URL dans BBS** (éditeur + carrousel) — feature à
  concevoir proprement : réutiliser `secubox_core.screenshots` (capture async
  cachée, jamais en requête), sécurité egress CSPN, réconcilier avec #1049.

## 2026-08-19 — Réparation, dé-Python, WAF, rapports

### ✅ Fait — déployé + synchronisé sur apt.secubox.in

- **secubox-toolbox-ng 0.1.43** (#1054) — split-brain réparé (merge 3-voies) +
  capture #1058 ; sur-ensemble canonique, R3 workers redémarrés.
- **secubox-toolbox 2.9.0** (#1054) — Python mitmproxy excisé (dép + units +
  addons + templates LXC + logique postinst) ; `apt purge mitmproxy` réussi,
  2 LXC détruits.
- **secubox-nextcloud 1.7.1** (#1046) — `flock` single-flight dans `occ()` :
  orage occ (charge 79) dompté à la racine.
- **secubox-hub 1.9.4** (#1060/#1054) — `set_real_ip_from` truste le LAN
  (visiteur unique corrigé) + pastille WAF verte (alias `waf←waf-ng`).
- **secubox-metrics 1.7.2** (#1059/#1062) — rapport PDF hebdo+quotidien anibal-amiot
  par mail ; référents regroupés + % accès direct ; section « Menaces WAF ».
- **secubox-waf 1.4.1** (#1062) — API de stats réactivée (webui WAF ressuscitée) ;
  endpoint `/history` (logs tournés → 34 j / 362 k menaces) + onglet Historique.
- **Dépôt** — 31 branches purgées, 26 issues fermées, SPDX Phase C (2288 fichiers).

### ⬜ Next Up

- **BBS #1049 mosaïque** — socle + collecteurs + pont Item→Contenu faits ; reste
  enrichir podcaster (poster), le handler `/mosaique`, le frontend grille, et
  peupler `gateway_contenu` à l'ingest.
- **#1061** — dédup de la boucle de fond du hub (2× `systemctl list-units`/5 s).
- **Dé-Python `/waf/` stats** (optionnel) — porter le lecteur de stats dans le Go sbxwaf.
- **secubox-waf** — verrou source du service de stats déjà couvert par le postinst.

## 2026-08-16 — Radio, cache du WAF, emulation

### ✅ Fait — deploye et synchronise sur apt.secubox.in

- **secubox-radio 0.1.2** (#1047) — le clip joue dans le cadre de la vignette ;
  une piste refusee par la passerelle est ecartee avec sa raison au lieu de
  geler toute la file ; URL statiques empreintes du contenu ; empreinte de la
  feuille de la banniere de sante dans `style-src`.
- **secubox-toolbox-ng 0.1.40** (#1031) — sbxwaf ne sert plus une entree de
  cache sans metadonnees lisibles.
- **PeerTube** — 4 ffmpeg bloques depuis 5-8 jours supprimes.
- **Depot** — 11 worktrees vides retires (28 → 18).

### ⬜ Next Up

- **Cache navbar du hub** — 180 services en un `systemctl` a 5 s, expire sous
  charge ; entree corrompue `'●'` dans la liste. Non corrige.
- **Groupe unique = point de panne unique** — les 6 groupes existent en
  configuration (`/etc/secubox/groups.d/g1..g6.conf`), un `systemctl` pour y
  revenir.
- **15 modules muets et 2 non importables** dans le groupe.
- **Empaqueter `secubox-groupd`** — le binaire et l'unite sont poses a la main.
- **Plafonds memoire des conteneurs** poses en direct, a remonter en paquet.
- **`--widget-exclude`** ne couvre que `social` ; nextcloud, peertube, gitea
  restent a ajouter.
- **secubox-portal** inutile (60 octets/min) mais `secubox-lite` en depend.
- **Conflit de paquets** : `hub` et `portal` livrent tous deux `login.html`.
- **gitea** en 504 intermittent.

- **Deployer les 126 paquets construits** — par lots de dix, controle de sante
  entre chaque. Versions deja montees, aucun echec de construction.
- **Refonte du BBS** — maquette validee, plus urgente depuis la reparation :
  un seul point de rupture au lieu de onze, barre de contexte, 40 classes
  mortes a retirer. Chantier de plusieurs sessions, a faire a froid.
- **#1056** — reste l'appel de `/media-fiche` depuis la page, et le podcaster
  (son JSON n'est expose que par sa socket, pas par le vhost).
- **#1054 sbxmitm** — splice WebSocket avant de basculer les deux chemins
  restants. Un chemin sur trois est migre.
- **#1052** — verifier que les sets nft restent peuples apres 24 h.
- **#1051 403 YouTube** — piste PO token, non verifiee.
- **#1050 SecuBox Retro** · **#1053 c3box** · **#1055 edition/suppression**.
- **Fusionner l'arriere** — 18 worktrees non fusionnes, aucune PR ouverte.

- **Deployer les 126 paquets construits** — par lots de dix, controle de sante
  entre chaque. Jamais d'un coup : 126 demons redemarres en parallele.
- **#1056 mosaique et vignettes BBS** — relais par le demon, pas d'`img-src`
  elargi. Question ouverte : le relais accepte-t-il une URL libre postee par un
  membre ? Sinon c'est un proxy ouvert.
- **#1055 edition et suppression** des messages, avec journal d'audit.
- **Sous-forums vides sur telephone** — demande un marqueur pose par le serveur.
- **#1054 sbxmitm** — splice WebSocket avant de basculer les deux chemins.
- **#1051 403 YouTube** — piste PO token, non verifiee.
- **#1053 c3box** — reinstallation from scratch.

- **403 YouTube sur le media** (#1048 voisin) — metadonnees OK, media refuse.
  Ni les cookies, ni notre interception, ni la version de yt-dlp. Piste non
  verifiee : fournisseur de PO token.
- **Charge moyenne a 41** (#1045) — les fantomes n'en etaient pas la cause,
  la source reste a trouver.
- **#1050 SecuBox Retro** — faisabilite a etudier, rien d'engage.
- **#1049 mosaique** — composant partage entre les flux.
- **PR manquantes** — 18 worktrees portent du travail non fusionne, dont
  #1047, #1044, #1045. Aucune PR ouverte.

## 2026-08-03 → 08-05 — Marathon perf & fiabilité : mur mosaïque, certificats, châssis, playlists

Session très dense. Plusieurs défauts de fond trouvés sous des symptômes anodins, chacun masquant le suivant.

### ✅ Fait — fusionné et déployé

- **Mur mosaïque Streamlit** (PR #963, issue #958 close) — quatre défauts enchaînés :
  détection unifiée (3 applis vues sur 15 → **23 avec leur vrai port**) ; attente du rendu
  réel (les captures photographiaient le **squelette de chargement**, sélecteurs vérifiés
  dans les bundles Streamlit 1.50-1.55) ; budget de réveil configurable (30 s en dur alors
  que les réveils prennent **26 à 78 s**) ; `idle-check` qui rapportait `active=0` avec
  24 applis en cours → `active=17 would-stop=6`. **18 vignettes servies**, 0 auparavant.
- **Châssis partagé** (PR #972) — la barre globale recouvrait le contenu, et `sidebar.js`
  **supprimait** (`display:none`) les en-têtes de page : les boutons d'action de ~112 modules
  sur 143 disparaissaient. Mesuré : waf 13→18, crowdsec 10→12, wireguard 10→11.
  Corrigé par `--gmb-h` unique. **Était déployé à la main depuis la veille sans être fusionné** —
  un rebuild aurait tout régressé.
- **Certificats Let's Encrypt** — `sliders.maegia.tv` à **4 jours** de l'expiration, renouvellement
  automatique cassé depuis toujours : nginx servait `/usr/share/secubox/www`, certbot écrivait
  dans `/var/www/html`. Chaque challenge tombait en 404. Corrigé, `sliders` valide au 2 novembre,
  `money.maegia.tv` émis, 4 `webroot_path` alignés, **essai à blanc vert sur 5/5**.
- **Metablogizer** (PR #976 puis #978) — `GET /sites` forkait **2 `git` + 1 `du` par site**,
  soit +500 processus pour 172 sites : **502 après 43 s → 28 ms**. Puis les vignettes servies
  directement par nginx : **36,7 s → 0,2 s** pour le mur complet.
- **Torrent** (PR #966) — téléchargement ZIP en flux (jamais de fichier temporaire, l'eMMC pleine
  met la board en 502) ; vrai vecteur de traversée trouvé dans `file.path` **venant d'un pair
  distant**, pas dans l'URL. Noms de fichiers réels : `stream.js` ne posait aucun
  `Content-Disposition`, le navigateur nommait les fichiers d'après l'index numérique.
- **Jellyfin** (PR #965) — transcodage désactivé, remuxage conservé. Pas de `/dev/dri`, encodage
  logiciel sur 4 cœurs ARM en concurrence avec les `ffmpeg` de PeerTube : un film ne se lisait
  que par intermittence. Durable via `jellyfinctl playback`, TOML et minuterie.
- **Navbar torrent + ytsas** (PR #973) — pages sans châssis, culs-de-sac sans retour.
  torrent 4→16 éléments interactifs, ytsas 5→17. Catégorie `media` invalide corrigée.
- **Routes nginx d'administration** (PR #980) — ytsas et torrent sont LXC-natifs, aucune app
  côté hôte : leurs webui appelaient dans le vide. Routes empaquetées.
- **PeerTube playlists** (PR #983) — l'import traitait une playlist comme une vidéo unique.
  Worker unique, une vidéo à la fois, plafond 30 min/élément.

### ⬜ Next Up

- **Migration unités Streamlit par appli** — code fusionné, **non appliqué au conteneur**.
  `streamlit-all.service` (`Type=forking`, `MainPID=0`, `NRestarts=3`) relance le parc entier
  dès qu'une appli meurt : rien n'est endormissable, cause de fond de #946.
  ⚠️ **Ne JAMAIS `systemctl stop streamlit-all`** — son `ExecStop=pkill -f streamlit` tue tout
  le parc. Neutraliser par drop-in vidant `ExecStop`. Séquence en 6 étapes dans le rapport de #958.
  ⚠️ `secubox-streamlit-idle.timer` est **arrêtée à la main** — ne survivrait pas à un reboot.
- **Route metablogizer orphelines** — `nginx/metablogizer.conf` n'est pas installé par son
  `debian/rules` (constat de #980). Ne survit pas à une réinstallation.
- **`metrics` brûle 15 % de CPU en continu** — 1 thread, 8 h cumulées, 244 Mo, sans enfant ni
  connexion visible. Cause non établie. Préalable à la hiérarchie de priorités CPU.
- **Hiérarchie CPU déclarative** — flux > admin > observation, via `Nice=`/`CPUWeight=`.
  L'agrégateur doit rester réactif mais céder (directive user).
- **401 sur `/profiles/` et `/toolbox/`** — attend l'inspection réseau du navigateur :
  la requête porte-t-elle un `Authorization` divergeant du cookie ?
- **Branches prêtes non fusionnées** : Lyrion audio (#967), webllm (#969/#970).
- **13 applis Streamlit sans port**, 5 partageaient le 8501 (désormais refusé explicitement).
- **Page 502 soignée** (module endormi / réveil / socket absent) — #979 en attente.
- **Sessions : liste blanche + approbation à distance** (#975) — conception posée.
- **SOGo** en alternative à Horde, arrêté (#968) ; Zimbra écarté (pas d'ARM64, 8 Go RAM).

---

## 2026-07-30 → 07-31 — Marathon média/perf (release v2.16.0)

### ✅ Fait
- **Jellyfin LXC-native 2.0.3** (#938) — refonte, 5 biblios auto-wire, self-mint clé API (DB), routé, wizard, mode léger. apt-synced.
- **Torrent 2.2.8** — peg event-loop tué (no-seed@100% + reapIdle complets only), 0-pair fixé (retrait throttleUpload(0)), /add tolérant + upload fichier, `webtorrent-server.js`. apt-synced.
- **Résidus MITM Python virés** — toolbox-mitm(R2)/mitmproxy/waf-watchdog.timer disable + LXC stop ; sbxwaf+sbxmitm(Go) intacts. Board **load 97→~20**.
- **Concentrateur agrégateur 0.3.0** — forward `/api/v1/<mod>/`→`<mod>.sock` (jellyfin & co) ; fini les locations nginx par module.
- **YouTube SAS 0.1.2 (NOUVEAU)** — LXC yt-dlp+deno+EJS+cookies, SAS kept/éphémère/conserve→peertube, webui+cardlet 🎞️. Âge-restreint 720p téléchargé e2e. apt-synced.
- **Companion** — métriques mockup-parity + emoji état/type + cardlets torrent/jellyfin/ytsas ; **APK v1.2** (Android TV) SW v20.

### ⬜ Next Up (queue de fin de marathon)
- **502 brandé global** — les 2 tentatives ont cassé `nginx -t` (revert propre). Approche par-bloc-serveur soignée (script python balanced-brace + `nginx -t`).
- **Ré-import library torrent** — mes films effacés par erreur (fichiers intacts /data + visibles Jellyfin) ; seed local → régénère infohash/magnet.
- **Paquets enregistrent leur vhost dans haproxy.toml** (directive user) — tue le drift HAProxy ; déclarer aussi les 2 backends spéciaux (gitea_ssh tcp, toolbox_landing). Fin des hand-add jellyfin/ytsas.
- **Jellyfin** : auto-wizard 10.11 (création admin), intégration `users` (gk2/admin), catégorie photoprism (photos vs homevideos).
- **QoS dynamique + veille-sur-accès** + **watchdog circuit-breaker** (noter oops→alerte→pause, pas relancer) — cf. `project_resource_governance_vision`.
- **Companion QR pairing** (emoji central) + **WG tunnel** phasé — cf. `project_companion_qr_wg_distribution`.
- **Cible : split-box mesh** quand mesh-stable.

---

## 🚨 2026-07-28 : Incident gk2 — malware C2 + WAN injoignable (bug driver mvpp2 Linux, prouvé par U-Boot)

Session incident. Partie d'un diag réseau, a déterré une **backdoor** puis isolé la panne WAN au **driver mvpp2 Linux**.

- **Malware `notwork-monitoring` (#914)** — backdoor C2 Go x86-64 UPX (SHA `f2ca2b20…`), installée hors-dpkg le **2026-06-09**, beacon `5.182.207.11` (bunq-helpdesk.dns04.com, AS213250 bulletproof). **Inerte sur ARM64** (mauvaise arch → n'a jamais tourné) mais **tournerait sur l'amd64**. Contenue : disable+quarantaine chmod 000 + unit `.evidence` + **nft DROP** + bundle exfiltré en série (SHA vérifié) + alerte + draft Gmail. Mémoire `project_notwork_monitoring_c2_incident`.
- **WAN injoignable — cause = driver mvpp2 Linux, PAS le HW.** ARP-résout-mais-tout-unicast-mort (eth2 **et** lan0). Tout le soft éliminé (nft flush total, tc/DPI/offloads/conntrack/NAT/XDP/policy-routing), + cold-boot + câble neuf + reboot Freebox = rien. **Test décisif U-Boot (Tow-Boot)** : `setenv ethact mvpp2-2; ping 192.168.1.254` → **`host is alive`** → port/PHY/câble/Freebox **tous sains**. Playbook : `docs/FAQ-NETWORK-WAN-RECOVERY.md`. Fix candidat = **unbind/rebind mvpp2** (`f2000000.ethernet`) — à confirmer (box en fsck /data après `reboot -f`).

### ✅ Fait (suite incident, 2026-07-28)

- **WAN gk2 RÉSOLU + guard permanent** — cause = 3 couches empilées (flow-control + négo marginale via hub + route lan0 parasite). `secubox-wan-link-guard` (service boot + timer 30s) installé, idempotent. FAQ à jour. gk2 stable en ligne.
- **503 board-wide RÉSOLU** — `secubox-waf-ng` (sbxwaf) crash-loopait sur cookie-audit non-inscriptible ; chown → `secubox-waf`. Mémoire `project_sbxwaf_cookieaudit_503`.
- **Anti-rootkit #915 déployé + fonctionnel** (branche `feat/antirootkit-spec`, PR #916, 94 tests) — scanner alerte-seule live, panel `admin.gk2.secubox.in/antirootkit/`. Mémoire `project_antirootkit_deployed`.

### ⬜ Next (incident)

- **Reboot gk2 + analyse full runtime** (en cours) — vérifier que tout redémarre : WAN guard, anti-rootkit (1 seul daemon, scanner OK), 503-fix persistant, tous les `secubox-*`.
- **⚠️ Sweep IOC amd64 (192.168.1.9, x86-64 = la charge tournerait) + c3box** : `notwork-monitoring` présent ? beacon `5.182.207.11` actif ? Confirmer clé `deploy@server`. Vecteur ~2026-06-09.
- **PR #916 anti-rootkit** — revue finale whole-branch + merge user ; puis follow-ups v1.1 (integrity timer, backport WAN guard #913, enforce après tuning allowlist).

---

## ✅ 2026-07-26/27 : Trilogie « auto-centre » — release-rings + assist (fixes) + p2p-ephemeral (déployés gk2)

Grosse session : sous-projets 1-2 de la trilogie finalisés/durcis + déployés, plus le socle p2p éphémère (fondation escalade assist). Tous mergés master + déployés + vérifiés live.

- **release-rings (PR #909, annuaire 0.8.x→0.9.0 + secubox-release 0.1.0 NEUF, déployé)** : livraison progressive d'artifacts par rings `draft→internal→published` pilotés centre (grant `capability="release"`). 9 tâches SDD + revue opus. Revue finale a rattrapé la classe **author-vs-payload au substrat partagé `active_grants`** (un pair mesh forge un GRANT_ISSUE`{issued_by=victime}` avec sa clé) → fixé fail-closed (`_author`==issued_by), **durcit aussi Centres&Grants**. `current_ring` filtré souveraineté. Actuateur repo reprepro-copy (garde arm64) + actuateur box 4R + panneau `/releases`. Prérequis : distributions reprepro provisionnées `/data/apt/conf/distributions`. Route API = **location manuelle webui.conf** (dropin secubox.d inerte sur vhost admin — gotcha lyrion/billets).
- **assist — 3 fixes déployés** : (1) **socle session-resolvers author-binding (PR #910)** — même classe author-vs-payload (phantom-session DoS via `ASSIST_SESSION_OPEN{issued_by=victime}` fédéré) fixé (`_self_by`/`_selfcert_by`) ; (2) **join-link URL publique** — `secubox-assistctl joinlink` dérive le hub `https://admin.<sso_cookie_domain>` au lieu de `assist.local` (LAN-only) ; (3) **python3-websockets Depends→Recommends** — installe propre sur gk2 (pip websockets 16.0).
- **INCIDENT (résolu)** : déployer annuaire 0.8.1 (master) par-dessus 0.7.0 (assist-dual non-mergé) a **droppé `assist_match.py`** → assist API 502. Réparé en mergeant assist-dual→master (annuaire **0.9.0** superset). Leçon en mémoire : ne jamais déployer une lib partagée par-dessus une branche déployée-non-mergée.
- **p2p-ephemeral (PR #911, secubox-p2p 1.11.0 + secubox-assist 0.2.3, déployé)** : `secubox-p2pctl` (CLI root neuf) + iface `wg-ephemeral` persistante-silencieuse (10.11.0.0/24, udp/51825), peers WG scopés-session pour l'escalade assist, auto-révoqués (backstop TTL sweep). L'assist `join` **exec** enfin via `sudo -n`. 4 tâches SDD + revue opus MERGEABLE. Bonus sécu : sudo `env_reset` strippe les `P2P_*` (pas de substitution de faux `wg`). Installé via `--force-depends` (aiohttp/websockets fournis par pip). Iface up + silencieuse vérifiée live.

### ✅ 2026-07-27 : fleet-metrics — métriques centralisées+meshed (sous-projet 3/3, PR #912, déployé gk2)

Dernier de la trilogie. Chaque nœud signe un `MetricSnapshot` (vitals+santé+compteurs) dans un store dédié last-wins `self.json` (PAS le journal CSPN immuable) ; les pairs se tirent mutuellement sur `:8799` (`/fleet/self` public signé, mirror `/log/export`) ; panneau `/fleet`. 5 tâches SDD + revue opus. `secubox-annuaire 0.10.0`, 424 tests. Bloquant rattrapé en revue finale : le listener `:8799` (allow-list exact-match) n'exposait pas `/fleet/self` → pulls 403 (moitié meshed inerte) — corrigé + tests. Déployé+vérifié gk2 : `/fleet`=401 JWT, panneau=200, `:8799/fleet/self`=200, timer publie ~60s. **TRILOGIE COMPLÈTE** (Centres&Grants ✅ + assist ✅ + fleet-metrics ✅, tous déployés).

### ⬜ Next
- **fleet-metrics** : déployer aussi c3box + amd64 (les 2 autres nœuds mesh) ; **health-noise** — `metrics_collect` compte tout unit `secubox-*` non-active comme "down" (incl. oneshots/timers by-design) → filtrer sur état `failed` ; sources disk_pct/soc_alerts (=0 actuellement).
- **Fast-follow p2p-ephemeral** : câbler `cmd_close`→`escalate.teardown` (sweep-only, peer vit jusqu'au TTL ≤4h/reboot) ; caveat `env_keep` au sudoers ; **Phase 2** rendezvous HTTPS `/assist/join/<token>`.
- **Dette Depends pip-shadow** : `secubox-p2p` (aiohttp), `secubox-eye-square`/`secubox-soc-gateway` (websockets) → passer en Recommends (comme assist 0.2.2).
- **Prérequis deploy** : Freebox UDP/**51825** forward → gk2 (escalade externe réelle). reprepro `sync-repo` reste manuel (passphrase GPG).
- **Dette Depends pip-shadow** : `secubox-p2p` (aiohttp), `secubox-eye-square`/`secubox-soc-gateway` (websockets) ont le même hard-Depends absent sur gk2 → passer en Recommends (comme assist 0.2.2).

---

## ✅ 2026-07-25 : R-level MITM par peer wg-toolbox — off/passive/active/reel (PR #901, déployé gk2)

Niveau d'inspection MITM **par peer** sur le moteur R3 Go (`sbxmitm`), réglable dynamiquement, self-service borné + override admin. SDD 8 tâches (revue 2 étages + revue finale opus). Mergé, déployé, validé fonctionnellement live.

- **4 modes croissants** (`off` bypass nft < `passive` splice < `active` déchiffré < `reel` +enforcement). Effectif = `forced ?? clamp(chosen, floor, reel)`. Défaut/fail-safe passive ; **seed board = reel** (préserve le comportement actuel). Self-service peer authentifié par l'identité tunnel (borné par floor, ne lève pas forced).
- **Go** : `clampVerdict` **pinné-safe** (un splice-learned reste splice même en reel) branché au call-site `Decide` (2 chemins d'accept) ; `PeerPolicy` (join wg-peers ip→pubkey, hot-reload, fail-safe passive).
- **`off` = nft same-chain** : named set `@rlevel_off` + `ip saddr @rlevel_off return` **1ère règle de la même chaîne** que le DNAT (une table séparée ne bloque PAS le DNAT — bug noyau corrigé en revue).
- **ctl sans sudo** : le portail lance `sbxmitm-policyctl` directement (fichier portal-owned + CAP_NET_ADMIN déjà accordé) → **NNP=true préservé**, zéro réduction de durcissement (meilleur que le NNP=false initialement envisagé).
- **Escalade fermée** (CRITIQUES de revue finale) : `_is_public_kbin` (le router sert aussi le vhost public kbin, DNAT L4) + `_require_admin_source` (rejette une source peer tunnel). Panneau = délégation d'événements (pas d'inline XSS).

### ⬜ Next
- **Drift .deb** : la live api.py est patchée A' (no-sudo) mais le .deb 2.8.7 installé prédate → le merge rebuild en 2.8.8 réconcilie. Un reinstall du 2.8.7 régresserait — rebuilder depuis master.
- Enforcement `reel` = block existant honoré ; ban/rewrite temps réel = hooks à étoffer (hors périmètre v1).

---

## ✅ 2026-07-24 : Transparent `.onion` (wg-toolbox+LAN) + WPAD/DHCP autodetect (PR #900, déployé gk2)

`.onion` route de bout en bout pour les clients wg-toolbox/LAN, validé live (onion réel → HTTP 200). Consolidé dans `secubox-proxypac` (la branche `feat/tor-onion-pac` était un doublon, abandonnée). SDD 8 tâches + revue finale.

- **Transparent (primaire, sans PAC)** : Tor TransPort/DNSPort automap + Unbound onion-forward (`local-zone transparent` + `domain-insecure`, sinon NXDOMAIN RFC6761) + nft dnat `10.192.0.0/10`→`9040`. **`route_localnet` par iface** (conf.all ne s'applique pas aux ifaces déjà créées) — c'était le bloqueur silencieux ; sysctl.d reboot-persistant.
- **PAC/WPAD (fallback)** : autodétection de rôle passive + panneau réécrit ; règle onion repointée du SocksPort mesh (injoignable) vers le SocksPort LAN.
- **secubox-tor** : SocksPort LAN (**jamais** de SocksPolicy — globale, casserait le port mesh) + torctl.
- **Réparations prod** : `tor@default` down depuis le 10/07 (HiddenServiceDir 0750→0700) ; DNS LAN cassé par le changement DHCP (Unbound bind IP LAN).
- **Gotchas déploiement** : proxypac absent d'`aggregator.toml` → API 404 ; role.detect faux-master (DHCP eye-br0) → `role="slave"`. Client Firefox : `network.dns.blockDotOnion=false` + `trr.mode=0`.

### ⬜ Next (fallback, non-bloquant)
- Route HAProxy `wpad.gk2` (vhost `listen 80` vs nginx:9080) + MIME strict `/proxy.pac` sur le vhost admin (webui.conf n'inclut pas secubox.d). Le transparent primaire couvre le cas réel.

### 🧹 Issues clôturées (session 24-25/07)
#900/#901 mergées. Backlog nettoyé : **#471, #494** (parent /run/secubox systémique), **#745** (podcaster socket-race #761), **#735** (autolearn faux-positif), **#765** (lyrionctl status-probe), **#743** (egress hors-Tor #797). **#816** gardé ouvert (fix websockets opérationnel seulement, pas de garde source).

---

## ✅ 2026-07-23 : Image rpi400 — deps auth, `--kiosk` en CI, postinst mediaflow (branche fix/rpi400-auth-deps-and-kiosk → master)

L'image Pi 400 livrait un webui sur lequel on ne pouvait **pas se connecter**, et **pas de kiosk**. Les deux causes racines trouvées, plus deux bugs de packaging latents révélés au passage.

- **Login** : l'image rpi installe les debs en `dpkg -i --force-depends`, ce qui **court-circuite les Depends déclarés**. `secubox-auth`/`secubox-users` importent `argon2`/`pyotp`/`qrcode` au chargement → le daemon mourait à l'import → 502 nginx → `JSON.parse: unexpected character`. Fix : `pyotp`+`qrcode` dans `INCLUDE_PKGS`, `argon2-cffi` dans l'étape pip du chroot. **Seul le chemin force-depends est exposé** (mochabin va bien, apt y résout les Depends).
- **Kiosk** : `--kiosk` n'était pas atteignable depuis la CI → booléen `workflow_dispatch` → `build-image.sh --kiosk` → transmis à `build-rpi-usb.sh`.
- **Postinst mediaflow cassé sur CHAQUE install** : un commentaire contenait le token littéral `#DEBHELPER#`, que `dh_installsystemd` substitue **textuellement partout où il apparaît** → bloc systemd expansé au milieu du commentaire, `; kick one refresh` orphelin → `syntax error near ';'`. Masqué par le `|| true` de l'image, mais fatal dès que l'apt-get strict du kiosk fait une passe de configure. Bump `2.3.0-1~bookworm3`. **Règle : jamais le token debhelper dans un commentaire.**
- **Prompts conffile** : `DEBIAN_FRONTEND=noninteractive` gouverne debconf, **pas** le prompt conffile de dpkg → `/etc/secubox/mesh.toml` préexistant faisait EOF sur stdin fermé et avortait le build. Ajout `--force-confdef/--force-confold`.
- **Carte flashée et vérifiée** : chromium, openbox, `boot-mode=kiosk`, argon2, pyotp, mediaflow `bookworm3` — tous confirmés sur la carte (bit-exact + inspection contenu).

### ⬜ Next / bloqué
- **⚠ Le Pi n'a toujours pas de réseau** : il boote sur une console, affiche une IP mais ne pingue pas. **Piste n°1** : l'IP affichée est probablement celle du bridge isolé `eye-br0` (10.55.0.1/24, secubox-eye-remote) alors qu'`eth0` n'a jamais eu de bail DHCP → trancher avec `ip -br a; ip r` en console (root/secubox). **Piste n°2** (kiosk qui ne s'affiche pas) : `config.txt` a `gpu_mem=64` et **pas** de `dtoverlay=vc4-kms-v3d` → X n'a peut-être aucun driver d'affichage utilisable.
- **Restaurer `cmdline.txt.bak`** sur la partition boot de la carte : j'y ai retiré `quiet splash` (+ `loglevel=7`) pour diagnostiquer.
- Propager le fix mediaflow vers apt.secubox.in / gk2 (le bug touche toutes les installs, pas seulement l'image rpi).

---

## ✅ 2026-07-22 : secubox-meshtastic — nœud LoRa multi-grilles + écoute passive (#897, PR #898, v2.15.0)

Nouveau module natif-hôte faisant de SecuBox un nœud Meshtastic multi-grilles. Construit en subagent-driven development (13 tâches, revue 2 étages chacune + revue opus de branche). Mergé, taggé **v2.15.0**, déployé sur gk2.

- **Trois grilles composables par canal** : off-grid RF (P2P + relais), shared-grid privée via MirrorNet/WireGuard, on-grid MQTT public opt-in — toutes **bridgées côté hôte**, donc le daemon (et non le firmware) maîtrise l'egress, le WAF et la politique.
- **Écoute passive CLIENT_MUTE** : journal de paquets, recensement des nœuds entendus, stats de canal ; payload retenu si non déchiffré.
- **Webui** `admin.gk2/meshtastic/` (5 onglets, carte canvas offline-clean) ; API `/api/v1/meshtastic/*` sous JWT.
- **Bloqué matériel (#897)** : pas encore de radio → `radio: absent` géré proprement ; 61 tests 100 % mock. RAK4631 WisBlock EU868 recommandé.
- **Trois bugs de déploiement trouvés en live** : broker injoignable faisait crash-looper le daemon (0.1.1) ; **le postinst chownait `/etc/secubox` en root:root et cassait le login OTP** (0.1.2 — chmod uniquement, *jamais* chown les parents partagés) ; socket UDS obsolète bloquait le restart (0.1.3).

### ⬜ Next
- **Différé** : l'egress on-grid n'est pas réellement contenu (OUTPUT en `policy accept` à l'échelle du dépôt) → approche à base de DROP nécessaire ; réconcilier le port broker par défaut (8883 vs 1883). Voir spec §11.
- Validation RF réelle EU868 à l'arrivée du matériel (#897).

---

## ✅ 2026-07-21 : Scale-to-zero services publics (#896) + UX de réveil 2-phases (branche feat/scale-to-zero-public-services → master)

Services on-demand : **sommeil si inactif, réveil à l'accès**, politique lifecycle par module, splash "terminal virtuel". Intègre aussi #893 (robustesse actionneur profils).

- **Fait** : lifecycle/wake_class (manifeste + setter panel webui→ctl), actionneur état-observé, **mémoire durable des routes portail** (réveil restaure la route WAF — round-trip prouvé live sur yacy), waker (phase 1) + sleeper (idle), déclencheur sbxwaf-side, **splash phase-2 nginx** (`error_page` sur backend qui boote) généralisé à tous les vhosts on-demand via `nginx-sync` (5 câblés live). Fix infra : worker@ WAF crash-loop re-chownait `/run/secubox` → désactivés.
- **Merge + release** : branche mergée sur master, issues #896/#893 fermées, bump + artefacts CI, sync debs → gk2, image rpi400.

### ⬜ Next / follow-ups
- **WAF-drift reconcile** : perms cookie-audit (workers crashent) + retirer `RuntimeDirectory=secubox` du unit WAF ; **décision cutover** (fan-out worker@ hardened vs formaliser l'unité intérimaire). Board workers désactivés.
- **Ré-activer secubox-sleeper** sur un service on-demand opt-in + observer un cycle idle→sleep→wake réel.
- Backport du câblage phase-2 par-vhost dans l'outillage vhost ; #895 (DNS via vortex).

---

## ✅ 2026-07-19 : Profils Phase 2 — `Requires=secubox-core` → `Wants=` (branche feat/profiles-phase2-core-wants)

Retrait de la cascade dure sur `secubox-core.service` (Type=oneshot mkdir+chown, RemainAfterExit) : un `Requires=` sur ~108 units les cascade-stoppait tous si core redémarre/échoue (ex. upgrade du paquet secubox-core) = thundering-herd. `After=` garde l'ordre, `Wants=` garde la dépendance souple **sans** la cascade. Prérequis de l'apply de masse natif (Phase 3).

- **Source** : 91 units (`packages/*/{debian,systemd}/*.service`) + 2 scaffolds (`new-module.sh`/`new-package.sh`) convertis → les futurs modules naissent en `Wants=`. Chaque ligne `Requires=` était core-only ⇒ sed 1-ligne sûr.
- **Live (Option A, sans herd)** : 162 units installés sed en place + `systemctl daemon-reload` — **aucun restart**. Board saine (admin/billets 200). Cascade retirée immédiatement.
- **Release** : bump minor sur les 87 paquets affectés → CI build + publish apt.secubox.in.

### ⬜ Next
- **Phase 3 native mass-apply** désormais débloqué (le cascade-stop ne peut plus entraîner d'autres units).
- **Réconciliation boot** (`secubox-profile-apply.service`, décidée enforce/auto-apply).
- **Surfaces API/panel/Companion profiles** + sudoers scopé (guideline webui→ctl).

---

## ✅ 2026-07-17 : Sessions auditables + Companion auth/system/metrics + billets hashtags emoji (branche feat/sessions-companion-emoji)

Sessions traçables, les 2 modules Companion stubs deviennent réels, billets gagne les vues rapides par hashtag emoji. Live-vérifié gk2. Détail dans HISTORY.md.

- **Sessions (root-cause)** 🔑 — `/login/mfa` + `/totp/confirm` codaient en dur `"ip": ""` (et pas d'UA) ; seul le chemin mot-de-passe les captait. **admin est forcé TOTP ⇒ tout login admin réel passait par MFA** → lignes de session non auditables, onglet Sessions de la webui users (déjà complet) affichait du vide. Fix `_client_meta(request)` (X-Forwarded-For d'abord : nginx/HAProxy sont devant, `request.client.host` = le proxy). Prouvé en pilotant le vrai handler `/login/mfa` en-process (fichier sessions temporaire) : `ip=192.168.1.77` + UA complet.
- **Companion auth + system** ⚙️ — 2 stubs de 34 lignes qui devinaient les routes (`/api/v1/auth/users` → **404** ; les identités sont sous `/api/v1/users`). Reconstruits sur les routes lues dans le source. auth = identités + **sessions (qui/IP/device/âge/courante)** ; system = status/metrics/resources/health_score/network/security, chaque section dégradant indépendamment.
- **Metrics emoji** 📊 — `core/metrics.js` : seuils **par type** (disk le plus strict, cpu tolérant) ⇒ disk 94.5% = 🔴 / cpu 10% = 🟢 ; langage simple ("Memory 75% — 5.5 GB of 7.7 GB used").
- **Billets hashtags emoji** 🏷️ — migration 0004 (`tag`+`billet_tag` indexés) ; tags **extraits du corps** (`#secu`) ⇒ zéro effort auteur + rétroactif : le backfill a taggé **37/46** billets. Slugs sans accents (#Réseau==#reseau), emoji stocké (pas de restyle silencieux), ancres d'URL non taggées, tag inconnu = badge neutre. Vues rapides `?tag=` sur `/` + `/feed.json` (EXISTS, pas JOIN → pagination keyset non dupliquée ; le pager garde le tag).
- **Résumés du feed** 📄 — billets longs = extrait court + "Lire la suite" ; courts = entiers (16/20 résumés en live).
- **`GET /admin/api/billets`** — liste d'authoring : le feed public ne peut pas la servir (son `id` est une URL permalien → **cause des 404 Edit/Delete**, et il masque les drafts).
- **Companion re-login 401** 🔓 — les tokens box vivent 24h mais le Companion scelle le sien au pairing et le réutilise → le lendemain tout 401 sans issue ("Failed: unauthorized" billets + podcaster). `api.js` déclenche la ré-auth et **rejoue la requête une fois**, single-flight (1 prompt), donc un write en cours (un billet tapé) n'est pas perdu. SW v10.

### ⬜ Next / follow-ups
- **Rebuild `.deb` billets** (migration 0004 + `services/tags.py` + postinst .pth).
- **Refresh token** : éviter la re-login toutes les 24h sur le Companion.
- ✅ **APK rebuild fait** : republié le 17/07 (SW v11, peertube, upload, re-login 401). Recette : `JAVA_HOME`=JBR Android Studio (le JDK système n'a pas `jlink`), `cap copy` (pas `sync`), gradle **8.9-bin**. Signer debug **inchangé** (`5e6163f9…`) → install par-dessus sans désinstaller. Ancien APK conservé en `.apk.prev`. `android/` est désormais versionné → build reproductible ailleurs.

---

## ✅ 2026-07-17 : Billets — API admin JWT + authoring/upload Companion (branche fix/companion-billets-feed)

Companion devient un vrai client d'écriture pour le micro-blog billets. Live-vérifié gk2. Détail dans HISTORY.md.

- **API admin JWT** 📝 — nouveau `api/routes/jwt_admin.py` : surface JSON JWT-authed (`require_jwt` : Bearer OU cookie `secubox_session`), parallèle à l'admin HTML session, **réutilise le même repo/media**. `POST/PUT/DELETE /admin/api/billets`, `POST /admin/api/billets/{id}/media` (multipart, EXIF-strip), `GET /admin/api/comments` + approve/delete. No-op si `secubox_core` absent.
- **Fix venv (packagé)** — le venv isolé billets ne pouvait pas importer le `secubox_core` géré par `.deb` ; postinst pose un `zz-secubox-system.pth` trié-dernier (append dist-packages, wheels venv prioritaires — fastapi/pydantic non shadowés). Backport du hotfix board.
- **Module Companion billets** — EP → `/feed.json` + `/admin/api/*` ; éditeur gagne un champ image uploadé après création du billet ; SW v6→v7.
- **Vérifié live gk2** — JWT minté en user `secubox` (résolution `_secret()` identique au service) : create → feed (30 items), upload PNG valide → `{url, thumb}` (PNG corrompu correctement 415), delete — tous 200.

### ⬜ Next / follow-ups
- **Merger** `fix/companion-billets-feed` ; rebuild `.deb` billets pour livrer le postinst .pth aux installs neuves.

---

## ✅ 2026-07-17 : WAF (webui + autoban→firewall + analyse) + Nextcloud rework (PR #866, #867 mergées)

Deux dashboards refaits cyan, un gros trou de contrôle WAF colmaté, module Nextcloud réparé. Live-vérifié gk2. Détail dans HISTORY.md.

- **WAF webui** 🛡️ — dashboard sbxwaf restylé cyan hybrid-skin (cartes emoji, pulse live, refresh réactif) ; endpoints préservés ; rend la donnée live (198k threats).
- **WAF autoban→firewall** 🔥 (PR #866) — le bridge CrowdSec était **silencieusement OFF** (unit passe `--crowdsec-url` mais pas `--crowdsec-jwt-file` → branche 'disabled' → `Report()` jamais appelé). 198k threats, ~0 ban réel (un IP a tapé 36 881×). Ajout `CscliReporter` (`cscli decisions add` = vrai drop nft bouncer, le chemin du ban manuel qui marche) + dedup 5-min par IP (anti-storm `signal: killed`). Rebuild arm64 + deploy. Prouvé : 5 hits honeypot → 1 seule décision.
- **WAF analyse efficacité** 📊 — détection forte / contrôle faible (2 bans seulement) ; ~26% du pattern-matching (voip/xmpp = 39/149) inutile en HTTP ; top /24 = 26% du volume. Fixes classés.
- **Nextcloud** ☁️ (PR #867) — `/nextcloud/` montrait Stopped/vide : probe status cassé (lxc-info/occ **sans sudo** + lxc_path `/srv/lxc` vs `/data/lxc` ; seul `sudo nextcloudctl` est permis ; **`NoNewPrivileges=yes` bloquait sudo** — gotcha wireguard). Fix : port-probe privilege-free + ops via `sudo nextcloudctl` (occ passthrough) + **cache daemon-thread 60s** (le startup uvicorn ne firait pas) + web_url public. Webui restylé cyan. Vérifié : running v32.0.10, 2 users, 5.8G.

### ⬜ Next / follow-ups
- **WAF efficacité #2–4** : bans subnet/ASN (le /24 = 26%), skip voip/xmpp en HTTP (26% de regex), ne plus logguer les IP déjà bannies.
- **Backport Nextcloud** : drop-in `NoNewPrivileges=false` + `[nextcloud] domain="nc.gk2.secubox.in"` dans le paquet (secubox.conf/unit).
- **#862–#864** toujours ouverts (provisioning mail, ACME wiring, vendorer ident_switch).

---

## ✅ 2026-07-16 : Mail overhaul + fix auth systémique + DPI exfil/regen (PR #865 mergée, #862–#864)

Session multi-fix, **live-vérifiée sur gk2**, portable mergé (PR #865). Détail dans HISTORY.md.

- **Auth (systémique, fleet-wide)** 🔑 — `require_jwt` : un Bearer périmé (vieux `sbx_token` localStorage) shadowait le cookie session valide → **boucle login sur tous les panels**. Fix : Bearer **puis** cookie. Prouvé (Bearer périmé + cookie valide → 200).
- **Mail** 📧 — reset gk2-only ; **mailbox réparée** (ownership idmap → host `105000`) ; **submission 587/465** (SASL dovecot + vrai cert) ; **status TCP-probe** (fini les "Stopped" faux) ; domaine → `gk2.secubox.in` ; **webui reskin cyan** ; **`/user/password`** réparé (écrivait un fichier non lu) ; Roundcube **`password`** (self-service) + **`ident_switch`** (Gmail externe, vendored).
- **DPI** 🔍 — `/exfil` sert le cumulatif (**7 devices**, "no devices" corrigé) ; moteur = `secubox-dpi-flowcap` (plus netifyd) ; **webui régénéré cyan**.
- **openclaw** 🕷️ — CT lookup fallback certSpotter.
- **ACME HTTP-01** 🔒 — câblé live (nginx `:8880` + route HAProxy) ; émission LE marchait pour aucun vhost WAF-routé.

### ⬜ Next / follow-ups
- **WAF webui rework** 🛡️ — en cours (sbxwaf, cyan hybrid-skin, live 198k threats) ; + **analyse efficacité triggers/control** demandée.
- **#862** provisioning mail (submission SASL, chown idmap 105000, users.sh maildir brace/path, helper self-service password) — backport paquet.
- **#863** ACME wiring (nginx `:8880` + route HAProxy + certs webroot) — backport paquet.
- **#864** vendorer `ident_switch` + schéma SQLite dans `secubox-mail`.
- Rappel : mot de passe mailbox gk2 = `Gk24@SECUBOX;001`.

---

## ✅ 2026-07-12 : metalogue — suite OSINT Maltego-style en modules LXC (#845)

Deux modules OSINT construits (subagent-driven + revue adversariale), déployés **et installés** sur gk2, mergés (#846–#850). Détail complet dans HISTORY.md. Voir [[Metalogue]] wiki.

- **secubox-maigret** 🔎 — collecteur d'identité (pseudo → comptes sur 3000+ sites). LXC 10.100.0.42, CLI wrappé par une API host (job async, cap 3 lookups, 429), passif-only, JWT + audit. **Installé + fonctionnel** (lookup `torvalds` = vrais comptes).
- **secubox-spiderfoot** 🌀 — moteur d'automatisation (200+ modules passifs + graphe corrélation = hub Maltego intérimaire). LXC 10.100.0.43. **Installé, UI live à https://spiderfoot.gk2.secubox.in/** (proxy à la racine, LAN-gated ; le subpath `/spiderfoot-ui/` heurtait le SPA portail → vhost dédié zigbee/lyrion pattern + route sbxwaf + ACL HAProxy).
- **Rapport PDF stylisé** (maigret) — raw → dossier formel SecuBox (masthead, bloc métadonnées CONFIDENTIAL, §1 Résumé, §2 Findings en table cohérente zébrée/colorée par catégorie). `GET /lookup/{id}/report.pdf` (JWT, off-loop) + bouton 📄 PDF. fpdf2.
- **2 root-causes corrigés (install)** : (1) `ip_forward` dérivé à 0 → aucune sortie internet des LXC (tous, openclaw inclus) ; restauré `sysctl --system`. (2) deps arm64 sans wheels → **piwheels** (17min-fail → 2min-ok). Backportés dans les `<mod>ctl`.

### ⬜ Next / follow-ups
- **P3 OpenCTI** (hub graphe Maltego) — différé sur nœud amd64/dédié (stack ES trop lourde pour gk2, ~1.5 Go libre).
- **ip_forward reset runtime** : qqch remet `ip_forward=0` après boot malgré le drop-in zz — investiguer (récurrent, casse la sortie des conteneurs).
- **Ré-activation sur image neuve** : l'expo publique SpiderFoot (route sbxwaf + ACL HAProxy + nft :9043 + snippet exposure) a été câblée **live** ; le paquet livre les vhosts mais un re-enable opérateur est requis au flash.
- **Self-registration aggregator.toml** : maigret/spiderfoot ajoutés à la main dans `modules=[]` (comme openclaw) ; le paquet ne s'auto-enregistre pas.

---

## ✅ 2026-07-10 : WireGuard — refonte WebUI + fix avalanche perf + purge peers (secubox-wireguard 1.0.3)

`/wireguard/` était inopérant + bruyant. Corrigé end-to-end (board + source), **commits sur master** (poussés). Détail dans HISTORY.md.

- **Privilège** : API (secubox) lit l'état WG via `sudo -n wgctl` (root requis pour `wg show dump`) ; sudoers scellé + `visudo`, unit `NoNewPrivileges=false` (bloquait sudo).
- **Avalanche perf (load 56 → board starved)** : `wgctl status`/`peers` faisaient ~8 subprocess **par peer** → 30s+ sur le tunnel wg-toolbox (542 peers) ; `asyncio.wait_for` ne tuait pas l'enfant → zombies. Fix : passes uniques `wg show dump`/awk (542 peers 30s→0.07s), kill-on-timeout, cache single-flight.
- **Sécurité (revue)** : le passage sudo activait une fuite de clé privée tronquée dans `_parse_wg_show` (parse all-dump par nombre de champs, ne lit jamais la privkey) ; handlers WebUI en `data-*`+délégation (plus d'interpolation onclick).
- **WebUI** : dashboard cartes-interfaces (rôles 🧰🕸️🛡️, status live, drawers peers lazy, up/down + add-peer/QR), skin certs + navbar partagée. Grands tunnels = peers **connectés seulement** par défaut (toggle "Show all").
- **Purge wg-toolbox** : 543 peers dont **540 jamais connectés** (R3 enrôle 1 peer/navigateur dans `/var/lib/secubox/toolbox/wg-peers.json`, re-appliqué au boot par `secubox-toolbox-wg-restore`). Store sauvegardé, purgé runtime+store aux 3 clients vivants.

### ⬜ Next / follow-ups
- **Reskin `/users/` en hybrid-skin (certs/wireguard) + doc "WebUI Panel Guidelines"** — demandé, en cours (users utilise crt-light light-green, à convertir dark-cyan).
- GC `secubox-toolbox` : timer purgeant les peers wg-toolbox sans handshake > N jours (sinon ré-accumulation).
- Merger PR nextcloud #429 (attend restauration gh auth).

---

## ✅ 2026-07-06 → 07-07 : Sentinel — moteur de menaces, activation, 3 surfaces + C2 auto-learn (#821 #823–#828)

Toutes mergées + déployées + validées live gk2 (sauf #828 en attente de merge, déjà déployé). Détail complet dans HISTORY.md.

- **#821/#822 Frigate NVR foundation** ✅ MERGED (podman-in-LXC amd64/OpenVINO).
- **#823/#824 moteur Sentinel** ✅ MERGED (dark) — gate IOC inline + daemon async `sbx-sentinel` (bbolt, YARA build-tag), packs spyware commercial (Pegasus/Predator/Intellexa), report-only.
- **#825 activation + 3 surfaces** ✅ MERGED — onglet WebUI **🛡️ Sentinelle** (flotte) + onglet **Compromission** rapport kbin + section **PDF**. Live gk2, e2e prouvé. Fix clobber `RuntimeDirectory=secubox` sur `/run/secubox` (drop-in).
- **#826/#827 C2 auto-learn** ✅ MERGED — apprentissage beaconing haute-précision (gate allowlist + multi-signal rare/non-browser-JA4/DGA + candidate→confirm ≥3 fenêtres/≥30min), `/c2/*` + vue **C2 appris** + bouton **Ignorer**. Report-only.
- **#828 fix faux-positif C2** ⏳ **OPEN (PR #828)** — dashboard admin appris sur rareté seule → exige désormais un signal FORT (`dga`/`non_browser_ja`), `rare` = support seul. Déployé board (toolbox-ng 0.1.31), validé live (vrai C2 appris, dashboard+mail supprimés).

### ⬜ Next / follow-ups
- Merger **PR #828** (aligne master 0.1.31 = board, ferme la dérive).
- Peupler `browser-ja4.txt` (seed vide → `dga` seul signal fort out-of-box ; besoin de vraies empreintes JA4 navigateur capturées).
- Optionnel : activer `secubox-sentinel-feeds.timer` (détection C2 réelle via overlay MVT/CitizenLab/abuse.ch — opt-in opérateur).
- Audit-log append-only pour les mutations `/c2/allow` (convention CSPN).

---

## ✅ 2026-07-03 → 07-04 : ToolBox — rapport vie privée fidèle + media types + fiche de personnage (#785 #790 #792)

Trois features (brainstorm → spec → plan → SDD subagent-driven, revue two-stage +
whole-branch adversariale), **toutes mergées sur master**, déployées + validées live gk2.

- **#785 — PDF kbin fidèle à la page web + media types + WebUI DPI** ✅ MERGED (PR #787).
  Onglets DPI-Exfil (me) + Overall en **donut-grids** matplotlib (fini les puces) ; bloc
  **🎬 media types** (MIME réels capté sbxmitm + catégorie DPI `media`), me+overall, PDF+web ;
  `secubox_core.media_catch` (tail-read borné, fail-empty) ; 2 cards WebUI DPI + endpoint
  `/media_types`.
- **Incident déploiement** ✅ résolu : rendu PDF matplotlib **sync sur l'event-loop** du
  worker unique + tempête auto-retry de la page 504 WAF → 504 board-wide. Durci (live+source) :
  threadpool + asyncio.Lock (pyplot pas thread-safe) + **cache PDF par device** (double-check →
  1 rendu par tempête) + **MPLCONFIGDIR** persistant.
- **#790 — fiche de personnage riche + parité routes** ✅ MERGED (PR #794). Fiche PDF fidèle
  à la carte `.nr` : ⚡ pips `●●●○○○`+notes, 🎒 inventaire ✓/✗, 🐉 bestiaire, ⚔️ Quêtes/menaces.
  `_enrich_report_data` factorisé → `/report/{token}` + `/admin/.../report` = même PDF riche
  que `/report/me` (avant : PDF nu). Full-fpdf.
- **#792 (replié dans #790) — Quêtes réelles** ✅ CLOSED. `_dpi_stats` expose `alerts_raw`
  (kind/service/dst/detail) → les menaces montrent destination + détail (`🗡️ NEW CLOUD — AWS S3`)
  au lieu d'un « — » orphelin, côté HTML + PDF.

Wiki : nouvelle page **[[ToolBox]]** (cas d'usage cabine numérique + features rapport). 202
tests toolbox verts. Backups board `/root/backup-785-*` + `/root/backup-790-062856`.

---

## ✅ 2026-07-04 : Zigbee WebSocket (#796 · PR #805) + PeerTube admin ops (#798 · PR #800/#804)

- **#796 — sbxwaf laissait tomber les upgrades WebSocket** ✅ FIXÉ + live, **PR #805 ouverte**.
  `wss://zigbee.gk2.secubox.in/api` cassait (close 1006 + boucle de reconnexion) alors que
  `http://10.100.0.111:8080` LXC-direct marchait. 3 couches : `main.go` forçait `Connection: close`
  écrasant `Connection: Upgrade` ; `statusRecorder` + `cachingResponseWriter` n'implémentaient pas
  `http.Hijacker`. Fix : `isWebSocketUpgrade()` + `Hijack()` forwardé sur les 2 wrappers + log
  d'erreur upstream (qui a épinglé la couche Hijacker). `websocket_test.go` neuf. Live gk2 :
  `wss://zigbee → 101 Switching Protocols`, dashboard stable. `go test ./cmd/sbxwaf/` vert,
  merge propre avec master.

- **#798 — PeerTube WebUI admin ops** (reset-password + version check + upgrade) ✅ MERGÉ (PR #800),
  spool→root (#407) : API non-privilégiée dépose un intent, `peertube-ops.path` root le draine via
  `peertubectl` (pas de sudo, NoNewPrivileges intact). **Bug de boucle corrigé, PR #804 ouverte** :
  `.path` surveille `OPS_DIR` en `DirectoryNotEmpty=` mais `process-ops` écrivait les résultats
  DANS `OPS_DIR` → jamais vide → `.path` re-déclenche `.service` en boucle → `start-limit-hit`
  tue le mécanisme après la 1re op. Fix : résultats dans `/run/secubox/peertube/results/` dédié ;
  `ops/` se vide après drain. Vérifié live gk2 (2 pings consécutifs drainent, `NRestarts=0`,
  résultat `root:secubox 0640` lisible secubox). Delta `main.py` posé en préservant les 4 endpoints
  async board.

> ℹ️ Session parallèle : `secubox-toolbox-autolearn` (miroir splice-learned → bypass webui
> MITM) + rename « WAF Filters → Filtres MITM » commités hors session sur master (`872be8c7`).

### ⬜ Next Up ToolBox (déféré, non bloquant)

- **#786 — double-caching de l'agrégation media-catch** : `/media_types` + `_media_stats`
  agrègent le JSONL par requête (borné mémoire par tail-read, mais pas de cache 60 s comme la
  règle CLAUDE.md). Option préférée : sbxmitm émet un `media-stats.json` pré-roulé. Dormant
  hors R3/R4.
- **Cosmétique HTML Quêtes** : double-espace quand une menace a un détail mais pas de destination.

---

## ✅ 2026-07-02 : P2P évolutions — DHT + Federation + Master-link LIVE sur le mesh 3 nœuds (#774 · PR #775)

Reprise et refonte propre du chantier P2P (le code Mistral non-intégrant a été supprimé),
puis construction **subagent-driven TDD** (17 tâches, 132 tests, revue par tâche + revue
finale opus). Branche `feature/p2p-dht-federation`, **PR #775 ouverte**.

- **Kademlia DHT custom** — asyncio/UDP `:51823`, records de joignabilité signés Ed25519
  `{did,id_pubkey,wg_pubkey,endpoint,ts,sig}`, lookup itératif α-parallèle, persistance
  routing, store `put_health`/`get_health`.
- **Federation health-checks** — probe aiohttp GET `/health` + fallback TCP, debounce
  up/down, publication via DHT.
- **Master-link hiérarchique** — UDP `:51824`, élection déterministe `(priorité, node_id)`,
  failover par *term* monotone avec tie-break (pas de fenêtre zéro-master), heartbeats
  signés Ed25519.
- **OPAD** — feature-flag OFF par défaut ; config `/etc/secubox/p2p.toml`
  `[dht]/[federation]/[masterlink]`.

**Live-activé sur les 3 nœuds** : gk2 `10.10.0.1` (MASTER, term 1, prio 10) · c3box
`10.10.0.2` + amd64 `10.10.0.3` (satellites). Chaque DHT découvre les 2 autres (peers=2),
pas de split-brain. Déployés aussi : **onglet Mesh viz** du dashboard p2p, **fix du rebond
de login** (3 box), **nginx gk2** re-routé `/api/v1/p2p/` → `p2p.sock` (l'endpoint reflète
le vrai daemon), **nft reboot-persist** `wg-mesh udp {51823,51824}` (c3box+amd64).

> Poster de synthèse + roadmap détaillée : `docs/P2P-EVOLUTIONS-POSTER-PROMPT.md`.

### ⬜ Next Up (roadmap P2P, non bloquant)

- **Pont bans mesh → moteur sbxwaf** — les bans fédérés (threatmesh #768) s'appliquent au
  nft (`inet secubox_meshban`) seulement ; les faire alimenter sbxwaf via
  `cscli decisions add --ip X -R "secubox-mesh" -d 4h` (anti-boucle : filtre *reason*
  `secubox-mesh` dans `secubox-threatmesh-bridge`).
- **macroctl sur satellites** — `secubox-p2p` standalone tourne `NoNewPrivileges=yes` ⇒
  `sudo macroctl activate` refusé ; OK sur gk2 (aggregator NNP=no). Fixer le chemin
  privilégié satellite sans casser le durcissement.
- **Fenêtre transitoire du socket p2p** — 502/504 webui satellite pendant un restart de
  `secubox-p2p` (recréation `p2p.sock`) ; lisser (socket-wait / `RuntimeDirectoryPreserve`).

---

## ✅ 2026-06-30 → 07-01 : Substrat de confiance Gondwana — fédération + registry + macros (#766 #769 #771)

Trois features complètes (brainstorm → spec → plan → SDD subagent-driven avec revue
adversariale), **toutes mergées sur master**, déployées gk2 + c3box, prouvées live :

- **#766 — annuaire fédération sans-confiance (0.2.0→0.3.x)** ✅ CLOSED/master.
  `ingest_offer` impose `did_from_pubkey(pubkey)==provider` avant la vérif sig
  (auto-certifiant, aucune confiance préalable) ; offres portent `sig`+`signer_did`+
  `provider_pubkey` ; verbe `genesis()` + CLI `annuairectl` (init/whoami/status/offer/
  services/pull) ; écouteur mesh (postinst, IP-mesh only, `ip_nonlocal_bind`, validate-or-
  revert). Live : un 2e nœud (fondateur distinct) `annuairectl pull` → ingest sans-confiance.
- **#769/#770 — p2p Service Registry = vue live du catalogue annuaire (secubox-p2p 1.8.0)** ✅
  MERGED. `/services` fusionne catalogue annuaire + abonnements + overlay d'activation +
  services p2p-locaux ; « Auto register all » (active locaux + s'abonne aux distants selon
  auto/pending) ; s'abonne EN TANT QUE nœud (clé 0600). Live gk2+c3box.
- **#771/#773 — sous-système macro + tor-exit (secubox-macro 0.1.0 NEW, p2p 1.9.0, annuaire 0.3.3)** ✅
  MERGED (+#772 auto-fermé). Un service propose une **macro d'accès** vettée, confinée
  AppArmor : `macroctl` dispatcher root (allowlist kind, tamper-guard plugin, euid env-pin,
  audit append-only) + `macros.d/tor-exit` (nft SOCKS-over-mesh grant/revoke) + sudoers
  (env_reset) + auto-détection table firewall (`secubox_filter`|`filter` via
  `/etc/secubox/macro.conf`). Endpoint grant p2p (auth Subscription auto-signée, self-cert,
  auto-mode). **Démo live end-to-end** : gk2 propose son exit Tor → fédère → c3box s'abonne+
  active → pull grant sur le mesh → gk2 nft-autorise l'IP mesh de c3box → **c3box route via
  l'exit Tor de gk2** (`IsTor:true`). La boucle de revue SDD a attrapé ~10 Criticals avant merge.

### ⬜ Next Up (déféré, non bloquant)

- **Liaison NIZK/PSI GK·HAM** — les verbes annuaire utilisent encore les stubs documentés
  (`ZKP-HAM-v1`) ; brancher `zkp-hamiltonian` cffi.
- **Nouveaux kinds macro** — `wg-relay`, `dns-resolver`, `http-mirror` (chacun = un plugin
  `macros.d/<kind>` vetté + profil AppArmor, même framework).
- **Macros en mode `pending`** — nécessite la fédération cross-nœud des Subscription/APPROVE.
- **Mesh gk2→c3box (sens inverse)** — pull satellite→master OK ; master→satellite bloqué
  (nft c3box) ; + installer Tor sur c3box pour un provider tor-exit natif.

---

## ✅ 2026-06-27 : c3box → SecuBox Debian — première install réussie · netboot prouvé (#748 #737)

### ✅ Fait (session 2026-06-27)

- **Netboot gk2→c3box prouvé** — factory U-Boot 2020.10 → TFTP → rescue shell installeur
  (kernel 6.12.85 #5secubox). Détour cabling résolu (impasse LAB, pas logiciel).
- **Première install SecuBox Debian sur un MOCHAbin physique (c3box)** — image CI artefact
  `secubox-mochabin-bookworm` (run 27426515472, 8 Gio), SHA256 + signature vérifiés,
  `gunzip|dd` en RAM → eMMC. c3box boot Debian v1.9.0 avec stack complète.
- **boot.scr workaround déployé** — extlinux.conf charge le kernel à `0x02080000` (réservé
  factory U-Boot → reset). Construit `/boot/boot.scr` (kernel@`0x0a000000`) ; auto-boot
  Debian sans intervention vérifié après reboot.
- **#748 bloquant documenté** — ciseau U-Boot : mochabin board UNIQUEMENT dans fork Tow-Boot
  2022.07 (pas de `wget`) ↔ `wget` UNIQUEMENT dans stock ≥2023.07 (pas de board mochabin).
  Branche `feature/748-enhanced-tow-boot-http-netboot-serial-fl` parkée (spec+CI+Kconfig en
  place, dépend du backport wget OU port board mainline).

### ⬜ Rig netboot temporaire gk2 à démonter (quand c3box autonome)

- `lan1=192.168.77.1/24` avec dnsmasq DHCP + `nft iif lan1 accept` + nginx `:8099` encore actifs.
- À retirer une fois c3box en prod (voir TODO T5 — teardown rig).

### ⬜ Bootloader propre à faire (#748 ou alternative)

- boot.scr = workaround ; fix durable = enhanced Tow-Boot (#748, bloqué ciseau) OU corriger
  les adresses de boot dans l'image (extlinux.conf → `0x0a000000`). Voir TODO T5.

---

## 🗂️ 2026-06-22 : triage issues (30 ouvertes → revue obsolètes)

- **Fermées (user-validé 2026-06-22)** : #722 (nDPId — décidé contre, reverté) ·
  #475 ToolBoX Phase 1 (live 2.7.x) · #502/#507/#508 Social mapping (carto +
  /social/me + report PDF live) · #495 Phase 5 mitm-LXC (superseded par #662 Go
  sbxmitm host) · #531 APK one-tap (superseded par #685/#686 non-root) ·
  #486 geoip/ASN+flags+catégories dans rapports (livré master : geo.py + dpi_class.py +
  report wiring ; complémentaire de #718 ASN collector ; worktree stale nettoyé) ·
  #515 CDN detection (live `social_host_meta.cdn_vendor`) · #516 anti-bot detection
  (live via #564/#565) · #519 enforcement plane (livré + **réparé** : blacklist-sync
  avortait NXDOMAIN + timeout unit → fix `|| true` + TimeoutStartSec 600, vérifié live,
  default-off ; inclut #522). Toolbox source bumpé 2.7.18 (fix live-patché sur gk2) ·
  #468 /etc/secubox traversal (source+live = 0755, secrets/CA enfants restent 0750).
- **Actives (worktrees en cours)** : #655 webext banner · #615 security-posture ·
  #494 secubox-core ExecStart · #498 Phase 7 WAF enforcement · #485 SOC scoring.

### 🔎 Reco T0 — recon live gk2 2026-06-24 (avant fix)
- ✅ **#494** : **FIX SYSTÉMIQUE poussé** (`fix/494-…`). Pas que core : 7 units re-chownaient
  le parent partagé `/run/secubox` (core+hub services, eye-remote/eye-square/metablogizer/
  metrics/p2p postinsts ; eye-square chownait aussi /var/log/secubox = pire). Tous nettoyés
  (mkdir fallback only ; logs modules en sous-dossier propre ; orphan /etc/tmpfiles.d nettoyé).
  **Vérifié live** : /run/secubox 1777 **root:root** stable après restart core ET hub ; webui 200.
  Bumps core 1.1.7/hub 1.4.4/eye-remote 1.0.1/eye-square 1.0.4/metablog 1.2.2/metrics 1.0.4/p2p 1.7.1.
- ✅ **#471** (mesh /run/secubox) : déjà résolu (changelog mesh "drop install -d /run/secubox") → verify-close.
- ⬜ **#421** : sockets cachés en mount-ns privé (RuntimeDirectory) — mécanisme distinct, non traité.
- 🆕 Suivi (classe #511) : mesh/toolbox/admin font `install -d -o <module> /var/log/secubox`
  (propriétaire du parent partagé = user module) → autres daemons ne peuvent créer leurs logs.
  Séparé de #494, à traiter (sous-dossiers propres comme fait pour eye-square/p2p).
- **#447** : pas une fuite — `password_hash=null` → lockout kiosk + user CI parasite ;
  **CI-image-gated** (rpi400, pas gk2).
- **#91** : `haproxy.cfg` active valide ; backup `*.broken-by-haproxyctl-*` prouve le bug
  passé ; drift-guard #627 rattrape. Root cause = generate `haproxyctl` (api/main.py l.846/896).
- ✅ **#53** : **FIX poussé** (`fix/53-…`) — gate `ConditionPathExists=/var/ossec/etc/ossec.conf`
  + `RestartSec=5` ; module conservé (SIEM opt-in). Vérifié gk2 (/var/ossec absent). Bump 1.0.1.
- ✅ **#65** : déjà résolu en prod (webui.conf déployé inclut `secubox-routes.d/*.conf`,
  163 snippets). Template `common/nginx/webui.conf` (stale) synchronisé sur `feature/65-…`.
  Reco fermer. Convention : `secubox-routes.d/`=actif, `secubox.d/`=legacy.
- ✅ **#121** : **FIX poussé** (`fix/121-…`) — helper `fix_perms` chown -R secubox:secubox
  le site dir après chaque ingest .git (metablog-ingest-site.sh). Script dev, pas de deploy.
- ⬜ Restent : **#91** (deploy WAF risqué) · **#65** (refactor include, risque 502) ·
  **#447** (CI kiosk) · **#494/#471/#421** (worktree fix/494). Build+deploy toolbox 2.7.18 (#519) en attente.
- **Backlog/future** : #685/#686 APK non-root (plan verrouillé) · #592 webmail-hub ·
  #514/#515/#516/#519/#522/#525 Phase 12-14 (#515 CDN / #516 anti-bot partiellement
  couverts par antibot_sites/opgrade_sites du social graph) · #500 Utiq · #497/#480/
  #478 VILLAGE3B Eye/poster · #472/#430/#429 Nextcloud · #471/#468/#421 perms (à
  vérifier si déjà corrigées) · #467/#462/#460/#255/#254 hardware/kernel · #455 egress ·
  #454/#453/#452/#449 mesh/BLE · #448/#447/#446/#434 kiosk · #422 vm cascade ·
  #393/#379/#347 packaging · #513 WebUI sub-tabs.
- ⚠️ Fermeture finale = **user only** (sauf issues créées en session) ; les
  recommandations ci-dessus sont commentées sur chaque issue.

---

## ✅ 2026-06-22 : DPI exfil + Netrunner report + sbxmitm fixes (tous mergés, live gk2)

Session livrée intégralement sur master + déployée. Détail dans HISTORY 2026-06-22.

### ✅ Fait (mergé + live)
- **DPI exfil pipeline (#687)** — `secubox-dpi 1.1.2` : flowcap (ndpiReader) → Go
  collector (catégories cloud/media/game/adult/ai/messaging/filehost/social + scénarios
  exfil) → `/api/v1/dpi/exfil` ; dashboard "Cloud Exfiltration Watch" + cartes repointées ;
  beaconing tuné (#692) ; cumulatif 7j `cumulative.json` (#705) ; packagé arm64.
- **Report kbin = fiche Netrunner (#707)** — HTML (onglets Pistage/DPI/Overall + persona
  néon) **et** PDF (`_persona_block` + "En un coup d'œil" + grille donuts + carto + tables
  emoji). Charts en **PNG matplotlib** (#714, rendu universel iOS/Chrome) ; grille = une
  image 2×2 (#716, fin des 24 pages). Classe via UA live + niveau R3 auto (wg peer).
- **sbxmitm** — cert forgé 24h→365d (#689, fin des "certificat expiré") ; fin de la
  troncature >8MiB (#697, Gmail OK) ; splice own-domain **rejeté** (#688, on intercepte tout).

### ⬜ Next Up (différé)
- **#685/#686 APK on-device — NON-ROOT ONLY (plan verrouillé)** : VpnService in-app
  (wireguard-go), CA en DER + network-security-config WebView, retrait du chemin root.
  Gros build Android (CI + test device) → session dédiée. Détail : commentaire #685 + TODO.
- **DPI Phase 3** — ✅ enrichissement ASN (#719, 1.1.3) · ✅ historique + timeline
  (#721, 1.1.4) · ❌ démon nDPId **écarté** (#722/#723 revertés) : risque perf
  (démon permanent vs fenêtres ndpiReader bornées) sur board saturée → **on garde
  ndpiReader**. **Phase 3 close.**
- **#685 APK on-device** — install auto CA + handoff WG + détection tunnel (en attente
  décision rooted vs non-root du user).
- **Cosmétique PDF** — glyphes drapeaux régionaux dégradent en lettres (police embarquée) ;
  chiffres légèrement espacés dans certaines cellules. Non bloquant.

---

## 🔄 2026-06-19 : kbin Tor egress (#683) — ToolBoX 2.7.1, implémenté DARK

Switch + tunnel Tor quick-switch livrés sur `feature/683`, **défaut OFF / fail-closed**.
Détail dans la section "Implémenté DARK" ci-dessous + HISTORY 2026-06-19.

---

## 🔄 2026-06-19 : kbin milestone — ToolBoX 2.7.0 + chapitre Tor (plan)

Checkpoint de fin de session. Pas de changement de comportement runtime — docs +
positionnement + version + plan de la lame suivante.

- ✅ **ToolBoX 2.7.0** (middle release) — clôt la ligne 2.6.x (ad-intelligence /
  Anti-Track v2 / anti-bot uTLS #662), ouvre le chapitre kbin « premier outil du
  couteau suisse cyber ». kbin = perf transparente + full encrypted + poison/smog +
  bandeau anti-adware + safe browsing.
- ✅ **Docs kbin** — wiki [`Kbin-Toolbox.md`](../docs/wiki/Kbin-Toolbox.md),
  [`FAQ-KBIN-TOR.md`](../docs/FAQ-KBIN-TOR.md), blurb README.
- ✅ **Plan #683** — spec
  [`2026-06-19-kbin-tor-anonymized-surfing-design.md`](../docs/superpowers/specs/2026-06-19-kbin-tor-anonymized-surfing-design.md) :
  endpoint Tor quick-switch (egress sortant, fail-closed, opt-in, no DNS leak,
  inspection préservée). Dépend du cœur Go #662.

### ✅ Implémenté DARK — chapitre Tor (#683, ToolBoX 2.7.1, branche feature/683)

- ✅ **Transport tranché** : *torify l'egress MITM* (owner-match nft sur l'uid
  `secubox-toolbox`/mitm-wg → Tor TransPort 9040 / DNSPort 5353). Inspection
  préservée. Décision USER (vs dialer SOCKS5 #662 = bloqué, vs torify client = casse
  l'inspection).
- ✅ **Switch** : flags `tor_mode`/`tor_preset` (filters.json) ; API kbin-gated
  `GET/POST /admin/tor/{state,on,off,newnym,check-leaks}` ; onglet 🧅 WebUI (badge,
  toggle, NEWNYM, sonde fuite). `tor_ctl.py` réutilise le control-port de secubox-tor.
- ✅ **Tunnel** : `conf/nft-toolbox-tor.nft` (fail-closed kill-switch + drop v6) +
  `conf/torrc-toolbox-egress.conf` + reconciler root path-triggered
  (`secubox-toolbox-tor.path` surveille filters.json → portail reste
  NoNewPrivileges=true). nft chargé AVANT tor (pas de fenêtre clearnet).
- ✅ 166 tests verts ; license headers OK ; changelog 2.7.1.

#### ⬜ Avant flip ON (USER)

- Soak DARK puis `tor_mode=true` via l'onglet (admin.gk2).
- Test de fuite **hors-board** : l'IP réelle de la box ne doit jamais apparaître.
- Forcer `tls_splice` (#649) OFF quand armé (sinon flux asset fuient l'IP réelle).
- **Per-client (WG-hash)** : nécessite le dialer SOCKS5 du cœur Go #662 (l'owner-match
  est global). Suivi sous #662.

---

## 🔄 2026-06-17/18 : Anti-Track v2 + perf/ops sprint (gk2 live)

Tout mergé sur master + déployé sur gk2. Détail dans HISTORY 2026-06-18.

- ✅ **Anti-Track v2 (#633, PR #637)** — bloque/empoisonne/anonymise, moteur
  `privacy.py` + addon `privacy_guard.py`, learning (`learn.py`), IP-drop +
  unbound DNS-refuse (`ip_dns.py`/`escalate.py`), bypass-seed + #filtres badges,
  #social top-5. **Tourne DARK** (`privacy_enforce` unset). Wiki `Anti-Track.md`.
- ✅ **Banner saga (#636/#639, PR #638/#640)** — mitm sert loader/bundle pour
  toute origine (PeerTube fixé), CSP fallback, top-bar, 1 bannière/visite.
- ✅ **#634/#635** — reset-all clients + emojis device/flag/hosting.
- ✅ **#642 (PR #643)** — social-graph ignore les edges IP-littéraux ; KPI
  "Trackers vus" = table.
- ✅ **#644 (PR #645)** — hub dashboard/health-batch servis depuis cache TTL
  (health-batch 3.3 s → 8 ms) ; clients/rich enrichit 12 max. **hub 1.4.6**.
- ✅ **#646 (PR #647)** — adaptive Accept-Encoding strip : plus de pages
  CSP-strict tirées décompressées via le worker R3 GIL-bound. **toolbox 2.6.53**.
- ✅ **crowdsec** réparé (403 transitoire CDN → `dpkg --configure` RC=0, audit clean).

- ✅ **#623 (PR #648, merged 9950e9ec)** — clobber systémique RÉSOLU au source.
  La vraie cause : boilerplate scaffold `install -d -m 750 /var/lib/secubox` +
  `/run/secubox` (parents NUS) dans ~56 postinsts — écrit `-m 750` (3 chiffres),
  d'où le ratage des sweeps précédents. Empiriquement prouvé que le form
  `install -d -m 750 /parent/leaf` NE clobbe PAS le parent (seuls les targets
  parents-nus). Fix : tous → 1777 (/run) / 0755 ; 6 lignes multi-arg splittées
  (4 mettaient /var/lib en world-writable 1777) ; 3 `chmod 750 /var/log` ;
  scaffold `new-package.sh` + `PATTERNS.md` ; core 1.1.8 tmpfiles.d déclare les 5
  parents 0755. **PAS de mass-deploy** (60 paquets = mass-restart = risque
  thundering-herd) ; live couvert par `dirs-guard.timer` ; arrive au prochain
  build CI / reflash.

- ✅ **#649 Lever A — selective SNI-splice (PR #650, toolbox 2.6.54 LIVE dark)**.
  New `tls_splice` addon (first in mitm-wg chain) splices pure-asset flows at the
  TLS ClientHello — curated media seed (googlevideo/ytimg/fbcdn/twimg/scdn…) ∪
  autolearn-promoted never-HTML hosts — so GIL-bound R3 workers skip
  forge/decrypt/parse/16-addons on no-L7-value flows. Ships `tls_splice=observe`
  (DARK: classify+log, still MITM). Deployed gk2, addon loads clean, 0 runtime
  errors. Answer to "do we need full mitm?": YES for outbound HTTPS (per-host cert
  forging is intrinsic) — but only decrypt what we modify. Lever B (Go/Rust core)
  = strategic follow-up. WAF = later.

### ⬜ Next Up

- **#649 SOAK → FLIP** — review `would-splice` logs + `/run/secubox/splice.json`
  on real traffic for a soak window, confirm no first-party/HTML host is
  classified, then flip `tls_splice=on` in `/etc/secubox/toolbox/filters.json`
  (hot-reload). Before flip: the fortknox-via-WebUI refresh gap is already fixed.
- **Lever B (#649 follow-up)** — Go/Rust forging-proxy core if A isn't enough.
- **Anti-Track v2 ARMING** (décision USER, gated) — soak observe-only puis flip
  `privacy_enforce=true` ; régénérer `data/cdn-allowlist.txt` depuis les plages
  publiques avant `privacy_ip_drop` ; `unbound-checkconf` avant `privacy_dns_feed`.
- **Tunnel R3 perf** — l'encoding fix aide ; reste la contention CPU board-wide
  (load ~5/4 cœurs, workers mono-thread). Lever suivant = réduire les co-tenants
  (gitea/R2-mitm/crowdsec/metrics) ou isoler le mitm, pas du tuning d'addon.
- **#615** — Security Posture dans la navbar du Hub (petit enhancement).
- **#592 webmail-hub** — BLOQUÉ : besoin client OAuth Google + vhost ; Phase 1
  IMAP (Gandi/OVH) peut démarrer sans OAuth.

---

## 🔄 2026-06-14 : ToolBoX privacy/perf sprint — 2.6.36 live (see HISTORY)

Tout mergé + déployé sur gk2 (kbin sain, `secubox-toolbox 2.6.36`).
Détail complet dans HISTORY 2026-06-14. Résumé :

- ✅ Protective spoof (#560), modular filters + ad-ghoster (#566, collapse
  #584), media cache opt-in (#577), autolearn (#589/#591), DPI media donut
  (#570), donut + domain-nugget cartographie (#553/#587, IP cachées #575,
  favicons #555), guirlande banner + pin (#572/#578), webext popup panel
  (#574), /ca/fingerprint R3 (#562), postinst restart fix (#581),
  detect_antibot deployment-vs-challenge (#564).
- ✅ Clients : APK v0.3.0 (zero-tap launch+boot), webext v0.1.4.
- ✅ Fixes live : Nextcloud iPhone photos (files_antivirus off + PHP
  limits), kbin 503 (#581).

### ⬜ Next Up

- **#592 secubox-webmail-hub** (Gmail OAuth2 + Gandi + OVH, inbox unifié) —
  design filé, **BLOQUÉ** : besoin d'un client OAuth Google (client_id/
  secret/redirect) + nom de vhost + (read-only Phase 1 ?). Phase 1 IMAP
  (Gandi/OVH) peut démarrer sans OAuth sur "start phase 1".
- Côté user : re-trust R3 CA `D5:E4:3A` sur l'iPhone (bannière HTTPS) ;
  tester l'upload photo Nextcloud ; activer `media_cache` si voulu
  (`/admin/filters/ui`) et surveiller `/admin/cache`.

---

## 🔄 2026-06-13 : Browser extension — emancipate cartographie live (#532)

Extension navigateur (`clients/webext-toolbox/`, MV3 Firefox `.xpi` +
Chromium) sœur de l'app Android. Sort la *cartographie sociale* R3 dans
le navigateur : badge live des traceurs + popup.

- **Extension** : `manifest.json` (MV3, background `service_worker` +
  `scripts` pour FF115+/Chromium), `api.js` (client `/wg/r3-check`,
  `/social/me` → token, `/social/graph/{token}`, `/social/wipe`),
  `background.js` (badge = total_trackers, re-pair silencieux si token
  expiré, couleur escalade gold→anti-bot→opérateur), popup (4 tuiles
  stats + **mini Round-Eye graph SVG sans dépendance** + top-traceurs
  taggés CDN/anti-bot/opérateur + actions cartographie/PDF/RGPD-wipe),
  options (hôte/fenêtre/token manuel). Pas de CORS backend nécessaire
  (host_permissions). Validé : JSON+JS+SVG OK, `.xpi` build 11.8 KB.
- **Serve depuis la toolbox** (`2.6.14`) : `GET /wg/toolbox.xpi` (local
  sinon 302 → release), bouton `🧩 Extension navigateur` sur les 2
  panneaux onboard, helper `secubox-toolbox-fetch-xpi`, postinst dir.
- **CI** : `build-webext.yml` — `web-ext lint` (0 erreur, 2 warnings
  bénins) + build, artifact, release asset sur tag `webext-v*`.
- **Release** (PR #540 + #541, mergées) : tag `webext-v0.1.1` poussé →
  CI a publié `secubox-toolbox-webext.xpi` (téléchargeable, vérifié 200).
  `make_latest:false` + URL **tag-pinned** dans `/wg/toolbox.xpi` +
  `secubox-toolbox-fetch-xpi` pour ne pas voler le pointeur "Latest" à la
  release APK Android (dont l'endpoint résout via `/releases/latest/...`).
  → bumper le tag dans la constante + le helper à chaque `webext-v*`.
- **Reste à faire** : signature AMO (`.xpi` non signé = sideload/dev) ;
  endpoint SSE `/social/live/{token}` optionnel ; icône PNG Chromium ;
  contrôle Poke/Emancipate par-site quand #525 (déception) arrive ;
  déployer `secubox-toolbox 2.6.14` sur la board pour activer le bouton.

---

## 🔄 2026-06-13 : Android ToolBox app — serve + root-mode silent onboarding (#531/#536/#538)

App compagnon Android **one-tap R3** pour la cabine VILLAGE3B
(`clients/android-toolbox/`, `in.secubox.toolbox`, Kotlin + Compose).

- **#531 — scaffold + CI** : projet Gradle/Compose (5-step stepper
  Discover→InstallCa→ImportProfile→Verify→Done), client `HttpURLConnection`,
  workflow `build-android-apk.yml` (debug APK artifact, release asset sur
  tag `android-v*`). CI **GREEN**.
- **#536 — serve depuis la toolbox** : endpoint `GET /wg/toolbox.apk`
  (sert le build local `/var/lib/secubox/toolbox/android/`, sinon 302 →
  release GitHub) + bouton *📱 Installer l'app ToolBoX (1-tap)* dans les
  panneaux onboard kbin + helper `secubox-toolbox-fetch-apk`. Vérifié :
  200 `application/vnd.android.package-archive`, 14.8 MB.
- **#538 — root-mode silent onboarding** (PR #539, branche poussée) :
  bouton *⚡ Installation automatique (root)* sur devices rootés →
  install CA dans le magasin **système** (bind-mount cacerts + APEX
  conscrypt, SELinux ctx, `subject_hash_old` en Kotlin pur) + tunnel
  WireGuard **natif noyau** (`ip link add … type wireguard` + `wg set`) +
  vérif R3 auto. Fallback handoff app WireGuard si noyau sans WG. Toutes
  les actions root gated derrière le tap explicite. Nouveaux fichiers
  `RootShell.kt`, `RootOnboard.kt`, step `RootAuto` (log streamé).
- **Reste à faire** : release signing (keystore secret CI) pour une
  empreinte publiée stable — actuellement debug-signé (sideload).

---

## 🔄 2026-06-12 : Admin WireGuard tunnel + SSH hardening (ref #529)

Accès admin out-of-band + fermeture de la surface SSH publique.

- **wg-admin** (#529) : interface dédiée UDP **51821**, server `10.98.0.1/24`,
  distincte de wg-toolbox (51820). Peer `gandalf-admin` @ `10.98.0.2`.
  nft drop-in `secubox-admin-wg.nft` (udp/51821), `wg-quick@wg-admin`
  enabled. Client importé dans NetworkManager du poste dev, tunnel UP,
  `ssh root@10.98.0.1` confirmé (key auth).
- **Découverte sécurité** : la box subissait un brute-force SSH public
  actif (centaines de tentatives 87.251.64.x / 51.68.34.x + IPs déjà
  blacklistées). Le routeur `192.168.1.254` port-forward :22 → box sur
  `eth1`/`lan0`, et l'input chain a un blanket `iif eth1 accept` (le
  DNAT préserve l'IP source publique réelle).
- **Hardening appliqué + vérifié** :
  - sshd : `PasswordAuthentication no` + `PermitRootLogin prohibit-password`
    (drop-in `99-secubox-hardening.conf`, key-only).
  - nft SSH-guard : `tcp dport 22 ip saddr != { 192.168.1.0/24, 10.0.0.0/8 } drop`
    inséré AVANT `iif eth1 accept` (live sans flush + persisté dans
    `/etc/nftables.conf`).
  - Résultat : `ssh root@10.98.0.1` (tunnel) OK key-only ; public
    `admin.gk2.secubox.in:22` **timeout (bloqué)**. Tables blacklist/wg
    intactes.
- **Script reproductible** `scripts/setup-admin-tunnel.sh`
  (`provision | add <name> | harden`), idempotent, branche `feature/529`
  poussée (pas de PR).
- **Reste à faire (côté user)** : retirer le port-forward :22 du routeur
  (le tunnel remplace l'accès) ; IPv6 SSH non couvert par le guard v4
  (à ajouter si exposition IPv6).

---

## 🔄 2026-06-11 : Phase 12.C + Phase 13 COMPLETE (protection enforcement plane) — v2.13.16→19 (ref #518-#528)

### ✅ Phase 12.C — operator-grade / state-adjacent (#518, v2.13.16)
detect_operator_grade : telco header-enrichment (MSISDN/x-acr), consortium
(Utiq/TrustPid), data-broker / state-adjacent (LiveRamp/BlueKai/Acxiom/
Neustar/Tapad/Experian/Palantir-class). Top-severity void-purple lens +
PDF section. `secubox-toolbox 2.6.7`.

### ✅ Phase 13 — protection enforcement plane (#519) COMPLETE
Le plan de bannissement (Vortex DNS + WAF + CrowdSec) enforce maintenant
sur le browsing des appareils, à tous les niveaux egress.

| Track | Issue | Livré | Tag |
|---|---|---|---|
| 13.A spine | #521 | nft set `inet secubox_blacklist` + forward-drop chain ; sync CrowdSec+threat-intel | v2.13.17 (2.6.8) |
| 13.B DNS-guard | #522 | résout domaines blocklistés → IPs (anti-DoH bypass) + détection DoH/DoT count-only | v2.13.17 (2.6.9) |
| 13.C attribution | #524 | per-device (WG/lease hash) blocked-attempts + quarantine set + endpoints | v2.13.18 (2.6.10) |
| 13.D feedback | #527 | escalation evaluator (detections→nft/cscli/quarantine), audit-log, **default OFF** | v2.13.19 (2.6.11) |

**Doctrine** : DEFAULT DROP préservé (policy accept n'ajoute que des drops) ;
pas de WAF bypass ; anonyme (mac_hash sel rotatif) ; tout réversible (TTL +
unban) ; escalade opt-in par source.

**Bug latent corrigé (#521)** : `override_dh_strip` ne tourne jamais pour
un paquet `Architecture: all` → tous les drop-ins nft/unbound/nginx/perf
avaient cessé de shipper (cause racine de la live-config-drift). Déplacé
vers `execute_after_dh_auto_install`. Mémoire ajoutée.

### 💡 Idée future capturée (#525)
Phase 14 « plan de déception » : au lieu de bloquer les IPs trackers,
générer des pseudo-réponses proxy (indistinguable du drop, pollue le
profil) ; idem neutraliser les scripts CDN préchargés. Pour plus tard.

### 🧹 État du dépôt
Toutes les branches Phase 11/12/13 mergées + supprimées sur origin.
master @ `v2.13.19` (`secubox-toolbox 2.6.11`). Worktrees Phase 11-13
nettoyés. (Worktrees plus anciens #429/#485/#486/#490/#494/#495/#498 +
license = travail parallèle, non touchés.)

### ⬜ Next up
- **Phase 13 opt-in tuning** : activer les sources d'escalade (env
  `SECUBOX_ESCALATE_*`) selon politique opérateur quand voulu.
- **threatfox feed = 0 IOCs** : investiguer pourquoi l'ingestion domain
  est vide (impacte 13.B resolved_domains).
- **Phase 14 déception** (#525) quand prêt.

---

## 🔄 2026-06-10 (soir) : Phase 11 COMPLETE + Phase 12.A/B + toolbox tabs — merged v2.13.15 (ref #502-#516)

Tout le stack Phase 11 + Phase 12.A/B mergé en une PR consolidée (#517),
`secubox-toolbox 2.5.2 → 2.6.6`, tag **v2.13.15**.

### ✅ Done — mergé master

| Issue | Livré | Version |
|---|---|---|
| #505 11.A backend | correlation engine + SQLite + /social API | 2.6.0 |
| #507 11.B frontend | d3 graph + i18n FR/EN + favicon proxy + wipe + /social/me | 2.6.1 |
| #513 toolbox tabs | 5-tab WebUI, kbin /admin/ inline UI supprimé | 2.6.2 |
| #508 11.C evidence | consent-probe + PDF bilingue FR/EN | 2.6.3 |
| #515 12.A CDN | detect_cdn + Round-Eye central-hotspot graph | 2.6.4 |
| #516 12.B anti-bot | detect_antibot + ring levels visibles + Carto/Reset | 2.6.5/2.6.6 |

### ✅ Phase 11 — social mapping per device (#502)

Live : `https://kbin.gk2.secubox.in/social/me` (🕸️ Ma carto).
Graphe Round-Eye : l'appareil = œil central pulsant, sites sur anneau
interne (forceRadial 0.9), trackers anneau externe. Montre le relais
ad-tech `35.214.136.108` reliant 360yield + seedtag + smartadserver +
smilewanted. PDF d'évidence bilingue (consentement RGPD art. 6.1.a+7,
transferts hors-UE art. 44). Effacement RGPD art. 17. Anonyme (mac_hash
sel rotatif 24h, aucune valeur cookie brute).

### ✅ Phase 12 — anti-human-detection platform (#514)

- **12.A CDN** : detect_cdn (Cloudflare/Fastly/Akamai/CloudFront/Google/
  Vercel/Netlify/Bunny/KeyCDN/Sucuri/Imperva). Nodes teintés par vendor,
  table social_host_meta, agrégat by_cdn.
- **12.B anti-bot** : detect_antibot (reCAPTCHA/hCaptcha/Turnstile/
  Datadome/PerimeterX-HUMAN/Arkose/Kasada/Akamai-BotManager). Lens
  cinnabar sévère + ring d'alerte + bannière "challenged your humanity".
  Table social_antibot per-client, agrégat by_antibot.
  **Bypass NON livré** — gated derrière doctrine (séquencement #514).
- **Ring levels visibles** : forceRadial dominant + guides d'anneau +
  cache-bust ?v=264b (le user ne voyait pas la réorg ; corrigé).
- **Outils opérateur Clients tab** : 🕸️ Carto (ouvre le graphe client
  via token, redirige vers kbin absolu), ↺ Reset/RAZ (efface social +
  events + score).

### ⚠️ Round Eye gadget — diagnostic, fix physique requis

OTG USB CDC-Ethernet **TX queue wedged** (NETDEV WATCHDOG timeout sur
3-1.1.2). Le gadget énumère (descripteurs lisibles) mais le data path
TX est mort — control transfers OK, bulk KO. Recovery gk2 épuisée
(link bounce, unbind/rebind → probe error -110). **Power-cycle du Pi
Zero ou re-seat câble OTG nécessaire** ; self-heal au prochain boot
propre via la règle systemd .link.

### ⬜ Next up

- **Phase 12.C** (#514) : opérateur-grade / state-adjacent (étend #500
  Utiq). Détection identité carrier-grade + analytics state-adjacent.
- **Phase 12.B bypass + 12.D noise** : derniers, chacun gated par sa
  doctrine + design review (interférence active 3rd-party = R3 opt-in).
- **Round Eye** : reprendre côté gk2 dès que le Pi re-énumère propre.

---

## 🔄 2026-06-10 : Phase 11 social mapping (A+B) + system triage round (ref #502-#509)

Grosse journée : Phase 11 social mapping shippé jusqu'au frontend live,
puis une cascade de fixes système découverts par l'utilisateur en
production sur gk2.

### ✅ Done — Phase 11 social mapping (#502 parent)

| Issue | Phase | État |
|---|---|---|
| #505 / PR #506 | **11.A backend** : correlation engine + SQLite + API | ✅ mergeable, déployé live `secubox-toolbox 2.6.0` |
| #507 | **11.B frontend** : d3 graph + i18n FR/EN + favicon proxy + wipe modal | ✅ déployé live `2.6.1`, branche poussée |
| #508 | **11.C evidence + PDF** | 🔄 WIP checkpoint `55626e51` (schema + GeoIP fold + evidence helper) |

**Design** : 2 rounds de design lock sur #502 (Gemini + GPT mockups),
edge-thickness + animated-pulse + tracker bottom-sheet + 3s wipe
countdown verrouillés.

**Live URL** : `https://kbin.gk2.secubox.in/social/me` (splash → 🕸️ Ma carto).
Le graphe montre les trackers cross-site réels (relais ad-tech
`35.214.136.108` reliant 360yield + seedtag + smartadserver + smilewanted).

**Fixes live-deploy critiques découverts** :
- `social_graph.py` : `from . import local_store` ne résolvait jamais
  (mitmproxy charge les addons en top-level) → inliné le WG peer hash.
- **PYTHONPATH manquant dans le launcher mitm-wg** : TOUS les addons
  (`inject_banner` dpi/geo/store, `social_graph`) avaient leurs
  `from secubox_toolbox import …` silencieusement dégradés. Fix global.
- i18n déplacé de `data-*` attr vers `<script>` (apostrophes FR
  cassaient `JSON.parse`).
- StaticFiles mount + chmod 0755 `/usr/share/secubox/www` (kbin passe
  par HAProxy direct uvicorn, bypass nginx).
- d3 : full-viewport + pan/pinch-zoom + pre-warm 300 ticks + autoFit
  data-based (146 nodes spread off-screen avant).

### ✅ Done — triage système gk2 (2026-06-10)

| Bug | Cause racine | Fix |
|---|---|---|
| CrowdSec firewall status faux | bouncer tournait mais sans tables nft (flush externe) | restart bouncer → `ip crowdsec` + `ip6 crowdsec6` recréées, 100 décisions live |
| WAF /threats + tracked attackers vides | `/var/log/secubox` 0750 secubox-toolbox bloquait traversal aggregator (user `secubox`) | chmod 0755 live |
| WAF /stats timeout 30s+ | `_get_threat_stats()` re-parsait 110 MB / 332k JSONL à CHAQUE requête (CPU 89%) | **#509 double-buffer cache** (disk + byte-position incrémental) `secubox-waf 1.2.2` |
| SOC /soc/ status WAF+firewall faux | consommait les mêmes endpoints WAF cassés | résolu en cascade par le fix WAF |
| PeerTube + PhotoPrism 502 | LXC STOPPED | `lxc-start` → 200 / 307 |

### ✅ Done — CI + release

- **#503 / PR #504** : drop espressobin-v7 + ultra du matrix build-image
  scheduled (faisaient échouer le pipeline release v2.13.9-12).
- **#509 / PR #510** : double-buffer WAF cache.
- **Merge #504 + #510 → master** (`3ebb4477`, `a6f44807`).
- **Tag `v2.13.14`** poussé.

### ⬜ Next up

- **Round Eye gadget** : ne voit plus le lien gk2, montre ses métriques
  locales. iface `eye-remote` UP côté gk2, route `/api/v1/eye-remote/*`
  renvoie page erreur. Investigation côté Pi Zero nécessaire.
- **admin.gk2/toolbox/ tab** : le toolbox est DÉJÀ wiré (`/toolbox/`
  alias + sidebar). User veut surfacer l'UI kbin/admin dedans —
  décision en attente : proxy_pass / iframe / sous-tab.
- **Phase 11.C** : reprendre depuis `55626e51` (consent probe addon +
  extra-EU flag + PDF bilingue + wire frontend).
- **Postinst patch** : `/var/log/secubox` 0755 en source (pour l'instant
  fix live uniquement) — même pattern que `/etc/secubox` + `www`.

---

## 🔄 2026-06-09 : Phase 10 — Banner injection perf quick wins + postinst regression fix (ref #501)

User signal : "la banner n'apparait qu'en fin de chargement et les
chargements de pages sont très lents. peut-on améliorer ces rendus sans
compromettre l'analyse... ou alléger l'analyse nécessaire à la
bannière ?".

Diagnostic — chaque réponse HTML déclenchait trois opérations
host-stables sans cache et **un scan plein-corps en regex** juste pour
remplir une tile "trackers: N" que personne ne lit :

* `_host_app.classify_host(host)` — walk sur 100+ patterns (5-50 ms à froid)
* `_whitelist_mod.match(host)` — match contre la whitelist
* `_geo_mod.lookup(host)` — DNS + mmdb GeoIP (5-50 ms à froid)
* `_count_trackers_in_body(flow.response.content)` — buffer-read intégral
  du corps avant injection → la bannière n'apparaissait qu'en fin de
  streaming.

### ✅ Done — packages

| Package | from → to | Commit |
|---|---|---|
| secubox-toolbox | 2.5.0 → **2.5.1** | `ce059d0f` (banner perf quick wins, déployé live) |
| secubox-toolbox | 2.5.1 → **2.5.2** | `15f48d9d` (postinst regression fix, code only) |

Branche : `perf/501-banner-injection-quickwins` (poussée sur origin, **pas de PR**).

### ✅ Done — détails

**1. Banner injection quick wins** (`secubox-toolbox` 2.5.1, commit `ce059d0f`)

* `_host_signals(host)` — nouvelle fonction LRU-cachée (maxsize=2048)
  retournant un tuple `(app_emoji, app, flag, country, asn, status,
  status_icon)`. Re-hits coûtent un dict lookup au lieu de 5-50 ms.
* `_count_trackers_in_body()` retiré du chemin chaud. Le flag
  `is_tracker_host` (regex cheap sur l'host de la requête) couvre le
  signal privacy.
* `_MAX_INJECT_BYTES = 2 MB` — skip de l'injection sur les gros corps
  via pré-check `Content-Length` + garde défensive `len(body)` pour les
  streamed bodies sans CL.
* Tile cookies + ⚠ tracker-host conservée ; tile 🎯 N trackers (corps)
  morte → supprimée.

**Mesure live** : sur le déploiement gk2, l'iPhone confirme "browsing
performance on iPhone is better... perfect work".

**2. Postinst regression fix** (`secubox-toolbox` 2.5.2, commit `15f48d9d`)

Deux régressions silencieuses pendant le déploiement 2.5.0 → 2.5.1 sur gk2 :

* **kbin.gk2.secubox.in 503 pendant 5 min** : dpkg upgrade a SIGTERMé
  `secubox-toolbox.service` et ne l'a jamais redémarré
  (`dh_installsystemd --no-start --no-enable` dans debian/rules).
* **iPhone tunnel KO** : postinst a écrasé
  `/etc/nftables.d/secubox-toolbox-wg.nft` avec la version single-port
  DNAT, supprimant le fanout Phase 9 que l'opérateur avait déployé en
  runtime → tout le trafic pinné sur worker@1 à 97 % CPU.

Fixes postinst (pas de code change) :

* Postinst déploie maintenant le fanout drop-in en
  `/etc/nftables.d/zz-secubox-toolbox-wg-fanout.nft`. Le préfixe `zz-`
  garantit le tri alphabétique après le base file dans le glob include
  de `/etc/nftables.conf` → le base file crée la table + chains, puis
  le zz drop-in flush+repeuple la chain `prerouting` avec le numgen
  fanout map.
* Sur upgrade (`$2` set), `systemctl try-restart` sur
  `secubox-toolbox.service`, `secubox-toolbox-mitm.service`, et les 4
  instances `secubox-toolbox-mitm-wg-worker@{1..4}.service`. `try-restart`
  est no-op si l'unité n'est pas active, donc safe sur fresh install.

### Mémoire mise à jour

* [nft layered drop-ins persistence](../memory/feedback_nft_layered_dropins_persistence.md)
  — drop-ins doivent trier APRÈS leur table-creator ; ne jamais
  symlinker en place du base file.
* [postinst must preserve runtime state](../memory/feedback_postinst_preserve_runtime_state.md)
  — dpkg upgrade SIGTERMe l'unité ; postinst doit try-restart + redéployer
  les drop-ins nft appliqués en runtime.

### ⬜ Next up

* **Build + deploy 2.5.2 sur gk2** (postinst-only fix — pas de code change ;
  attendre prochaine fenêtre de maintenance, ne pas perturber la session
  iPhone actuellement stable).
* **PR #501** quand prêt (branche poussée mais pas de PR ouvert, per
  rule "Don't open PRs unprompted").
* **Phase 10 future** : refactor banner injection vers une approche
  JS-driven async pour éliminer complètement le buffer-read du corps
  (envoyer un `<script>` minimal à la position `<head>` qui fetch le
  contenu de la bannière + le contexte via XHR, puis injecte le DOM
  côté client). Ferait passer la bannière de "fin de streaming" à
  "first paint" pour TOUS les corps, pas seulement les < 2 MB.
* **#502 D redesign** : captive → LXC avec TPROXY-inside-LXC (toujours
  en attente, pas commencé).

---

## 🔄 2026-06-08 : Phase 7.E.x — LXC hygiene + auth recovery + Phase 8 plan (ref #498, #500)

Une journée chargée — beaucoup de petits fixes empilés + une découverte
architecturale + l'ouverture de Phase 8.

### ✅ Done — packages

| Package | from → to | Commit |
|---|---|---|
| secubox-waf | 1.2.0 → **1.2.1** | `c5f0482e` (LXC mitmproxy.service RuntimeMaxSec + memory caps) |
| secubox-toolbox | 2.2.0 → **2.3.2** | `c5f0482e`, `f1418b53`, `3c4d1cc1` (auto-detect /wg/onboard + NM keyfile name + LXC scaffolding) |
| secubox-auth | 1.0.1 → **1.0.2** | `87bd8e51` (ntp_health timedatectl fallback) |
| secubox-users | 1.4.1 → **1.4.2** | `64e4de16` (postinst chowns auth.toml) |

### ✅ Done — détails par axe

**LXC mitm WAF hygiene** (`secubox-waf` 1.2.1) — `RuntimeMaxSec=21600` +
memory caps shippés sur `mitmproxy.service` inside la LXC. Comble
l'oubli Phase 6.P qui ne couvrait que les host units.

**Auto-detect /wg/onboard** (`secubox-toolbox` 2.3.0) — une URL unique
sniff User-Agent → panneau iOS / Android / Linux / macOS / Windows
ouvert en premier. Tous les artefacts inchangés ; l'onboard compose.

**NM connection name** (`secubox-toolbox` 2.3.1) — switch de l'UA brut
("Mozilla/5.0…") à `village3b-r3-<dernier-octet>` pour le champ
NetworkManager `id`.

**LXC mitm-wg scaffolding + finding architectural** (`secubox-toolbox`
2.3.2)
- Provision script accepte `wg` target → LXC privilégié à 10.100.0.62
  (drop de `lxc.idmap`, résout la perm denial sur ca-wg).
- Launcher mitm-wg paramétré par `MITM_WG_LISTEN_HOST` (host : `10.99.1.1`
  / LXC : `0.0.0.0`).
- **Cutover live tenté + rollback** : transparent-mode mitm dans un LXC
  ne marche pas tant que le DNAT happen dans le netns hôte —
  `SO_ORIGINAL_DST` est conntrack-backed et conntrack est
  namespace-scoped. Chaque flow erre avec
  `Transparent mode failure: FileNotFoundError(2)`. Documenté inline
  dans `toolbox-mitm-wg.conf.template`.
- `mitmproxy --mode wireguard` (alternative) est **strictly single-peer**
  (JSON {server_key, client_key}). Migration de 35 peers = re-onboarding
  complet. Pas viable. **mitm-wg reste sur l'hôte.**

**Auth recovery** (`secubox-auth` 1.0.2 + `secubox-users` 1.4.2)
- `ntp_health.probe()` n'utilisait que `chronyc` — fallback timedatectl
  ajouté (les SecuBox ship timesyncd, pas chrony).
- **Auth complètement cassée découverte** : `/etc/secubox/users.json`
  + `auth.toml` étaient `root:root` → aggregator user `secubox` ne
  pouvait rien lire → `user_store: fallback to auth.toml... Permission
  denied` → tous les logins → "Identifiants incorrects".
- Le postinst `secubox-users` 1.4.1 chownait users.json mais ne touchait
  PAS auth.toml. `auth.toml` n'avait JAMAIS été chown'd par aucun
  postinst depuis l'install initiale en mai. Source fix : `secubox-users`
  1.4.2 couvre les deux.
- Live mitigations : chown manuel + drop-in `40-etc-secubox-rw.conf`
  (`ReadWritePaths=/etc/secubox` pour l'engine puisse persister
  `last_step` post-verify — sans ça verify levait 500
  "Read-only file system"). Note : `/etc/secubox` est déjà dans
  `ReadWritePaths` côté source `secubox-aggregator` 0.2.1, le drop-in
  est juste la couverture en attendant l'upgrade dpkg live.

**Phase 8 — anti-tracking opérateur (Utiq)** (`#500`)
- Issue créée avec plan complet R0 (log) / R1 (block) / R2 (mask) /
  R3 (pseudo-avatar via `avatar.py`).
- Schéma SQLite `utiq_events`, banner UI, doctrine CSPN du R3,
  Quick Win 1 j + Phase 2 1 sem + Phase 3 doctrine.

### ⬜ Next up

* **Phase 8 Quick Win (1 j)** : addon `utiq_defense.py` R0 + R1, tile
  banner "🎯 Utiq detecté", tableau brut `/admin/utiq-events`.
* **secubox-aggregator** : vérifier que 0.2.1 (drop NoNewPrivileges +
  `/etc/secubox` dans ReadWritePaths) sera bien upgrade live au prochain
  dpkg run sur gk2 — sinon ré-appliquer le drop-in manuel.
* **wg-quick / mitm-wg en LXC** : nécessite un dispatcher multi-peer
  custom ou wg-quick sur LXC privilégié avec accès netfilter partagé.
  Pas urgent — l'archi hôte est saine pour 35 peers.

---

## 🔄 2026-06-07 : Phase 7 reboot follow-up sprint SHIPPED (ref #498)

Two main user-visible problems surfaced after the Phase 7.D ASGI
consolidation reboot : (1) iPhone tunnel ceased to work end-to-end,
and (2) the kbin R3 verification card insisted "Hors tunnel R3" even
when the iPhone was clearly on the tunnel. Both fixed + several
collateral fixes.

### ✅ Done — packages bumped

| Package | from | to | Why |
|---|---|---|---|
| secubox-toolbox | 2.1.0-1 | **2.2.0-1** | WG boot survival + R3 detection chain + NM keyfile + admin rate-limit |
| secubox-aggregator | 0.1.0-1 | **0.2.0-1** | Loader v2 + migration helper v2 |
| secubox-waf | 1.1.3-1 | **1.2.0-1** | /bans/history + Tracked Attackers tile |
| secubox-magicmirror | 1.1.0-1 | **1.1.1-1** | api/routers/ shipping fix |
| secubox-openclaw | 1.0.0-1 | **1.0.1-1** | postinst chown for aggregator user |

### ✅ Done — fixes in detail

**WG boot survival** ([commit `8b0d4840`](https://github.com/CyberMind-FR/secubox-deb/commit/8b0d4840))

* `/etc/nftables.d/secubox-toolbox-wg.nft` — UDP 51820 input accept +
  `inet wg-toolbox` table (postrouting MASQUERADE, prerouting DNAT
  443/80 to mitm-wg, DNS DNAT 10.99.0.1:53 + 8088 → 10.99.1.1, QUIC
  drop). Loaded by `nftables.service` at boot.
* `secubox-toolbox-wg-restore.service` — one-shot replays
  `wg-peers.json` (35 peers) after `wg-quick@wg-toolbox` at boot
  via `wg set`.
* `unbound/99-secubox-wg.conf` — binds 10.99.1.1 + 10.99.0.1 with
  `ip-transparent`, allows 10.99.0.0/16.
* `wg.py` — new profiles get `DNS = 10.99.1.1` (was 10.99.0.1,
  served by wlan AP which is often linkdown).
* `service.d/20-bind-all.conf` — captive portal uvicorn binds
  `0.0.0.0:8088` so DNAT can land WG peer probes (was
  `--host 10.99.0.1`, only on the down wlan).

**R3 detection chain** ([commits `22748b29`, `613de765`, `9ac35005`](https://github.com/CyberMind-FR/secubox-deb/commits/master))

* New `inject_xff.py` mitm-wg addon (loaded FIRST) sets
  `X-Forwarded-For`, `X-R3-Peer: 10.99.1.x`, `X-Through-R3-Tunnel: 1`
  on every upstream request — so HAProxy → nginx → toolbox FastAPI
  see the real peer IP after the wg → mitm-wg → upstream loop.
* `api.py` new `_client_ip(request)` helper : `X-R3-Peer` > leftmost
  XFF > raw socket peer. Splash + `_resolve()` now use it.
* New `GET /wg/r3-check` returns `{tunnel:bool, peer_ip}` based on
  `_client_ip`. Same-origin HTTPS so iOS Safari doesn't block it as
  mixed content (the previous probe used `http://10.99.0.1:8088/qr/...`
  which Safari refused to fire from an HTTPS page).
* `landing.html.j2` JS rewritten — `fetch('/wg/r3-check')` for tunnel
  detection ; `fetch('https://duckduckgo.com/favicon.ico', mode:
  'no-cors')` for CA trust (was `<img https://www.gstatic.com/...>`
  which was both whitelisted by mitm-wg AND returned ambiguous
  204 errors).

**NetworkManager keyfile** ([commit `6812dfb0`](https://github.com/CyberMind-FR/secubox-deb/commit/6812dfb0))

* New `GET /wg/profile/new.nmconnection` emits the same fresh peer
  in NM keyfile format with `private-key-flags=0` — Linux operators
  can drop it into `/etc/NetworkManager/system-connections/` and
  `nmcli c reload` for one-click Cosmic/GNOME/KDE import without
  the `--ask` workaround.

**Rate-limit + memory** ([commit `7e5c510c`](https://github.com/CyberMind-FR/secubox-deb/commit/7e5c510c))

* `nginx/toolbox.conf` + `nginx/secubox-toolbox-limits.conf` :
  `limit_req zone=sbx_toolbox_admin rate=20r/s burst=40 nodelay`
  on `/api/v1/toolbox/admin/*`. A Firefox tab on the admin dashboard
  was hammering the aggregator at 530 req/s (stacked setInterval) —
  load avg dropped 9.16 → 2.34, free RAM 137 → 353 MB once applied.
* Live-masked `secubox-ui-manager.service` — was looping in
  `activating(start)`, eating 74 % of one core. Needs a real fix or
  systemd `Restart=` policy tightening as a follow-up.

**Aggregator follow-ups** ([commits `0cc99d51`, `33b35643`](https://github.com/CyberMind-FR/secubox-deb/commits/master))

* `secubox-magicmirror` debian/rules now installs `api/routers/`
  (was shipping only `api/main.py` and an empty `__init__.py`).
* `secubox-openclaw` postinst `chown secubox:secubox` on
  `/var/lib/secubox/openclaw/` so the aggregator user can traverse
  it during the module's import-time `mkdir`.
* Migration helper skips legacy `/usr/lib/secubox/secubox-<name>/`
  twin dirs whose canonical unprefixed sibling already exists.

### ⬜ Next up

* **R3 verification PAGE on iPhone** still needs a refresh after the
  cert-trust probe fix lands ; expected to read "Tunnel R3 actif +
  CA R3 trusté" once the user retests.
* **`secubox-ui-manager`** is masked live but the service-side fix
  (preventing the `activating(start)` loop) is not in source yet.
* **Heartbeat 503 + sentinelle-gsm 404** — minor module-state
  issues, not loader-related.

---

## 🔄 2026-06-06 : Phase 7.D ASGI consolidation SHIPPED (ref #498)

Master uvicorn process mounts every per-module FastAPI as a sub-app —
replaces 100+ per-module uvicorn services. Branch
`feature/498-asgi-migrate` (commits `5ef13b56`, `7b8cc301`, `b1ee9427`,
`705476cf`). No PR yet (per memory rule — push freely, open PRs only on
ask).

### ✅ Done

* New package `secubox-aggregator` (1.0.0-1) :
  - `aggregator/main.py` : FastAPI gateway, reads
    `/etc/secubox/aggregator.toml`, mounts each module's FastAPI at
    `/api/v1/<name>` via `app.mount()`. Loader uses synthetic parent
    package `sbx_pkg_<name>` so `from .deps import X` works AND
    `sys.modules["api.X"]` cache is dropped before/after each load
    (otherwise auth shadows haproxy etc.).
  - `systemd/secubox-aggregator.service` : single uvicorn listening on
    `/run/secubox/aggregator.sock` — `--workers 1 --backlog 400
    --limit-concurrency 200 --log-level warning`, `PYTHONOPTIMIZE=1`,
    `MemoryMax=1G`, `MemoryHigh=768M`.
* `sbin/secubox-aggregator-migrate` : reusable cutover helper.
  Discovers all `/usr/lib/secubox/<name>/api/main.py`, writes
  `/etc/secubox/aggregator.toml`, restarts aggregator, reads
  `/health` to learn what mounted, then rewrites nginx
  `proxy_pass` lines in **both** `/etc/nginx/secubox.d/` and
  `/etc/nginx/secubox-routes.d/` plus the inline blocks +
  `/api/` catch-all in `sites-enabled/webui.conf`, preserving
  `/api/v1/<name>/` prefix on every rewrite. Stops + disables
  migrated per-module services, prints rollback recipe.
* Live on gk2 after reboot :
  - **119 of 121 modules mounted** in a single aggregator process
    (1 mounted from 110 after the loader fix added 9 modules)
  - Per-module uvicorn count : 103 → 41 procs (still 41 because
    some modules are not yet in the toml or run side-services)
  - RAM uvicorn footprint : 3499 → 1984 MB (**-43 %**)
  - Free RAM : 153 MB → 2.7 GiB (**+18×**)
  - Aggregator RSS ≈ 170 MB serving 119 modules
* 2 remaining import failures are real module bugs, not loader bugs :
  - `magicmirror` ships `api/__init__.py + api/main.py` only ; its
    `from .routers import mmpm` import has no `routers/` package
    in the .deb. Was already broken under its own systemd unit.
  - `openclaw` mkdir's `/var/lib/secubox/openclaw/scans` at import
    time — that directory is 0750 `root:root`, aggregator runs as
    `secubox`. Fix is in openclaw postinst, not here.

### ⬜ Next up

* Fix magicmirror : ship `api/routers/mmpm.py` in the .deb (it's
  currently missing from `debian/install`).
* Fix openclaw : `chown -R secubox:secubox /var/lib/secubox/openclaw`
  in postinst (or chmod 0755 the parent dir).
* Chase 4 nginx 503/404 stragglers (`heartbeat 503`, `secubox-haproxy`
  / `secubox-hub` / `sentinelle-gsm` 404) — these route fine but the
  module's own `/health` route is missing or hangs.
* Wiki page : add Phase 7.D section to `Phase-7-Roadmap.md` (done
  in same sprint — see commit in `secubox-deb.wiki`).

---

## 🔄 2026-06-05 : Phase 7.A.2 + 7.B WAF dashboard + rate-limit + honeypot SHIPPED (ref #498)

### ✅ Done

* Backport `packages/secubox-waf/mitmproxy/secubox_waf.py` : Phase 6.J
  Connection:close + Phase 7.A bridge code. Two WAF copies in sync.
* `debian/postinst` auto-runs `secubox-waf-cs-bridge-setup` if cscli present,
  installs config to `/etc/secubox/waf/` AND bind-mounts into LXC.
* `api/routers/waf.py` GET `/enforcement` : bridge_enabled, bans_pushed,
  bans_failed, requests, blocked, warnings, rate_limit_offenders,
  honeypot_hits_last_hour, recent_bans (cscli --origin=secubox-waf),
  recent_threats (threats.log tail).
* `www/mitmproxy/threats.html` : new dashboard tab — 6 KPI cards + 2 tables,
  auto-refresh 5s.
* `nftables/secubox-waf-ratelimit.nft` : table inet `secubox_waf_ratelimit`
  with offenders_v4/v6 (dynamic 5min) + whitelist_v4 (LAN). Rule :
  tcp SYN 80/443, limit 30/s burst 50 → add offender + drop. Live-loaded.
* `secubox-waf-ratelimit.service` (systemd) replays on boot.
* `nginx/honeypot.conf` : 5 location blocks (/wp-admin /.env /.git/config
  /phpmyadmin /actuator /autodiscover ...) → empty 200 + log
  `/var/log/nginx/honeypot.log` (custom format).
* `debian/postinst` installs honeypot.conf in `secubox-routes.d/` + creates
  log_format snippet in `conf.d/`.
* Merge `4f89bd8b` on master (8 files, 938 insertions). Worktree cleaned.

### ⬜ Next up

* **Phase 7.C** (kept in #498, long-term) :
  - eBPF/XDP kernel filter (replace Python WAF hot-path)
  - ModSecurity in HAProxy with OWASP CRS rules
  - Federation : CrowdSec Hub + AlienVault OTX + Spamhaus DROP
* **Wiki page** `WAF-active-enforcement` documenting Phase 7.A/A.2/B setup +
  operator runbook.
* **FAQ entry** : "How are scanners dropped?" → links to Phase 7 pipeline.
* **README** Phase 7 mention in the security stack section.

---

## 🔄 2026-06-05 : Phase 7.A WAF active enforcement SHIPPED (ref #498)

### ✅ Done

* Bridge mitm WAF (LXC) → CrowdSec LAPI (host) → nft drops, full chain E2E :
  login 200 + alert 201 + cscli decision + nft entry, ~12s round-trip.
* `_ban_via_crowdsec()` in `secubox_waf.py` uses watcher JWT auth (POST
  /v1/alerts), urllib stdlib (no httpx dep), 25-min JWT cache, auto-refresh
  on 401. Stats : `bans_pushed`, `bans_failed`.
* `secubox-cs-bridge.service` (socat 10.100.0.1:8080 → 127.0.0.1:8080) so
  the mitm LXC reaches host LAPI without invasive CrowdSec config change.
* `secubox-waf-cs-bridge-setup` script : idempotent, registers machine with
  `cscli machines add -f -` (avoids touching local_api_credentials.yaml),
  writes config TOML.
* `crowdsec.toml.example` documents schema (enabled/url/machine_id/password/duration).
* Merged to master in `3eb5378e`. Worktree 498 cleaned.

### ⬜ Next up

* **Phase 7.A.2 followups** : backport into `packages/secubox-waf/`,
  wire `debian/postinst` to invoke setup script + bind-mount config into LXC,
  WAF dashboard tab in admin webui showing `bans_pushed` counter.
* **Phase 7.B mid-term** : nft rate-limit pre-mitm (catches TCP-only scanners
  like the 134.195.158.62 slowloris from earlier today), live attacker
  top-20 dashboard, honeypot routes for `/wp-admin /.env /.git/config` etc.
* **Phase 7.C long-term** : eBPF/XDP kernel filter, ModSecurity replacement,
  CrowdSec Hub + AlienVault OTX + Spamhaus federation.

---

## 🔄 2026-06-05 : Phase 6 R3 WireGuard — MAJOR RELEASE shipped (ref #496)

### ✅ Done

* **WG server** `wg-quick@wg-toolbox` UDP 51820 multi-peer, NAT via pure nft,
  DSL port-forwarded, `kbin.gk2.secubox.in` DNS A record via Gandi API.
* **mitm-wg transparent** sur 10.99.1.1:8081, launcher wrapper compose
  `--set ignore_hosts=<regex>` from `/var/lib/secubox/toolbox/mitm-bypass.conf`
  (15 patterns defaults : Signal/WhatsApp/Telegram/Apple Push/banks FR).
* **Dedicated R3 CA** `Gondwana ToolBoX R3 CA` (final : pas de SAN — Android
  Chrome ne supporte pas SAN avec espaces, affichait "émis par null").
  Serve `/wg/ca.pem`, `/wg/ca.crt` (DER), `/wg/ca.mobileconfig`.
* **R3 first-class identity** : `mac_hash_of()` WG-aware (10.99.1.x →
  sha256(pubkey)[:16]). Cascade fix tous addons + `/wg/profile/new`
  enregistre peer in `clients` table level=r3. 21 peers backfilled.
* **Banner enrichi** : 🍪 cookies (set+sent) + 🎯 trackers (body scan 200kB)
  + ⚠ tracker-host (1st-party). URL "Mon rapport" dynamique kbin public.
* **Splash R3 detection** : large banner violet pour 10.99.1.x source, masque
  R0/R1/R2 chooser (useless en R3).
* **Landing public** kbin : 8-icon quicknav, 8 live KPI cells /5s, 🔬 cert
  2-step probe (tunnel + CA trust), 4-level cards, SVG charts.
* **Admin webui** : tabs 👥 Clients + 🛡 Mitm filtering, rich client table,
  level switch modal, inline pattern add/delete.
* **Kbin filter-control = READ-ONLY**, edit déplacée vers
  `admin.gk2.secubox.in/toolbox/` (SSO-gated, new Filter card).
* **Multi-OS install** : `/wg/r3-install` 5 tabs (iOS/Android/Linux/macOS/Win)
  avec copy-paste commands. Wiki page complète.
* **mitm WAF leak FIXÉ** : root cause = pool keep-alive upstream qui jamais
  shrink, 1500+ FDs après 4h → 504. Fix 1 ligne :
  `flow.request.headers["Connection"] = "close"` dans SecuBoxWAF.request.
  Before/after : FDs 1513→3, scur 812→87, /toolbox/ 504→200/31ms.
  Backporté dans `packages/secubox-mitmproxy/addons/secubox_waf.py`.
* **Bugs résolus** :
  - mitm-wg crash-loop 191x (mitmproxy-ca.pem 0600 → 0640)
  - banner gate accepted only r2 (now r2+r3)
  - /report/me/html 400 sur WG (ajout ?mh= bypass)
  - streamlit LXC bouffait 250MB + 15 procs (stopped + auto-start off)

### ⬜ Next up

* **iPhone + Android E2E retest** : réinstaller CA Gondwana NEW
  (SHA1 `D5:E4:3A:C1:AD:4E:25:8A:A9:D4:2A:26:52:2C:D8:82:50:63:EA:0E`),
  supprimer ancien profil d'abord, vérifier banner R3 + cookies + trackers
  visibles sur HTTPS pages.
* **Merge branche feature/496-phase-6-wireguard-mitm-autocert-mode-r3 →
  master** (30 commits, 2918 lignes, branche prête).
* **Ouvrir PR #495** (Phase 5 LXC) + **PR #496** (Phase 6 WG) une fois
  banner E2E confirmé.

### 📌 Follow-ups potentiels

* Threat_counts dict cleanup périodique (mineur leak, ~1 entrée/IP unique)
* Investigation : pourquoi mitm-wg garde CPU > 30% au repos (idle keep-alives ?)
* WAF leak fix : appliquer aussi à secubox-mitmproxy-deb (LXC template)

---

## 🔄 2026-06-02 : Pi 400 boot to kiosk + login working

### ✅ Done

* **Diag du boot Pi 400** (SD v2.13.10) : multi-user.target jamais atteinte
  parce que 150 services enabled → restart loops sur ~10 services →
  kernel `task blocked > 120s` → boot abandonné à tty1. Identifié dans le
  journal post-boot (sudo NOPASSWD activé pour faciliter le diag).
* **SD patchée live** : 130 symlinks retirés de
  `multi-user.target.wants/`, 20 essentiels gardés (Debian core + SecuBox
  web stack). `secubox-bootmenu.service` aussi retiré de
  `sysinit.target.wants/`.
* **users.json patch live** : `admin` password = `secubox` (hash
  argon2id), `must_change_password` = false, user `runnervm3jyl0`
  auto-créé par le CI supprimé.
* Pi 400 reboot sur SD patchée → `Reached target multi-user`,
  `Started secubox-kiosk.service`, `Reached target graphical.target`,
  Chromium fullscreen sur la kiosk login UI. Login `admin / secubox` OK.
* **#442 filée + PR #443 mergée** : Step 5.3 dans `build-rpi-usb.sh`
  applique le même whitelist en CI build (130 symlinks → 20).
  `secubox-bootmenu.service` également retiré de sysinit.target.wants.
* **Tag v2.13.11 poussé**, watcher `boqacts2x` en cours sur le rebuild
  rpi400.

### ⬜ Next up

### 🎪 Salon demo readiness — rpi400 doit être prêt

Le Pi 400 doit servir de démo terrain. Tout ce qui distingue un appareil
"prototype" d'un appareil "fini" doit être corrigé. Priorité salon :

* **Cursor kiosk** (P0 salon, **PAS cosmétique**) : retirer `-nocursor`
  du `ExecStart` de `secubox-kiosk.service`. Le visiteur salon DOIT
  voir où il pointe à l'écran sinon ça paraît cassé. Fix simple en
  source + live SD patch.
* **LAN IP visible sur la kiosk login UI** : afficher l'IP du board
  sur l'écran de login pour qu'on puisse pointer/expliquer "ce boîtier
  est joignable à 192.168.x.y".
* **Admin password seed côté CI** : ship `users.json` avec un password
  seedé (pas `password_hash: null`). Pour le salon, login direct sans
  intervention manuelle.
* **Mode profil kiosk UI allégé** (architecture propre, post-v2.13.11) :
  remplacer `secubox-full` + mass-mask par un profil "kiosk-light"
  installant ~15 paquets (nginx + secubox web stack + chromium/openbox/xinit).
  Image plus petite (~3-4 GB au lieu de 8 GB), boot plus rapide,
  plus de mass-mask défensif. À filer en issue.
* Verdict v2.13.11 CI (watcher `boqacts2x` en cours) — confirmer que
  le mass-mask CI-side produit une image qui boote autonomement.

### 📋 Backlog non-bloquant (post-salon)

* #434 kiosk lockdown, PR #429 NC dashboard, #421 sockets, #422 vm-x64,
  espressobin / live-amd64 / mochabin builds, cloud.gk2 vhost.

---

## 🔄 2026-06-01 : kiosk-on-rpi400 actually ships (#436 closed)

### ✅ Done

* **5 PRs / 6 tags v2.13.5 → v2.13.10** pour faire passer `--kiosk` du stub
  au vrai. Voir HISTORY.md 2026-06-01 pour la table complète des failures
  exposées à chaque itération.
* **#436 chain résolu** :
  - PR #437 (v2.13.6) — chroot safety net (systemctl wrapper exporte
    `SYSTEMD_OFFLINE=1`, `policy-rc.d` retourne 101, tmpfs 64M `/boot/firmware`).
  - PR #438 (v2.13.7) — tmpfs 64M → 512M (ENOSPC sur initrd) + bind `/proc` et
    `/sys` (raspi-firmware utilise findmnt).
  - PR #439 (v2.13.8) — force `graphical.target.wants/secubox-kiosk.service`
    symlink (SYSTEMD_OFFLINE ne le matérialise pas toujours).
  - PR #440 (v2.13.9) — symlink relatif au lieu d'absolu (host `[[ -e ]]`
    ne peut suivre un chemin absolu hors `${ROOTFS}`).
  - PR #441 (v2.13.10) — tmpfs → `mount --bind ${ROOTFS}/boot/firmware
    ${ROOTFS}/boot/firmware` (tmpfs jetait les fichiers raspi-firmware au
    umount, self-bind les préserve).
* **Image v2.13.10 rpi400 téléchargée depuis le workflow artifact**
  (build-live-usb-rpi400 = SUCCESS, le Release n'a pas publié à cause des
  autres archs cassées). 1940 MB compressé, sha256 ✓.
* **SD `/dev/mmcblk0` flashée** v2.13.10 — 8.6 GB en 227s @ 37.8 MB/s.
* **Tous les artefacts kiosk vérifiés** sur la SD :
  boot-mode=kiosk, default.target → graphical.target,
  secubox-kiosk.service présent, WantedBy symlink relatif OK,
  chromium installé, `/usr/share/secubox/kiosk/secubox-kiosk.sh` présent.

### ⬜ Next up / carry-overs

* **Boot test physique** Pi 400 avec la SD v2.13.10 — confirmer que le
  kiosk chromium s'affiche bien sur HDMI au 1er boot.
* Release `create-release` job rouge à cause de :
  - `build-live-usb x64 amd64` (préexistant)
  - `build-mochabin-live-usb` (préexistant)
  - `build-images espressobin-v7` / `-ultra` (préexistant)
  À traiter séparément du chain kiosk.
* **#434** kiosk lockdown design (frontend + backend rate-limit + admin unlock).
* **PR #429** NC dashboard fix encore à ouvrir (branche pushée).
* **#421** sockets `/run/secubox/*.sock` + `#422` vm-x64 cascade.
* **cloud.gk2.secubox.in** pas dans `nextcloud.conf` server_name.

---

## 🔄 2026-05-31 : v2.13.3 → v2.13.4 cross-build green + media + 4 issues filées

### ✅ Done

* **v2.13.3** taggé puis verdict KO : PR #428 (`-a matrix.arch`) nécessaire
  mais insuffisante. Sur runner amd64 avec `-a arm64`, debhelper appelle les
  cross-tools `aarch64-linux-gnu-{strip,objdump}` non installés.
* **#431** filée + **PR #432** mergée même heure : install
  `binutils-aarch64-linux-gnu` dans la step apt du job arm64 de
  `build-packages.yml` (~5 MB, ~3 s setup).
* **v2.13.4** taggé → ✅ **APT publish vert pour la 1ʳᵉ fois depuis v2.13.0**.
  Release contient 153 assets dont 5 arm64 ; `apt.secubox.in/dists/bookworm`
  sert 15 packages arm64. Chaîne complète : #425 + #427 + #431.
* **#429** Nextcloud dashboard data réelle : `_public_base_url()` lit
  `overwrite.cli.url` → trusted_domains → fallback ; `/users` ne court-circuite
  plus quand LXC down ; `/storage` passe par `lxc_attach` `du`/`df` ; `/backups`
  reconnaît 3 patterns. Branche `feature/429-...` pushée (commit `b715c0e4`),
  **PR pas ouverte** (carry-over). Déployée live sur `/usr/lib/secubox/nextcloud/api/main.py`.
* **Deploy mistake** rattrapée : `find | head` a renvoyé `mail/api/main.py`
  alpha 1ᵉʳ → nextcloud's main.py a écrasé celui de mail. Restauré via scp
  depuis sources, `secubox-mail` actif.
* **NC upload limits debug live** :
  - PHP SAPI Apache : drop-in `/etc/php/8.2/apache2/conf.d/99-secubox.ini` à
    4G uploads, 3600s exec. Premier essai n'a rien fait : `#` n'est pas un
    commentaire `.ini`, il faut `;`. Fixé.
  - nginx host : `client_max_body_size 4G` + `proxy_request_buffering off`
    dans `nginx.conf` http{}. Smoke test PUT 50M sur `nc.gk2` → 401 Sabre OK.
* **Media flashé** :
  - 🟢 microSD rpi400 (`/dev/mmcblk0`) avec v2.13.4 (8.6 GB, 38 MB/s, sha ✅).
    ⚠️ **kiosk MISSING** dans l'image malgré `--kiosk` CI (#433).
  - 🟢 USB live amd64 (`/dev/sda`, DataTraveler 3.0). 1ᵉʳ stick mort (I/O
    errors à 268 MB, `usb 2-1: device not accepting address`). 2ᵉ stick OK
    (8.6 GB, 24 MB/s, sha ✅).
  - 🟢 VBox VM `SecuBox-live-amd64-v2134` créée + boote sur la kiosk login.
    Test : "Invalid credentials" inline mais pas de lockdown — voir #434.
* **Issues filées (5)** : #430 (NC federation OCM), #431 (cross-binutils,
  déjà fixé), #433 (kiosk silent fail), #434 (kiosk lockdown).

### ⬜ Next up / carry-overs

* **PR #429** à ouvrir (branche déjà pushée, fix déployé live mais source
  pas encore mergé en master).
* **#421** sockets `/run/secubox/*.sock` (RuntimeDirectory vs tmpfs collision)
  — reboot-tested fix attendu, puis revert le contournement Authelia sur
  lyrion.
* **#422** vm-x64 cascade `[FAILED]` en VBox (préexistant, pas re-testé v2.13.4).
* **#433** kiosk silent fail dans `build-rpi-usb.sh` — apt qemu-arm64 broken
  + `|| warn` masque, heredoc/seed ne se retrouvent pas dans le .img.
  Faire fail-loud + assertion build-time avant rsync.
* **#434** kiosk lockdown design : frontend template + JS counter + backend
  rate-limit 429 + endpoint admin unlock + TOML config.
* **cloud.gk2.secubox.in** pas dans `nextcloud.conf` server_name → tombe sur
  default_server "wrong-domain". Ajouter à la ligne `server_name nc.gk2
  nextcloud.gk2;`.
* **Patch SD kiosk** via chroot qemu encore en pending (chromium + xorg +
  openbox + xinit + secubox-kiosk.service + boot-mode=kiosk).
* Espressobin-v7 / -ultra image builds : encore en échec préexistant v2.13.4
  (à investiguer séparément).

---

## 🔄 2026-05-30 : release polish (v2.13.1 → v2.13.2) + media livré

### ✅ Done

* **v2.13.1** taggé (fix dual-compat fmrelay + zkp-hamiltonian → fmrelay built
  clean, mais publish toujours bloqué par sentinelle-gsm arm64).
* **#425** (sentinelle-gsm arm64 build) filée + fixée le même jour : add
  `override_dh_shlibdeps: dh_shlibdeps -Xsecubox-redsea` dans `debian/rules`
  pour sauter le scan auto-deps sur le binaire prébuild aarch64 (les runtime
  deps sont déjà déclarées dans control). PR #426 mergée.
* **#423** (`--kiosk` flag dans `build-rpi-usb.sh` était un stub) filée +
  fixée : ajout du vrai bloc d'install (chromium + xorg + openbox + xinit +
  unit `secubox-kiosk.service` sur vt7 + seed `boot-mode=kiosk` + default
  target `graphical`), et CI `build-all-live-usb.yml` ajoute `extra_args:
  "--kiosk"` sur l'entrée matrice rpi400. PR #424 mergée.
* **#422** filée (vm-x64 cascade `[FAILED]` en VBox : otg-gadget +
  networkd-wait-online + openclaw restart-loop, sshd plombe par cascade).
* **#421** filée + contournement live (lyrion) : sockets `/run/secubox/{authelia,
  cookies,certs}.sock` cachés par collision tmpfs-mount vs
  `RuntimeDirectory=secubox` dans namespace privé. Lyrion débloqué en
  commentant les 4 lignes `auth_request` du vhost (sauvegarde `.bak.sso-removed`).
* **v2.13.2** taggé : intègre fmrelay + zkp + sentinelle-gsm packaging fixes +
  rpi400 kiosk-by-default → la Release CI re-orchestre le tout, publish APT
  devrait débloquer pour la première fois depuis v2.13.0.
* **Media flashé pour l'opérateur** :
  - 🟢 **USB live amd64** sur Kingston DataTraveler 28,8 G (dd, sync OK).
  - 🟢 **microSD rpi400** sur SanDisk SC32G 29,7 G (dd, partprobe OK).
  - 🟡 **VirtualBox VM `SecuBox-amd64`** créée (NAT port-forward 2222/8080/8443)
    mais image cassée (#422) → VM gardée *powered off* en attendant le fix.

### ⬜ Next up / carry-overs

* Verdict v2.13.2 CI (watcher en cours) : confirmer que `publish` APT passe
  enfin proprement avec les 3 packaging fixes mergés (fmrelay + zkp +
  sentinelle-gsm).
* **#421** systemic socket fix (réconcilier `/run/secubox` tmpfs mount vs
  `RuntimeDirectory=secubox`) — reboot-tested. Re-activer ensuite l'Authelia
  `auth_request` sur lyrion (revert du contournement live).
* **#422** vm-x64 image : gater les services appliance-only (`otg-gadget`,
  etc.) sur le profil VM ; assouplir `networkd-wait-online`. Re-tester en
  VBox une fois fixé.
* Espressobin-v7 / -ultra image builds : encore en échec préexistant
  v2.13.2 (à investiguer séparément, distinct de la chaîne packaging).

---

## 🔄 2026-05-29: live ops + backlog sweep + v2.13.0 release

### ✅ Done
* **Live ops on gk2**: WAF LAN/RFC1918 whitelist (operator unban, #waf),
  LXC DNS fix (NC + mitmproxy resolved.conf upstream; FAQ doc), Nextcloud
  31.0.14→32.0.10 + config hardening (trusted_proxies, APCu, PHP mem/opcache,
  HSTS, gmp/imagick), NC user cleanup (→ admin+gk2 only), PhotoPrism stale env
  removed.
* **Issues merged/closed**: #390, #410 (user provisioning), #409 (Companion
  personas), #392, #394, #152, #150, #168, #395, #389, #391, #377; #153
  confirmed already-merged.
* **secubox-user-sync** (#410): SecuBox = source of truth; `set/seed/sync/list`
  pushes master users (gk2/admin) + passwords into NC + PhotoPrism with per-user
  photo folders. gk2/admin seeded live by operator.
* **Worktree tree tidied** to zero stale worktrees (license-phase-b-full kept).
* **v2.13.0** release tagged (minor bump) → CI builds packages + images
  (mochabin/real-ARM, espressobin-v7/ultra, vm-x64/amd64+VirtualBox, rpi400)
  + APT publish.

### ⬜ Next up / carry-overs
* Verify v2.13.0 CI: packages + the arm/amd64/rpi400 image artifacts.
* WAF addon two-copy drift (secubox-waf vs secubox-mitmproxy) — make cred-004 +
  whitelist durable in the live-source copy.
* Operator: re-confirm NC mobile reconnect (bruteforce stays OFF by decision).

---

## 🔄 2026-05-27 (evening): peertube + photoprism + mail + WAF unblocking

### ✅ Done (this leg)

* **PhotoPrism LIVE** at https://photoprism.gk2.secubox.in/
  (login: admin / secubox-CHANGE-ME). Podman-based, LXC 10.100.0.130,
  `--network=host` (CNI bridge unprivileged-LXC workaround).
* **Photos shared folder** `/data/shared/photos` bind-mounted into both
  PhotoPrism (`/var/lib/photoprism/originals`) and Nextcloud
  (`/var/www/nextcloud/data/Photos`). Smartphone NC client → "Photos"
  → PhotoPrism auto-indexes.
* **nextcloud.gk2.secubox.in URL** wired (was only `nc.gk2`):
  mitmproxy route entry added (host + LXC copies, see drift in TODO);
  nginx `server_name` aliased.
* **#394 NC SSO removal** so official mobile clients can authenticate
  (HTTP Basic + app-password don't carry Authelia cookie). NC bf
  protection disabled at runtime + table truncated.
* **#395 WAF cred-004 false-positive** on NC mobile login-poll
  (`/index.php/login/v2/poll?token=...`) fixed live + source-side.
* **CrowdSec allowlist** `secubox-trusted` with 4 internal nets.
* **8 GB swap** total (was 4 GB).
* **IP forwarding** root-fixed: `99-secubox-hardening.conf` set
  `ip_forward=0`, overrode our `90-secubox-lxc-forward.conf`
  (alphabetical loss). Renamed to `99-secubox-zz-…` so it wins.
  Also added explicit `lan0 masquerade` rule (real WAN, eth2 is
  down).
* **LXC template fix** for peertube + photoprism: replaced strict
  `common.conf + userns.conf + apparmor` defaults with matrix's
  working `debian.common.conf` template; otherwise postgres-15
  postinst and podman CNI both fail in unprivileged-LXC sandbox.
* **Bind-mount UID-mapping recipe**: host-side `chown -R
  100000:100000 /data/<service>/` to allow LXC root (UID 100000
  outside) to manage them.

### ✅ Done (2026-05-28 — peertube finished)

* **PeerTube LIVE** at https://peertube.gk2.secubox.in/ — upload
  confirmed by operator. Native install in LXC 10.100.0.120
  (Node 22 + pnpm + postgres-15 + redis + `peertube.service`).
  Admin `root` / `gisatejewumefatibedu` (rotate via UI). Fixes:
  pnpm with `MSGPACKR_NATIVE_ACCELERATION_DISABLED=1`, chown tree to
  peertube, Node 20→22 (8.2.0 requires ≥22), production.yaml
  (hostname/https/secret/db/listen 0.0.0.0). "Missing upload button"
  was a stale browser bundle — server side was correct throughout.
  See HISTORY 2026-05-28 entry. **Source backport still pending**
  (live native-in-LXC ≠ #388 Docker/Podman package design; #390
  vhost conf incomplete) — see TODO P0.

### 📋 Carry-overs (filed in TODO.md)

* Mail backup gap + URL fix (still deferred from earlier today)
* IP-forward + lan0-masquerade + sysctl-ordering backport to
  `secubox-system-tuning` package
* mitmproxy + WAF script live-config drift (host vs LXC copies)
* LXC template wiki: DNS resolv.conf, bind-mount chown UID 100000,
  template choice (debian.common vs strict)
* Release bump after everything lands (per user)

---

## 🔄 2026-05-27 (morning): Consolidation pass — audit + 2 real merges + 5 naming sweeps + gk2 deploy

### ✅ Done (this session)

- **Phase 1 audit** (`docs/superpowers/plans/2026-05-27-secubox-consolidation-audit.md`):
  re-runnable `scripts/audit-packages.py` inventories all 141
  packages with cluster + dep + service + route + has-payload data.
  Meta-finding: audit's projected ~100-package floor was naming-
  affinity intuition, real floor is ~135-137 (4-5% reduction).

- **2 real package merges** (-2 effective packages):
  - **#381** mmpm → magicmirror: APIRouter fold, frontend moves
    `/mmpm/` → `/magicmirror/mmpm/`. Old becomes oldlibs.
  - **#384** master-link → p2p: master-link's 851 LOC was dead
    (no nginx config → unreachable). Operator-scoping calls
    documented in commit.

- **1 packaging bug** (#378): secubox-c3box binary collision —
  Go variant renamed to `secubox-daemon-c3box`. **Not yet on gk2**
  (Arch:any, needs arm64 rebuild — daemon not currently installed
  on board so non-acute).

- **1 cleanup** (#380): 2634 LOC of dead source pruned from the
  three already-transitional mail packages.

- **5 Description-clarity sweeps** (#382, #383, #385, #386, #387):
  24 Descriptions clarified, 9 maintainer placeholders corrected.
  After these land, no `secubox-*` package on master ships an
  "X Module" placeholder headline anymore.

- **Build tooling fix** (`561007fe`): `scripts/build-packages.sh`
  switched from hardcoded 30-package allowlist to dynamic glob
  over `packages/secubox-*/` with `debian/control`. Was silently
  skipping 110 of 141 packages.

- **gk2 deploy**: 30 .debs apt-installed and verified.
  Transitional Breaks/Replaces fired cleanly. 24/24 expected
  services active post-deploy.

- **GitHub housekeeping**: 9 issues (#378, #380-#387) closed; 9
  merged remote branches deleted; 9 local worktrees cleaned.

### 📋 Carry-overs (filed in TODO.md)

- `secubox-daemon` arm64 rebuild on a Marvell-arm64 host so the
  c3box binary rename (#378) lands on gk2.
- `secubox-ndpid 1.0.1` blocked from gk2 by missing `ndpid` apt
  source — needs either package upload or `Recommends:` relax.
- Orphan nginx snippets (`mail-lxc.conf`, `webmail.conf`,
  `webmail-lxc.conf`) on gk2 manually removed; mail transitional
  postinsts should be patched to do this on other boards.
- Smart-strip packaging (#379, deferred to hardware track).

---

## 🔄 2026-05-26: SOC dashboard fixes — firewall_summary + WAF backend warm cache

### ✅ Done

- **v2.12.17** (`40b58372`, tagged + pushed): nft cache populator moved
  from `image/firstboot.sh` to `secubox-hub` package. Ships
  `/usr/sbin/secubox-nft-cache`, `secubox-nft-cache.{service,timer}`
  (timer auto-enabled via `timers.target.wants/` symlink), plus a
  sudoers fragment for the realtime fallback path.

- **v2.12.18** (`a1c60d6b`, tagged + pushed): `/firewall_summary`
  fallback ladder rewritten — `cache → realtime → cache-stale → none`.
  Found at deploy time that `NoNewPrivileges=true` on the hub blocks
  sudo, so realtime is best-effort; the stale-cache fallback prevents
  the widget from ever rendering zeros. Verified all four paths on gk2.

- **gk2 board cleanup**: removed two stray cron files
  (`/etc/cron.d/secubox-nft-cache`, `/etc/cron.d/secubox-nft-stats`) and
  `/usr/local/bin/secubox-nft-cache.sh` — leftovers from an earlier
  ad-hoc fix, NOT shipped by any package. They were racing the new
  systemd timer (both writing to the same `nft-ruleset.json`) and
  occasionally produced a 0-byte JSON. Documented for boards upgrading
  from v2.12.16.

- **secubox-waf 1.1.2** (not yet committed, deployed to gk2): the
  expensive `/stats`, `/alerts`, `/bans` computations moved to a
  single asyncio background task (`_warm_loop`, refresh every 30 s).
  Endpoints are now O(1) dict reads. Previously the 200 k-line
  threat-log scan ran on the request path; each cache miss took
  longer than the 30 s TTL on this board, so the cache never warmed,
  HAProxy 504'd, and the dashboard rendered empty with the WAF
  process burning 50-67 % CPU continuously. Post-fix on gk2:
  `/stats` 200-900 ms (was 6+ s or timeout), `/alerts` 360 ms,
  `/bans` 210 ms (was 5-15 s). `_read_log_tail()` uses
  seek-from-end of 512 KB so memory no longer scales with log size.

- **v2.12.19** (`30e89193`, tagged + pushed): secubox-waf 1.1.2 source
  committed. See above for the warm-cache rewrite rationale.

- **secubox-soc 1.0.1** (`0de665c5`, on master, deployed): source-side
  SOC dashboard had silently been rewritten into a "gateway-style" 44 KB
  frontend that talks to `/api/v1/soc/*` (a backend the production boards
  don't run). Production boards still ran the 107 KB "comprehensive
  dashboard" aggregating `/api/v1/hub`, `/api/v1/waf`,
  `/api/v1/crowdsec` and `/api/v1/hub/public/firewall_summary` — never
  captured back into source. First deploy of 1.0.1 from raw source
  clobbered the board's working dashboard and locked the user out
  (login.html redirect, no gateway backend). Recovery: pulled the 107 KB
  file from `/srv/www/soc/index.html` (May 10 snapshot still on board)
  back into source, stripped the `.logo*` CSS overrides that re-styled
  the sidebar.js-injected SecuBox brand logo as a 40×40 gradient box,
  committed, rebuilt, redeployed. Source is now the canonical
  comprehensive dashboard.

  Memory `feedback_source_first_always` saved as a hard rule: never
  bump+deploy a package without first diff-ing source against what's
  on the running board. Board frontends are authoritative.

- **RuntimeDirectoryPreserve mass-deploy**: discovered while
  troubleshooting crowdsec endpoint 502s. The crowdsec Unix socket
  had vanished from `/run/secubox/` because another secubox service
  restarted with a unit file that lacked `RuntimeDirectoryPreserve=yes`
  and wiped the directory. Source-side commit 24000d67 already added
  the keyword to all 96 source units, but only 16/127 service files on
  the board had it — the other 111 packages had never been redeployed
  since the commit. Rebuilt 100 packages (3 needed `-d` to skip
  python3-all build-dep), shipped 99 to gk2 with
  `dpkg -i --force-confold`. The cascade of postinst restarts on a
  Marvell ARM target overwhelmed the board enough that an emergency
  reboot was needed and triggered an fsck on `/data` (some writers
  hadn't shut down cleanly). Post-reboot: clock auto-synced via NTP,
  TOTP login OK, 84/127 services with Preserve, 41 services without
  `RuntimeDirectory=` (Preserve sans objet), 2 vrais restants à
  finir : `secubox-torrent` + `secubox-voip`.

- **wazuh postinst masked-tolerant** (`63284497`, pushed): one of
  the 100 packages (`secubox-wazuh`) initially failed install because
  its postinst did `systemctl enable` against a masked unit and `set -e`
  aborted, leaving the package `half-configured`. Recovery on board
  was `unmask → configure → re-mask` to respect operator intent.
  Source-side fix: wrap enable+start in
  `[ "$(systemctl is-enabled X 2>/dev/null)" != "masked" ]` so the
  same pattern survives masking. Same pattern likely belongs in every
  secubox-* postinst — audit deferred to TODO.

- **Docs sync** (`cfe16a6c`, pushed): TODO + WIP updated with the four
  session follow-ups in P0 (finish torrent+voip Preserve, audit
  postinst enable patterns, orchestrated mass-restart helper,
  build-packages.sh dynamic discovery).

### ⬜ Next up

All session deliverables landed and pushed. Follow-ups tracked in
`.claude/TODO.md` P0:

- Finir Preserve fix sur les 2 services restants (torrent + voip)
- Audit des `postinst` `systemctl enable` non-masked-tolerant
- Orchestrateur `secubox-system-restart` avant prochaine mass-deploy
- `scripts/build-packages.sh` discovery dynamique des paquets

### Notes

- Plans (TODO docs) saved earlier but not yet committed:
  `docs/superpowers/plans/2026-05-26-build-scripts-refactor.md`,
  `docs/superpowers/plans/2026-05-26-secubox-modules-consolidation.md`.
- amd64 DHCP work deferred — operator swapping hub for switch first.
- CI release-upload .gz truncation still pending investigation.

---

## ✅ 2026-05-24: Module dual-vhost MUST pattern + Lyrion/Zigbee/Authelia alignment (master 54da8a7c, b1718788, d4adc1a3)

Codified the dual-vhost split as a **REQUIRED** rule in
`docs/MODULE-GUIDELINES.md` §4 + `.claude/PATTERNS.md` Pattern 12:

| URL | Role |
| --- | --- |
| `https://admin.gk2.secubox.in/<module>/` | SecuBox admin (static, calls `/api/v1/<module>/*`) |
| `https://<module>.gk2.secubox.in/` | Real app web UI at vhost root, Authelia-gated |

**Why** — LMS Material loads `/material/customcss/`, z2m `/api/`,
Authelia `/api/firstfactor/`, Nextcloud `/apps/`. Reverse-proxying any
of them under `/<module>/` silently breaks every absolute asset URL.
Hit live on `admin.gk2.secubox.in/lyrion/`: 405 on `/cometd/handshake`,
CSS served as text/html.

**Source-of-truth rule** — `Open <App> UI →` button reads its href
from `/api/v1/<module>/access` at runtime. Never hardcode the public
hostname.

Aligned three modules:

- **lyrion 1.1.0** (b1718788, d4adc1a3) — `/lyrion/` is now static admin; `lyrion.gk2.secubox.in` keeps the real LMS Material UI. `lyrionctl` access URLs corrected (LAN `http://IP:9000/`, public `https://lyrion.gk2.secubox.in/`), `config_get` strips TOML inline comments (the bug that produced `http://IP:9000#webadminUI/`).
- **zigbee** (54da8a7c) — `Open Zigbee Manager` button now dynamic from `/access`.
- **authelia** (54da8a7c) — `autheliactl` same config_get + access_json fixes; public hostname default `auth.maegia.tv` → `sso.gk2.secubox.in`; `Open SSO Portal` button dynamic.

Live verified — all three return same shape:

```text
lyrion   lan http://192.168.1.200:9000/  public https://lyrion.gk2.secubox.in/
zigbee   lan http://10.100.0.111:8080/   public https://zigbee.gk2.secubox.in/
authelia lan http://10.100.0.20:9091/    public https://sso.gk2.secubox.in/
```

**Next**: apply same pattern to `secubox-nextcloud` and audit
`grafana/yacy/rustdesk` admin webuis for the same anti-pattern.

---

## ✅ 2026-05-21: Authelia SSO loop fix end-to-end — multi-cookie + access_control + X-Original-URL + named-location refactor (Issues #272 #273 #274 #278)

Closed the infinite redirect loop the user hit on `https://admin.gk2.secubox.in/zigbee/` after v1.0.5. Four PRs merged, hot-deployed, browser-validated.

- **#272 / PR [#275](https://github.com/CyberMind-FR/secubox-deb/pull/275)** — `secubox-authelia v1.0.6`: `install-lxc.sh` renders TWO `session.cookies[]` entries (`maegia.tv` + `${SECUBOX_HUB_DOMAIN}`, default `gk2.secubox.in`) + matching `access_control` rules. New env knob.
- **#273 / PR [#276](https://github.com/CyberMind-FR/secubox-deb/pull/276)** — `secubox-zigbee v2.4.4` + `secubox-lyrion v1.0.7`: `@sbx_auth_login` uses `$host` not `$http_host` to strip `:9080` leak; lyrion-vhost hardcodes `https://`.
- **#274 / PR [#277](https://github.com/CyberMind-FR/secubox-deb/pull/277)** — `secubox-authelia v1.0.7`: nginx `/__sbx_auth_verify` + FastAPI `/verify` forward `X-Original-URL` + `X-Forwarded-{Method,Proto,Host,Uri,For}` so Authelia picks the right `session.cookies[]` entry. Without it Authelia defaulted to `maegia.tv`, 401 → loop.
- **#278 / PR [#279](https://github.com/CyberMind-FR/secubox-deb/pull/279)** — `secubox-authelia v1.0.8` owns `location @sbx_auth_login` (moved from secubox-zigbee v2.4.5). Decouples lyrion from a transitive zigbee install.

**Hot-deployment caveat:** source-side `install-lxc.sh` doesn't touch the live LXC config — had to sed-patch `/etc/authelia/configuration.yml` inside the LXC to add `gk2.secubox.in` + `*.gk2.secubox.in` access_control rules; matching change is in v1.0.6 source for next install. Memorialized in memory `feedback_live_config_drift.md`.

**Collateral:** z2m frontend at 10.100.0.111:8080 was silently hung 14h with no listener (process alive but never bound). Restart took 20s before binding — root cause unknown, watch list. Board load 359 → 7 once the loop stopped.

---

## 🔄 2026-05-20: deploy grafana/yacy/rustdesk LXC modules on gk2 (192.168.1.200) — install-lxc.sh iterating bug-fixes

End-to-end deployment of v2.11.0's three new LXC modules on the live arm64 board surfaced four install-lxc.sh bugs missing from the local smoke build (which doesn't exercise lxc-create). All fixes are on branch `fix/install-lxc-download-template` (not yet committed/PR'd; pending v1.0.4 install validation on board).

- **Fix 1 — `lxc-create -t debian` broken on bookworm unprivileged** → switch to `lxc-create -t download -- --dist debian --release bookworm --arch $(dpkg --print-architecture)` (the legacy `debian` template fails: "This template can't be used for unprivileged containers").
- **Fix 2 — NAT MASQUERADE missing for 10.100.0.0/24** → existing `ip lxc` nftables table only masquerades `10.0.3.0/24` (default LXC bridge). LXC can ping its gateway but can't reach the internet without the rule. systemd-networkd's `IPMasquerade=ipv4` only lands when systemd-networkd manages the bridge — appliances using ifupdown/NM skip it. Add `ensure_masquerade()` idempotent function.
- **Fix 3 — Grafana apt GPG key not dearmored** → `wget https://apt.grafana.com/gpg.key` returns ASCII-armored key; `[signed-by=...]` requires binary keyring. Pipe through `gpg --dearmor`.
- **Fix 4 — `/etc/resolv.conf` symlink in download template** → ships as a symlink to `/run/systemd/resolve/stub-resolv.conf` which doesn't exist before systemd-resolved is up. `cat > /etc/resolv.conf` fails. Unlink then write. Also moved `ensure_resolv` after `lxc-start` (rootfs is owned by mapped uid 100000, host root can't write directly; needs `lxc-attach`).

Iteration trail: v1.0.0 (initial) → v1.0.1 (download template) → v1.0.2 (masquerade + resolv via host write + gpg dearmor) → v1.0.3 (resolv via lxc-attach) → v1.0.4 (unlink symlink). Currently v1.0.4 install running on board.

When grafana install completes successfully, repeat for yacy + rustdesk, then commit the four fixes as PR → tag **v2.11.1** (patch release).

### Spec backlog filed in parallel

- **#236 `secubox-rbs-sensor`** — Quectel EP06-E modem-based rogue-base-station sensor, layer WALL. Spec at `docs/superpowers/specs/2026-05-20-secubox-wall-ep06.md`. Prerequisites flagged: `wall_rbs_sensor.py` / `Observer` Protocol / `CellObservation` not yet in the repo — needs framework scaffolding in same package.
- **#237 `secubox-sentinelle-gsm`** — RTL-SDR + gr-gsm passive RX-only sensor for false-BTS detection (IMSI-catcher), layer MIND, feeds WALL/OPAD. Spec at `docs/superpowers/specs/2026-05-20-secubox-sentinelle-gsm.md`. Privacy-by-design: HMAC-truncated identifiers in PROD mode, LAB mode with consent banner + audit. Hard limits: RX only, no decryption, no tracking primitive.

Both deferred until v2.11.0 deployment is fully validated on board.

---

## 🔄 2026-05-19: bare-metal x86_64 polish — Pi services + X11 drivers (Issue [#226](https://github.com/CyberMind-FR/secubox-deb/issues/226), PR [#227](https://github.com/CyberMind-FR/secubox-deb/pull/227) opened pending review)

Follow-up to v2.10.1 bare-metal validation. Two ergonomic fixes; no functional change for arm64 Pi/MOCHAbin/ESPRESSObin targets.

- **Part A** — `ConditionArchitecture=arm64` on the three services that crash-looped on x86_64 boot: `secubox-healthbump.service`, `secubox-led-trigger.service`, `secubox-picobrew.service`. Same pattern as the existing `secubox-led-heartbeat.service` `ConditionPathExists` gate. systemd marks the unit "condition failed" in the journal but no `[FAILED]` noise on the boot console.
- **Part B** — `image/build-image.sh:606` expanded from `xserver-xorg-video-fbdev` only to the standard xorg driver set: `fbdev,vesa,intel,amdgpu,radeon,nouveau,qxl,vmware`. ~15 MB extra; KMS modesetting picks the right one at boot. Bare-metal Intel/AMD/Nvidia should hit X11 init under 15s vs. the 30-90s fbdev-fallback path observed during #224 validation.

Branch `fix/226-bare-metal-x86-64-polish-gate-pi-hardwar` head `3f5a24dd`. Test plan in PR body: re-run build-packages.yml (for the two .deb), then build-image.yml, then VBox + bare-metal regression.

---

## ✅ 2026-05-19: v2.10.0 + v2.10.1 — firstboot → image build → web URL → kiosk chain, end-to-end validated

Closed the chain that prevented `admin / secubox` login from working on a fresh appliance image — validated on both VBox amd64 and USB-booted bare-metal x86_64.

- **#210 / #211** — firstboot users.json v2 + argon2 (landed pre-session).
- **#218 / PR [#219](https://github.com/CyberMind-FR/secubox-deb/pull/219)** — `image/build-image.sh`: `dpkg -i --force-depends` left ~15 Debian-only Python deps uninstalled (python3-argon2, jose, cryptography, jsonschema, maxminddb, …). Added `apt-get install -f -y` after the slipstream step. Three CI iterations: first added all deps to `INCLUDE_PKGS` (python3-zmq broke debootstrap second-stage), second narrowed to argon2 only (same C-ext postinst issue), third dropped all `INCLUDE_PKGS` additions and relied solely on `apt-get install -f -y` post-debootstrap. Final minimal diff: 1 file, +17/-2.
- **#220 / PR [#221](https://github.com/CyberMind-FR/secubox-deb/pull/221)** — `secubox-health-doctor` declared compat 13 in both `debian/compat` and `Build-Depends: debhelper-compat (= 13)`. dh refused both. 132 other packages use the modern single-source pattern; deleted the duplicate file.
- **#222 / PR [#223](https://github.com/CyberMind-FR/secubox-deb/pull/223)** — discovered via offline image dump (debugfs on the dd-extracted ROOT partition, no sudo needed): nginx `try_files $uri $uri/ /index.html` fell back to hub `index.html` whose `checkAuth()` redirected to `/portal/login.html` which no longer exists since PR #169. Sed-replaced 67 source files, 82 occurrences → `/login.html`. The empty body in the offline `nginx-error.log` and the access log's identical `200`-serving the wrong file was the clincher.
- **v2.10.0 tag** (`fa07088a...wait wrong sha — see HISTORY`) — bundles #218 / #220 / #222. Release workflow triggered.
- **#224 / PR [#225](https://github.com/CyberMind-FR/secubox-deb/pull/225)** — bare-metal validation found chromium's zygote crashing in a restart loop with `disabled unprivileged user namespaces with AppArmor` on Debian 12. The kiosk-launcher only passed `--no-sandbox` in the VM branch. Added it to the bare-metal branch too (kiosk runs as a dedicated unprivileged user on a closed-network appliance with AppArmor per-process profile still applied — chromium renderer sandbox provides marginal value).
- **v2.10.1 tag** — bundles #224.

**Non-obvious learning** (saved to memory as `reference_ci_artifact_source.md`): `build-image.yml` uses `dawidd6/action-download-artifact@v3` to pull `secubox-debs-all` from the latest SUCCESSFUL `build-packages.yml` run **on any branch** (default `workflow_conclusion: success`). Cost one CI cycle today when PR #223's sed fix was on the test branch but the .debs came from master. Mitigation: always run `build-packages.yml` on the test branch **first**, then `build-image.yml`, and verify failure count = 0 (else action-download-artifact silently falls back to the previous successful master run).

---

## 🔄 2026-05-18/19: dropletctl static-publisher CLI — port from OpenWrt (Issue [#196](https://github.com/CyberMind-FR/secubox-deb/issues/196), PR [#199](https://github.com/CyberMind-FR/secubox-deb/pull/199) opened pending review)

### Objective

Build `/usr/sbin/dropletctl` in the `secubox-droplet` Debian package — the OpenWrt-derived static-content publisher that the existing FastAPI consumer (`packages/secubox-droplet/api/main.py`) has long expected. Subcommands: `publish` / `list` / `remove` / `rename`. Static-only (HTML / ZIP / tarball / directory). Delegates all HTTP-facing work (nginx vhost, HAProxy ACL, mitmproxy route) to `metablogizerctl site publish`. The package replaces the API-socket noun-verb wrapper from PR #185 / issue #181 (user-approved supersession).

### Workflow

Full superpowers loop in worktree `feature/196-implement-secubox-droplet-cli-dropletctl`:

1. **Brainstorm** → spec `docs/superpowers/specs/2026-05-18-dropletctl-design.md` (commit `5e6e1d83`)
2. **Plan** → `docs/superpowers/plans/2026-05-18-dropletctl.md` (commit `133c2c0e`, 11 TDD tasks, 1230 lines)
3. **Subagent-driven execution** with two-stage review (spec compliance + code quality) per task:
   - T1 scaffold (replaced PR #185's 215-line wrapper, surfaced to user, approved)
   - T2 publish arg validation (3 error cases)
   - T3 sanitization + HTML staging + metablogizerctl delegation
   - T4 ZIP extraction with single-nested-dir unwrap
   - T5 tarball + plain-directory input
   - T6 pinned idempotent re-publish
   - T7 remove subcommand
   - T8 rename subcommand + hardening fixes (collision/same-name guards)
   - T9 list subcommand
   - T10 Debian packaging — bumped 1.0.2 → 1.1.0, Depends: `secubox-metablogizer (>= 1.1), rsync, unzip, python3`
   - T11 lint sweep (shellcheck not installed locally, bash -n clean, bats green)
4. **Final whole-branch review** caught 2 bugs not seen in per-task reviews:
   - **Fix A** (`550403df`): `cmd_rename` was storing prefixed FQDN; switched to bare base domain so `cmd_list` doesn't double-prefix.
   - **Fix B** (`550403df`): `cmd_publish` now validates `domain` against `^[a-zA-Z0-9.-]+$` to block TOML injection via the API boundary.
   - **Test strengthening** (`0c08ae06`): test 16 now seeds the legacy-FQDN scenario via explicit-domain publish, genuinely red on old code.
5. **Final state:** 17 bats tests, 0 failures; debian/ packaged; spec/plan committed; PR opened.

### Accepted plan deviations (all bug fixes)

- **T3** — `local staging` → script-global so the EXIT trap can reference `$staging` after `cmd_publish` returns under `set -u`.
- **T8 hardening** — added collision check on `$new` (`mv` would nest into existing dir, corrupting both sites) + `old == new` short-circuit + inline comments on the asymmetric metablogizerctl delete (tolerant) vs publish (hard-fail).
- **T9** — `cmd_list`'s python heredoc now reconstructs `vhost = f"{name}.{domain}"`; plan's literal `https://{domain}/` would have printed the bare base domain for every site (test asserted the full vhost).

### Status

- **PR [#199](https://github.com/CyberMind-FR/secubox-deb/pull/199) opened** as `feature/196-implement-secubox-droplet-cli-dropletctl` head `0c08ae06`.
- **Hardware deploy on gk2** (192.168.1.200) deferred to post-merge per plan §"Hardware deploy".
- **Follow-up backlog** documented in the PR body: flock around TOML writers, shared python helper to dedupe the 3 regex copies, rename-on-publish-failure rollback, real metablogizerctl state in `cmd_list`, package README, man page.

---

## ✅ 2026-05-17: Release v2.9.0 + matrix-cap fix + amd64 VBox tester bundle + README frontend

### Status

- **Tag `v2.9.0`** pushed on master `8d02cdc9` — first master-line minor release since `v2.8.0` (2026-05-10).
- **`release.yml` run `25984244712`** in progress — builds packages (134 combos), system images (4 boards), Live USB, publishes to `apt.secubox.in`, creates GH Release.
- **README front page** got a new "Latest Releases" section (commit `382f5902`) with download links per target + verification recipe + pointer to the turn-key VBox tester bundle.

### What unblocked the release pipeline

`release.yml` had been silently failing since the package catalog crossed 128 entries (last successful full release was `v2.7.x`). Diagnosis:

- `build-packages.yml` matrix was `packages (134) × archs [amd64, arm64] = 268` — over GitHub Actions' hard **256-jobs-per-matrix cap**. The whole `build` step got skipped (zero matrix entries scheduled), cascading through collect → publish → build-images → build-live-usb → create-release.
- Fix on master `8d02cdc9`: `discover` now emits a flat `[{package, arch}, …]` list, pre-filtering arch-all packages out of the arm64 set. `build` uses `matrix.include` instead of cross-product. Inputs moved to step `env:` to avoid YAML/shell quote hell. Find pattern tightened to `*/debian/control` -not `*/debian/*/DEBIAN/control` to ignore dpkg-build artifacts. Result: ~134 combos (132 amd64 + 2 arm64), ≈half the cap.

### amd64 VirtualBox tester bundle ([`output/ci-vm-x64-25983593168/`](../output/ci-vm-x64-25983593168/))

- Built via CI run `25983593168` (master `2eff4045`, 14 min).
- Server-side fix to unblock CI: `apt.secubox.in/secubox-keyring.gpg` was ASCII-armored (apt's `signed-by=` needs binary). Dearmored in place on the board, sanity-checked with `apt-get update` from the board itself.
- Bundle contents: `secubox-vm-x64-bookworm.{img.gz,img,vdi}` + pure-Python `raw_to_vdi.py` (no `qemu-img`/`VBoxManage` needed) + `verify.sh` (6 green checks: CI SHA + local hashes + VDI header + GPT layout + ESP `/EFI/BOOT/BOOTX64.EFI`) + tester-friendly `README.md` + `FIX-PXE.md` (NIC-off one-liner workaround for VBox 7 EFI quirk).

### Followup

- After release.yml completes, verify all 9 expected asset categories landed on the GH Release page (5 board images + Live USB + installer ISO + .deb bundle + SHA256SUMS).
- Cross-check that `apt.secubox.in/dists/bookworm/main/binary-{amd64,arm64}/Packages` lists the v2.9.0 versions.
- Bump the README's [Metric] table from 132 → actual final package count if the discover output differs.

---

## ✅ 2026-05-16/17: eye-remote multi-gadget L3 DHCP — Phase 1 (Issue [#158](https://github.com/CyberMind-FR/secubox-deb/issues/158), PR [#161](https://github.com/CyberMind-FR/secubox-deb/pull/161) MERGED `e91b9e9e` + live-deploy fixes PR [#164](https://github.com/CyberMind-FR/secubox-deb/pull/164) MERGED `680734db`)

### Objective

Allow N Pi RNDIS gadgets to coexist at L3 on `eye-br0` with deterministic
per-Pi addressing via a `dnsmasq` DHCP server scoped to the bridge. Round
images switch from static `10.55.0.2/30` peer to a DHCP client so each Pi
gets a unique `10.55.0.10–.250` lease. Phase 2 (explicit pairing approval)
stubbed and deferred to a follow-up issue.

### Tasks executed via subagent-driven development (17 tasks)

- **Task 1** — Parser library: `reservations.conf` reader (per-MAC TOML-style entries, Pydantic model)
- **Task 2** — Parser library: `dnsmasq.leases` reader (epoch + MAC + IP + hostname)
- **Task 3** — Parser library: IP assignment logic (pool `10.55.0.10–.250`, first-fit, MAC stable)
- **Task 4** — Pydantic models: `GadgetLease`, `GadgetReservation`, `LeaseState` + full pytest suite
- **Task 5** — FastAPI router: `GET /api/v1/eye-remote/leases` (active leases joined with reservation table, JWT-gated)
- **Task 6** — `api/main.py` registration of the leases router + lifespan wiring
- **Task 7** — dnsmasq config: `eye-remote-dnsmasq.conf` scoped to `eye-br0`, pool `10.55.0.10–.250`, 24 h lease, `dhcp-script=leasewatch.sh`
- **Task 8** — Dedicated systemd unit `secubox-eye-dnsmasq.service` (masked by `dnsmasq.service` on Debian, `PIDFile=/run/secubox/eye-dnsmasq.pid`)
- **Task 9** — `find-usb-serial`: udev + sysfs helper that maps a USB gadget interface to the Pi's CPU serial (written to `/etc/secubox/eye-remote/serials/`)
- **Task 10** — `leasewatch.sh` dhcp-script hook: on `add`/`old` events auto-appends new MAC to `reservations.conf`; logs JSONL audit entry
- **Task 11** — nftables snippet: narrow DHCP allow on `eye-br0` only (`udp dport 67`) — default DROP preserved
- **Task 12** — Debian packaging (`secubox-eye-remote`): ships dnsmasq config, systemd unit, nftables snippet, leasewatch.sh, postinst enables + starts `secubox-eye-dnsmasq.service`
- **Task 13** — Debian packaging (`secubox-system`): ships `find-usb-serial` + `leasewatch.sh` to `/usr/lib/secubox/`; bumped version
- **Task 14** — Round image: `usb0` → `eye0` rename via `.link` file (udev predictable names), updated all references in build script + gadget composer
- **Task 15** — Round image: `eye0` switched to DHCP client via `systemd-networkd` `.network` file; firstboot derives hostname from CPU serial; build script enables `systemd-networkd`, disables competing `dhcpcd`/`usb-network.service`
- **Task 16** — netns multi-gadget DHCP integration test (`tests/scripts/test-eye-remote-multi-gadget-netns.sh`): two veth pairs simulate two Pi gadgets; verifies distinct leases, lease renewal, and `find-usb-serial` path — skipped without root, ready for privileged CI runners
- **Task 17** — Docs + tracking (this commit): `MULTI-GADGET.md` banner, WIP.md, HISTORY.md

### Status

- **PR [#161](https://github.com/CyberMind-FR/secubox-deb/pull/161) MERGED** as `e91b9e9e` (2026-05-16 21:32 UTC) — main DHCP work.
- **PR [#164](https://github.com/CyberMind-FR/secubox-deb/pull/164) MERGED** as `680734db` (2026-05-17 04:17 UTC) — `fix(eye-remote): live-deploy regressions on 192.168.1.200`, caught after the MOCHAbin deploy.
- Phase 2 (pairing approval) remains a separate follow-up issue, not on master.
## ✅ 2026-05-16: eye-remote — link-rename collision fix for multi-gadget MOCHAbin USB (Issue [#155](https://github.com/CyberMind-FR/secubox-deb/issues/155), PR [#157](https://github.com/CyberMind-FR/secubox-deb/pull/157) MERGED `e2a905ca`)

### Status (worktree `155-eye-remote-link-rename-collision-when-mu`, branch `fix/155-eye-remote-link-rename-collision-when-mu`)

- New canonical `eye-br0` bridge `.netdev` + `.network` shipped in `packages/secubox-eye-remote/networkd/`
- `secubox-eye-remote.install` updated to deploy them to `/etc/systemd/network/`
- udev rule + connect/disconnect handlers rewritten across `packages/secubox-system/` (and mirror in `packages/secubox-eye-remote/udev/`) — no per-iface IP assignment, just enslave into bridge
- Idempotent `remote-ui/round/host-cleanup-dead-config.sh` runs locally on a host to:
  - Drop the deployed netplan `eye-remote` ethernet stanza
  - Remove the hand-installed `10-eye-remote.link` / `50-eye-remote.network` / `interfaces.d/usb0`
  - Install the packaged bridge files, sync udev + handlers
  - Reload networkd + udev
- Multi-gadget L3 limitation documented in `remote-ui/round/MULTI-GADGET.md` (both Pis claim `10.55.0.2/30` — needs a Round-image change, not host-side)
- **Hotfix applied live on `192.168.1.200`** — `eye-br0` UP with `10.55.0.1/24`, three rndis_host slaves attached, uvicorn binding succeeds, `curl http://10.55.0.1:8000/health` → HTTP 200
- **PR [#157](https://github.com/CyberMind-FR/secubox-deb/pull/157) MERGED** as `e2a905ca` (2026-05-16 11:43 UTC)

### Followup (separate issue)

- Round image: derive peer IP from MAC (or run DHCP client) so two gadgets can coexist at L3 — beyond #155 scope

## ✅ 2026-05-17: Cookie audit pipeline DEPLOYED + banner UX cleanup (Issue [#156](https://github.com/CyberMind-FR/secubox-deb/issues/156) closed via PR [#159](https://github.com/CyberMind-FR/secubox-deb/pull/159) `a19486c9`)

RGPD / ePrivacy compliance reconciler — server ledger (mitmproxy addon) ⨝ browser snapshots (`document.cookie` sha256-hashed) → per-cookie verdict `source ∈ {http, js, both}` + RGPD violation flag (`source == "js"` AND `category != "strictly_necessary"`).

**Live on board (gk2 / 192.168.1.200):**
- mitmproxy LXC: `cookie_audit.py` addon active via systemd drop-in, ledger filling at `/var/log/secubox/cookie-audit/server.jsonl` (66+ entries captured)
- secubox-metrics 1.0.2 + secubox-core 1.1.1 installed via `.deb`; secubox-hub 1.3.0 `.deb` install blocked by pre-existing `login.html` conflict with `secubox-portal` → `health-banner.js` + `cookie-inventory.js` scp'd directly as workaround
- `[cookie_audit]` enabled in `/etc/secubox/secubox.conf` + operator classifier patterns for `Horde` / `roundcube_sessid` (otherwise they'd land in `unclassified`)
- Endpoints accessible via nginx: `POST /api/v1/cookie-audit/ingest`, `GET /api/v1/cookie-audit/{report,summary}`
- 6 vhosts captured, 0 RGPD violation as of 2026-05-17 04:00

**Banner v1.4.4 in flight (post-merge polish, uncommitted on master):**
- v1.4.0 — `CookieAudit` live tile (red/green RGPD verdict + per-category breakdown)
- v1.4.1 — double-init guard (`window.__SBX_HEALTH_BANNER__`) — script was loaded twice (`index.html` + nginx `sub_filter` in `webui.conf:33`)
- v1.4.2 — `sectionContainer()` now appends inside `.hb-content` instead of `#health-banner` — fixes latent #92 bug where live sections were positioned **outside** the visible scroll area
- v1.4.3 — removed the 5 module tiles (waf/crowdsec/haproxy/nginx/system) — redundant with the persistent indicators top-right
- v1.4.4 — dead-code cleanup: removed `MODULE_EMOJIS` / `STATUS_EMOJIS` constants + ~40 lines of `.hb-mod*` CSS
- Also activated `[visitor_origin]` / `[live_hosts]` / `[cert_status]` in board conf (VisitorOrigin stays disabled at runtime — missing GeoLite mmdb)

**Tests:** 43 metrics tests green (34 pre-existing + 9 new), 7 new mitmproxy tests green.

**Cascade incidents surfaced during deploy (separate tickets):**
- [#162](https://github.com/CyberMind-FR/secubox-deb/issues/162) — `secubox-core` postinst overwrites `/etc/nginx/sites-available/secubox` with legacy `listen 80/443` → crashes nginx on HAProxy-fronted boards (caused 4-min prod outage)
- [#163](https://github.com/CyberMind-FR/secubox-deb/issues/163) — Triple `/soc/` location duplicate (`webui.conf` inline + `secubox.d/soc.conf` + `secubox.d/soc-web.conf`) blocks every nginx reload
- `secubox-hub` 1.3.0 packaging conflict with `secubox-portal` on `login.html` (needs `dpkg-divert` or split — to file)
- nginx `systemctl reload` silently no-op'd for hours (workers from 16:09 never replaced until full restart)

**Workaround currently active on board (manual, not in packages):**
- `/etc/nginx/sites-enabled/secubox → sites-available/secubox-local` (HAProxy-aware variant — reverts #162's regression)
- `/etc/nginx/secubox.d/soc.conf.disabled-156` + `soc-web.conf.disabled-156` (dups removed — workaround for #163)
- `/etc/nginx/secubox-routes.d/cookie-audit.conf` (new nginx route to metrics socket)
- `mitmproxy.service.d/cookie-audit.conf` drop-in inside LXC (loads addon alongside WAF)

**Follow-ups deferred:**
- AppArmor rule update for `/var/log/secubox/cookie-audit/` + `/var/lib/secubox/cookie-audit/`
- Logrotate snippet for the JSONL ledger
- GeoLite ASN DB install to fire up VisitorOrigin

---

## ✅ 2026-05-15: Mail stack Phase 1 — LXC consolidation (Issue [#136](https://github.com/CyberMind-FR/secubox-deb/issues/136), PR [#141](https://github.com/CyberMind-FR/secubox-deb/pull/141) MERGED `32190507` + `35ba4c2c` replay; PR [#144](https://github.com/CyberMind-FR/secubox-deb/pull/144) CLOSED-as-superseded)

### Objective

Catch the in-repo source up to the test board's `/data/lxc/mail` + `/data/volumes/mail` + `10.100.0.10/24` reality (repo still references `/srv/lxc`, `/srv/mail`, `192.168.255.30`, separate `mail_container`/`webmail_container`). Phase 1 collapses the dual-container layout into a single mail LXC, deprecates legacy `secubox-mail-lxc` / `secubox-webmail` / `secubox-webmail-lxc` companion packages with `Breaks/Replaces`, and ships HAProxy mail-TCP snippets pointed at the new IP.

### Status (worktree `136-mail-stack-phase-1-source-catch-up-legac`, branch `feature/136-mail-stack-phase-1-source-catch-up-legac`)

- Phase 0 spec rev. 2 (`docs/superpowers/specs/2026-05-15-mail-stack-architecture-design.md`) + Phase 1 plan + rollback recipe committed to master
- mailctl/mailser feature commits landed
- Versions bumped to 2.2.0 with `Breaks/Replaces` markers on the three legacy packages
- HAProxy mail-TCP snippet targets new `10.100.0.10`
- Test coverage shipped: 62-route endpoint-presence pytest + end-to-end acceptance smoke
- **PR [#141](https://github.com/CyberMind-FR/secubox-deb/pull/141) MERGED** as `32190507`

### Follow-up PR [#144](https://github.com/CyberMind-FR/secubox-deb/pull/144) — SUPERSEDED, must NOT be merged as-is

Two small fixes caught after #141 landed, pushed to the existing `feature/136-…` branch:

- `529f5ec7` `fix(mail): move lib/{lxc,install,migrate}.sh into lib/mail/` — debian/rules ships `lib/mail/*` to `/usr/lib/secubox/mail/lib/`; the Phase 1 commit landed helpers under `lib/` so they never reached the installed path.
- `6f6f98a5` `fix(mail): mailctl cmd_install sources lib/mail/{lxc,install}.sh` — `cmd_install` was still shelling out to `mailserverctl install` / `roundcubectl install` (now deprecation shims per Phase 1). Rewritten to source the moved helpers and call `bootstrap_debian` + `lxc_create_config` + …

**Status — superseded by `35ba4c2c` on master:**

A parallel session diagnosed the same Phase-1-squash-loss and added more fixes (`bd0053e4` test gate 11, `85394e10` post-mortem docs) to push the branch up to `85394e10`, then committed `35ba4c2c` directly to master — "replay Phase 1 fix commits lost in PR #141 squash-merge" — to unblock Phase 2. Master now has everything the branch carried.

**Why #144 became dangerous:** the branch was forked from old master (pre-#140 / pre-#137 squash) and never rebased. Its diff against current master shows `697 inserts / 6483 deletes across 45 files` because the branch's stale history would *remove* the converged-dashboard work that landed via PR #140. Merging it would undo PR #140 and PR #143.

**Action:** PR #144 should be closed (work already on master). To re-open as a true fix-followup if needed, re-fork from current master and cherry-pick only the missing commits.

---

## 🔄 2026-05-16: Mail stack Phase 2 — Rspamd migration (Issue [#153](https://github.com/CyberMind-FR/secubox-deb/issues/153), PR [#160](https://github.com/CyberMind-FR/secubox-deb/pull/160) OPEN)

Brought in by a parallel session (`b78e2584` + `1f562593`). Replaces SpamAssassin + OpenDKIM with Rspamd; single-domain DKIM (`secubox.in`, selector `default`); ClamAV deferred to Phase 2.5.

### Status — live-deployed on admin.gk2.secubox.in (192.168.1.200), 13/13 gates green

- **Spec:** [`docs/superpowers/specs/2026-05-15-mail-phase2-rspamd-design.md`](../docs/superpowers/specs/2026-05-15-mail-phase2-rspamd-design.md) committed `b78e2584` — locked decisions D1 (Rspamd replaces SA + OpenDKIM, Phase 0 invariant I3), D2 (ClamAV deferred), D3 (single-domain DKIM, Phase 3 widens).
- **Plan:** [`docs/superpowers/plans/2026-05-15-mail-phase2-rspamd.md`](../docs/superpowers/plans/2026-05-15-mail-phase2-rspamd.md) committed `1f562593` — 8 milestones, ~25 bite-sized TDD tasks.
- **Branch:** `feature/153-mail-stack-phase-2-rspamd-migration-roun` pushed to origin, head `bc7545b1`. PR [#160](https://github.com/CyberMind-FR/secubox-deb/pull/160) opened 2026-05-16 — awaiting reviewer + merge.
- **Live deploy 2026-05-16 (admin.gk2.secubox.in):**
  - `secubox-mail_2.3.0-1~bookworm1_all.deb` installed
  - rspamd + redis-server provisioned in `mail` LXC
  - DKIM keypair generated for `secubox.in` selector `default` (2048-bit) — DNS TXT awaiting publication
  - Postfix milter wired: `smtpd_milters = inet:127.0.0.1:11332`
  - Rspamd web UI reachable at `https://rspamd.gk2.secubox.in/` via HAProxy → mitmproxy → 10.100.0.10:11334 with `x-secubox-waf: inspected`
  - `mailctl rspamd purge-legacy` removed OpenDKIM + SpamAssassin cleanly (D9 health gate honoured)
- **Live-deploy fixes pushed as `637b2221`:**
  - `configure_rspamd_controller` now chowns `secrets.inc` via `lxc-attach -- chown _rspamd:_rspamd` (kernel idmap) instead of hardcoded host `100110:100110` — `_rspamd` is uid 107 in this Debian image, not 110, so the hardcoded value crash-looped rspamd on `Permission denied`
  - Acceptance gate 7 grep loosened to `Messages scanned|Pools allocated` (rspamc stat doesn't print the literal string "rspamd")
  - Acceptance gate 12 `dpkg -l` call wrapped with `|| true` so the smoke doesn't silently abort under `set -e` when the named packages are absent (success case)
- **Live-deploy follow-up refactor pushed as `bc7545b1`:**
  - `configure_rspamd_milter` + `configure_rspamd_controller` now stream templates through the live LXC via `lxc-attach -- tee` instead of guessing the host-side rootfs path — fixes the Phase 2 first-pass skip (board's runtime rootfs is `/data/lxc/<name>/rootfs` per `lxc.rootfs.path`, not `/var/lib/lxc/<name>/rootfs`).
  - `rspamd_keygen` now takes a `container` arg and runs `rspamadm dkim_keygen` inside the LXC; writes to `/etc/rspamd-keys/<domain>/` (bind-mounted) with `/var/lib/rspamd/dkim/` fallback; mirrors the DNS TXT to the host data dir.
  - `mailctl rspamd dkim-keygen` delegates to the lib function (drops its own hardcoded `chown 100110:100110`).
  - `rspamd-route-sync-patch.sh` verifies each JSON write via read-back and fails loudly on mismatch — Phase 2 deploy needed a manual second pass for the mitmproxy LXC copy.
  - Smoke 13/13 still green post-refactor (`/tmp/phase2-smoke-post-refactor.log` on host).
- **Acceptance:** all 13 gates green on the live board after both fix and refactor commits.
- **HAProxy cert recovery (separate `master` commit `70176578`):** `/srv/haproxy/certs` symlinked to `/data/haproxy/certs` + `haproxy.cfg` rebuilt from baseline + intentional grafts; reload now safe. Full post-mortem in HISTORY.md.

⏭️ **Next:** user reviews PR [#160](https://github.com/CyberMind-FR/secubox-deb/pull/160), merges → `scripts/agent-worktree.sh clean 153`. DNS TXT for `default._domainkey.secubox.in` still needs zone-side publication (record content in `/data/volumes/mail/rspamd/dkim/secubox.in/default.txt` on the board).

---

## ✅ 2026-05-15: remote-ui converged dashboard (Issue [#135](https://github.com/CyberMind-FR/secubox-deb/issues/135), PR [#140](https://github.com/CyberMind-FR/secubox-deb/pull/140) MERGED `b0b42e81`)

### Status

- PR [#137](https://github.com/CyberMind-FR/secubox-deb/pull/137) (initial converge round/ + square/ dashboards into `secubox_common` + pointer input on Pi 4B/400) **squash-merged `839bab94`**
- **PR [#140](https://github.com/CyberMind-FR/secubox-deb/pull/140) OPEN** on `feature/135-converge-round-square-dashboards-into-re` — head `89968477`, 35 commits ahead of `origin/master`, net +35 / −2086 lines
- Spec + plan landed on master (`b5e44e72`, `78316556`)

### Fixups added in this session (2026-05-15)

- `387fabb4` `fixup(common): pod_size=48 to match deployed icon sizes` — modules pods were rendering as letter placeholders on Pi 4B because `paint_pod_cluster(pod_size=40)` missed the deployed icon sizes (22/48/96/128); bumped to 48, radius 70→78 for clearance from the central button.
- `f4acd5a9` `fixup(square): ship remote-ui/common/assets/icons` — the square build copied `common/python/` but skipped `common/assets/`; without the icons under `/var/www/common/assets/icons/`, `secubox_common.icons.load_module_icon` would fall back to first-letter placeholders.
- `89968477` `fixup(square): install secubox-otg-gadget.sh to /usr/local/sbin` — the square `secubox-otg-gadget.service` ExecStarts that path; without the composer script the gadget never composed (zero USB enumeration events on the MOCHAbin, xHCI setup timeouts).

### Hardware bench (2026-05-15)

- **Pi 4B + 7" DSI (square):** converged dashboard renders ✓, icons ✓, all 4 right-panel tabs work (alerts/console/module_detail/mode_controls), USB-C OTG composes to MOCHAbin after the gadget-composer fixup landed.
- **Pi Zero W + HyperPixel 2.1 (round):** boots clean, `fallback_manager.py` OFFLINE radar renders correctly on the existing image.

---

## ✅ 2026-05-15: Port `radar_concentric` into `secubox_common` (Issue [#138](https://github.com/CyberMind-FR/secubox-deb/issues/138), PR [#142](https://github.com/CyberMind-FR/secubox-deb/pull/142) MERGED `d50aa52d`)

### Status

- Issue opened today; PR [#142](https://github.com/CyberMind-FR/secubox-deb/pull/142) opened the same day on `feature/138-port-radar-concentric-into-secubox-commo` with title "Port radar_concentric into secubox_common + phase-aware dashboards (closes #138)"
- New `secubox_common.painters.radar_concentric` module (phase-aware); module→arc-angle decoupled from list order via `DEFAULT_NAME_TO_ANGLE`
- `RoundDashboard.layout(metrics, phase=0.0)` + `SquareDashboard.layout(metrics, phase=0.0)` — backward-compatible (phase=0 = still frame)
- Square kiosk `__main__` drives `phase = (time.monotonic() * 12.0 / 60.0) % 1.0` at 12 RPM (matches deployed `fallback_manager._sweep_speed`)
- 118 / 118 tests green (36 secubox_common incl. 8 new + 78 square kiosk + 4 round)
- **Hardware bench (Pi 4B + 7" DSI, 2026-05-15):** rotating radar ✓ · icons ✓ · right panel ✓ — user-confirmed
- `fallback_manager.py` migration deferred (visual-palette decision needed; follow-up)

---

## ✅ 2026-05-15: Round image cleanup — dead ifupdown + secubox sudo + OTG comment (Issue [#139](https://github.com/CyberMind-FR/secubox-deb/issues/139), PR [#143](https://github.com/CyberMind-FR/secubox-deb/pull/143) MERGED `35576793`)

### Original misdiagnosis → rescoped

Initial report claimed "OTG networking dead": `/etc/network/interfaces.d/usb0` was a static stanza for ifupdown, but `ifupdown` was missing → `usb0` stayed DOWN. Wrong conclusion. Live-system probe via ACM serial showed the actual binding is on `usb1` (10.55.0.2/30), set programmatically by `secubox-otg-gadget.sh`. The dead ifupdown stanza never did anything; OTG was always working.

### Rescoped fix

- Drop dead `/etc/network/interfaces.d/usb0` (file + the inline heredoc in `build-eye-remote-image.sh` that recreated it)
- Add `secubox` user to `sudo` group (so ACM serial recovery is possible — previously the only-path-in had no path-to-fix)
- Rewrite the misleading `usb1 = ECM` comment in `secubox-otg-gadget.sh` — RNDIS+ECM share host_addr so host reaches 10.55.0.2 via either function

### Status

- Issue opened 2026-05-15 10:27; PR [#143](https://github.com/CyberMind-FR/secubox-deb/pull/143) opened 2 minutes later on `fix/139-round-image-usb0-otg-networking-dead-ifu`
- Initial misdiagnosis annotated as a comment on issue #139 — diagnostic confusion came from the dead stanza being visible
- **Hardware bench (Pi Zero W 1st gen, HyperPixel 2.1 Round, 2026-05-15):** all 3 fixes verified live:
  - `/etc/network/interfaces.d/` directory absent ✓
  - `secubox` in `sudo` group (`27(sudo)`) ✓
  - Gadget composer comment rewritten ✓
  - Bonus: ping `10.55.0.2` from host 3/3 received at 0.3 ms, SSH port 22 OPEN, both `usb0` + `usb1` UP @ 10.55.0.2/30 on the Pi
- Mid-bench: caught a pre-existing Pi Zero W `dwc2` kernel panic under host xHCI reset hammering — unrelated to #143 (image was good, dwc2 driver instability on ARMv6 under USB stress); deferred to a separate investigation

---

## 🔄 2026-05-15: CMSD SPDX header rollout (Issue [#81](https://github.com/CyberMind-FR/secubox-deb/issues/81))

### Status

Worktree `secubox-deb-license-wt` on branch `feature/license-phase-b-full` at `aa1f7481` ("enroll all in-scope files via `**` allowlist (Phase B + C)"). Phase A + B + C work all on the branch but no PR opened yet.

---

## 🧹 2026-05-15: worktree + local-state housekeeping

### Cleaned 2026-05-15 (morning)

- `secubox-deb-worktrees/127-add-remote-ui-square-variant-for-pi-4b-7` (Phase 1, PR #130 merged as `7c37415f`) — removed
- `secubox-deb-worktrees/127-phase2-square-variant` (Phase 2, PR #131 closed/superseded) — removed
- `secubox-deb-worktrees/127-phase3-python-kiosk` (Phase 3, PR #132 merged as `dee8bf8b`) — force-removed (had two stray untracked Signal Desktop apt-key files unrelated to the project, safe to discard)

`agent-worktree.sh clean` resolves by issue number which collides for multi-worktree issues like #127; used direct `git worktree remove` + `git branch -D`.

### Cleaned 2026-05-15 (afternoon — post-merge sweep of #140/#142/#143)

- `secubox-deb-worktrees/135-converge-round-square-dashboards-into-re` (PR #140 squash-merged `b0b42e81`) — removed
- `secubox-deb-worktrees/138-port-radar-concentric-into-secubox-commo` (PR #142 squash-merged `d50aa52d`) — removed
- `secubox-deb-worktrees/139-round-image-usb0-otg-networking-dead-ifu` (PR #143 squash-merged `35576793`) — removed

Branches `feature/135-…`, `feature/138-…`, `fix/139-…` deleted locally. Worktree `136-mail-stack-…` cleaned in the evening sweep (see below).

### Cleaned 2026-05-15 (evening — after PR #144 closed-as-superseded)

- `secubox-deb-worktrees/136-mail-stack-phase-1-source-catch-up-legac` (PR #144 CLOSED, work replayed via `35ba4c2c` on master) — removed
- Local branch `feature/136-mail-stack-phase-1-source-catch-up-legac` deleted
- A last unsaved `users.sh` path-default fix (canonical `/data/volumes/mail` + container `mail`) was preserved as `stash@{0}` "136-users-paths-canonical: users.sh defaults to /data/volumes/mail + container 'mail'" — recover via `git stash pop` or `git stash show -p stash@{0}` in the main checkout.

### Conflict resolution notes

- PR #140 went DIRTY/CONFLICTING after #137's earlier squash-merge because the branch carried all 32 pre-squash commits. Resolved by `git reset --hard origin/master + cherry-pick 387fabb4 f4acd5a9 89968477 + force-push`, leaving 3 clean fixup commits.
- PR #142 went DIRTY/CONFLICTING after #140 merged because it carried a merge commit from feature/135. Same fix: reset + cherry-pick `6d12af86` (the radar painter commit), with `--theirs` resolution on `square_dashboard.py` and `round_dashboard.py` (radar version was the canonical post-fixup state). Force-push, then merge.
- `gh pr merge … --squash --delete-branch` raced once on the freshly-pushed PR #142 HEAD and auto-closed the PR; recovered with `gh pr reopen 142` then re-merge succeeded.

### Local master state (2026-05-17 sync)

- `master` synced with `origin/master` at `680734db` (head was `320bdb01` on 2026-05-15 PM; 12 commits landed since).
- Main checkout carries uncommitted parallel-session WIP at sync time (not committed by me):
  - `packages/secubox-core/debian/changelog` (+10 lines, secubox-core 1.1.1-1~bookworm1 entry for cookie-audit helper baseline)
  - `packages/secubox-hub/debian/changelog` (+13 lines, secubox-hub 1.3.0-1~bookworm1 entry for health-banner CookieAudit tile + cookie-inventory.js)
  - `packages/secubox-hub/www/shared/health-banner.js` (modified)
  - `packages/secubox-metrics/debian/changelog` (modified)
  - These look like changelog/banner bumps for the merged #156/#159 cookie-audit work that didn't make it into the squash; intentionally left untouched.
- Untracked: `.claude/settings.json` (pre-existing, intentional)

### Worktrees still active (2026-05-17)

| Worktree | Branch | Status |
|---|---|---|
| `145-secubox-waf-apply-double-cache-pattern-o` | `fix/145-…` | PR [#146](https://github.com/CyberMind-FR/secubox-deb/pull/146) OPEN — parallel session, not this conversation's work |
| `147-add-scripts-check-dashboard-cache-py-lin` | `feature/147-…` | PR [#148](https://github.com/CyberMind-FR/secubox-deb/pull/148) OPEN — parallel session, not this conversation's work |
| `153-mail-stack-phase-2-rspamd-migration-roun` | `feature/153-…` | PR [#160](https://github.com/CyberMind-FR/secubox-deb/pull/160) OPEN — mail Phase 2 Rspamd, hardware-validated 13/13 gates live |
| `156-cookie-audit-pipeline-rgpd-eprivacy-comp` | `feature/156-…` | PR [#159](https://github.com/CyberMind-FR/secubox-deb/pull/159) MERGED `a19486c9`; worktree retained with WIP listed above |
| `secubox-deb-license-wt` | `feature/license-phase-b-full` | SPDX rollout #81, no PR yet |

### Parallel-session work landed between 2026-05-15 PM and 2026-05-17 (not from this conversation)

- `a34c194d` `fix(users): surface password-change errors in edit-user form (closes #154)` — direct to master.
- `d3ae2d57` `feat(users): disable password policy enforcement (admin opt-out)` — direct to master.
- `18c85939` `docs: Phase 0 spec rev. 3 — three-LXC topology (mail / roundcube / horde)` — direct to master.
- `b6947276` `docs: Mail Phase 2 Rspamd deployed live, 13/13 gates green (ref #153)` — direct to master.
- `c203c3bc` `docs(history): HAProxy cert recovery — symlink /srv/haproxy/certs + rebuilt cfg (ref #153)` — direct to master.
- `f95e0d9f` `docs(wip): mail Phase 2 follow-up refactor + HAProxy cert recovery (ref #153)` — direct to master.
- `fccb51ca` `docs(wip): PR #160 opened for mail Phase 2 (ref #153)` — direct to master.
- PR [#157](https://github.com/CyberMind-FR/secubox-deb/pull/157) MERGED `e2a905ca` — `fix(eye-remote): own the OTG bridge` (closes #155).
- PR [#159](https://github.com/CyberMind-FR/secubox-deb/pull/159) MERGED `a19486c9` — cookie audit pipeline (closes #156).
- PR [#160](https://github.com/CyberMind-FR/secubox-deb/pull/160) OPEN — mail Phase 2 Rspamd migration.
- PR [#161](https://github.com/CyberMind-FR/secubox-deb/pull/161) MERGED `e91b9e9e` — eye-remote multi-gadget L3 DHCP Phase 1 (ref #158).
- PR [#164](https://github.com/CyberMind-FR/secubox-deb/pull/164) MERGED `680734db` — `fix(eye-remote): live-deploy regressions on 192.168.1.200` (ref #158).
- PR #146, PR #148 still open from 2026-05-15.

---

## ✅ 2026-05-14: remote-ui Phase 3 — Pillow+framebuffer kiosk for Pi 4B/400 (Issue #127, PR #132 MERGED)

### Objective

Replace Phase 2's Chromium+PySide6 dual-window stack with a single-process Python kiosk targeting Pi 4B + Pi 400 + official Raspberry Pi 7" Touchscreen V1.1 (DSI, 800×480). Pillow draws an 800×480 BGRA frame each tick and `mmap`s it to `/dev/fb0`. Touch input via python-evdev. No X, no Qt, no Chromium, no Openbox, no nginx. Carries forward the Phase 2 Helper FastAPI (Unix socket, SO_PEERCRED) for privileged operations.

### Completed

- Brainstormed spec → [`docs/superpowers/specs/2026-05-13-eye-square-phase3-python-kiosk-design.md`](../docs/superpowers/specs/2026-05-13-eye-square-phase3-python-kiosk-design.md)
- Plan → [`docs/superpowers/plans/2026-05-13-eye-square-phase3-python-kiosk.md`](../docs/superpowers/plans/2026-05-13-eye-square-phase3-python-kiosk.md) (25 tasks)
- Executed via superpowers:subagent-driven-development with two-stage review (spec compliance + code quality) on every task
- 22 commits in [`feature/127-phase3-python-kiosk`](https://github.com/CyberMind-FR/secubox-deb/pull/132)
- **82/82 pytest green** (21 helper + 61 kiosk) · `bash -n` + `shellcheck` clean on all modified/new shell scripts
- Phase 3 PR: [#132](https://github.com/CyberMind-FR/secubox-deb/pull/132) — branched from master + cherry-picked Phase 2 helper carry-forward
- Phase 2 PR #131 closed (superseded by Phase 3)
- **Squash-merged 2026-05-14 as `dee8bf8b`** on master (after Phase 1 `7c37415f`)

### Hardware gates — 3 of 4 closed (2026-05-15)

| Task | Hardware | Status |
|------|----------|--------|
| **Task 23** — Pi 4B square/ manual bench | Pi 4B + official 7" DSI 800×480 | ✅ kiosk renders correctly post-#134 fixes |
| **Task 24** — Pi 400 square/ sanity | Pi 400 + HDMI 1920×1080 | ✅ same image, kiosk center-padded into letterbox (PR #134 second commit) |
| **Task 19** — Pi Zero W round/ manual bench | Pi Zero W + HyperPixel 2.1 | ✅ booted from CI-built `secubox-eye-remote-2.2.1.img.xz`, rainbow ring dashboard clean post-`common/` |
| Task 18 — round/ `diffoscope` regression gate | n/a (automated) | ⏳ still blocked on `hyperpixel2r.dtbo` prerequisite |

### Bug haul from the bench (fixed in PR [#134](https://github.com/CyberMind-FR/secubox-deb/pull/134), merged `a3a918ed`)

1. `/run/secubox` not recreated at boot (tmpfs wipe) → added `tmpfiles.d/secubox-eye-square.conf`
2. `fonts-dejavu-core` missing from chroot apt-install → added
3. `draw.text()` calls relied on Pillow legacy bitmap default (no Unicode) → `theme.DEFAULT_FONT` + `font=` kwarg on all 25 call sites
4. `framebuffer.py` hardcoded 32bpp BGRA but `vc4drmfb` is 16bpp RGB565 → numpy RGB565 packer + `bits_per_pixel` auto-detect
5. (followup) `framebuffer.py` hardcoded 800×480 → `virtual_size` auto-detect + center-pad for HDMI

Issue #127 closure now gated only on Task 18. Bug #139 (round image OTG networking) and enhancement #138 (radar to common) were surfaced from the same bench session — see today's PRs above.

---

## ✅ 2026-05-14: remote-ui Phase 1 — extract common/ shared core (Issue #127, PR #130 MERGED)

### Objective

Refactor `remote-ui/round/` to consume a new `remote-ui/common/` directory (JS/CSS/icons/shell) without changing round/'s behaviour, plus add two additive deltas (TransportManager `onModuleTap`/`onTransportChange` hooks, and a `form_factor` field on `RemoteUIConnectedRequest`). Foundation for Phase 2's `remote-ui/square/` variant (Pi 4B/400 + 7" 800x480).

### Completed

- Brainstormed full design → [`docs/superpowers/specs/2026-05-13-eye-square-variant-design.md`](docs/superpowers/specs/2026-05-13-eye-square-variant-design.md)
- Wrote Phase 1 implementation plan → [`docs/superpowers/plans/2026-05-13-eye-square-phase1-common-extraction.md`](docs/superpowers/plans/2026-05-13-eye-square-phase1-common-extraction.md) (20 tasks, ~80 steps)
- Executed via superpowers:subagent-driven-development with two-stage review on every task (60+ subagent dispatches, multiple fix-loops landed)
- 22 commits in [`feature/127-add-remote-ui-square-variant-for-pi-4b-7`](https://github.com/CyberMind-FR/secubox-deb/pull/130)
- Green gates: Task 12 visual AE=0, Task 13 form_factor TDD 4/4 green, Task 17 pytest 80/80 green
- Phase 1 PR: [#130](https://github.com/CyberMind-FR/secubox-deb/pull/130) — **squash-merged 2026-05-14 as `7c37415f`**
- CI fix shipped on the branch right before merge: `.github/workflows/build-eye-remote.yml` `VERSION: '2.2.0'` → `'2.2.1'` (Compress step was failing on a stale hardcoded version vs. `build-eye-remote-image.sh:16` `VERSION="2.2.1"`)

### Followups

- **Post-merge hardware gates** (issue #127 stays open until done): Task 18 `diffoscope` on round/ image build (blocked in subagent env by missing `hyperpixel2r.dtbo` prerequisite — structural verification in `docs/superpowers/specs/2026-05-13-task18-regression-gate-report.txt`); Task 19 manual Zero W bench (depends on Task 18).
- Phase 2 plan no longer needed — superseded by Phase 3 (merged).
- Pre-existing `TM.jwt_otg` / `TM.jwt_wifi` references in round/'s inline JS (visible in code reviewer feedback) — orthogonal to Phase 1, track separately if rendering hits the path.

---

## ✅ Session 167: Auth rework — secubox-users + TOTP 2FA (Issue #120, PR TBD)

### Objective
Replace the plaintext `auth.toml` admin login with secubox-users-backed argon2id auth + TOTP 2FA, kill-on-disable session revocation, CLI↔API parity via a single engine, and a feature-flagged cutover.

### Completed
- Brainstormed spec → `docs/superpowers/specs/2026-05-13-secubox-users-auth-design.md`
- Plan (19 tasks) → `docs/superpowers/plans/2026-05-13-secubox-users-auth.md`
- All 19 tasks implemented in `feature/120-auth-rework-secubox-users-as-identity-so`
- 70+ tests per package, all green
- Live smoke script written (not run — pending deploy)

### Followups
- Build + publish .deb, then run smoke.
- Cutover phase: flip feature flag on the canonical board.
- Top-10k common-passwords list refresh.
- Frontend: surface "fallback active" red banner when users.json is unhealthy.

---

## ✅ 2026-05-13: MetaBlogizer deploy webhook (Issue #113, sub-E of #49)

### Objective
Auto-deploy on `git push` to metablog-* repos. HMAC-verified Gitea webhook → per-site asyncio.Lock → git pull → cache invalidate → conditional nginx reload. Closes the umbrella #49.

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-13-metablog-deploy-webhook-design.md`
- Plan (8 tasks) → `docs/superpowers/plans/2026-05-13-metablog-deploy-webhook.md`
- New module `api/webhook.py`: `verify_signature` (constant-time HMAC-SHA256), `load_secret` (cached), `classify_payload` (accept/skip/malformed), `site_lock` pool with master lock, `git_pull` helper with timeouts, 50-entry deploy ring buffer
- `main.py` mounts `POST /webhook` (public, HMAC) and `GET /deploys` (JWT)
- `scripts/metablog-webhook-install.sh` + `metablog-webhook-uninstall.sh` (Gitea API, idempotent, --dry-run)
- 3-gate bash smoke `tests/scripts/test-metablog-webhook.sh`
- 21 pytest cases (HMAC, secret loader, ring buffer, git_pull, classify_payload, lock semantics)

### Followups
- Streamlit auto-deploy via a parallel webhook (separate issue if needed)
- Optional drill-in UI surfacing `GET /deploys` for ops review

---

## ✅ 2026-05-13: Hub sidebar mobile-mode auto-detect fix (Issue #114, PR #115)

### Objective
Stop the Hub sidebar from flipping to mobile mode on touchscreen laptops with a mouse. The log gave it away: `Mobile mode: ON (touch: true, narrow: false)` on a wide-window desktop.

### Completed
- `packages/secubox-hub/www/shared/sidebar.js` `isTouchDevice()` now checks `(hover: none) and (pointer: coarse)` — primary-input only, so hybrid devices with a mouse stay in normal mode.
- Narrow-viewport (`≤768px`) fallback unchanged; still handles resized desktop windows and phones.
- Commit `ce1f270c`, merged in PR #115.

### Followups
- None. Phones, tablets, and touchscreen laptops with mouse all behave correctly.

---

## ✅ Session 165: MetaBlogizer version dashboard (Issue #103, sub-D of #49)

### Objective
Extend the existing /metablogizer/ list view with version-aware columns + filter + sort + 60s polling, and add a per-site drill-in page at /metablogizer/site.html?name=<X>. Consumes the enriched API from sub-C (PR #102).

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-12-metablog-version-dashboard-design.md`
- Plan (5 tasks) → `docs/superpowers/plans/2026-05-12-metablog-version-dashboard.md`
- Extended `index.html`: 3 new columns (version → Gitea releases link, streamlit_app icon link, last_updated as relative time + ISO tooltip), filter box, sortable headers with ▲/▼, 60s polling paused when tab hidden, row name links to drill-in
- New `site.html`: single-fetch drill-in surfacing every site.json field + 3 external links (live, Gitea, Streamlit hidden when null), same CRT P31 phosphor theme as index
- 4-gate smoke `tests/scripts/test-metablogizer-ui.sh` (file shape + drill-in anchors + HTML well-formedness + live reachability — all green at 200)
- Fixed localStorage key bug: site.html now uses canonical `sbx_token` (matches index.html and shared/api-utils.js)
- CRT P31 phosphor theme matched exactly with the existing module style

### Followups
- Sub-E (deploy webhook) — last open sub-project of #49.
- Optional follow-up: server-side proxy for Gitea tag history (so the drill-in can show tag list inline, no browser-side Gitea auth). Out of MVP scope.

---

## ✅ Session 164: MetaBlogizer site.json schema + version metadata (Issue #101, sub-C of #49)

### Objective
Formal JSON Schema for site.json + Python validator/enricher (derives `version`/`last_updated` from git) + backfill script for missing files + API extension exposing enriched fields. Unblocks sub-D (Dashboard).

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-12-metablog-site-schema-design.md`
- Plan (8 tasks) → `docs/superpowers/plans/2026-05-12-metablog-site-schema.md`
- JSON Schema draft-07 at `packages/secubox-metablogizer/schema/site.json.schema.json`
- `api/site_schema.py` (`load_schema`/`validate`/`enrich`) + 8 pytest cases
- `load_sites()` calls `_load_site_json()` (validate warn-only, log violations)
- `python3-jsonschema` added to `debian/control`
- `scripts/metablog-site-backfill.sh` — creates missing, merges with `--force`
- 3-gate smoke test (`tests/scripts/test-metablog-site-schema.sh`)
- Live run: 165 sites, 104 created, 61 skipped (incl. 2 fixed via `--force`: `money`, `evolution` missing `published`), 0 failed
- Summary at `docs/superpowers/runs/2026-05-12-metablog-site-backfill-summary.md`

### Followups
- Sub-D (Dashboard) — depends on this enriched API.
- Sub-E (deploy webhook) — independent.

---

## ✅ Session 163: Streamlit Gitea version pinning (Issue #95, sub-F of #49)

### Objective
Mirror the 28 directory-form Streamlit apps from `/srv/streamlit/apps/` into Gitea as `gandalf/streamlit-<app>` with `v1.0.0` tag, extend `streamlitctl` with `--from-gitea --tag` deploy + `rollback`, and surface `current_tag`/`deployed_at` in the FastAPI.

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-12-streamlit-gitea-version-pinning-design.md`
- Plan (9 tasks) → `docs/superpowers/plans/2026-05-12-streamlit-gitea-version-pinning.md`
- Per-app ingest function `scripts/lib/streamlit-ingest-app.sh` (sibling of metablog's)
- Cherry-picked `scripts/lib/gitea-ssh-preflight.sh` from PR #97 (not yet on master)
- Orchestrator `scripts/streamlit-ingest.sh` with preflights + JSON report
- Filter dot-dirs + `__pycache__` (excluded `.claude`)
- Fixed two `set -- "${var[@]:-}"` empty-array bugs
- 3-app smoke + idempotent re-run
- Full run: 28/28 apps, 0 failed — see `docs/superpowers/runs/2026-05-12-streamlit-ingest-summary.md`. First pass 20 fail-internal-error from broken stubs (same as B); bulk-deleted via API, second pass clean.
- `streamlitctl deploy <app> --from-gitea --tag <vX.Y.Z>` — clone+replace in-place with backup, max 3 backups retained
- `streamlitctl rollback <app>` — promote latest `.bak.*` to current, sentinel for the previous current
- Auto-restart **removed** — `cmd_start`/`cmd_stop` operate on whole LXC; would kill other apps. Streamlit auto-reloads on file changes.
- FastAPI `_get_apps()` enrichment: `current_tag` (from `.deploy.json` → fallback `git describe --tags --exact-match`), `deployed_at`
- Deploy/rollback cycle smoke (canary: yijing) — all gates pass

### Followups
- Sub-projects C, D, E of #49 remain.
- API gate during smoke showed empty `current_tag` — service on MOCHAbin needs restart after package upgrade for the new `_get_apps()` to take effect.

---

## ✅ Session 160: Health Banner Live Panel (Issue #92)

### Objective
Add three public banner sections (VisitorOrigin / LiveHosts / CertStatus)
sharing one polling and CORS pipeline in `secubox-metrics`.

### Completed
- Spec + plan written and committed.
- Three aggregators with unit + error-path tests (25 tests passing).
- nftables ruleset, systemd timer, postinst plumbing.
- Banner v1.3.0 with three fail-isolated fetch loops.
- README updated.

### Status
PR pending review against `master`.

---

## ✅ Session 160: secubox apt + clone — validate implementation (Issue #89)

### Objective
Walk the 2026-05-11 apt+clone plan against the implemented Go CLI, fix any genuine gaps, and end-to-end the workflow against the now-live `https://apt.secubox.in/`.

### Completed
- **Plan audit** (`docs/superpowers/plans/2026-05-11-secubox-apt-clone.md`): all 48 task steps ticked. `go test ./internal/apt/... ./cmd/...` passes; binary builds; `--help` correct for `apt setup`, `apt init/publish/sync/list/remove/check`, `clone`.
- **Real bug found in E2E**: `apt.Client.DefaultGPGKeyURL` pointed at `https://apt.secubox.in/secubox.gpg`. That URL doesn't exist on the public repo (nginx `try_files` falls through to `index.html`, so the Go code wrote a 2.5 kB HTML page as the keyring → `apt update` returned exit 100). Fixed by pointing at `/secubox-keyring.gpg.bin` (binary OpenPGP, exactly what apt expects under `signed-by=`). No dearmor step needed.
- **E2E verified in fresh bookworm chroot**:
  ```
  secubox apt setup       # OK
  apt-get update          # Hit:1 https://apt.secubox.in bookworm InRelease
  apt-cache search secubox  # 15 packages
  ```
  `clone --minimal -y` reaches `apt install`; the dpkg postinst then fails inside a minbase chroot (no systemd) — environmental, not a CLI bug. Real targets (MOCHAbin, VM with systemd) will succeed.

### Commits
- `4e8eadf4` — docs(apt): Tick plan checkboxes per code audit (ref #89)
- `6e3276bb` — fix(apt): Use binary keyring URL so apt accepts the signed-by= source (ref #89)

### Outcome
Code matched the plan within one bug — the wrong default GPG URL was masked because the existing tests use `httptest` servers (so they never hit the real URL). Plan is retroactively complete; CLI is functional against production.

---

## ✅ Session 159: CMSD-1.0 License Headers — Phase A merged, B/C in review (Issue #81)

### Objective
Add the CyberMind Source-Disclosed License (CMSD-1.0) SPDX header to every first-party source file in the repository, build the tooling and CI gate to keep it that way, and roll out repo-wide.

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-12-license-headers-design.md`
- Implementation plan → `docs/superpowers/plans/2026-05-12-license-headers.md`
- **`scripts/license-headers.py`** — stdlib-only CLI with `--check` / `--fix` / `--list` / `--diff`, language-aware comment rendering (hash / slash / block / html), placement rules per language (Python shebang+encoding, Bash shebang, HTML doctype, Markdown frontmatter), idempotent `apply()`, enrollment-allowlist walker
- **`.github/workflows/license-check.yml`** — CI runs `--check` on PRs and pushes to master
- **`tests/test_license_headers.py`** — 53 pytest cases (rendering, MATCH/FOREIGN/NONE detection, idempotence, walker pruning, allowlist filtering, CLI dispatch + exit codes, plus regression tests for two mid-rollout fixes)
- **`scripts/README.md`** + **`.claude/CLAUDE.md`** — documented the new SPDX convention and updated Python/Bash header examples

### Stack status
| PR | Status | Description |
|---|---|---|
| #84 | ✅ Merged | Phase A — tool + CI + conventions + walker-subdir fix + detect-regex-tightening + missing-file=repo-wide fix |
| #86 | 📝 Draft | Phase B pilot — `secubox-hub` enrollment (51 files, 1 foreign Apache-2.0 skipped) |
| #88 | 📝 Draft | Phase B+C bulk — repo-wide enrollment via `**` (1,529 files, 11 foreign SPDX skipped) |

### Two mid-rollout bug fixes (rolled into #84)
1. `walk()` now accepts `repo_root` so subdir invocations (`--fix packages/foo`) resolve repo-relative allowlist patterns correctly
2. `detect_existing()` regex now requires comment-start markers — prose mentions of "SPDX-License-Identifier:" inside docstrings no longer false-match
3. `_read_enrollment()` missing file now returns `["**"]` per spec §5.2 — Phase C closure can delete the file

### Foreign SPDX preserved (11 files)
- 1× Apache-2.0 (`packages/secubox-hub/www/luci-static/resources/secubox/secubox.css`)
- 9× GPL-2.0-or-later in `packages/zkp-hamiltonian/` (cryptographic primitives)
- 1× GPL-2.0-only kernel module (`packages/secubox-led-heartbeat/kmod/leds-is31fl319x.c`)

### Next steps
1. Move #86 and #88 out of draft when ready for review
2. Merge #86 → #88 → master
3. Close #81

### Commits (Phase A, merged via #84)
`cdc74563` `c7166597` `bd7975d1` `f08eb380` `70ac535e` `5b4d3e25` `63e62c1d` `9b0fce3f` `6474728d` `ada50406` `2bd965f4` `72733385` `c93cfdb6` `e90a07a5` `4d937995` `9eb75676` `643d39af` `2763009f` `b88b8ada` `b0b6e78c (merge)`

---

## ✅ Session 152: APT Public Repo Staging Pipeline (Issue #80)

### Objective
Stage a signed APT repo at `output/repo/` for bookworm × {arm64, amd64}, validated end-to-end. User pushes to `apt.secubox.in` out-of-band.

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-12-apt-public-repo-staging-design.md`
- Implementation plan → `docs/superpowers/plans/2026-05-12-apt-public-repo-staging.md`
- All 10 tasks delivered. Pipeline runs end-to-end on base + tier-lite × arm64+amd64; 9 packages published; all four validation gates pass (`reprepro check`, `gpg --verify InRelease`, license byte-match, chroot `apt-get update`).
- GPG fingerprint: `31848880ED89C1722677D75A25C9E32645166DB9` (persistent in `~/.gnupg/secubox/`)
- Deploy artifacts ready: `output/repo/{nginx-apt.conf, DEPLOY.md, install.sh, LICENCE-CMSD-1.0.md, LICENSE-CMSD-1.0.en.md, secubox-keyring.gpg, FINGERPRINT.txt, MANIFEST.txt}`

### Key finding
130/132 SecuBox packages are `Architecture: all`. Only `secubox-daemon` and `zkp-hamiltonian` are `Architecture: any`, and neither is in `scripts/build-packages.sh`'s PACKAGES list. So the arm64-specific pool is currently empty; adding those two to the build list is separate work.

### Next steps (pending user action)
1. Optional: full pipeline (`bash scripts/stage-apt-repo.sh`) for all four tiers (30-90 min).
2. rsync staged tree to `apt.secubox.in` per `output/repo/DEPLOY.md`.
3. certbot --nginx; verify SAN includes `apt.secubox.in` (fixes the current `ERR_TLS_CERT_ALTNAME_INVALID`).
4. Validate from clean client: `curl -fsSL https://apt.secubox.in/install.sh | sudo bash && sudo apt-get update`.
5. Close issue #80.

### Commits (merged via PR #82, plus `0f1907df` follow-up)
`ce82e13d` `6f59de25` `52463db1` `3b99bcf4` `5f7b8474` `d6fe14d5` `bb58789b` `197eba63` `0f1907df`

---

## ✅ Session 149: Mode Control API & Dashboard Integration

### Objective
Add web-based mode control to the Eye Remote admin dashboard for safer manual gadget switching.

### Completed
- **Mode Control API** (`mode_api.py`):
  - HTTP API on port 8081 (8080 used by CrowdSec)
  - `GET /api/status`: Current gadget mode and functions
  - `POST /api/switch/<mode>`: Switch composite/network/storage/silent/hid
  - `GET /health`: Health check endpoint
  - `GET /metrics`: System metrics (CPU, RAM, disk, temp, load, uptime)
  - HTML control panel with mode buttons

- **Dashboard Integration** (`admin.gk2.secubox.in/eye-remote/`):
  - USB Gadget Mode card with current status
  - Mode switch buttons (COMPOSITE, NETWORK, STORAGE, SILENT)
  - Live metrics display (CPU, RAM, Temp, Uptime)
  - Auto-refresh every 10 seconds

- **Infrastructure**:
  - Systemd service `secubox-mode-api.service` on Pi
  - Nginx proxy `/eye-remote/mode/` → `http://10.55.0.2:8081/`
  - Nginx proxy `/api/v1/eye-remote/` → `http://10.55.0.2:8081/`

### Commits
- `462d2712` — feat(eye-remote): Add Mode Control API with metrics endpoint

### Files Changed
| File | Change |
|------|--------|
| `remote-ui/round/agent/api/mode_api.py` | NEW: Mode Control API with metrics |
| `remote-ui/round/agent/auto_mode_controller.py` | Minor improvements |
| `.gitignore` | Exclude backup images |

### Deployed To
- Pi Zero W: `/home/pi/eye-remote/agent/api/mode_api.py`
- MOCHAbin: nginx config updated for port 8081

### Current State
- ✅ Mode API running on Pi (port 8081)
- ✅ Dashboard shows Pi metrics and connection status
- ✅ Mode control buttons integrated in admin panel
- ✅ Health and metrics endpoints working
- ✅ Composite mode active (ECM+ACM+RNDIS+Storage)

### Next Steps
1. ⬜ Test mode switching from web UI
2. ⬜ Add HID mode button to dashboard
3. ⬜ Create new backup image v2.2.2 with mode API
4. ⬜ Investigate gadget crash root cause during mode switch

---

## ✅ Session 148: Eye Remote Auto-Mode Stability

### Problem
- Auto-mode controller caused USB gadget crashes when switching modes
- Mode detection not working (always saw "none" instead of COMPOSITE)
- Multiple display processes could run simultaneously
- Network probing triggered unnecessary mode switches

### Solution Implemented
- **Mode Detection**: Added `_detect_current_mode()` to read configfs functions
- **Smart Probing**: Check network connectivity BEFORE attempting mode switches
- **Single Instance**: PID file locking in `fallback_manager.py`
- **Storage Recovery**: If storage not mounted after 30s, switch back to composite

### Commits
- `b859817e` — fix(eye-remote): Improve auto-mode stability and single-instance display

### Files Changed
| File | Change |
|------|--------|
| `agent/auto_mode_controller.py` | Mode detection, smart probing, storage recovery |
| `agent/display/fallback/fallback_manager.py` | PID lock for single instance |
| `files/etc/secubox/eye-remote/gadget-setup.sh` | Lock file, cooldown safeguards |

### Status
- ✅ Completed — mode detection and stability fixes deployed

---

## ✅ Session 147: Fix Eye Agent Import Errors (#78)

### Problem
- `main.py` tried to import classes that don't exist: `DashboardRenderer`, `LocalRenderer`, `FlashRenderer`, `GatewayRenderer`, `RenderContext`
- Missing modules: `agent.system`, `agent.secubox`, `agent.web`
- Import chain failures due to missing optional dependencies (aiohttp)

### Solution
- Created stub implementations for missing modules:
  - `system.py`: WifiManager, BluetoothManager, DisplayController
  - `secubox.py`: DeviceManager, FleetAggregator
  - `web.py`: WebServer
- Created `display/renderers.py` with mode-specific renderers:
  - DashboardRenderer: 3D cube + metric rings
  - LocalRenderer: Disconnected mode display
  - FlashRenderer: Alert messages
  - GatewayRenderer: Fleet overview
  - RenderContext: Data container
- Rewrote imports in `main.py` with robust try/except handling
- Updated `display/__init__.py` with graceful fallbacks

### Branch
- `fix/78-eye-agent-imports`
- Commit: `e71209f5` — fix(eye-agent): Resolve import errors and add missing modules

### Files Changed
| File | Change |
|------|--------|
| `agent/main.py` | Robust import handling |
| `agent/display/__init__.py` | Graceful fallbacks |
| `agent/display/renderers.py` | NEW: Mode renderers |
| `agent/system.py` | NEW: System controllers |
| `agent/secubox.py` | NEW: Device management |
| `agent/web.py` | NEW: Web server stub |

### Status
- ✅ Imports work without crashes
- ✅ Core components instantiate correctly
- ⚠️ Optional dependencies (aiohttp) show warnings but don't block startup

---

## ✅ Session 146: Eye Remote v2.2.1 Build & Validation

### Build Script Updated
- [x] Added `secubox-fallback-display.service` to build
- [x] Enabled fallback-display instead of broken eye-agent
- [x] Added PIL dependencies: libopenjp2-7, libtiff6
- [x] Bumped version to 2.2.1
- [x] All agent subdirectories copied: display, secubox, system, web, api, recovery, sync

### Image Built & Tested
- [x] Built `/tmp/secubox-eye-remote-2.2.1.img` (5.3GB)
- [x] Flashed to SD card and tested on MOCHAbin
- [x] Dashboard working: 3D cube + rainbow rings + real metrics
- [x] Compressed to `.img.xz` for archival

### GitHub Issues Created
- [#78] Fix eye-agent import errors and missing DashboardRenderer class
- [#79] Investigate Buildroot/Busybox minimal image for Eye Remote

### Artifacts
- `/tmp/secubox-eye-remote-2.2.1.img.xz` — Production image
- Commit: `b2f046c1` — Build script fix

---

## ✅ Session 145: Eye Remote Dashboard Fix

### Working State Restored
- [x] Fixed fallback_manager.py as main dashboard (3D cube + rainbow rings)
- [x] Deployed to `/usr/lib/secubox-eye/agent/display/fallback/`
- [x] Created `secubox-fallback-display.service` systemd unit
- [x] NAT routing through MOCHAbin for Pi internet access
- [x] PIL dependencies installed (libopenjp2-7, libtiff6)

### Root Cause Analysis
- Agent code incomplete: `DashboardRenderer` class missing
- Relative imports failing when running as script
- Build script missing `agent/api/` directory copy

### Services Configuration
| Service | Status | Purpose |
|---------|--------|---------|
| `secubox-fallback-display.service` | ✅ ACTIVE | Main dashboard (use this) |
| `secubox-fb-dashboard.service` | DISABLED | Old simple dashboard |
| `secubox-eye-agent.service` | DISABLED | Broken imports |

### Files Updated
- `/etc/systemd/system/secubox-fallback-display.service` — NEW working service
- `/usr/lib/secubox-eye/agent/display/fallback/` — Complete fallback display

---

## ✅ Session 143: Health Banner System + CDN Injection

### Global Health Banner with Smart Doctor
- [x] Created `health-banner.js` with double-buffer cache (active/shadow)
- [x] Added Smart Doctor advisor with rule-based diagnostics
- [x] Implemented spunky emoji-based UI with animations
- [x] Added `/api/v1/metrics/health/summary` endpoint to metrics API
- [x] Module status LEDs: WAF 🛡️, CrowdSec 👮, HAProxy 🌐, Nginx 🌍, System 💻
- [x] Score-based vibes: VIBING (95%+), SOLID (85%+), OKAY (70%+), MEH (50%+), YIKES (<50%)
- [x] Deployed to all HTML pages (hub, soc, nac)

### Nginx CDN Injection (NEW)
- [x] Added `/etc/nginx/conf.d/health-banner-inject.conf`
- [x] Auto-injects `health-banner.js` via `sub_filter` on all HTML responses
- [x] No need to modify source HTML files
- [x] Banner at full-width top (28px height, z-index 9999)

### GitHub Issues
- [#70 ✅ DONE] Health Banner System: Smart Doctor + Auto-Detect Host
- [#71 ✅ DONE] CDN Proxy Injection: Auto-inject scripts via nginx/HAProxy

### Package Rebuild
- [x] Rebuilt 126 packages successfully (0 failed)
- [x] Locked packages: secubox-hub, secubox-waf, secubox-mitmproxy

### Files Created/Modified
- `packages/secubox-hub/www/shared/health-banner.js` — Banner UI (full-width top)
- `packages/secubox-metrics/api/main.py` — Added health/summary endpoint
- `/etc/nginx/conf.d/health-banner-inject.conf` — NEW (nginx injection)

---

## ✅ Session 142: SOC Triple Eyemotes Migration

### SOC Dashboard — WarGames Geomap → Triple Eyemotes
- [x] Replaced WarGames geomap CSS with eyemote mini CSS
- [x] Replaced geomap HTML with 3 eyemote cards in grid layout
- [x] Added `updateEyemoteMini()` and `updateAllEyemotes()` functions
- [x] Implemented double-cache pattern for async API handling
  - `window._socStats` — stores stats data from WAF API
  - `window._socEvents` — stores alerts from `/alerts?limit=100`
  - Either API can trigger eyemote update when counterpart ready
- [x] Removed obsolete `renderGeomap()` call
- [x] Deployed to `/srv/secubox/www/soc/index.html`

### Triple Eyemote Sensors (SOC)
| Sensor | Data Source | Visualization |
|--------|-------------|---------------|
| 👁️ Attack Origin | WAF alerts by country | Olympic rings by continent |
| 👤 Visitors | Unique IPs by country | Cyan/purple gradient rings |
| 🎯 Target Vhosts | Attacks per vhost | Red/orange/green rings |

### Files Updated
- `packages/secubox-hub/www/soc/index.html` — Triple eyemotes with double-cache

---

## ✅ Session 141: WAF Eyemotes + Quick Actions

### WAF Dashboard Enhancements
- [x] Triple Eyemote sensors (Attack Origin, Visitors, Target Vhosts)
- [x] Quick action buttons (refresh, WAF toggle, clear bans, export, settings)
- [x] Double-cache pattern for async API response handling
- [x] Removed obsolete `renderGeomap()` function

---

## ✅ Session 140: Route Sync + Export Package

### Route Sync Script — FIXED
- [x] Fixed `((updated++))` bash arithmetic failure in `scripts/sync-mitmproxy-routes.sh`
- [x] Changed to `updated=$((updated + 1))` for `set -e` compatibility
- [x] Deployed and tested — 4 routes synced successfully
- [x] Systemd timer running every 5 minutes

### Metablogizer Export Package — ENHANCED
- [x] Complete export ZIP with:
  - `content/` — Site files (HTML, CSS, JS)
  - `config/site.json` — Site configuration
  - `config/nginx.conf` — Generated nginx vhost config
  - `config/haproxy.cfg` — HAProxy routing snippet
  - `certs/` — SSL certificate + privkey (if available)
  - `README.md` — Complete republishing instructions
- [x] Includes Quick Republish (SecuBox) and Manual Republish (Any Server) guides
- [x] DNS configuration examples
- [x] Certificate status indicator

### Files Updated
- `scripts/sync-mitmproxy-routes.sh` — Fixed bash arithmetic
- `packages/secubox-metablogizer/api/main.py` — Enhanced export endpoint

---

## ✅ Session 137: Module Screenshots Wiki Multilangue

### Screenshot Capture System — COMPLETE
- [x] `scripts/capture-screenshots.py` — Auto-discovers 117 modules from packages/
- [x] Playwright-based capture with JWT authentication (admin/secubox)
- [x] 30-second delay per page for cache refresh
- [x] Thumbnail generation (400x225) for wiki index
- [x] JSON manifest output (`capture-manifest.json`)

### Documentation Generator — COMPLETE
- [x] `scripts/generate-docs.py` — Extended to 105 modules
- [x] Multilingual descriptions (EN, FR, DE, ZH)
- [x] `--include-screenshots` flag for wiki integration
- [x] Category index pages generation
- [x] Screenshot existence checking

### Module Categories (105 in generate-docs, 117 discovered)
| Category | Count |
|----------|-------|
| Security | 19 |
| Network | 11 |
| Monitoring | 8 |
| System | 8 |
| Media | 7 |
| AI | 6 |
| DNS | 6 |
| Publishing | 6 |
| Dashboard | 5 |
| VPN & Privacy | 9 |
| Email | 4 |
| IoT | 4 |
| Communication | 4 |
| Access | 3 |
| Services | 3 |
| Apps | 3 |

### Files Created/Updated
- `scripts/capture-screenshots.py` — NEW
- `scripts/generate-docs.py` — Extended 47→105 modules
- `docs/screenshots/README.md` — Updated
- `docs/screenshots/thumbnails/` — NEW directory

### Running
```bash
# Capture running in background (~1h for 117 modules @ 30s each)
tail -f /tmp/capture-screenshots-full.log

# Generate wiki with screenshots
python scripts/generate-docs.py --include-screenshots
```

### ✅ Session 138 Additions
- [x] Mobile hamburger menu toggle (sidebar.js v2.36.0)
- [x] Portal/login.html transparent redirect to /login.html
- [x] Mobile popup overrides — bottom sheet style (sidebar.js v2.37.0)
  - Strip popup: Full-width bottom sheet on mobile
  - HW LED tooltip: Centered at bottom
  - Status panel: Full-screen on mobile
  - Better touch targets (44px min-height)
- [x] Smart mobile detection (sidebar.js v2.38.0) ✓ DEPLOYED
  - Touch device detection (touchstart, maxTouchPoints, pointer:coarse)
  - Narrow viewport detection (≤768px)
  - Auto resize/orientation change handling

### Session 139: Nginx Health Routes — COMPLETE
- [x] Generated nginx routes for 82 modules with API sockets
- [x] Fixed missing `include /etc/nginx/secubox-routes.d/*.conf;` in webui.conf
- [x] All `/api/v1/<module>/health` endpoints now working
- [x] Sidebar health checks functional

### ⬜ Next Up
- [ ] (Add new tasks here)

---

## ✅ Session 136: API Routes + Unified NAC + Metablogizer Publish

### Modular Nginx Routes — COMPLETE
- [x] Created `/etc/nginx/secubox-routes.d/` for per-module route files
- [x] Added routes for metablogizer, cyberfeed, hub, nac
- [x] Each module can ship its own nginx route file

### Hub Public Endpoints — COMPLETE
- [x] Added `/api/v1/hub/public/menu` — returns sidebar menu structure
- [x] Added `/api/v1/hub/public/led_status` — returns system health LEDs
- [x] Added `/api/v1/hub/public/health-batch` — batch health check for modules
- [x] No auth required for sidebar components

### Safe JSON API Wrapper — COMPLETE
- [x] Created `packages/secubox-hub/www/shared/api-utils.js`
- [x] Safe JSON parsing (handles HTML error responses gracefully)
- [x] Automatic 401 redirect to login
- [x] Timeout handling

### Unified NAC Module — COMPLETE
- [x] Merged NAC (Client Guardian) + MAC-Guard into single module
- [x] Tabs: Devices, Whitelist, Blacklist, Quarantine, Alerts, Vendors, Settings
- [x] Full device management with search/filter
- [x] Quick actions: whitelist, blacklist, quarantine
- [x] Vendor statistics bar chart
- [x] Network scan capability

### Metablogizer Publish — COMPLETE
- [x] Replaced all `.sb.local` and `.secubox.local` domains with `.gk2.secubox.in`
- [x] Published 50+ unpublished sites with valid domains
- [x] Sites now use wildcard cert `*.gk2.secubox.in`

### Files Updated (Server)
- `/usr/lib/secubox/admin/api/main.py` — Added public endpoints
- `/etc/nginx/secubox-routes.d/*.conf` — Modular nginx routes
- `/usr/share/secubox/www/nac/index.html` — Unified NAC module
- `/usr/share/secubox/www/shared/api-utils.js` — Safe API wrapper
- `/srv/metablogizer/sites/*/index.html` — Domain replacements

### Files Updated (Repo)
- `packages/secubox-hub/www/nac/index.html` — Unified NAC module
- `packages/secubox-hub/www/shared/api-utils.js` — Safe API wrapper

---

## ✅ Session 135: Error Pages + WAF Rework + Geomap Fix

### Error Pages — COMPLETE
- [x] Created fun/smarty error pages (`packages/secubox-hub/www/shared/error.html`)
- [x] ASCII art with kaomoji for each error code (400, 401, 403, 404, 500, 502, 503, 504)
- [x] CRT light theme, system diagnostics, health checks
- [x] Fixed nginx to properly return 404 for unknown paths (`try_files $uri $uri/ =404;`)
- [x] Homepage route `location = /` serves index.html

### WAF Dashboard Rework — COMPLETE
- [x] **Live Attack Banner** at top with real-time last attack display
- [x] Combined **Security Events** table (alerts + bans unified)
- [x] Emoji stats cards: 🔥 Threats | 🚫 Bans | ⚡ Rules | 📁 Categories | 🔒 Blocked | 🛡️ Protected
- [x] **Category Pills** with emojis (💉 SQLi, 🔥 XSS, 💀 RCE, 🔍 Scanner, 🤖 Bot...)
- [x] 10s refresh for live banner, 30s for full stats

### Geomap Positions — FIXED
- [x] Recalibrated country coordinates for wargames-earth.png projection
- [x] 50+ countries with accurate x,y positions
- [x] Target set to France (SecuBox HQ - Notre-Dame-du-Cruet)

### CrowdSec Enrollment — FIXED
- [x] API now handles "already enrolled" gracefully (returns `already_enrolled: true`)
- [x] Frontend shows "✅ Already enrolled to CAPI" instead of error

### Sidebar JSON Fix — COMPLETE
- [x] Added HTML detection to clear corrupted localStorage cache
- [x] Better error handling with cache cleanup

### USB Gadget Network — FIXED
- [x] Brought up usb1 interface
- [x] Assigned IP 192.168.42.1/24
- [x] NAT forwarding for USB clients

### Files Updated
- `packages/secubox-hub/www/shared/error.html` — NEW
- `packages/secubox-hub/www/shared/sidebar.js` — JSON.parse fix
- `packages/secubox-waf/www/waf/index.html` — Full rework
- `packages/secubox-crowdsec/api/main.py` — Enrollment fix
- `packages/secubox-crowdsec/www/crowdsec/index.html` — Enrollment UI
- `/etc/nginx/sites-enabled/webui.conf` — Error page routing

---

## ✅ Session 134: CrowdSec Bans Fix + Auth Parser + CPU Optimization

### CrowdSec Decisions API — OPTIMIZED
- [x] **Cache 60s** to avoid hammering LAPI (was causing high CPU)
- [x] **Deduplication** by IP value (16574 raw → ~400 unique)
- [x] **Limit 500** decisions per request (performance)
- [x] **Total count** returned separately from paginated results
- [x] Frontend displays up to 200 with "X more" indicator

### SecuBox Auth CrowdSec Filter — NEW
- [x] Parser: `secubox/secubox-auth` detects 401 on login endpoints
- [x] Scenario: `secubox/secubox-auth-bf` triggers after 5 failures in 30s
- [x] Uses `evt.Meta.http_path` and `evt.Meta.http_status` (correct fields)

### Auth Session Logging — COMPLETE
- [x] Login events emit to callback in `secubox_core.auth`
- [x] `secubox-auth` module records sessions in JSON
- [x] Fixed `login.html` endpoint URLs

### Live Server Stats
- **407 unique bans** (down from 16574 total with CAPI)
- **Top attacker**: 13.42.14.127 (AWS UK) - 291 alerts
- **Load**: Still high (~10) due to Streamlit processes

### Commits
- `676630ca` fix(crowdsec): Display total bans count
- `fb5c33ea` feat(auth): Add session event logging
- `0887b81e` feat(crowdsec): Add SecuBox auth parser and scenario

### ⬜ Next Up (from user requests)
- [ ] Add active WebUI sessions display to System module
- [ ] SOC mini histograms with progressive animation
- [ ] Streamlit sleep/wake optimization (pausing system)

---

## ✅ Session 133: WAF Categories + NFTables Donuts + Mini Histograms

### WAF Dashboard — COMPLETE
- [x] Category toggles (ON/OFF buttons for each WAF filter)
- [x] API error handling (null responses)
- [x] 24h threats count instead of today
- [x] `loadCategories()` function

### SOC Dashboard — COMPLETE
- [x] **NFTables Eyeremote Donut** with breakdown:
  - ✅ Accept (green)
  - 🛡️ CAPI DROP (red)
  - 👁️ CrowdSec DROP (orange)
  - ✋ Manual DROP (yellow)
- [x] **Mini Histograms** for system health:
  - 🔥 CPU (red) | 💾 Memory (yellow) | 💿 Disk (green) | 🌐 Network (blue)
  - Rolling 12-sample history
  - Color-coded percentages
- [x] API null handling for offline states

### NFTables Stats
- IPv4 Processed: 3.3M packets
- CAPI DROP: 524 | CrowdSec DROP: 57 | Manual DROP: 2,250
- Cron job: `/etc/cron.d/secubox-nft-cache` (every minute)

### Files Updated
- `packages/secubox-waf/www/waf/index.html` — Category toggles, 24h count
- `packages/secubox-hub/www/soc/index.html` — NFT donut, mini histograms
- `packages/secubox-hub/api/main.py` — firewall_summary with counters

### Tag: v2.7.1

---

## ✅ Session 130: Eyeremote Style Visualizations + SOC/WAF Improvements

### Multi-Layer Concentric Donuts — COMPLETE
- [x] `createConcentricGauge()` for Hub System Health (CPU/RAM/Disk)
- [x] `createMultiLayerDonut()` for CrowdSec categories
- [x] `createCountryDonut()` for WAF Top Countries with flags
- [x] `createSiteDonut()` for WAF Top Attacked Sites with emojis
- [x] Ring gauges replaced by eyeremote-style concentric visualization

### Hub Dashboard Updates — COMPLETE
- [x] Concentric gauge for System Health with icons (🔥CPU/🧠RAM/💾Disk)
- [x] Legend with color-coded percentages
- [x] Smooth transitions on data update

### SOC Dashboard Updates — COMPLETE
- [x] Firewall packet stats bubbles (DROP/ACCEPT/REJECT)
- [x] CrowdSec category multi-layer donut
- [x] sidebar.js injection added
- [x] Fixed CATEGORY_EMOJI definition (syntax error)

### WAF Statistics Page — COMPLETE
- [x] Restored separate Severity/Category donuts
- [x] Country donut with flags alongside bar graph
- [x] Site donut with emojis
- [x] Fixed `parseDuration()` for compound formats ("22m47s")
- [x] Bar graphs with percentage backgrounds

### Backend API — COMPLETE
- [x] New `/api/v1/hub/public/firewall_summary` endpoint
- [x] Cron job for nftables cache (permission fix)
- [x] Cache files: `/var/cache/secubox/nft-counters.txt`, `nft-ruleset.json`

### Files Updated
- `packages/secubox-hub/www/index.html` — Concentric gauge
- `packages/secubox-hub/www/soc.html` — Multi-layer donuts, firewall stats
- `packages/secubox-waf/www/index.html` — Country/Site donuts, duration fix
- `packages/secubox-hub/api/main.py` — firewall_summary endpoint

---

## ✅ Session 129: Eye Remote Radar Animation + SOC Fixes
*(completed earlier today)*

---

## 🔄 Session 128: LED Tooltips + Kernel NFTables Fix

### Sidebar v2.32.0 — IN PROGRESS
- [x] Per-LED tooltips (separate for Hardware/Services/Security)
- [x] Fixed tooltip positioning for sidebar elements
- [x] Service layer tooltip with OK/WARN/ERROR/UNKNOWN counts
- [x] Security layer tooltip with bans/alerts stats
- [x] Hardware layer with CPU/MEM/DISK/LOAD histograms

### SOC Page Fix — COMPLETE
- [x] Fixed nginx route for /soc/ (was proxying to API, now serves static files)
- [x] SOC page HTML now loads correctly

### Kernel nftables Issue #64 — CRITICAL
- [x] Identified missing kernel options: `CONFIG_NF_TABLES_INET`, `CONFIG_NF_TABLES_IPV4`
- [x] Created GitHub issue #64 with full config requirements
- [x] Updated `board/mochabin/kernel/config-6.12-openwrt-merged.fragment` with complete nftables config
- [ ] Rebuild kernel with new config
- [ ] Deploy new kernel to MOCHAbin
- [ ] Add nftables modules to initramfs for early boot

### CrowdSec Bouncer Alert — TODO (ref issue #64)
- [ ] Add pre-flight nftables check to bouncer startup
- [ ] Alert SOC dashboard if firewall offline
- [ ] Set LED3 (Security) to RED if nftables fails

---

## ✅ Session 127: Smart Strip + LED Pulsing + Round UI Virtual

### Smart Strip & Health Bumper — COMPLETE
- [x] sidebar.js v2.25.0 with Smart Strip (6 mini modules)
- [x] LED tri-level pulsing (NOMINAL/WARNING/CRITICAL)
- [x] Health Bumper in top bar with sync emojis
- [x] Module colors: AUTH/WALL/BOOT/MIND/ROOT/MESH
- [x] Live metrics: CPU%, MEM%, DISK%, LOAD, TEMP°, NET dB
- [x] CSS for smart-strip, health-bumper, health-led-main

### Eye Remote Round UI Virtual — COMPLETE
- [x] Deployed 6 module icons (auth-22.png, etc.)
- [x] Canvas-based concentric rings (drawRoundRings)
- [x] 6 positioned pods with live values
- [x] Clock, hostname, status display
- [x] Transport indicator (OTG)

### Eye Remote 3-Column Layout — COMPLETE
- [x] Converted from large device boxes to compact chips
- [x] Device status bar minimized (MOCHAbin/eye-remote)
- [x] Grid 3-column responsive layout
- [x] Synced to local repo

---

## ⬜ Backlog — Deferred Items

### CDN Fonts Proxy (secubox-cdn module)
- [ ] Create `/cdn/fonts/space-grotesk.css` proxy endpoint
- [ ] Create `/cdn/fonts/jetbrains-mono.css` proxy endpoint
- [ ] Cache Google Fonts locally via CDN module
- [ ] Update SOC/modules to use CDN-proxied fonts
- [ ] Fallback to external URL if CDN unavailable

---

## ✅ Session 126: Hybrid Skin License & Centralized Injection

### License Headers — COMPLETE
- [x] Added CyberMind/Gérald Kerma license to `hybrid-skin.css`
- [x] Added license to `design-tokens.css`
- [x] Added license to `sidebar.css`
- [x] Added license + architecture docs to `soc/index.html`
- [x] Deployed to production (192.168.1.200)
- [x] Updated HISTORY.md

### Centralized Hybrid Skin Injection — COMPLETE
- [x] Updated `sidebar.js` to v2.19.0
- [x] Added `injectHybridSkin()` function
- [x] Auto-injects: design-tokens.css, sidebar.css, hybrid-skin.css
- [x] Auto-adds `hybrid-skin` class to body
- [x] Auto-adds `hybrid-main` class to main content
- [x] Any page loading sidebar.js gets hybrid skin automatically
- [x] Verified local/live sync (all files match)

---

## 🔄 Session 125: Socket Repair & Health API Standardization

### Socket Repair — COMPLETE
- [x] Identified 91 running services, 87 with Unix sockets
- [x] Fixed `ai-gateway` — permission denied for `/tmp/secubox/ai-gateway`
- [x] Fixed `mcp-server` — socket now active
- [x] Restarted `crowdsec`, `vhost`, `wireguard`, `system` — all responding
- [x] Verified all critical services: hub, waf, crowdsec, haproxy, vhost, wireguard

### Services Status
| Service | Status | Notes |
|---------|--------|-------|
| hub | ✅ TCP:8001 | VM compatibility mode |
| waf | ✅ socket | v1.2.0 |
| crowdsec | ✅ socket | v2.0.0 |
| haproxy | ✅ socket | healthy |
| vhost | ✅ socket | ok |
| wireguard | ✅ socket | v2.0.0 |
| ai-gateway | ✅ socket | fixed |
| dns | ⚠️ degraded | unbound not running |
| metrics | ❓ no /health | needs endpoint |

### Planned: Navbar-Compliant Health APIs
- [ ] Standardized `HealthResponse` schema in `secubox_core`
- [ ] Fields: `status`, `module`, `version`, `enabled`, `dev_stage`
- [ ] Batch health endpoint `/api/v1/hub/public/health-batch`
- [ ] Update `sidebar.js` to display version, dev_stage badges
- [ ] Retrofit all 116 modules to standard format

---

## 🔄 Session 124: Multi-Layer Health & Auto-Repair System

### Architecture Health/Doctor/Repair — EN COURS
- [x] HAProxy: `/repair`, `/certificates/repair`, `/vhosts/repair`
- [x] WAF: `/health`, `/doctor`, `/repair`
- [x] Hub: `/repair/{module}`, `/repair/all`, `/repair/diagnose/{module}`
- [ ] Appliquer pattern à TOUS les modules SecuBox
- [ ] Vhost comme master controller (HAProxy + nginx + certs)
- [ ] État distribué sans duplication
- [ ] Escalade multi-niveau avec récursion

### Pattern Multi-Layer
```
Layer 1: /health     → Status basique (up/down/degraded)
Layer 2: /doctor     → Diagnostic détaillé + can_repair
Layer 3: /repair     → Auto-réparation avec log
Layer 4: Escalade    → Si repair échoue → notifier admin / hub central
```

### Modules à migrer vers ce pattern
- [ ] secubox-crowdsec (CAPI, hub, bouncer)
- [ ] secubox-wireguard (peers, routes)
- [ ] secubox-nginx (vhosts, configs)
- [ ] secubox-dns (zones, unbound)
- [ ] secubox-mail (postfix, dovecot, dkim)
- [ ] Tous les autres...

---

## ✅ Session 122: WAF GeoIP Country Lookup & Stats Enhancement

### WAF API Enhancements — COMPLETE
- [x] Added GeoIP country lookup using MaxMind GeoLite2-Country database
- [x] Added `top_countries` to WAF threat stats (replaces reliance on top IPs)
- [x] Added `top_vhosts` to WAF threat stats (most attacked vhosts)
- [x] Fixed field name: `ip` → `client_ip` for log compatibility
- [x] Added `_lookup_country()` helper with caching for performance
- [x] Source files synced to debian package directories

### Files Updated
- `packages/secubox-waf/api/main.py`
  - `_get_threat_stats()`: Now returns top_countries, top_vhosts, and uses correct client_ip field
  - `_lookup_country()`: New GeoIP lookup function with LAN detection
- `packages/secubox-waf/debian/secubox-waf/usr/lib/secubox/waf/api/main.py` (synced)
- `packages/secubox-haproxy/debian/secubox-haproxy/usr/lib/secubox/haproxy/api/main.py` (synced)

### Stats Response Now Includes
```json
{
  "total_threats": 8000,
  "threats_today": 2819,
  "by_category": {"rce": 100, "sqli": 50, ...},
  "by_severity": {"critical": 10, "high": 200, ...},
  "top_ips": {"1.2.3.4": 100, ...},
  "top_countries": {"CN": 500, "RU": 300, "US": 200, ...},
  "top_vhosts": {"git.secubox.in": 2558, "gitea.gk2.secubox.in": 2414, ...}
}
```

---

## ✅ Session 121: HealthBump v2.1 with Activity Detection & K2000

### HealthBump Enhancements — COMPLETE
- [x] Activity-based brightness: ACTIVE (100) when metrics change, SLEEP (20) when stable
- [x] K2000 (Knight Rider) sweep effect for boot/success announcements
- [x] Alert mode (red K2000) for warnings
- [x] Rainbow party mode for testing
- [x] Aligned I2C timing with secubox-led-safe (300ms write delay)
- [x] Simplified to POSIX `/bin/sh` (was bash)

### Commands Added
- `secubox-healthbump k2000 N C` — K2000 sweep N cycles, color C
- `secubox-healthbump success` — Boot complete announcement
- `secubox-healthbump alert N` — Red alert sweep
- `secubox-healthbump rainbow` — All colors party

### I2C Bus Recovery Documented
```bash
echo '80018000.i2c' > /sys/bus/platform/drivers/mv64xxx_i2c/unbind
sleep 2
echo '80018000.i2c' > /sys/bus/platform/drivers/mv64xxx_i2c/bind
modprobe leds-is31fl319x
```

### Files Updated
- `packages/secubox-led-heartbeat/usr/sbin/secubox-healthbump`
- `packages/secubox-led-heartbeat/systemd/secubox-healthbump.service`
- `docs/LED-HEALTHBUMP.md`

---

## ✅ Session 120: LED System Complete & Kernel 6.6.137 Validation

### LED System Working
- [x] Kernel 6.6.137 LTS deployed (same generation as OpenWrt)
- [x] IS31FL319X LED driver stable
- [x] secubox-led-safe with 300ms I2C timing
- [x] HealthBump 3-tier status system

---

## ✅ Session 118: Kernel LED Driver + USB Network + Documentation

### Kernel Enhancements — COMPLETE
- [x] Added IS31FL319X LED driver (=y) for I2C LED controller
- [x] Added USB network drivers for Eye Remote (cdc_ether, usbnet)
- [x] Rebuilt kernel 6.12.85-openwrt-led
- [x] Deployed to MOCHAbin /boot/Image-openwrt
- [x] **LEDs WORKING!** 9 LEDs visible (blue/green/red × led1/led2/led3)
- [x] Heartbeat trigger active: `echo heartbeat > /sys/class/leds/green:led1/trigger`
- [ ] Test USB network with Eye Remote gadget (pending device)

### Documentation Created
- [x] `kernel-build/README.md` - Complete build guide
- [x] GitHub Issue #60 updated with progress
- [x] USB gadget architecture documented (SecuBox=HOST, Eye Remote=GADGET)

### Config Fragment Updated
```
board/mochabin/kernel/config-6.12-openwrt-merged.fragment
```
**Additions:**
- `CONFIG_LEDS_IS31FL319X=y` (I2C LED controller)
- `CONFIG_USB_USBNET=y`, `CONFIG_USB_NET_CDCETHER=y` (USB network)
- `CONFIG_OF_OVERLAY=y`, `CONFIG_OF_CONFIGFS=y` (DT overlays)

---

## ✅ Session 117: OpenWrt-style Kernel with DSA Built-in

### Kernel Migration — RESOLVED
- [x] Diagnosed: Custom kernel DSA module chain incomplete
- [x] Switched to Debian kernel for immediate DSA fix
- [x] Analyzed OpenWrt MVEBU/Cortex-A72 kernel configs
- [x] Created merged config fragment (OpenWrt + Debian systemd)
- [x] Built kernel 6.12.85 with DSA built-in (=y)
- [x] Deployed to MOCHAbin as default boot option
- [x] Verified: lan0/1/2/3 interfaces working
- [x] Verified: No DSA modules (all built-in)
- [x] Verified: /proc/config.gz available (IKCONFIG)
- [x] Verified: HAProxy running, WAN uplink OK

### Config Fragment Created
- [x] `board/mochabin/kernel/config-6.12-openwrt-merged.fragment`
  - 365 lines merged config
  - OpenWrt MVEBU DSA options (built-in)
  - Debian systemd compatibility
  - IKCONFIG, WireGuard, nftables, LED triggers

### Boot Menu Updated
- [x] Option 1: OpenWrt-style kernel (DSA built-in) — DEFAULT
- [x] Option 2: Debian kernel (modules, initrd)
- [x] Option 3: SecuBox custom (previous)

---

## ✅ Session 116: Kernel 6.12.85 Boot Fix

### Kernel Boot Crisis — RESOLVED
- [x] Diagnosed: Critical drivers as modules (=m) instead of built-in (=y)
- [x] Created USB rescue boot system
- [x] Fixed `CONFIG_MMC_SDHCI_XENON=y` — eMMC detection
- [x] Fixed `CONFIG_EXT4_FS=y` — Root filesystem
- [x] Fixed `CONFIG_VFAT_FS=y` — Boot partition
- [x] Fixed `CONFIG_NLS_ASCII=y` / `CONFIG_NLS_UTF8=y` — VFAT charset
- [x] Fixed `CONFIG_PHY_MVEBU_CP110_UTMI=y` — USB PHY deferred probe
- [x] Fixed `CONFIG_BLK_DEV_SD=y` — /dev/sda block devices
- [x] Kernel deployed to eMMC /boot
- [x] MOCHAbin boots from eMMC without USB

### Kernel Fragment Saved
- [x] `board/mochabin/kernel/config-6.12.85-secubox-boot.fragment`

### Hardware Verified
- [x] eMMC: 14.7 GiB (mmcblk0)
- [x] SATA: WD Blue SA510 1TB @ 6Gbps
- [x] USB: Both xHCI controllers functional
- [x] Network: eth0/eth1/eth2 OK

---

## 🔄 Session 113: WAF Ban Page Styling + Autoban Debug

### WAF Ban Page Aesthetic
- [x] Added styled BAN_PAGE with cyberpunk aesthetic:
  - Skull icon with shake animation
  - Red glow effects, scanlines overlay
  - Client IP display, 4h ban duration notice
  - Legal notice (Art. 323-1 Code Penal)
  - CyberMind/SecuBox branding
- [x] Updated ban_ip() to use SSH to host for CrowdSec
- [x] Ban page shows {client_ip} placeholder replaced dynamically

### Whitelist Updates
- [x] Added 192.168.1.36 (user workstation) to WHITELIST
- [x] Added 192.168.1.254 (user router) to WHITELIST
- [x] Source file synced: secubox_waf.py

### HAProxy WAF Routing Investigation
- [x] Tested routing admin.gk2.secubox.in through mitmproxy_inspector
- [x] Found issue: 400 Bad Request with query parameters
- [x] Reverted admin.gk2.secubox.in to nginx_vhosts
- [x] Confirmed default_backend mitmproxy_inspector works fine
- [ ] TODO: Investigate why use_backend causes 400 errors

### CrowdSec Integration
- [x] Cleared all CrowdSec decisions
- [x] Verified SSH from mitmproxy container to host works
- [x] Ban commands execute successfully via SSH chain
- [x] Dashboard shows: 0 bans, 1 bouncer, 1 machine, 43k parsed logs

### WAF False Positive Fixes (v1.3.0)
- [x] Fixed 7 false positive patterns in waf-rules.json:
  - `lfi-001`: Require 3+ levels of `../` traversal (was: any `../`)
  - `rce-006`: Target Python SSTI `__class__/__mro__` (was: all `{{ }}`)
  - `scan-004`: Only block xmlrpc pingback/multicall (was: all WordPress)
  - `waf-fp-005`: Target MySQL version comments (was: all `/* */`)
  - `recon_crawler`: Disabled entire category (FP on robots.txt, .well-known)
  - `cred-002`: Detect password in URL query (was: Basic auth header)
  - `cred-006`: Detect secrets in URL query (was: X-API-Key header)
- [x] Synced to debian package locations

### Known Issues
- **HAProxy use_backend vs default_backend**: Explicit `use_backend mitmproxy_inspector`
  causes 400 errors with query params, but `default_backend mitmproxy_inspector` works.
  Needs further investigation.

### ⬜ Next Up
- [ ] Debug HAProxy use_backend 400 error issue
- [ ] Route critical vhosts through WAF properly
- [ ] Test autoban end-to-end with external IP

---

## 🔄 Session 112: WAF Autoban + eMMC Rootfs Expansion

### eMMC Rootfs Expansion
- [x] Deleted mmcblk0p3 partition (unused 8.9G)
- [x] Expanded mmcblk0p2 rootfs from 5.4G to 14.4G
- [x] **Disk usage: 95% → 36%** (8.7G free now)

### WAF Autoban via CrowdSec
- [x] Fixed SSH key: container→host auth for cscli commands
- [x] Added mitmproxy container SSH key to host authorized_keys
- [x] Tested ban_ip SSH chain (works manually)
- [x] Routed webui through WAF (HAProxy→mitmproxy→nginx)
- [x] Fixed Host header preservation in mitmproxy addon
- [ ] Test autoban end-to-end (3 threats → CrowdSec ban)
- [ ] IP-based webui access through WAF (192.168.1.200:9443)

### System Services Fixed
- [x] Restarted secubox-system (socket was missing)
- [x] Restarted secubox-hub, secubox-crowdsec
- [x] Fixed JSON parse error handling in system webui

### Source Sync
- [x] Updated secubox_waf.py with Host header preservation
- [x] Updated system/index.html with JSON error handling

### ⬜ Next Up
- [ ] Clear WAF threats to 0
- [ ] Verify autoban works end-to-end
- [ ] Add IP route to haproxy-routes.json for direct IP access

---

## ✅ Session 111: LED Kernel + CrowdSec GeoIP + 503 Fix

### LED Kernel Build (#60)
- [x] Fixed kernel config: MARVELL_PHY=y (was =m)
- [x] Fixed kernel config: MDIO=y, SFP=y, MDIO_I2C=y
- [x] Fixed kernel config: USB_XHCI=y, USB_STORAGE=y (for live USB)
- [ ] Kernel build in progress (~25%)
- [ ] Deploy Image-secubox-led to MOCHAbin
- [ ] Debug LED I2C probe failure (IS31FL319X at 0x64)

### CrowdSec WebUI GeoIP
- [x] Added GeoIP cache with 24h TTL (localStorage)
- [x] Country flags on bans/decisions list (ipapi.co HTTPS)
- [x] Backend fallback for GeoIP lookup
- [x] Deployed to MOCHAbin

### WAF X-Forwarded-For Fix
- [x] Fixed mitmproxy to use X-Forwarded-For for real client IP
- [x] WAF stats now show correct attacker IPs

### GitHub Issues Created
- [x] #59 — 503 errors at boot (service startup delay)
- [x] #60 — LED kernel with built-in drivers
- [x] #61 — Eye Remote gadget metrics endpoint

### ⬜ Next Up
- [ ] Fix 503 errors permanently (HAProxy/mitmproxy chain)
- [ ] Test LED kernel after build complete
- [ ] Update netplan boot timing

---

## ✅ Session 110: System Optimization + Eye Remote Fix

### System Resource Cleanup
- [x] Killed orphan health prober (PID 1169103, 705MB VIRT memory leak)
- [x] Disabled netdata (freed 213MB RAM, 26% CPU)
- [x] **Load: 7.16 → 4.78 (-33%)**
- [x] **Free RAM: 380MB → 692MB (+82%)**

### Eye Remote Dashboard Fix
- [x] Fixed duplicate `get_pizero_metrics()` function bug in API
- [x] Deployed clean API source (removed router bugs)
- [x] Added `clearMetricsUI()` - resets gauges to `--` when disconnected
- [x] Frontend now shows proper disconnect state instead of stale data

### Eye Remote Round UI Fix
- [x] Added `/api/v1/system/metrics` endpoint for MOCHAbin metrics
- [x] Round UI on Pi Zero now receives live data from MOCHAbin
- [x] Metrics: cpu_percent, mem_percent, disk_percent, cpu_temp, load, uptime
- [x] Fixed CPU calculation: real /proc/stat delta (was load-based → stuck at 100%)
- [x] Added async double pre-cache buffer (per guidelines):
  - Background task updates shadow buffer every 2s
  - Atomic swap to active buffer
  - API returns instantly from cache
- [x] Exposed API on TCP port 8000 (10.55.0.1) for Pi Zero access
  - Was: Unix socket only (Pi Zero couldn't reach)
  - Now: TCP listener via systemd drop-in
- [x] Verified working on HyperPixel 2.1 Round display
- [x] Rings now show varied fill levels matching real metrics

### Current Health Status
- **VHost Health:** 🟢 27 🟡 134 🔴 0 ⬜ 58 (96.4%)
- **Module Health:** 🟢 5 🟡 3 🔴 0 (62.5%)
- **System Load:** 4.78 (4-core ARM)
- **Memory:** 6.1GB/7.7GB (79%)

---

## ✅ Session 109: Metablogizer Full Config + Health Prober Fix

### Metablogizer Full Configuration
- [x] Configured **165 metablogizer sites** (ports 8900-9204)
- [x] Created flat config: `/etc/secubox/metablogizer.json`
- [x] Generated nginx server blocks for all sites
- [x] Added 131 new HAProxy backends + ACLs
- [x] Synced **225 mitmproxy routes** through WAF
- [x] Committed config to repo: `config/metablogizer.json`

### Health Prober Fixes
- [x] Fixed prober to use localhost with Host header (was hitting HTTPS externally)
- [x] Fixed recursive probe bug in semaphore code
- [x] Placeholder detection working (58 Streamlit apps identified)
- [x] **Current health: 🟢 29 🟡 132 🔴 0 ⬜ 58 (100%)**

### VHost Matrix Sync Tool
- [x] Created `scripts/vhost-matrix-sync.sh` with Python-based extraction
- [x] Fixed stderr logging for clean JSON output capture
- [x] Syncs HAProxy vhosts → mitmproxy routes + health prober
- [x] Successfully synced 225 vhosts on server

### Eye Remote Fixes
- [x] Added `/api/v1/system/metrics` alias for Pi Zero compatibility
- [x] Fixed dashboard to use public endpoints (no JWT)

### GitHub Issues
- [x] #49 — MetaBlogizer + Streamlit version management via Gitea
- [x] #50 — Green Computing: Sleep/Wake WAF + Health Prober Optimization

### Release
- [x] Tagged **v2.5.0** and pushed to master

---

## ✅ Session 108 (Continued): VHost Health Fixes + Services Restore

### VHost Health Prober
- [x] Updated prober to treat placeholders as "placeholder" status (not "down")
- [x] Added ⬜ placeholder indicator to dashboard
- [x] Health % now only counts real vhosts (excludes placeholders)

### HAProxy Routing Fixes
- [x] Fixed c3box.maegia.tv → metablog_gandalf (was nginx_vhosts placeholder)
- [x] mitmproxy backend confirmed UP at 10.100.0.60:8080

### Service Socket Restoration
- [x] Restarted all secubox-* services
- [x] 86 API sockets now active
- [x] Verified hub, crowdsec, system, haproxy all working

### System Load Issues (Ongoing)
- [ ] mitmdump using 95% CPU (821MB RAM) - investigate
- [ ] Memory at 91% (7.1GB/7.7GB)
- [ ] Load average: 11-17 (very high)

### Metrics Dashboard (User Request)
- [ ] Add precaching + double-buffer with threaded updating
- [ ] Currently 1.6s response time due to high load

---

## 🔄 Session 108: Dashboard Health Widgets + HAProxy Workflow

### HAProxy Workflow Script
- [x] Created `scripts/haproxy-workflow.sh` with 3 commands:
  - `rehealth` — Auto-rehealth HAProxy (reload, invalidate caches, restart probers)
  - `waf-sync` — Sync vhost→backend routes through WAF (mitmproxy)
  - `certs` — Check/list certificate status for all vhosts
  - `all` — Run complete workflow

### Dashboard Health Widgets (Upper Position)
- [x] Added Module Health widget to dashboard index.html
  - Progress bar + health percentage
  - Emoji counters 🟢🟡🔴 (healthy/degraded/down)
  - Calls `/api/v1/hub/module-health/summary`
- [x] Added VHost Health widget to dashboard index.html
  - Progress bar + health percentage
  - Emoji counters 🟢🟡🔴 (ok/slow/down)
  - Calls `/api/v1/hub/health-monitor/summary`
- [x] Positioned both widgets upper in grid (before main content)

### Dashboard Widget Limits
- [x] Modules Overview: Reduced from 10 to 4 items
- [x] Alert Timeline: Reduced from 5 to 3 items

### Hub API Health Endpoints
- [x] Added `/module-health/summary` — Module health counts
- [x] Added `/module-health/status` — Detailed module status
- [x] Added `/module-health/alerts` — Degraded/down modules
- [x] Added `/health-monitor/summary` — VHost health counts
- [x] Added `/health-monitor/status` — Detailed VHost status
- [x] Added `/health-monitor/alerts` — Slow/down VHosts

---

## ✅ Session 107: Module Health Monitor + Placeholder Detection

### Admin Page Fixes
- [x] Fixed "undefined/undefined" bug in System Administration page
- [x] Added null coalescing (`?? 0`) for missing API data

### Module Health Prober System
- [x] Created `/usr/lib/secubox/health/module_prober.py`
- [x] Multilayer checks: systemd → socket → API
- [x] 8 core modules monitored (hub, crowdsec, dpi, haproxy, vhost, wireguard, system, heartbeat)
- [x] Results cached to `/var/cache/secubox/health/modules.json`
- [x] Created `secubox-module-prober.service` (enabled)
- [x] Added API router `/api/v1/hub/module-health/`:
  - `GET /summary` - Global module health stats
  - `GET /status` - All modules with layer details
  - `GET /module/{name}` - Single module status
  - `GET /alerts` - Degraded/down modules
- [x] Dashboard widget "Module Health" with:
  - Progress bar + health %
  - Emoji counters 🟢🟡🔴
  - Alert list for degraded/down modules

### Sidebar Module Filtering
- [x] Menu API now hides inactive modules from sidebar
- [x] Only functional modules displayed (systemd active)
- [x] Reduces sidebar clutter for partially-deployed systems

### VHost Health Prober Enhancements
- [x] Added placeholder page detection (`SecuBox Domain` / `SecuBox Protected`)
- [x] Sites showing placeholder = marked as "down" (not "ok")
- [x] Real health: 7 slow, 85 down (mostly placeholder pages)

### VHost Routing Fixes
- [x] Fixed gandalf.maegia.tv routing
- [x] Added `metablog_gandalf` backend (port 8901)
- [x] Updated HAProxy ACL → metablog_gandalf

---

## ✅ Session 106: Double Pre-Cache + Adaptive Navbar + DNS Migration

### Double Pre-Cache System (metablogizer)
- [x] Created `cache.py` module with memory + file cache
- [x] Directory mtime tracking for smart invalidation
- [x] Background refresh every 30s (only if changes)
- [x] Patched `main.py` for cache integration
- [x] Guideline: "Only regenerate when necessary"

### Adaptive Navbar Status Dots
- [x] Added health check code to `sidebar.js`
- [x] Status classes: `.active` (green), `.warning` (orange), `.error` (red)
- [x] Checks `/api/v1/{module}/health` with 30s cache TTL
- [x] Modem health returns `degraded` when no hardware

### DNS Migration
- [x] Ported `dnsmaster` from OpenWrt to Debian
- [x] Replaced `uci_get` with TOML config reading
- [x] Uses `journalctl` instead of `logread`
- [x] Uses `systemctl` instead of `/etc/init.d/`
- [x] DNS API now returns proper BIND status

### Metablogizer Fixes
- [x] Fixed Export ZIP/Download Cert buttons (JS fetch + JWT)
- [x] Fixed closing tags `</a>` → `</button>`
- [x] Fixed `downloadCert` missing closing brace

### money.maegia.tv Deployment
- [x] Added HAProxy vhost
- [x] Fixed nginx listen port (80 → 9080)
- [x] Generated ACME certificate via ZeroSSL
- [x] Restored WebUI 9443 frontend (broken by haproxyctl generate)

### GitHub Issue
- [x] Created Issue #38: Double Pre-Cache System + Adaptive Navbar Status

### Notes Architecture
- LXC pour services non-vitaux
- Vital = WebUI + heartbeat monitoring (contrôle SecuBox)
- TODO: Porter LEDs heartbeat depuis OpenWrt

### Heartbeat Monitor System
- [x] Created `/usr/sbin/secubox-heartbeat` CLI (bash)
- [x] Created `/usr/lib/secubox/heartbeat/api/main.py` (FastAPI)
- [x] Config: `/etc/secubox/heartbeat.toml`
- [x] Auto-restart for vital services with max_retries
- [x] LED control (green/orange/red) for hardware indicators
- [x] Alerts system with acknowledge/clear
- [x] Git status integration for live dashboard
- [x] Metrics: CPU, memory, disk, uptime

### VHost Exposure Modes
- [x] Created `/etc/secubox/vhost-modes.toml`
- [x] Mode `darkpublish`: Protected by default, whitelist access
- [x] Mode `lightexposure`: Open by default, blacklist blocking
- [x] Global + per-vhost whitelist/blacklist
- [x] CrowdSec/fail2ban integration for dynamic blocking
- [x] Rate limiting and geo-blocking options

### Enhanced Navbar (Adaptive LEDs)
- [x] Updated `/usr/share/secubox/www/shared/sidebar.js`
- [x] GREEN (.active): Service running, healthy
- [x] ORANGE (.warning): Service degraded or disabled
- [x] RED (.error): Service down, critical
- [x] GRAY (.disabled): Service not installed
- [x] DISABLED section at bottom for absent modules
- [x] 30s health check cache TTL

### Live Dashboard (live.maegia.tv)
- [x] Deployed `secubox-live.html` autogenerative landing
- [x] GitHub API live sync for commits/releases/languages
- [x] Stack canonique AUTH→WALL→BOOT→MIND→ROOT→MESH
- [x] Heartbeat API integration at `/api/v1/heartbeat/`

### Guidelines Added
- **Double Pre-Cache Pattern**: Memory + file cache + mtime tracking
- **VHost Multi-Cache**: Offline buffer, pre-publish, refresh on update
- **Navbar Camouflage**: Orange LED for absent, DISABLED section
- **Only Regenerate When Necessary**: Smart invalidation

### VHost Routing Fixes (Session 106 continued)
- [x] Identified live.maegia.tv routing issue (HAProxy → nginx_vhosts instead of metablogizer)
- [x] Created `metablog_live` backend (port 8906)
- [x] Fixed HAProxy ACL for live.maegia.tv → metablog_live
- [x] Verified live.maegia.tv serves correct content

### GitHub Issues Created
- [x] **#43**: Health Monitor Dashboard - Buffered Metrics & Live Status
  - Prober background task + cache JSON
  - Config vs actual state comparison
  - Emoji/LED status (🟢🔴🟡⚪)
  - Global alert sketch on dashboard
  - WebSocket real-time updates
- [x] **#44**: WebUI Obfuscation - admin.HOSTNAME.secubox.in Only
  - WebUI never responds on arbitrary URLs
  - Pattern strict: `admin.*.secubox.in`
  - Security feature for CSPN compliance

### Sidebar Fix (Session 106 continued)
- [x] Identified truncated sidebar.js (324 lines vs 446 lines)
- [x] Missing `sidebar.innerHTML` generation code
- [x] Redeployed correct version from repo
- [x] Navbar now renders with all 110 modules

### LED Investigation (IS31FL3199)
- [x] CONFIG_LEDS_IS31FL319X not compiled in Debian kernel
- [x] DTB GST factory lacks IS31FL3199 node
- [x] Options: kernel recompile or userspace I2C driver
- [x] **#45**: Created GitHub issue for tracking

### GitHub Issues Created (continued)
- [x] **#45**: LED Hardware IS31FL3199 Driver
  - Kernel module not available
  - Userspace I2C driver option
  - Integration with heartbeat monitor
- [x] **#46**: Navbar Dynamic Visibility & Toggle
  - Hide disabled modules
  - Reorder modules (drag & drop)
  - Toggle enable/disable inline
  - Favorites section
  - Config `/etc/secubox/navbar.toml`

### Health Monitor Implementation (#43)
- [x] Created `/etc/secubox/health.toml` config
- [x] Created `/usr/lib/secubox/health/prober.py` daemon
- [x] Extracts 92 vhosts from HAProxy config
- [x] Async probing with aiohttp (20 concurrent)
- [x] Writes to `/var/cache/secubox/health/status.json`
- [x] Created `secubox-health-prober.service` (enabled)
- [x] Added API router to secubox-hub:
  - `GET /health-monitor/summary` - Global stats
  - `GET /health-monitor/status` - All vhosts
  - `GET /health-monitor/vhost/{domain}` - Single vhost
  - `GET /health-monitor/alerts` - Down/error list
- [x] Dashboard widget (frontend)
  - Progress bar avec % health
  - Compteurs emoji 🟢🟡🔴
  - Liste des vhosts down (max 5)
  - Auto-refresh 30s avec loadVHostHealth()

---

---

## ✅ Session 105: Wiki License Links + Issue #35 Update

### Wiki License Documentation
- [x] Added full CMSD-1.0 license section to `wiki/Home.md`
- [x] Added license section to `wiki/Home-FR.md` (French)
- [x] Added license section to `wiki/Home-DE.md` (German)
- [x] Added license section to `wiki/Home-ZH.md` (Chinese)
- [x] Updated `wiki/_Footer.md` with CMSD-1.0 link
- [x] Updated footer wiki version to v2.5.0

### GitHub Issue #35 Update
- [x] Updated migration tracking issue with Session 104-105 progress
- [x] Added WAF Phase 1-5 as complete
- [x] Added ACME/SSL, SecuBox CLI v2.0.0, license alignment to completed items
- [x] Updated recent updates table with 2026-05-06 fixes

---

## ✅ Session 104: ACME SSL Renewal + SecuBox CLI v2.0.0

### ACME SSL Certificate Renewal
- [x] Fixed live.maegia.tv expired certificate (P0 OPORD F-001)
- [x] Configured HAProxy ACME ACL (path_beg /.well-known/acme-challenge/)
- [x] Added acme_challenge backend (nginx port 8880)
- [x] Renewed certificate via ZeroSSL (valid until Aug 4, 2026)
- [x] Deployed certificate to /data/haproxy/certs/
- [x] Set up ACME cron for auto-renewal (0 2 * * *)

### SecuBox CLI v2.0.0
- [x] Enhanced `secubox` unified CLI with new commands:
  - `secubox threats` - View CrowdSec + WAF threats
  - `secubox waf` - WAF inspection status
  - `secubox firewall` - nftables rules
  - `secubox bans` - CrowdSec active bans
  - `secubox vhosts` - HAProxy virtual hosts
  - `secubox certs` - SSL certificate status
  - `secubox mode [kiosk|tui|console]` - Display mode
  - `secubox acme-renew <domain>` - Renew SSL certificate
- [x] Created helper scripts:
  - `secubox-services` - Service management
  - `secubox-network` - Network configuration
  - `secubox-firewall` - Firewall status
  - `secubox-threats` - Threat intelligence
  - `secubox-waf-status` - WAF status
  - `secubox-mode` - Display mode switcher

### OPORD Fixes
- [x] F-001: SSL expired live.maegia.tv - FIXED
- [x] F-002: License conflict README vs Wiki - FIXED (removed Apache-2.0 reference)
- [ ] F-003: Package count - Already correct at 131 packages

### Metablogizer Fixes
- [x] Fixed site.json permissions (chown secubox:secubox)

---

## 🎯 Plan v2.5.0 — WAF Fixing & Full Health

**Target:** Complete WAF integration and achieve fully healthy SecuBox deployment

### Phase 1: WAF/Mitmproxy Container Setup ✅ COMPLETE
- [x] Create mitmproxy LXC container at `/data/lxc/mitmproxy`
- [x] Install mitmproxy with transparent proxy support
- [x] Configure haproxy-routes.json for backend routing (139 routes)
- [x] Symlink `/var/lib/lxc/mitmproxy` for lxc-* compatibility
- [x] Deploy `secubox_waf.py` addon (Host-based routing)
- [x] Create `wafctl` control script (xxxctl pattern)
- [x] Verified working: gandalf 200, pix 200 via WAF

### Phase 2: HAProxy WAF Integration ✅ COMPLETE
- [x] Configure HAProxy backends to route through mitmproxy
- [x] `backend mitmproxy_inspector` → LXC 10.100.0.60:8080
- [x] Update all vhost backends to use WAF inspection (330 rules)
- [x] Using `http-request set-uri` for proxy-style requests
- [ ] Test bypass rules for WebSocket/streaming services

### Phase 3: WAF Rules & Monitoring
- [x] Deploy mitmproxy inspection scripts (SecuBox WAF addon)
- [x] Configure logging to `/srv/mitmproxy/logs/waf-threats.log`
- [x] Create `wafctl` control script (xxxctl pattern)
- [x] Graduated Response System (GH Issue #37):
  - Warning page on first detection (not immediate block)
  - Counter: shows attempts vs threshold (e.g., "1/3")
  - Auto-ban via CrowdSec after 3 attempts in 5 min window
  - SecuBox-themed alert page with license/legal notice
- [ ] WebUI integration: WAF status, blocked requests, rules

### Phase 4: Health Verification ✅ COMPLETE
- [x] All HAProxy backends healthy (no 503s)
- [x] WAF container running and inspecting traffic
- [x] All 6 LXC containers running: gitea, nextcloud, matrix, mitmproxy, streamlit, mail
- [x] Metablogizer sites accessible (gandalf, cyberzine, devel, etc.)
- [x] Streamlit: 26 instances running
- [x] Matrix: PostgreSQL permissions fixed, Synapse running
- [x] All traffic tagged with X-SecuBox-WAF: inspected
- [ ] CrowdSec integration with WAF logs (future)

### Phase 5: Package Updates ✅ COMPLETE
- [x] Create `secubox-waf` package (mitmproxy + wafctl + config)
  - Updated debian/control with LXC dependencies
  - Updated debian/rules to install wafctl and mitmproxy addon
  - Added mitmproxy.service for LXC container
  - Added haproxy-routes.json.example
  - Updated debian/changelog to v1.1.0
- [x] Update `secubox-haproxy` for WAF backend support
  - Added `waf` subcommand (status/enable/disable)
  - Added waf_backend_ip config for LXC IP (10.100.0.60)
  - Updated mitmproxy_inspector backend with http-request set-uri
  - Updated debian/changelog to v1.2.0
- [x] Add WAF status to WebUI dashboard
  - Added mitmproxy container status card
  - Shows container running state, IP:port, requests inspected

### Dependencies
- mitmproxy compatible with OpenSSL on Debian arm64
- br-lxc network configured (10.100.0.0/24)
- HAProxy TOML config support

---

## ✅ Session 103: CrowdSec + WAF Dashboard Fixes

### CrowdSec API Fixes
- [x] Added `lapi_key` to `/etc/secubox/secubox.conf` (bouncer API key)
- [x] Registered CAPI with `cscli capi register`
- [x] Updated alerts router to use `cscli` instead of LAPI
- [x] Hub update/upgrade working (base-http-scenarios 1.3→1.4)
- [x] All API endpoints return real data:
  - Decisions: 100 active bans
  - Alerts: 139 alerts in 24h
  - Bouncers: 1 firewall bouncer
  - Machines: 2 machines
  - Hub: 7 collections installed

### CrowdSec Dashboard Fixes
- [x] Fixed alerts display: `a.source_ip` and `a.country`
- [x] Added `loadMachines()` function for machines count
- [x] CAPI status now shows registered ✅

### WAF Dashboard Fixes
- [x] Fixed `_get_bans()` to flatten nested CrowdSec data
- [x] Added Country, ASN columns to bans table
- [x] Added `allow-sudo.conf` drop-in for service
- [x] Bans display with full details (IP, scenario, country, ASN, duration)

### WAF Graduated Response (Phase 3 Enhancement)
- [x] Implemented progressive threat response:
  - First detection → Warning page (not block)
  - 3 attempts → Auto-ban via CrowdSec
- [x] Beautiful SecuBox-themed alert page
- [x] Counter shows "Warnings: X / 3"
- [x] License/legal notice included
- [x] Created GitHub Issue #37
- [x] Saved addon to `packages/secubox-waf/config/mitmproxy-addon.py`

### Commits
- `271f4d4` fix(crowdsec,waf): Fix dashboard API data and display
- [x] All cards now show real data

### Known Issues (External - Cannot Fix)
- CrowdSec Central API: 403 Forbidden (IP 82.67.100.75 blocked by CrowdSec)
- Hub Update: 403 from cdn-hub.crowdsec.net (same IP blocking)
- These require contacting CrowdSec support or waiting for IP unblock

---

## ✅ Session 102: CMSD-1.0 License + WAF Phase 2 + Gitea

### License Integration
- [x] Created `LICENCE-CMSD-1.0.md` (French, authoritative)
- [x] Created `LICENSE-CMSD-1.0.en.md` (English, informative)
- [x] Created `LICENSING.md` (documentation & SPDX guidance)
- [x] Updated `README.md` with prominent license notice
- [x] Wiki pages: License.md, License-FR.md with QR codes
- [x] GitHub issues: #35 (migration), #36 (license)

### WAF Phase 2 Complete
- [x] All 330 backends routed through mitmproxy_inspector
- [x] HAProxy `http-request set-uri` for proxy-style requests
- [x] All traffic inspected: X-SecuBox-WAF header added
- [x] Tested: gandalf, pix, gitea, nextcloud - all via WAF

### Gitea Configuration
- [x] Fixed permissions (`/var/lib/gitea` → gitea:gitea)
- [x] Updated domain: gitea.gk2.secubox.in
- [x] Updated ROOT_URL: https://gitea.gk2.secubox.in/
- [x] Gitea fully operational through WAF

### WebUI LAN Access
- [x] Added HAProxy frontend for 192.168.255.1:9443
- [x] Added HAProxy bind for 192.168.1.200:9443
- [x] Created webui_direct backend (bypasses WAF for admin)
- [x] WebUI accessible at https://192.168.1.200:9443/

---

## ✅ Released v2.4.0 — Source Package Sync

---

## 🔄 Previous — Session 101: MOCHAbin Migration COMPLETE

### ✅ Fait cette session

1. **Metablogizer migration complète**
   - Config TOML: `.claude/configs/metablogizer.toml` (151 sites)
   - Déployée: `/etc/secubox/metablogizer/config.toml`
   - 59 sites publiés synchronisés avec HAProxy backends
   - API: 165 sites total, 59 publiés
   - Sites internet OK (gandalf.maegia.tv, etc.)

2. **Streamlit migration complète**
   - Container LXC: `/data/lxc/streamlit` (mSSD), symlink `/var/lib/lxc/streamlit`
   - IP: 10.100.0.50 (br-lxc)
   - Config TOML déployée: `/etc/secubox/streamlit.toml` (35 apps, 29 instances)
   - 22+ instances running dans LXC
   - HAProxy backends configurés pour tous les domaines emancipated
   - WebUI: container status = running, 29 instances configurées
   - Accès internet: https://pix.gk2.secubox.in/, etc.

3. **Configs TOML sauvegardées**
   - `.claude/configs/metablogizer.toml`
   - `.claude/configs/streamlit.toml`

### ✅ Corrections API appliquées
- NoNewPrivileges=false pour permettre sudo lxc-*
- Sudoers: secubox peut exécuter lxc-info, lxc-attach, streamlitctl
- API utilise sudo pour les commandes LXC

---

## 📋 Guidelines de développement (Session 101)

### Confinement LXC obligatoire
Tous les services apportés par les modules SecuBox doivent être confinés dans des conteneurs LXC:
- Chaque module a son propre LXC (`/data/lxc/<module>`)
- Symlink vers `/var/lib/lxc/<module>` pour compatibilité lxc-*
- Le module expose des ports IP vers le nginx/HAProxy du système hôte
- Exemple: streamlit LXC expose ports 8501-8599, HAProxy route les vhosts

### Pattern xxxctl
Chaque module doit avoir un outil CLI `<module>ctl`:
- `streamlitctl` - gestion container, apps, instances
- `metablogizerctl` - gestion sites, publish, sync
- Format de sortie JSON pour intégration API
- Commandes: install, start, stop, status, list, etc.

### Bundle system (à implémenter)
Pour archivage, backup, mesh publish, migration:
- Chaque service exportable en bundle autonome
- Inclut: content, config, requirements, vhost, cert

---

### ⬜ À faire — Bundle system

Voir section détaillée ci-dessous.

---

## 📦 Plan: Bundle System pour archivage/distribution

Structure cible:
```
/srv/secubox/bundles/<service>/<name>/
├── content/        # Fichiers
├── config.toml     # Config
├── requirements.txt
├── vhost.conf
├── cert/           # SSL si emancipated
└── manifest.json   # Version, checksums
```

Objectifs: archivage, backup, mesh publish, migration simplifiée.

---

## 🔄 Previous — MOCHAbin Full Migration (HAProxy/WAF/Services)

### Status (Session 99-100)
**Export COMPLETE** - Archive ready at `/tmp/c3box-migration-20260506.tar.gz`

✅ Step 1 Complete: Export from C3BOX
- 93 SSL certificates exported
- 99 nginx secubox.d configs exported
- HAProxy config exported
- 4 LXC container configs exported (gitea, mail, matrix, nextcloud)
- Services content exported (metablogizer/streamlit dirs empty on source)

⬜ Step 2: MOCHAbin network setup (MOCHAbin currently unreachable at 192.168.255.10)
⬜ Step 3: Import migration archive
⬜ Step 4: Run `haproxyctl migrate`
⬜ Step 5-8: LXC, WAF, verification

**To continue when MOCHAbin is online:**
```bash
# Transfer archive
scp /tmp/c3box-migration-20260506.tar.gz root@192.168.255.10:/tmp/

# On MOCHAbin
tar xzf /tmp/c3box-migration-20260506.tar.gz -C /tmp/
cp -a /tmp/c3box-export/secrets/certs/* /data/haproxy/certs/
haproxyctl generate
systemctl reload haproxy
```

### Context
Previous attempt (Session 97) failed due to incomplete HAProxy migration:
- Only 5 ACLs created instead of all 93 domains
- Default backend incorrectly set to WebUI (nginx_vhosts) instead of 503 error page
- WAF (mitmproxy) not functional due to OpenSSL compatibility
- Websites not accessible from internet
- User reverted to old C3BOX

### Root Cause Analysis
1. **Manual HAProxy config** instead of using `haproxyctl migrate` command
2. **Missing full export** - should use `scripts/migration-export.sh` first
3. **Incorrect default backend** - should be `http-request deny deny_status 503`
4. **WAF not integrated** - mitmproxy needs to be installed in LXC container

### Proper Migration Procedure

#### Step 1: Export from Old C3BOX (OpenWrt)
```bash
# From dev machine, export FULL configuration including all services
bash scripts/migration-export.sh \
  -h 192.168.255.1 \
  -i ~/.ssh/secubox-openwrt \
  -m haproxy,certs,nginx,vhosts,services,content,databases \
  -o /tmp/c3box-migration.tar.gz

# Services module exports (from /srv/):
# - streamlit/apps     → All Streamlit applications
# - metablogizer       → Tor hidden service blogs + configs
# - gitea              → Git repositories + app.ini
# - nextcloud          → User files + config
# - matrix             → Synapse data
# - mitmproxy          → WAF routes and config
# - haproxy            → Certs + config
```

#### Step 2: Network Setup on MOCHAbin
```yaml
# /etc/netplan/01-secubox-gateway.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth2:  # WAN (copper, DMZ)
      addresses:
        - 192.168.1.200/24
      routes:
        - to: default
          via: 192.168.1.254
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
    lan0:  # LAN (DSA port)
      addresses:
        - 192.168.255.1/24
  bridges:
    br-lxc:  # LXC container network
      interfaces: []
      addresses:
        - 10.100.0.1/24
```

#### Step 3: Import Migration Archive
```bash
# On MOCHAbin - import ALL modules
bash scripts/migration-import.sh \
  -f /tmp/c3box-migration.tar.gz \
  -m haproxy,certs,nginx,vhosts,services,content,databases

# This imports:
# - /srv/streamlit/apps → Streamlit applications
# - /srv/metablogizer   → Metablogizer data + Tor configs
# - /srv/gitea          → Git repositories
# - All other services from export
```

#### Step 4: HAProxy Migration with haproxyctl
```bash
# Use the built-in migration command
haproxyctl migrate 192.168.255.1

# This will:
# 1. Sync certificates from /srv/haproxy/certs/
# 2. Convert UCI vhosts/backends to TOML
# 3. Generate haproxy.cfg with proper 503 fallback
# 4. Validate configuration
```

#### Step 5: Verify HAProxy Configuration
```bash
# Check generated config
cat /etc/haproxy/haproxy.cfg

# Should have:
# - All ACLs for domains
# - WAF inspector backend (if waf_enabled=true)
# - Fallback backend with deny_status 503

# Validate
haproxy -c -f /etc/haproxy/haproxy.cfg

# Reload
systemctl reload haproxy
```

#### Step 6: WAF Setup (mitmproxy in LXC)
```bash
# Install mitmproxy container
mitmproxyctl install

# Start WAF
mitmproxyctl start

# Sync HAProxy routes
curl -X POST http://unix:/run/secubox/haproxy.sock/waf/sync-routes

# Enable WAF globally
curl -X POST http://unix:/run/secubox/haproxy.sock/waf/toggle -d '{"enabled":true}'
```

#### Step 7: LXC Containers + Native Services
```bash
# Start LXC containers
lxc-start -n mail
lxc-start -n nextcloud
lxc-start -n gitea
lxc-start -n matrix

# Configure DNAT in nftables
nft add rule inet nat prerouting ip protocol tcp tcp dport { 25, 465, 587, 993, 995 } dnat ip to 10.100.0.10
nft add rule inet nat prerouting ip protocol tcp tcp dport 2222 dnat ip to 10.100.0.40:22

# Start native services (metablogizer + streamlit)
systemctl enable --now secubox-metablogizer
systemctl enable --now secubox-streamlit

# Verify Metablogizer (Tor hidden service blogs)
metablogizerctl status
# Check /srv/metablogizer for blog data

# Verify Streamlit apps
streamlitctl list
# Apps should be at /srv/streamlit/apps/
```

#### Step 8: Verification Checklist
- [ ] All 93 SSL domains route correctly
- [ ] Default backend returns 503 (not WebUI)
- [ ] WAF inspection working
- [ ] Mail container accessible on SMTP/IMAP ports
- [ ] Gitea accessible on port 2222
- [ ] NextCloud accessible
- [ ] WebUI on port 9443 only
- [ ] **Metablogizer**: Tor hidden services running, blogs accessible
- [ ] **Streamlit**: Apps deployed and accessible via HAProxy

### Key Files
| File | Purpose |
|------|---------|
| `/etc/secubox/haproxy.toml` | HAProxy TOML config with vhosts/backends |
| `/etc/haproxy/haproxy.cfg` | Generated HAProxy config |
| `/srv/haproxy/certs/` | SSL certificates |
| `/etc/nftables.conf` | Firewall with DNAT rules |
| `/var/lib/secubox/haproxy/vhost-routes.json` | WAF routing table |
| `/srv/metablogizer/` | Metablogizer blogs + Tor hidden service configs |
| `/srv/streamlit/apps/` | Streamlit applications |

### Error Page Requirement
The default backend MUST return 503:
```haproxy
backend fallback
    mode http
    http-request deny deny_status 503
```
NOT:
```haproxy
# WRONG - do not use WebUI as fallback
default_backend nginx_vhosts
```

---

## ✅ Complété (Session 90) — Mitmproxy WAF Module Migration

**Goal:** Migrate mitmproxy WAF from OpenWrt to SecuBox-DEB

**Approach (Subagent-Driven Development):**
1. Created design spec and 15-task implementation plan
2. Executed each task with fresh subagent + two-stage review
3. Final code review identified 3 issues, all fixed

**Components Delivered:**
- `secubox-mitmproxy` Debian package (complete)
- mitmproxyctl CLI for LXC container management
- FastAPI backend with 5 routers (25+ endpoints)
- secubox_waf.py mitmproxy addon (90+ patterns, 14 categories)
- WebUI dashboard (status, settings, filters)
- CrowdSec integration for auto-banning
- HAProxy route sync for traffic inspection

**Files Created:**
- `packages/secubox-mitmproxy/` — 25+ files

**Result:**
- Package ready for build and deployment
- 17 commits on master branch

---

## ✅ Complété (Session 85) — VirtualBox VM Network Detection Fix

### VM Network Fix ✅

**Problem:** VBox VMs with NAT + host-only interfaces had broken host-only access due to bridge configuration.

**Root Cause:**
- `secubox-net-detect` put host-only interface (enp0s8) into br-lan bridge with static 192.168.1.1/24
- Should get DHCP from VBox host-only network (192.168.56.x)

**Fix:**
- Separate `x64-vm)` case from `x64-baremetal)` in `get_interface_config()`
- VMs set `profile="vm"` which forces `mode="single"` (no bridge)
- `generate_netplan()` detects `board="x64-vm"` and configures ALL interfaces with DHCP

**Files Modified:**
- `image/sbin/secubox-net-detect` — VM-specific handling

**Result:**
- VM visible at 192.168.56.110 (host-only DHCP working)
- SSH service issue separate from network fix (pending investigation)

---

## ✅ Complété (Session 84) — AMD64 Real Hardware Network Fix

### x64-live Netplan Fix for Bare Metal ✅

**Problem:** IP assignment failure on real AMD64 hardware due to broken netplan wildcard syntax.

**Root Cause:**
- `wan0:` with `match: name: "e*"` but no `set-name:` directive
- Multiple interfaces matching `e*` caused conflicts
- No fallback when primary pattern failed

**Files Modified:**
- `board/x64-live/netplan/00-secubox.yaml` — Proper bootstrap config
- `image/sbin/secubox-net-detect` — Enhanced detection for real hardware

**Files Created:**
- `image/sbin/secubox-net-reset` — Utility to force network re-detection

**Solution Architecture:**
```
Boot → Bootstrap netplan (DHCP on all en*/eth*) → Network up
    → secubox-net-detect.service runs once
    → Detects WAN (first with link) / LAN (remaining)
    → Generates proper netplan with explicit interface names
    → Applies config → Network reconfigured
```

**Testing on real AMD64:**
```bash
secubox-net-reset --status    # Check detection state
secubox-net-reset --apply     # Force immediate re-detection
ip addr show                  # Verify IP assignment
```

---

## ✅ Complété (Session 74) — Migration Data Saver v1.0.0

### OpenWrt → SecuBox-DEB Migration Tools ✅

**Feature:** Export services and content from SecuBox-OpenWrt and restore to SecuBox-DEB targets

**Files Created:**
- `scripts/migration-export.sh` — SSH export from OpenWrt (UCI configs, services, content)
- `scripts/migration-import.sh` — Import to SecuBox-DEB with transformation
- `scripts/migration-transform.py` — UCI → TOML/netplan/nftables/dnsmasq converter

**Files Modified:**
- `scripts/README.md` — Added migration documentation

**Architecture:**
```
SecuBox-OpenWrt → migration-export.sh → archive.tar.gz → migration-import.sh → SecuBox-DEB
                  (SSH + tar)           (manifest.json)   (transform + apply)
```

**Exported Modules:**
| Module | OpenWrt Format | Debian Format |
|--------|----------------|---------------|
| network | UCI /etc/config/network | netplan YAML |
| firewall | UCI /etc/config/firewall | nftables |
| wireguard | /etc/wireguard/*.conf | Direct copy |
| crowdsec | /etc/crowdsec/* | Direct copy |
| dhcp | UCI /etc/config/dhcp | dnsmasq.conf |
| haproxy | /etc/haproxy/* | Direct copy |
| nginx | /etc/nginx/* | Direct copy |
| certs | /etc/letsencrypt/* | Direct copy (secrets) |
| content | /srv/www/* | Direct copy |
| vhosts | UCI /etc/config/vhost | TOML |
| users | auth.toml + SSH keys | Direct copy (secrets) |
| state | /var/lib/secubox/* | Direct copy |

**Transformer Features:**
- UCIParser: Parse OpenWrt UCI format → Python dict
- NetworkTransformer: UCI network → netplan YAML (bridges, static/DHCP)
- FirewallTransformer: UCI firewall → nftables (zones, rules, redirects)
- DHCPTransformer: UCI dhcp → dnsmasq.conf (pools, static hosts, DNS)
- Generic UCI → TOML for other configs

**Security:**
- AES-256 encryption option for archives
- Secrets stored in separate encrypted section
- SHA256 checksums for integrity verification
- Pre-import rollback snapshot (4R pattern)

**Usage:**
```bash
# Export from OpenWrt
bash scripts/migration-export.sh -h 192.168.255.1 -i ~/.ssh/secubox-openwrt -o /tmp/migration.tar.gz

# Preview import (dry-run)
bash scripts/migration-import.sh -f /tmp/migration.tar.gz --dry-run

# Apply migration
bash scripts/migration-import.sh -f /tmp/migration.tar.gz
```

---

## ✅ Complété (Session 73) — Eye Remote Interactive v1.9.0

### Mode-Aware Display System ✅

**Feature:** Multi-mode USB gadget display system for Eye Remote

**Files Modified:**
- `remote-ui/round/fb_dashboard.py` — Added mode detection, TTY terminal, flash progress, auth QR
- `packages/secubox-hub/debian/secubox-hub.service` — Changed to TCP binding (port 8001)
- `packages/secubox-hub/nginx/hub.conf` — Changed to TCP proxy
- `common/nginx/modules.d/hub.conf` — Changed to TCP proxy

**New Features:**
| Mode | Display | Function |
|------|---------|----------|
| TTY | Serial terminal | Real-time U-Boot/console output from /dev/ttyGS0 |
| FLASH | Progress bar | Transfer progress with speed/ETA for eMMC flashing |
| AUTH | QR code | Backup authentication code for FIDO2 security |
| NORMAL | Dashboard | Standard metrics display |
| DEBUG | Dashboard | Network + storage + serial combined |

**TTY Mode Features:**
- SerialTerminal class reading from /dev/ttyGS0 at 115200 baud
- Real-time line buffering with ASCII filtering
- Monospace font rendering adapted to round display
- Automatic mode switching via /etc/secubox/gadget-mode

**Flash Mode Features:**
- FlashProgress class tracking /var/lib/secubox-flash.img transfers
- Progress bar with percentage, speed (MB/s), and ETA
- Status: WAITING/TRANSFERRING/COMPLETE indicators

**Auth Mode Features:**
- AuthState class with QR code generation
- Device ID based on /etc/machine-id
- Backup authentication URL format: secubox-auth://device_id/challenge
- State machine: idle → pending → approved/denied

**Hub Service Fix:**
- Changed from Unix socket to TCP port 8001 for VM compatibility
- Issue documented in FAQ-Troubleshooting.md and GitHub #34

**WebUI Menu Fix:**
- Added public menu endpoint at `/api/v1/hub/public/menu` (no auth required)
- Fixed Pydantic 1.x compatibility: `Optional[HTTPAuthorizationCredentials]` for require_jwt
- Updated sidebar.js to use public menu endpoint
- Resolves "Failed to load menu: Invalid menu data" error on WebUI

---

## ✅ Complété (Session 71) — Eye Remote Display System v2.3.0

### Display State Machine ✅

**Feature:** Complete display visualization system for Pi Zero Eye Remote

**Components:**
- **Splash Screen** (`splash.py`) — Animated phoenix logo for boot/halt/start/reboot states
- **Fallback Manager** (`fallback_manager.py`) — Connection state detection with local metrics radar
- **Touch Analysis** — Noise pattern analyzer, calibration tool, X-stable filter

**Display Modes:**
| Mode | Trigger | Display |
|------|---------|---------|
| BOOT | Service starting | Phoenix logo + "BOOTING" |
| START | Initialization | Phoenix logo + "STARTING" |
| HALT | Shutdown | Phoenix logo + "SHUTTING DOWN" |
| OFFLINE | No connection | Local metrics radar (6 rings) |
| CONNECTING | Probing | Rotating cube animation |
| ONLINE | Connected | Full dashboard with cube + icons |
| COMMUNICATING | Data transfer | Fast rotating cube |

**Radar Visualization:**
- 6 concentric rings: AUTH, WALL, BOOT, MIND, ROOT, MESH
- Balanced metric arcs centered at 12 o'clock
- Rainbow sweep line with trailing fade
- 3D rotating cube with module icons (A, W, B, M, R, X)
- Pulsing glow effects

**Touch Noise Analysis:**
- Pattern: Y-axis oscillation at stable X position (~240-250)
- Solution: Filter events where X delta ≈ 0 and Y changes wildly

**Package Build:**
- ✅ Built 128/128 SecuBox Debian packages
- ✅ ESPRESSObin rebuild with packages slipstreamed

---

## ⬜ Next Up — Eye Remote Recovery Boot System v1.0.0

**Priority:** High
**Reference:** `.claude/PLAN-EYE-REMOTE-RECOVERY.md`

### Overview

Extend Eye Remote Pi Zero W to provide full Marvell board recovery capabilities:
- **kwboot** serial boot protocol for bricked boards
- **XMODEM** file transfer for U-Boot/rescue images
- **mvebu64boot** for Armada 7040/8040 platforms
- **Tow-Boot UEFI** firmware installation
- **Automated recovery workflows**

### Target Boards

| Board | SoC | Boot Tool |
|-------|-----|-----------|
| MOCHAbin | Armada 7040 | mvebu64boot |
| ESPRESSObin v7 | Armada 3720 | kwboot |
| ESPRESSObin Ultra | Armada 3720 | kwboot |

### New Display Modes

| Mode | Description |
|------|-------------|
| RECOVERY | Board recovery with kwboot/XMODEM progress |
| UEFI | Tow-Boot UEFI firmware installation |

### Files to Create

| File | Description |
|------|-------------|
| `remote-ui/round/recovery_controller.py` | Main recovery controller |
| `remote-ui/round/protocols/kwboot.py` | kwboot protocol (boot pattern + XMODEM) |
| `remote-ui/round/protocols/xmodem.py` | XMODEM-CRC file transfer |
| `remote-ui/round/protocols/mvebu64.py` | mvebu64boot for Armada 7K/8K |
| `remote-ui/round/api/recovery_api.py` | WebSocket API for recovery |
| `remote-ui/round/display/recovery_display.py` | Recovery mode display |
| `remote-ui/round/systemd/secubox-eye-recovery.service` | Systemd service |

### Recovery Storage

```
/srv/secubox-recovery/
├── boards/mochabin/       # U-Boot, Tow-Boot, rescue images
├── boards/espressobin-v7/
├── boards/espressobin-ultra/
├── tools/                 # kwboot, mvebu64boot binaries
└── config/                # Board signatures, workflows
```

### Dependencies

- `pyserial>=3.5` — Serial port control
- `crcmod>=1.7` — CRC-16-CCITT for XMODEM

---

## 🔨 En préparation / Élaboration — Smart-Strip USB Module (SBX-STR-01)

**Statut:** Spec ready for fabrication
**Référence:** SBX-STR-01 v1.1
**Date:** 2026-04-27

### Description

Le **Smart-Strip** est l'interface HMI modulaire de SecuBox : 6 indicateurs lumineux RGB (SK6812-MINI-E) + 6 zones tactiles capacitives invisibles. Contrôleur RP2350A avec dual-mode USB-C / I²C auto-détecté.

### Fichiers ajoutés

| Fichier | Description |
|---------|-------------|
| `docs/hardware/smart-strip-v1.1.md` | Fiche technique complète (550 lignes) |
| `docs/hardware/smart-strip/simulator.html` | Simulateur interactif HTML |
| `packages/secubox-smart-strip/firmware/parser.c` | Parser CDC grammaire blanche |
| `packages/secubox-smart-strip/firmware/parser.h` | Header parser |
| `packages/secubox-smart-strip/firmware/ring_buffer.c` | Ring buffer diagnostic |
| `packages/secubox-smart-strip/firmware/ring_buffer.h` | Header ring buffer |
| `packages/secubox-smart-strip/host/secubox_smart_strip.py` | Driver Python (USB/I²C unifié) |
| `packages/secubox-smart-strip/host/smart-strip-mockup.html` | Simulateur (copie) |
| `wiki/Smart-Strip.md` | Page wiki hardware |

### Caractéristiques clés

- **MCU:** Raspberry Pi RP2350A (dual M33 + TrustZone-M)
- **Touch:** Microchip AT42QT2120-XU (12 ch I²C)
- **LEDs:** 6× SK6812-MINI-E (RGB side-emit, 5V)
- **USB:** VID 0x1209 / PID 0x4242, composite HID+CDC
- **I²C:** Adresse 0x42, compatible Qwiic/STEMMA QT
- **ESD:** IEC 61000-4-2 niveau 4

### Mapping fonctionnel (chemin Hamiltonien)

| Index | Icône | Rôle | Charte |
|-------|-------|------|--------|
| 0 | AUTH | VPN / chiffrement | `#C04E24` |
| 1 | WALL | Pare-feu nftables/CrowdSec | `#9A6010` |
| 2 | BOOT | Système / OS | `#803018` |
| 3 | MIND | Charge IA / CPU | `#3D35A0` |
| 4 | ROOT | Privilèges / intégrité | `#0A5840` |
| 5 | MESH | Maillage WireGuard/Tailscale | `#104A88` |

### Prochaines étapes

- [ ] Schéma KiCad v1.1 (validation netlist)
- [ ] Layout PCB 85×15 mm 2-couches
- [ ] Firmware MicroPython proof-of-concept
- [ ] Firmware C/C++ TinyUSB production
- [ ] Premier batch JLCPCB qty 5

### Coûts estimés

| Phase | Coût |
|-------|------|
| Proto JLCPCB qty 100 | ~9,55€/unité |
| Production Eurocircuits CSPN | ~14,50€/unité |
| Tarif public | 39-49€ TTC |

---

## ✅ Complété (Session 65) — Multi-Boot Storage System v2.2.2

### Multi-Architecture Boot System ✅

**Feature:** USB storage that boots ARM64 and AMD64 systems with shared data

**Implementation:**
- Created `image/multiboot/` directory with 3 files
- `build-multiboot.sh` — Creates 16GB+ image with 4 partitions (EFI, ARM64 rootfs, AMD64 rootfs, shared data)
- `build-amd64-rootfs.sh` — Debootstrap AMD64 rootfs with SecuBox packages
- U-Boot boot.scr for ARM64 with USB/MMC detection
- GRUB BOOTX64.EFI for AMD64 UEFI boot
- Shared data partition auto-mounted with bind mounts

**Commits:**
- `5cf69c0` — feat(multiboot): Add multi-architecture boot system with shared data

**Next Steps:**
- Build actual multi-boot image on build host
- Test ARM64 boot from USB
- Test AMD64 UEFI boot
- Deploy to Pi Zero storage

---

## ✅ Complété (Session 65) — Eye Remote USB Boot Fix v2.2.1

### Eye Remote → ESPRESSObin USB Boot ✅

**Problem:** ESPRESSObin would not boot from Eye Remote USB mass storage. Multiple cascading issues:
1. Wrong image on Pi Zero W SD card (had ESPRESSObin image instead of Eye Remote image)
2. Conflicting USB gadget services (`secubox-otg-gadget` vs `secubox-eye-gadget`)
3. Storage.img boot partition was empty (no kernel, initrd, boot.scr)
4. mv88e6xxx driver infinite loop — "Marvell 88E6341 detected" repeating every ~125ms
5. Rootfs corruption on storage.img

**Root Cause (mv88e6xxx loop):** Live USB kernel had mv88e6xxx built-in (not a module), so `modprobe.blacklist` had no effect. The eMMC kernel has mv88e6xxx as a loadable module.

**Fix:**
1. Flashed correct Eye Remote image (v2.2.1) to SD card
2. Disabled conflicting `secubox-otg-gadget.service`
3. Copied kernel, initrd, DTB, boot.scr from eMMC image to storage.img boot partition
4. Copied rootfs from eMMC image to storage.img rootfs partition
5. Updated boot scripts with extended blacklist for future builds

**Files Modified:**
- `board/espressobin-v7/boot-live-usb.cmd` — Added mv88e6085 + initcall_blacklist
- `board/espressobin-v7/boot-usb.cmd` — Same fix
- `board/espressobin-v7/boot.cmd` — Same fix

**Boot Script Change:**
```bash
# Before
modprobe.blacklist=mv88e6xxx,dsa_core

# After
modprobe.blacklist=mv88e6xxx,mv88e6085,dsa_core initcall_blacklist=mv88e6xxx_driver_init
```

**Results:**
- ✅ Eye Remote presents USB mass storage
- ✅ ESPRESSObin boots from USB storage
- ✅ mv88e6xxx driver loads correctly (DSA ports: wan, lan0, lan1)
- ✅ Network operational (192.168.255.x)

---

## ✅ Complété (Session 65) — HAProxy Service Restart Loop Fix

### secubox-haproxy.service Crash Loop ✅

**Problem:** Service restarted every 5 seconds with `NAMESPACE` error:
```
Failed to set up mount namespacing: /run/systemd/unit-root/etc/haproxy: No such file or directory
```

**Root Cause:**
1. `RuntimeDirectory=haproxy` in service file triggers systemd namespace setup
2. Namespace setup expects `/etc/haproxy` to exist
3. HAProxy is `Recommends:` not `Depends:`, so directory may not exist

**Fix:**
1. postinst now creates `/etc/haproxy` directory if not present
2. Removed `RuntimeDirectory=haproxy` from service (HAProxy creates its own)
3. Moved directory creation from import-time to startup event
4. Increased RestartSec 5→30s with StartLimitBurst=5

**Files Modified:**
- `packages/secubox-haproxy/debian/postinst`
- `packages/secubox-haproxy/debian/secubox-haproxy.service`
- `packages/secubox-haproxy/api/main.py`

**Commits:**
- `4321a7c` — fix(haproxy): Prevent service restart loop
- `9f47e54` — fix(haproxy): Create /etc/haproxy and remove RuntimeDirectory=haproxy

**Results:** ✅ Service runs stable (41.8M memory, no restart loop)

---

## ✅ Complété (Session 64) — USB OTG Network Fix v2.1.1

### USB OTG NO-CARRIER Fix ✅

**Problem:** Linux hosts showed NO-CARRIER despite Pi Zero interface being UP.

**Root Cause:** Composite gadget creates `usb0` (RNDIS) and `usb1` (ECM). Linux uses ECM → `usb1`, but scripts configured `usb0` only, causing asymmetric routing.

**Fix:** Configure only `usb1` (ECM) for Linux hosts.

**Files:**
- `secubox-otg-gadget.sh` — Use usb1 instead of usb0
- `gadget-setup.sh` — Same fix for eye-remote variant
- `agent/main.py` — `ensure_usb_network()` prefers usb1
- `agent/network_debug.py` — New debug script

**Results:** ✅ OTG network working (0.3ms), display shows OTG mode

---

## 🔄 En cours — Eye Remote Full Integration v2.0.0

### Feature: Real Metrics + SecuBox WebUI + Multi-SecuBox Support

**Status:** 📋 Design complete, ready for implementation

**Spec:** `docs/superpowers/specs/2026-04-21-eye-remote-integration-design.md`

**GitHub Issue:** #31

#### Components to Implement

1. **secubox-eye-agent** (Eye Remote side)
   - [ ] Multi-SecuBox connection manager
   - [ ] Device token auto-authentication
   - [ ] Metrics bridge to dashboard
   - [ ] WebSocket command handler
   - [ ] Touchless pairing with QR
   - [ ] SSH auto-provisioning
   - [ ] Touch gestures for control

2. **secubox-eye-remote** (SecuBox module)
   - [ ] FastAPI endpoints for device management
   - [ ] Device registry + token manager
   - [ ] Pairing flow with QR generation
   - [ ] WebSocket for bidirectional commands
   - [ ] Serial console bridge (xterm.js)
   - [ ] WebUI management dashboard

3. **secubox-eye-gateway** (Dev tool)
   - [ ] Emulator mode (fake SecuBox API)
   - [ ] Gateway mode (proxy to real hardware)
   - [ ] Fleet mode (multi-SecuBox aggregation)
   - [ ] Metrics profiles (idle/normal/busy/stressed)

#### Key Features
- One Eye Remote → Multiple SecuBoxes
- Touchless pairing via QR code
- Eye Remote as controller (restart services, lockdown, etc.)
- Screenshot capture, OTA updates, serial console
- Device token authentication (no manual login)

#### Implementation Order
1. Phase 1: Eye Remote Agent — basic metrics from single SecuBox
2. Phase 2: SecuBox Module — API + device registry + pairing
3. Phase 3: WebUI — management dashboard
4. Phase 4: Control — bidirectional commands
5. Phase 5: Multi-SecuBox — device manager
6. Phase 6: Gateway — emulator and fleet tool
7. Phase 7: Polish — OTA, serial console, screenshot

---

## ✅ Complété (Session 63) — Framebuffer Dashboard v1.11.0

### S63-02 — Framebuffer Dashboard for Pi Zero W ✅

**Status:** ✅ Complete

#### Problem (v1.10.0)
Chromium browser requires NEON SIMD instructions which are not available on Pi Zero W (ARMv6). Error displayed:
> "The hardware on this system lacks support for NEON SIMD extensions"

#### Solution (v1.11.0)
Created Python framebuffer dashboard that renders directly to `/dev/fb0`:

1. **fb_dashboard.py** — PIL-based renderer
   - 6 circular module rings (AUTH/WALL/BOOT/MIND/ROOT/MESH)
   - Real-time clock and date
   - Hostname and uptime display
   - Animated metrics with realistic drift
   - OTG/WiFi/SIM mode indicator
   - SecuBox branding

2. **secubox-fb-dashboard.service** — systemd service
   - Starts after `hyperpixel2r-init.service`
   - Auto-restart on failure
   - Runs as root for framebuffer access

3. **Build script updated** (v1.11.0)
   - Installs `fb_dashboard.py` to `/usr/local/bin/`
   - Enables framebuffer dashboard service
   - No longer requires X11/Chromium for display

#### Files Created
- `remote-ui/round/fb_dashboard.py` — Framebuffer renderer
- `remote-ui/round/secubox-fb-dashboard.service` — systemd service

#### Test Results
- ✅ Dashboard auto-starts on boot
- ✅ All 3 services active: `pigpiod`, `hyperpixel2r-init`, `secubox-fb-dashboard`
- ✅ 6 module rings animate correctly
- ✅ Clock updates in real-time
- ✅ Simulation mode works (API integration ready)

---

## ✅ Complété (Session 63) — HyperPixel Display Fix v1.10.0

### S63-01 — Fix HyperPixel 2.1 Round Display Not Working ✅

**Status:** ✅ Complete

**Issue:** [GitHub Issue #30](https://github.com/CyberMind-FR/secubox-deb/issues/30)

#### Problem (v1.9.0)
HyperPixel 2.1 Round display was not showing any content despite framebuffer being correctly configured at 480x480. Two root causes identified:

1. **Wrong device tree overlay**: `/boot/firmware/config.txt` was using `dtoverlay=hyperpixel4` (rectangular HyperPixel 4.0) instead of `dtoverlay=hyperpixel2r` (round display)

2. **LCD init script failure**: The `hyperpixel2r-init` script used RPi.GPIO which relies on lgpio on Raspberry Pi OS Bookworm. lgpio throws "GPIO not allocated" errors when DPI overlay is active because the GPIO pins are claimed by the kernel for DPI output.

#### Solution (v1.10.0)

1. **Fixed overlay name**: Changed `dtoverlay=hyperpixel4` → `dtoverlay=hyperpixel2r` in config.txt generation

2. **Replaced RPi.GPIO with pigpio**: Rewrote `hyperpixel2r-init` script to use pigpio library which works correctly with Bookworm. pigpio accesses GPIO via the pigpiod daemon, bypassing lgpio's allocation issues.

3. **Fixed service dependencies**: Updated `hyperpixel2r-init.service` to:
   - Require `pigpiod.service`
   - Start after pigpiod is running
   - Enable both services at boot

4. **Added pigpio packages**: Added `python3-pigpio` and `pigpio` to the package list for QEMU chroot installation

5. **Fixed config.txt settings**:
   - Removed `,disable-i2c` flag from overlay
   - Added `display_default_lcd=1` setting

#### Files Modified
- `remote-ui/round/build-eye-remote-image.sh` — v1.9.0 → v1.10.0
- `remote-ui/round/hyperpixel2r-init` — Rewritten to use pigpio instead of RPi.GPIO
- `remote-ui/round/hyperpixel2r-init.service` — Added pigpiod dependency

#### Working config.txt (verified on hardware)
```
dtoverlay=hyperpixel2r
enable_dpi_lcd=1
display_default_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 55 480 0 15 60 15 0 0 0 60 0 19200000 6
framebuffer_width=480
framebuffer_height=480
dtparam=i2c_arm=on
dtparam=spi=on
dtoverlay=dwc2
```

#### Test Results
- ✅ GPIO pins correctly set to ALT2 (DPI function) after boot
- ✅ pigpiod service starts successfully
- ✅ hyperpixel2r-init script runs without errors
- ✅ ST7701S LCD controller initialized via software SPI
- ✅ Backlight ON (GPIO 19)
- ✅ Display shows framebuffer content (tested with solid colors and stripes)

---

## ✅ Complété (Session 62) — Eye Remote OFFLINE Image Builder

### S62-01 — Fix build-eye-remote-image.sh ✅

**Status:** ✅ Complete

**Issue:** [GitHub Issue #30](https://github.com/CyberMind-FR/secubox-deb/issues/30)

#### Problem (v1.8.0)
The script was incomplete, missing critical components for a working Eye Remote SD image.

#### Solution v1.8.1
Added firstrun script (rc.local) with package installation at first boot.

### S62-02 — OFFLINE Mode (v1.9.0) ✅

**Status:** ✅ Complete

#### Problem
v1.8.1 required internet at first boot to download ~500MB of packages (chromium, nginx, lightdm, etc.). This is not acceptable for field deployment.

#### Solution (v1.9.0 OFFLINE MODE)
Complete rewrite to pre-install all packages via QEMU chroot during image build:

1. ✅ **QEMU ARM emulation** — Uses qemu-user-static to run ARM binaries in chroot
2. ✅ **Image expansion** — Adds 1GB to rootfs for pre-installed packages
3. ✅ **Package pre-installation** — All dependencies installed at build time:
   - chromium-browser, xserver-xorg, xinit, lightdm, openbox
   - nginx, python3-pil, python3-pip, git, i2c-tools
   - fonts-dejavu-core, unclutter, x11-xserver-utils
4. ✅ **User creation in chroot** — secubox user with all groups configured
5. ✅ **All configurations pre-applied:**
   - LightDM autologin
   - Openbox autostart with Chromium kiosk
   - nginx site configuration
   - USB OTG gadget services
6. ✅ **No rc.local/firstrun** — System boots directly into kiosk mode
7. ✅ **GitHub Actions updated** — Added qemu-user-static, increased timeout to 60min

#### Files Modified
- `remote-ui/round/build-eye-remote-image.sh` — v1.8.1 → v1.9.0 (complete rewrite)
- `.github/workflows/build-eye-remote.yml` — Added QEMU deps, VERSION 1.9.0

#### Build Requirements
```bash
# Host system needs:
sudo apt install qemu-user-static binfmt-support parted e2fsprogs
```

#### Build & Test
```bash
# Download Raspberry Pi OS Lite (32-bit armhf)
wget https://downloads.raspberrypi.com/raspios_lite_armhf/images/\
raspios_lite_armhf-2024-11-19/2024-11-19-raspios-bookworm-armhf-lite.img.xz

# Build OFFLINE image
cd remote-ui/round
sudo ./build-eye-remote-image.sh \
    -i /path/to/raspios-lite.img.xz \
    -s "WiFiSSID" -p "WiFiPassword"

# Flash to SD card
sudo dd if=/tmp/secubox-eye-remote-1.9.0.img of=/dev/sdX bs=4M status=progress
```

#### Boot Time Comparison

| Version | First Boot | Requires Internet |
|---------|------------|-------------------|
| v1.8.0 | ~10 min (package download) | Yes |
| v1.8.1 | ~10 min (package download) | Yes |
| v1.9.0 | ~60 sec (ready immediately) | **No** |

---

## ✅ Completed (Session 61) — Eye Remote Documentation & Modes

### S61-01 — README.md Enhancement ✅

**Status:** ✅ Complete

Updated README.md with:
- Eye Remote concept (transformation from clock to remote control)
- 5 USB gadget modes documentation (Normal, Flash, Debug, TTY, Auth)
- ASCII mockups for each mode
- x64/amd64 live boot support
- Architecture diagrams showing USB OTG flow
- Script documentation for secubox-otg-gadget.sh and secubox-hid-keyboard.sh

### S61-02 — WIKI.md Enhancement ✅

**Status:** ✅ Complete

Added to WIKI.md:
- Complete modes documentation with technical details
- Visual mockups for all 5 modes (ASCII art)
- ConfigFS USB gadget configuration examples
- x64 Live Boot section with build instructions
- Quick command reference appendix

### S61-03 — Infographic Prompt File ✅

**Status:** ✅ Complete

Created `INFOGRAPHIC-PROMPT.md` with 7 Claude.ai prompts for:
1. Hero infographic (Eye Remote overview)
2. Mode comparison infographic
3. Quick Start howto
4. Architecture diagram
5. x64 Live Boot platforms
6. Auth Mode (Security Key) infographic
7. Social media banner

#### Files Created/Modified
- `remote-ui/round/README.md` — Enhanced with Eye Remote documentation
- `remote-ui/round/WIKI.md` — Enhanced with modes, mockups, x64 support
- `remote-ui/round/INFOGRAPHIC-PROMPT.md` — New file for image generation

---

## ✅ Completed (Session 60) — EspressoBin eMMC Boot Fixes

### S60-01 — HAProxy Service Restart Loop Fix ✅

**Status:** ✅ Complete

#### Problem
secubox-haproxy.service was failing with NAMESPACE errors:
```
Failed to set up mount namespacing: /run/systemd/unit-root/etc/haproxy: No such file or directory
```

#### Root Cause
`ReadWritePaths=/etc/haproxy /run/haproxy` in service file requires directories to exist for namespace setup, but haproxy is only `Recommends:` not `Depends:`.

#### Fix
Removed sandboxing directives that cause issues when haproxy not installed.

#### Files Modified
- `packages/secubox-haproxy/debian/secubox-haproxy.service`

---

### S60-02 — Network Fallback Script Fix ✅

**Status:** ✅ Complete

#### Problem
secubox-net-fallback was trying DHCP on `lan0`, `lan1` interfaces which are downstream LAN ports where SecuBox provides DHCP (not receives it).

#### Root Cause
Script processed `lan*` interfaces for DHCP, but these are LAN downstream ports on EspressoBin DSA switch.

#### Fix
Added logic to skip `lan*` interfaces and bridged interfaces:
```bash
case "$IFACE" in
    lan*)
        logger -t secubox-net "Skipping LAN interface $IFACE (downstream port)"
        continue
        ;;
esac
```

#### Files Modified
- `image/build-image.sh` — Updated secubox-net-fallback script

---

### S60-03 — Network Configuration Fix ✅

**Status:** ✅ Complete

#### Problem
1. dummy0 had IP 192.168.255.1/24 which conflicted with gateway
2. IP was assigned to eth0 (CPU port) instead of wan (physical DSA port)

#### Root Cause
- dummy0 IP overlapped with upstream gateway IP
- EspressoBin DSA topology: eth0 is CPU port, wan/lan0/lan1 are physical ports

#### Fix
- Changed dummy0 to use 10.55.255.1/24 (non-conflicting)
- Updated all board netplan configs to include dummy0
- Fixed IP assignment to wan interface instead of eth0

#### Files Modified
- `board/espressobin-v7/netplan/00-secubox.yaml`
- `board/espressobin-ultra/netplan/00-secubox.yaml`
- `board/mochabin/netplan/00-secubox.yaml`

---

### S60-04 — EspressoBin V7 Device Mapping Notes

**Important for future reference:**
- **U-Boot**: eMMC is `mmc 1`, SD card is `mmc 0`
- **Linux**: eMMC is `/dev/mmcblk0`, detected by presence of `boot0` partition
- **DSA Switch**: eth0 is CPU port (master), wan/lan0/lan1 are physical ports (slaves)
- **Network**: Assign IPs to `wan` interface, not `eth0`

---

## ✅ Completed (Session 59) — v1.7.0 Image Builds & Fixes

### S59-01 — EspressoBin Live USB with eMMC Flasher ✅

**Status:** ✅ Complete

#### Changes
- Built EspressoBin V7 live USB image with embedded eMMC flasher
- Fixed SquashFS path issue (`/filesystem.squashfs` → `/live/filesystem.squashfs`)
- Fixed boot partition sizing for embedded images (dynamic sizing based on embed size)
- Successfully booted live USB and flashed to eMMC on real hardware
- Added `secubox-flash-emmc` command for easy eMMC flashing

#### Files Modified
- `image/build-ebin-live-usb.sh` — Dynamic boot partition sizing, fixed SquashFS copy path
- `board/espressobin-v7/boot-live-usb.cmd` — Boot script for live USB

---

### S59-02 — Slipstream Packages by Default ✅

**Status:** ✅ Complete

#### Changes
- Changed `SLIPSTREAM_DEBS` default from 0 to 1 in `build-image.sh`
- All images now include 126 SecuBox packages by default
- Rebuilding EspressoBin eMMC image with full package set (in progress)

#### Files Modified
- `image/build-image.sh` — Default SLIPSTREAM_DEBS=1

---

### S59-03 — VirtualBox AMD64 Image Test ✅

**Status:** ✅ Working (console mode)

#### Notes
- AMD64 live USB boots in VirtualBox with bridged networking
- All 30+ SecuBox services start successfully
- Kiosk mode doesn't launch (expected - VirtualBox graphics drivers)
- Console mode works, Web UI accessible via port forwarding

---

### S59-04 — VBox Kiosk/WebUI Fix 🔄

**Status:** 🔄 In Progress (v1.6.7.14)

#### Issue
- Kiosk (Chromium) didn't launch in VirtualBox
- Root cause: VirtualBox VMSVGA controller needs `vmware` X11 driver, not `modesetting`
- The `systemd-detect-virt` returns "oracle" but lspci shows "VMware SVGA"

#### Fix Applied
1. Created `secubox-x11-setup.service` — runs before kiosk, auto-detects VM and configures X11 driver
2. Updated `build-live-usb.sh`:
   - Install `xserver-xorg-video-vmware` for VMSVGA support
   - Create `/usr/local/bin/secubox-x11-setup` for boot-time detection
   - Enable `secubox-x11-setup.service` in multi-user.target
3. Updated `secubox-kiosk.service`:
   - Added dependency: `After=secubox-x11-setup.service`
4. Updated `secubox-kiosk-launcher` (v3.3):
   - Defers to X11 setup service if config exists
   - VirtualBox + VMSVGA → `vmware` driver
   - VirtualBox + VBoxVGA → `modesetting` driver

#### Driver Selection Logic
| VM Type | GPU in lspci | X11 Driver |
|---------|--------------|------------|
| VirtualBox (oracle) | VMware SVGA | vmware |
| VirtualBox (oracle) | VBox VGA | modesetting |
| VMware | * | vmware |
| KVM/QEMU | * | modesetting |
| Bare metal | Intel/AMD/NVIDIA | modesetting |

#### Files Modified
- `image/build-live-usb.sh` — X11 auto-setup service
- `image/sbin/secubox-kiosk-launcher` — v3.3, vmware driver for VBox VMSVGA
- `image/systemd/secubox-kiosk.service` — depends on x11-setup service

#### Testing
- Rebuilding AMD64 live USB (in progress)
- Will test in VirtualBox with VMSVGA controller

---

### S59-05 — Remote UI / HyperPixel 2.1 Round Dashboard ✅

**Status:** ✅ Complete

#### Summary
Complete implementation of the SecuBox Remote UI — Round Edition dashboard for HyperPixel 2.1 Round Touch (480×480 px) on RPi Zero W. Provides real-time metrics visualization via concentric rings UI.

#### Deliverables (10/10)
1. ✅ **Backend metrics** — `packages/secubox-system/core/metrics.py` (no psutil, /proc only)
2. ✅ **Alerts engine** — `packages/secubox-system/core/alerts.py` (configurable thresholds)
3. ✅ **Pydantic schemas** — `packages/secubox-system/models/system.py` (AlertLevel, AlertItem, etc.)
4. ✅ **FastAPI router** — `packages/secubox-system/api/routers/metrics.py` (5 endpoints)
5. ✅ **Frontend dashboard** — `remote-ui/round/index.html` (480×480 SVG rings)
6. ✅ **Installation script** — `remote-ui/round/install_zerow.sh` (safe SD flash)
7. ✅ **Deployment script** — `remote-ui/round/deploy.sh` (SSH + nginx patch)
8. ✅ **systemd service** — `remote-ui/round/secubox-remote-ui.service` (memory limited)
9. ✅ **API integration** — Already in `api/main.py` (metrics router included)
10. ✅ **Documentation** — `[remote_ui]` section in `secubox.conf.example`

#### Key Features
- Lightweight metrics collection via /proc filesystem (no psutil overhead)
- 6-ring concentric display: AUTH → WALL → BOOT → MIND → ROOT → MESH
- Central CPU percentage with color-coded alerts (nominal/warn/crit)
- JWT authentication with scope-based access control
- Simulation mode for offline testing
- Safe install script (refuses /dev/sda, /dev/nvme0n1, /dev/mmcblk0)

#### Files Created/Modified
- `packages/secubox-system/core/metrics.py` — SystemMetrics class
- `packages/secubox-system/core/alerts.py` — AlertsEngine class
- `packages/secubox-system/models/system.py` — Pydantic response models
- `packages/secubox-system/models/__init__.py` — Exports
- `packages/secubox-system/api/routers/metrics.py` — 5 FastAPI endpoints
- `packages/secubox-system/api/routers/__init__.py` — Router exports
- `remote-ui/round/index.html` — Full circular dashboard
- `remote-ui/round/install_zerow.sh` — SD card flash script
- `remote-ui/round/deploy.sh` — SSH deployment script
- `remote-ui/round/secubox-remote-ui.service` — systemd unit
- `secubox.conf.example` — Added [remote_ui] section with thresholds config

---

### S59-06 — Remote UI OTG Composite Connection ✅

**Status:** ✅ Complete

#### Summary
Implemented USB OTG composite gadget connection between RPi Zero W (Remote UI) and SecuBox host. Provides CDC-ECM (Ethernet over USB @ 10.55.0.0/30) plus CDC-ACM (serial console @ 115200 baud) with automatic WiFi fallback.

#### Deliverables

**Gadget Side (RPi Zero W):**
1. ✅ `remote-ui/round/secubox-otg-gadget.sh` — configfs libcomposite setup script
2. ✅ `remote-ui/round/secubox-otg-gadget.service` — systemd oneshot (loads libcomposite, usb_f_ecm, usb_f_acm)
3. ✅ `remote-ui/round/secubox-serial-console.service` — Getty on /dev/ttyGS0 @ 115200

**Host Side (SecuBox):**
4. ✅ `remote-ui/round/90-secubox-otg.rules` — udev rules (renames interface to secubox-round, creates /dev/secubox-console symlink)
5. ✅ `remote-ui/round/secubox-otg-host-up.sh` — udev hook (configures 10.55.0.1/30, notifies API)

**Backend API:**
6. ✅ `packages/secubox-system/models/system.py` — TransportType enum, RemoteUIConnectedRequest, RemoteUIStatusResponse
7. ✅ `packages/secubox-system/core/remote_ui.py` — RemoteUIManager singleton with probe/failover logic
8. ✅ `packages/secubox-system/api/routers/remote_ui.py` — REST endpoints (/status, /connected, /disconnected, /probe, /serial/info)

**Frontend:**
9. ✅ `remote-ui/round/index.html` — TransportManager class with OTG/WiFi failover, transport badge UI

**Documentation:**
10. ✅ `remote-ui/round/README.md` — Quick-start guide
11. ✅ `remote-ui/round/WIKI.md` — Comprehensive technical documentation

#### Key Features
- **Deterministic MAC addresses** from RPi serial number (02:sb:xx:xx:xx:xx)
- **OTG priority transport** with 3-timeout failover to WiFi
- **Separate JWT tokens** per transport
- **30-second reprobe** interval to resume OTG when reconnected
- **Transport badge** visual indicator (green OTG / blue WiFi / gray SIM)

#### Files Created/Modified
- `remote-ui/round/secubox-otg-gadget.sh` (new)
- `remote-ui/round/secubox-otg-gadget.service` (new)
- `remote-ui/round/secubox-serial-console.service` (new)
- `remote-ui/round/90-secubox-otg.rules` (new)
- `remote-ui/round/secubox-otg-host-up.sh` (new)
- `packages/secubox-system/models/system.py` (updated)
- `packages/secubox-system/models/__init__.py` (updated)
- `packages/secubox-system/core/remote_ui.py` (new)
- `packages/secubox-system/api/routers/remote_ui.py` (new)
- `packages/secubox-system/api/routers/__init__.py` (updated)
- `packages/secubox-system/api/main.py` (updated)
- `remote-ui/round/index.html` (updated - TransportManager)
- `remote-ui/round/README.md` (new)
- `remote-ui/round/WIKI.md` (new)
- `secubox.conf.example` (updated - [remote_ui] section)

---

### S59-07 — Remote UI RPi Zero W + HyperPixel Debugging ✅

**Status:** ✅ Complete (April 15, 2026)

#### Issues Discovered & Fixed

1. **Wrong RPi image (64-bit)** — Zero W requires 32-bit armhf, not arm64
   - Correct URL: `https://downloads.raspberrypi.com/raspios_lite_armhf/images/raspios_lite_armhf-2024-11-19/2024-11-19-raspios-bookworm-armhf-lite.img.xz`

2. **HyperPixel black screen — KMS overlay is the solution!**
   - Non-KMS overlay (hyperpixel2r) has GPIO conflicts on Bookworm
   - The non-KMS overlay's i2c@0 claims GPIO 10,11 which are needed for SPI init
   - The backlight driver also has pinctrl conflicts with SPI/I2C
   - **SOLUTION:** Use KMS overlay (`vc4-kms-v3d` + `vc4-kms-dpi-hyperpixel2r`)
   - KMS handles panel init in kernel — no userspace script needed
   - Config.txt:
     ```
     dtoverlay=vc4-kms-v3d
     dtoverlay=vc4-kms-dpi-hyperpixel2r
     display_auto_detect=0
     hdmi_blanking=2
     gpu_mem=128
     ```

3. **USB OTG network NO-CARRIER**
   - NetworkManager ignores ifupdown config on Bookworm
   - Fix: Created `usb0-up.sh` script that directly configures the interface
   - Service: `usb0-up.service` runs after `secubox-otg-gadget.service`

4. **SSH Permission denied**
   - RPi OS Bookworm requires `userconf` file in boot partition
   - Format: `user:hashed_password`
   - Default: `pi:raspberry` (hash in install script)

5. **install_zerow.sh refusing mmcblk0**
   - Script's FORBIDDEN_DEVICES check too conservative
   - Fix: Smart detection based on actual root filesystem location

6. **Host IP keeps disappearing**
   - NetworkManager removes manually added IPs on USB interfaces
   - Fix: `sudo nmcli device set enxXXXX managed no` before adding IP

#### Files Modified
- `remote-ui/round/install_zerow.sh` — Use KMS overlay by default, all fixes integrated
- `remote-ui/round/README.md` — Updated troubleshooting for KMS overlay
- `remote-ui/round/secubox_dashboard.py` — **NEW** Python/PIL dashboard (no Chromium!)

#### Testing Status
- [x] SD card flashing works
- [x] USB OTG interface appears on host
- [x] SSH connection works (pi:raspberry via userconf)
- [x] HyperPixel display works with KMS overlay
- [x] Python dashboard running with live metrics

#### Technical Notes
- Framebuffer is RGB565 (16-bit), not 32-bit BGRA
- KMS overlay provides DRM `/dev/fb0` at 480x480
- Dashboard uses PIL for rendering, direct FB write for display
- No X11, no Chromium = lightweight (~18MB RAM)

---

## ⬜ Next Up

1. **Deploy dashboard to Zero W** — Now that display works
2. **Rebuild EspressoBin eMMC with 126 packages** — In progress
3. **Test VBox kiosk after rebuild** — Verify vmware driver works
4. **Dashboard real data display** — Memory, storage, IPs, versions

---

## ✅ Fait (Session 58) — v1.7.0 Phase 11

### P11-01 — Version Display in Kiosk Header/Footer ✅

**Status:** ✅ Implemented

#### Changes
- Added **footer bar** to dashboard (`index.html`) showing:
  - SecuBox version
  - Boot mode (kiosk/console)
  - Auth mode (ZKP/Standard)
  - System uptime
- Added new API endpoints:
  - `GET /api/v1/hub/boot_mode` — Returns kiosk/console status
  - `GET /api/v1/hub/auth_mode` — Returns ZKP/Standard auth status
- Updated version to **v1.7.0** across:
  - `image/build-live-usb.sh` (SECUBOX_VERSION)
  - `packages/secubox-hub/api/main.py` (FastAPI version)
  - `packages/secubox-hub/www/shared/sidebar.js` (VERSION constant)
  - `packages/secubox-hub/www/index.html` (footer default)

#### Files Modified
- `packages/secubox-hub/www/index.html` — Footer with version/mode display
- `packages/secubox-hub/api/main.py` — boot_mode + auth_mode endpoints
- `packages/secubox-hub/www/shared/sidebar.js` — Version constant
- `image/build-live-usb.sh` — Version bump to 1.7.0

---

### P11-03 — Boot Mode Indicator on Splash ✅

**Status:** ✅ Implemented

#### Changes
- Updated Plymouth theme (`secubox-simple.script`) to show boot mode
- Added `send_plymouth_mode()` function to cmdline-handler
- Sends "KIOSK MODE", "TUI MODE", or "CONSOLE MODE" to Plymouth during boot

#### Files Modified
- `image/plymouth/secubox-simple/secubox-simple.script` — Boot mode display
- `image/sbin/secubox-cmdline-handler` — Plymouth message function

---

### P11-07/P11-08 — Plymouth & GRUB Version Display ✅

**Status:** ✅ Implemented

#### Changes
- Plymouth theme updated to show v1.7.0
- GRUB menu entries already use `${SECUBOX_VERSION}` variable

#### Files Modified
- `image/plymouth/secubox-simple/secubox-simple.script` — Version v1.7.0

---

### P11-09 — Boot Mode Selection Descriptions ✅

**Status:** ✅ Implemented

#### Changes
- Added descriptive echo messages to GRUB menu entries
- Each boot option now shows brief explanation when selected:
  - Console: "Access via SSH or Web UI"
  - Kiosk: "Fullscreen GUI on HDMI/display"
  - TUI: "Text User Interface mode - keyboard navigation"
  - Bridge: "Transparent inline sniffer"
  - Safe Mode: "Basic video driver, no persistence"
  - Install: "WARNING: This will erase the target disk!"
  - To RAM: "Faster operation, USB can be removed after boot"

#### Files Modified
- `image/build-live-usb.sh` — GRUB menu entry descriptions

---

### P11-04 — Auth Mode Feedback on Login Page ✅

**Status:** ✅ Implemented

#### Changes
- Added auth mode indicator to login page showing "Standard" or "ZKP"
- Added version badge at bottom of login form
- Created public API endpoint: `GET /api/v1/hub/public/info`
  - Returns version, auth_mode, name (no auth required)
- Login page fetches and displays auth mode dynamically

#### Files Modified
- `packages/secubox-hub/www/portal/login.html` — Auth mode badge + version
- `packages/secubox-hub/api/main.py` — Public info endpoint

---

### Emoji Icon Fix ✅

**Status:** ✅ Implemented — USB ready for testing

#### Issue
- Icons/emojis in sidebar menus rendering as empty boxes (□)
- Missing emoji font-family CSS declarations

#### Fix Applied
- Added `Noto Color Emoji` as first font in font-family stack
- Wrapped category icons in `.cat-icon` span element with emoji font
- Updated both `sidebar.css` (dark) and `sidebar-light.css` (light) themes
- Added explicit `fonts-noto-color-emoji` installation in build script
- Applied to: `.logo-icon`, `.nav-section-title .cat-icon`, `.nav-item .icon`

#### Files Modified
- `packages/secubox-hub/www/shared/sidebar.css` — Emoji font-family for icons
- `packages/secubox-hub/www/shared/sidebar-light.css` — Same for light theme
- `packages/secubox-hub/www/shared/sidebar.js` — Cat-icon wrapper span
- `image/build-live-usb.sh` — Explicit emoji font installation

#### Build & Flash
- ✅ Image built: `output/secubox-live-amd64-bookworm.img.gz` (1.2G)
- ✅ USB flashed to `/dev/sda` (DataTraveler 3.0, 28.8G)
- ❌ Hardware test revealed service crashes (see below)

---

### Boot Service Crashes — v1.7.0.1 Fix 🔄

**Status:** 🔄 Building with fixes

#### Issues Found (from USB boot test screenshots)

| Service | Error | Root Cause |
|---------|-------|------------|
| `secubox-avatar.service` | `ImportError: email-validator is not installed` | pydantic `EmailStr` requires `email-validator` |
| `secubox-hardening.service` | `OSError: [Errno 30] Read-only file system: /var/lib/secubox/` | Live squashfs is read-only |
| `secubox-jitsi/matrix/mesh.service` | `Failed to locate executable /usr/bin/uvicorn` | pip installs to `/usr/local/bin/` |
| `secubox-haproxy/threats/metrics.service` | `Failed at step NAMESPACE` | Sandboxing on read-only fs |

#### Fixes Applied

1. **Missing email-validator** — Added to pip install:
   ```bash
   pip3 install 'pydantic[email]' email-validator
   ```

2. **Read-only filesystem** — Created systemd tmpfs mount:
   ```ini
   # /etc/systemd/system/var-lib-secubox.mount
   [Mount]
   What=tmpfs
   Where=/var/lib/secubox
   Type=tmpfs
   Options=mode=0755,uid=secubox,gid=secubox,size=100M
   ```

3. **uvicorn PATH mismatch** — Added symlink:
   ```bash
   ln -sf /usr/local/bin/uvicorn /usr/bin/uvicorn
   ```

4. **Network still getting 169.254.x.x** — Fixed grep bug in fallback script:
   ```bash
   # BUG: grep -q produces no output to pipe
   if ip addr show "$IFACE" | grep -q "inet " | grep -v "169.254"; then
   # FIX: Remove -q from first grep
   if ip addr show "$IFACE" | grep "inet " | grep -qv "169.254"; then
   ```

5. **Enhanced emoji font support** — Added:
   - `fonts-symbola`, `fonts-noto-core`, `fonts-noto` packages
   - Symbola as fontconfig fallback
   - @font-face with system emoji fallback in CSS

#### Files Modified
- `image/build-live-usb.sh` — pip packages, symlinks, tmpfs mount unit, fonts

#### Build Status
- 🔄 Rebuilding image with fixes...

---

### ⬜ Next Up (Phase 11)

| ID | Task | Status |
|----|------|--------|
| P11-02 | Auth mode indicator in kiosk UI | ✅ (via P11-01 footer) |
| P11-05 | Auth mode toggle in settings | ⬜ |
| P11-06 | ZKP status in dashboard | ⬜ |

---

## ✅ Terminé (Session 57)

### v1.6.7.14 — Network Auto-Discovery (GitHub Issue #28)

**Status:** ✅ Released

#### Fix Applied
- **LAN auto-discovery** when DHCP fails
- Probes common gateways: `192.168.1.1`, `192.168.0.1`, `192.168.255.1`, `10.0.0.1`...
- If gateway responds → auto-configure IP `.250` on that subnet
- Only falls back to `169.254.1.1` as last resort

#### Files Modified
- `image/build-live-usb.sh` — Enhanced `secubox-net-fallback` script

---

### v1.6.7.13 — VirtualBox Kiosk Fix (GitHub Issue #27) ✅

**Status:** ✅ Closed (semi-fixed)

#### Test Results
- ✅ **Real hardware kiosk** — Works perfectly
- ✅ **VirtualBox WebUI** — Works (https://localhost:9443)
- ❌ **VirtualBox kiosk** — Console only (acceptable limitation)

#### Fix Applied
- **VirtualBox detection** — Use `systemd-detect-virt` ("oracle") instead of lspci
- VBox with VMSVGA was incorrectly detected as VMware

---

### v1.6.7.12 — Lenovo Boot Fix (GitHub Issue #26) ✅

**Status:** ✅ Released and tested

#### Test Results
- ✅ **Kiosk on real hardware** — Works!
- ✅ **Lenovo install test** — PASSED! Error 1962 fix confirmed

#### Fixes
- Fallback EFI bootloader at `/EFI/BOOT/BOOTX64.EFI`
- CI `--slipstream` flag fix
- Wiki updated to use `/releases/latest/` URLs

---

### Builds Completed ✅

| Build | Image | Size |
|-------|-------|------|
| x64 | `secubox-live-amd64-bookworm.img` | 8.0G |
| ARM64 | `secubox-espressobin-v7-live-usb.img` | 539M |

---

### GitHub Issues (Session 57)

| Issue | Title | Status |
|-------|-------|--------|
| #26 | Lenovo Error 1962 boot fix | ✅ Closed |
| #27 | VBox kiosk not starting | ✅ Closed |
| #28 | Network fallback 169.254.1.1 | 📝 Addressed |

---

## ✅ Terminé (Session 56)

### v1.6.7.11 — Kiosk Bug Fixes ✅ (GitHub Issue #24 CLOSED)

**Tested on real hardware: KIOSK LOADING OK ✅**

#### Fixes Applied
1. ✅ **systemd `StartLimitIntervalSec`** — fixed syntax (was `StartLimitInterval`)
2. ✅ **Platform detection message** — shows "bare-metal (native)" instead of "none"
3. ✅ **Lock file cleanup** — PID-based tracking, auto-removes stale locks
4. ✅ **Services masked** — picobrew, voip, zigbee, newsbin (already in build script)

#### Files Modified
- `image/systemd/secubox-kiosk.service` — StartLimitIntervalSec fix
- `image/sbin/secubox-kiosk-launcher` — v3.2 with platform name + PID lock

#### Release
- Git commit: `66ad146`
- Git tag: `v1.6.7.11` pushed to origin
- USB image built and tested successfully

---

## ✅ Terminé (Session 55)

### v1.6.7.10 — KIOSK WORKING ON REAL HARDWARE ✅

**Tested on real hardware (Intel HD Graphics 630):**
- ✅ X.Org started with modesetting driver
- ✅ Chromium launched in fullscreen kiosk mode
- ✅ WebUI loaded and displayed
- ✅ Authentication worked
- ✅ No VT freeze
- ✅ VT switching works (Ctrl+Alt+F1/F7)

**Key fixes that worked:**
- VM vs real hardware GPU detection
- Systemd restart rate limiting (even with syntax warning)
- Longer restart delay (15s)
- Console feedback before X11 start
- Lock file mechanism (though needs cleanup fix)

### v1.6.7.9 — Real Hardware Kiosk Fix (Partial)

#### Fixes Applied
**`image/sbin/secubox-kiosk-launcher`**:
- Removed `pipefail` for graceful degradation
- Added **failure tracking** with 3-attempt limit
- Auto-disables kiosk after 3 failures (prevents boot loop)
- Added real hardware GPU detection (Intel, AMD, NVIDIA, fbdev, vesa)

**`image/build-live-usb.sh`**:
- Added `secubox-ui-manager` and `secubox-ui-health` to masked services

---

## ✅ Terminé (Session 54-55)

### v1.6.7.8 — Kiosk Improvements ❌
- Built and flashed to USB
- Tested on VirtualBox: FAILED (same issues as real HW)
- Tested on real hardware: FAILED (VT freeze)
- **Both environments:** Kiosk not starting at all

### v1.6.7.6 — cmdline-handler Fix for X11 ✅

---

## ✅ Terminé cette session (Session 53)

### v1.6.7.4 — Fix Boot Input Freeze (Critical) ✅

#### Problem
Both VirtualBox AND real hardware frozen at boot:
- No keyboard input working
- No login prompt visible
- No VT switching
- Kiosk not starting

#### Root Cause (ACTUAL)
GRUB Kiosk entry used `systemd.unit=graphical.target` but **no display manager** was installed.
systemd waited forever for graphical.target → getty never started → no input.

#### Fix Applied (v1.6.7.4)
**`image/build-live-usb.sh`** — Removed `systemd.unit=graphical.target` from Kiosk GRUB entry:
```bash
# BROKEN:
linux ... secubox.kiosk=1 systemd.unit=graphical.target

# FIXED:
linux ... secubox.kiosk=1
# (kiosk service is in multi-user.target, not graphical.target)
```

Also applied in v1.6.7.3:
- Reverted getty `Type=idle` to simple service
- Enabled backup TTYs (tty2-6) for emergency access

---

## ✅ Terminé cette session (Session 52)

### VirtualBox Debug Logging ✅

#### Problem
VirtualBox VM boots to console instead of kiosk, while real hardware works fine.
Need diagnostic info to trace X11/graphics issues in VirtualBox.

#### Fix Applied
**`image/sbin/secubox-kiosk-launcher`** — Added comprehensive debug logging:
1. `generate_debug_report()` function creates `/tmp/kiosk-debug-YYYYMMDD-HHMMSS.log`
2. Debug report captures:
   - System info (hostname, kernel, arch)
   - Virtualization detection (systemd-detect-virt, DMI)
   - Graphics hardware (lspci VGA/display)
   - DRM/KMS devices (/dev/dri/)
   - Framebuffer status
   - TTY status
   - Kiosk flag files
   - X11 config and binaries
   - Loaded kernel modules (video-related)
   - Systemd kiosk service status
   - Journal logs
   - Xorg.0.log (when available)
3. VM detection logging at X11 start
4. Enhanced error reporting when Xorg fails:
   - Appends failure details to debug report
   - Logs dmesg graphics entries
   - Captures VT status

#### Debug Report Location
```
/tmp/kiosk-debug-latest.log → symlink to most recent
/tmp/kiosk-debug-YYYYMMDD-HHMMSS.log → timestamped reports
```

#### To Read Debug Info After Failed Boot
1. Login via TTY1 (autologin)
2. Run: `cat /tmp/kiosk-debug-latest.log`
3. Or check journalctl: `journalctl -t secubox-kiosk`

---

## ✅ Terminé cette session (Session 51)

### SecuBox v1.6.7.2 — Advanced Overlay Installer ✅

#### Overview
Transformed SecuBox from a simple live-boot system to a production-grade appliance with:
- Multi-layer overlay architecture for clean separation of system/config/data
- Versioned snapshots for rollback capability
- RAM acceleration for responsive UI
- Factory reset without full reinstall

#### Files Created
1. **`image/partition-overlay.sh`** — GPT partition layout script for overlay mode
2. **`image/sbin/secubox-overlay-init`** — Boot-time overlay filesystem composer
3. **`image/sbin/secubox-snapshot`** — Versioned snapshot manager (create/restore/delete/prune)
4. **`image/sbin/secubox-ramcache`** — RAM cache preload utility for fast UI
5. **`image/sbin/secubox-factory-reset`** — Clean reset without reflashing
6. **`image/initramfs/overlay-hooks`** — Initramfs hooks installer
7. **`image/initramfs/overlay-init-premount`** — Early boot overlay preparation
8. **`image/initramfs/overlay-local-bottom`** — Persistent mount setup

#### Files Modified
- **`image/build-live-usb.sh`** — Added `--overlay` flag, overlay partition layout, initramfs hooks
- **`packages/secubox-hub/api/main.py`** — Version bump to 1.6.7.2
- **`image/sbin/secubox-kiosk-launcher`** — Version bump

#### Overlay Partition Layout (--overlay flag)
```
ESP (512MB)      — UEFI boot
SYSTEM (2GB)     — SquashFS read-only base
CONFIG (512MB)   — Persistent config (/etc/secubox, nginx, systemd)
DATA (2GB)       — Persistent data/logs (/var/lib/secubox, /var/log)
SNAPSHOTS (1GB)  — Versioned config/data backups
SWAP (512MB)     — RAM extension
```

#### GRUB Boot Options Added
- `secubox.persist=no` — RAM-only mode
- `secubox.factory-reset=1` — Factory reset on boot
- `secubox.recovery=1` — Recovery mode

#### Status
- ✅ All scripts created and made executable
- ✅ Build script updated with --overlay option
- ✅ Version bumped to 1.6.7.2
- ⬜ Test overlay mode build pending

---

### Navbar Icons Fix ✅

#### Problem
Sidebar menu items showing small colored squares instead of emoji icons

#### Root Cause
- Noto Color Emoji font installed but not configured in fontconfig
- Chromium not finding emoji glyphs

#### Fix Applied
1. **sidebar.css / sidebar-light.css** — Added emoji font-family to `.nav-item .icon`
2. **design-tokens.css** — Added `--font-emoji` variable
3. **debian/control** — Added `fonts-noto-color-emoji` dependency
4. **build-live-usb.sh** — Added fontconfig setup for Noto Color Emoji
5. **scripts/fix-emoji-fonts.sh** — Quick-fix script for existing VMs

#### To Apply on Running VM
```bash
bash /tmp/fix-emoji-fonts.sh
pkill chromium
```

---

### Kiosk Mode Race Condition Fix ✅

#### Problem
Kiosk mode stopped working since v1.6.7.1 - VM boots to console instead of Chromium kiosk

#### Root Cause
Race condition between two competing kiosk startup mechanisms:
1. `secubox-kiosk.service` (systemd) runs `/usr/sbin/secubox-kiosk-launcher`
2. `.bash_profile` runs `/usr/local/bin/start-kiosk` on tty1 autologin

Both could try to start X11 simultaneously because `start-kiosk` checks for `/tmp/.kiosk-starting` lock file, but `secubox-kiosk-launcher` never created it.

#### Fix Applied
1. **`image/sbin/secubox-kiosk-launcher`** — Added lock file creation at startup
   - Creates `/tmp/.kiosk-starting` before doing anything
   - Checks if lock exists to avoid double-start
   - Uses trap to clean up on exit

2. **`image/build-live-usb.sh`** (start-kiosk script) — Added systemd service checks
   - Checks if `secubox-kiosk.service` is active before starting
   - Checks if service is activating to avoid race
   - Only runs as fallback when systemd service isn't handling it

#### Files Modified
- `image/sbin/secubox-kiosk-launcher` — Lock file mechanism
- `image/build-live-usb.sh` — Updated start-kiosk and .xsession version

---

## ✅ Terminé session précédente (Session 50)

### Auth Login 404 Fix ✅

#### Problem
- Login page showing 404 for `POST /api/v1/hub/auth/login`
- Browser console: `https://localhost/api/v1/hub/auth/login 404 (Not Found)`

#### Root Cause Investigation
1. **Initial suspicion**: nginx not routing to hub socket — **WRONG**
2. **Second suspicion**: secubox-hub service not running — **PARTIALLY RIGHT** (permission error crash loop)
3. **Third suspicion**: Socket permission issue — **FIXED** with `chown secubox:secubox /run/secubox/`
4. **Final root cause**: Double `/auth` prefix — route was `/auth/auth/login` not `/auth/login`

#### Diagnostic Steps
- `systemctl status secubox-hub` → crash loop with PermissionError
- `curl --unix-socket /run/secubox/hub.sock http://localhost/health` → `{"status":"ok"}`
- `curl --unix-socket /run/secubox/hub.sock http://localhost/auth/login` → `{"detail":"Not Found"}`
- OpenAPI inspection revealed route at `/auth/auth/login` (double prefix!)

#### Fix Applied
- **Removed** `prefix="/auth"` from `common/secubox_core/auth.py` router definition
- **Added** `prefix="/auth"` to `app.include_router(auth_router, prefix="/auth")` in `packages/secubox-hub/api/main.py`

#### Files Modified
- `common/secubox_core/auth.py` — removed router prefix
- `packages/secubox-hub/api/main.py` — added prefix on include

#### Commit
- `35c9340` — fix(auth): Remove duplicate /auth prefix from login endpoint

#### Status
- ✅ Image rebuilt with fix
- ✅ USB flashed and tested
- ✅ Login working with root/secubox

---

## ✅ Terminé session précédente (Session 49)

### SecuBox Live v1.6.5 x64 Fixes ✅

#### Problems Fixed
1. **Sandbox warning banner**: `--no-sandbox` flag caused warning at top of screen
2. **No keyboard/mouse input**: X11 wasn't detecting input devices
3. **Plymouth splash**: Re-enabled after v1.6.4 disabled it for boot freeze debugging

#### Fixes Applied
- **Removed** `--no-sandbox` from Chromium flags
- **Added** `--disable-infobars` to hide any remaining info bars
- **Added** X11 InputClass sections for libinput keyboard/pointer/touchpad
- **Added** ServerFlags: `AutoAddDevices=true`, `AllowEmptyInput=false`
- **Restored** `splash` to kernel cmdline in GRUB entries

#### Files Modified
- `image/build-live-usb.sh` — version bump + splash restored
- `image/sbin/secubox-kiosk-launcher` — input devices + Chromium flags
- `image/plymouth/secubox-simple/secubox-simple.script` — version update

#### Commit
- `f8d8bac` — fix(live): v1.6.5 remove sandbox warning, fix input devices, restore splash

#### Status
- ✅ USB flashed with v1.6.5
- ⬜ Test on real hardware pending

---

## ✅ Terminé session précédente (Session 48)

### Plymouth Cube Theme Integration ✅

- **Integrated** secubox-cube theme with 3D rotating module icons
- **Updated** `build-live-usb.sh` and `build-rpi-usb.sh` to use cube theme
- **Assets**: logo, scanlines, progress-bar, 6 module icons (BOOT, AUTH, ROOT, MIND, MESH, WALL)

### Portal Authentication Fix ✅

- **Problem**: admin/secubox login not working (users.json missing)
- **Fix**: Build script now creates `/etc/secubox/users.json` with SHA256 hashed passwords
- **Credentials**: admin/secubox, root/secubox

### secubox-flash-disk Script Fix ✅

- **Problem**: `line 236: local: can only be used in a function`
- **Fix**: Removed `local` keyword from variables outside function scope

### x64-live Netplan Update ✅

- **Added** br-lan/wan structure similar to ARM boards
- **WAN**: DHCP on first interface
- **br-lan**: Static 192.168.1.1/24 for LAN gateway

### Commit
- `3898816` — fix(live): Plymouth cube theme, auth, flash-disk, netplan

### Status
- ✅ Kiosk working on Lenovo hardware (v1.6.1)
- ✅ USB flashed with v1.6.2 fixes
- ⚠️ QEMU test frozen (KVM issue, real hardware OK)

---

## ⬜ Next Up

1. Test full dashboard functionality after login
2. Verify all API endpoints work via authenticated requests
3. Test module status/control from dashboard
4. Verify JWT token persistence across page refreshes

---

## ✅ Terminé session précédente (Session 47)

### Kiosk Service Systemd Enable Fix ✅

#### Problem
- Kiosk service was not starting automatically despite being configured
- User reported "ko pareil" (still not working) after previous fixes
- Root cause: Wrong path in service symlink creation

#### Root Cause Found
The `build-live-usb.sh` script:
- **Copied** service file to: `/etc/systemd/system/secubox-kiosk.service` (line 1412)
- **Checked and symlinked** from: `/usr/lib/systemd/system/secubox-kiosk.service` (line 1567)
- The condition was **never true** because the file doesn't exist at that path

#### Fix Applied
Fixed symlink paths in `image/build-live-usb.sh`:
```bash
# BEFORE (wrong path):
if [[ -f "${ROOTFS}/usr/lib/systemd/system/secubox-kiosk.service" ]]; then
    ln -sf /usr/lib/systemd/system/secubox-kiosk.service ...

# AFTER (correct path):
if [[ -f "${ROOTFS}/etc/systemd/system/secubox-kiosk.service" ]]; then
    ln -sf /etc/systemd/system/secubox-kiosk.service ...
```

#### Verification
- ✅ Rebuilt live USB image
- ✅ Booted in QEMU KVM
- ✅ `secubox-kiosk.service` is **active (running)** and **enabled**
- ✅ Xorg running on VT7 with modesetting driver
- ✅ Chromium in kiosk mode displaying `https://localhost/`

---

## ⬜ Next Up

1. Commit and push the kiosk service fix
2. Flash USB and test on Lenovo hardware
3. Run full integration test suite
4. Prepare release v1.6.2 with all fixes

---

## ✅ Terminé session précédente (Session 46)

### Kiosk "Can't Be Reached" Fix ✅

#### Problem
- Kiosk on real hardware (Lenovo) showed "secubox.local" URL that couldn't be reached
- nginx config was invalid due to missing/broken symlinks in `secubox.d/`

#### Fixes Applied
1. **Kiosk URL** → Changed from `https://localhost/` to `https://127.0.0.1/`
   - Avoids DNS resolution issues on fresh systems
   - File: `image/kiosk/secubox-kiosk.sh`

2. **`/etc/hosts`** → Added `secubox.local` to all build scripts
   - Files: `build-live-usb.sh`, `build-image.sh`, `build-rpi-usb.sh`, `build-installer-iso.sh`

3. **nginx config cleanup** → Aggressive broken symlink removal
   - Uses `find` to remove ALL broken symlinks in `secubox.d/`
   - Creates placeholder `repo.conf` if missing
   - Auto-detects missing configs from nginx error output
   - File: `image/build-live-usb.sh`

#### Commits
- `09526c4` — fix(kiosk): Use IP address and add secubox.local to hosts
- `1ff368c` — fix(build): Add aggressive nginx config cleanup for live image

#### Verified
- ✅ QEMU KVM test passed — kiosk displays dashboard correctly
- ✅ nginx config valid in build log
- ✅ USB flashed and ready for Lenovo hardware test

---

## ✅ Terminé session précédente (Session 45)

### Wiki Cleanup & German Translations ✅

#### Cleanup Completed
- **Removed `docs/wiki/`** — Eliminated duplicate wiki folder
- **Removed old module docs** — Deleted fragmented `Modules.md`, `Modules-FR.md`, `Modules-ZH.md`
- **Consolidated** — Now only `MODULES-*.md` (comprehensive versions) remain

#### German Translations Created (8 new files)
- `wiki/Home-DE.md` — Hauptseite
- `wiki/Installation-DE.md` — Installationsanleitung
- `wiki/Live-USB-DE.md` — Live USB Anleitung
- `wiki/ARM-Installation-DE.md` — ARM U-Boot Installation
- `wiki/ESPRESSObin-DE.md` — ESPRESSObin Guide
- `wiki/Configuration-DE.md` — Konfiguration
- `wiki/Troubleshooting-DE.md` — Fehlerbehebung
- `wiki/API-Reference-DE.md` — API-Referenz

#### Sidebar Updated
- Added German (DE) links to all pages in `wiki/_Sidebar.md`

#### Translation Coverage (Updated)

| Page | EN | FR | ZH | DE |
|------|:--:|:--:|:--:|:--:|
| Home | ✅ | ✅ | ✅ | ✅ |
| Installation | ✅ | ✅ | ✅ | ✅ |
| Live-USB | ✅ | ✅ | ✅ | ✅ |
| ARM-Installation | ✅ | ✅ | ✅ | ✅ |
| ESPRESSObin | ✅ | ✅ | ✅ | ✅ |
| Configuration | ✅ | ✅ | ✅ | ✅ |
| Troubleshooting | ✅ | ✅ | ✅ | ✅ |
| API-Reference | ✅ | ✅ | ✅ | ✅ |
| MODULES | ✅ | ✅ | ✅ | ✅ |
| UI-COMPARISON | ✅ | — | — | — |

**Translation coverage:** EN 100%, FR 100%, ZH 100%, DE 100%

---

## ✅ Also Completed This Session

### Package Rebuild & USB Flash ✅

#### 11 Packages Rebuilt with UI Fixes
- secubox-cloner, secubox-magicmirror, secubox-mmpm
- secubox-ndpid, secubox-ossec, secubox-p2p
- secubox-redroid, secubox-rezapp
- secubox-vault, secubox-vm, secubox-wazuh

#### Live Image Rebuilt
- `output/secubox-live-amd64-bookworm.img.gz` (1.2GB)
- Includes all 11 UI-fixed packages

#### USB Flash Completed
- Target: `/dev/sda` (28.8GB DataTraveler 3.0)
- Written: 8.6GB in ~5.8 minutes
- Partitions verified:
  - sda1: 2M (BIOS boot)
  - sda2: 512M vfat ESP
  - sda3: 5.5G ext4 LIVE
  - sda4: 2G ext4 persistence
- Boot credentials: `root` / `secubox`
- Web UI: `https://<IP>:8443`

### Previous Tasks Completed
1. ~~Fix 13 modules missing sidebar container~~ ✅ Done (11 fixed, 3 excluded)
2. ~~Complete German wiki translations~~ ✅ Done
3. ~~Consolidate module documentation~~ ✅ Done
4. ~~Run integration tests on VM~~ ✅ QEMU tested
5. ~~Rebuild all packages with UI fixes~~ ✅ Done

---

## ✅ Terminé session précédente (Session 44)

### UI Audit & Documentation Review ✅

#### Documentation Status Report
- Created `REPORT-2026-04-10.md` — Comprehensive board/financer report
- **124 modules** complete (100%)
- **147 documentation files** total

#### UI Compliance Audit
- Created `scripts/ui-screenshot-capture.py` — Playwright-based screenshot capture
- Created `scripts/ui-fix-checker.sh` — UI guideline compliance checker

**Results:** 107/120 modules pass UI guidelines

**11 modules fixed (sidebar added):**
- secubox-cloner, secubox-magicmirror, secubox-mmpm
- secubox-ndpid, secubox-ossec, secubox-p2p
- secubox-redroid, secubox-rezapp
- secubox-vault, secubox-vm, secubox-wazuh

**3 modules excluded (intentional - no sidebar):**
- secubox-portal (login.html) — login pages don't need nav
- secubox-system (dev-status-standalone.html) — standalone embed
- secubox-p2p (master-link/index.html) — mesh onboarding wizard

---

## ✅ Terminé session précédente (Session 43)

### Critical Bug Fix: ARM Images Missing Kernel ✅

#### Issue Discovered
- **Problem:** ARM images (ESPRESSObin, MOCHAbin) had empty `/boot` directory
- **Root cause:** `build-image.sh` only installed `linux-image-arm64` for `vm-arm64`, not physical ARM boards
- **Impact:** gzwrite flash succeeded but system couldn't boot (no kernel)

#### Solution
- Modified `image/build-image.sh` to install `linux-image-arm64` for ALL ARM boards
- Added kernel copy: `/boot/vmlinuz-*` → `/boot/Image` (U-Boot format)
- Added DTB copy: `/usr/lib/linux-image-*/marvell/` → `/boot/dtbs/marvell/`
- Generated `extlinux.conf` for distroboot
- Generated `boot.scr` for U-Boot autoboot (requires `mkimage`)

#### Files Modified
- `image/build-image.sh:185-191` — Add linux-image-arm64 for all ARM
- `image/build-image.sh:503-550` — Kernel/DTB copy + bootscript generation

### Wiki ESPRESSObin Pages ✅

#### New Pages Created
- `wiki/ESPRESSObin.md` — Complete U-Boot guide (EN)
- `wiki/ESPRESSObin-FR.md` — French translation
- `wiki/ESPRESSObin-ZH.md` — Chinese translation

#### Content
- Hardware variants table (v5/v7/Ultra)
- eMMC storage limits
- Board layout diagram with UART pinout
- DIP switches boot modes
- 4 flash methods: USB gzwrite, SD gzwrite, TFTP, mmc write
- Automatic boot methods (boot.scr, extlinux.conf, manual)
- DSA switch network interfaces
- Troubleshooting & UART recovery
- Performance comparison ESPRESSObin vs MOCHAbin

### Wiki Translations Complete ✅

#### New Pages
- `wiki/ARM-Installation-FR.md` — French translation
- `wiki/ARM-Installation-ZH.md` — Chinese translation
- `wiki/UI-COMPARISON.md` — Moved from docs/wiki/

#### Sidebar Updated
- Added multilingual links for ARM-Installation (EN/FR/ZH)
- Added multilingual links for ESPRESSObin (EN/FR/ZH)

### Wiki Coverage

| Page | EN | FR | ZH | DE |
|------|:--:|:--:|:--:|:--:|
| Home | ✅ | ✅ | ✅ | — |
| Installation | ✅ | ✅ | ✅ | — |
| Live-USB | ✅ | ✅ | ✅ | — |
| ARM-Installation | ✅ | ✅ | ✅ | — |
| ESPRESSObin | ✅ | ✅ | ✅ | — |
| Modules | ✅ | ✅ | ✅ | ✅ |
| API-Reference | ✅ | ✅ | ✅ | — |
| UI-COMPARISON | ✅ | — | — | — |

**Commits:**
- `1ee6513` docs: Add ESPRESSObin wiki pages (EN/FR)
- `823a84d` fix: Install linux-image-arm64 for all ARM boards
- `43b6231` docs: Complete wiki translations (FR/ZH)

---

## ✅ Terminé session précédente (Session 42)

### Build Script Fixes

#### Live USB Missing Dependencies ✅
- **Issue:** `secubox-install` script in live USB image failed — missing `parted`
- **Root cause:** `build-live-usb.sh` debootstrap didn't include disk tools
- **Solution:** Added `parted`, `dosfstools`, `grub-pc-bin` to INCLUDE_PKGS
- **File:** `image/build-live-usb.sh:147`

#### RPi 400 Missing Dependencies ✅
- **Issue:** Same missing tools in Raspberry Pi image
- **Solution:** Added `parted`, `dosfstools`, `e2fsprogs`, `pciutils`, `usbutils`
- **File:** `image/build-rpi-usb.sh:122`

### Documentation

#### ESPRESSObin v7 Installation Guide ✅
- Created `board/espressobin-v7/README.md`
- Documented U-Boot flash procedure (USB → eMMC via `gzwrite`)
- Includes: boot targets, network interfaces, troubleshooting, serial console settings

#### Wiki ARM Installation Page ✅
- Created `wiki/ARM-Installation.md`
- Complete U-Boot flash guide for all ARM boards
- Covers ESPRESSObin v7/Ultra and MOCHAbin
- Added to wiki sidebar

#### Wiki Modules Update ✅
- Added 73 missing modules to `wiki/MODULES-EN.md`
- **Total documented modules: 119** (was 46)
- New categories: AI, Automation, Communication, Media
- All 124 packages now have wiki documentation

### eMMC Size Compatibility Fix ✅

#### Board-Specific Image Sizes
- **Issue:** Default 4GB/8GB images too large for 4GB eMMC ESPRESSObin boards
- **Solution:** Added `IMG_SIZE` to board configs:
  - ESPRESSObin v7: **3584M** (3.5GB) — fits 4GB eMMC
  - ESPRESSObin Ultra: 4G (8GB eMMC)
  - MOCHAbin: 4G (8GB eMMC + SATA option)

#### CI Workflow Update
- Removed hardcoded `--size 8G` from build-image.yml
- CI now uses board-specific sizes from `board/*/config.mk`

#### Documentation
- Added eMMC storage limits to `wiki/ARM-Installation.md`
- Created `board/mochabin/README.md` with U-Boot guide
- Updated `board/espressobin-v7/README.md` with size table

### Release v1.5.2 ✅
- Tag created and pushed
- CI building images with correct eMMC-compatible sizes
- https://github.com/CyberMind-FR/secubox-deb/releases/tag/v1.5.2

**Commits:**
- `271f27e` fix: Add missing parted/dosfstools deps to live USB image
- `75f0406` fix: Add parted/dosfstools to RPi 400 image
- `81fa1d7` docs: Add ESPRESSObin v7 installation guide
- `b8ab323` docs: Add ARM installation wiki page
- `37c8d75` docs: Add 73 missing modules to wiki
- `41011c5` docs: Add eMMC size limits for ESPRESSObin/MOCHAbin
- `4772fc2` fix: Use board-specific image sizes for eMMC compatibility

---

## ✅ Terminé session précédente (Session 41)

### Phase 9 Modules — 11 New System/Infrastructure Tools ✅

Created 11 new modules via parallel Task agents, all with FastAPI backends, P31 Phosphor light theme frontends, and Debian packaging:

| Module | Description | Size |
|--------|-------------|------|
| **secubox-nettweak** | Network tuning (sysctl, TCP/IP optimization) | 14KB |
| **secubox-ksm** | KSM memory optimization (runs as root) | 10KB |
| **secubox-avatar** | Identity manager (avatar upload, service sync) | 13KB |
| **secubox-admin** | System administration (services, logs, disk, reboot) | 15KB |
| **secubox-metabolizer** | Log processor (pattern detection, trends) | 16KB |
| **secubox-metacatalog** | Service registry (discovery, health, deps) | 15KB |
| **secubox-cyberfeed** | Threat intelligence (12 feeds, nftables export) | 14KB |
| **secubox-mirror** | APT/CDN cache (APT, NPM, PyPI, Docker) | 12KB |
| **secubox-saas-relay** | API proxy (Fernet encryption, rate limiting) | 16KB |
| **secubox-rezapp** | App deployment (Docker/LXC, 8 templates) | 12KB |
| **secubox-picobrew** | Homebrew controller (sensors, fermentation) | 18KB |

All packages built successfully and added to packages/ directory.

**Total SecuBox Packages: 124** (was 93)

---

## ✅ Terminé session précédente (Session 40)

### VirtualBox EFI Boot Fix ✅
- **Issue:** VirtualBox EFI firmware wasn't finding the GRUB bootloader, showing PXE boot instead
- **Root cause:** VirtualBox EFI shell doesn't always auto-detect `/EFI/BOOT/BOOTX64.EFI`
- **Solution:** Added `startup.nsh` script to ESP root for EFI shell auto-boot
- **Files Modified:**
  - `image/build-live-usb.sh` — Added startup.nsh creation after GRUB EFI install

### TUI Mode Boot Fix ✅
- **Issue:** Selecting TUI mode from GRUB menu loaded Kiosk GUI instead
- **Root cause:** Kiosk service started before cmdline handler could disable it
- **Solution:**
  - Use `systemctl mask` to prevent kiosk from starting
  - Kill X11/Chromium if already running
  - Create generator drop-in for correct systemd target
  - Add `Requires=secubox-cmdline.service` to kiosk and TUI services
- **Files Modified:**
  - `image/sbin/secubox-cmdline-handler` — Mask kiosk, kill X11
  - `image/systemd/secubox-kiosk.service` — Require cmdline handler
  - `image/systemd/secubox-console-tui.service` — Require cmdline handler

### CI Workflows — Package Slipstream Fix ✅
- **Issue:** CI-built images didn't include SecuBox packages
- **Root cause:** `build-image.yml` didn't download packages or pass `--slipstream` flag
- **Solution:**
  - Added package download step using `dawidd6/action-download-artifact`
  - Added `--slipstream` flag to build command
  - Updated package count from 33/93 to **124 packages**
- **Files Modified:**
  - `.github/workflows/build-image.yml` — Download packages + slipstream
  - `.github/workflows/build-live-usb.yml` — Remove redundant cache copy
  - `.github/workflows/release.yml` — Update package count

### Wiki Update ✅
- Updated all wiki pages to v1.5.1
- Package count updated from 93 to 124
- Updated Home.md, Home-FR.md, Home-ZH.md, _Sidebar.md

### Release v1.5.1 ✅
- Tag created and pushed
- 248 package build jobs succeeded
- Only `publish` (APT repo) failed due to missing secrets
- **Release assets available:**
  - secubox-live-amd64-bookworm.img.gz (1.1GB)
  - secubox-vm-x64-bookworm.img.gz
  - secubox-mochabin-bookworm.img.gz
  - secubox-espressobin-v7-bookworm.img.gz
  - secubox-espressobin-ultra-bookworm.img.gz
  - secubox-installer-amd64-bookworm.img.gz
  - secubox-installer-amd64-bookworm.iso.gz
  - SHA256SUMS

### v1.5.1 Image Test ✅
- Downloaded from GitHub release
- Verified `startup.nsh` present in ESP partition
- VirtualBox VM boots successfully with UEFI
- Kiosk GUI mode working
- SSH access confirmed
- **URL:** https://github.com/CyberMind-FR/secubox-deb/releases/tag/v1.5.1

### Mode Switching Test ✅
- **Kiosk → TUI:** `secubox-mode tui --now` ✅
- **TUI persists after reboot:** ✅
- **TUI → Kiosk:** `secubox-mode kiosk --now` ✅
- Both modes work correctly with immediate switching
- Modes persist across reboots via marker files

### CI Workflow Chain (Fixed)
```
build-packages.yml → secubox-debs-all (124 packages)
         ↓
build-image.yml    → Downloads + slipstreams
build-live-usb.yml → Downloads + slipstreams
         ↓
release.yml        → All packages + images
```

**Commits:**
- `70961cb` - fix(build): Add startup.nsh for VirtualBox EFI compatibility
- `38841a9` - fix(ci): Include all SecuBox packages in image builds
- `df8c984` - fix(boot): TUI mode now properly overrides kiosk
- `10d09e3` - docs: Update to v1.5.1 with 124 packages (wiki)

---

## ✅ Terminé session précédente (Session 39)

### Boot Banner Improvements — CRT Style with Colors & Emojis ✅
- **`/etc/issue`** — Pre-login banner with ANSI colors (gold/cyan)
  - ASCII art SecuBox logo
  - Default credentials display
  - Web UI and SSH info
- **`/etc/motd`** — Post-login MOTD with colored ASCII art
  - LIVE USB badge in green
  - Access info with color highlights
- **`/usr/bin/secubox-status`** — System status command with CRT colors
  - System info (hostname, uptime, memory, disk)
  - Network interfaces with IP addresses
  - Core services status (nginx, haproxy, crowdsec, etc.)
  - Display mode indicator (kiosk/TUI/console)
  - Quick access links
- **`/usr/sbin/secubox-boot-banner`** — Boot-time banner script
  - Boot progress indicators with checkmarks
  - Network/Nginx/API status at boot

### Profile.d Login Status ✅
- **`/etc/profile.d/secubox-login.sh`** — Login status display
  - Quick status line showing mode, service count, IP
  - Only displays on TTY login (not SSH/tmux)
- **`/usr/bin/secubox-help`** — Quick help command
  - Lists common secubox-* commands by category
  - System, Network, Security, Modes sections
- **`/usr/bin/secubox-logs`** — Live security logs shortcut

### secubox-cmdline-handler Improvements ✅
- **TUI mode fix** — Now properly starts TUI service, not just enables it
- **Console mode** — Enables standard getty on tty1
- **Default mode detection** — Checks for build-time kiosk marker
- **Better logging** — Mode transitions logged to journal

### secubox-mode CRT Styling ✅
- Updated with CRT-style colors (gold, cyan, green, red)
- Emoji status indicators (✓, ✗, ⚠, ●)
- Improved status display with mode details and help text
- Better visual formatting for mode selection

### GRUB Menu Improvements ✅
- **Dynamic default** — Kiosk GUI (entry 1) is default when `--kiosk` flag used
- **Emoji indicators** — All menu entries have relevant emojis:
  - ⚡ SecuBox Live (standard)
  - 🖼️ Kiosk GUI [DEFAULT]
  - 📟 Console TUI
  - 🌉 Bridge Mode
  - 🛡️ Safe Mode
  - 💾 Install to Disk
  - 🚀 To RAM
  - 🔧 HW Check
  - 🚨 Emergency Shell
  - 🐛 Debug modes
- **CRT menu colors** — Cyan on black with yellow highlights

### Files Modified
- `image/build-live-usb.sh` — Banner, profile.d, GRUB config updates
- `image/sbin/secubox-cmdline-handler` — Mode switching improvements
- `image/sbin/secubox-mode` — CRT style colors and emoji status

---

## ✅ Terminé session précédente (Session 38)

### Wiki Documentation — VirtualBox Quick Start ✅
- **wiki/Home.md** — Updated with VirtualBox (2 Minutes) quick start section
- **wiki/Home-FR.md** — French translation of VirtualBox quick start
- **wiki/Home-ZH.md** — Chinese translation of VirtualBox quick start
- **wiki/_Sidebar.md** — Updated with v1.5.0 and improved VirtualBox link
- All pages updated to v1.5.0 with 93 packages count
- Complete VM creation script options documented
- One-liner download commands included

**Commits:**
- `2265d7c` — docs(wiki): Add VirtualBox quick start to all wiki home pages
- `5d8c327` — docs(wiki): Update sidebar with v1.5.0 and VirtualBox link text

---

## ✅ Terminé session précédente (Session 37)

### Phase 10 — Security Extensions COMPLETE (10/10)

**New Modules Created & Built (8):**
- `secubox-ai-insights_1.0.0-1~bookworm1_all.deb` (18KB) — ML threat detection
- `secubox-ipblock_1.0.0-1~bookworm1_all.deb` (15KB) — IP blocklist manager
- `secubox-interceptor_1.0.0-1~bookworm1_all.deb` (15KB) — Traffic interception
- `secubox-cookies_1.0.0-1~bookworm1_all.deb` (16KB) — Cookie tracking/analysis
- `secubox-mac-guard_1.0.0-1~bookworm1_all.deb` (16KB) — MAC address control
- `secubox-dns-provider_1.0.0-1~bookworm1_all.deb` (18KB) — DNS API (OVH, Gandi, Cloudflare)
- `secubox-threats_1.0.0-1~bookworm1_all.deb` (17KB) — Unified threat dashboard
- `secubox-openclaw_1.0.0-1~bookworm1_all.deb` (17KB) — OSINT reconnaissance

**Previously Built:**
- `secubox-wazuh_1.0.0-1_all.deb` — SIEM (Session 24)
- `secubox-ossec_1.0.0-1_all.deb` — Host IDS (Session 24)

**Total Packages: 93** (was 85)

---

### Phase 8 — Applications COMPLETE (21/21)

**New Modules Created & Built (13):**
- `secubox-hexo_1.0.0-1~bookworm1_all.deb` (17KB) — Static blog generator (Hexo)
- `secubox-webradio_1.0.0-1~bookworm1_all.deb` (16KB) — Internet radio streaming
- `secubox-torrent_1.0.0-1~bookworm1_all.deb` (18KB) — BitTorrent client (Transmission)
- `secubox-newsbin_1.0.0-1~bookworm1_all.deb` (17KB) — Usenet downloader (SABnzbd)
- `secubox-domoticz_1.0.0-1~bookworm1_all.deb` (16KB) — Home automation
- `secubox-gotosocial_1.0.0-1~bookworm1_all.deb` (16KB) — Fediverse/ActivityPub server
- `secubox-simplex_1.0.0-2_all.deb` (15KB) — SimpleX secure messaging
- `secubox-photoprism_1.0.0-1~bookworm1_all.deb` (16KB) — Photo management
- `secubox-homeassistant_1.0.0-1~bookworm1_all.deb` (16KB) — IoT/Home automation hub
- `secubox-matrix_1.0.0-1_all.deb` (18KB) — Matrix chat server (Synapse)
- `secubox-jitsi_1.0.0-1~bookworm1_all.deb` (18KB) — Video conferencing
- `secubox-peertube_1.0.0-1~bookworm1_all.deb` (17KB) — Video platform
- `secubox-voip_1.0.0-1~bookworm1_all.deb` (17KB) — VoIP/PBX (Asterisk/FreePBX)

**Phase 8 Summary (21 modules total):**
- Previously complete: ollama, localai, jellyfin, zigbee, lyrion, jabber, magicmirror, mmpm (8)
- Session 37: hexo, webradio, torrent, newsbin, domoticz, gotosocial, simplex, photoprism, homeassistant, matrix, jitsi, peertube, voip (13)

**Total Packages: 85** (was 72)

---

## ✅ Terminé session précédente (Session 36)

### Phase 9 — System Tools COMPLETE (22/22)

**CI/CD Fix:**
- Fixed `build-live-usb.sh` pipefail issue with non-existent directories
- `find` commands now check directory existence before running
- Commit: `a1c0d56` - Pushed to master

**READMEs Added:**
- `secubox-ksm/README.md` — KSM documentation
- `secubox-admin/README.md` — Admin module documentation

**New Modules Created & Built (7):**
- `secubox-metabolizer_1.0.0-1~bookworm1_all.deb` (16KB) — Log processor/analyzer
- `secubox-metacatalog_1.0.0-1~bookworm1_all.deb` (15KB) — Service catalog/registry
- `secubox-cyberfeed_1.0.0-1~bookworm1_all.deb` (14KB) — Threat feed aggregator
- `secubox-mirror_1.0.0-1~bookworm1_all.deb` (12KB) — Mirror/CDN caching
- `secubox-saas-relay_1.0.0-1~bookworm1_all.deb` (16KB) — SaaS API proxy
- `secubox-rezapp_1.0.0-1_all.deb` (12KB) — App deployment manager
- `secubox-picobrew_1.0.0-1~bookworm1_all.deb` (19KB) — Homebrew/fermentation controller

**Commits:**
- `a1c0d56` — fix(ci): Handle non-existent directories in build-live-usb.sh
- `17e40e0` — feat(phase9): Complete all 22 System Tools modules

**Total Packages: 72** (was 65)

---

## ✅ Terminé session précédente (Session 35)

### Phase 9 — System Tools (15/22 complete)

**Modules Built (Session 35):**
- `secubox-rtty_1.0.0-1~bookworm1_all.deb` — Remote terminal
- `secubox-routes_1.0.0-1~bookworm1_all.deb` — Routing table view
- `secubox-reporter_1.0.0-1~bookworm1_all.deb` — System reports
- `secubox-smtp-relay_1.0.0-1~bookworm1_all.deb` — Mail relay
- `secubox-nettweak_1.0.0-1~bookworm1_all.deb` — Network tuning
- `secubox-ksm_1.0.0-1~bookworm1_all.deb` — Kernel same-page merging
- `secubox-avatar_1.0.0-1~bookworm1_all.deb` — Identity management
- `secubox-admin_1.0.0-1~bookworm1_all.deb` — Admin dashboard

**New Modules Created (Session 35 earlier):**
- `secubox-glances` v1.0.0 — System monitoring (Glances wrapper)
  - Real-time CPU/memory/disk/network stats
  - Process list, sensor readings
  - Historical data with charts
- `secubox-mqtt` v1.0.0 — MQTT broker management (Mosquitto)
  - Client list, topic tree view
  - User/ACL management
  - Message statistics
- `secubox-turn` v1.0.0 — TURN/STUN server (coturn)
  - Session monitoring
  - Credential generation (HMAC)
  - User/realm management
- `secubox-netdiag` v1.0.0 — Network diagnostics
  - Ping, traceroute, DNS, WHOIS, MTR
  - Port scanning, nmap
  - Interface/route/connection views

**Packages Built:**
- `secubox-glances_1.0.0-1~bookworm1_all.deb` (15KB)
- `secubox-mqtt_1.0.0-1~bookworm1_all.deb` (15KB)
- `secubox-turn_1.0.0-1~bookworm1_all.deb` (14KB)
- `secubox-netdiag_1.0.0-1~bookworm1_all.deb` (16KB)

**Previously Built (Session 24):**
- `secubox-vault_1.0.0-1_all.deb` — Config backup/restore
- `secubox-cloner_1.0.0-1_all.deb` — System imaging
- `secubox-vm_1.0.0-1_all.deb` — KVM/LXC virtualization

**Total Packages:** 65 (was 61)

---

## ✅ Terminé session précédente (Session 34)

### Build Timestamp Display — secubox-hub v1.2.0 ✅
- **API**: Added `_get_build_info()` function to read `/etc/secubox/build-info.json`
- **Dashboard**: Build timestamp badge displayed in header (date + time)
- **Tooltip**: Shows git commit, branch, board info on hover
- **Build script**: Creates `build-info.json` with timestamp, git info, board type

### Build System Fixes ✅
- **Package priority**: Fixed `build-live-usb.sh` to prefer `output/debs` over cache
- **nginx config**: Fixed secubox-soc-web to install in `secubox.d/` not `sites-available/`
- **Symlink fix**: Removed broken `secubox-repo.conf` symlink creation from postinst

### Packages Updated (Session 34)
- `secubox-hub_1.2.0-1~bookworm1_all.deb` — Build timestamp feature
- `secubox-soc-web_1.1.0-1_all.deb` — Nginx config fix (secubox.d/)

### Release v1.4.0 ✅
- Tag: `v1.4.0`
- Commit: `19ca292`
- Pushed to: `origin/master`

### Wiki Update ✅
- Updated `wiki/Home.md` — v1.4.0 version, 61 packages, SOC feature
- Updated `wiki/Home-FR.md` — French version sync
- Updated `wiki/Home-ZH.md` — Chinese version sync
- Updated `wiki/Modules.md` — Added SOC modules, secubox-console, hub v1.2.0 features
- Updated `.claude/HISTORY.md` — Session 34 entry, statistics (61 packages, v1.4.0)

---

## ✅ Terminé session précédente (Session 33)

### SecuBox SOC — Hierarchical Security Operations Center (Phases 1-4) ✅

**Phase 1: secubox-soc-agent v1.0.0** — Edge Node Metrics Agent
- **Collector**: CPU, memory, disk, network, CrowdSec/Suricata/WAF alerts
- **Upstreamer**: HMAC-SHA256 signed push to gateway (60s interval)
- **Command Handler**: Whitelist-based remote command execution
- **Enrollment**: One-time token workflow with HMAC key generation
- **Files**: `packages/secubox-soc-agent/{api/main.py, lib/{collector,upstreamer,command_handler}.py}`

**Phase 2: secubox-soc-gateway v1.0.0** — SOC Aggregation Gateway
- **Node Registry**: Enrollment, health tracking, HMAC token validation
- **Aggregator**: Fleet-wide metrics aggregation with StatsCache pattern
- **Alert Correlator**: Cross-node threat correlation (multi-node attack detection)
- **Remote Command**: Proxy commands to edge nodes via secure channel
- **WebSocket**: Real-time `/ws/alerts` stream for live monitoring
- **Files**: `packages/secubox-soc-gateway/{api/main.py, lib/{node_registry,aggregator,alert_correlator,remote_command}.py}`

**Phase 3: secubox-console v1.1.0** — TUI Extension
- **SOC Client**: Gateway API client for console
- **Fleet Screen**: Node grid with health indicators (f key)
- **Alerts Screen**: Unified alert stream with correlation toggle (a key)
- **Node Screen**: Remote node detail with service management
- **Files**: `packages/secubox-console/console/{soc_client.py, screens/soc_{fleet,alerts,node}.py}`

**Phase 4: secubox-soc-web v1.0.0** — React Web Dashboard
- **Stack**: React 18 + Vite + TypeScript + lucide-react
- **Pages**: FleetOverview, AlertStream, ThreatMap, NodeDetail
- **Components**: Sidebar, Header, NodeCard, AlertItem, StatCard
- **Hooks**: useWebSocket (reconnect), useFleet/useAlerts (data)
- **Theme**: Full cyberpunk CSS (--cosmos-black, --cyber-cyan, etc.)
- **Nginx**: /soc/ location with proxy to gateway API
- **Files**: `packages/secubox-soc-web/src/{App.tsx, pages/*, components/*, hooks/*}`

**Packages Built (Phases 1-4):**
- `secubox-soc-agent_1.0.0-1_all.deb` (12KB)
- `secubox-soc-gateway_1.0.0-1_all.deb` (15KB)
- `secubox-console_1.1.0-1_all.deb` (24KB)
- `secubox-soc-web_1.0.0-1_all.deb` (62KB)

**Phase 5: Hierarchical Mode** ✅
- **hierarchy.py**: Mode management (edge/regional/central), regional SOC enrollment
- **cross_region_correlator.py**: Cross-region threat correlation, global summary
- **Gateway API v1.1.0**: 11 new endpoints for hierarchy management
- **Web Dashboard v1.1.0**: GlobalView page, Settings page, mode indicators

**New API Endpoints (Gateway v1.1.0):**
- `GET /hierarchy/status` - Get hierarchy mode
- `POST /hierarchy/mode` - Set mode (edge/regional/central)
- `POST /regional/token` - Generate regional enrollment token (central)
- `POST /regional/enroll` - Enroll regional SOC (central)
- `POST /regional/ingest` - Receive regional data (central)
- `GET /regional/socs` - List regional SOCs (central)
- `POST /upstream/enroll` - Enroll with central (regional)
- `GET /upstream/status` - Upstream connection status (regional)
- `GET /global/summary` - Global cross-region summary (central)
- `GET /global/regions` - Regional breakdown (central)
- `GET /global/threats` - Cross-region threats (central)

**Packages Updated (Phase 5):**
- `secubox-soc-gateway_1.1.0-1_all.deb` (21KB)
- `secubox-soc-web_1.1.0-1_all.deb` (67KB)

---

## ✅ Terminé session précédente (Session 32)

### secubox-console v1.0.0 — Console TUI Dashboard
- **New package** providing terminal-based dashboard using Python Textual
- **Features**:
  - Dashboard screen with live metrics (CPU, memory, disk), uptime, health score
  - Services screen with start/stop/restart/enable/disable actions
  - Network screen with interface classification (WAN/LAN/SFP)
  - Logs screen with real-time streaming and unit filter
  - Menu screen with system info and quick actions (reboot, shutdown)
- **Board-specific theming** matching secubox-portal colors:
  - MOCHAbin (Pro) — Sky blue
  - ESPRESSObin (Lite) — Green
  - ESPRESSObin Ultra — Teal
  - x64-vm — Purple
  - x64-baremetal — Orange
  - Raspberry Pi — Pink
- **Vim-style navigation**: j/k for up/down, h for back, Enter to select
- **Auto-start on TTY1** when GUI kiosk is disabled
- **Files created**:
  - `packages/secubox-console/` — Complete package structure
  - `packages/secubox-console/console/app.py` — Main Textual App
  - `packages/secubox-console/console/api_client.py` — Async Unix socket client
  - `packages/secubox-console/console/theme.py` — Board-specific colors
  - `packages/secubox-console/console/screens/` — Dashboard, Services, Network, Logs, Menu
  - `packages/secubox-console/console/widgets/` — Header, Metrics, ServiceList
  - `packages/secubox-console/debian/` — Full Debian packaging

### secubox-kiosk-setup — Console Mode Integration
- **New commands**: `console`, `no-console`
- **Updated `status`** to show kiosk/console/none mode
- **Files modified**:
  - `image/sbin/secubox-kiosk-setup` — Added console mode support
  - `common/secubox_core/kiosk.py` — Added `console_status()`, `display_mode()`
  - `common/secubox_core/__init__.py` — Export new functions

---

## ✅ Terminé cette session (Session 31)

### secubox-portal v2.1.0 — Device-Specific Theming ✅
- **New API endpoints**:
  - `GET /theme` — Returns device-specific theme (colors, badge, name)
  - `GET /branding` — Full branding info with capabilities
- **7 board themes**:
  - MOCHAbin (Pro) — Sky blue accent (#0ea5e9)
  - ESPRESSObin (Lite) — Green accent (#22c55e)
  - x64-vm (Virtual) — Violet accent (#8b5cf6)
  - x64-baremetal (Server) — Orange accent (#f97316)
  - RPi (Maker) — Pink accent (#ec4899)
  - unknown (Standard) — Amber accent (#f59e0b)
  - default — Blue accent (#58a6ff)
- **Login page enhancements**:
  - Dynamic CSS variables applied from theme
  - Device badge shows board edition (PRO, LITE, VM, SERVER, PI)
  - Subtitle shows "SecuBox [Edition] Edition"
  - Gradient colors match board theme
- **Files modified**:
  - `packages/secubox-portal/api/main.py` — Theme endpoints
  - `packages/secubox-portal/www/login.html` — Dynamic theming JS
  - `packages/secubox-portal/debian/changelog` — v2.1.0

---

## ✅ Terminé cette session (Session 30)

### secubox-core v1.1.0 — Kiosk & Board Detection Library ✅
- **New module `kiosk.py`** in secubox_core with reusable functions:
  - `kiosk_status()` — Get kiosk mode status
  - `kiosk_enable(mode)` — Enable kiosk (x11/wayland)
  - `kiosk_disable()` — Disable kiosk mode
  - `detect_board_type()` — Auto-detect board type
  - `get_board_profile()` — Get profile (full/lite)
  - `get_board_capabilities()` — Board-specific capabilities
  - `get_board_model()` — Get full model string
  - `get_physical_interfaces()` — List physical network interfaces
  - `get_interface_classification()` — Classify WAN/LAN/SFP
  - `check_interface_carrier()` — Check if cable connected
- **Supported boards**: MOCHAbin, ESPRESSObin v7/Ultra, x64-vm, x64-baremetal, RPi
- **Files created/modified**:
  - `common/secubox_core/kiosk.py` — New module (350+ lines)
  - `common/secubox_core/__init__.py` — Export new functions, v1.1.0
  - `packages/secubox-core/debian/changelog` — v1.1.0

### secubox-hub v1.1.0 — Network Mode Selection ✅
- **New API endpoints**:
  - `GET /network_mode` — Current mode, available modes, interfaces
  - `POST /network_mode` — Change mode (proxies to secubox-netmodes)
  - `GET /network_mode/preview` — Preview YAML config for a mode
  - `GET /board_summary` — Quick board info for widgets
- **Frontend updates**:
  - New "Network Mode" card on dashboard
  - Mode selector with all available modes (Router, Inline Sniffer, Passive Sniffer, AP, Relay)
  - Preview button shows YAML config
  - Apply button changes mode with confirmation
  - Real-time WAN/LAN interface display
- **Integration**:
  - Uses secubox_core.kiosk for board/interface detection
  - Communicates with secubox-netmodes via Unix socket
- **Files modified**:
  - `packages/secubox-hub/api/main.py` — +150 lines for network mode
  - `packages/secubox-hub/www/index.html` — New Network Mode card + JS
  - `packages/secubox-hub/debian/changelog` — v1.1.0

### secubox-system v1.2.0 — Board Detection Integration ✅
- **Refactored to use secubox_core.kiosk** functions (no code duplication)
- **New API endpoints**:
  - `GET /board` — Detailed board detection (type, profile, interfaces)
  - `POST /board/detect` — Refresh detection (runs secubox-net-detect)
  - `GET /board/capabilities` — Board-specific capabilities and features
  - `GET /kiosk/status` — Kiosk mode status (enabled, mode, service state)
  - `POST /kiosk/enable` — Enable kiosk mode (x11 or wayland)
  - `POST /kiosk/disable` — Disable kiosk mode
- **Frontend updates**:
  - New "Board Detection" card with WAN/LAN/SFP classification
  - Interface details with carrier status (●/○)
  - Refresh detection button
  - New "Kiosk Mode" card with enable/disable controls
  - Mode selection (X11 for VMs, Wayland for native hardware)
- **Files modified**:
  - `packages/secubox-system/api/main.py` — Uses secubox_core.kiosk
  - `packages/secubox-system/www/system/index.html` — New UI cards
  - `packages/secubox-system/debian/changelog` — v1.2.0

---

## ✅ Terminé cette session (Session 29)

### Kiosk X11 Mode — Integrated into Build Scripts ✅
- **Problem**: Cage/Wayland kiosk fails on VMs (VirtualBox, VMware) with "Basic output test failed"
- **Solution**: Switched default kiosk mode from Wayland to X11
- **Files updated**:
  - `image/sbin/secubox-kiosk-setup` — Now supports `--x11` (default) and `--wayland` modes
  - `image/systemd/secubox-kiosk.service` — X11/startx service (default)
  - `image/systemd/secubox-kiosk-wayland.service` — Wayland/Cage service (optional)
  - `image/build-live-usb.sh` — Uses X11 kiosk mode with .xinitrc
- **New features**:
  - Mode auto-detection saved in `/var/lib/secubox/.kiosk-mode`
  - `secubox-kiosk-setup status` shows current mode
  - Automatic package installation for selected mode (xorg/xinit vs cage)
- **Usage**:
  ```bash
  # Default X11 mode (recommended)
  secubox-kiosk-setup install
  secubox-kiosk-setup enable

  # Wayland mode (native hardware only)
  secubox-kiosk-setup install --wayland
  secubox-kiosk-setup enable --wayland
  ```

---

## ✅ Terminé cette session (Session 28)

### Live USB Initramfs Fix ✅
- **Problem**: x64 live USB image boots to initramfs prompt (can't find root)
- **Root cause**: Modules for live-boot (squashfs, loop, overlay) were only in `/etc/modules-load.d/` which loads AFTER boot, not in initramfs
- **Fixes applied to `image/build-live-usb.sh`**:
  - Added critical modules to `/etc/initramfs-tools/modules` (squashfs, loop, overlay, ext4, vfat, iso9660, usb_storage, uas, sd_mod, dm_mod, virtio_blk, virtio_scsi, virtio_pci)
  - Created `/etc/initramfs-tools/conf.d/live-boot.conf` with `MODULES=most` for broad hardware support
  - Added `filesystem.size` and `filesystem.packages` files to live partition
  - Fixed `chroot` call for filesystem.packages (used awk on dpkg status instead)
  - Added debug GRUB menu entries (break=init, break=premount) for troubleshooting
  - Removed `2>/dev/null` from update-initramfs to surface any errors

### Images Built ✅
- **x64 Live USB**: `output/secubox-live-amd64-bookworm.img` (8GB, 670MB squashfs)
- **RPi 400**: `output/secubox-rpi-arm64-bookworm.img` (8GB)

---

## ✅ Terminé cette session (Session 27)

### Kiosk X11 Mode ✅
- **Switched from Cage/Wayland to X11/startx** — VirtualBox GPU compatibility
  - Cage/wlroots fails with "Basic output test failed" on VBoxSVGA
  - Created `secubox-kiosk-x11.service` using startx + chromium
  - Works reliably with VMware SVGA II / VBoxSVGA drivers
- **Files created on VM**:
  - `/etc/systemd/system/secubox-kiosk-x11.service`
  - `/home/secubox-kiosk/.xinitrc`

### Menu System Fix ✅
- **Problem**: Only 2 modules shown (hub, portal) instead of all installed
- **Root cause**: menu.d/*.json files not installed on VM
- **Fix**: Copied 85 menu JSON files to `/usr/share/secubox/menu.d/`
- **Result**: Menu API now returns all installed modules correctly

### Authentication Fix ✅
- **Created `/etc/secubox/secubox.conf`** with auth section
- **JWT login working** — admin/secubox credentials
- **All API endpoints** now properly authenticated

### secubox-netmodes Fixes ✅
- **Bug fix**: `int(float())` for /proc/uptime parsing (line 95)
- **Frontend JWT fix**: Added `getToken()` and auto-login on 401
- **Auto-Detect working**: Returns board=x64-vm, wan=enp0s3
- **Files modified**:
  - `packages/secubox-netmodes/api/main.py` — uptime bug fix
  - `packages/secubox-netmodes/www/netmodes/index.html` — JWT auth in api()

---

## ✅ Terminé session précédente (Session 26)

### Kiosk GUI VM Testing ✅
- **Fixed kiosk display** — Enabled 3D acceleration in VirtualBox
  - `VBoxManage modifyvm "VM" --accelerate3d on --vram 128`
  - Cage Wayland compositor now renders properly
- **Installed SecuBox packages on kiosk VM**
  - secubox-core, secubox-hub, secubox-portal
  - Fixed nginx port 9443 + nftables firewall rule
- **Kiosk fully functional** — Displays SecuBox Control Center

### secubox-net-detect Integration ✅
- **New API endpoints in secubox-netmodes**:
  - `GET /detect` — Run secubox-net-detect, return JSON (board, interfaces)
  - `GET /detect_cached` — Return cached detection (faster)
  - `POST /auto_apply` — Auto-configure network based on detection
  - `GET /board_info` — Get detected board from state
- **Frontend updates**:
  - Added "Auto-Detect" button in header
  - Auto-Detection card with board/WAN/LAN/SFP display
  - Preview YAML and Apply buttons
  - Pre-fills WAN/LAN selectors from detection
- **Files modified**:
  - `packages/secubox-netmodes/api/main.py` — +200 lines
  - `packages/secubox-netmodes/www/netmodes/index.html` — Auto-detect UI

---

## ✅ Terminé session précédente (Session 25)

### Kiosk Mode Fixes ✅
- **Fixed UID mismatch** — Service now uses dynamic UID detection
  - Kiosk user created with UID 1000 when possible
  - Service file updated with actual UID at runtime
  - `XDG_RUNTIME_DIR=/run/user/<actual-uid>`
- **Fixed timing issue** — cmdline handler no longer tries apt-get at sysinit.target
  - If packages pre-installed (--kiosk flag): enable immediately
  - If packages missing: creates oneshot service to install after network
- **Fixed marker file confusion**
  - `.kiosk-installed` — Marks packages installed
  - `.kiosk-enabled` — Marks kiosk mode activated (required by service)
- **Updated build-live-usb.sh**
  - `--kiosk` flag now creates user and start script during build
  - All kiosk dependencies pre-installed for immediate boot
- **Improved start-kiosk.sh**
  - Waits for nginx/hub service to be ready (30s max)
  - Uses `curl -sk` to check HTTPS endpoint
- **Updated secubox-kiosk.service**
  - `ConditionPathExists=/var/lib/secubox/.kiosk-enabled`
  - `After=nginx.service secubox-hub.service`
- **Root autologin preserved**
  - Kiosk uses tty1 for display
  - Root autologin moved to tty2 (Ctrl+Alt+F2 to access)
  - Console access always available for debugging
- **Files modified**:
  - `image/sbin/secubox-kiosk-setup` — Refactored with setup_kiosk_user(), update_service_file(), setup_root_autologin_tty2()
  - `image/sbin/secubox-cmdline-handler` — Smart package detection
  - `image/systemd/secubox-kiosk.service` — ConditionPathExists for enabled marker
  - `image/build-live-usb.sh` — Full kiosk setup when --kiosk flag used, tty2 autologin

---

## ✅ Terminé session précédente (Session 24)

### Network Auto-Detection & Preseed System ✅
- **secubox-net-detect** — Auto-detection script for WAN/LAN interfaces
  - Board detection via /proc/device-tree/model (MochaBin, ESPRESSObin)
  - x64 detection via DMI (VM vs baremetal)
  - Interface mapping: eth0=WAN, eth*/lan*=LAN based on device
  - Netplan generation for 3 modes: router, bridge, single
  - Link detection for x64 auto-discovery
- **Board configurations**:
  - `board/x64-live/config.mk` — Live USB profile settings
  - `board/x64-vm/config.mk` — VM-specific settings
  - Netplan templates for x64 auto-DHCP on common interfaces
- **secubox-cmdline-handler** — Kernel parameter parser
  - `secubox.netmode=router|bridge|single` — Network mode selection
  - `secubox.kiosk=1` — Enable GUI kiosk mode
  - `secubox.debug=1` — Enable debug mode
  - Runs early at boot (sysinit.target)
- **secubox-kiosk-setup** — GUI kiosk mode installer
  - Installs Cage Wayland compositor + Chromium
  - Fullscreen WebUI at https://localhost:9443/
  - Commands: install, enable, disable, status
  - Perfect for touchscreen/embedded displays
- **build-live-usb.sh updates**:
  - GRUB menu entries: Kiosk Mode, Bridge Mode
  - Installs all detection scripts and services
  - Systemd services for early boot configuration
- **firstboot.sh integration**:
  - Calls secubox-net-detect to configure network
  - Updates secubox.conf with detected board/interface
  - Creates .net-configured marker

### Phase 8-10 Progress ✅
- secubox-jabber (XMPP) — Deployed
- secubox-magicmirror — Deployed
- secubox-mmpm — Deployed
- secubox-redroid — Deployed
- secubox-vault — Built
- secubox-cloner — Built
- secubox-vm — Built
- secubox-wazuh — Built
- secubox-ossec — Built
- All commits pushed to master

---

## ✅ Terminé session précédente (Session 23)

### Migration Preparation Workflow ✅
- Created `.claude/REMAINING-PACKAGES.md` — 53 packages remaining inventory
- Classified by complexity (Easy/Medium/Complex/Native)
- Identified 25 packages with different naming (already ported)
- Defined Phase 8 (21 apps), Phase 9 (22 tools), Phase 10 (10 security)
- Updated TODO.md with P8/P9/P10 task items
- Created HISTORY.md for milestone tracking
- Set priority: ollama → jellyfin → vault → homeassistant

### secubox-ollama v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (485 lines)
  - Container management (Docker/Podman detection)
  - Model management (list, pull, remove)
  - Chat completion API (`/chat`)
  - Text generation API (`/generate`)
  - System resource monitoring (`/system`)
  - Container logs (`/logs`)
- **CRT-light frontend** — Full P31 phosphor theme
  - Tabs: Chat, Models, System, Logs, Settings
  - Popular model quick-pull buttons
  - Real-time chat interface
- **Deployed to VM** — Running at https://localhost:9443/ollama/

### secubox-jellyfin v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (15+ endpoints)
  - Container management (Docker/Podman)
  - Media library configuration
  - Hardware acceleration (VAAPI)
  - Backup/restore functionality
  - Setup wizard tracking
- **CRT-light frontend** — Jellyfin blue accent theme
  - Tabs: Libraries, Settings, Logs, Backup
  - Install banner when not installed
  - Library type icons (movies, tvshows, music, photos)
- **Deployed to VM** — Running at https://localhost:9443/jellyfin/

### secubox-lyrion v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (18+ endpoints)
  - Container management (Docker/Podman)
  - Player control via Squeezebox JSON-RPC
  - Library scanning, stats
  - Backup/restore functionality
- **CRT-light frontend** — Theme-aware with Lyrion orange accents
  - Tabs: Players, Library, System, Logs, Settings
  - JSON-RPC integration for library stats
- **Deployed to VM** — Running at https://localhost:9443/lyrion/

### secubox-zigbee v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (20+ endpoints)
  - Container management (Docker/Podman)
  - USB serial dongle detection (/dev/ttyUSB*, /dev/ttyACM*)
  - Device management: rename, remove, permit_join
  - MQTT integration
  - Kernel module detection (cp210x, ch341)
- **CRT-light frontend** — Theme-aware with Zigbee green accents
  - Tabs: Devices, Network, Diagnostics, Logs, Settings
  - Pairing mode toggle with animation
- **Deployed to VM** — Running at https://localhost:9443/zigbee/

### secubox-localai v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (15+ endpoints)
  - Container management (Docker/Podman)
  - Model gallery with popular LLMs
  - OpenAI-compatible chat/completion API proxy
  - Resource monitoring (CPU/memory)
- **CRT-light frontend** — Theme-aware with LocalAI purple accents
  - Tabs: Chat, Models, Gallery, Logs, Settings
  - Interactive chat interface
- **Deployed to VM** — Running at https://localhost:9443/localai/
- **Total modules: 59** (was 55)

### Ad Guard Theme Update ✅
- Updated frontend to be theme-aware
- Added Ad Guard blue accent color
- Dark mode support via body.dark class

---

## ✅ Terminé session précédente (Session 21)

### Live ISO Boot Console Fixes ✅
- **Issue**: Live ISO boot showed flickering console, login prompt disappearing
- **Root causes identified and fixed**:
  1. **Service restart loops** — 14 SecuBox services crashing on live boot (missing configs)
  2. **Martian packet logging** — Network errors flooding console
  3. **Getty autologin conflict** — live-config tried to login as 'user' (doesn't exist)
  4. **Systemd status messages** — [FAILED] messages overwriting login prompt

- **Fixes applied to `image/build-installer-iso.sh`**:
  - Mask 14 services incompatible with live boot (secubox-haproxy, secuboxd, lxc-net, etc.)
  - Disable martian packet logging via sysctl
  - Configure systemd ShowStatus=no for quiet boot
  - Fix getty autologin: disable live-config autologin, create 'user' fallback account
  - Set kernel printk level to suppress non-critical messages
  - Add debug boot menu entries (rescue, emergency, no-preseed)

- **Fixes applied to `image/preseed-apply.sh`**:
  - Skip service restarts on live boot entirely
  - Use background processes for installed systems

- **Output**:
  - ISO: `secubox-c3box-clone-amd64-bookworm.iso` (457MB)
  - IMG: `secubox-c3box-clone-amd64-bookworm.img` (969MB)
  - Live boot working with stable console login

- **Commit pushed**: `288b27a Fix live ISO boot console issues`

---

## ✅ Terminé session précédente (Session 20)

### x64 Installer ISO Build System ✅
- **image/build-installer-iso.sh** (886 lines) — Hybrid Live USB / Headless Installer
  - UEFI boot with GRUB (x86_64-efi)
  - Live boot mode with SquashFS + persistence partition
  - Headless auto-install to first available disk
  - Preseed system for configuration restoration
  - Boot menu: Live, Install (headless), Safe Mode, To RAM
- **image/export-c3box-clone.sh** (340 lines) — Export device configuration
  - Exports: /etc/secubox/, netplan, WireGuard, users, nginx, SSL certs
  - LXC container configs, /data partition
  - Creates preseed.tar.gz for cloning
- **image/build-c3box-clone.sh** (174 lines) — Combined export + ISO workflow
  - Single command to clone any C3Box device
  - `--skip-export` option to rebuild ISO from existing preseed
- **Commit pushed**: `141b0c0 Add x64 installer ISO and C3Box clone build system`

### C3Box Configuration Export ✅
- **Exported from VM** (localhost:2222)
- **50 SecuBox packages** captured in manifest
- **Configuration**: secubox.conf, mesh.toml, users.json, traffic-shaper.json, etc.
- **Network**: netplan + WireGuard configs
- **Services**: nginx sites, CrowdSec, nftables rules
- **LXC containers**: mailserver, roundcube, streamlit
- **Output**: `output/c3box-clone-preseed.tar.gz` (36KB)

### streamlitctl v1.0.0 ✅
- **packages/secubox-streamlit/scripts/streamlitctl** (521 lines)
- Full Streamlit LXC controller for Debian bookworm
- **Commands**: install, start, stop, restart, status, destroy, logs, shell
- **App management**: app create, app list
- **Features**:
  - Debootstrap-based minimal Debian container
  - Python 3.11 + Streamlit installation
  - Persistent apps directory at /srv/streamlit/apps
  - Memory limit 1GB per container
  - Three-fold commands: components, access (JSON output)
- **Debian packaging** updated (control, rules, changelog v1.2.0)

### VSCode Tasks ✅
- **Build C3Box Clone ISO (from VM)** — Clone localhost:2222
- **Build C3Box Clone ISO (custom host)** — Clone any device
- **Export C3Box Config Only** — Export without building ISO
- **Build Installer ISO (x64)** — Fresh install ISO
- **Build Live USB (x64)** — Live-only USB
- **Build Installer ISO with Preseed** — ISO with custom preseed
- **New inputs**: c3boxHost, c3boxPort, preseedFile

---

## ✅ Terminé session précédente (Session 19)

### Socket Directory Fix (Permanent) ✅
- **Issue**: `/run/secubox/` sockets disappearing, causing 502 errors and navbar showing only 2 categories
- **Root cause**: Directory permissions reset after service restarts
- **Solution**: Created `secubox-runtime.service` — oneshot service that runs before all secubox services
  - Creates `/run/secubox` with correct ownership (secubox:secubox)
  - Sets permissions to 775
  - Runs after local-fs.target, before hub/portal/p2p services
- **Files added**:
  - `packages/secubox-core/systemd/secubox-runtime.service`
  - Updated `packages/secubox-core/debian/rules` to install the service
  - Updated `packages/secubox-core/debian/postinst` to enable the service
- **Commit pushed**: `ba6b5da Add secubox-runtime.service to ensure /run/secubox exists`

### Master-Link Admin Navbar Integration ✅
- **Updated `/master-link/admin.html`** with standard SecuBox UI
  - Added sidebar navbar using shared `sidebar.js`
  - Changed from dark CRT to P31 Phosphor light theme
  - Removed back button (navigate via sidebar instead)
  - Consistent styling with other SecuBox modules
  - Fixed sidebar element: `<nav class="sidebar" id="sidebar">` (was wrong div)
- **Commit pushed**: `5834115 Update Master-Link Admin with navbar integration`

### VM Restart & Verification ✅
- Restarted frozen VirtualBox VM
- Applied `secubox-runtime.service` fix on VM
- Verified all **46 sockets** restored in `/run/secubox/`
- Verified all **46 services** running
- Verified navbar API: **7 categories**, **45 modules**
- Tested Master-Link: status, peers, tree, invite-local all working

### ReDroid (Android in Container) Integration ✅
- **redroid/redroid-lxc-setup.sh** — Interactive wizard for ReDroid deployment
  - Docker installation, ADB/scrcpy setup
  - Automatic architecture detection (ARM64/x86_64)
  - LXC binder device configuration
  - Multi-instance support with docker-compose
  - NDK translation for ARM apps on x86 hosts
  - Android versions: 9, 10, 11, 12, 13, 15
- **redroid/proxmox-host-config.sh** — Proxmox host configuration helper
  - Binder kernel module loading (binder_linux, ashmem_linux)
  - LXC config snippets for device passthrough
  - Instructions for MOCHAbin/ESPRESSObin ARM64 and x86_64
- **VSCode tasks for ReDroid management**:
  - Setup wizard, auto-setup Android 12
  - Start/stop/status commands
  - Screen mirroring (scrcpy), ADB shell
  - APK installation, live logs
  - Binder device diagnostics
  - Multi-instance support (up to 3 instances)
- **Commit pushed**: `5340ebc Add ReDroid (Android in Container) LXC setup scripts`

---

## ✅ Terminé session précédente (Session 18)

### Master-Link Admin Dashboard (v1.6.0) ✅
- **Admin Dashboard** — `/master-link/admin.html`
  - Dark CRT theme matching SecuBox aesthetics
  - Stats cards: role, peers, pending, active tokens
  - Tabs: Overview, Peers list, Mesh Tree, Generate Invite
  - Token generation with copy buttons (token, URL, CLI)
  - Peer approval workflow from dashboard
- **Localhost-only API endpoints**:
  - `POST /master-link/invite-local` — Generate tokens without JWT auth
  - `POST /master-link/cleanup-local` — Cleanup expired tokens
  - `is_local_request()` helper checks X-Real-IP, X-Forwarded-For headers
- **IP prioritization**: `get_lan_ip()` now prefers 192.168.255.x mesh addresses
- **Dependencies**: Added `avahi-daemon`, `avahi-utils` for mDNS discovery
- **Commit pushed**: `0ecdb98 Add Master-Link Admin Dashboard (v1.6.0)`

### Mesh Invite CLI (v1.5.0) ✅
- **sbx-mesh-invite v1.0.0** — CLI tool to generate mesh invite tokens
  - Options: `--auto-approve`, `--manual-approve`, `--ttl`, `--ip`
  - Auto-detects local LAN IP (prefers 192.168.x.x addresses)
  - Stores tokens in `/var/lib/secubox/p2p/master-link/tokens.json`
  - ASCII box formatted output for easy copy-paste
  - Works on Debian and OpenWRT (openssl, sha256sum, or fallbacks)
- **Commit pushed**: `9b6f7fd Add sbx-mesh-invite CLI tool (v1.5.0)`

### VM Socket Fix ✅
- **Issue**: All 46 secubox API sockets disappeared from `/run/secubox/`
- **Cause**: Directory permissions reset after service restarts
- **Fix**: Created `/etc/tmpfiles.d/secubox.conf` with `d /run/secubox 0775 secubox secubox -`
- **Result**: All 46 sockets now persist across restarts

### Multi-Master Support (v1.4.0) ✅
- **sbx-mesh-join v1.4.0** — Auto-detect master type
  - `detect_master_type()` — Probe endpoints to identify master type
  - Debian API support: `/api/v1/p2p/master-link/join` (port 7331)
  - OpenWRT CGI support: `/cgi-bin/masterlink/join` (port 80 or 7331)
  - Fallback: Try all methods when master type unknown
  - Save `master_type` in local config for future reference
  - Better troubleshooting hints for both master types
- **Commit pushed**: `aadbe17 sbx-mesh-join v1.4.0: Auto-detect master type`

### Simplified Invite Flow (v1.3.0) ✅
- **secubox-p2p v1.3.0** — Simplified mesh join workflow
  - `POST /master-link/invite` — Generate shareable invite with URLs + CLI commands
  - `GET /master-link/join-script?token=xxx` — Returns executable shell script
  - Copy-paste friendly ASCII box output for invites
  - One-liner join: `wget -qO- '<url>' | sh`
- **sbx-mesh-join CLI tool** — `/usr/bin/sbx-mesh-join`
  - Works on OpenWRT (wget, uci, br-lan) and Debian (curl)
  - Accepts URL or IP+token arguments
  - Auto-detects system type and configures accordingly
- **Commits pushed**:
  - `aa8493a Add simplified invite flow and OpenWRT join script (v1.3.0)`
  - `066ed94 Add OpenWRT Master-Link client implementation guide`

### OpenWRT Documentation ✅
- **docs/OPENWRT-MASTERLINK.md** — Complete implementation guide (487 lines)
  - RPCD backend script (luci.masterlink)
  - LuCI JavaScript view for join/leave UI
  - UCI config template
  - OpenWRT package Makefile
  - ACL permissions file
  - Testing commands and directory structure

### P2P Hub Light Theme ✅
- **secubox-p2p www/p2p/index.html** — Full P31 Phosphor light theme applied
  - Updated CSS root variables from dark (#0a0a0a, #33ff33) to light palette (#e8f5e9, #006622)
  - Fixed all components: buttons, forms, tables, modals, status cards, status badges
  - Updated mesh visualization canvas colors to light theme
  - Added border-radius and improved shadows for modern look
- **Commit pushed** — `91d6550 Apply P31 Phosphor light theme to P2P Hub page`

### VM Testing ✅
- **VirtualBox SecuBox-Dev** — Running and accessible
  - SSH: `ssh -p 2222 root@localhost`
  - HTTPS: https://localhost:9443
- **P2P Hub page** — Deployed and tested at /p2p/
- **Master-Link page** — Tested at /master-link/
  - All endpoints working (status, peers, tree, token validation)
  - 3 peers approved via master-link (test-peer, c3box, C3BOX/OpenWRT)
  - Mesh hierarchy: master (depth 0) → 3 children (depth 1)
- **CLI tools tested**:
  - `sbx-mesh-invite` — Generates tokens with auto-detected IP (192.168.100.1)
  - `sbx-mesh-join` — Joins mesh with multi-master support

---

## ✅ Terminé session précédente (Session 17)

### Master-Link Enrollment System ✅
- **secubox-p2p v1.2.0** — Token-based mesh node enrollment (ported from secubox-openwrt)
  - Token generation with TTL and auto-approve options
  - Join request handling with token validation
  - Peer approval workflow: approve, reject, promote to sub-master
  - Depth-based mesh hierarchy (max_depth configurable)
  - Master/sub-master/peer role management
  - Mesh tree visualization endpoint
  - Upstream join capability for peer-side enrollment
- **Master-Link join page** — `/master-link/?token=xxx`
  - P31 Phosphor light theme (consistent with other modules)
  - 3-step wizard: Review master → Enter details → Join mesh
  - Shows master fingerprint, role, depth for verification
  - Auto-approval status display
- **New API endpoints**:
  - `GET /master-link/status` — Status and peer counts (public)
  - `POST /master-link/token` — Generate join token
  - `POST /master-link/join` — Handle join request
  - `POST /master-link/approve` — Approve/reject/promote peer
  - `GET /master-link/peers` — List all join requests
  - `GET /master-link/tree` — Mesh hierarchy tree
  - `GET/POST /master-link/config` — Configuration management
  - `POST /master-link/join-with-token` — Join upstream mesh
- **nginx config** — Added `/master-link/` route
- **debian/rules** — Installs master-link www directory

### Device Intel Enhancement ✅
- **secubox-device-intel v1.2.1** — Enhanced SecuBox/OpenWRT detection
  - Specific SecuBox markers (no false positives)
  - GL.iNet custom UI detection
  - SecuBox theme extraction (crt-p31, etc.)
  - Single IP probe endpoint

### Mesh UI Fix ✅
- **secubox-mesh www/mesh/index.html** — P31 light theme (was dark CRT conflict)
- **secubox-mesh API** — Made /status, /services, /domains public endpoints

---

## ✅ Terminé cette session (Session 16)

### UI Theme & Navbar Consistency ✅
- **Theme toggle system** — Light/dark P31 phosphor themes working across all modules
  - Light theme: mint green palette (#e8f5e9, #006622)
  - Dark theme: blue-tinted palette (#0a0e14, #33ff66)
  - Toggle persists via localStorage (`sbx_theme` key)
- **Fixed 35+ pages** — Body class standardized to `crt-light`
- **Fixed inline CSS variables** — Added `updateInlineThemeVars()` for modules using `--bg`/`--fg`/`--dim`
- **Collapsed sidebar categories** — Categories collapse by default, only active category expanded
- **Fixed navbar integration issues**:
  - Portal: Changed path from `/c3box/` to `/portal/`
  - Metrics: Fixed `title` → `name` in menu JSON
  - Mesh DNS: Removed duplicate 580-mesh.json
  - WireGuard: Removed duplicate 21-wireguard.json
  - Metrics: Fixed sidebar.js path `/assets/js/` → `/shared/`
  - p2p, zkp, mesh: Added missing crt-light.css link

### Documentation & Screenshots ✅
- **45 module screenshots captured** — Using Playwright screenshot-tool.py
- **docs/UI-GUIDE.md** — CRT theme documentation with color palette and module list
- **scripts/fix-navbar.sh** — Automated navbar integration checker
- **docs/OPENWRT-DEBIAN-COMPARISON.md** — Full comparison:
  - OpenWRT: 103 luci-app modules
  - Debian: 52 packages (49 UI + 3 backend)
  - Migration status by category
  - ~1000+ API endpoints documented
  - Roadmap for remaining 68 modules

### Previous Session (15) — Module Compliance Fixes ✅
- **Maintainer standardization** — All 51 packages now use `Gerald KERMA <devel@cybermind.fr>`
  - Fixed 12 control files with wrong maintainer
  - Fixed 9 changelog files with wrong maintainer
- **JWT Authentication** — Added to secubox-mesh API (was missing)
  - All endpoints now require JWT auth except /health
  - secubox-roadmap is intentionally public (read-only migration status)

### Go Daemon Organization ✅
- **Moved Go code to `daemon/` directory** — Proper structure for mesh daemon
  - `daemon/cmd/secuboxd/` — Mesh daemon main
  - `daemon/cmd/secuboxctl/` — CLI tool
  - `daemon/c3box/` — Situational awareness dashboard
  - `daemon/internal/` — Internal packages (discovery, identity, telemetry, topology)
  - `daemon/pkg/` — Shared packages (config, hamiltonian)
  - `daemon/systemd/` — systemd service units
  - `daemon/testdata/` — Test configuration files
- **Added `daemon/Makefile`** — Build targets for all binaries
- **Added `daemon/README.md`** — Documentation for mesh daemon architecture

### Debian Packaging for Go Daemon ✅
- **packages/secubox-daemon/** — New package for mesh daemon
  - `secubox-daemon` — Contains secuboxd + secuboxctl
  - `secubox-c3box` — Situational awareness dashboard (separate package)
  - Full debian packaging (control, changelog, rules, postinst, prerm)
  - Systemd integration with socket activation

### Unix Socket Control Server ✅
- **daemon/internal/control/server.go** — Control server implementation
  - Unix socket at `/run/secuboxd/topo.sock`
  - Commands: mesh.status, mesh.peers, mesh.topology, mesh.nodes
  - Commands: node.info, node.rotate, telemetry.latest, ping
  - JSON responses with proper error handling
  - Graceful shutdown and socket cleanup
- **daemon/cmd/secuboxctl/main.go** — CLI expanded with new commands
  - `secuboxctl mesh topology` — Show mesh topology
  - `secuboxctl mesh nodes` — List mesh nodes with ZKP status
  - `secuboxctl telemetry latest` — Show telemetry metrics
- **Tested on VM** — All commands working:
  - Node info shows DID, role, ZKP expiry
  - Mesh status shows running state, uptime
  - Telemetry shows CPU/memory/disk, nftables rules, CrowdSec bans

### Go Daemon Telemetry Implementation ✅
- **pkg/hamiltonian/hamiltonian.go** — Fixed `currentTimestamp()` to use `time.Now().Unix()`
- **internal/telemetry/telemetry.go** — Implemented metrics collection:
  - `getCPUPercent()` — Reads from /proc/stat
  - `getDiskPercent()` — Uses syscall.Statfs for root filesystem
  - `getNFTablesRuleCount()` — Parses `nft list ruleset` output
  - `getCrowdSecBans()` — Queries `cscli decisions list`

---

## ✅ Terminé session précédente (Session 14)

### API Documentation Expansion ✅
- **wiki/API-Reference.md** — Comprehensive API docs for all 48 modules
  - Core modules: hub, portal, system (70+ endpoints)
  - Security modules: crowdsec, waf, mitmproxy, hardening, nac, auth (150+ endpoints)
  - Network modules: netmodes, wireguard, qos, dpi, traffic, vhost, cdn (200+ endpoints)
  - Services modules: haproxy, netdata, mediaflow (80+ endpoints)
  - Application modules: mail, dns, users, gitea, nextcloud (100+ endpoints)
  - Container modules: backup, watchdog, tor, exposure (60+ endpoints)
  - Intel modules: device-intel, vortex-dns, vortex-firewall, soc, metrics, meshname (100+ endpoints)
  - Other modules: mesh, p2p, zkp, repo, roadmap (40+ endpoints)
  - Total: ~1000+ documented API endpoints
  - Code examples for common operations (login, ban IP, add peer)
  - Error response format and rate limiting info
  - WebSocket documentation for real-time updates

---

## ✅ Terminé session précédente (Session 13)

### Multilingual Module Documentation ✅
- **wiki/MODULES-EN.md** — English module docs (48 modules, 771 lines)
- **wiki/MODULES-FR.md** — French module docs
- **wiki/MODULES-DE.md** — German module docs
- **wiki/MODULES-ZH.md** — Chinese module docs
- **wiki/_Sidebar.md** — Updated with multilingual module links
- **docs/SCREENSHOTS-VM.md** — Added missing Metrics Dashboard entry (47 screenshots)
- All screenshots captured and linked to GitHub raw URLs

---

## ✅ Terminé session précédente (Session 12)

### secubox-metrics Module ✅
- **Metrics Dashboard** — Migrated from OpenWRT luci-app-metrics-dashboard
  - FastAPI backend with caching (30s TTL)
  - System overview: uptime, load, memory, vhosts, certs, LXC count
  - Service status: HAProxy, WAF, CrowdSec
  - WAF stats: active bans, alerts (24h), blocked requests
  - Connections: TCP by port (HTTPS/HTTP/SSH)
  - P31 Phosphor CRT theme (#33ff66 green glow)
- **API endpoints**: /status, /health, /overview, /waf_stats, /connections, /all, /refresh, /certs, /vhosts
- **CI Fix**: Added build-essential to build dependencies
- **Nginx config**: Modular /etc/nginx/secubox.d/metrics.conf
- **Total modules: 47** (was 46)

### secubox-soc Module ✅
- **Security Operations Center** — New SOC dashboard module
  - World Clock: 10 timezone display (UTC, EST, PST, GMT, CET, MSK, GST, SGT, JST, AEST)
  - World Threat Map: SVG with 30 country coordinates, threat heatmap
  - Ticket System: Create, assign, track security incidents
  - Threat Intel: IOC management (IPs, domains, hashes)
  - P2P Intel: Peer-to-peer threat sharing network
  - Alerts: Real-time security alert feed
  - WebSocket: Live updates for all components
  - CRT P31 theme: Full green phosphor aesthetic
- **API endpoints**: 20+ (clock, map, tickets, intel, peers, alerts, stats, ws)
- **Total modules: 46** (was 45)

### Documentation ✅
- **docs/MODULES.md** — Comprehensive module documentation
  - 46 modules cataloged by category
  - API endpoint counts per module
  - CRT P31 theme documentation
  - Screenshot checklist for all modules
  - Module architecture diagram
  - Build and deploy instructions
- **docs/screenshots/.gitkeep** — Created screenshots directory

### CRT Theme Fixes ✅

### 4 New Modules Ported ✅
From OpenWRT planned modules to Debian:
- **secubox-device-intel** v1.0.0 — Asset discovery and fingerprinting
  - ARP table scanning, MAC vendor lookup (OUI database)
  - DHCP lease tracking, hostname detection
  - Device tagging and notes, trusted device marking
  - Network interface listing, active scan capability
- **secubox-vortex-dns** v1.0.0 — DNS firewall with RPZ and threat feeds
  - Blocklist management (hosts/domains format)
  - Custom domain rules (block/allow/redirect)
  - Unbound and dnsmasq support
  - Threat feed integration (Steven Black, OISD, URLhaus, etc.)
- **secubox-vortex-firewall** v1.0.0 — nftables threat enforcement
  - IP blocklist management (plain/CIDR/CSV formats)
  - nftables sets for IPv4/IPv6 blocking
  - Custom IP rules (drop/reject/log)
  - Threat feed integration (Spamhaus, Feodo, SSL Blacklist, etc.)
- **secubox-meshname** v1.0.0 — Mesh network domain resolution
  - Mesh node registration with custom domain
  - mDNS host discovery via Avahi
  - dnsmasq integration for local DNS
  - DNS resolver test endpoint

All modules include FastAPI backend, Catppuccin frontend, Debian packaging.
Total modules: **45** (was 41)

### VM Fixes ✅
- **Hub socket fix** — Fixed /run/secubox permissions for socket creation
- **Roadmap navbar** — Standardized to use shared sidebar.js like all other modules
- **Login credentials** — Recreated /etc/secubox/users.json with admin user
- **VM RAM** — Increased to 4GB for 47 services (was 2GB, causing timeouts)
- **vortex-firewall** — Fixed permission error creating /etc/nftables.d (try/except + postinst)

### Frontend Fixes ✅
- **Login redirect** — Fixed path `/login/` → `/portal/login.html` in 4 new modules
- **JSON error handling** — Improved API function to handle non-JSON responses gracefully
- **Sidebar CSS** — Added missing `sidebar.css` link to 4 new modules + roadmap
- **CSS conflicts** — Removed local `.sidebar` overrides to allow shared CRT P31 theme
- All 5 pages tested: device-intel, vortex-dns, vortex-firewall, meshname, roadmap

### Menu Fix ✅
- Removed duplicate WireGuard menu entry (21-wireguard.json)

### secubox-qos v1.1.0 — Per-VLAN QoS Support ✅
- **Multi-interface support** — Manage QoS on eth0, eth0.100, eth0.200, etc.
- **VLAN discovery** — Auto-detect existing VLAN interfaces
- **Per-VLAN policies** — Independent bandwidth limits per VLAN
- **802.1p PCP marking** — Map tc classes to VLAN priority (0-7)
- **VLAN creation/deletion** — Create VLAN interfaces with QoS from UI
- **VLAN-aware rules** — Traffic classification by VLAN ID
- **Per-interface statistics** — RX/TX bytes, tc class stats
- **Apply-all function** — Apply QoS to all managed interfaces at once
- **Frontend updated** — VLAN policies table, PCP settings, interface stats

New API endpoints:
- `GET /vlans` — List VLAN interfaces with policies
- `GET/POST/DELETE /vlan/{interface}` — VLAN policy management
- `POST /vlan/create` — Create new VLAN with QoS
- `POST /vlan/apply_all` — Apply QoS to all interfaces
- `GET/POST /pcp/mappings` — 802.1p priority mappings
- `GET/POST/DELETE /interfaces` — Interface management
- `GET/POST/DELETE /vlan/rules` — VLAN classification rules

### 6 New Modules Committed (Session 9) ✅
- **secubox-backup** v1.0.0 — System config and LXC container backup/restore
- **secubox-watchdog** v1.0.0 — Container, service, and endpoint monitoring
- **secubox-tor** v1.0.0 — Tor circuits and hidden services management
- **secubox-exposure** v1.0.0 — Unified exposure settings (Tor, SSL, DNS, Mesh)
- **secubox-mitmproxy** v1.0.0 — WAF with traffic inspection, alerts, and bans
- **secubox-traffic** v1.0.0 — TC/CAKE QoS traffic shaping per interface

All modules include FastAPI backend, Catppuccin frontend, Debian packaging.
Total modules: **41** (was 35)

### Menu.d Fixes ✅
- Added missing menu.d JSON files for exposure, mitmproxy, traffic
- Updated debian/rules to install menu.d files

### Metapackages Updated to v1.1.0 ✅
- **secubox-full** — Now includes all 39 modules (was 14)
- **secubox-lite** — Added portal, hardening; watchdog/backup in suggests
- **repo/README.md** — Updated package list (41 total)

---

## ✅ Previously Done (Session 8)

### secubox-mail Enhancement (v2.1.0) ✅
- **Security features dashboard** — Visual grid with toggle switches
  - DKIM, SpamAssassin, Greylisting, ClamAV controls
  - Security score indicator (0-4)
  - Real-time status for each feature
- **Mail logs viewer** — New tab with configurable line count
- **Mailbox repair** — Per-user repair action
- **DKIM record display** — DNS setup modal shows DKIM record
- **LXC path fix** — Added `-P /srv/lxc` to lxc-info/lxc-attach commands
- **Service permissions** — Run as root for LXC access, removed sandboxing

### secubox-users Enhancement (v1.1.0) ✅
- **usersctl CLI v1.1.0** — Full user management controller
  - Commands: status, list, add, delete, get, enable, disable, passwd, sync, export, import
  - Service provisioning: Nextcloud, Gitea, Email, Matrix, Jellyfin, PeerTube, Jabber
  - Three-fold commands: components, access (JSON output)
  - Consistent v1.1.0 versioning
- **Enhanced API** — Groups, validation, import/export
  - Pydantic models with validation (username 3+ chars, password 8+ chars)
  - Group endpoints with permissions
  - Import/export for bulk user management
  - Service status per user
- **Modern Frontend** — Catppuccin-styled UI
  - User/group tables with action buttons
  - Modal dialogs for create/edit
  - Toast notifications
  - Service status chips with icons
  - Import/export functionality
- **Nginx config** — Frontend + API locations

---

## ✅ Previously Done (Session 7)

### New Modules (2 in Session 7) ✅
- **secubox-repo** (v1.0.0) — APT repository management module
  - repoctl CLI for package management
  - GPG key generation and signing
  - Multi-distribution support (bookworm, trixie)
  - Web dashboard for repository status
  - FastAPI endpoints for remote management

- **secubox-hardening** (v1.0.0) — Kernel and system hardening
  - hardeningctl CLI for security management
  - Sysctl hardening (ASLR, kptr_restrict, SYN cookies, etc.)
  - Module blacklist (uncommon protocols, filesystems)
  - Security benchmark tool
  - Web dashboard with security score

### APT Repository Deployment Scripts ✅
- **export-secrets.sh** — Export GPG + SSH keys for GitHub Actions
- **local-publish.sh** — Local test server (reprepro + Python HTTP)
- **install.sh** — User installation script (`curl | bash`)
- **README updates** — Complete deployment documentation

### Nextcloud File Sync ✅
- **nextcloudctl v1.2.0** — Full Nextcloud LXC management
- **Debian bookworm LXC** — PHP 8.2, Nginx, Redis, SQLite
- **Nextcloud 30.0.4** — Latest stable release
- **Port 9080** — Avoids CrowdSec conflict (8080)
- **Redis caching** — Fixed systemd unit for LXC
- **Admin user** — ncadmin / secubox123
- **WebDAV, CalDAV, CardDAV** — All enabled
- **Bind mounts** — /srv/nextcloud/{data,config} persistent

### Gitea Git Server ✅
- **giteactl v1.4.0** — Full Gitea LXC management
- **Alpine Linux LXC** — Lightweight container via debootstrap
- **Host networking** — No br0 bridge required (lxc.net.0.type = none)
- **Two-phase install** — install-init.sh → start-gitea.sh
- **PATH/HOME fix** — Export environment for su-exec
- **WORK_PATH config** — Gitea 1.22.6 requirement
- **Admin user** — Created via `giteactl user add`
- **SSH + HTTP** — Port 2222 (SSH), 3000 (HTTP)
- **LFS support** — Enabled with proper config

### AppArmor Security Profiles ✅
- **Base profile** — secubox-base abstractions for all services
- **Hub profile** — Menu, systemd, monitoring access
- **Mail profile** — LXC containers, ACME, mail data
- **WireGuard profile** — wg tools, config, QR codes
- **CrowdSec profile** — cscli, logs, API socket
- **Generic profile** — For simple API services
- **Install script** — scripts/install-apparmor.sh

### Audit Rules ✅
- **50-secubox.rules** — Comprehensive audit rules
- **Config changes** — secubox, wireguard, mail, haproxy
- **Security events** — JWT access, privilege escalation, failed access
- **System changes** — nftables, netplan, SSH, sudo
- **Install script** — scripts/install-audit.sh

### ClamAV Antivirus ✅
- **mailserverctl v2.6.0** — av setup/enable/disable/status/update commands
- **ClamAV daemon + milter** — Installed in LXC container via apt
- **Postfix integration** — Via clamav-milter on port 8894
- **Freshclam** — Automatic virus definition updates
- **API endpoints** — /av/status, /av/setup, /av/enable, /av/disable, /av/update
- **secubox-mail v2.0.0** — Full mail security stack complete

### Postgrey Greylisting ✅
- **mailserverctl v2.5.0** — grey setup/enable/disable/status commands
- **Postgrey** — Installed in LXC container via apt
- **Whitelist** — Common mail providers (Google, Microsoft, Yahoo, etc.)
- **Postfix integration** — smtpd_recipient_restrictions with policy service
- **Auto-whitelist** — After 5 successful deliveries from same sender
- **API endpoints** — /grey/status, /grey/setup, /grey/enable, /grey/disable
- **secubox-mail v1.9.0** — Deployed and tested

### Service Fixes ✅
- **secubox-haproxy v1.1.1** — Fixed systemd namespace error when HAProxy not installed
- **RuntimeDirectory=haproxy** — Automatically creates /run/haproxy
- **All 32 services** — Now running on VM

### SpamAssassin Integration ✅
- **mailserverctl v2.4.0** — spam setup/enable/disable/status/update commands
- **SpamAssassin + spamc** — Installed in LXC container
- **Postfix content filter** — Integrates via spamfilter pipe
- **Bayes learning** — Auto-learn enabled by default
- **API endpoints** — /spam/status, /spam/setup, /spam/enable, /spam/disable

### Mail Autodiscover ✅
- **Thunderbird/Evolution** — /mail/config-v1.1.xml (Mozilla autoconfig)
- **Outlook** — /autodiscover/autodiscover.xml (Microsoft format)
- **Apple iOS/macOS** — /{domain}.mobileconfig (configuration profile)
- **Well-known** — /.well-known/autoconfig/mail/config-v1.1.xml
- **Public endpoints** — No authentication required for client access

### OpenDKIM Integration ✅
- **mailserverctl v2.3.0** — Full DKIM/OpenDKIM support
- **dkim setup** — Complete setup (keygen + install + configure + sync)
- **dkim keygen** — Generate 2048-bit RSA key pair
- **dkim status** — Show key, DNS record, service status
- **OpenDKIM** — Installed in LXC container with milter
- **Postfix integration** — smtpd_milters configured
- **DNS records** — Standard and BIND format output
- **API endpoints** — /dkim/status, /dkim/setup, /dkim/keygen, /dkim/sync

### ACME Certificate Support ✅
- **mailserverctl v2.2.0** — ACME certificate management
- **acme.sh integration** — issue, renew, install commands
- **SSL/TLS commands** — ssl status, ssl selfsigned
- **Dovecot SSL** — TLS 1.2+ configuration
- **API endpoints** — /acme/status, /acme/issue, /acme/renew

### Previous: Mail Server LXC ✅
- **mailserverctl v2.1.0** — Debian bookworm via debootstrap
- **roundcubectl v1.4.0** — Debian bookworm via debootstrap
- **Host networking** — LXC containers use `lxc.net.0.type = none`
- **Three-fold commands** — Both scripts have `components` and `access` JSON commands
- **Postfix + Dovecot** — Tested and working with authentication

### VM Service Count ✅
- **30 services running** — All SecuBox APIs active
- **Disk expanded** — VM disk resized to 16GB for Debian LXC

---

## ⚠️ Known Issues

### Debian LXC Disk Space
- **VM root partition** — Only 2.4GB, Debian debootstrap needs ~500MB per container
- **Solution** — Move /srv/lxc to /data partition (symlinked)
- **Recommendation** — Production systems need 8GB+ root partition

---

## ⬜ Next Up

### PRIORITY: Extend Existing Modules (Before Adding New)
Per user request: Focus on completing and enhancing existing modules before porting new ones from OpenWRT.

**Modules to Enhance:**
1. ~~**secubox-netmodes** — Integrate secubox-net-detect for auto-configuration~~ ✅ Done (Session 26)
2. ~~**secubox-system** — Add board detection info to system status~~ ✅ Done (Session 30)
3. ~~**secubox-core** — Integrate kiosk setup option in admin~~ ✅ Done (Session 30)
4. ~~**secubox-hub** — Add network mode selection to dashboard~~ ✅ Done (Session 30)
5. ~~**secubox-portal** — Add device-specific theming based on board~~ ✅ Done (Session 31)

**✅ All Priority Module Enhancements Complete!**

### SecuBox SOC — Phase 5: Hierarchical Mode ✅

**Phase 5 implements multi-tier deployment:**
- [x] Mode configuration (edge/regional/central) via API
- [x] Regional-to-central aggregation (upstream push)
- [x] Cross-region threat correlation
- [x] Multi-tier enrollment workflow
- [x] Global View page for central SOC
- [x] Settings page for mode configuration
- [ ] Deploy and test multi-tier setup (requires hardware)

**Packages Updated:**
- `secubox-soc-gateway_1.1.0-1_all.deb` (21KB) - Added hierarchy lib
- `secubox-soc-web_1.1.0-1_all.deb` (67KB) - Added GlobalView & Settings

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                      CENTRAL SOC                             │
│   secubox-soc-gateway (central) + secubox-soc-web (React)   │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  REGIONAL SOC   │ │  REGIONAL SOC   │ │  REGIONAL SOC   │
│  (Paris)        │ │  (London)       │ │  (New York)     │
└─────────────────┘ └─────────────────┘ └─────────────────┘
       │                   │                   │
   ┌───┴───┐           ┌───┴───┐           ┌───┴───┐
   ▼       ▼           ▼       ▼           ▼       ▼
┌─────┐ ┌─────┐     ┌─────┐ ┌─────┐     ┌─────┐ ┌─────┐
│Edge │ │Edge │     │Edge │ │Edge │     │Edge │ │Edge │
│Node │ │Node │     │Node │ │Node │     │Node │ │Node │
└─────┘ └─────┘     └─────┘ └─────┘     └─────┘ └─────┘
```

**Build & Test Live USB:**
```bash
sudo bash image/build-live-usb.sh --local-cache
# Flash and test on x64 hardware or VM
```

### Phase 8: Applications (In Progress)

**Completed:**
- [x] secubox-ollama — LLM inference ✅
- [x] secubox-jellyfin — Media server ✅
- [x] secubox-lyrion — Audio server ✅
- [x] secubox-zigbee — IoT gateway ✅
- [x] secubox-localai — Local AI inference ✅
- [x] secubox-jabber — XMPP messaging ✅
- [x] secubox-magicmirror — Smart display ✅
- [x] secubox-mmpm — MagicMirror packages ✅
- [x] secubox-redroid — Android container ✅

**Phase 9 (Built, not deployed):**
- [x] secubox-vault — Secrets management
- [x] secubox-cloner — System backup/restore
- [x] secubox-vm — Virtualization (KVM/LXC)

**Phase 10 (Built, not deployed):**
- [x] secubox-wazuh — SIEM
- [x] secubox-ossec — Host IDS

> See [REMAINING-PACKAGES.md](REMAINING-PACKAGES.md) for full Phase 8-10 inventory

---

### Mail Server ✅ COMPLETE
All optional mail security features implemented:
- DKIM signing (OpenDKIM)
- Spam filtering (SpamAssassin)
- Greylisting (Postgrey)
- Virus scanning (ClamAV)

### CI/CD Workflows ✅
- **build-packages.yml** — Dynamic matrix for all 33 packages
- **build-image.yml** — System images for 5 boards (MOCHAbin, ESPRESSObin, VM)
- **Dual architecture** — arm64 + amd64 builds
- **Auto-publish** — On tag v* → APT repo + GitHub Release
- **GPG signed** — SHA256SUMS with GPG signatures
- **build-all.sh** — Local build script for development

### APT Repository Scripts ✅
- **export-secrets.sh** — Export GPG keys and SSH deploy keys for GitHub Actions
- **local-publish.sh** — Local testing with Python HTTP server
- **install.sh** — User installation script for apt.secubox.in
- **Deployment docs** — Complete GitHub secrets configuration

### Infrastructure
1. **Configure GitHub Secrets** — Add GPG_PRIVATE_KEY, DEPLOY_SSH_KEY, DEPLOY_KNOWN_HOSTS
2. **Deploy apt.secubox.in server** — Run setup-repo-server.sh on VPS
3. **Create initial release** — Tag v1.0.0 to trigger workflows
4. **Documentation** — User guide, API docs

---

## ✅ Précédemment terminé

### Three-fold Architecture ✅
- **6 modules upgraded** — vhost, haproxy, streamlit, gitea, metablogizer, roundcube
- **All *ctl scripts have** — `components` and `access` JSON commands
- **Version bumps** — 1.1.0 for all modules with three-fold

### Mail Integration ✅
- **mail-lxc and webmail-lxc** — Integrated into secubox-mail (no standalone UI)
- **secubox-mail 1.3.0** — Full mail management with installation wizard
- **roundcubectl** — Added three-fold commands (components, access)
- **API endpoints** — /webmail/start, /webmail/stop, /webmail/install, /settings, /dkim/setup

### Mail Frontend ✅
- **Install banner** — Shows when mail not installed with wizard button
- **Settings tab** — Domain, hostname, IP, ports configuration
- **Per-component controls** — Install/Start/Stop buttons for mail server and webmail
- **DNS Setup modal** — Shows required DNS records
- **DKIM Setup** — Generate DKIM keys with one click

### Maintainer Update ✅
- **Gerald KERMA <devel@cybermind.fr>** — Propagated to 33 control + 33 changelog files

### Authentication Fix ✅
- **JWT secret mismatch fixed** — Portal and modules now use same secret
- **Fixed redirect paths** — All 12 modules now redirect to `/portal/login.html` instead of `/login/`
- **Token flow working** — Login → localStorage → API auth chain verified

### New Modules (4) ✅
- **secubox-c3box** — Services Portal page with links to all SecuBox services
- **secubox-gitea** — Gitea Git Server management (LXC, repos, users, backups)
- **secubox-nextcloud** — Nextcloud File Sync (LXC, storage, users, backups)
- **secubox-portal** — Added to navbar, links to services portal

### Module Count ✅
- **33 packages total** — 30 services + 3 new modules
- **29 services running** — All core + new modules active on VM
- **Menu shows 26 modules** — Organized in 6 categories

---

## ✅ Précédemment terminé

### WAF + HAProxy Integration ✅
- **secubox-waf** : Web Application Firewall (300+ rules, 17 categories)
  - SQLi, XSS, RCE, LFI detection
  - VoIP/SIP, XMPP, router botnet patterns
  - CrowdSec auto-ban integration
  - Rate limiting per IP
- **secubox-haproxy** : Updated with WAF MITM integration
  - `/waf/status`, `/waf/toggle`, `/waf/routes`, `/waf/sync-routes`
  - Per-vhost WAF bypass controls
  - Config generation routes traffic through waf_inspector backend

### 2-Layer Architecture Modules ✅
- **secubox-mail-lxc** : LXC container for Postfix/Dovecot
- **secubox-webmail-lxc** : LXC container for Roundcube/SOGo
- **secubox-publish** : Unified publishing dashboard (streamlit + streamforge + droplet + metablogizer)

### New Modules Ported (4) ✅
- **secubox-dns** : DNS Master / BIND zone management (zones, records, DNSSEC)
- **secubox-mail** : Email server Postfix/Dovecot (users, aliases, dkim)
- **secubox-users** : Unified identity management (7 services: nextcloud, matrix, gitea, email, jellyfin, peertube, jabber)
- **secubox-webmail** : Roundcube/SOGo management (config, cache, plugins)

### Script Fix ✅
- **scripts/new-module.sh** : Removed manual systemd installation (conflicts with dh_installsystemd)

### Dynamic Menu System ✅
- **sidebar.js** : Shared sidebar component for all modules
- **Menu API** : `/api/v1/hub/menu` returns 22 modules in 6 categories
- **menu.d/** : JSON definitions per package (installed via debian/rules)
- **CSS fixes** : Added missing variables (--cyan, --yellow, --purple) to all modules

### Module Scaffold ✅
- **.claude/skills/module.md** : Skill documentation
- **scripts/new-module.sh** : Complete package scaffold script

### All Services Running ✅
26 secubox-* services active on VM:
- secubox-hub, secubox-system
- secubox-crowdsec, secubox-wireguard, secubox-auth, secubox-nac
- secubox-netmodes, secubox-dpi, secubox-qos, secubox-vhost
- secubox-netdata, secubox-mediaflow
- secubox-haproxy, secubox-cdn, secubox-waf
- secubox-droplet, secubox-streamlit, secubox-streamforge, secubox-metablogizer
- secubox-dns, secubox-mail, secubox-users, secubox-webmail
- secubox-mail-lxc, secubox-webmail-lxc, secubox-publish

---

## ✅ Completed this session

### Build & Integration ✅
- **30 packages built** — All packages compile successfully
- **27 services running** — Full deployment on VM
- **27 nginx configs** — Modular API routing working
- **Fixed prerm scripts** — No longer remove nginx configs on upgrade
- **Fixed hub uptime** — int(float()) for /proc/uptime parsing
- **Fixed portal login** — Now stores JWT token to localStorage
- **Fixed logout** — Clears tokens and redirects properly

---

## ⬜ Next Up

1. **Deploy apt.secubox.in** — Setup reprepro server
2. **Publish packages** — Upload all 30 debs to APT repo
3. **Documentation** — User guide, API docs

---

## 🛠️ Quick Commands

```bash
# SSH to VM (key auth configured)
ssh -p 2222 root@localhost

# Create new module
./scripts/new-module.sh myapp "Description" apps "🚀" 500

# Build package
cd packages/secubox-<name> && dpkg-buildpackage -us -uc -b

# Deploy to VM
scp -P 2222 *.deb root@localhost:/tmp/ && ssh -p 2222 root@localhost "dpkg -i /tmp/*.deb"

# Check menu API (should show 22 modules)
curl -sk https://localhost:8443/api/v1/hub/menu | jq '.total_modules'
```

---

## 🗓️ Historique récent

- **2026-03-27** (Session 21):
  - Fixed live ISO boot console issues (flickering, no login prompt)
  - Masked 14 services that cause restart loops on live boot
  - Fixed getty autologin conflict with live-config
  - Disabled martian packet logging and systemd status messages
  - Added debug boot menu entries (rescue, emergency, no-preseed)
  - Live ISO now boots with stable console login
  - Commit pushed: `288b27a Fix live ISO boot console issues`

- **2026-03-26** (Session 20):
  - x64 Installer ISO build system: build-installer-iso.sh (hybrid live/installer)
  - C3Box clone scripts: export-c3box-clone.sh, build-c3box-clone.sh
  - streamlitctl v1.0.0: Streamlit LXC controller (521 lines)
  - Exported C3Box config: 50 packages, 3 LXC containers, full settings
  - VSCode tasks for ISO building added
  - Commit pushed: `141b0c0 Add x64 installer ISO and C3Box clone build system`

- **2026-03-26** (Session 19):
  - Socket directory fix: secubox-runtime.service ensures /run/secubox exists
  - ReDroid integration: Android in Container LXC setup scripts
  - VSCode tasks for ReDroid management added
  - Both commits pushed to GitHub

- **2026-03-26** (Session 18):
  - Master-Link Admin Dashboard v1.6.0
  - Localhost-only API endpoints
  - sbx-mesh-invite CLI tool v1.5.0
  - Multi-master support v1.4.0

- **2026-03-26** (Session 16):
  - UI theme toggle fixed (light/dark P31 phosphor)
  - Collapsed sidebar categories by default
  - Fixed 35+ pages with wrong body class
  - 45 module screenshots captured
  - docs/UI-GUIDE.md created
  - docs/OPENWRT-DEBIAN-COMPARISON.md created (103 vs 52 modules)
  - scripts/fix-navbar.sh created

- **2026-03-25** (Session 15):
  - Maintainer standardized to Gerald KERMA on all 51 packages
  - JWT auth added to secubox-mesh
  - Go daemon reorganized to daemon/ directory
  - Unix socket control server implemented

- **2026-03-21** (Session 2):
  - WAF module created (300+ rules, CrowdSec integration)
  - HAProxy WAF MITM integration complete
  - 2-layer architecture: mail-lxc, webmail-lxc containers
  - Unified secubox-publish module
  - All 26 services running on VM

- **2026-03-21** (Session 1):
  - Ported 4 new modules: dns, mail, users, webmail
  - Fixed new-module.sh script (removed manual systemd install)
  - Dynamic menu now shows 22 modules in 6 categories
  - All 22 services running on VM

- **2025-03-21** :
  - Dynamic menu system complete (18 modules, 6 categories)
  - Shared sidebar.js for consistent navigation
  - CSS variables fixed across all modules
  - Module scaffold skill created

- **2025-03-20** :
  - Phase 4 complete: apt.secubox.in (reprepro, GPG, CI)
  - Local cache build system added
  - Image VM x64 built successfully

## VirtualBox Kiosk Fix (2026-04-08)

**Problem**: Kiosk mode causes black screen in VirtualBox due to X11/graphics driver issues.

**Solution**: 
1. Skip kiosk service on VirtualBox (detect via `systemd-detect-virt | grep oracle`)
2. Default target set to `multi-user.target` (console) instead of `graphical.target`
3. Users access via SSH or web UI when testing in VirtualBox
4. Kiosk works normally on real hardware

**Files modified**:
- `image/systemd/secubox-kiosk.service` - Added VirtualBox skip check
- `image/build-live-usb.sh` - Changed default target to multi-user

**Testing**:
- VirtualBox: Boot to console, access via SSH (port 2222) or web UI (port 9443)
- Real hardware: Kiosk starts automatically as before

## Dashboard Real Data Fix (2026-04-14)

**Problem**: Dashboard showing placeholder values:
- Memory: -/-
- Storage: -/-
- LAN/BR-WAN: -
- Module versions: all showing "-"

**Root Causes**:
1. `loadNetwork()` had hardcoded IP addresses instead of using API data
2. No calls to `/memory` and `/disk` endpoints for actual used/total values
3. `network_summary` API didn't return IP addresses
4. Module version info wasn't included in service status data

**Solutions**:
1. Updated `network_summary` API to return actual LAN/WAN IP addresses
2. Added `loadMemory()` and `loadDisk()` functions to fetch real data
3. Updated `loadNetwork()` to use API response for IP addresses
4. Added `_get_package_version()` helper to fetch installed package versions
5. Updated modules table to display actual versions from dpkg

**Files Modified**:
- `packages/secubox-hub/api/main.py`:
  - Enhanced `network_summary` endpoint with IP address discovery
  - Added `_get_package_version()` function
  - Updated `_svc()` to include package versions
- `packages/secubox-hub/www/index.html`:
  - Fixed `loadNetwork()` to use API data instead of hardcoded IPs
  - Added `loadMemory()` and `loadDisk()` functions
  - Updated modules table to show real versions
  - Added new functions to refresh cycle

## EspressoBin Slipstream Consistency (2026-04-14)

**Problem**: EspressoBin build only checked `output/debs` while AMD64 also checked cache.

**Solution**: Updated `build-ebin-live-usb.sh` to:
- Check both `output/debs` and `~/.cache/secubox/debs`
- Prefer output/debs over cache (for newer local builds)
- Install secubox-core first as dependency
- Use `--force-overwrite` for duplicate files

**Files Modified**:
- `image/build-ebin-live-usb.sh` - Consistent slipstream with AMD64 build

## EspressoBin Build Fix - $HOME Issue (2026-04-14)

**Problem**: EspressoBin live USB build failed after step 3/7, jumping to cleanup. The slipstream step couldn't find packages.

**Root Cause**: When running with `sudo`, `$HOME` becomes `/root` instead of `/home/reepost`. The script used `${HOME}/.cache/secubox/debs` which resolved to `/root/.cache/secubox/debs` (non-existent).

**Solution**: Updated `build-ebin-live-usb.sh`:
1. Added `SUDO_USER` detection to get original user's home directory
2. Changed `ls` to `find` to avoid `set -e` failures when no files match

```bash
# Get original user's home when running with sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME="$HOME"
fi
CACHE_DEBS="${USER_HOME}/.cache/secubox/debs"
```

**Files Modified**:
- `image/build-ebin-live-usb.sh` - Fixed slipstream $HOME handling

## Build Status (2026-04-14 18:20)

- **AMD64 Live USB**: ✅ Complete (8GB image)
  - Location: `output/secubox-live-amd64-bookworm.img`
  - 126 packages slipstreamed

- **EspressoBin Live USB**: 🔄 Building (ARM64/QEMU emulation)
  - Build restarted with fixed script
  - Progress: Debootstrap phase

## Build Complete (2026-04-14 22:45)

### AMD64 Live USB ✅
- **Image**: `output/secubox-live-amd64-bookworm.img` (8.0 GB)
- **SHA256**: Available at `.img.sha256`
- All 126 SecuBox packages slipstreamed

### EspressoBin V7 Live USB ✅
- **Image**: `output/secubox-espressobin-v7-live-usb.img` (2.0 GB)
- **SHA256**: Available at `.img.sha256`
- All SecuBox packages slipstreamed
- Includes secubox-flash-emmc tool

### Fixes Applied:
1. Fixed `$HOME` issue in EspressoBin build when running with sudo
2. Changed `ls` to `find` to avoid `set -e` failures
3. Added error handling for dpkg installation step
4. Fixed grep in package count verification

### How to Use:

**AMD64 (x86_64):**
```bash
sudo dd if=output/secubox-live-amd64-bookworm.img of=/dev/sdX bs=4M status=progress
```

**EspressoBin V7:**
```bash
sudo dd if=output/secubox-espressobin-v7-live-usb.img of=/dev/sdX bs=4M status=progress
# Boot from USB, then run:
secubox-flash-emmc
```


---

## 2026-04-20: Remote UI Enhanced Architecture

### New Gadget Modes (secubox-otg-gadget.sh v2.0)

| Mode | Functions | Purpose |
|------|-----------|---------|
| **normal** | ECM + ACM | Network + Serial (default) |
| **flash** | Mass Storage + ACM | Boot EspressoBin from USB for recovery/flashing |
| **debug** | ECM + Mass Storage + ACM | Network + File exchange + Serial |

### Round UI as Remote Control (Not Just Clock)

The Round UI should function as a **full remote control interface**:

1. **Mode Selector**
   - Touch to switch between Normal/Flash/Debug modes
   - Visual indicator of current mode

2. **Status Panels**
   - Normal: EspressoBin metrics (CPU, MEM, DISK, etc.)
   - Flash: Boot status, flash progress, U-Boot console
   - Debug: Connection status, file transfer, serial output

3. **Interactive Controls**
   - Reboot EspressoBin
   - Start/Stop services
   - Switch network modes
   - Trigger eMMC flash

4. **U-Boot Console**
   - In Flash mode, display serial output from /dev/ttyGS0
   - Send commands to U-Boot

### Files Updated

- `remote-ui/round/secubox-otg-gadget.sh` - Added flash/debug modes + status JSON
- `image/firstboot.sh` - Added filesystem expansion for eMMC

### Next Steps

1. Update Round UI index.html with mode-aware interface
2. Add WebSocket or polling for serial console output
3. Create flash progress indicator
4. Test USB enumeration between Pi Zero and EspressoBin

### Current Issue

Pi Zero USB enumeration failing with error -110 (timeout). Possible causes:
- Cable issue (data lines)
- Power issue
- Gadget not ready fast enough


---

## 2026-04-22: HyperPixel DPI / I2C Pin Conflict (RESOLVED)

### Issue
HyperPixel 2.1 Round display not working on Pi Zero W - screen stays blank.

### Root Cause
Kernel error: `pin gpio2 already requested by i2c; cannot claim for dpi`

The DPI display driver needs GPIO pins 2/3, but `dtparam=i2c_arm=on` enables I2C on those same pins, causing a conflict.

### Solution
Remove from config.txt:
```
# DO NOT USE - conflicts with DPI:
# dtparam=i2c_arm=on
# dtparam=spi=on
```

The hyperpixel2r overlay:
- Uses **i2c10** (software I2C) for touch controller
- LCD init uses **pigpio software SPI** (bit-banging), not hardware SPI

### Files Updated
- `remote-ui/round/build-eye-remote-image.sh` - Removed i2c_arm/spi from config
- Config.txt on SD card - Disabled conflicting parameters

### Lesson Learned
When using DPI displays on Raspberry Pi, avoid enabling standard I2C/SPI that may conflict with DPI GPIO pins.

---

## 2026-04-22: Pi Zero W requires explicit DPI timings (INVESTIGATING)

### Issue
Display still blank after fixing I2C conflict. Pi Zero W not booting or not creating framebuffer.

### Root Cause (suspected)
The `hyperpixel2r` overlay may be designed for KMS mode only. Pi Zero W (BCM2835) doesn't support KMS, so the overlay alone doesn't configure DPI output.

### Solution
Add explicit DPI timing parameters to config.txt:

```
enable_dpi_lcd=1
display_default_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 59 480 0 15 60 15 0 0 0 60 0 19200000 6
framebuffer_width=480
framebuffer_height=480
```

These settings explicitly tell the VideoCore GPU how to drive the DPI display, bypassing the need for KMS driver support.

### Testing
- Awaiting confirmation that explicit DPI settings fix the display

---

## 2026-05-06: Session 106 - Heartbeat, LEDs, GitHub Issues Workflow

### Accomplished

1. **GitHub Issues Workflow** ajouté à CLAUDE.md
   - Synchronisation obligatoire WIP/TODO ↔ GitHub Issues
   - Règle: jamais de fermeture automatique, validation manuelle user

2. **LED Investigation (Issue #39)**
   - `CONFIG_LEDS_IS31FL319X is not set` dans kernel Debian
   - I2C bus errors (mv64xxx_i2c_fsm: Ctlr Error)
   - DTB Factory GST n'a PAS la config IS31FL3199
   - Différence: GST kernel 5.4.163 vs mainline avec support LED

3. **References GST intégrées**
   - `docs/references/gst/mochabin-release-v4.10.txt`
   - `docs/references/gst/MOCHABIN-BOX-block-diagram-Jan10-2020.pdf`

4. **Issue #38 vérifiée** - Navbar health checks déployés
   - `sidebar.js` avec healthEndpoints
   - Classes status-dot active/warning/error/disabled

### Technical References (memorized)

| Doc | Location |
|-----|----------|
| GST Release Notes | ~/DEVEL/GST/ReleaseNote.txt |
| GST Downloads | ~/DEVEL/GST/Downloads/Mochabin/ |
| Marvell Datasheets | ~/DEVEL/ARMADA/*.pdf |
| MOCHAbin Images | ~/DEVEL/MOCHABIN/ |

### LEDs - Root Cause

Le DTB factory GST (v4.10) ne configure PAS le contrôleur LED IS31FL3199.
Le support a été ajouté dans le DTS upstream Linux (torvalds/linux) mais:
1. Kernel doit être compilé avec CONFIG_LEDS_IS31FL319X=y
2. DTS doit inclure le noeud is31fl3199 sur i2c@701100
3. GPIO SDB (62) doit être contrôlé pour activer la puce

### Next Steps

- [ ] Compiler kernel avec CONFIG_LEDS_IS31FL319X
- [ ] Ou continuer avec userspace i2cset après fix I2C
- [ ] Privatiser repo gkerma/secubox-openwrt
- [ ] Mettre à jour licence secubox-openwrt
- [ ] Deploy live.maegia.tv


## CI Sync 2026-07-21
- Packages: 163
- Endpoints: 3003
- Migration: 82%
- Commits: 2915

## CI Sync 2026-07-22
- Packages: 164
- Endpoints: 3010
- Migration: 82%
- Commits: 2941

## CI Sync 2026-07-23
- Packages: 164
- Endpoints: 3010
- Migration: 82%
- Commits: 2948

## CI Sync 2026-07-24
- Packages: 164
- Endpoints: 2982
- Migration: 82%
- Commits: 2976

## CI Sync 2026-07-25
- Packages: 164
- Endpoints: 2988
- Migration: 82%
- Commits: 3022

## CI Sync 2026-07-26
- Packages: 166
- Endpoints: 3011
- Migration: 82%
- Commits: 3098

## CI Sync 2026-07-27
- Packages: 166
- Endpoints: 3019
- Migration: 82%
- Commits: 3140

## CI Sync 2026-07-28
- Packages: 167
- Endpoints: 3025
- Migration: 82%
- Commits: 3189

## CI Sync 2026-07-29
- Packages: 168
- Endpoints: 2999
- Migration: 81%
- Commits: 3225

## CI Sync 2026-07-30
- Packages: 169
- Endpoints: 2996
- Migration: 81%
- Commits: 3280

## CI Sync 2026-07-31
- Packages: 169
- Endpoints: 2996
- Migration: 81%
- Commits: 3285

## CI Sync 2026-08-01
- Packages: 169
- Endpoints: 2997
- Migration: 81%
- Commits: 3300

## CI Sync 2026-08-02
- Packages: 169
- Endpoints: 2998
- Migration: 81%
- Commits: 3323

## CI Sync 2026-08-03
- Packages: 169
- Endpoints: 2998
- Migration: 81%
- Commits: 3326

## CI Sync 2026-08-17
- Packages: 176
- Endpoints: 3108
- Migration: 79%
- Commits: 3948

## CI Sync 2026-08-18
- Packages: 177
- Endpoints: 3119
- Migration: 78%
- Commits: 3970

## CI Sync 2026-08-20
- Packages: 177
- Endpoints: 3126
- Migration: 78%
- Commits: 4085

## CI Sync 2026-08-21
- Packages: 177
- Endpoints: 3127
- Migration: 78%
- Commits: 4111

## CI Sync 2026-08-23
- Packages: 178
- Endpoints: 3127
- Migration: 78%
- Commits: 4279

## CI Sync 2026-08-24
- Packages: 180
- Endpoints: 3127
- Migration: 77%
- Commits: 4342

## CI Sync 2026-08-25
- Packages: 181
- Endpoints: 3136
- Migration: 77%
- Commits: 4519

## CI Sync 2026-08-26
- Packages: 181
- Endpoints: 3138
- Migration: 77%
- Commits: 4542

## CI Sync 2026-08-28
- Packages: 182
- Endpoints: 3154
- Migration: 76%
- Commits: 4650

## CI Sync 2026-08-29
- Packages: 182
- Endpoints: 3160
- Migration: 76%
- Commits: 4747

## CI Sync 2026-08-30
- Packages: 182
- Endpoints: 3160
- Migration: 76%
- Commits: 4749
