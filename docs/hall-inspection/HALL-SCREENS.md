<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# HALL-SCREENS — description écran par écran

Parcours d'un **visiteur invité** sur https://hall.gk2.secubox.in/, le 2026-10-02, par **Chromium headless 145** (Playwright), JavaScript exécuté. Chaque description vient de ce que le navigateur a chargé et affiché ; rien n'est tiré du code source ni de la documentation.

**Deux conditions de test** (voir HALL-MAP.md) : (A) depuis le réseau local de la box, vu comme LAN ; (B) le même Chromium avec l'en-tête `X-Forwarded-For: 203.0.113.50`, qui simule un visiteur externe. Quand l'écran diffère, c'est dit. Toutes les requêtes d'écriture (POST/PUT/DELETE) ont été bloquées par le navigateur : aucun formulaire n'a été envoyé.

Étiquettes : `[TESTÉ DANS CHROMIUM]` · `[AFFICHE MAIS NON FONCTIONNEL]` · `[EXISTE MAIS NON ACCESSIBLE INVITÉ]`. Captures dans `screenshots/`.


## 1. Fenêtre de bienvenue (première visite)
- **URL** : `https://hall.gk2.secubox.in/` · **Titre** : « SecuBox Hall » · **HTTP** 200 · capture `01-bienvenue.png`
- **Texte visible** : « PREMIER ABORD · VOTRE BUREAU SOUVERAIN — Le Hall vous accueille. Ce n'est pas un portail de liens : chaque service de la box habite le Hall en une carte vivante — on y lit, écoute, regarde et surfe sans jamais le quitter. »
- **Quatre gestes** : Ranger (poignée ⠿, ordre gardé), Épingler (★, bande de favoris, un favori se partage et se répète), Voir & écouter (coller un lien dans la barre du viewer : lecteur souverain sans pub ni Google), Surfer (taper une adresse dans la recherche : la box relaie, pisteurs coupés).
- **Explorer le parc** : menu Services (« Accueil · Services · Système »), survol d'une carte, puces cliquables, aide « ? » de chaque carte, puis un bandeau « La barre d'adresse est un navigateur souverain » avec les pastilles traqueurs · pubs · cookies · notifs · pop-ups.
- **Bouton** : « Entrer dans le Hall → » (`#bienv-entrer`). **Tout le Hall reste derrière la fenêtre, floutée, tant qu'on ne clique pas.** `[TESTÉ DANS CHROMIUM]`


## 2. Hall — bureau d'accueil
- **URL** : `https://hall.gk2.secubox.in/` · **Titre** : « SecuBox Hall » · captures `02-hall-accueil.png`, `03-hall-accueil-pleine-page.png` (LAN), `51-externe-accueil.png` (externe simulé), `42-mobile-accueil.png` (390×844)
- **Chargement** : 257 réponses réseau (79 scripts, 68 appels `fetch`, 37 documents, 37 images, 29 feuilles de style, 4 polices, 3 médias) : 239 en 200, 2 en 206 (média), 6 en 401 (`webos/session`, `vault/moi`, `vault/etat`, `openpgp/moi`, `sbxid/moi`, `acces/file`), et 10 abandonnées — 8 sont les cadres des cartes réservées à une session (Sécurité, Renseignement, Coffre, Mon coffre, Zigbee, Mes sites, Mes comptes, DPI) que le Hall charge puis retire pour un invité ; 2 sont une écriture radio bloquée par mon test.
- **Barre du haut** : logo SbX avec halo animé et pastille « 1 » (Diffusions du parc) · menu « 🗂️ Services ▾ » · champ « chercher un service, ou surfer une adresse… » · trois boutons ronds (📻 Agrandir, 🔊 Ouvrir le lecteur, 📡 Diffusion en direct) · ◐ thème papier/nuit · profil « Invité — ○ Non connecté » · bouton « Lexie ».
- **Mosaïque** : 17 cartes vivantes en 4 colonnes depuis le LAN (16 en visiteur externe, voir HALL-MAP.md §4). Chaque carte porte une poignée ⠿, une étoile ★ et un « ? » d'aide.
- **Bas d'écran** : barre « Volume général » (100 %), deux lecteurs flottants (radio et viewer) avec ⏮ ❚❚ ⏭, volume, ⤢ agrandir, ⌄ ranger, ✕ fermer ; fil d'Ariane « Hall › Accueil » ; pied « nœud secubox-mochabin · ◆ 81 en ligne · ● 113 modules · hall.gk2.secubox.in — mon bureau numérique souverain : mes services et mes données, hébergés chez moi sur ma SecuBox, sous mon contrôle. »
- **Animations observées** : `logohalo`, `notifbat` (pastille), `medcycle` (médaillons), `fpulse` (pulsation des boutons flottants) ; les cartes se rafraîchissent seules (pistes qui avancent, minuteurs).
- `[TESTÉ DANS CHROMIUM]`


## 3. Menus et panneaux de la barre du haut
| Élément | Ce qui s'affiche | Capture | Étiquette |
|---|---|---|---|
| Menu « Services ▾ » | Liste « Services principaux » de 31 entrées, chacune avec un point d'état, ⚙️ (console d'administration) et ⧉ (nouvel onglet) ; en pied « 🏠 Tableau d'accueil » et « 🗄️ Tout le parc… » | `04-menu-services.png` | `[TESTÉ DANS CHROMIUM]` |
| Recherche « radio » | Ouvre la vue « Système — tous les modules » filtrée : Radio (Esprit) et Meshtastic (Maillage) | `05-recherche-radio.png` | `[TESTÉ DANS CHROMIUM]` |
| Recherche « example.com » + Entrée | Ouvre le Surf : la box relaie la page (`surf-example-com.gk2.secubox.in`), bandeau « example.com — relayé, pisteurs coupés » | `34-surf-example-com.png` | `[TESTÉ DANS CHROMIUM]` |
| ◐ Thème | Bascule papier ↔ nuit, tout le Hall change | `06-theme-nuit.png` | `[TESTÉ DANS CHROMIUM]` |
| Profil « Invité » | Menu : « Demander un accès… », « Connexion SecuBox… », « Ordre actuel = défaut », « Réinitialiser l'affichage », « Revoir l'accueil », « Aide du Hall », puis « DIFFUSIONS (1) » | `07-profil-invite.png` | `[TESTÉ DANS CHROMIUM]` |
| « Connexion SecuBox… » | Ouvre une fenêtre `admin.gk2.secubox.in/login.html` (« SecuBox — Login ») | `70-connexion-secubox.png` | `[TESTÉ DANS CHROMIUM]` |
| « Demander un accès… » | Ouvre l'écran Accès (`/i/acces/`) | `71-demander-acces.png` | `[TESTÉ DANS CHROMIUM]` |
| « Aide du Hall » | Guide : trois espaces (Accueil, Services, Système), gestes, FAQ | `72-aide-du-hall.png` | `[TESTÉ DANS CHROMIUM]` |
| Bouton « Lexie » | Panneau « Lexie » : « Service vocal injoignable (HTTP 401). Vérifiez secubox-voice. » | `08-lexie.png` | `[AFFICHE MAIS NON FONCTIONNEL]` |
| Pastille « 1 » / 📡 | « Diffusion en direct — rejoindre : Wyclef Jean - 911 (Official Video) ft. Mary J. Blige » : un lecteur plein écran avec barre « Direct — … », ↻, ■, ✕ | `11-diffusion-direct.png` | `[TESTÉ DANS CHROMIUM]` |
| 📻 Agrandir / 🔊 Ouvrir le lecteur | Ouvre le lecteur radio / viewer en grand ; la piste en cours s'affiche dans une info-bulle | `10-media-agrandir.png` | `[TESTÉ DANS CHROMIUM]` |
| Étoile ★ d'une carte | Épingle la carte (état gardé dans le navigateur, aucune écriture serveur) | `31-favori-epingle.png` | `[TESTÉ DANS CHROMIUM]` |
| « ? » d'une carte | Bulle « AIDE DE CARTE » : rôle de la carte, métriques vivantes, étapes numérotées (testé sur les 25 cartes) | `30-aide-carte-1.png` à `-4.png` | `[TESTÉ DANS CHROMIUM]` |


## 4. Vue « Système — tous les modules »
- **Accès** : « 🗄️ Tout le parc… » du menu Services, ou la recherche. **URL** inchangée (`/`), fil d'Ariane « Hall › Système ». Captures `32-tout-le-parc.png`, `33-tout-le-parc-pleine-page.png`.
- **Contenu** : 113 modules en six familles — 🛡️ Muraille (19), 🧠 Esprit (20), 🕸️ Maillage (46), 🔑 Accès (6), ⚙️ Racine (15), ⚡ Amorce (7) ; chaque module est une tuile avec icône, nom, sous-domaine `<nom>.gk2.secubox.in`, description (en anglais pour beaucoup) et un point d'état. **31 tuiles sont grisées** (hors ligne).
- **Action** : cliquer une tuile ouvre le module embarqué. Les consoles d'administration s'ouvrent derrière une session ; non suivies une par une.
- `[TESTÉ DANS CHROMIUM]` pour l'affichage et le filtre ; `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` pour la plupart des consoles derrière.


## 5. Les 31 services du menu, ouverts un à un
Chaque service a été ouvert depuis le menu « Services ▾ » (condition A, LAN). Colonnes : statut HTTP du document embarqué, adresse du cadre, titre ou premiers mots affichés.

| Service | HTTP | Adresse du cadre | Étiquette | Ce que Chromium a affiché | Capture |
|---|---|---|---|---|---|
| 🎟️ Accès | 200 | `acces.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Formulaire « Demander un accès » (nom, adresse facultative, appareil détecté « Linux x86_64 », mot facultatif) ; l'envoi n'a pas été fait (écriture réseau bloquée). Explique qu'une invitation ouvre une session à un appareil, pas un compte. | `20-service-acces.png` |
| ✦ Activité | 200 | `hall.gk2.secubox.in/cardlets/activite.html?embed=1&mega=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Fil de 19 gestes récents de la box (fils ouverts, fichiers partagés, diffusions), chaque ligne étiquetée « public » et datée en jours. | `20-service-activite.png` |
| 💬 BBS | 200 | `bbs.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Forum AletheiaVox en lecture visiteur (« Vous lisez en visiteur ») : carrousel « À la une » de discussions, bloc « Actualités ». Boutons « Entrer avec ma session SecuBox » / « Autre compte » : mènent à la connexion, non suivis. | `20-service-bbs.png` |
| 🎟️ Billets | 200 | `billets.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Fil immersif de micro-blog : filtres TOUS/AUTH/WALL/BOOT/MIND/ROOT/MESH, vidéo à la une avec lecteur YouTube souverain, réactions emoji, auteurs affichés (admin, sbx-…, Gk2). | `20-service-billets.png` |
| ☁️ Cloud | 302 | `nc.gk2.secubox.in/sbx/entrer?embed=1&theme=light` | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` | La tuile redirige (302) vers `/sbx/entrer` puis vers le formulaire « S'identifier – SecuBox » de Nextcloud : sans session, pas d'entrée automatique. Aucun contenu de fichiers. | `20-service-nextcloud.png` |
| 🔐 Coffre | 200 | `admin.gk2.secubox.in/vault/?theme=light` | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` | Console du Coffre servie sur `admin.gk2.secubox.in/vault/` : titre et textes visibles, mais l'état, les serrures et le journal restent vides (« Token Bearer ou session manquant »). Le formulaire de pose de secret est affiché, inutilisable. | `20-service-coffre.png` |
| 📦 Dépôt | 200 | `depot.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Page de dépôt : « Laissez vos fichiers ici », zone de glisser-déposer (2,0 Gio par fichier, 20 fichiers par dépôt), champ « mot pour accompagner le dépôt ». Dépôt non tenté (écriture). | `20-service-depot.png` |
| 🛰️ DevWatch | 200 | `admin.gk2.secubox.in/devwatch/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Tableau de bord du dépôt GitHub CyberMind-FR/secubox-deb : commits, contributeurs, releases, issues, courbe de cadence 30 jours, coût/carbone. Vu depuis le LAN ; en visiteur externe simulé l'API `devwatch/summary` répond 401. | `20-service-devwatch.png` |
| 🔬 DPI · Trafic | 200 | `hall.gk2.secubox.in/cardlets/dpi.html?embed=1&mega=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | « DPI · Trafic vivant » : flux actifs, débit, répartition par protocole (TLS 88 %, DNS 10 %…) et applications. Vu depuis le LAN ; en visiteur externe simulé l'écran est « EN VEILLE » et les API `dpi/*` répondent 401. | `20-service-dpi.png` |
| 📺 Freebox TV | 200 | `hall.gk2.secubox.in/cardlets/freeboxtv.html?embed=1&mega=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Grille de 177 chaînes de la Freebox (numéro + nom) avec filtre. Vu depuis le LAN ; en visiteur externe simulé : « Aucune chaîne. » (API 403). | `20-service-freeboxtv.png` |
| 🎚️ Lyrion | 200 | `lyrion.gk2.secubox.in/?embed=1&theme=light` | `[AFFICHE MAIS NON FONCTIONNEL]` | L'interface Lyrion s'affiche (menu, Ma Musique, Radio, Favoris, Applications) mais indique « Pas de platine » ; les appels `jsonrpc.js` échouent et le bouton pause est bloqué (écriture). | `20-service-lyrion.png` |
| 📧 Mail | 200 | `webmail.gk2.secubox.in/?embed=1&theme=light` | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` | Formulaire « CONNEXION » du webmail (Roundcube « SecuBox Webmail »). Aucune boîte accessible sans session. | `20-service-mail.png` |
| 🗝️ Mes comptes | 200 | `hall.gk2.secubox.in/cardlets/comptes.html?embed=1&mega=1&theme=light` | `[AFFICHE MAIS NON FONCTIONNEL]` | Carte « Mes comptes » : message « Identité injoignable pour le moment. » (API `sbxid/moi` répond 401 à un invité). | `20-service-comptes.png` |
| 🌐 Mes sites | 200 | `admin.gk2.secubox.in/metablogizer/?vue=mosaique&theme=light` | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` | « Mes sites » embarqué dans l'administration : écran vide, les API `metablogizer/sites` répondent 401. La carte de la mosaïque publique, elle, indique « mosaïque injoignable » en visiteur externe. | `20-service-metablogizer.png` |
| 💬 Messagerie | 200 | `hall.gk2.secubox.in/messagerie/?embed=1&mega=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Mur public de la box (80 messages, dont le chat de la radio) avec onglets « Mur public » / « Privés » ; zone d'écriture avec pseudo et « À tous (mur public) ». Envoi non testé (écriture). | `20-service-messagerie.png` |
| 🗞️ MetaNews | 200 | `metanews.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Actualité regroupée par sujets (À LA UNE, GÉNÉRAL, FRANCE, MONDE, TECH, CYBER, ÉCO, SCIENCE) : chaque sujet réunit plusieurs sources, avec confiance et lien « Discuter ». | `20-service-metanews.png` |
| 🗝️ Mon coffre | 200 | `hall.gk2.secubox.in/coffre/?embed=1&mega=1&theme=light` | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` | « Mon coffre » : badge RÉSERVÉ, texte « Connectez-vous au Hall pour ouvrir votre coffre. » ; le formulaire de création de serrure est affiché mais le Coffre répond 401. | `20-service-mon-coffre.png` |
| 🎙 Mood | 200 | `mood.gk2.secubox.in/?embed=1&theme=light` | `[AFFICHE MAIS NON FONCTIONNEL]` | « Audio Mood » : statut HORS LIGNE, boutons « Écouter » / « Oublier » ; analyse prosodique locale non démarrée (micro non accordé en headless). | `20-service-mood.png` |
| 📹 PeerTube | 302 | `peertube.gk2.secubox.in/sbx/entrer?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Redirige vers `/sbx/entrer` puis le catalogue PeerTube public (« Ajoutées récemment », vidéos, « Demander un compte utilisateur »). | `20-service-peertube.png` |
| 📷 Photos | 504 | `photoprism.gk2.secubox.in/?embed=1&theme=light` | `[AFFICHE MAIS NON FONCTIONNEL]` | Page d'erreur de la passerelle : « 504 — Délai dépassé », le service amont PhotoPrism ne répond pas. | `20-service-photoprism.png` |
| 🎙️ Podcaster | 200 | `podcaster.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Liste de 8+ épisodes du « Bureau des Complots » avec lecteurs audio intégrés et bouton de téléchargement. | `20-service-podcaster.png` |
| 📻 Radio | 200 | `radio.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | « SecuBox Radio » : lecture en direct du même point pour tous, antenne (chat du parc), playlist en rotation, ♥, propositions. | `20-service-radio.png` |
| 🧠 Renseignement | 200 | `actor.gk2.secubox.in/?embed=1&theme=light` | `[AFFICHE MAIS NON FONCTIONNEL]` | « Actor Intelligence » : trame de l'écran (profil acteur, flux de défense OBSERVE→QUARANTINE) mais « Moteur Actor Intelligence injoignable » pour un invité. | `20-service-acteurs.png` |
| ▲ SBX OS | — | `hall.gk2.secubox.in/sbxos/?embed=1&mega=1&theme=light` | `[AFFICHE MAIS NON FONCTIONNEL]` | Embarquée dans un cadre du Hall, la page SBX OS reste blanche (aucun document enregistré). Ouverte seule (`/sbxos/`), elle fonctionne : voir plus bas. | `20-service-sbxos.png` |
| 🛡️ Sécurité | 200 | `waf.gk2.secubox.in/?embed=1&theme=light` | `[AFFICHE MAIS NON FONCTIONNEL]` | « SBXWAF — Poste de garde » : titre et textes, mais les graphiques restent sur « chargement… » (données réservées à une session). | `20-service-securite.png` |
| 🔄 SocialRelay | 200 | `socialrelay.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Relais de fédération : onglets Mastodon / Facebook, publications de Gerald (@gk2) et autres comptes, médias en cache local. | `20-service-socialrelay.png` |
| 🧭 Surf & Viewer | 200 | `hall.gk2.secubox.in/cardlets/surfviewer.html?embed=1&mega=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | « Surf & Viewer » : champ « coller un lien à voir / surfer », bande FAVORIS (vide : « Rien encore »). | `20-service-surfviewer.png` |
| 🧲 Torrent | 401 | `torrent.gk2.secubox.in/?embed=1&theme=light` | `[EXISTE MAIS NON ACCESSIBLE INVITÉ]` | Réponse JSON brute 401 « Lecture gardée : jeton requis ». | `20-service-torrent.png` |
| 🎬 YTSaS | 200 | `ytsas.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | « YT-SAS » : 178 vidéos prêtes, 2 en cours ; liste de titres avec ▶ LIRE / 💾 CONSERVER ; formulaire « Récupérer une vidéo » (envoi non testé). | `20-service-ytsas.png` |
| 🦊 ZIA | 200 | `hall.gk2.secubox.in/zia/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | ZIA Hall : assistante 100 % locale (modèle GGUF), message d'accueil, suggestions (« la dernière vidéo sur le WAF », « les podcasts »…), saisie et micro. Question non posée (écriture) ; l'API `zia/capabilities` répond 401 à un invité externe. | `20-service-zia.png` |
| 💡 Zigbee | 200 | `zigbee.gk2.secubox.in/?embed=1&theme=light` | `[TESTÉ DANS CHROMIUM]` | Vue d'ensemble de 6 appareils Zigbee (lampes, prises). Vu depuis le LAN ; en visiteur externe simulé : « Le pilotage Zigbee est réservé au réseau local » (API 403). | `20-service-zigbee.png` |

## 6. Pages et interfaces ouvertes seules
Chaque page a été chargée directement. **LAN** = condition A ; **EXT** = condition B (visiteur externe simulé).

| Page | LAN | EXT | Titre | Ce qui s'affiche (extrait) | Capture |
|---|---|---|---|---|---|
| `hall.gk2.secubox.in/login.html` | 200 | 200 | SecuBox Hall | SbX / 1 / 🗂️ / Services / ▾ / ⌕ / 📻 / 🔊 / 📡 / ◐ / 🧙 / 1 / Invité / ○ Non connecté / Lexie / ⠿ / ★ / ? / ⠿ / ★ / ? / ⠿ / ★ / ? / ⠿ / ★ / ? / ⠿ / ★ / ?  | `40-login.png` |
| `hall.gk2.secubox.in/sbxos/` | 200 | 200 | SBX OS | ▲ SBX OS / Bienvenue / GUEST / Votre Hall /  / 🏠 / Hall / ⭐ / Favoris / ⚙️ / Réglages | `40-sbxos.png` |
| `hall.gk2.secubox.in/i/acces/` | 200 | 200 | Accès | 🎟️ / ACCÈS / QUI ENTRE, ET COMMENT / relevé à 13:08 /  / Une invitation n'ouvre pas un compte : elle ouvre une session à un appareil. L'empreinte comp | `40-acces-moi.png` |
| `hall.gk2.secubox.in/acces/` | 200 | 200 | Accès | 🎟️ / ACCÈS / QUI ENTRE, ET COMMENT / relevé à 13:08 /  / Une invitation n'ouvre pas un compte : elle ouvre une session à un appareil. L'empreinte comp | `40-acces-invitation.png` |
| `hall.gk2.secubox.in/messagerie/` | 200 | 200 | Messagerie de la box | 💬 / Messagerie / visiteur — publié aussitôt, modéré ensuite / Mur public80 / Privés / G / 📻 RADIO / 26 août 11:48 / YES YES YES / Répondre / g / 📻 RAD | `40-messagerie.png` |
| `hall.gk2.secubox.in/zia/micro.html` | 200 | 200 | ZIA — chat | 🦊 / ZIA / GGUF local / MODÈLE / 🦊 / Salut ! 🦊 Je connais ton Hall — demande-moi un média, un doc, un sujet. / la dernière vidéo sur le WAF / les podca | `40-zia-micro.png` |
| `hall.gk2.secubox.in/coffre/` | 200 | 200 | Mon coffre | 🔐 / Mon coffre / RÉSERVÉ /  / Votre compartiment dans le Coffre de la box. Il s'ouvre avec votre serrure (votre connexion, une phrase, ou une clé d'ap | `40-coffre.png` |
| `hall.gk2.secubox.in/vault/` | 200 | 200 | SecuBox Hall | SbX / 🗂️ / Services / ▾ / ⌕ / ◐ / 🧙 / Invité / ○ Non connecté / Hall › Accueil / · / chargement du registre… / 🔴 / En direct au parc / ✕ | `40-vault.png` |
| `hall.gk2.secubox.in/robots.txt` | 200 | 200 |  | # SecuBox Hall â€” politique d'exploration (#1871) / # Le Hall est public en mode invitÃ© : le parcours public se lit, le privÃ© reste fermÃ©. / # L'a | `—` |
| `hall.gk2.secubox.in/cardlets/metablog.html` | 200 | 200 | Mes sites — mosaïque | 🌐 / Mes sites / 162 SITES · 159 ILLUSTRÉS / 🗒️ / astrod / astrod.gk2.secubox.in / migrate / torrent-search / test / zkp / zoom / zlib / ziptest / werd | `40-cardlet-metablog.png` |
| `hall.gk2.secubox.in/cardlets/peertube.html` | 200 | 200 | PeerTube — vue micro | 📹 / PeerTube / 156 VIDÉOS / 2:43 / ▶ / les_regards_suspendus_FR-EN / SPIRITUALCEPT / 1/24 / 🆕 RÉCENTES | `40-cardlet-peertube.png` |
| `hall.gk2.secubox.in/cardlets/dpi.html` | 200 | 200 | DPI — Trafic vivant | 🔬 / DPI · Trafic vivant / LIVE / 1551979 / FLUX ACTIFS / … / Mb/s / DÉBIT / 1 / RISQUES / 🔒 / TLS / 88% / 📡 / DNS / 10% / 📞 / STUN / 2% / 🧲 / BitTorre | `40-cardlet-dpi.png` |
| `hall.gk2.secubox.in/cardlets/zigbee.html` | 200 | 200 | Zigbee — vue micro | 💡 / Zigbee / 0/6 ALLUMÉS / ✨ / Guirlande Lit / injoignable / ⚠️ / 🔌 / Inter Bur / ⏻ / 🔌 / Inter Lit / ⏻ / 💡 / Light Bibli / injoignable / ⚠️ / 💡 / Lig | `40-cardlet-zigbee.png` |
| `hall.gk2.secubox.in/cardlets/surfviewer.html` | 200 | 200 | Surf & Viewer — rappel | 🧭 / Surf & Viewer / ⌕ / ▶ / ⭐ FAVORIS / · se partage & se répète / Rien encore — collez un lien, mettez en favori (⭐) ou proposez au parc (📡). / ⭐ FAV | `40-cardlet-surfviewer.png` |
| `hall.gk2.secubox.in/cardlets/freeboxtv.html` | 200 | 200 | Freebox TV | 📺 / Freebox TV / 2 / France 2 / 3 / France 3 / 4 / France 4 / 5 / France 5 / 12 / Gulli / 13 / BFM TV / 14 / CNews / 17 / CStar / 27 / TV5 Monde / 28  | `40-cardlet-freeboxtv.png` |
| `hall.gk2.secubox.in/cardlets/actor.html` | 200 | 200 | Renseignement — Actor Intelligence | 🧠 / Renseignement · Actor Intelligence / SHADOW · OBSERVE / 318 / ACTEURS / 23 / CAMPAGNES / 0 / ÉVÉN. / J / 0 / BLOQUÉS / J / 🎭 ACTEURS CORRÉLÉS — TP | `40-cardlet-actor.png` |
| `hall.gk2.secubox.in/cardlets/comptes.html` | 200 | 200 | Mes comptes | 🗝️ / Mes comptes / Identité injoignable pour le moment. / Ouverts avec votre session du Hall · Mon identité | `40-cardlet-comptes.png` |
| `radio.gk2.secubox.in/micro` | 200 | 200 | SecuBox Radio | 2TH - 7ème Ciel (Clip Officiel) / ♥ 5 / ⟳ / ❚❚ / ♥ / 🔇 / ⧉ / 🎶 115 · 🗳️ 0 · 👥 2 · 👁️ 150 / → Kid Francescoli - Don't Get On The Plane feat. Andréa (Of | `40-radio-micro.png` |
| `radio.gk2.secubox.in/` | 200 | 200 | SecuBox Radio | 🎵 SecuBox Radio /  / Écoutez la radio en direct — tout le monde au même endroit du morceau. /  / En direct / EN LECTURE / 2TH - 7ème Ciel (Clip Offici | `40-radio-accueil.png` |
| `metanews.gk2.secubox.in/` | 200 | 200 | MetaNews · observer le monde | 📡 MetaNews / observer le monde / ⚙ Sources / À LA UNE / GÉNÉRAL / FRANCE / MONDE / TECH / CYBER / ÉCO / SCIENCE / 🔗 8 / Extraction des données, consta | `40-metanews.png` |
| `podcaster.gk2.secubox.in/` | 200 | 200 | Podcasts · SecuBox | 🎙️ / SecuBox Podcaster /  / Relayed locally by SecuBox · listen freely /  / 📡 Subscribe (RSS) / 🔗 Copy feed URL / All / Le Bureau des Complots · 55 /  | `40-podcaster.png` |
| `mood.gk2.secubox.in/micro.html` | 200 | 200 | Audio Mood — carte | en veille / ⤢ / … / Indéterminé / personne n'est écouté / 😌 / 😊 / 😬 / 😠 / 😴 / 🤔 / —Hz / —syl / —% / silence / 🎙 écouter / Indices acoustiques — pas un | `40-mood.png` |
| `bbs.gk2.secubox.in/` | 200 | 200 | AletheiaVox — SecuBox BBS | NŒUD BBS.GK2.SECUBOX.IN / ◆ 873 FILS · 938 MESSAGES / ● 19 BILLETS PUBLIÉS / SecuBox BBSLA GAZETTE SOUVERAINE / ⌕ / ⌘K / 3 / en ligne / Entrer / ⧉ / ◐ | `40-bbs.png` |
| `billets.gk2.secubox.in/` | 200 | 200 | billets · Fil immersif | B / BILLETS / FIL IMMERSIF · MICRO-BLOG GATEWAY / EN DIRECT / TOUS / AUTH / WALL / BOOT / MIND / ROOT / MESH / LES AUTRES / A / admin / il y a 9 j / 🔥 | `40-billets.png` |
| `peertube.gk2.secubox.in/` | 200 | 200 | Ajoutées récemment - PeerTube Gk2 | Passer au contenu principal / PeerTube Gk2 / Demander un compte utilisateur⋅rice / Connexion / RÉVÉLER • LIBÉRER • TRANSMETTRE / PeerTube Gk2 / PeerTu | `40-peertube.png` |
| `nc.gk2.secubox.in/` | 200 | 200 | S’identifier – SecuBox | SecuBox / Se connecter à SecuBox / Nom d’utilisateur ou adresse e-mail / Mot de passe / Se souvenir de moi / Se connecter / Se connecter avec un périp | `40-nextcloud.png` |

## 7. SBX OS (Aurora) — `/sbxos/`
- **Titre** : « SBX OS » · HTTP 200 · capture `40-sbxos.png`. Écran « ▲ SBX OS — Bienvenue » avec badge **GUEST**, titre « Votre Hall », quatre pastilles (Radio, PeerTube, MetaNews, Billets) et un dock Hall / Favoris / Réglages.
- Embarquée dans la carte « SBX OS » du Hall, la même page apparaît dans un cadre étroit. Embarquée plein cadre par le menu Services, elle reste blanche. `[AFFICHE MAIS NON FONCTIONNEL]` en cadre ; `[TESTÉ DANS CHROMIUM]` ouverte seule.


## 8. Écran Accès — `/i/acces/` et `/acces/`
- **Titre** : « Accès » · HTTP 200 · capture `40-acces-moi.png`. « ACCÈS — QUI ENTRE, ET COMMENT » : « Une invitation n'ouvre pas un compte : elle ouvre une session à un appareil. L'empreinte comparée ici désigne l'unique appareil qui saura ensuite signer. »
- Formulaire de demande : VOTRE NOM · VOTRE ADRESSE (FACULTATIVE) · CET APPAREIL (« Linux x86_64 ») · UN MOT (FACULTATIF) · bouton « Demander un accès ». `[TESTÉ DANS CHROMIUM]` (envoi non fait).
- L'API `/api/v1/acces/invitation/url` renvoie au visiteur l'adresse de la page d'accès, de son QR et de SBX OS ; aucun jeton.


## 9. Version mobile (390×844)
Captures `41-mobile-bienvenue.png`, `42-mobile-accueil.png`, `43-mobile-menu.png`. La fenêtre de bienvenue passe en pleine largeur, la mosaïque devient une colonne, le menu Services s'ouvre en panneau latéral avec le même contenu. `[TESTÉ DANS CHROMIUM]`
