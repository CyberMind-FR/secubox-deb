<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Migration SBXOS — de la maquette Aurora à `secubox-sbxos` 1.0

> #1604 · épopée #1598 · 2026-09-28
> Complète : [AUDIT-COMMUNITY-REFACTOR.md](AUDIT-COMMUNITY-REFACTOR.md) (Community P3/P4),
> [`packages/secubox-webos/HIG.md`](../../packages/secubox-webos/HIG.md) (protocole sbx, aide).
>
> Ce document est la **version publique** du plan. Une partie du travail côté box
> (P3, P4, P5) durcit des modules existants : son détail est tenu hors du dépôt
> jusqu'à ce que les paquets corrigés soient publiés et installés par
> `secubox-majauto`. Les issues de ces phases restent volontairement sobres.

## 0. En une page

**Décisions de départ (Gandalf, 2026-09-28)**

- **Le Hall vanille** (`packages/secubox-webos/www/hall/`) **reste tel quel** : ni réécrit, ni restylé.
- **SBXOS devient l'interface jouable**, livrée à côté par le paquet `secubox-sbxos`, sur les mêmes API. La logique reste dans secubox-deb ; le SDK n'est que présentation.
- **Profil Complet** (web par défaut, navigateur de la personne, gameplay complet) et **profil Léger** (kiosque de la box, TV, clients faibles).
- **Canon graphique = les planches raster** SDK Characters, Icons et UI Components. Jamais d'icône vectorielle dessinée à la main. Une image manquante se commande par prompt ChatGPT à partir des planches.
- Les 32 **Zanimalos** sont les membres de la communauté.

**Approche retenue : « risques d'abord »**, accélérée par des greffes des approches « tranche verticale » et « SDK d'abord ». On répare et on sécurise ce qui existe avant d'ajouter une surface ; un traceur Aurora tourne sur gk2 dès la semaine 3 ; la bascule publique n'arrive qu'après une porte de parité, une porte d'art et une validation sur box neuve.

| Phase | Issue | Livraison | Contenu | Semaine visée |
|---|---|---|---|---|
| P0 | #1604 | — | ce plan, suivi, arbitrages | 1 |
| P1 | #1605 | `secubox-sbxos` 0.5.2 (publiée) | pont : SBX OS actuel réparé, service worker sûr | 1 |
| P2 | #1606 | `secubox-webos` | vhost du Hall prêt pour une app construite | 1 |
| P3 | #1607 | `secubox-core` | tests backend en CI, durcissement commun des écritures, `require_personne` | 1–2 |
| P4 | #1608 | plusieurs modules | durcissement avant tout nouveau relais (suivi privé) | 2–4 |
| P5 | #1609 | `secubox-webos` | gabarit de relais imposé par la CI, correctifs ponctuels du Hall (sur accord) | 2–4 |
| P6 | #1610 | `secubox-webos` | manifeste de session côté box, `espaces.toml` | 2–4 |
| P7 | #1611 | 0.6.0~aurora1 (gk2) | chaîne React → CI → `.deb`, traceur à `/sbxos/aurora/` | 3 |
| P8 | #1612 | piste parallèle | art canon raster, contrôle d'art en CI | 3 → |
| P9 | #1613 | 0.6.0~aurora2 (gk2) | couche données, protocole sbx des deux côtés | 4–5 |
| P10 | #1614 | 0.6.0~aurora3 (gk2) | Espace Hall jouable sur de vraies données | 6 |
| P11 | #1615 | aperçu gk2 | Lexie + palette Ctrl K branchées sur ZIA | 7–8 |
| P12 | #1616 | aperçu gk2 | carte légère, profils mesurés, accessibilité, mobile | 7–9 |
| P13 | #1617 | **0.7.0 (publiée)** | **bascule** : Aurora à `/sbxos/`, classique en retour arrière | 10–11 |
| P14 | #1618 | 0.7.x | Flux Hall serveur, canal temps réel | 12–13 |
| P15 | #1619 | 0.7.x | Espaces Média et Sécurité | 12–14 |
| P16 | #1620 | 0.7.x | Espaces Atelier et Maison | 13–15 |
| P17 | #1621 | 0.7.x | communauté, premier démarrage, quêtes (fusion Community P3) | 14–16 |
| P18 | #1622 | 0.7.x | kiosque Léger, parc hors gk2, nettoyage | 16–17 |

Issues voisines : #1623 (noms `gk2` écrits en dur côté serveur), #1624 (`menu.json` absent sur gk2).
Issues SDK de l'épopée, reprises par les phases : #1594 (icônes), #1595 (personnages), #1596 (environnements), #1597 (composants), #1600 (gameplay).

Total estimé : environ 17 semaines.

---

## 1. Ce qui ne bouge pas

- **Le Hall vanille.** Seuls changent dans `hall.vhost.conf` la location `/sbxos/` et les relais (gabarit, P5). Des correctifs ponctuels du Hall ne se font qu'avec l'accord de Gandalf.
- **La carte SBX OS du Hall** (`FEATURED`, carte `/sbxos/`, 420 px, `hall/index.html:1414`), chargée en `/sbxos/?theme=dark|light`, et sa vue mega `?embed=1&mega=1&theme=` : `frame-ancestors 'self'` et `body[data-encadre]` posés avant la première peinture.
- **L'URL `/sbxos/` sur l'origine `hall.<box>`.** La clé d'appareil vit dans IndexedDB `sbx-acces`, donc par origine : SBXOS doit rester sur l'origine du Hall pour que l'appareil admis soit le même.
- **Le serveur par défaut** (IP, localhost) ne sert jamais `/sbxos/` sur une seconde origine : il redirige, en 302.
- **Tout ce qui pointe vers `/sbxos/`** : `acces.toml` `url_sbxos`, `/invitation/url`, `acces/index.html:380`, `micro.html:150`.
- **La PWA** : id `/sbxos/`, `start_url` et `scope` `./`, service worker à `/sbxos/offline/sw.js` de portée `/sbxos/`. Les PWA installées ne deviennent pas orphelines.
- **Le nom du paquet `secubox-sbxos`** : exception consignée à la règle « `sbxos-*` = interface ». `secubox-service-hall` en dépend et la découverte CI ne voit que `packages/secubox-*`. Chemin d'installation et `Architecture: all` inchangés.
- **L'entrée sans mot de passe** (#1562) : `session/etat`, puis `appareil.js` `ouvreSiAdmis()`, puis lien `/acces/`. Jamais de mot de passe demandé ni affiché, jamais `/acces/{svc}/manuel`, jamais de session ouverte par-dessus une session valide, jamais de cookie ni de jeton injecté par root.
- **Admin = vrai admin** (#1581) : `require_jwt` réservé à `est_admin_reel`, un appareil n'est jamais admin. Aucune garde relâchée pour faire vivre une carte.
- **Le stockage des autres sur l'origine partagée** : `sbx-acces`, `sbx-acces-suivi`, `sbx_token`, `sbx.hall.*`. Jamais de `Clear-Site-Data`. Les préférences `sbxos.hall` actuelles sont migrées, l'ancienne clé est gardée.
- **Les fonctions actuelles de SBX OS**, selon la matrice de parité de P13 : chaque abandon est décidé et motivé.
- **Lexie est le visage et la voix, ZIA le seul cerveau** (`lexie.js:6-34`).
- **La CSP du Hall** : pas de CDN, pas de police externe, `connect-src 'self'`. Aucun nouveau HTML tiers sur l'origine du Hall.
- **Déploiement par paquet uniquement**, version de la box vérifiée avant chaque montée, jamais `--force-confnew` à l'aveugle.
- **Le kiosque actuel** (Hall sur localhost) jusqu'à P18. Lyrion reste hors de SBXOS (#1247).

---

## 2. Architecture cible

Trois couches, une origine (`hall.<box>`).

### 2.1 Présentation : `packages/secubox-sbxos/`

`sbx-sdk/` reprend l'arborescence de l'épopée #1598. Il vit dans le paquet : la découverte CI le trouve, et il n'y a qu'un `package-lock.json`.

| Paquet du SDK | Rôle |
|---|---|
| `tokens` | `#07111F`, `#0B2036`, `#38BDF8`, `#22C55E`, `#A855F7`, `#F59E0B` en variables CSS et `@theme` Tailwind 4 ; préréglages de mouvement Complet/Léger. `--faint` relevé à 4,5:1 (3,66 à 4,05 dans la maquette), gardé par un test de contraste. |
| `fonts` | Orbitron auto-hébergé + OFL.txt ; Inter et JetBrains Mono pris sur `/fonts/` du Hall. |
| `icons` (#1594) | `<SbxIcon id taille etat>`, raster seulement. |
| `characters` (#1595) | `<SbxCharacter>`. |
| `environments` (#1596) | `<EnvironmentScene qualite>`. Particules seulement si les mesures de P12 les autorisent. `audio`, `particles` et `shaders` reportés après la 1.0. |
| `ui` (#1597) | composants qui ne reçoivent que des props. |
| `protocol` | côté hôte : portage TypeScript de `SBXCapabilities`, `sbxExecuteAction`, `sbxPost` et de l'écouteur du Hall, filtré par type de message et par origine. Côté enfant : messages de HIG.md §4.1 (`theme`, `relis`, `aide`, `aide?`, `survol`, `quitte`), réponse `aide-zones`, émission de `ouvre`, `zoom`, `carte-haut`. |
| `data` | le **seul** code qui parle à la box. |
| `gameplay` (#1600) | magasins Zustand : Espace actif, transitions, palette, onboarding, quêtes, file du Flux. |

Sens des dépendances, imposé par ESLint : `tokens`, `fonts` ← `icons`, `characters`, `environments` ← `ui` ← `app` ; `data`, `protocol` ← `gameplay` ← `app`.

`app/` est un assemblage mince :

- navigation par `?espace=hall|atelier|securite|media|maison`, sans routes en chemin ;
- un morceau par Espace, chargé à la demande ; l'art se charge à l'entrée de l'Espace ;
- un script externe et bloquant dans `<head>` choisit le rendu avant la première peinture (aucun script en ligne, pour une CSP stricte) :
  - **carte légère** : page encadrée (`window.top !== window`) sans `mega=1`, c'est-à-dire l'URL que le Hall envoie aujourd'hui (`/sbxos/?theme=dark|light`, `hall/index.html:1581-1602`). Module TypeScript sans React, 15 Ko gzip au plus ;
  - **app encadrée** : `?embed=1&mega=1` (`hall/index.html:1843-1845`), chrome masqué par `body[data-encadre]`. Ouvrir un module envoie `{sbx:'ouvre', id}` au Hall au lieu d'imbriquer des iframes ;
  - **app complète** ;
- thème : `?theme=dark|light` traduit en sombre/clair. Aurora 1.0 est sombre seulement, sous réserve d'arbitrage (l'art actuel a un fond marine incrusté) ;
- rendu : `?rendu=complet|leger` (pas `?profil=`, qui désigne déjà un rôle). Léger si `?rendu=leger`, kiosque, `prefers-reduced-motion`, `Save-Data` : pas de canvas ni de WebGL, dégradés CSS, portraits fixes, variantes 256 px, pas de son ;
- langue : français en 1.0, chaînes externalisées dans `sbx-sdk`, `Intl` pour les dates relatives et les pluriels, ⌘K affiché sur macOS.

`vitrine/` : galerie des composants sur fixtures synthétiques. Jamais livrée.

### 2.2 Données : `sbx-sdk/data`

- `sbxFetch` : même origine, `credentials: 'same-origin'` ; réponse JSON exigée (un `/api/` non relayé renvoie l'index du Hall en 200, `hall.vhost.conf:719-721`) ; après 401/403, recul par module de 30 s à 5 min comme `sonde.js` ; `AbortController` ; sondage seulement quand l'onglet et la carte sont visibles.
- Gardes de type écrites à la main, reprises de `mine.js`. Une charge invalide est ignorée, jamais affichée à moitié. Tout est inséré comme texte.
- Une aide d'URL unique : chemins de même origine et hôtes `*.<domaine>` listés par le manifeste. Toute URL venue du manifeste, de ZIA ou d'une diffusion passe par elle.
- `registre.ts` : une ligne par source avec son statut ; chaque carte affiche un badge (live, vide, démo, refusé, LAN, erreur).
- `LiveChannel` ne dépend pas du transport : sondage des curseurs d'abord, SSE en P14.
- Le **manifeste** `GET /api/v1/webos/sbxos/manifeste` (P6) donne rôle, LAN, domaine, Espaces, modules et `capacites`. L'interface n'affiche un contrôle que si la box le déclare.

### 2.3 Logique : secubox-deb

- `secubox-core` : durcissement commun des écritures, plancher `require_personne`.
- `secubox-webos` : manifeste, flux, canal temps réel, vignettes Nextcloud.
- `secubox-sbxid` : préférences, portraits, présence, vue Mesh réduite.
- `secubox-zia` : paramètres chaîne, classe d'effet et `role_min` des capacités, objets Espace, domaine lu dans la configuration.
- Hall : relais GET exacts, selon le gabarit (P5).

### 2.4 Stockage (origine partagée avec le Hall)

- Par appareil : `localStorage` `sbxos.v2.appareil` (rendu, thème, densité, mouvement réduit), chaque accès en `try/catch`. Migration unique depuis `sbxos.hall`, ancienne clé conservée.
- Par personne, si l'arbitrage l'accepte : `/api/v1/sbxid/moi/preferences`, espace de noms `sbxos.*` seulement.
- Jamais touchés : IndexedDB `sbx-acces` et `sbx-acces-suivi`, `sbx_token`, `sbx.hall.*`.

### 2.5 Entrée sans mot de passe

Une seule promesse : `GET /api/v1/acces/session/etat` (`packages/secubox-sbxid/acces/api/main.py:410-430`) ; si pas de session, `import('/acces/appareil.js')` puis `ouvreSiAdmis()` ; si l'appareil n'a pas d'accès, lien vers `/acces/`. Cela supprime la course entre les deux appels de `composeLeBureau` (`www/index.html:388-416`).

### 2.6 Service worker

Une seule URL, `/sbxos/offline/sw.js`, portée `/sbxos/`. Règles communes à v6 (pont) et v7 (bascule) :

- ne traite que les URL `/sbxos/` ; laisse au réseau `/api/`, `/acces/`, `/domaine.js`, `/fonts/`, `/hls.min.js`, les requêtes non-GET et les autres origines ;
- ne met jamais en cache une réponse privée (API, média obtenus avec les cookies, `private`, `no-store`) ;
- clé de cache des navigations normalisée en `/sbxos/index.html` ;
- ne supprime que ses propres caches `sbxos-*` autres que le courant ;
- purge les caches propres à la personne quand l'état de session change ;
- interrupteur d'arrêt : `kill.json` n'agit que sur une réponse 200 JSON `{"kill":true}`.

Pendant l'aperçu, v6 laisse aussi au réseau `/sbxos/aurora/`, `/sbxos/assets/`, `/sbxos/art/` et toute requête dont le client est une page sous `/sbxos/aurora/` ; l'aperçu n'enregistre aucun worker. À la bascule, v7 (`sbxos-v7-<empreinte>`) pré-cache depuis le manifeste Vite, a un cache d'art séparé, recharge une fois sur `controllerchange` et laisse `/sbxos/classique/` au réseau.

---

## 3. Paquet et service

### 3.1 Arbre source

- `www-classique/` : le vanille actuel, gelé après P1. `outils/extraire-curation.py:60` et `outils/verifie-gabarits.py:44` sont mis à jour dans le même commit que le déplacement.
- `package.json` (workspaces `sbx-sdk/*`, `app`, `vitrine`), `package-lock.json`, `.nvmrc` = 22.
- `sbx-sdk/`, `app/`, `vitrine/`, `espaces.toml` (généré depuis le `FEATURED` du Hall), `debian/`.
- `dist/` et `node_modules/` ignorés par git.

`sbx-sdk/ui` ne remplace pas `secubox-sbxui` (SBXAide, SliceBar à `/shared/sbxui/`), que le Hall continue d'utiliser. SBXOS réimplémente le contrat d'aide (`aide-zones`) en TypeScript.

### 3.2 Contenu installé

| | Aperçu `0.6.0~auroraN-1~bookworm1` (gk2 seulement) | Bascule `0.7.0-1~bookworm1` |
|---|---|---|
| `/sbxos/` | le vanille | Aurora (`index.html`) |
| `/sbxos/aurora/` | Aurora + `version.json` | — |
| `/sbxos/classique/` | — | le vanille, une version, sans worker ni manifeste |
| `/sbxos/assets/`, `/sbxos/art/` | fichiers hachés, art | idem |
| `/usr/share/secubox/sbxos/` | — | `espaces.toml`, `OFL.txt`, `THIRD-PARTY.txt` |
| outils | — | `secubox-sbxosctl` (interrupteur de retour arrière) |

`debian/control` : `Depends: secubox-webos (>= P2)`, puis `(>= P6)` à la bascule, puis `(>= P14)` avec le Flux temps réel.

Conffiles : `nginx/sbxos.conf` est installé dans `secubox-routes.d` **et** dans `secubox.d`. La copie `secubox.d` ne peut pas être retirée seule : le serveur par défaut (`common/nginx/secubox.conf`, livré par `secubox-core`) n'inclut que `secubox.d`. Sans elle, `/sbxos/` sur l'IP ou localhost serait servi sur une seconde origine, avec une autre clé d'appareil. On déplace d'abord la redirection (P18).

### 3.3 Service (`secubox-webos`, `hall.vhost.conf:494-535`)

- `location /sbxos/` (le classique pendant l'aperçu, `/sbxos/classique/` après) : alias ; CSP redéclarée (`frame-ancestors 'self'`, `media-src 'self' blob:`, `img-src 'self' data: blob:`, `form-action 'self'`, `object-src 'none'` ; `'unsafe-inline'` pour les scripts du classique seulement) ; nosniff ; Permissions-Policy et Referrer-Policy redéclarées ; index en no-cache ; repli SPA ; point d'inclusion `/etc/nginx/secubox-sbxos-mode.d/*.conf`.
- `location ^~ /sbxos/aurora/` puis `/sbxos/` : CSP stricte, `script-src 'self'` plus les deux empreintes sha256 du drapeau LAN injecté par `sub_filter` (variantes `"1"` et `"0"`, fixes, écrites dans le vhost). `style-src 'self' 'unsafe-inline'` pour le mouvement. Réservée au LAN pendant l'aperçu.
- `location ^~ /sbxos/assets/` : cache immuable d'un an, `gzip_static`, nosniff, CSP.
- `sw.js` : no-store, `Service-Worker-Allowed /sbxos/`, CSP, nosniff. `kill.json` et `version.json` : no-store.
- Regex des fichiers statiques : + avif, ogg, opus, mp3, wasm, txt (un fichier absent rend 404).
- **gzip seulement dans les locations statiques** `/sbxos/` et `/fonts/`, jamais au niveau du serveur Hall : `gzip_proxied` ne se déclenche que sur un en-tête `Via` qu'HAProxy n'ajoute pas, donc un `gzip_types` de serveur compresserait les réponses d'API porteuses de jetons (conditions de BREACH). `index.html` n'est jamais précompressé, pour que le `sub_filter` du drapeau LAN (`hall.vhost.conf:59-61`) s'applique.
- **Gabarit de relais** (P5, grep en CI) : `location =` exacte ; `proxy_set_header X-SecuBox-LAN $lan_client` et `X-Real-IP $remote_addr` ; en-têtes `X-Sbx-*` vidés (comme le relais radio, #1430) ; `limit_except GET`.
- Temps réel (P14) : location dédiée `/api/v1/webos/flux/stream`, `proxy_buffering off`, `X-SecuBox-LAN` réécrit, `limit_conn`.
- Redirection `/sbxos` sur le serveur admin et le serveur par défaut : 302, jamais 301 ; en P18, `return 302 https://hall.<domaine>$request_uri;` rendu au postinst depuis la chaîne de domaine.

### 3.4 Versions et publication

Forme : `0.5.2-1~bookworm1` → `0.6.0~auroraN-1~bookworm1` → `0.7.0-1~bookworm1`.
`scripts/restamp-changelog.sh` ne remplace que le dernier suffixe `~<suite>N` : la marque `aurora` survit et l'ordre dpkg reste bon (`0.5.2 < 0.6.0~aurora1 < 0.6.0 < 0.7.0`). Une forme `0.6.0~aurora1` sans révision perdrait la marque.

- 0.5.2 : publiée par `scripts/apt-publier.sh`.
- 0.6.0~auroraN : gk2 seulement, par `dpkg -i`. **Trois contrôles automatiques** l'écartent de la publication : le job publish de `build-packages.yml` et `apt-publier.sh` sautent tout `.deb` `~aurora` ; les constructions d'image le refusent ; un test CI le vérifie. Sans eux, une étiquette `v*` posée pendant l'aperçu le publierait et `secubox-majauto` le pousserait à tout le parc la nuit suivante.
- 0.7.0 puis 0.7.x : publiées.

**Retour arrière** : le jour même, sans apt, `secubox-sbxosctl mode classique` (extrait nginx qui réécrit `/sbxos/` vers `/sbxos/classique/`, `kill.json` exposé depuis `/var/lib/secubox/sbxos/`, rechargement de nginx). Ensuite une 0.7.1 supérieure qui réinstalle le classique, puisque majauto ne rétrograde pas. Le `.deb` 0.5.2 reste archivé.

---

## 4. Chaîne de construction

### 4.1 Un script, deux appelants

`scripts/construire-front.sh <paquet>` est appelé par la CI **et** par la construction locale qui alimente apt.secubox.in (#1335 : jamais deux producteurs divergents).

1. Refuser un Node dont la majeure diffère de `.nvmrc` (22).
2. `npm ci --ignore-scripts` strict, sans repli sur `npm install` (le motif `npm ci || npm install` de `build-packages.yml:262` n'est pas à copier) ; `npm audit signatures`.
3. `tsc`, vitest, ESLint : seul `sbx-sdk/data` appelle `fetch` ; `ui` n'importe ni `data` ni `protocol` ; `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` et `dangerouslySetInnerHTML` interdits partout.
4. `vite build` : base `/sbxos/`, es2022, pas de sourcemap ; aucune police inline ; `@vitejs/plugin-react`, `@tailwindcss/vite`, `rollup-plugin-license` (→ `THIRD-PARTY.txt`) ; Framer Motion en `LazyMotion` + `domAnimation` ; hls.js non empaqueté (`/hls.min.js` du Hall) ; aucun script en ligne sauf le marqueur `<!--SBX_LAN_FLAG-->`.
5. Générer `offline/sw.js` depuis le manifeste Vite (chemins absolus, VERSION = empreinte, cache d'art séparé).
6. Budgets : JS initial ≤ 190 Ko gzip (objectif 150), morceau d'Espace ≤ 60 Ko, carte légère ≤ 15 Ko.
7. Balayer `dist` et échouer sur : une autre origine (dont fonts.googleapis), `eval(` ou `new Function`, un chemin `/acces/…/manuel`, une fixture, une source démo hors canal aperçu, un script en ligne autre que le marqueur LAN.
8. Jumeaux `.gz` des js, css, json, webmanifest (jamais `index.html`).
9. `dist/.construit` : version amont (sans révision ni `~<suite>N`), sha256 du lockfile, des sources, des configs et de l'art, canal `apercu` ou `publie`.

### 4.2 `debian/rules`

Ne lance jamais npm (Build-Depends reste debhelper ; Vite 7 et Tailwind 4 exigent Node ≥ 20, bookworm a 18.19). Échoue, dans le style de #1335 (`sbxos-audio-mood` `rules:77-82`), si :

- le dist attendu manque (`dist/aurora/index.html` pendant l'aperçu, `dist/index.html` + `dist/offline/sw.js` après), ou `dist/.construit` ;
- la version amont de `.construit` diffère du changelog (comparées sans `~<suite>N`, puisque l'étape Node tourne avant `restamp-changelog.sh`) ;
- l'empreinte recalculée par `scripts/empreinte-front.sh` diffère (un dist périmé est refusé, là où soc-web l'accepte en silence) ;
- `canal=apercu` pour une version sans `~aurora`, ou une version `~aurora` construite sur une étiquette.

### 4.3 CI

- `build-packages.yml` : étape Node générique conditionnée par `hashFiles(format('packages/{0}/.nvmrc', matrix.package))` (pas par le lockfile : soc-web en a un sans `.nvmrc`), `actions/setup-node` épinglé par SHA ; `secubox-sbxos` reste `Architecture: all`, construit une fois sur le runner amd64. Job publish et `apt-publier.sh` écartent `~aurora`. Test de `restamp-changelog.sh` sur un changelog `~aurora`.
- `backend-tests.yml` (P3) : pytest pour webos, sbxid, zia (leurs `tests/` ne tournent pas en CI aujourd'hui) ; go test pour secubox-bbs et sbx-actord.
- `sbxos-front.yml` (PR sur `packages/secubox-sbxos/**`) : types, vitest (gardes, hooks, contrat du protocole, contrats fixtures ↔ schémas d'API), frontières ESLint, contrôle d'art, grep des fixtures (refuse IP, `did:`, `sbx-[0-9a-f]{12}`, pseudos réels — le dépôt est public), barrière CSP + axe-core dans Chromium headless (chaque Espace, la carte encadrée, `?embed=1&mega=1` ; échec sur violation CSP, erreur console, requête vers une autre origine, défaut axe-core sérieux), construction de la vitrine.
- Chaîne d'approvisionnement : actions épinglées par SHA, Dependabot ou Renovate sur le lockfile, SBOM, liste de dépendances courte, `.tsx`/`.jsx` ajoutés à `scripts/license-headers.py`.

---

## 5. Chaîne d'art

**Canon raster, jamais de SVG dessiné à la main.**

### 5.1 État réel de l'art de la maquette

- 41 découpes webp, **toutes en RVB sans alpha**, fond marine `(4,16,30)` incrusté. Tailles : icônes 100×100, mini-cartes 52×52, fonds ~151×87, îles 123×172, Lexie 270×263, hero 522×217.
- Conséquence : 100 % de l'art importé est **provisoire**, jamais agrandi au-delà de la source. Le rendu de P10 sera flou, c'est attendu.

### 5.2 Sources versionnées

- **Zanimalos** : le paquet déjà présent, `packages/secubox-billets/api/static/stickers/zanimalos/` (32 PNG 256×256 RGBA). Le contrat `docs/zanimalos-pack-contract.md` (`01_peek`…`32_solko`) fait foi sur les trois nommages en circulation. Les Zanimalos servent déjà de tampons d'état de contenu (AUDIT-COMMUNITY-REFACTOR §7.2) : le sens « portrait de personne » coexiste avec lui.
- **Planches canon** (SDK Characters, Icons, UI Components, 1536×1024), archive des vignettes et pack de prompts ChatGPT : versés dans le dépôt en P8, provenance de chaque image dans `manifest.json`.
- **Masters** : webp sans perte avec alpha (512 px pour les icônes). Variantes générées au build par un encodeur épinglé (sharp, version fixée dans le lockfile) pour une empreinte déterministe. Quelques dizaines de Mo dans git, sans LFS au départ.
- Rangement : `sbx-sdk/{icons,characters,environments}/art`, publication à `/sbxos/art/<paquet>/<id>-<taille>.webp`.

### 5.3 Déclinaison et contrôle

- Variantes 256, 128, 64, 48, 32, 24 ; personnages et décors en qualité Complet et Léger (256 px).
- `manifest.json` par paquet d'art : id, tailles, variantes, états, licence CMSD, provenance, statut `definitif` ou `provisoire`. États `idle` et `pulse` en CSS ; `alert` et `success` en rendus dédiés.
- CI : tout `.svg` dans les dossiers d'art est refusé ; ids uniques ; alpha exigé pour `definitif` ; noms de Zanimalos canoniques ; nombre de provisoires publié dans le résumé ; l'art entre dans l'empreinte du dist.

### 5.4 Porte d'art avant la bascule 0.7.0

Masters alpha définitifs pour : hero et env-hall, Lexie, les 5 icônes du rail, les 4 cartes de pièce, les icônes des cartes live, les icônes PWA 192, 512 et maskable.

Manques connus : ~106 des 120 icônes, env-maison, tous les masters alpha, les animations (Lexie et ses 8 animations d'abord). Commandés par lots de prompts ChatGPT, porte d'art en premier.

### 5.5 Audio, polices, poids

- Audio (#1596, `sbx-sdk/audio`) reporté après la 1.0 : aucune source n'existe.
- Polices : Inter et JetBrains Mono depuis `/fonts/` du Hall (non mises en cache par le worker) ; Orbitron en woff2 dans `sbx-sdk/fonts` avec OFL.txt, `font-display: swap`. Ajouter les OFL.txt manquants des woff2 du Hall.
- Budgets : Léger ≤ 1 Mo au premier chargement ; Complet ≤ 5 Mo, 2 à 3 Mo par Espace ; ~40 Mo pour Aurora complet sur disque.
- Licences : art CMSD, polices OFL, code tiers (React, Framer Motion, Tailwind, hls.js du Hall) dans `THIRD-PARTY.txt`.

---

## 6. Carte composants ↔ API

| Composant de la maquette | Source côté box | État | Phase |
|---|---|---|---|
| Coquille + entrée sans mot de passe | `/api/v1/acces/session/etat`, `/acces/appareil.js`, `/api/v1/sbxid/moi` | prêt | P7 |
| Rail des 5 Espaces, modules, feuille « Applications » | nouveau manifeste + `espaces.toml` (aujourd'hui `clone.js` + `curation.json` + `/public/services`) | manquant | P6 |
| Scène d'Espace (île + guide) | art canon | provisoire | P8, P10 |
| Fil d'activité | `/api/v1/sbxid/activite?n=&depuis=` (filtré par personne, déjà relayé) | prêt | P10 |
| Carte Radio | `/public/cardlets/radio`, `/api/v1/radio/current`, capacité `media.toggle` → `{sbx:'cmd', action:'toggle'}` | partiel | P10 |
| Flux Hall (≤ 3, TTL, action) | candidats : activité, diffusion, WAF, Actor ; cible `/api/v1/webos/flux` | manquant | P14 |
| Lexie + palette Ctrl K | `/api/v1/zia/v1/chat`, `/api/v1/zia/capabilities` | partiel | P11 |
| Guides par Espace (Néo, Actor, Lyrión, Zia) | manifeste + ZIA | partiel | P10, P11 |
| Lieu / Théâtre | classique `www/index.html:242-296` | manquant | P10 |
| Protocole sbx, côté hôte | `hall/index.html:2492-2506`, `3412-3611` | partiel | P9 |
| Protocole sbx, côté enfant | HIG.md §4.1, §8 | manquant | P9, P12 |
| Carte BBS | menu public, puis API membre | partiel | P16 |
| Carte Photos / Nextcloud | `/api/v1/webos/acces/nextcloud/*` ; mandataire de vignettes par personne | partiel | P15 |
| CloudExplorer (#1597) | `nc_super.py` | partiel | P15 |
| Actor Intelligence | `/api/v1/actor/*` (sbx-actord, shadow) ; échelle affichée « proposé », jamais appliquée | partiel | P15 |
| Carte WAF | `/public/cardlets/waf`, `/public/waf/qui-frappe` | partiel | P15 |
| Carte Mesh | nouvelle vue réduite dans sbxid (noms, états, sans adresse) | manquant | P15 |
| Carte Billets | billets `feed.json`, `stats.json` (relais exacts) | partiel | P15 |
| Carte DPI | relais `/api/v1/dpi/` existant, aligné sur le gabarit | partiel | P15 |
| Carte PeerTube | objets peertube du bus ZIA ; carte de liens seulement | partiel | P15 |
| Carte Freebox TV | `/api/v1/freeboxtv/*`, `/hls.min.js` du Hall ; LAN et session | partiel | P15 |
| Carte DevWatch | `/api/v1/devwatch/summary`, `/issues` (relais exacts, jamais `/modules`, `/flows`, `/config`) | partiel | P16 |
| Carte Zigbee (on/off) | `/api/v1/zigbee/devices` (LAN), commande sur capacité + clic | à arbitrer | P16 |
| Rangée de présence, portraits | aucune source ; modèle `secubox-bbs` `presence.go` | manquant | P17 |
| Premier démarrage + 3 quêtes | `/api/v1/webos/acces` ; préférences sans route | partiel | P17 |
| Réglages, « à propos », retour au classique | `version.json`, `registre.ts` | manquant | P10, P13 |
| Temps réel | aucun canal sur l'origine du Hall | manquant | P14 |
| Projets, Gitea, Énergie, Mail, Agenda, Terminal/SSH, Docs, Caméras, objets Maison, Relay | aucune source adaptée | **masqué en 1.0**, jamais simulé | P16 |

---

## 7. Règles tenues par des contrôles automatiques

Plutôt que par la revue :

- la logique reste dans secubox-deb (manifeste, flux, présence, préférences) ;
- seul `sbx-sdk/data` appelle `fetch` ;
- `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML` interdits ;
- aucune donnée de démo ni fixture réelle dans une version publiée ;
- chaque relais du Hall suit le gabarit ;
- aucune garde n'est relâchée pour faire vivre une carte ;
- jamais de mot de passe ni de `/acces/{svc}/manuel` ;
- l'échelle Actor reste en lecture seule ; toute action physique ou d'écriture proposée par ZIA demande un clic ;
- aucun `.svg` dans les dossiers d'art ; aucune version `~aurora` publiée.

Pile : React 19, TypeScript, Tailwind 4, Framer Motion (LazyMotion), Zustand, Vite — celle de #1598 — plus le hls.js déjà servi par le Hall. Pas de TanStack Query, valibot ni openapi-typescript au départ.

---

## 8. Risques principaux

| Risque | Parade |
|---|---|
| Un service worker collant : c'est la seule erreur qu'une rétrogradation apt ne répare pas. | Pont 0.5.2 en premier, testé dans Chromium headless ; portée `/sbxos/`, purge limitée à `sbxos-*`, `kill.json`. URL du worker inchangée ; v7 testé aussi depuis v5. |
| Un dist vide ou périmé expédié, deux producteurs pour le même `.deb` (#1335). | Un seul `construire-front.sh`, Node épinglé, `npm ci` strict, `dist/.construit` lié à l'empreinte, `debian/rules` qui échoue. |
| Un aperçu poussé à tout le parc (publish sur étiquette + majauto nocturne, #1522). | `~auroraN`, `dpkg -i` sur gk2 seulement, trois filtres automatiques, test CI. |
| Des données de démo prises pour des vraies ; sur une appliance de sécurité, un faux état Actor, WAF ou Mesh est un défaut d'intégrité. | `registre.ts` + badge par carte ; démo permise au seul canal aperçu ; fixtures synthétiques, grep en CI. |
| La logique qui glisse dans le SDK (la maquette calcule priorité et TTL, analyse Lexie par regex, code la curation). | Frontières ESLint ; manifeste et flux calculés côté serveur ; la palette appelle toujours ZIA ; données de maquette = fixtures. |
| ZIA orienté par du contenu qu'il lit (BBS, billets, metanews). | Classe d'effet et `role_min` dans `capabilities.d` ; seul `effet=media` s'exécute sans clic ; garde serveur toujours appliquée. |
| Beaucoup de cartes sans backend : SBXOS 1.0 paraîtra plus vide que la maquette. | Masquer plutôt que simuler, piloté par `capacites` et l'état « sans source » d'`espaces.toml` ; piste backend en parallèle. |
| Art provisoire flou ; bascule avec un art indigne. | Porte d'art explicite, alpha exigé pour `definitif`, commandes ChatGPT priorisées. |
| Performances : la carte 420 px charge `/sbxos/` à chaque visite du Hall ; kiosques faibles ; un seul worker uvicorn. | Carte légère sans React ; morceaux par Espace ; art 256 px en Léger ; budgets en CI ; mesures réelles (P12) avant la bascule. |
| Domaine absent ou `gk2` écrit en dur. | Chaîne de domaine dans le manifeste, `/domaine.js` dès le pont, `sbxos.conf` rendu au postinst, #1623, validation sur box `domain=exemple.test`. |
| Temps réel : HAProxy coupe à 30 s d'inactivité, sbxwaf à 10 s sans en-têtes, un seul worker. | Sondage d'abord ; SSE avec en-têtes immédiats, battement ≤ 20 s, location dédiée, `limit_conn`, test de plus de 10 min. |
| Registre public vide sur gk2 (#1624). | Le manifeste s'en passe (`etat='inconnu'`). |
| Deux copies du protocole sbx qui dérivent ; trois listes curées qui divergent. | Test de contrat (formes de message, résolution des capacités) ; `espaces.toml` et `curation.json` générés par le même outil depuis `FEATURED`, test de dérive. |
| Licences : polices OFL et code tiers hors CMSD ; `.tsx` hors contrôle des en-têtes. | OFL.txt livrés, `THIRD-PARTY.txt` généré, `license-headers.py` étendu, exception OFL documentée. |
| Pièges de paquet : conffiles dans deux répertoires, box en avance sur la branche, pas de retour par version inférieure. | `dpkg-query` avant chaque montée ; redirection du serveur par défaut avant tout `rm_conffile` ; `secubox-sbxosctl` ; 0.7.1 répétée ; migrations additives précédées d'un `sqlite .backup`. |

---

## 9. Arbitrages

Chaque arbitrage bloque une phase ; la réponse va dans l'issue de la phase.

| # | Question | Bloque |
|---|---|---|
| A1 | Correctifs ponctuels du Hall vanille (détail tenu en privé) : acceptés comme exception à « le Hall reste tel quel » ? | P5 |
| A2 | Temps réel : WebSocket (texte de #1598) ou SSE (recommandé : `connect-src 'self'`, worker unique, coupures HAProxy/sbxwaf) ? | P14 |
| A3 | Préférences par personne côté serveur (`/api/v1/sbxid/moi/preferences`) : rupture avec « rien ne quitte l'appareil » de 0.5.x. Acceptée ? Sinon préférences par appareil. | P17 |
| A4 | Voix de Lexie : `/api/v1/voice/asr` et `/tts` ouverts aux personnes avec limite de débit ? Voix réservée à SBXOS autonome/PWA ? | P11 |
| A5 | Zigbee on/off : personne + capacité `zigbee.control` + verrou LAN + clic, ou admin seulement ? | P16 |
| A6 | Suggestions de Lexie pour un invité : aucune, ou sous-ensemble public des capacités ? | P11 |
| A7 | Thème : Aurora 1.0 sombre seulement, ou jetons clairs et masters alpha avant la bascule ? | P13 |
| A8 | « Kiosque sur la box » : kiosque rpi400/x64 branché à la box, ou client faible servi par une ESPRESSObin (qui n'a pas de sortie vidéo) ? | P12, P18 |
| A9 | Modèle du kiosque : appareil propre au profil plafonné, `https://hall.<domaine>/sbxos/?rendu=leger`, `/etc/hosts` géré ; Hall en mode LAN sans domaine ? | P18 |
| A10 | Actor : échelle à 6 niveaux affichée en lecture seule, « proposé (shadow) », aucune application depuis SBXOS ? | P15 |
| A11 | Quelques glyphes d'interface monochromes en SVG (chercher, réglages, fermer) tolérés, ou tout raster ? | P8 |
| A12 | Polices OFL (Orbitron, Inter, JetBrains Mono) : acter l'exception à la licence CMSD ? | P7 |
| A13 | Onboarding fusionné avec Community P3 ? 4 favoris (maquette) ou 6 (#1600) ? Qui tient le catalogue des quêtes ? | P17 |
| A14 | Mail + Cloud à l'onboarding : ouverture de comptes en libre-service (avec capacité) ou réservée à l'admin ? | P17 |
| A15 | Carte « Projets » de l'Atelier : Mes sites (metablogizer), Gitea, autre ? | P16 |
| A16 | Énergie : module Linky/TIC, ou `power`/`energy`/`voltage` depuis zigbee ? | P16 |
| A17 | Présence : même règle de visibilité que les activités, compteur seul pour les invités ? | P17 |
| A18 | Acter dans #1598 : `sbx-sdk/` dans `packages/secubox-sbxos/`, exception de nommage, convergence future avec `secubox-sbxui` ? | P7 |
| A19 | PeerTube : planifier son déplacement vers une origine séparée (`pt-hall.<domaine>`) ? | P15 |
| A20 | Aperçu `/sbxos/aurora/` : LAN seulement, ou aussi hors LAN avec une session vérifiée par `auth_request` ? | P2, P7 |
| A21 | gk2 : écrire `[global] domain = "gk2.secubox.in"` (comme premier-pas), ou s'appuyer sur `sso_cookie_domain` ? | P6 |
| A22 | Art dans git : ~40 Mo de masters sans LFS au départ, ou LFS tout de suite ? | P8 |
