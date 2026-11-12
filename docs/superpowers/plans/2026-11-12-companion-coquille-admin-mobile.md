<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Companion 2.0 — coquille de l'admin mobile — plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** un même APK, servi par chaque box sur `/companion/`, qui retient une liste de box et ouvre l'admin de la box choisie dans un WebView sans pont natif.

**Architecture:** deux couches dans l'APK. (1) Écrans **locaux** (Capacitor, origine `https://localhost`) : liste des box, confirmation d'association, « box injoignable », proposition de mise à jour ; logique pure dans `www/core/boites.js`. (2) **`BoxActivity`**, une activité Android avec un `WebView` simple (aucune interface JavaScript, aucun plugin), qui charge l'admin distant, reste sur son origine et envoie tout autre lien au navigateur. Un plugin Capacitor minimal `Boite` fait le pont local → `BoxActivity`. Côté box, un nouveau paquet `secubox-companion` (arch all) sert l'APK, `version.json` et la page `/companion/`.

**Tech Stack:** Capacitor 6 (Android, Java), JS ES modules sans dépendance, Node 22 (`node --test`), pytest + Playwright (`.venv` du dépôt), paquet Debian (debhelper 13), nginx (vhost admin existant).

**Spec:** `docs/superpowers/specs/2026-11-12-companion-coquille-admin-mobile-design.md`

## Global Constraints

- APK : `applicationId in.secubox.companion`, `versionName "2.0"`, `versionCode 7` ; signé avec la **clé de débogage** de ce poste (`~/.android/debug.keystore`), comme la 1.x.
- Le lien d'association est exactement `secubox://associer?box=<origine encodée>` ; il ne porte **aucun secret** ; `box` doit être en `https:`.
- Liste des box : clé `localStorage` `sbx.boites`, 20 box au plus, la box courante en tête. Ancienne clé 1.x à migrer : `sbx.meta` (`{url}`).
- User-Agent du WebView de `BoxActivity` : UA par défaut + ` SecuBoxCompanion/2.0`.
- Aucun pont natif vers l'origine distante : pas d'`addJavascriptInterface`, pas de Capacitor dans `BoxActivity`.
- Page de la box : `/companion/` sur le vhost admin existant ; **aucun** nouveau vhost, aucune route WAF, aucune exemption d'authentification.
- `version.json` : `{"version": "2.0", "version_code": 7, "sha256": "<hex>", "taille": <octets>, "fichier": "secubox-companion.apk"}`, calculé au build depuis `secubox-companion/dist/secubox-companion-2.0.apk` ; build du paquet en **échec** si ce fichier manque. APK jamais commité.
- Paquet `secubox-companion` : version `2.0.0-1~trixie1`, `debian/compat` 13, `Standards-Version: 4.6.2`, en-tête SPDX CMSD-1.0 sur tout fichier nouveau.
- Texte construit par `textContent`/éléments, jamais `innerHTML` avec une donnée. Pages à 420 px sans débordement.
- Commits `type(companion): … (ref #3683)` terminés par `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Pas de `git stash`.

## Review Focus

1. Page `/companion/` ouverte par adresse IP ou en `http:` (ex. `http://192.168.1.200/companion/`) → aucun lien d'association proposé ; message « ouvrez cette page par l'adresse https de la box » (Task 4).
2. `sbx.boites` corrompu, absent, ou contenant une entrée non https → l'appli démarre sur l'écran d'association, sans plantage, entrées invalides ignorées (Task 1).
3. Box injoignable au lancement (autre réseau, box éteinte) → écran local « injoignable » avec la liste, jamais un WebView blanc (Tasks 2 et 3).
4. Dans `BoxActivity`, un lien vers un autre sous-domaine (`jellyfin.<box>`) ou un site tiers → navigateur du téléphone ; une redirection **dans** l'origine (connexion → `/`) reste dans l'appli (Task 3).
5. Lien d'association reçu alors que l'appli est déjà ouverte (`singleTask`, `onNewIntent`) → même confirmation qu'au démarrage à froid (Task 3).

---

### Task 1: logique pure des box — `www/core/boites.js`

**Files:**
- Create: `secubox-companion/www/core/boites.js`
- Test: `secubox-companion/tests/boites.test.mjs` (lancé par `node --test`)

**Interfaces:**
- Produces (exports ES) :
  - `analyserLienAssociation(lien: string) -> {ok: true, origine: string} | {ok: false, raison: string}`
  - `normaliserOrigine(url: string) -> string | null` (https seulement, sans identifiants, chemin `/` ou vide, sans requête ni fragment ; renvoie `URL.origin`)
  - `lireBoites(stockage: Storage) -> Array<{origine: string, nom: string, vu: number}>` (tolère JSON invalide, filtre via `normaliserOrigine`)
  - `ecrireBoites(stockage, liste) -> void`
  - `ajouterBoite(liste, origine: string, maintenant: number) -> liste` (dédoublonne par origine, met en tête, tronque à 20 ; `nom` = nom d'hôte)
  - `retirerBoite(liste, origine) -> liste`
  - `migrerDepuis1x(stockage, maintenant) -> boolean` (si `sbx.boites` vide et `sbx.meta.url` valide → l'ajoute ; ne supprime pas `sbx.meta`)
  - `versionPlusRecente(distante: string, locale: string) -> boolean` (comparaison numérique par segments : `"2.10" > "2.9"`)

- [ ] **Step 1: tests qui échouent** — `tests/boites.test.mjs` avec `node:test` et `node:assert/strict` :
  - `analyserLienAssociation("secubox://associer?box=https%3A%2F%2Fadmin.gk12.secubox.in")` → `{ok:true, origine:"https://admin.gk12.secubox.in"}`
  - refus (`ok:false`) : `box=http://admin.gk12.secubox.in`, `box=https://u:p@admin.gk12.secubox.in`, `box=https://admin.gk12.secubox.in/x`, `box=https://admin.gk12.secubox.in/?a=1`, `box=javascript:alert(1)`, schéma `https://associer?...`, hôte `autre` au lieu de `associer`, paramètre `box` absent, chaîne vide.
  - `ajouterBoite` : ajout de 3 box puis ré-ajout de la 1re → elle passe en tête, longueur 3 ; 25 ajouts → longueur 20.
  - `lireBoites` sur `"{pas du json"` → `[]` ; sur une liste mêlant une entrée `http:` → entrée filtrée.
  - `migrerDepuis1x` : `sbx.meta = {"url":"https://admin.gk2.secubox.in"}` et `sbx.boites` absent → `true`, liste = 1 box ; second appel → `false`.
  - `versionPlusRecente("2.10","2.9") === true`, `("2.0","2.0") === false`, `("1.9","2.0") === false`.
  Utiliser un faux `Storage` (objet avec `getItem/setItem`).
- [ ] **Step 2:** `cd secubox-companion && node --test tests/` → échec (module absent).
- [ ] **Step 3:** écrire `www/core/boites.js` selon les signatures ci-dessus (aucune dépendance, aucun accès DOM).
- [ ] **Step 4:** `node --test tests/` → tout passe.
- [ ] **Step 5:** commit `feat(companion): liste des box et analyse du lien d'association (ref #3683)`.

### Task 2: écrans locaux — retrait de la 1.x

**Files:**
- Rewrite: `secubox-companion/www/index.html`, `secubox-companion/www/core/app.js`
- Delete: `secubox-companion/www/modules/` (tout), `www/core/{api,auth,store,metrics,registry}.js`, `www/sw.js`, `www/manifest.webmanifest`
- Keep: `www/core/ui.js` (si utile), `www/styles/`, `www/assets/`
- Test: `secubox-companion/tests/test_ecrans_locaux.py` (pytest + Playwright, servi par `python -m http.server` sur `www/`)

**Interfaces:**
- Consumes: Task 1 (toutes les fonctions).
- Produces, contrat JS ↔ natif (utilisé par Task 3) :
  - au chargement, `app.js` lit `location.hash` ; `#associer=<lien encodé>` → écran de confirmation « Ajouter <nom d'hôte> à vos box ? » (Oui → `ajouterBoite` + ouverture ; Non → liste).
  - ouverture d'une box : `window.Capacitor.Plugins.Boite.ouvrir({origine})` ; promesse rejetée ou `{joignable:false}` → écran « injoignable ».
  - `#injoignable=<origine encodée>` → écran « injoignable » pour cette box (posé par `BoxActivity` quand le chargement échoue).
  - avant d'ouvrir, lecture de `<origine>/companion/version.json` par `fetch` (CapacitorHttp le rend natif) avec délai 4 s : échec → écran « injoignable » ; `versionPlusRecente(json.version, "2.0")` → bandeau « Nouvelle version — ouvrir la page de téléchargement » qui appelle `Boite.navigateur({url: origine + "/companion/"})`.
- Écrans (charte `styles/charte.css`, 420 px) : **liste** (box courante en tête, bouton « Ouvrir », bouton « Retirer » avec confirmation, explication « ouvrez la page /companion/ de votre box » + champ d'adresse https) ; **confirmation** ; **injoignable** (« Réessayer », « Choisir une autre box »).

- [ ] **Step 1: tests qui échouent** (Playwright, `window.Capacitor` simulé par un script injecté qui enregistre les appels) :
  - `test_liste_vide_montre_association` : stockage vide → texte « /companion/ » visible, champ d'adresse présent.
  - `test_hash_associer_confirme_puis_ouvre` : `#associer=secubox%3A%2F%2Fassocier%3Fbox%3Dhttps%253A%252F%252Fadmin.gk12.secubox.in` → confirmation affiche `admin.gk12.secubox.in` ; clic Oui → `sbx.boites[0].origine == "https://admin.gk12.secubox.in"` et `Boite.ouvrir` appelé avec cette origine.
  - `test_hash_associer_refus_non_https` : lien `box=http://…` → message de refus, aucune écriture.
  - `test_injoignable` : `fetch` de `version.json` rejeté → écran injoignable, boutons présents.
  - `test_stockage_corrompu` : `sbx.boites = "{x"` → écran d'association, aucune erreur console.
  - `test_aucun_innerhtml` : `grep` du source `www/` → pas de `innerHTML` (hors `= ''`).
  - `test_largeur_420` : `scrollWidth <= 420` pour chaque écran.
- [ ] **Step 2:** lancer `…/.venv/bin/python -m pytest -q -p no:cacheprovider secubox-companion/tests/test_ecrans_locaux.py` → échec.
- [ ] **Step 3:** réécrire `index.html` (CSP stricte : `default-src 'self'; connect-src https:; img-src 'self' data:`) et `app.js` ; supprimer les fichiers 1.x listés ; `migrerDepuis1x` au démarrage.
- [ ] **Step 4:** tests Task 1 et Task 2 au vert.
- [ ] **Step 5:** commit `feat(companion): écrans locaux de la 2.0, retrait des vues 1.x (ref #3683)`.

### Task 3: couche Android — `Boite`, `BoxActivity`, lien profond

**Files:**
- Create: `secubox-companion/android/app/src/main/java/in/secubox/companion/BoitePlugin.java`, `…/BoxActivity.java`
- Modify: `…/MainActivity.java`, `android/app/src/main/AndroidManifest.xml`, `android/app/build.gradle` (`versionCode 7`, `versionName "2.0"`), `capacitor.config.json` (pas d'`allowNavigation`), `package.json` (`"version": "2.0.0"`, script `test`: `node --test tests/`)
- Test: `secubox-companion/tests/test_android_statique.py`

**Interfaces:**
- Consumes: contrat JS ↔ natif de Task 2.
- Produces:
  - `@CapacitorPlugin(name = "Boite")` : `ouvrir({origine})` → démarre `BoxActivity` avec l'extra `origine`, résout `{joignable: true}` ; `navigateur({url})` → `Intent.ACTION_VIEW` (https seulement).
  - `BoxActivity` : `WebView` avec JS et DOM storage activés, cookies acceptés (y compris tiers pour l'origine), **aucune** `addJavascriptInterface` ; `WebViewClient.shouldOverrideUrlLoading` : même origine (schéma + hôte + port) → reste ; sinon `ACTION_VIEW` et `true` ; `onReceivedError` / HTTP ≥ 500 sur la **frame principale** au premier chargement → `finish()` et retour à `MainActivity` avec `#injoignable=<origine encodée>` ; retour arrière : `goBack()` si possible, sinon `finish()` ; UA = défaut + ` SecuBoxCompanion/2.0`.
  - `MainActivity` : `registerPlugin(BoitePlugin.class)` avant `super.onCreate` ; `onCreate` et `onNewIntent` : si `intent.data` a le schéma `secubox` → charger `https://localhost/#associer=` + lien encodé dans le WebView Capacitor.
  - Manifest : `intent-filter` `VIEW` + `DEFAULT` + `BROWSABLE`, `data android:scheme="secubox" android:host="associer"` sur `MainActivity` ; `BoxActivity` déclarée `exported="false"`.

- [ ] **Step 1: tests statiques qui échouent** (`test_android_statique.py`, lecture des sources) : intent-filter `secubox`/`associer` présent ; `BoxActivity` non exportée ; `addJavascriptInterface` absent de `BoxActivity.java` ; chaîne `SecuBoxCompanion/2.0` présente ; `versionCode 7` et `versionName "2.0"` ; `allowNavigation` absent de `capacitor.config.json` ; `onNewIntent` présent dans `MainActivity.java`.
- [ ] **Step 2:** pytest → échec.
- [ ] **Step 3:** écrire les classes et modifications ci-dessus.
- [ ] **Step 4:** pytest au vert, puis construire l'APK selon la recette du poste : `npx cap copy android` (jamais `cap sync`), wrapper Gradle repointé sur la distribution en cache `gradle-8.9-bin.zip`, `JAVA_HOME=~/Téléchargements/android-studio-panda2-linux/android-studio/jbr`, `ANDROID_HOME=~/Android/Sdk`, `./gradlew assembleDebug --no-daemon` avec le truststore SecuBox si les téléchargements Maven échouent. Attendu : `BUILD SUCCESSFUL` ; copier vers `secubox-companion/dist/secubox-companion-2.0.apk` ; `apksigner verify --print-certs` (ou `keytool -printcert -jarfile`) montre le certificat de `~/.android/debug.keystore`.
- [ ] **Step 5:** commit `feat(companion): coquille Android — BoxActivity sans pont natif, lien secubox://associer (ref #3683)`.

### Task 4: paquet `secubox-companion` — page `/companion/` et `version.json`

**Files:**
- Create: `packages/secubox-companion/` : `debian/{changelog,control,rules,compat,copyright}`, `www/companion/index.html`, `www/companion/qrcode.js`, `menu.d/companion.json`, `README.md`, `tests/test_page_companion.py`, `tests/test_paquet.py`
- Modify: `packages/secubox-hub/espaces.json` (+ montée de version hub et changelog), profils `mobile` et `full` et métapaquets selon la façon dont `secubox-mobile` y figure, `.github/workflows/build-packages.yml` (exclure `secubox-companion` du CI comme les paquets à binaire construit hors CI, avec commentaire), `secubox-companion/deploy/nginx-companion.conf` (tout `companion.gk2.secubox.in` → `301 https://admin.gk2.secubox.in/companion/`), `secubox-companion/README.md`
- Test: `packages/secubox-companion/tests/`

**Interfaces:**
- Consumes: `secubox-companion/dist/secubox-companion-2.0.apk` (Task 3).
- Produces: fichiers installés `/usr/share/secubox/www/companion/{index.html,qrcode.js,version.json,secubox-companion.apk}`, `/usr/share/secubox/menu.d/companion.json` (aucune route nginx nouvelle : les pages sont servies par le vhost admin).

- [ ] **Step 1: tests qui échouent** :
  - `test_page_companion.py` (Playwright, `version.json` factice) : servie en `https://admin.gk12.secubox.in` simulé (route Playwright) → lien `secubox://associer?box=https%3A%2F%2Fadmin.gk12.secubox.in`, QR rendu (canvas ou svg non vide), version et empreinte affichées, bouton de téléchargement vers `secubox-companion.apk` ; servie en `http://192.168.1.200` → **aucun** lien `secubox://`, message « adresse https de la box » ; pas d'`innerHTML` ; `scrollWidth <= 420`.
  - `test_paquet.py` : `debian/rules` échoue (code ≠ 0) quand l'APK manque (exécuter la cible d'installation dans un répertoire temporaire, ou vérifier le garde `test -f` et son message) ; `version.json` produit par le script de build a les 5 clés et un `sha256` égal à celui du fichier ; SPDX sur chaque fichier nouveau ; `secubox-companion` présent dans l'exclusion CI.
- [ ] **Step 2:** pytest → échec.
- [ ] **Step 3:** écrire le paquet : page Aurora (`?embed=1`, origine prise de `location` : lien proposé seulement si `location.protocol === "https:"` et que le nom d'hôte n'est pas une adresse IP) ; `qrcode.js` = copie adaptée en module ES de `packages/secubox-wireguard/www/luci-static/resources/wireguard-dashboard/qrcode.js` (sans `'require'`, l'original n'est pas modifié) ; `rules` : garde sur l'APK, copie, génération de `version.json` (`sha256sum`, `stat -c %s`) ; menu dans la même catégorie que `secubox-mobile` ; entrées profils/métapaquets/espaces en reprenant celles de `secubox-mobile`.
- [ ] **Step 4:** pytest du paquet + tests du hub au vert ; `dpkg-buildpackage -us -uc -b` dans `packages/secubox-companion` → `.deb` contenant les 4 fichiers de `www/companion/` (`dpkg -c`).
- [ ] **Step 5:** commit `feat(companion): paquet secubox-companion, page /companion/ et version.json (ref #3683)`.
