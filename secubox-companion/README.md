<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# SecuBox Companion 2.0

Coquille Android de l'administration de SecuBox (`in.secubox.companion`, versionName 2.0). L'appli ne réimplémente rien :
elle **associe** une ou plusieurs box (adresse `https://admin.<box>`), puis charge l'administration de la box dans un WebView.
La connexion est celle de la page de connexion habituelle de la box (mot de passe, 2FA) ; la session vit dans le stockage
du WebView, comme dans un navigateur. Pas de pont natif exposé à l'origine distante.

## Fonctionnement

- **Écrans locaux** (`www/`, Capacitor `webDir`) : « Associer une box », « Box injoignable » (réessayer, changer de box),
  sélecteur des box associées. JavaScript sans bundler, modules ES (`www/core/app.js`, `www/core/boites.js`).
- **Navigation** limitée à l'origine associée ; tout autre lien s'ouvre dans le navigateur du téléphone.
- **Lien d'association** : `secubox://associer?box=<origine https encodée>` (https obligatoire, ni identifiant ni chemin,
  confirmation affichant le nom d'hôte, aucun secret dans le lien).
- **Mises à jour** : au lancement, l'écran local lit `https://<box associée>/companion/version.json` et, si son champ
  `version` dépasse « 2.0 », propose d'ouvrir `/companion/` dans le navigateur. Pas d'installation par l'appli.
- Le WebView ajoute `SecuBoxCompanion/2.0` à son User-Agent.

## Côté box : paquet `secubox-companion`

Le paquet Debian `packages/secubox-companion/` sert, sur le vhost d'administration existant (aucun vhost ni route WAF
nouveaux), `/companion/` : page de téléchargement (version, empreinte SHA-256), lien et QR code d'association,
`version.json` et l'APK. Voir `packages/secubox-companion/README.md`.

L'ancien vhost `companion.gk2.secubox.in` (PWA 1.x) n'existe plus : `deploy/nginx-companion.conf` le redirige vers
`https://admin.gk2.secubox.in/companion/` pendant la période de transition.

## Construire l'APK

L'APK n'est jamais commité (`dist/` est ignoré) : il se construit sur le poste de développement, puis se dépose dans
`dist/` pour la construction du paquet. Signature : clé de débogage du poste (`~/.android/debug.keystore`), comme les
versions 1.x, pour que la mise à jour par-dessus reste possible ; sauvegarder cette clé avec les secrets du propriétaire.

```bash
cd secubox-companion
npm install                                        # @capacitor/* 6.x
npx cap copy android                               # génère les fichiers Capacitor ignorés par git
echo "sdk.dir=$HOME/Android/Sdk" > android/local.properties
cd android
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 ANDROID_HOME=$HOME/Android/Sdk
./gradlew assembleRelease --no-daemon              # signé avec la clé de débogage
mkdir -p ../dist
cp app/build/outputs/apk/release/app-release.apk ../dist/secubox-companion-2.0.apk
apksigner verify --print-certs ../dist/secubox-companion-2.0.apk
```

Une nouvelle version : monter `versionCode` et `versionName` dans `android/app/build.gradle`, puis `VERSION` et
`VERSION_CODE` dans `packages/secubox-companion/debian/rules` et la version du paquet.

## Tests

```bash
npm test                                           # tests Node des listes de box
python -m pytest -q -p no:cacheprovider secubox-companion/tests   # écrans locaux (Playwright) et sources Android
```

## Disposition

```
secubox-companion/
├── www/                 # écrans locaux (index.html, core/, styles/, assets/)
├── android/             # projet Capacitor : BoxActivity, plugin Boite, manifeste
├── deploy/              # redirection de l'ancien vhost companion.gk2
├── dist/                # APK construit (ignoré par git)
├── capacitor.config.json
└── package.json
```

Licence CMSD-1.0 (`LicenseRef-CMSD-1.0`).
