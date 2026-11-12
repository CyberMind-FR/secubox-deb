<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# secubox-companion

Paquet `all` qui livre sur la box l'appli Android **Companion 2.0** et sa page d'association. Pas de service, pas d'API, pas
de socket, pas de route nginx ni WAF nouvelle : les fichiers sont servis comme les autres pages par le vhost
d'administration (`https://admin.<box>/companion/`), sans connexion (la page ne contient rien de secret).

## Fichiers installés

| Chemin | Rôle |
|---|---|
| `/usr/share/secubox/www/companion/index.html` | page Aurora (`?embed=1` : sans menu) : version, empreinte SHA-256, bouton de téléchargement, « Ouvrir dans l'appli », QR code |
| `/usr/share/secubox/www/companion/qrcode.js` | générateur de QR code (module ES, SVG construit élément par élément) |
| `/usr/share/secubox/www/companion/secubox-companion.apk` | l'APK (≈ 3 Mo) |
| `/usr/share/secubox/www/companion/version.json` | `{"version": "2.0", "version_code": 7, "sha256": "…", "taille": …, "fichier": "secubox-companion.apk"}` lu par l'appli |
| `/usr/share/secubox/menu.d/companion.json` | entrée de menu (catégorie `root`, comme `secubox-mobile`) ; rattachée à l'espace Système dans `secubox-hub/espaces.json` |

## Lien d'association

La page propose `secubox://associer?box=<origine encodée>` seulement si elle est ouverte en **https** sur un **nom d'hôte**
(pas une adresse IP) ; l'origine vient de `location`, jamais d'une valeur en dur. Ailleurs, elle demande d'ouvrir l'adresse
https de la box. Le même lien est affiché en QR code pour un autre téléphone.

## Construction

L'APK est construit hors de la box (`secubox-companion/README.md`) et n'est pas commité. `debian/rules` attend
`secubox-companion/dist/secubox-companion-2.0.apk` (variable `APK=` pour un autre chemin) et **échoue** s'il manque.
`version.json` est calculé à la construction par `build/version-json.sh` depuis l'APK installé (`sha256sum`, `stat -c %s`).
`dh_strip_nondeterminism` est neutralisé : réécrire l'APK changerait son empreinte et romprait sa signature.

```bash
cd packages/secubox-companion
dpkg-buildpackage -us -uc -b          # .deb dans packages/ ; jamais construit dans le CI (SKIP_CI)
```

## Profils et métapaquets

`secubox-service-administration` le recommande, `secubox-mobile` en dépend, et les profils `mobile` et `full` l'activent
(`companion`).

## Tests

```bash
python -m pytest -q -p no:cacheprovider packages/secubox-companion/tests
```

Les tests de page utilisent Playwright (box simulée par routes) ; `test_paquet.py` vérifie la garde sur l'APK, le
`version.json`, les en-têtes SPDX et l'exclusion du CI.
