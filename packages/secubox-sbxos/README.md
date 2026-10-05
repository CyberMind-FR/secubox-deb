<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-sbxos

SBX OS — the Hall as an installable PWA.

The Hall that fits in a pocket. A Progressive Web App that reproduces the SecuBox Hall on any phone, tablet or desktop: a checkerboard of cardlets, each opening a place rather than an application — Cinema, Radio, Billets, Cloud.

Two sources decide what you see, and they are kept apart on purpose. The MINE says what is AVAILABLE: the box decides, per profile, and ships a manifest. The HALL says what is SHOWN: order, favourites, hidden modules, opening screen, theme — the user decides, in the browser, and nothing leaves the device.

Offline first. The shell is cached so the app opens instantly with no network; the manifest is fetched network-first so a freshly granted cardlet appears at once; watched media are kept for replay. Nothing else is cached — not API calls, not other origins.

V1 carries no backend: the manifest is served as a file and profiles are simulated locally, so the whole journey — including the invitation — is playable end to end. The data contract is already the one the box will serve.

Paquet Debian : version `0.6.0~aurora14-1~bookworm1`, architecture `all`.

## Contenu

- `app/` : fichiers du module
- `nginx/` : route nginx
- `outils/` : fichiers du module
- `sbx-sdk/` : fichiers du module
- `tests/` : tests
- `vitrine/` : fichiers du module
- `www/` : interface web

## Tests

1 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-sbxos`.
