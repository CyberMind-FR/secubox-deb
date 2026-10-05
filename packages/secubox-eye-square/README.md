<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-eye-square

SecuBox Eye Remote — Square variant (Pi 4B / Pi 400 + 7" 800x480).

Pillow-on-framebuffer single-process kiosk. Renders the SecuBox dashboard directly to /dev/fb0 — no X server, no Qt, no Chromium. Companion to the round/ Pi Zero W variant (also Pillow+fb).

Includes a privileged Helper FastAPI on a Unix socket (SO_PEERCRED) for USB gadget mode switching, service restart, lockdown (nftables atomic swap), and console streaming.

Paquet Debian : version `1.0.4-1~bookworm1`, architecture `all`.

## Contenu

- `helper/` : fichiers du module
- `kiosk/` : fichiers du module

## Exécution

Socket Unix : `/run/secubox/eye-square-helper.sock`.

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `POST` | `/` | aucune |
| `GET` | `/state` | aucune |
| `POST` | `/mode` | aucune |
| `POST` | `/restart` | aucune |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`, `secubox-eye-remote`.

## Tests

22 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-eye-square`.
