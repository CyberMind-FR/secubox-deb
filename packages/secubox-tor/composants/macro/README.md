<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-macro

SecuBox vetted access-macro framework + tor-exit kind.

Root dispatcher secubox-macroctl and the vetted tor-exit macro that offers a node's Tor SOCKS port to approved mesh peers.

Paquet Debian : version `0.1.0-1~bookworm1`, architecture `all`.

## Contenu

- `apparmor/` : profil AppArmor
- `conf/` : configuration livrée
- `macros.d/` : fichiers du module
- `sbin/` : exécutables
- `sudoers.d/` : règles sudo
- `tests/` : tests

## Dépendances SecuBox

`secubox-core`.

## Tests

2 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-macro`.
