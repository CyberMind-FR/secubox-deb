<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-groupd

SecuBox — hote de groupe pour les modules.

Sert plusieurs modules SecuBox dans un seul interpreteur Python, chacun sur sa socket habituelle. L'interpreteur, FastAPI et Starlette sont ainsi payes une fois au lieu d'une fois par module : 82 modules tiennent dans 180 Mo la ou leurs demons separes en occupaient 3070.

L'empaquetage reste separe et modulaire : chaque module garde son paquet et son unite. C'est l'INSTALLATION qui est rassemblee — un module se declare groupable en deposant un fichier a son nom dans /usr/share/secubox/groupable.d, et le groupe constate ce que l'installation contient au lieu de tenir une liste.

Paquet Debian : version `0.3.0-1~bookworm1`, architecture `all`.

## Contenu

- `sbin/` : exécutables
- `systemd/` : unités systemd

## Exécution

- `secubox-group-root@.service` : SecuBox — groupe PRIVILEGIE de modules « %i » (utilisateur `root`), lance `secubox-groupd`
- `secubox-group@.service` : SecuBox — groupe de modules « %i » dans un interpreteur partage (utilisateur `secubox`), lance `secubox-groupd`
