<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-radio

SecuBox — radio et television collaboratives synchronisees.

Une playlist partagee ou tout le monde ecoute et regarde la meme chose au meme instant. Les membres proposent, la communaute soutient, le sysop valide.

Le tirage est pondere par la nouveaute, les coeurs et un temps de repos, de sorte qu'une nouveaute s'entende sans qu'un succes monopolise l'antenne.

Les clips sont rapatries une seule fois par la passerelle yt-dlp puis servis depuis la board : aucun auditeur ne contacte de service tiers.

Paquet Debian : version `0.1.76-1~bookworm1`, architecture `any`.

## Contenu

- `capabilities.d/` : fichiers du module
- `cmd/` : sources Go
- `internal/` : fichiers du module
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `systemd/` : unités systemd
- `tmpfiles/` : répertoires d'exécution
- `vendor/` : fichiers du module
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/bbs.sock`, `/run/secubox/radio.sock`.
- `secubox-radio.service` : SecuBox Radio — radio collaborative synchronisee (utilisateur `secubox-radio`), lance `secubox-radiod`

## Dépendances SecuBox

`secubox-sbxui`.
