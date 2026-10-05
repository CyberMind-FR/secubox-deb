<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-socialrelay

SecuBox — relais de reseaux sociaux (fediverse + consentement).

SocialRelay suit des sources sociales, CACHE leurs medias en local (le navigateur ne contacte jamais le tiers) et ouvre un fil BBS par publication.

Trois modes d'acces, JAMAIS de scraping : open (Mastodon/fediverse, public), consent (Facebook via l'API Graph avec un jeton fourni par l'operateur), et bridge (un flux RSS que l'operateur heberge lui-meme).

Paquet Debian : version `0.1.19-1~bookworm1`, architecture `any`.

## Contenu

- `cmd/` : sources Go
- `internal/` : fichiers du module
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `systemd/` : unités systemd
- `tmpfiles/` : répertoires d'exécution
- `vendor/` : fichiers du module

## Exécution

Socket Unix : `/run/secubox/bbs.sock`, `/run/secubox/socialrelay.sock`.
- `secubox-socialrelay.service` : SecuBox SocialRelay — relais de reseaux sociaux (medias caches, fils BBS) (utilisateur `secubox-socialrelay`), lance `secubox-socialrelayd`
