<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-ytsas

YouTube/web-media SAS for SecuBox (LXC-native).

Paste a YouTube (or any yt-dlp-supported site) link, pull it into a staging space and watch it in the browser (HTTP Range) — then decide: Garder (conserve) or leave ephemeral with an opt-in purge TTL. The yt-dlp fetch engine runs isolated in a dedicated LXC (cookie vault for age-gated/private videos stays inside it); the host only proxies an authenticated vhost and mediates the conserve pipeline — video to PeerTube, audio (mp3/flac/…) to Lyrion; ffmpeg (ffprobe) lets the host resolve ambiguous containers precisely.

Paquet Debian : version `0.2.12-1~bookworm1`, architecture `all`.

## Contenu

- `conf/` : configuration livrée
- `lxc/` : fichiers du module
- `menu.d/` : entrée de menu
- `nft/` : fichiers du module
- `nginx/` : route nginx
- `sbin/` : exécutables
- `systemd/` : unités systemd
- `tests/` : tests
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/aggregator.sock`.
- `secubox-ytsas-conserve.service` : SecuBox ytsas → PeerTube conserve queue processor, lance `secubox-ytsas-conserve`
- `secubox-ytsas-conserve.timer` : SecuBox ytsas conserve — drain the PeerTube upload queue
- `secubox-ytsas.service` : SecuBox YouTube SAS (yt-dlp fetch + FastAPI), lance `python3`

## Dépendances SecuBox

`secubox-core`.

## Tests

4 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-ytsas`.
