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

## Flux du compte YouTube (0.4.0)

`GET /api/v1/ytsas/flux?type=envie|propositions|abonnements|historique&limite=24` : les listes que YouTube tient pour le compte dont
les cookies sont dans le coffre (`/var/lib/secubox/ytsas/cookies.txt`). **Lecture seule**, une requête à plat (`yt-dlp --flat-playlist`),
rien n'est téléchargé ni modifié. Cache 15 min (`YTSAS_FLUX_TTL`), un appel à la fois par flux, repli sur la dernière lecture si YouTube
refuse (`perime: true`). `GET /api/v1/ytsas/flux/vignette/<id>` sert la vignette par la box (hôtes ytimg / ggpht seulement).
Sans cookies : 401. Ces routes exigent l'en-tête `X-Sbx-Flux: 1`, posé uniquement par le Hall après `auth_request` ; elles sont
refusées en accès direct. Carte du Hall : `secubox-webos` « Flux YouTube ».
