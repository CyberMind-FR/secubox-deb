<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-freeboxtv

SecuBox — streamer Freebox TV (RTSP vers HLS, on-demand).

Derriere une Freebox, les chaines TV sont exposees en RTSP unicast. Un navigateur ne lit pas le RTSP : ce module interpose un sas ffmpeg RTSP->HLS (remux -c copy, sans re-encodage), lance A LA DEMANDE par chaine et tue apres inactivite. Il sert la playlist de base (variante standard) et le HLS que la cardlet du Hall joue. Donnees reelles uniquement, usage personnel LAN.

Paquet Debian : version `0.1.2-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `conf/` : configuration livrée
- `systemd/` : unités systemd
- `tests/` : tests

## Exécution

Socket Unix : `/run/secubox/freeboxtv.sock`.
- `secubox-freeboxtv.service` : SecuBox Freebox TV — streamer on-demand (RTSP->HLS) (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/channels` | require_lecture |
| `GET` | `/hls/{cid}/live.m3u8` | require_lecture |
| `GET` | `/hls/{cid}/{seg}` | require_lecture |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

1 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-freeboxtv`.
