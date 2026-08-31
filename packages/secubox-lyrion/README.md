# 🎵 Lyrion Music

Music streaming server

**Category:** Media

## Screenshot

![Lyrion Music](../../docs/screenshots/vm/lyrion.png)

## Features

- Music library
- Playlists
- Radio
- Multi-room

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-lyrion
```

## Configuration

Configuration file: `/etc/secubox/lyrion.toml`

## API Endpoints

- `GET /api/v1/lyrion/status` - Module status
- `GET /api/v1/lyrion/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).

## Lecteur web + agent de cast (2026-08-31)

Deux ajouts autour de la carte Hall « Lyrion » :

- **Cast** — `POST /player/{id}/play-url {"url"}` (LMS `playlist play`). Le Hall
  relaie SON audio (radio / diffusion du parc, bouton 📡 de la carte) vers un
  lecteur Squeezebox physique. URL en valeur JSON (pas de shell), schéma
  `http(s)` validé, LAN-only comme les autres transports.

- **Lecteur web « SBX-Web »** — un **vrai client LMS** jouable dans le
  navigateur, sans matériel. `squeezelite` tourne *headless* en `-o null` (il
  s'enregistre auprès de LMS comme un lecteur et défausse l'audio local) ; le
  navigateur écoute le flux que **LMS produit déjà** pour ce lecteur
  (`/stream.mp3?player=MAC`), relayé de même origine par le Hall
  (`/lyrion-stream.mp3`). Unité `sbx-lyrion-webplayer.service`, config
  `/etc/secubox/lyrion-webplayer.env` (nom, MAC fixe, hôte LMS).

  > Un premier essai via carte ALSA loopback (`snd-aloop`) + `ffmpeg` + `icecast`
  > a été abandonné (le loopback refuse le format tant que rien ne joue). Le flux
  > natif LMS est plus simple et robuste — LMS fait le transcodage.

  État : client réel + télécommande + cast **OK** ; le dernier maillon
  cast→flux-navigateur pour le player à MAC fixe reste à finaliser.
