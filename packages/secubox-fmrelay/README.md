# secubox-fmrelay

FM broadcast → Icecast2 MP3 mount with live RDS metadata, controlled
from the SecuBox dashboard. Closes [#377](https://github.com/CyberMind-FR/secubox-deb/issues/377).

## What it does

- `rtl_fm | ffmpeg -c:a libmp3lame` pipes RTL-SDR FM audio into an
  Icecast2 SOURCE mount. ffmpeg speaks `icecast://` natively and
  handles reconnects, so the runner stays small.
- A parallel `rtl_fm | redsea` pipeline decodes the 57 kHz RDS
  subcarrier (PI / PS / RT) and POSTs each RadioText update to
  `icecast2/admin/metadata`, so HTTP listeners see
  `Artist - Title` change live.
- A small FastAPI on `/run/secubox/fmrelay.sock` exposes lifecycle
  + introspection endpoints, consumed by the SecuBox admin webui.

The Icecast mount it produces is what the SecuBox **webradio** module
serves and what **Lyrion** ingests as a Favourite remote URL.

## Hardware sharing — RTL-SDR

The dongle is shared with `secubox-sentinelle-gsm` (GSM scans + RDS
sweep). Don't start a relay while a GSM scan is running — the bus
contention will crash both. Cross-package device-claim coordination is
planned for v0.2.

## API

| Method | Path                          | Description                                       |
|--------|-------------------------------|---------------------------------------------------|
| GET    | `/api/v1/fmrelay/healthz`     | liveness probe                                    |
| GET    | `/api/v1/fmrelay/version`     | version + build sha                               |
| GET    | `/api/v1/fmrelay/status`      | overall green / yellow / red                      |
| GET    | `/api/v1/fmrelay/components`  | per-component state (icecast2 / rtl_fm / lame / redsea / runner) |
| GET    | `/api/v1/fmrelay/access`      | mount URL (lan) + webradio URL (public) — admin UI button reads from here |
| GET    | `/api/v1/fmrelay/mounts`      | active Icecast mounts + listener counts           |
| GET    | `/api/v1/fmrelay/now-playing` | current RDS RadioText (or `{}`)                   |
| POST   | `/api/v1/fmrelay/start`       | `{freq, mount, bitrate?, gain?, ppm?}`            |
| POST   | `/api/v1/fmrelay/stop`        | stop runner + redsea-icy pusher                   |

All routes are SSO-gated via `auth_request /__sbx_auth_verify`
(Authelia). Per **MODULE-GUIDELINES.md §4** the admin webui never
hardcodes external URLs — the `Open Webradio →` button reads its
target from `/access` at runtime (single source of truth).

## CLI

```
fmrelayctl components [--json]
fmrelayctl status     [--json]
fmrelayctl access     [--json]
fmrelayctl mounts     [--json]
fmrelayctl now-playing [--json]
fmrelayctl start FREQ --mount NAME [--bitrate K] [--gain dB] [--ppm N]
fmrelayctl stop
fmrelayctl version
```

Example:

```bash
fmrelayctl start 103.9M --mount savoie --bitrate 128 --gain 49 --ppm 60
fmrelayctl mounts
fmrelayctl stop
```

## Config — `/etc/secubox/fmrelay.toml`

Seeded from `fmrelay.toml.example` on first install. Operator only
needs to swap the default `hackme` Icecast2 credentials.

```toml
[icecast]
icecast_host         = "127.0.0.1"
icecast_port         = 8000
icecast_admin_pass   = "<change-me>"
icecast_source_pass  = "<change-me>"

[runner]
bitrate_kbps         = 128
gain_db              = 49
ppm                  = 0

[exposure]
webradio_url         = "https://admin.gk2.secubox.in/webradio/"
```

## Dependencies

- `rtl-sdr` — RTL-SDR userspace + `rtl_fm`
- `ffmpeg` — libmp3lame encoder + Icecast SOURCE client
- `icecast2` — the streaming server
- `curl` — used by `fmrelayctl mounts` against `/admin/listmounts`
- `python3-fastapi`, `python3-uvicorn` — FastAPI host
- `secubox-core` (≥ 1.0) — shared SecuBox runtime
- `redsea` — optional, falls back to `/usr/libexec/secubox/secubox-redsea`
  if shipped by `secubox-sentinelle-gsm`

## Files installed

```
/usr/sbin/fmrelayctl
/usr/libexec/secubox/secubox-fmrelay-runner
/usr/libexec/secubox/secubox-fmrelay-icy
/usr/lib/secubox/fmrelay/api/main.py
/usr/share/secubox/www/fmrelay/index.html
/usr/share/secubox/menu.d/72-fmrelay.json
/etc/nginx/secubox.d/fmrelay.conf
/etc/nginx/secubox-routes.d/fmrelay.conf
/etc/secubox/fmrelay.toml.example
/lib/systemd/system/secubox-fmrelay.service
```

## Service

`secubox-fmrelay.service` runs uvicorn as `secubox:secubox` on
`/run/secubox/fmrelay.sock`, with `NoNewPrivileges`, `ProtectHome`,
`PrivateTmp` and a restricted `ReadWritePaths` set. The actual
rtl_fm/ffmpeg/redsea child processes are spawned by the runner +
icy scripts in `/usr/libexec/secubox/`.
