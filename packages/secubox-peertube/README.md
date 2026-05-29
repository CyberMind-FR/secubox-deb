# 📺 PeerTube

Federated video platform

**Category:** Media

## Screenshot

![PeerTube](../../docs/screenshots/vm/peertube.png)

**Deployment:** PeerTube runs **natively inside a dedicated Debian LXC**
(its own `peertube.service`: Node 22 + PostgreSQL 15 + Redis + ffmpeg), not
in Docker/Podman — an unprivileged LXC can't reliably bring up a podman CNI
bridge on the Marvell arm64 boards. The host nginx vhost (`:9080`) proxies
the public hostname to the LXC at `10.100.0.120:9000`.

## Features

- Video hosting, channels, users, federation (ActivityPub)
- **Import from URL** (YouTube/Vimeo/direct file) via PeerTube's native HTTP
  import (yt-dlp) — from the dashboard "Import" tab or PeerTube's own UI
- Transcoding settings (HLS, WebTorrent), plugins, storage monitoring
- Host dashboard at `/peertube/` + `/api/v1/peertube/*`

## Installation

```bash
sudo apt install secubox-peertube     # installs the host dashboard daemon
peertubectl install                   # provisions the LXC + native PeerTube
peertubectl status                    # LXC state + HTTP reachability
```

Then wire the public hostname: add the HAProxy SNI ACL
(`host_<host> → nginx_vhosts`) and an ACME cert. The package ships the nginx
vhost at `/etc/nginx/sites-available/peertube.conf` (symlinked into
sites-enabled by postinst).

The first-boot admin password is captured to
`/etc/secubox/secrets/peertube-admin` (rotate it via the web UI; if you do,
update that file or the dashboard's write operations re-auth fails).

## Configuration

`/etc/secubox/peertube.toml` — `[lxc]` (name/ip/path), `[peertube]`
(http_port/admin/transcoding), `[exposure]` (public_hostname).

## API Endpoints

- `GET  /api/v1/peertube/status`  — real LXC state + HTTP reachability + version
- `GET  /api/v1/peertube/health`  — health check
- `POST /api/v1/peertube/import`  — `{target_url, channel_id?, name?, privacy}`
- `GET  /api/v1/peertube/imports` — recent import jobs
- `POST /api/v1/peertube/container/{install,start,stop,restart}` — LXC lifecycle

## License

MIT License - CyberMind © 2024-2026
