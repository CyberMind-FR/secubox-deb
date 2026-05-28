# 📸 PhotoPrism

AI-powered photo management

**Category:** Media

## Screenshot

![PhotoPrism](../../docs/screenshots/vm/photoprism.png)

**Deployment:** PhotoPrism runs as a **podman container inside a dedicated
Debian LXC** (`--network=host`), provisioned by `photoprismctl install`. The
host nginx vhost (`:9080`) proxies the public hostname to the LXC at
`10.100.0.130:2342`.

## Nextcloud photo integration

Photos live on the host at `/data/shared/photos`, bind-mounted into PhotoPrism
as `originals` **and** exposed in Nextcloud as the **"PhotoLibrary"** external
storage. Flow:

```
phone (Nextcloud app, auto-upload → PhotoLibrary)
  → Nextcloud  → /data/shared/photos  → PhotoPrism originals
                                         → indexed every 15 min (photoprism-index.timer)
```

PhotoPrism's built-in auto-index only fires for uploads through its *own* UI,
so the timer is what picks up Nextcloud-synced files.

## Features

- Face recognition, auto-tagging, search, albums
- Nextcloud photo integration (shared library + auto-index)

## Installation

```bash
sudo apt install secubox-photoprism   # host dashboard daemon
photoprismctl install                 # provisions the LXC + podman + PhotoPrism
photoprismctl status                  # LXC + service + reachability + index timer
photoprismctl index                   # force an immediate index
```

Admin password is generated to `/etc/secubox/secrets/photoprism-admin`
(rotate via the UI). Wire the public hostname via HAProxy SNI ACL + ACME.

## Configuration

`/etc/secubox/photoprism.toml` — `[lxc]`, `[photoprism]` (http_port, image,
auto_index, originals), `[exposure]` (public_hostname).

## API Endpoints

- `GET /api/v1/photoprism/status` - Module status
- `GET /api/v1/photoprism/health` - Health check

## License

MIT License - CyberMind © 2024-2026
