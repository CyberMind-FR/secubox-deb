# secubox-podcaster

Modern podcast manager for SecuBox — subscribe, download locally, and relay a
shareable RSS feed.

## What it does (v1, #726)

- **Subscribe** by RSS URL or **OPML import** (pure-stdlib feed parsing — no
  `feedparser` dependency).
- **Download locally** into `media_path` via an asyncio + httpx queue with
  per-episode progress.
- **Relay / share**: a generated RSS of the local library at
  `/api/v1/podcaster/share/feed.xml`. LAN by default; set `public_base` to your
  exposed vhost to publish externally.
- **In-UI service status + TOML config**; modern C3BOX WebUI with inline player.

Lyrion integration is deferred to a follow-up (standalone first).

## Layout

| Path | Role |
|------|------|
| `/usr/share/secubox/podcaster/api` | FastAPI app (uvicorn WorkingDirectory) |
| `/run/secubox/podcaster.sock` | Unix socket |
| `/var/lib/secubox/podcaster/podcaster.db` | SQLite store |
| `/var/lib/secubox/podcaster/media/<feed_id>/` | downloaded episodes |
| `/etc/secubox/podcaster.toml` | config |
| `/etc/nginx/secubox-routes.d/podcaster.conf` | nginx route (active include) |

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health`, `/status` | public | service + counts |
| GET | `/share/feed.xml` | public | shareable RSS of local library |
| GET | `/media/{id}` | public | stream a downloaded episode |
| GET/POST/DELETE | `/feeds*` | JWT | manage feeds (+ `/feeds/import-opml`) |
| GET | `/episodes` | JWT | list (optional `feed_id`, `state`) |
| POST | `/episodes/{id}/download` | JWT | enqueue download |
| GET/POST | `/config` | JWT | TOML config |

## Public exposure (relay to the web)

Publish the share feed externally via HAProxy TLS → mitmproxy (never bypass the
WAF):

```bash
haproxyctl vhost add podcast.gk2.secubox.in   # backend = mitmproxy_inspector
# add the route to BOTH mitmproxy routes files -> 127.0.0.1:<nginx>
systemctl restart mitmproxy
```

Then set `public_base = "https://podcast.gk2.secubox.in"` in
`/etc/secubox/podcaster.toml` and restart `secubox-podcaster` so the generated
feed's enclosure URLs are absolute.

---
*CyberMind — Gérald Kerma. LicenseRef-CMSD-1.0.*
