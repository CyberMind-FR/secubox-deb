<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-torrent v2.0 — WebTorrent Streaming Pivot — Design Spec

**Issue:** #917
**Date:** 2026-07-28
**Status:** Design approved, pending spec review → implementation plan

## Goal

Pivot the dormant `secubox-torrent` module from a Transmission download-manager
into a **WebTorrent streaming** module: paste a magnet → watch it in the browser
(HTML5 `<video>`, HTTP Range) while it downloads. Ephemeral by default, with an
optional **Keep** action that retains a title in a persistent library on the
SSD `/data`. True WebRTC-hybrid: the browser participates in the swarm.

## Non-Goals (YAGNI)

- No RSS / scheduled downloads (that was Transmission's job; dropped).
- No multi-user quotas / per-user libraries (single admin-scoped tool; master
  users gk2 + admin only).
- No transcoding (serve the file as-is; the browser plays what it can — MP4/WebM
  natively; MKV/AVI may not play — documented, not solved in v1).
- No built-in search/indexer (paste magnets/torrent files only).
- No antivirus scan hook in v1 (noted as a future SecuBox-native extension).

## Context & Constraints

- **Board:** MOCHAbin gk2, Debian bookworm **arm64**. Storage: eMMC (small, fills
  up) + USB SSD mounted at `/data` (media MUST live here — see podcaster).
- **Existing module:** `secubox-torrent` 1.0.0 (host FastAPI + Transmission via
  Docker) — installed on gk2 but **dormant/inactive**. This pivot **replaces**
  it; the package name, vhost, and menu entry are preserved (version → 2.0.0).
- **SecuBox module pattern:** LXC-native app modules (peertube/podcaster/lyrion),
  fronted by a host vhost → HAProxy (TLS 1.3) → sbxwaf (:8085) → nginx (:9080) →
  LXC. Auth = JWT `sbx_token` (localStorage), master users gk2 + admin.
- **Security posture:** torrent connects to **untrusted peers** — on a security
  appliance the engine MUST be isolated in a dedicated LXC, never on the host.

## Architecture

```
Browser (player webui, <video>)
  │  https://torrent.gk2.secubox.in/  + /api/*  + /stream/*
  ▼
HAProxy (TLS 1.3) ──► sbxwaf (:8085) ──► nginx (:9080)
  │  JWT gate (auth_request → secubox-auth) on /api + /stream + panel
  ▼
LXC "torrent" (isolated, 10.100.0.x, /data-backed)
  └─ Node.js service (systemd inside LXC):
       ├─ engine        (webtorrent-hybrid: BitTorrent + WebRTC via @roamhq/wrtc)
       ├─ stream server (Fastify: GET /stream/:infohash/:file → Range → res)
       ├─ library       (better-sqlite3: ephemeral/kept state + purge)
       └─ api + static  (Fastify: /api/* JSON, serves the player webui)
```

**Isolation & egress:** the LXC's outbound torrent traffic is scoped by an nft
rule set on the host (the LXC's veth), logged and rate-limitable. The webui is
reachable ONLY through the WAF vhost; the LXC's Node port is not exposed on the
LAN directly.

**wrtc-arm64 risk (Task 1 spike):** `@roamhq/wrtc` ships arm64 prebuilds; if the
prebuild fails to load in the bookworm-arm64 LXC, fall back to **BitTorrent-only**
(`webtorrent` without the WebRTC transport). The player + streaming are identical;
only browser-peer swarm participation is lost. The spike gates which npm dep the
package pins.

## Components

Each is a focused unit with one responsibility and a mockable interface.

### `engine.js` (torrent engine wrap)
- Wraps a single `WebTorrent` client instance.
- `add(magnetOrTorrent) → {infohash, name, files:[{idx,name,length,type}]}`
  (resolves once metadata is available; timeout → error).
- `get(infohash) → torrent | null`; `remove(infohash, {deleteData})`.
- `stats(infohash) → {progress, downloadSpeed, uploadSpeed, numPeers, wires:[{type:'webrtc'|'tcp'|'utp', addr}]}`.
- Enforces a max-concurrent-torrents cap (config) to bound memory.
- Interface is injectable so tests use a `FakeWebTorrent` (no network).

### `stream.js` (HTTP Range streaming)
- `GET /stream/:infohash/:fileIdx` → validates infohash+idx, sets
  `Content-Type` from file ext, honours the `Range` header, pipes
  `file.stream({start,end})` to the response. Supports seeking (multiple Range
  requests) while the torrent is still downloading (WebTorrent handles
  out-of-order piece prioritisation on read).
- 404 for unknown infohash/idx; 416 for unsatisfiable range.

### `library.js` (persistence + retention)
- SQLite (`better-sqlite3`) at `/data/torrent/library.db`.
- Row per torrent: `infohash, name, magnet, added_at, last_played_at, kept(0/1),
  path`. Ephemeral rows (kept=0) live under `/data/torrent/tmp/<infohash>/`;
  kept rows under `/data/torrent/library/<infohash>/`.
- `keep(infohash)` → move files tmp→library, set kept=1 (continues seeding).
- `unkeep(infohash)`, `remove(infohash)`.
- **Purge policy:** a periodic sweep removes ephemeral (kept=0) torrents whose
  `last_played_at` is older than `ephemeral_ttl` (config, default 6 h) OR when
  `/data` free space drops below a floor (config) — oldest-ephemeral-first.
  Kept torrents are never auto-purged. All purges logged.

### `api.js` (control API, Fastify)
- `GET /api/v1/torrent/status` → engine up, counts, disk free.
- `POST /api/v1/torrent/add {magnet}` → engine.add + library insert (kept=0).
- `GET /api/v1/torrent/list` → library rows + live stats.
- `GET /api/v1/torrent/files/:infohash` → file list.
- `POST /api/v1/torrent/keep/:infohash`, `POST /api/v1/torrent/remove/:infohash`.
- `GET /api/v1/torrent/health`.
- All JSON; auth enforced at the host WAF layer (see below), the LXC service
  trusts the proxied request (LXC is not LAN-exposed).

### `www/` player webui
- Single-page (SecuBox webui look per WEBUI-PANEL-GUIDELINES, reads `sbx_token`):
  magnet input → on add, show file list → click a playable file → `<video
  src="/stream/:infohash/:idx" controls>`; **📌 Keep** / **🗑 Remove** buttons;
  a live stats strip (progress, peers, WebRTC vs TCP/uTP wire count).
- Non-playable files (unknown container) show a **Download** link instead of the
  player.

### Host side (thin)
- `debian/` package installs: the LXC (`install-lxc.sh`, idempotent, same
  pattern as peertube/podcaster), the host **vhost** (`nginx/torrent.conf` →
  proxies to the LXC), the **WAF route** (haproxy-routes.json), the **menu.d**
  entry, `/etc/secubox/torrent.toml`, and an **nft egress drop-in** for the LXC
  veth. No business logic on the host — it only proxies + authenticates.
- Auth: the vhost uses the standard SecuBox `auth_request` → secubox-auth to
  gate `/`, `/api/`, and `/stream/` with the `sbx_token` cookie/bearer, exactly
  like other module vhosts.

## Data Flow

1. User pastes a magnet in the webui → `POST /api/v1/torrent/add`.
2. `engine.add` fetches metadata → returns file list; `library` inserts kept=0
   under `/data/torrent/tmp/<infohash>/`.
3. User clicks a playable file → browser opens `<video src=/stream/:infohash/:idx>`.
4. `stream.js` serves Range requests; WebTorrent prioritises the needed pieces →
   playback starts before full download; seeking issues new Range requests.
5. In hybrid mode, the browser (loading webtorrent in-page, optional v1.1) and the
   LXC engine both peer over WebRTC + BitTorrent.
6. User clicks **Keep** → files moved tmp→library, kept=1, seeding continues.
   Otherwise the purge sweep removes the ephemeral torrent after TTL / on low disk.

## Config (`/etc/secubox/torrent.toml`)

```toml
[engine]
max_active = 5              # concurrent torrents cap
download_dir = "/data/torrent"
webrtc = true               # false forces BitTorrent-only (fallback)

[retention]
ephemeral_ttl_hours = 6     # purge ephemeral not played within this window
disk_floor_gb = 5          # purge oldest ephemeral when /data free < this

[net]
# torrent listen port inside the LXC; host nft scopes egress on the veth
listen_port = 6881
```

## Error Handling

- `engine.add` metadata timeout → 504 + user-facing "magnet unreachable / no
  peers".
- wrtc load failure at boot → log once, run BitTorrent-only, expose
  `webrtc:false` in `/status` so the webui shows a "BitTorrent-only" badge.
- Disk full on `/data` → `add` refused with a clear error; purge sweep triggers.
- LXC down → host vhost returns 502; a host watchdog (existing secubox-watchdog
  pattern) may restart the LXC.
- Stream of a still-metadata-less torrent → 409 "not ready".

## Security & Confinement

- **LXC isolation:** untrusted peer traffic never touches the host.
- **nft egress scope:** host drop-in on the LXC veth — allow the torrent listen
  port + DHT/WebRTC, log the rest; rate-limitable. (OUTPUT is `policy accept`
  repo-wide, so containment is a **drop-based** rule on the veth, not an allow —
  same lesson as the meshtastic on-grid note.)
- **WAF + JWT:** webui/API/stream only reachable through sbxwaf + `auth_request`;
  master users gk2 + admin.
- **No host business logic:** compromise of the Node engine is contained to the LXC.
- Future (not v1): scan **kept** files via antirootkit/ClamAV before they land in
  the library.

## Testing

- `engine` against a `FakeWebTorrent` (deterministic metadata/files/stats) — no
  network.
- `stream` Range handling: full, partial, open-ended, unsatisfiable (416),
  seeking mid-download (mock file stream).
- `library`: insert/keep/unkeep/remove + purge policy (TTL + disk-floor) on a
  tmp SQLite + tmp dirs.
- `api`: each route, JSON shape, error codes (mock engine/library).
- `packaging`: install-lxc.sh idempotency assertions, vhost + WAF route present,
  nft drop-in sorts after the table-creator, config installed.
- No real BitTorrent/WebRTC in tests. The **wrtc-arm64 spike (Task 1)** is a
  manual/CI feasibility check, not a unit test.

## Open Questions (resolved defaults)

- **Name/version:** keep `secubox-torrent`, bump to **2.0.0-1~bookworm1**; the
  1.0.0 Transmission code is removed. Vhost host = `torrent.gk2.secubox.in`
  (existing) preserved.
- **LXC provisioning:** reuse the existing `install-lxc.sh` LXC pattern
  (peertube/podcaster), Debian bookworm arm64 base + Node LTS.
- **Browser-side WebRTC peer (in-page webtorrent):** deferred to v1.1 — v1 ships
  the server-side hybrid engine + player; the in-browser swarm participant is an
  additive enhancement once the server path is proven.
