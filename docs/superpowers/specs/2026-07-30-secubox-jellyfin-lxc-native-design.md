# SecuBox Jellyfin (LXC-native) + partner auto-wire + Lyrion external mount — Design

**Date:** 2026-07-30
**Status:** design — awaiting user review
**Supersedes:** the existing `secubox-jellyfin 1.0.0` host-API stub (no ctl, no
LXC, amd64-only, never deployed on gk2 arm64).

## Goal

Bring `secubox-jellyfin` up to the peertube/nextcloud/lyrion model: an
LXC-native Jellyfin media server behind vhost → HAProxy → sbxwaf → nginx, with a
control webui, a scoped-sudo `jellyfinctl`, **partner auto-wire** (detect the
sibling SecuBox media services and mount their media as Jellyfin libraries), and
a companion cardlet. Plus a Lyrion enhancement: auto-detect an external media
library and bind-mount it into the Lyrion LXC on opt-in confirm.

## Architecture

```
jellyfin.gk2.secubox.in ──HAProxy(TLS1.3)──▶ sbxwaf(:8085) ──▶ nginx(:9080)
                                                                  │
                                          /            ──▶ Jellyfin LXC :8096 (br-lxc)
   companion / admin webui ── /api/v1/jellyfin/* ──▶ aggregator ──▶ host api/main.py
                                                                  └─ jellyfinctl (scoped sudo)
```

- **Jellyfin LXC** `jellyfin` (unprivileged, idmap 0→100000, `/data/lxc`,
  br-lxc): official Jellyfin `.deb` inside a Debian bookworm-arm64 container,
  listening on `:8096`. Provisioned by an **idempotent `install-lxc.sh`**
  (peertube/lyrion pattern): create container once, install jellyfin, write
  config, start service. `arch: all` package; the LXC does the arch-specific work.
- **Host api** `api/main.py` (served by the aggregator on `/api/v1/jellyfin/*`,
  JWT-required): `/status` (LXC state + jellyfin health + library summary +
  partner map), `/partners` (detection), partner-wire actions, control actions —
  all delegating to `jellyfinctl` (WebUI-delegates-to-confined-ctl pattern).
- **`jellyfinctl`** (root, scoped sudoers): `status | start | stop | restart |
  library scan|status | partner list|wire|unwire <name> | check-upgrade | upgrade`.
- **Control webui** `www/jellyfin/` per WEBUI-PANEL-GUIDELINES (cyan hybrid-dark,
  Courier Prime, emoji; `sbx_token`): status card, partner grid (present/absent +
  wire toggle), library list, open-Jellyfin button.
- **Security:** JWT on every endpoint; scoped sudoers per verb; WAF route in
  `haproxy-routes.json`; nft egress drop-in on the veth; AppArmor profile;
  daemon under `secubox-jellyfin` user (NNP as needed for sudo).

## Partner auto-wire (decision: detect + auto-wire libraries)

`jellyfinctl partner list` probes each sibling by **presence of its media dir on
the host** (not by guessing), returning `{name, present, media_path, kind,
wired}`:

| Partner   | Detection (host path)                         | Jellyfin library | Mode |
|-----------|-----------------------------------------------|------------------|------|
| photoprism| `/data/shared/photos` (originals)             | Photos           | RO bind |
| nextcloud | NC data media root (from nextcloud.toml)      | Files/Media      | RO bind |
| torrent   | torrent SAS download dir (from torrent.toml)  | Torrents         | RO bind |
| lyrion    | Lyrion music dir (from lyrion config)         | Music            | RO bind |
| peertube  | n/a (federated video platform)                | — (deep link)    | link-only |

**Wire** = (1) read-only `lxc.mount.entry` bind of the host media dir into the
Jellyfin LXC under `/media/<partner>`, (2) add a Jellyfin **virtual folder**
(library) pointing at it via the Jellyfin API (API key minted at provision,
stored `/etc/secubox/secrets/jellyfin-apikey` 0600 `secubox-jellyfin`), (3)
trigger a library scan. **Unwire** removes the virtual folder + the bind. Wiring
is auto-applied for every *present* partner on `partner wire --all` (the webui
default action), and each partner is independently toggleable. RO binds only —
Jellyfin never writes partner media. Peertube stays a deep link (no filesystem
library).

Idmap note: the RO bind must be readable by the container's mapped uid; media
dirs already shared with other LXCs (photoprism/nextcloud share an idmap) use the
same 100000 mapping — verify per-partner at wire time, surface a clear error if
the ownership doesn't allow container read (don't silently mount an unreadable dir).

## Lyrion external media mount (decision: auto-detect + opt-in confirm)

New `lyrionctl medialib detect|mount <path>|unmount|status`:
- **detect**: enumerate candidate external mounts (host mountpoints under
  `/media`, `/mnt`, `/data/external`, and removable devices) that contain audio
  files; return the candidates — never mount blind.
- **mount `<path>`**: after user confirm in the webui, add a RO `lxc.mount.entry`
  binding `<path>` into the Lyrion LXC under `/medialib/external`, restart/refresh,
  and trigger `lyrion library scan`. Persist the choice in `lyrion.toml`
  (`external_medialib = "<path>"`) so it re-binds on boot if still present.
- **unmount**: remove the bind + config, rescan.
- Webui: a "Médiathèque externe" panel showing detected candidates + a Monter
  button per candidate (confirm), and the current mount with an Unmount button.

## Companion cardlet

Add a `jellyfin` module (module.json + view.js) — icon 🍿, MIND, favourite.
Metrics from real `/status`: `libraries` (count) + `sessions` (active playback).
Pill via `status:'ok'`. Deep-link to `jellyfin.gk2`. (Matches the mockup's
Jellyfin card: "1 flux actif · média".)

## Packaging

- `secubox-jellyfin` bumped to **2.0.0** (LXC-native rewrite; retire the 1.0.0
  host-API stub). `arch: all`. `install-lxc.sh` under `/usr/lib/secubox/jellyfin/`.
- postinst: create user, run install-lxc.sh, install sudoers, nft drop-in, nginx
  vhost + reload, register menu.d + WAF route, write `jellyfin.toml`.
- `secubox-lyrion` bumped (external-medialib verbs + webui panel).
- Both published to `apt.secubox.in` after build (standing rule).

## Testing

- `jellyfinctl` partner detection: mock host paths + config files; assert the
  correct partner map (present/absent, media_path) with NO network.
- partner wire/unwire: mock the Jellyfin API + lxc.mount file; assert bind entry
  written/removed and virtual-folder call made.
- lyrion medialib detect: mock mountpoints; assert candidates (audio-containing
  only) and that mount is never auto-applied.
- packaging: assert LXC files installed, sudoers scoped, no 1.0.0 host-service
  unit remains.

## Out of scope (this iteration)

- Jellyfin plugin management, transcoding tuning, hardware accel.
- Cross-node (mesh) Jellyfin federation.
- Auto-wiring peertube as a real library (stays deep-link).
