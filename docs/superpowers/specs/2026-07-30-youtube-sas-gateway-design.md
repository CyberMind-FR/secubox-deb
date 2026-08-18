<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# YouTube / web-media SAS gateway — Design

**Date:** 2026-07-30 · **Status:** design (plan) — mirrors the torrent SAS pattern.

## Goal
A sovereign **SAS gateway** to pull a video from a web link (YouTube and any
yt-dlp-supported site) into a staging space, **visualise it in the browser**, then
**decide**: *Garder* → conserve to PeerTube, or leave **ephemeral** with an opt-in
purge TTL. Same "récupération → visualisation → conserver/effacer" model as the
torrent SAS ([[project_torrent_webtorrent_deployed]] / the torrent 2.x design), with
**yt-dlp** as the fetch engine instead of WebTorrent, and **cookie-based
authentication** for age-restricted / members / private videos.

## Why a sibling of torrent, not a torrent feature
Different fetch engine (yt-dlp vs WebTorrent), different auth (cookies vs peers),
but the **downstream is identical**: a SAS library (kept-by-default + ephemeral TTL
+ disk-floor purge), an in-browser `<video>` player, and the host-mediated
`conserve → peertubectl upload` pipeline. Reuse that downstream verbatim.

## Architecture (LXC-native, torrent pattern)
```
ytsas.gk2 ─HAProxy─ sbxwaf ─ nginx ─▶ ytsas LXC (Node or Python + yt-dlp)
   webui: paste link → progress → files → <video> → Garder / Purger
   host timer: .conserve-queue → peertubectl upload (same as torrent)
```
- **Module `secubox-ytsas`** (LXC-native): a small service that runs `yt-dlp` jobs
  into `/data/ytsas/<id>/`, a SQLite library (id, url, title, path, kept,
  ephemeral_until, peertube_status/url, complete), and an API:
  `POST /add {url}` (queue a yt-dlp job), `GET /list`, `GET /files/:id`,
  `GET /stream/:id/:file` (Range), `POST /keep/:id`, `POST /ephemeral/:id {until}`,
  `POST /conserve/:id` (→ peertube), `POST /remove/:id`, `GET /status`.
- **Engine**: bounded concurrent yt-dlp workers (niced, `-f` best mp4/webm,
  `--newline` progress parse, write-to `/data/ytsas` on SSD). Never block the loop.
- **webui** (WEBUI-PANEL-GUIDELINES, sbx_token): paste-a-link box, job cards with
  progress %, file list + `<video>` player, **Garder (→ PeerTube)** / **Purger dans…**
  TTL picker — identical UX to the torrent SAS.
- **Conserve**: drop a `.conserve-queue` entry; a host oneshot+timer drains it and
  runs `peertubectl upload <file> <title> <channel> <privacy>` (the exact pipeline
  the torrent SAS already uses — reuse `secubox-*-conserve` pattern).

## Authentication (the age-restricted / private case)
yt-dlp needs cookies for age-gated / members / private videos (the error the user
hit: "Sign in to confirm your age … use --cookies"). Headless `--cookies-from-browser`
is not available, so:
- **Cookie vault**: the webui has an "Authentification" panel to **upload a
  `cookies.txt`** (Netscape format, exported from the user's browser via a
  cookie-export extension). Stored `/etc/secubox/secrets/ytsas-cookies.txt`
  0600 owner `secubox-ytsas`, NEVER logged, NEVER in the library DB.
- yt-dlp jobs run with `--cookies /etc/secubox/secrets/ytsas-cookies.txt` when the
  vault is present; without it, public videos still work, gated ones report a clear
  "auth requise — dépose tes cookies" status (not a raw yt-dlp error).
- Cookies expire → the panel shows freshness + a re-upload button; a gated failure
  flips the panel to "cookies périmés".
- Optional later: per-site cookie sets; a browser-extension companion to push
  cookies straight to the vault.

## SAS model (identical to torrent)
- **Kept by default**: a downloaded video is conserved until the user opts into
  purge; `ephemeral_until` TTL + a disk-floor safety valve reap only ephemerals.
- **Conserve → PeerTube** = the durable home; the SAS is a transit lounge.
- Lazy: large libraries don't re-download; the file is on SSD `/data/ytsas`.

## Companion + nav
- `secubox-ytsas` menu.d category **`mind`** (NO new category — reuse existing).
- Companion cardlet 🎞️ (jobs / kept / →peertube metrics), favourite-able.

## Legal / WAF posture
Same accepted posture as the torrent SAS (user-owned box, personal archival). Route
via sbxwaf; large downloads/streaming may need the declarative `waf_bypass` per the
media-streaming exception in CLAUDE.md.

## Packaging
`secubox-ytsas 0.1.0` arch:all, install-lxc.sh (yt-dlp via pip/apt + auto-update
yt-dlp, since sites change), vhost + nft + sudoers + menu.d + toml. Published to
apt.secubox.in after build (standing rule).

## Reuse checklist (don't reinvent)
- library.js/py + purge + lazy + conserve-queue → copy the torrent SAS modules.
- peertubectl upload → already exists, verified e2e.
- webui player + Garder/Purger → adapt the torrent www.

## Out of scope (v1)
- Playlist/channel bulk pulls (v2), subtitle/chapter import, format picker UI,
  browser-extension cookie push.
