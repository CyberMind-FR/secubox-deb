<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Companion (WebExtension)

Firefox WebExtension companion for a SecuBox appliance. Issue #401.

## Status — P1 (scaffold)

- **Toolbar popup**: live module health dots + quick links to each module +
  "Open dashboard". Toolbar badge shows the count of down modules.
- **YouTube cookie relay**: reads `youtube.com` cookies from *this* browser
  (which is logged in / passes BotGuard) and POSTs them to PeerTube's
  cookie-intake endpoint — so PeerTube's yt-dlp import works without manually
  exporting `cookies.txt` + scp. Solves the import problem from the browser
  side (see #388).
- **Settings**: configure the hub base URL, the monitored module slugs, and
  the cookie endpoint.

## Roadmap (#401)

- **P1** (this): popup status + module links + cookie relay. ✅ scaffold
- **P2**: `sidebar_action` widget with live metrics (RAM/CPU/health).
- **P3**: console TUI (xterm.js) over a curated, authenticated command API.
- **P4**: PO-token relay for YouTube import (the browser passes BotGuard, so
  it can hand PeerTube a working PO token — no bgutil server needed).

## Auth

Requests use `credentials: "include"` so they ride the SecuBox **SSO-lite**
session cookie (#400). Until #400 lands, health probes work for unauthenticated
`/health` endpoints; authenticated calls (cookie relay backend) need the
session.

## Install (development, unsigned)

Firefox requires signing for permanent installs. For development:

1. `about:debugging` → **This Firefox** → **Load Temporary Add-on** →
   pick `packages/secubox-webext/manifest.json`.
2. Click the toolbar icon → **Settings** → set the hub URL
   (e.g. `https://admin.gk2.secubox.in`).

For a permanent install, sign via AMO (`web-ext sign`) or run on Developer/ESR
with `xpinstall.signatures.required=false`.

## Backend dependency

The cookie-relay button POSTs to `<hubBase><cookieEndpoint>` (default
`/api/v1/peertube/import/cookies`). That endpoint (write the Netscape body to
the PeerTube LXC at `storage/tmp-persistent/youtube-cookies.txt` + enable +
restart, à la `peertubectl set-youtube-cookies`) is the P1.5 backend task on
secubox-peertube (#388).

## Build a distributable XPI

```
cd packages/secubox-webext
zip -r -FS ../secubox-webext.xpi . -x '*.git*'
# or: web-ext build
```
