<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# 🧩 Browser extension — Cartographie sociale live

The **SecuBox ToolBoX browser extension** *emancipates* the R3 toolbox live
tracker analysis into your browser. Instead of only seeing the *cartographie
sociale* on `kbin/social/me`, a toolbar badge ticks up as trackers fire and a
popup shows who is watching you — live, as you browse.

Sibling of the [[Android-ToolBox]] app. Talks **only** to your cabine over the
R3 tunnel — no third-party calls.

- Source : [`clients/webext-toolbox/`](https://github.com/CyberMind-FR/secubox-deb/tree/master/clients/webext-toolbox)
- WebExtension **MV3** (Firefox `.xpi` + Chromium) · plain JS/HTML/CSS, no bundler
- License : `LicenseRef-CMSD-1.0`

## Install

Published release `.xpi` (downloadable directly):

```
https://github.com/CyberMind-FR/secubox-deb/releases/download/webext-v0.1.4/secubox-toolbox-webext.xpi
```

The toolbox also serves it from the cabine:

```
https://kbin.<board>.secubox.in/wg/toolbox.xpi
```

The kbin onboard panel exposes a **🧩 Extension navigateur (cartographie)**
button. When a local build is present the cabine serves it
(`application/x-xpinstall`); otherwise it 302-redirects to the **tag-pinned**
release asset above. The webext release is published `make_latest:false` so it
does not steal the repo "Latest" pointer from the Android APK release.

- **Firefox** — open the `.xpi`. A permanent install needs an AMO-signed build
  (release CI / `web-ext sign`); for development use *about:debugging → Load
  Temporary Add-on*, or an ESR/Dev build with
  `xpinstall.signatures.required=false`.
- **Chromium** — load unpacked (`chrome://extensions` → Developer mode).
  Chromium action icons must be raster — rasterise `icons/icon.svg` to PNG
  before a Web Store build (Firefox accepts the SVG as-is).

## What it does

- **Pairing** — calls `/social/me` over the tunnel, which 303-redirects to
  `/social/{token}`; the extension reads the minted HMAC token from the final
  URL. Anonymous (rotating `mac_hash`), no account. Manual token entry in the
  options page.
- **Live badge** — the toolbar icon shows the live tracker count (polled once a
  minute). Colour escalates: 🟡 gold → 🟥 anti-bot present → 🟪 operator-grade
  present.
- **Popup** — four stat tiles (trackers / sites / anti-bot / operator-grade), a
  dependency-free **mini Round-Eye graph** (device centre, trackers on the ring,
  radius by hits, colour by tier), and a top-tracker list tagged with CDN
  (12.A) / anti-bot (12.B) / operator-grade (12.C).
- **Actions** — *Cartographie complète* (full d3 view at `/social/{token}`),
  *Rapport PDF* (`/social/report/{token}.pdf`), *Effacer mes données* (RGPD
  art. 17 wipe → `POST /social/wipe/{token}`).

## Build (CI)

No bundler — `build-webext.yml` runs `web-ext lint` then packages the `.xpi`:

- artifact on push to `master` / PRs touching `clients/webext-toolbox/**`
- tagging `webext-v*` publishes the `.xpi` as a release asset

Locally:

```bash
cd clients/webext-toolbox
./build.sh            # → secubox-toolbox-webext-<version>.xpi
```

## Cabine endpoints consumed

| Endpoint | Purpose |
|----------|---------|
| `/wg/r3-check` | tunnel presence indicator |
| `/social/me` | pair → mint token (303 → `/social/{token}`) |
| `/social/graph/{token}?since=` | per-session tracker graph JSON |
| `/social/wipe/{token}` | RGPD art. 17 erasure |
| `/social/{token}` | full d3 cartographie page |
| `/social/report/{token}.pdf` | bilingual PDF report |
| `/wg/toolbox.xpi` | the extension itself |

## Notes

- No server-side CORS needed: an MV3 extension with `host_permissions` for
  `*.secubox.in` fetches cross-origin from its background without CORS.
- MVP polls `/social/graph` and computes the delta client-side; a future
  `GET /social/live/{token}` (SSE) can replace the poll. The deception-plane
  *Poke/Emancipate* per-site control lands once the deception plane ships.
