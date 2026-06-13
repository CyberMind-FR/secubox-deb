<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# SecuBox ToolBoX — browser extension (Cartographie sociale, #532)

A WebExtension (Firefox `.xpi` + Chromium MV3) that **emancipates** the R3
toolbox live tracker analysis into the browser: instead of only seeing the
*cartographie sociale* on `kbin/social/me`, a toolbar badge ticks up as
trackers fire, and a popup shows who is watching you — live.

Sibling of [`clients/android-toolbox/`](../android-toolbox/). Talks **only**
to your cabine over the R3 tunnel — no third-party calls.

## What it does

- **Pairing** — calls `/social/me` over the tunnel, which 303-redirects to
  `/social/{token}`; the extension reads the minted HMAC token from the
  final URL. Anonymous (rotating `mac_hash`), no account. Manual token entry
  available in the options page.
- **Live badge** — the toolbar icon shows the live tracker count for the
  session (polled once a minute). Colour escalates: gold → 🟥 anti-bot
  present → 🟪 operator-grade present.
- **Popup** — four stat tiles (trackers / sites / anti-bot / operator-grade),
  a dependency-free **mini Round-Eye graph** (device centre, trackers on the
  ring, radius by hits, colour by tier), and a top-tracker list with CDN
  (12.A) / anti-bot (12.B) / operator-grade (12.C) tags.
- **Actions** — *Cartographie complète* (opens the full d3 view at
  `/social/{token}`), *Rapport PDF* (`/social/report/{token}.pdf`), and
  *Effacer mes données* (RGPD art. 17 wipe → `POST /social/wipe/{token}`).

## Install

Published release `.xpi` (downloadable directly):

```
https://github.com/CyberMind-FR/secubox-deb/releases/download/webext-v0.1.2/secubox-toolbox-webext.xpi
```

The toolbox also serves it from the cabine:

```
https://kbin.<board>.secubox.in/wg/toolbox.xpi
```

The kbin onboard panel exposes a **🧩 Extension navigateur (cartographie)**
button. When a local build is present the cabine serves it; otherwise it
302-redirects to the **tag-pinned** release asset above. The webext release
is published `make_latest:false` so it does not steal the repo "Latest"
pointer from the Android APK release (whose endpoint resolves via
`/releases/latest/download/…`) — bump the tag in the `/wg/toolbox.xpi`
endpoint constant + `secubox-toolbox-fetch-xpi` when a new `webext-v*`
release is cut.

- **Firefox** — open the `.xpi`. A permanent install needs an AMO-signed
  build (release CI step / `web-ext sign`); for development use
  *about:debugging → Load Temporary Add-on*, or an ESR/Dev build with
  `xpinstall.signatures.required=false`.
- **Linux Firefox (fast)** — one call grabs the `.xpi` and launches Firefox
  with it loaded (via `web-ext run`, no signing needed):
  ```bash
  clients/webext-toolbox/install-firefox-linux.sh            # from kbin.gk2.secubox.in
  clients/webext-toolbox/install-firefox-linux.sh --release  # from the GitHub release
  clients/webext-toolbox/install-firefox-linux.sh --local    # from this checkout
  ```
- **Chromium** — load unpacked (`chrome://extensions` → Developer mode).
  Ships rasterised PNG icons (`icons/icon-48/128.png`), so it loads as-is.

## Build

No bundler — the extension is plain JS/HTML/CSS. CI zips it:

- GitHub Actions `build-webext.yml` → `.xpi` artifact on push to `master` /
  PRs touching `clients/webext-toolbox/**`; tagging `webext-v*` publishes the
  `.xpi` as a release asset.

Locally:

```bash
cd clients/webext-toolbox
./build.sh           # → secubox-toolbox-webext-<version>.xpi
```

## Files

| File | Role |
|------|------|
| `manifest.json` | MV3, cross-browser background (`service_worker` + `scripts`) |
| `api.js` | shared client over `/wg/r3-check`, `/social/*` |
| `background.js` | badge sync + silent re-pair (SW or event page) |
| `popup/` | live view, mini graph (`graph.js`), actions |
| `options/` | host / window / manual token |

## Cabine endpoints consumed

| Endpoint | Purpose |
|----------|---------|
| `/wg/r3-check` | tunnel presence indicator |
| `/social/me` | pair → mint token (303 → `/social/{token}`) |
| `/social/graph/{token}?since=` | per-session tracker graph JSON |
| `/social/wipe/{token}` | RGPD art. 17 erasure |
| `/social/{token}` | full d3 cartographie page |
| `/social/report/{token}.pdf` | bilingual PDF report |

## Notes

- No server-side CORS needed: an MV3 extension with `host_permissions` for
  `*.secubox.in` fetches cross-origin from its background without CORS.
- MVP polls `/social/graph` and computes the delta client-side; a future
  `GET /social/live/{token}` (SSE) can replace the poll. The deception-plane
  *Poke/Emancipate* per-site control lands once #525 ships.

License `LicenseRef-CMSD-1.0`.
