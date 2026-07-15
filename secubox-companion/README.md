<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# SecuBox Companion

Remote, modular companion for **SecuBox-Deb** — use and administer each box
component **module by module**, from a phone or a browser. The Companion
reimplements nothing server-side: it **consumes** the box's existing FastAPI
endpoints, organised along the canonical path **AUTH → WALL → BOOT → MIND →
ROOT → MESH**.

## Design

- **Buildless.** Vanilla JS ES modules, no bundler. `www/` is deployable as-is
  (static PWA) and is the Capacitor `webDir`. "Add a module" = drop a folder.
- **Minimal core** (`www/core/`): shell/router, a generic API client (bearer
  token + GET cache + offline write-queue), and a runtime module registry.
- **Module registry.** Each module is a folder `www/modules/<id>/` with a
  `module.json` manifest + a `view.js` (`export default async mount(ctx)`).
  `www/modules/index.json` lists the ids. The core never changes.
- **Offline-first.** The service worker caches the app shell; reads are cached
  in IndexedDB; writes are queued and replayed on reconnect — always through the
  box's real, journalled endpoints (OPAD-safe, no admin bypass).

## Security

- **Outbound-only.** HTTPS + token to the box, obtained from the AUTH API. No
  inbound port on the phone, no third-party relay. Works over LAN/WAN or
  **WireGuard/MESH** when the box isn't publicly exposed.
- **Sealed token.** Credentials are exchanged once for a bearer token, then
  sealed with **AES-GCM under a local PIN** (PBKDF2). No bare-localStorage
  token; no SecuBox data kept in clear beyond the read cache.
- License **CMSD-1.0** (`LicenseRef-CMSD-1.0`).

## Run (PWA)

```bash
cd secubox-companion
npm run serve        # → http://localhost:8080  (or serve www/ with any static host)
```

Open it, **Pair** with the box URL + credentials + a local PIN, and the
dashboard shows one card per module. Installable from the browser (Android/iOS)
as a standalone PWA. Serve over HTTPS for install + service worker in production.

## Build the Android APK

```bash
cd secubox-companion
npm install
npx cap add android      # first time only
npm run apk              # → android/app/build/outputs/apk/debug/app-debug.apk
```

iOS uses the same project: `npx cap add ios && npx cap open ios` (build deferred).

## Reference modules

- **`billets`** (MIND) — write/publish billets, edit, moderate comments.
- **`podcasteur`** (MIND) — containers → episodes, publish/download, add feed,
  import from URL.
- **`_template`** — copy to build a new module in < 30 min (see
  [docs/NEW-MODULE.md](docs/NEW-MODULE.md)).

## Layout

```
secubox-companion/
├── www/                     # the PWA (Capacitor webDir)
│   ├── index.html · manifest.webmanifest · sw.js
│   ├── styles/charte.css    # SecuBox_Charte_Light_3
│   ├── core/                # app · api · store · registry · auth · ui
│   ├── modules/             # index.json + one folder per module
│   └── assets/
├── capacitor.config.json
├── package.json             # serve + apk scripts
└── docs/NEW-MODULE.md
```

> Some write endpoints are marked `TODO(api)` in the modules where the exact
> JWT-authed box route/shape still needs confirming (e.g. billets admin, which
> is session-based server-side). Reads work today; wiring a write is a one-line
> path change once the box route is known.
