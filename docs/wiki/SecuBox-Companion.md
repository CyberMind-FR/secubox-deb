<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🟠 SecuBox Companion (Firefox WebExtension)

> Browser companion for a SecuBox appliance — live status, quick access,
> credential relay, and an **on-box, client-encrypted session vault**.
> Package: `secubox-webext` · Issues: #401, #402, #409

`🟠 AUTH` (credentials/login) · `🟢 ROOT` (system metrics) — the Companion
touches several modules but lives in the AUTH family because its core job is
brokering browser authentication to the box.

---

## What it does

| Surface | What you get |
|---------|--------------|
| **Toolbar popup** | Module health dots, quick links, a badge with the down-count |
| **Quick metrics** | Live CPU / RAM / Disk / Temp (`/api/v1/system/metrics`), red ≥ 90% |
| **Login sync** | "Sync browser logins" — relays your live cookies to the avatar broker for backend services (e.g. YouTube → PeerTube import) |
| **Avatar personas** | Group several site sessions under a named persona, **encrypted in the browser**; reapply a persona with one **Become** click to quick-switch profiles on your own boxes |

Everything talks to **your** SecuBox over your LAN and rides the SSO-lite
session (#400). **Nothing is published off-box.**

---

## Install (development / self-hosted)

Firefox requires signing for permanent installs, so for a self-hosted box:

1. Build the `.xpi`:
   ```bash
   cd packages/secubox-webext && ./build.sh    # → ../secubox-webext-<ver>.xpi
   ```
2. `about:debugging` → **This Firefox** → **Load Temporary Add-on** → pick the
   `.xpi` (or `manifest.json`). *(Temporary add-ons reset on Firefox restart.)*
3. Toolbar icon → **Settings** → set **Hub base URL**
   (e.g. `https://admin.gk2.secubox.in`) → Save.

For a permanent install: sign with `web-ext sign` (AMO) **or** run Firefox
Developer/ESR with `xpinstall.signatures.required=false`.

---

## Features

### Status + metrics
The popup polls each configured module's `/api/v1/<module>/health` and
`/api/v1/system/metrics`. The background event-page refreshes a toolbar badge
every 5 min (the down-module count).

### Login sync (avatar peek/poke broker)
"Sync browser logins" reads your live cookies for each service the avatar
broker registers (`GET /api/v1/avatar/cred/peek`) and **pokes** them to
`POST /api/v1/avatar/cred/poke/{service}`. For `youtube` the box installs them
into the PeerTube LXC (via a root path-unit, no sudo — see #407) so yt-dlp
import can use your session.

### Avatar personas (client-encrypted)  `🟠 AUTH`

A **persona** is the avatar wearing a named set of site sessions — a group of
logins you can save once and reapply on your own boxes.

- A **passphrase** you type in the popup derives an AES-GCM key (PBKDF2,
  200 000 iters, WebCrypto). Sessions are **encrypted in the browser** before
  upload. The avatar module stores **opaque ciphertext only** under
  `/var/lib/secubox/avatar/vault/` (0700) — it never sees plaintext or the key.
- **Pick what's in it** — open *edit* under the persona and the popup lists the
  sites you're currently signed into (with cookie counts). Tick the ones the
  persona should hold; your selection is remembered (`vaultDomains`). You can
  also type a site to add it.
- **Save persona** encrypts + uploads the ticked group under the persona name.
- **Become** decrypts the whole group locally with your passphrase and
  `cookies.set()`s every site back at once — a one-click profile quick-switch.
  Run it on another machine on the same LAN and that box adopts the persona's
  logins (passwordless), without the sessions ever leaving the SecuBox.

> 🔒 The passphrase never leaves the browser. Lose it and the personas are
> unreadable (by design).

---

## Settings (`about:addons` → options, or popup → Settings)

| Field | Meaning |
|-------|---------|
| **Hub base URL** | Your dashboard, no trailing slash |
| **Modules** | Comma-separated slugs to monitor |
| **Cookie endpoint** | Avatar poke endpoint (default `/api/v1/avatar/cred/poke/youtube`) |

`vaultDomains` (the persona selection) is stored in extension storage and is
managed from the popup picker (*Avatar persona → edit*) — no manual editing
needed. The manifest grants `<all_urls>` so the picker can list every site
you're signed into; ticking is what scopes a persona.

---

## Security model

- **LAN/SSO only** — never expose the avatar webui / vault on clearnet. A public
  cookie vault is a total-account-compromise target.
- **Client-side encryption** — the box stores ciphertext; a server breach yields
  unreadable blobs.
- **Broad read, narrow write** — the persona picker needs `<all_urls>` to *list*
  the sites you're signed into, but only the **sites you tick** are ever
  encrypted and uploaded. Nothing is captured silently; selection is the gate.
  Manifest V3.
- **Auth** — API calls send the SecuBox Bearer token (popup login) and ride the
  SSO-lite cookie (#400). Backend endpoints are `require_jwt`.

---

## YouTube import note

YouTube blocks **server** IPs ("Sign in to confirm you're not a bot") and now
requires a PO token (SABR). The Companion relays your *browser's* cookies (and,
experimentally, a captured PO token) so the box uses your good session instead
of fighting from its flagged IP. If imports still fail, the box IP needs a
cooldown / fresh cookies — your workstation's `yt-dlp` is the reliable fallback.

---

## Build a distributable XPI

```bash
cd packages/secubox-webext
./build.sh                      # zip → ../secubox-webext-<ver>.xpi
# permanent install: web-ext sign  (needs AMO API creds)
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| All dots grey / "Set the hub URL" | Settings → set Hub base URL |
| "SecuBox login required" | Enter your SecuBox user/pass in the popup |
| Module red but it's up | Its `/api/v1/<m>/` route must be in `secubox-routes.d/` |
| "Restore failed (wrong passphrase?)" | Re-enter the exact vault passphrase |
| Persona list empty | Save a persona with at least one ticked, logged-in site first |

---

*See also: [Architecture-Security](Architecture-Security.md),
[Developer-Guide](Developer-Guide.md).*
