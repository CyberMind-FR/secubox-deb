<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Plan 2c: Proactive cert-pinned bypass seed + #filtres source labels

- **Date:** 2026-06-17
- **Package:** `secubox-toolbox`
- **Issue:** #633
- **Status:** Design approved, pending implementation plan
- **Origin:** operator observation — the `#filtres` "🚦 Hosts bypassés" panel shows
  "aucun host bypassé".

---

## 0. Discovery during planning (corrects the origin diagnosis)

Reading `api.py` + `www/toolbox/index.html` revealed the panel is empty for a
**different reason than assumed**:

1. **The panel's data endpoint does not exist.** `loadFilters()` fetches
   `GET /admin/filter-control/list`, but `api.py` only defines
   `GET /admin/filter-control` (HTML page), `/add`, `/remove`, and `/regex` — there
   is **no `/list` JSON route**. So the panel always renders empty/"no data"
   regardless of how many hosts are bypassed. **This missing endpoint is the
   actual bug** and the primary fix.
2. **A seed already exists, inline.** `_ensure_bypass_file()` writes a large
   `_MITM_BYPASS_DEFAULT_ENTRIES` default list (Signal/WhatsApp/Telegram/Apple/
   French banks/googleapis/facebook/ad-networks) into `mitm-bypass.conf` on first
   creation. So "no proactive seed" is false — but the seed is baked into the
   **operator** file (mixing package + operator ownership) and is fairly broad.
3. **The frontend already supports source tags.** `loadFilters()` already renders
   `h.source` if present — so the API just needs to return `[{pattern, source}]`.

**Revised scope (supersedes the original framing below):**
- **Primary:** add the missing `GET /admin/filter-control/list` JSON endpoint,
  returning tagged `[{pattern, source}]` over all sources (seed/static/learned).
- **Secondary:** move the inline `_MITM_BYPASS_DEFAULT_ENTRIES` seed into a
  package-owned `mitm-bypass-seed.conf` (read-only) + 3-way merge in the launch
  script, so `mitm-bypass.conf` becomes purely operator-owned (created empty).
- The source-label rendering (§5) is already wired client-side; only a small
  legend/badge polish remains.

The Sections below describe the seed-file + merge + labels design; read them
through the lens of this revised scope (the `/list` endpoint is the keystone).

---

## 1. Goal

Two changes to the existing TLS-passthrough (`ignore_hosts`) machinery:

1. **Proactive seed** — ship a curated, conservative list of well-known
   cert-pinned hosts so common pinned apps (Apple push/iCloud, WhatsApp, Signal,
   Telegram, Google FCM, major mobile banking) are passed through TLS inspection
   from first contact, instead of breaking ~3× until cert_pin_detect learns them.
2. **Source labels** — surface seed + operator-static + learned entries in the
   `#filtres` panel, each tagged with its origin, so the panel is informative
   instead of empty/opaque.

### WAF-doctrine framing (important)

The project rule is "no WAF bypass — all traffic through mitmproxy." `ignore_hosts`
is **TLS passthrough, not full bypass**: mitmproxy still sees the SNI and JA4 of
these flows (DPI/social_graph still record them), it just does not decrypt the
body. Cert-pinned hosts physically cannot be MITM'd (they reject our CA → the app
breaks), so passthrough for them is the existing, accepted behavior — cert_pin_detect
already does it reactively. The seed only makes it **proactive**.

**Hard constraint:** every seed entry is an inspection blind spot, so the seed must
stay **conservative** — only genuinely-pinned endpoints that would otherwise break,
each justified by a comment. It is NOT a general allowlist.

### Decision locked during brainstorming

| Question | Decision |
|---|---|
| Seed mechanism | **Separate packaged seed file + 3-way merge** (package-seed + operator-static + learned-dynamic) |

---

## 2. Architecture

```
Three bypass sources, merged into the ignore_hosts regex by the launch script:

  /usr/lib/secubox/toolbox/mitm-bypass-seed.conf   ← NEW, package-owned (read-only)
  /var/lib/secubox/toolbox/mitm-bypass.conf        ← operator-editable (API-managed)
  /var/lib/secubox/toolbox/mitm-bypass-dynamic.conf ← cert_pin_detect auto-learned

sbin/secubox-toolbox-mitm-wg-launch  (EXTENDED)
   for src in SEED BYPASS DYNAMIC: merge → sort -u → join '|' → --set ignore_hosts

secubox_toolbox/api.py  (EXTENDED)
   the #filtres panel endpoint reads all THREE files, tags each entry with its
   source, returns [{pattern, source}] where source ∈ {seed, static, learned}

www/toolbox/index.html :: loadFilters()  (EXTENDED)
   render each entry with a source badge: 🌱 seed · ✋ static · 🔍 learned
```

**Files**
- **New:** `mitm-bypass-seed.conf` (curated regex list), `tests/test_bypass_sources.py`.
- **Extended:** `sbin/secubox-toolbox-mitm-wg-launch` (add SEED to the merge loop),
  `secubox_toolbox/api.py` (multi-source read + tagging for the panel endpoint),
  `www/toolbox/index.html` (`loadFilters` rendering with source badges),
  `debian/rules` (ship the seed file), `debian/changelog`.
- **Untouched:** cert_pin_detect's reactive threshold (operator chose "keep
  reactive"); the operator's `mitm-bypass.conf` (still their own, API-managed);
  the dynamic file (still cert_pin's).

**Boundary.** The seed is package-owned and read-only (refreshed on upgrade). The
launch-script merge is the single composition point (already dedups + sorts). The
API gains a small helper that returns tagged entries; the panel only renders.

---

## 3. The seed file (`mitm-bypass-seed.conf`)

- Format identical to the existing bypass files: one regex fragment per line,
  `#` comments, blank lines ignored — exactly what cert_pin_detect writes (e.g.
  `(.+\.)?icloud\.com`) and what the launch script merges.
- Header documents: purpose, the conservatism constraint, and that these are
  regex fragments joined into the `ignore_hosts` alternation.
- Curated, conservative starter set (~15–25 entries), each commented. Categories:
  - **Apple** — `push.apple.com`, `(.+\.)?icloud\.com`, `gateway.icloud.com`
  - **WhatsApp** — `(.+\.)?whatsapp\.net`, `(.+\.)?whatsapp\.com`
  - **Signal** — `(.+\.)?signal\.org`
  - **Telegram** — `(.+\.)?telegram\.org`, `(.+\.)?t\.me`
  - **Google mobile push** — `mtalk\.google\.com`, `(.+\.)?gvt1\.com`
  - **Mobile banking (representative pinned)** — a few well-known pin patterns,
    documented as "extend per region."
- **NOT** included: broad CDN/API wildcards (`googleapis.com`, `amazonaws.com`)
  that would blind-spot huge swaths — those are exactly what must stay inspected.

---

## 4. API — multi-source tagged read

The `#filtres` panel endpoint (currently reads only `mitm-bypass.conf` via
`_load_bypass_entries`) gains a helper that reads all three files and returns a
list of `{pattern, source}` with `source ∈ {seed, static, learned}`:

- seed → `/usr/lib/secubox/toolbox/mitm-bypass-seed.conf` (env-overridable for tests)
- static → the existing `MITM_BYPASS_FILE`
- learned → `mitm-bypass-dynamic.conf`

Dedup: if a pattern appears in more than one source, report the **most
authoritative** single source (seed > static > learned) so the panel shows one row
per pattern. The existing add/list/delete bypass endpoints (operator-managed
static file) are unchanged; only the panel's read is enriched. The
ignore_hosts-regex endpoint (`--set ignore_hosts` consumer) is unaffected (the
launch script composes the regex itself).

---

## 5. UI — `loadFilters()` source badges

`loadFilters()` already fetches the bypass list and renders `<li>` rows (or
"aucun host bypassé" when empty). Change: render each `{pattern, source}` with a
leading badge — 🌱 `seed` · ✋ `static` · 🔍 `learned` — and a small legend.
Empty-state only shows if all three sources are empty (seed ships non-empty, so the
panel is now informative on a fresh install). No new page, no new socket — same
endpoint, richer payload. Frontend stays vanilla JS consistent with the existing
file.

---

## 6. Error handling + tests

- **Error handling:** a missing/unreadable source file → treated as empty for that
  source (the others still load); the launch-script merge already tolerates a
  missing file (its `for src` loop guards existence). The panel never errors on a
  missing source.
- **Tests (`tests/test_bypass_sources.py`):**
  - the tagged-read helper: three temp files with overlapping + unique patterns →
    correct `{pattern, source}` list; dedup picks seed > static > learned; a
    missing source is skipped, not an error.
  - seed-file validity: every non-comment line in the shipped `mitm-bypass-seed.conf`
    compiles as a Python `re` pattern AND the joined alternation
    `(?:a|b|c)` compiles (mirrors how mitmproxy consumes `ignore_hosts`).
  - (launch-script merge is shell; covered by the seed-validity + the existing
    launch behavior — no new shell test framework introduced.)

---

## 7. Rollout / safety

- Pure additive: shipping the seed makes more hosts pass through TLS inspection.
  This is **not** gated by `privacy_enforce` — bypass/passthrough is orthogonal to
  the block/poison engine and is needed for the pinned apps to work at all. But the
  seed is conservative by construction (Section 3) to keep the blind spot small.
- No shared-`/…/secubox`-parent mode changes; the seed ships read-only under
  `/usr/lib/secubox/toolbox/`. Reloading `ignore_hosts` happens via the existing
  launch path (service restart / the dynreload path-watcher) — no new reload
  mechanism.

---

## 8. Out of scope

- Lowering cert_pin_detect's reactive threshold (operator chose keep-reactive).
- Per-region banking pin packs (the seed documents "extend per region").
- The DNS-refuse feed (Plan 2b-DNS, separate, board-topology-gated).
- `#social` top-5 UI (Plan 2d).
