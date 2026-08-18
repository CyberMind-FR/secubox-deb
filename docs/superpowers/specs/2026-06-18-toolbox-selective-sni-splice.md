<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Toolbox selective SNI-splice (Lever A) — design

- **Date:** 2026-06-18 · **Package:** `secubox-toolbox` · **Issue:** #649
- **Status:** Design approved (adaptive seed+learned, dark-launch). Pending plan.
- **Parent:** lighter-MITM plan, A-then-B. This is **Lever A** (stay in mitmproxy,
  decrypt only what we modify). Lever B (Go/Rust core) is a later strategic call.
  WAF is explicitly out of scope here ("maybe later").

## Problem
R3 web loading is slow because the 4 `secubox-toolbox-mitm-wg-worker@` processes
are GIL-bound (~1 core total, each pinned ~25–30% = single-thread ceiling) and
**forge a cert + terminate TLS + parse HTTP + run 16 addons on every flow**, then
most addons bail. Heavy asset/video/CDN flows (e.g. YouTube `googlevideo`)
dominate that CPU for **zero privacy value** — there's nothing to inspect or
rewrite in image/video/audio bytes. (#646 measured the ceiling.)

## Goal
Run the expensive L7 path only on flows we'd actually inspect/modify. **Splice**
(raw TCP passthrough, no forge/TLS/parse/addons) the pure-asset flows, decided at
the TLS ClientHello from the **SNI** alone (the only thing known pre-decrypt).

Non-goals: removing the MITM (outbound HTTPS interception intrinsically needs
per-host cert forging — see issue); WAF; the Go/Rust rewrite.

## Mechanism
A new addon `mitmproxy_addons/tls_splice.py`, registered **FIRST** in
`sbin/secubox-toolbox-mitm-wg-launch` (before `inject_xff`), implements:

```python
def tls_clienthello(self, data):
    mode = _filters().get("tls_splice", "observe")   # off | observe | on
    if mode == "off":
        return
    sni = (data.client_hello.sni or "").lower()
    if not sni:                       # no SNI → never splice blind
        return
    if splice.should_splice(sni, self._seed, self._learned, self._never):
        if mode == "on":
            data.ignore_connection = True   # SPLICE: raw passthrough
            _bump("spliced")
        else:                               # observe: classify + log, still MITM
            _bump("would_splice"); log.info("would-splice %s", sni)
```

`data.ignore_connection = True` is mitmproxy's documented splice (no TLS
interception). `tls_clienthello` / `data.client_hello.sni` are already used by
`ja4.py` and `local_store.py`, so the API is present in our mitmproxy 11.

The same addon also records a lightweight **learning observation** on the response
hook of MITM'd flows (see Learning), so the learned-splice set can grow. (Spliced
flows produce no response hook — once a host is promoted, its observation freezes;
acceptable, the seed is media-only and the toggle is a kill-switch.)

## Classifier — `secubox_toolbox/splice.py` (pure, testable)
```python
def load_splice_seed(path) -> set[str]      # suffix patterns from conf (+ comments stripped)
def load_learned_splice(path) -> set[str]   # learned hostnames (autolearn output)
def host_matches(host, patterns) -> bool    # host == p or host endswith "."+p
def should_splice(sni, seed, learned, never) -> bool:
    # never wins (defensive): trackers we block/poison, fortknox sites
    if host_matches(sni, never): return False
    return host_matches(sni, seed) or host_matches(sni, learned)
```
- `never` = pure-trackers (`pure-trackers.txt`, already maintained by Anti-Track
  2a) ∪ `fortknox_sites` (from filters). Even a CDN-fronted tracker stays MITM'd.
- Suffix match so `r1---sn-x.googlevideo.com` matches seed `googlevideo.com`.
- The seed/learned/never sets are loaded once per worker and **mtime-refreshed**
  (mirror `_common._wg_hash_of`'s cache pattern) so autolearn updates land without
  a restart, but per-connection lookups stay O(1) set hits.

## Seed — `conf/tls-splice-seed.conf`
Curated, **media/asset-specific only** (NOT generic CDN edges like cloudfront/
fastly/akamai-edge, which also serve HTML apps — splicing those would blind us to
real pages). v1 set:
```
googlevideo.com      # YouTube video (the single biggest hog)
ytimg.com            # YT thumbnails
gstatic.com          # Google static assets
ggpht.com            # Google user content
fbcdn.net            # Facebook/IG media
cdninstagram.com
twimg.com            # Twitter/X media
licdn.com            # LinkedIn media
sndcdn.com           # SoundCloud audio
scdn.co              # Spotify audio
mzstatic.com         # Apple media
```
Operator can extend via an operator splice file (same 3-way merge idea as the
bypass lists), but v1 ships only the seed + learned.

## Learning — never-HTML promotion
New table (SQLite, WAL already on):
```sql
CREATE TABLE IF NOT EXISTS splice_host_obs (
  host TEXT PRIMARY KEY, hits INTEGER NOT NULL DEFAULT 0,
  html_hits INTEGER NOT NULL DEFAULT 0, last_seen REAL
);
```
- `tls_splice.py` response hook (MITM'd flows only) upserts: `hits += 1`,
  `html_hits += 1` if `Content-Type` contains `text/html`. **Sampling cap:** stop
  counting once `hits >= 50` per host (bounds write amplification; 50 is enough
  signal). Cheap: one upsert, no body read.
- `sbin/secubox-toolbox-autolearn` gains `_splice_feed()`: promote hosts with
  `hits >= 20 AND html_hits == 0` (never served HTML over ≥20 observations) to
  `/var/lib/secubox/toolbox/splice-learned.txt` (atomic write, `os.replace`).
  Gated on `tls_splice != "off"`. Registrable-folded, deduped, capped (e.g. 2000).
- Demotion: not automatic (spliced hosts stop being observed). The media-only seed
  + the never-set + the kill-switch toggle bound the risk; a host that wrongly got
  spliced is removed by clearing the learned file or toggling off.

## Config — `filters.json`
Add `tls_splice` ∈ `{off, observe, on}`, **default `observe`** (dark-launch:
classify + log would-splice, but still MITM — zero behavior change until flipped).
- `filters.py`: add `"tls_splice": "observe"` to `DEFAULTS`; add
  `_VALID_SPLICE = {"off","observe","on"}` and validate (mirror `protective`).
- `set_filters`: accept `tls_splice` only if in `_VALID_SPLICE`.

## Counters / observability
`tls_splice.py` flushes `/run/secubox/splice.json`
(`{spliced, would_splice, mitm, since, updated}`) every ~5 s (mirror
`ad_ghost._flush`). Optional future UI tile; not required for v1.

## Tradeoff (explicit)
Spliced flows are invisible to DPI / media-stats / social-graph / media-cache.
Acceptable for pure asset CDNs (no privacy signal in media bytes; assets aren't
HTML so no banner/ad-ghost lost). **media_cache interaction:** when
`media_cache` is enabled, do NOT splice (media_cache needs to see those flows) —
`should_splice` returns False if `filters.media_cache` is true. (v1: media_cache
defaults off, so this is a guard for the opt-in case.)

## Safety / rollout
1. Ships `tls_splice=observe` (dark). Soak, review `/run/secubox/splice.json` +
   "would-splice" logs against real traffic, confirm no first-party/HTML host is
   classified, THEN flip to `on`.
2. No SNI → MITM. `never` set wins. media_cache-on → MITM.
3. Kill-switch: `tls_splice=off` reverts to today's behavior instantly (filters
   hot-reload, 5 s cache).
4. Deploy = rolling sequential restart of the 4 `mitm-wg-worker@` (3/4 capacity
   during the roll), no mass restart.

## Tests
- `splice.py`: `host_matches` suffix logic (exact, subdomain, non-match, no false
  prefix match e.g. `notgooglevideo.com`); `should_splice` (seed hit, learned hit,
  never wins over seed, no-SNI→False, empty sets→False).
- filters: `tls_splice` validates {off,observe,on}, bad value → default; round-trips
  via set_filters.
- learning: `_splice_feed` promotes `hits>=20 & html_hits==0`, excludes
  `html_hits>0` and `hits<20` (monkeypatch DB rows).
- addon: `tls_clienthello` sets `ignore_connection` only when mode==on AND
  should_splice; observe mode never sets it; off mode returns early. (Fake
  ClientHelloData with `.client_hello.sni`.)

## Files
- Create `secubox_toolbox/splice.py`, `mitmproxy_addons/tls_splice.py`,
  `conf/tls-splice-seed.conf`, tests.
- Modify `secubox_toolbox/filters.py` (toggle), `sbin/secubox-toolbox-mitm-wg-launch`
  (register addon first + ship seed path), `sbin/secubox-toolbox-autolearn`
  (`_splice_feed`), `secubox_toolbox/store.py` or `social.py` (obs table),
  `debian/rules` (install seed conf), `debian/changelog`.
