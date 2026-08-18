<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Toolbox R3 banner — stream_inject CSP fallback + R3 report-url fix

- **Date:** 2026-06-17
- **Package:** `secubox-toolbox`
- **Issue:** #636
- **Status:** Design approved, pending implementation plan
- **Origin:** "no more banner injected in r3?" — investigation showed the banner
  IS delivered on R3 (loader.js + bundle fetched live) but two regressions in the
  merged `stream_inject` (#620/#621/#630) feature break it on common sites.

---

## 1. Goal

Restore the R2/R3 transparency banner on strict-CSP sites and fix the dead R3
report link, without losing the `stream_inject` TTFB win on normal sites.

### Bugs (live-verified on gk2)

1. **CSP not handled (primary).** The `stream_inject` path injects
   `<script src="/__toolbox/loader.js">` and the loader does
   `fetch("/__toolbox/bundle")`. On sites with a strict CSP (`script-src`/
   `connect-src` without `'unsafe-inline'`/nonce/`'self'` for the needed sources),
   the browser blocks the loader and/or its fetch → **no banner**. The *legacy*
   buffer path injects an inline-CSS banner `<div>` (no external script, no fetch)
   and was CSP-tolerant by design — but `responseheaders` streams the loader
   without ever checking CSP, so the legacy fallback never runs.
2. **~~R3 report link unreachable~~ — RETRACTED (misdiagnosis).** Live re-test
   showed the route (`api.py:71`) DOES forward `bool(wg)` to `get_bundle`, and a
   real R3 client's loader sends `&wg=1` → `_report_url(client_id, is_wg=True)` →
   the public `https://kbin.gk2.secubox.in/report/me/html?mh=<wg_hash>`. **R3's
   report link is correct.** The captive URL I first saw came from a curl WITHOUT
   `wg=1`. The only genuine residual is a **minor cache bug**: `bundle.get_bundle`
   caches by `client_id` (mh) only, ignoring `is_wg`, so a wg/non-wg pair sharing
   one mh can bleed report_urls. Low impact (R3 always sends wg=1 with a unique
   wg_hash mh), but a real correctness nit — fixed cheaply here as a bonus.

### Decisions

| Question | Decision |
|---|---|
| CSP handling (Bug 1, primary) | **Fall back to the legacy buffer path on strict CSP** (reuse `_detect_csp_strict`); do NOT rewrite the site's CSP header |
| Bundle cache key (minor) | Key `_cache` by `(client_id, is_wg)` so wg/non-wg bundles don't bleed |

---

## 2. Architecture / changes

Two small, isolated edits:

### Bug 1 — `mitmproxy_addons/inject_banner.py :: InjectBanner.responseheaders`

Add, after the existing `banner`-filter check and before `resp.stream = …`:
```python
if _detect_csp_strict(flow):
    return   # strict CSP → don't stream the loader; legacy buffer path
             # (inline-CSS banner, no script/fetch) handles it CSP-safely.
```
Returning early means `flow.metadata["sbx_streamed"]` is **not** set, so the
existing `response` buffer path runs and injects the inline-CSS banner — the
pre-stream_inject behavior, which survives strict CSP.

`_detect_csp_strict` already exists (checks `script-src`/`default-src` lacking
`'unsafe-inline'`/nonce). It is conservative for the external-loader case (it may
fall back even when `script-src 'self'` would have allowed the loader) — that is
acceptable: the fallback always produces a correct banner, only forgoing the TTFB
optimization on those sites. (A future refinement could special-case `'self'`.)

### Bug 2 (minor) — `bundle.get_bundle` cache ignores `is_wg`

`get_bundle(client_id, is_wg)` caches by `client_id` only:
`_cache.get(client_id or "")`. So once an mh is cached for one `is_wg` value, a
later request for the same mh with the *other* `is_wg` returns the stale bundle
(wrong `report_url`). The report-url *selection* itself is already correct
(`_report_url(client_id, is_wg)`); only the cache key is wrong. Fix: key the cache
by `(client_id, is_wg)`:
```python
key = (client_id or "", bool(is_wg))
hit = _cache.get(key)
...
_cache[key] = (now, bundle)
```
Low impact (R3 always sends `wg=1` with a unique wg_hash mh, R2 sends `wg=0`), but
a genuine correctness fix and trivial.

---

## 3. Error handling / safety

- Bug 1: `_detect_csp_strict` is wrapped by the surrounding `responseheaders`
  try/except discipline already present; a parse failure → treat as non-strict
  (stream as before) — fail toward the existing behavior, never error the flow.
- Bug 2: if WG-ness/`mh` can't be derived, fall back to the captive URL (current
  behavior) — no worse than today.
- Neither change touches the block/poison engine, nft, or DNS. No `privacy_*`
  gating involved (the banner is orthogonal). No shared-dir mode changes.

## 4. Tests

- `responseheaders`: a flow whose response carries a strict CSP
  (`content-security-policy: script-src 'self'` with no unsafe-inline/nonce) →
  after `responseheaders`, `flow.metadata.get("sbx_streamed")` is falsy AND
  `resp.stream` is not a `_LoaderInjector` (fell back). A flow with no CSP (or
  `'unsafe-inline'`) → streams (`sbx_streamed` true). Use mitmproxy `tflow`.
- bundle cache key: `get_bundle("mh1", is_wg=True)` then `get_bundle("mh1",
  is_wg=False)` return DIFFERENT bundles (public vs captive report_url) — i.e. the
  second call is not served the cached wg=True bundle. (Clear `_cache` between, or
  assert the two report_urls differ.)
- Reuse mitmproxy `tflow` / monkeypatch for filters (stream_inject on) as the other
  inject_banner-adjacent tests do.

## 5. Rollout

Behavior-restoring; no toggle. After deploy, R3 clients on strict-CSP sites get
the (legacy inline-CSS) banner again, and the R3 "report ▸" link resolves to the
reachable public endpoint. Deploy = rebuild + redeploy `secubox-toolbox`, reload
`secubox-toolbox-mitm-wg-worker@*` (no mass restart). Verify live on a known
strict-CSP site from an R3 client.

## 6. Out of scope

- Refining `_detect_csp_strict` to allow the loader when `script-src 'self'`
  (TTFB optimization on more sites) — future nicety.
- Rewriting site CSP headers to whitelist the loader.
- Anti-Track v2 (#633) work.
