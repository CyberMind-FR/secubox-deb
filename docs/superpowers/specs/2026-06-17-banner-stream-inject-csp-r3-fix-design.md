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
2. **R3 report link unreachable.** `/__toolbox/bundle` returns
   `report_url=http://10.99.0.1:8088/report/me/html` for everyone. R3 (WG) clients
   cannot reach the captive `10.99.0.1` (per `inject_banner.py`'s own comment) →
   the "report ▸" link is dead for R3. R3 should get the public
   `https://kbin.gk2.secubox.in/report/me/html?mh=<wg_hash>`.

### Decisions

| Question | Decision |
|---|---|
| CSP handling | **Fall back to the legacy buffer path on strict CSP** (reuse `_detect_csp_strict`); do NOT rewrite the site's CSP header |
| R3 report-url | Bundle selects public-kbin+`mh` for WG/R3 clients, captive for R2 (mirror `inject_banner._report_url_for`) |

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

### Bug 2 — the `/__toolbox/bundle` builder (`secubox_toolbox/bundle.py` and/or its `api.py` route)

Select `report_url` by client class:
- **R3 / WG** (client IP `10.99.1.x`, or the `wg` flag the loader carries):
  `https://kbin.gk2.secubox.in/report/me/html?mh=<wg_hash>` (public, reachable).
- **R2 / captive:** the existing `http://10.99.0.1:8088/report/me/html`.

Reuse the existing report-url logic in `inject_banner.py` (`REPORT_URL_PUBLIC`,
`_peer_hash_from_ip`, `_report_url_for`) — extract/share it rather than duplicate,
or replicate the same selection in the bundle builder. The bundle endpoint already
sees the client connection (it served the loader's fetch), so it can derive
WG-ness from the client IP; if the bundle is fetched same-origin through the proxy,
the client IP is the WG peer IP (10.99.1.x) and `_peer_hash_from_ip` yields the
`mh`.

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
- bundle report_url: build the bundle for a WG client (10.99.1.x / wg=1) → URL is
  the public kbin form with `mh=`; for an R2/captive client → captive URL.
- Reuse `SECUBOX_*` env / monkeypatch for filters (stream_inject on) as the other
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
