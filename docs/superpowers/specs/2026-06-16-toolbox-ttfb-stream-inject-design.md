<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# Spec — toolbox TTFB: stream-inject + async per-host decision bundle

*2026-06-16 · issue #620*

## Problem

The mitm toolbox rewrites HTML in the synchronous mitmproxy `response` hook.
`inject_banner` buffers the entire body — `body = flow.response.content`
(`mitmproxy_addons/inject_banner.py` ~L689) — solely to insert a client-side
`<script>`, then re-serialises it. Buffering the whole document before
forwarding adds TTFB latency on every HTML page and holds whole bodies in the
RAM-limited R3 workers (4 × `mitmdump`). 7 addons modify in `response`.

## Goal & constraints (chosen)

- **TTFB-first.** Optimise perceived page load.
- **Conservative caching.** Cache *decisions* only, never personalised HTML.
  Fail-open everywhere (like `media_cache` #577).
- **WAF integrity (non-negotiable, CLAUDE.md).** All traffic still flows through
  mitmproxy for full inspection. Only *cosmetic* transforms move client-side.
  Security/header/`Set-Cookie`/request-blocking stay server-side. No `waf_bypass`.

## Design

Three layers; cosmetic work leaves the proxy critical path.

### 1. Async per-host decision bundle (lever B)
A bundle keyed by **stable client identity** (`_common.mac_hash_of(ip)` — WG
pubkey hash for R3 `10.99.1.0/24`, salted MAC HMAC for captive) holds only
per-host config:
- client level (R1–R4), shared top-1 pin, dynamic report URL (captive vs WG),
- banner template params, ad-collapse CSS selectors, cosmetic block list.

Built by `secubox_toolbox/bundle.py:build_bundle(client_id, level)`, cached
in-process with a short TTL and refreshed asynchronously. **No page body is
needed** to build it.

### 2. Per-page dynamics → client-side
The banner's per-page numbers (trackers referenced, cookies set) are currently
computed by scanning the response body server-side. They move into `loader.js`:
- trackers → `performance.getEntriesByType('resource')` matched against the
  bundle's tracker patterns,
- cookies → `document.cookie` + a `Set-Cookie` count the proxy already has at
  header level (cheap, no body buffer).

### 3. Streaming injector (kills the buffer)
For top-level `text/html` navigations, `inject_banner` stops reading
`flow.response.content`. Instead it sets `flow.response.stream` to a chunk
modifier that injects one small `<script src="/__toolbox/loader.js" …>` (plus a
JSON `<script>` with the bundle URL + client id) into the **first chunk** and
passes the rest through untouched. TTFB ≈ passthrough; workers no longer hold
whole bodies.

**Compression trade-off:** you cannot inject into a gzip/br body without
decoding it. For top-level HTML navigations only (not sub-resources) the proxy
strips `Accept-Encoding` on the request so the document returns identity-encoded
and is injectable mid-stream. Standard filtering-proxy technique; cost is the
HTML document (only) travelling uncompressed on the upstream hop.

### Endpoints (toolbox FastAPI, `secubox_toolbox/api.py`)
- `GET /__toolbox/loader.js` — static, aggressively cached cosmetic loader.
- `GET /__toolbox/bundle` — resolves client from `request.client.host` via
  `mac_hash_of`, returns the cached per-host bundle (JSON). Fail-open: returns a
  minimal safe bundle if anything is unavailable.

## Phasing

- **Phase 1 (this PR — additive, inert):** `bundle.py` (builder + async cache),
  the two endpoints, `loader.js`, and a `stream_inject` filter toggle **default
  OFF**. Does NOT modify `inject_banner` yet → cannot affect live traffic.
- **Phase 2:** convert `inject_banner` to streaming injection gated on the
  toggle; strip `Accept-Encoding` for top-level HTML; move per-page stats into
  `loader.js`.
- **Phase 3:** fold `ad_ghost` cosmetic collapse into the bundle/loader.
- **Phase 4:** measure TTFB before/after on the board; tune; default-on decision.

## Testing

- `bundle.py` builder is pure given (client_id, level) → unit-testable.
- Endpoint shape test (fail-open returns minimal bundle).
- Phase 2+ verified live on gk2 with sequential worker restarts (RAM-limited;
  never mass-restart — see project memory).

## Out of scope

- Caching modified HTML output (lever A) — excluded by the conservative choice.
- Aggressive pre-fetch/pre-modify of popular pages.
- Any change to security blocking or inspection coverage.
