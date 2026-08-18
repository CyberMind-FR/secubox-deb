<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Design — Targeted Service-Worker neuter for the R3 banner (#753)

- **Issue:** #753
- **Date:** 2026-06-27
- **Status:** Approved (brainstorm), pending implementation plan
- **Author:** Gérald Kerma / CyberMind

## Problem

The R3 transparency banner is absent on Service-Worker PWA sites (leparisien.fr,
cnn.com, 20minutes.fr, franceinfo). Their SW serves the **main HTML document from
its cache**, so the navigation request never reaches the MITM → nothing to inject
into. Confirmed via `SBX_DEBUG_CSP`: `www.leparisien.fr` produced **0**
`[csp-debug]` lines (vs lemonde/x.com which do). The inline #662 banner defeats
SW hijack of the *loader src*, but not a fully cached HTML shell.

## Decided scope (from brainstorm)

- **Targeted + auto-learn.** Neuter the SW only on an editable allow-list of
  hosts; nothing global (a global SW-kill would break offline/push for every
  tunnel site). Auto-detection proposes candidate hosts; the operator promotes.
- **Passive re-appearance.** The neuter SW unregisters silently and clears its
  caches; it does NOT force-reload clients. The banner returns on the **next
  navigation** (which bypasses the now-gone SW → fresh fetch → MITM injects).
- **Accepted tradeoff:** neutering a listed site's SW breaks its offline mode /
  web-push / background-sync for tunnel clients. This is the cost of coverage,
  scoped to the curated list.

## Approach (chosen)

Intercept the **Service-Worker script fetch** in sbxmitm and, for allow-listed
hosts, serve a self-unregistering SW instead of proxying the real one. The
browser updates to it → unregisters → caches cleared → next navigation is fresh.

Why this over alternatives:
- **vs. injecting a SW-unregister script into pages:** chicken-and-egg — the main
  doc is SW-served, so our injected script never reaches it. Intercepting the SW
  *script fetch* works because the browser re-fetches the SW script over the
  network (the `Service-Worker: script` request DOES traverse the MITM), even
  for cache-first PWAs.
- **vs. blocking sw.js with a 204:** a 204 stops SW *updates* but does not remove
  an already-installed controlling SW. Serving an unregistering SW actively
  removes it.

## Components

Each is small and follows an existing sbxmitm pattern.

### 1. `cmd/sbxmitm/swneuter.go` (new)
- **Allow-list loader:** wraps `reload.LoadLines("/var/lib/secubox/toolbox/sw-neuter-hosts.txt", true)` with a `reload.Watcher` for hot-reload — identical to the splice-whitelist / learned-trackers loaders. Exposes `Match(host) bool` doing the same suffix-match used by `policy`/splice (`host == p || strings.HasSuffix(host, "."+p)`), lowercased + port-stripped.
- **`isSWScriptRequest(req) bool`:** true when the request carries the spec-mandated `Service-Worker: script` header (browsers send it on every SW script fetch).
- **`NeuterSW` constant:** the self-unregistering SW body (see below).
- Construction wired in `main()` from a flag `--sw-neuter-hosts` (default `/var/lib/secubox/toolbox/sw-neuter-hosts.txt`); nil-safe (a nil neuter = feature off).

### 2. Insertion in `mitmPipeline` (main.go)
After the decrypted request is read and BEFORE the normal proxy, at the same
layer as the `verdict == "block"` → 204 short-circuit: if
`neuter != nil && isSWScriptRequest(req) && neuter.Match(host)` →
`writeRaw(tconn, 200, "OK", {"Content-Type":"application/javascript","Cache-Control":"no-store","X-SecuBox-Ng":"sw-neutered"}, []byte(NeuterSW))` and return. The real SW script is never fetched.

### 3. Autolearn candidate feed
When sbxmitm sees `isSWScriptRequest(req)` for a host that is NOT on the allow-list,
record it as a sw-neuter candidate (lock-guarded, capped map, mirroring
`adstats.go`'s ad-candidate aggregator). Drained by the existing stats flusher
into a portal POST (a new `sw_candidates` field on the existing ad-event payload,
or a sibling `/__toolbox/sw-candidate` endpoint — decide at plan time to reuse the
existing channel where cleanest). The portal stores candidates; the existing
`secubox-toolbox-autolearn` proposes them; the operator promotes a host by adding
it to `sw-neuter-hosts.txt` (de-whitelist = remove the line — same UX as
splice-whitelist).

Precision note: candidate proposal is intentionally broad (any SW-script host not
already listed). It is SAFE because nothing is neutered until the operator
promotes a host to the allow-list — proposals never auto-neuter.

### The neuter SW body (`NeuterSW`)
```js
// SecuBox SW-neuter (#753): self-unregister + drop caches so the next
// navigation is a fresh network fetch the MITM can inject the banner into.
// Passive — no client.navigate(), so the current page is not force-reloaded.
self.addEventListener('install', function(e){ self.skipWaiting(); });
self.addEventListener('activate', function(e){
  e.waitUntil((async function(){
    try { var ks = await caches.keys(); await Promise.all(ks.map(function(k){ return caches.delete(k); })); } catch (_) {}
    try { await self.registration.unregister(); } catch (_) {}
  })());
});
```

## Data flow

```
SW script fetch (Service-Worker: script)  →  sbxmitm mitmPipeline
   ├─ host ∈ allow-list  → writeRaw(200, NeuterSW) → browser unregisters SW → next nav fresh → banner
   └─ host ∉ allow-list  → record sw-neuter candidate → flush → portal store → autolearn proposes → operator promotes
```

## Error handling / safety

- **Targeted-strict:** only allow-listed hosts are neutered; an empty/missing
  list is a complete no-op (fail-safe via `LoadLines` → empty set).
- **Off-switch:** a nil neuter (flag pointing at a non-existent file, or feature
  disabled) means the SW-script path is untouched — normal proxy.
- **Scoped trigger:** the neuter is served ONLY on requests carrying the
  `Service-Worker: script` header, never on normal navigation/subresource
  traffic.
- **Idempotent / loop-safe:** re-serving the neuter SW is harmless (it just
  unregisters again); passive mode means no reload loop.
- **Candidate cap:** the autolearn buffer is bounded (mirrors `adCandMapCap`) so
  a flood of SW hosts cannot grow memory unbounded.

## Testing

- **Unit (Go, `cmd/sbxmitm/swneuter_test.go`):**
  - `Match`: suffix-match positives (`leparisien.fr` matches `www.leparisien.fr`)
    + negatives (`notleparisien.fr` must NOT match); exact host; port-stripped.
  - `isSWScriptRequest`: true with `Service-Worker: script`, false without.
  - `NeuterSW` body: contains `self.registration.unregister()` and clears caches,
    and does NOT contain `client.navigate`/`clients.matchAll(...).navigate`
    (passive guarantee).
  - empty/missing allow-list file → `Match` always false (no-op).
- **Manual:** add `leparisien.fr` to `sw-neuter-hosts.txt`; reload leparisien
  through the tunnel; confirm the SW is unregistered (DevTools → Application →
  Service Workers) and the banner appears on the next navigation. Confirm a host
  NOT on the list keeps its SW.

## Out of scope (this iteration)

- A WebUI panel to manage the allow-list / review candidates (v2 — the text file
  + the autolearn proposal channel are the v1 surface, mirroring splice-whitelist).
- Forced/immediate reload (the brainstorm chose passive).
- Injecting into the SW's own revalidation fetches (approach 2 in the issue) —
  the neuter approach supersedes it for cache-first PWAs; revisit only if a
  network-first PWA proves the neuter too aggressive.

## Durability

The new flag + allow-list default ship in the `secubox-toolbox-ng` package; the
allow-list file is operator state under `/var/lib/secubox/toolbox/` (not shipped,
created empty by postinst/tmpfiles if needed). A `.deb` bump + reinstall makes
the engine change durable (same flow as #754).
