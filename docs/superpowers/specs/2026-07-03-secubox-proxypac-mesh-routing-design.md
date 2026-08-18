<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-proxypac — WPAD/PAC auto-config for mesh-service routing (design)

**Issue:** #784 · **Date:** 2026-07-03 · **Status:** design (sub-project A of 2)

## Goal

Give end-users **zero-config** access to the tools and services distributed across the
SecuBox p2p mesh. A locally-served, auto-generated **proxy.pac** — discovered by clients
via **WPAD** — routes each host/URL to the right transport:

- a mesh **tor-exit** SOCKS (SOCKS-over-mesh, macro #771/#773),
- the **toolbox MITM** inspection proxy,
- a **remote HTTP service** on another node (via the future mesh gateway, sub-project B),
- or **DIRECT**.

The routing map is composed automatically from the **active/subscribed** p2p `/services`
catalog, refined by an **operator per-host policy** (seed + WebUI + auto-learn), exactly
mirroring the #740 splice-whitelist / #743 tor-egress override pattern.

## Scope

**In scope (A):** the PAC generator, WPAD/PAC serving, the hybrid routing source (annuaire
service patterns + operator override + auto-learn), the WebUI override panel, and a
browser-extension complement. Routing targets are **on-mesh** transports (mesh IPs) plus
placeholder emission for gateway URLs.

**Out of scope (B, separate spec):** the mesh **gateway with generative URLs** that lets
**off-mesh** clients (a plain LAN/internet browser not on the wg-mesh) reach services on
another node — e.g. gk2 reverse-proxying to a c3box service via a minted URL. A's PAC will
emit `PROXY <gateway-host>` / the generated URL for such services **once B exists**; until
then those services simply are not routed for off-mesh clients.

## Non-goals / YAGNI

- No per-client/per-identity dynamic PAC (static file only; browsers cache PAC hard).
- No replacement of the toolbox webext — it is an optional complement, not the engine.
- No new transport implementation — A only *routes to* transports that already exist
  (tor-exit SOCKS grant, toolbox MITM, direct).

## Architecture

New Debian package **`secubox-proxypac`**, deployed **per node**. Each node serves a PAC
reflecting *its own* active subscriptions + operator policy. Five components:

### 1. Generator (`proxypac-gen`)
A small script/service that reads the inputs, composes the PAC JavaScript, and writes a
**static** file `/var/lib/secubox/proxypac/proxy.pac`. Runs on a change trigger (below),
never in the client's resolution path.

**Inputs:**
- **Mesh service catalog** — p2p `GET /services` (active + subscribed). Each service may
  carry an optional `pac` descriptor (new annuaire field, below) declaring the host
  patterns it serves and the proxy directive to use.
- **Toolbox tool state** — whether MITM inspection is active (and its proxy address), read
  from the toolbox filters/state already exposed by secubox-toolbox.
- **Operator override rules** — `/etc/secubox/proxypac/rules.d/*.rules` (per-host →
  directive), seed + WebUI-managed. Same shape/precedence as #740/#743 lists.
- **Auto-learn candidates** — `/var/lib/secubox/proxypac/candidates.json`; *proposed only*,
  never applied until an operator accepts (which promotes them into `rules.d`).

**Output:** `/var/lib/secubox/proxypac/proxy.pac` (+ a `.shadow` staged copy, atomically
swapped — see Safety).

### 2. WPAD / PAC serving (nginx)
- `http://<node>/proxy.pac` — content-type `application/x-ns-proxy-autoconfig`.
- `http://wpad.<domain>/wpad.dat` — same file, on a dedicated `wpad` vhost, **LAN/mesh
  only** (`allow` the LAN + `10.10.0.0/24`, `deny all`).
- **DHCP option 252** (WPAD URL) added to the toolbox AP's dnsmasq and, where applicable,
  the mesh-facing DHCP, so browsers auto-discover with no user action.

### 3. Regeneration trigger
A debounced watcher that regenerates on any input change:
- mtime of `rules.d/` and the toolbox state file (a lightweight systemd path unit / timer);
- an explicit hook `proxypac-gen --once` called by p2p **service activate/revoke** and by
  the toolbox inspection toggle, so routing updates immediately on a service change.

### 4. WebUI override panel
A dashboard panel (served like other secubox modules) to: view the current PAC + effective
rules; add/remove a per-host override with its target directive; accept/reject auto-learn
candidates. Reuses the #740/#743 UX and **dual-engine write** (write the rule, trigger
regen). Live list.

### 5. Browser-extension complement (optional, #655)
The existing toolbox webext reads the same effective rules (or the served PAC) to offer
per-request UI and a one-click "route this host via <tool>" toggle that writes back into
`rules.d/` (through the WebUI API). Not required for the PAC to function; purely additive.

## Routing source & PAC composition

`FindProxyForURL(url, host)` is generated with a fixed **precedence**:

1. **Operator override** (explicit per-host / pattern) — highest, always wins.
2. **Active mesh-service patterns** (from the catalog `pac.match`).
3. **Toolbox default** — if "inspect all" is on, route the rest through the toolbox MITM.
4. **`DIRECT`** — terminal default.

Each matched rule yields one PAC directive:
- `SOCKS5 10.10.0.1:9050; DIRECT` — a mesh tor-exit (provider mesh IP + granted SocksPort).
- `PROXY <toolbox-mitm-host:port>; DIRECT` — toolbox inspection.
- `PROXY <gateway-host>; DIRECT` — a remote HTTP service via gateway **B** (emitted only
  when a `pac.proxy == "gateway"` service is active *and* B is present; otherwise skipped).
- `DIRECT` — no proxy.

Every non-DIRECT directive ends with `; DIRECT` fallback so a dead proxy fails **open to
direct**, never blackholes the client.

### Annuaire schema addition
Add an **optional** `pac` object to a service offer:

```json
"pac": { "match": ["*.onion", "check.torproject.org"], "proxy": "socks5" }
```

- `proxy ∈ {"socks5", "http", "gateway", "direct"}`.
- The provider's mesh IP + granted port fill the concrete address at generation time.
- **Backward-compatible**: absent `pac` ⇒ the service contributes no routing rule. A
  **byte-stability guard** keeps `pac`-less offers signature-compatible with pre-schema
  nodes (same pattern as the macro field #771).

## Data flow

```
service activate/revoke (p2p)  ─┐
operator edits override (WebUI) ─┼─▶ regen trigger ─▶ proxypac-gen
toolbox inspection toggle       ─┘        reads: /services + rules.d + toolbox state
                                          writes: proxy.pac (atomic swap)
                                                     │
client (WPAD-discovered, short cache) ◀── nginx /proxy.pac + wpad.dat
```

## Safety, security, CSPN

- **Fail-safe PAC:** if generation errors, keep the **last-good** file (never serve an
  empty/broken PAC). The terminal `DIRECT` + per-directive `; DIRECT` fallback guarantee a
  malformed or stale rule cannot blackhole traffic.
- **Atomic swap:** generate to `proxy.pac.shadow`, validate (parse-check the JS), then
  rename over `proxy.pac` — active/shadow double-buffer (PARAMETERS 4R pattern).
- **Authorization coupling:** the PAC references only transports the node is *currently
  authorized* for. A revoked mesh grant ⇒ its rule disappears on the next regen (bounded by
  the debounce). No secrets ever appear in the PAC (it carries hosts + proxy addresses
  only).
- **WPAD hijack containment:** `wpad.dat` and `/proxy.pac` are served **only** on the
  trusted LAN/mesh vhost (`deny all` otherwise); never public. DHCP 252 is set only on the
  operator-controlled AP/mesh DHCP.
- **Audit (CSPN):** every override add/remove and every auto-learn accept/reject is written
  append-only to `/var/log/secubox/audit.log`.

## Auto-learn (candidate proposal)

A detector proposes per-host candidates but **never** applies them:
- signal source is deliberately generic in A — a hook other components can feed (e.g. the
  toolbox observing a Tor-hostile 403/captcha for #743, or a "service X advertises host Y"
  event). A writes candidates to `candidates.json`; the operator promotes via WebUI.
- This keeps A's auto-learn mechanism decoupled from any single signal, and lets #743 plug
  its Tor-hostile detector in later without changing A.

## Testing

- **Generator (golden):** given a fixed catalog + `rules.d` + toolbox state, assert the
  exact generated PAC JS.
- **Routing correctness:** evaluate `FindProxyForURL` for representative hosts (onion,
  cloudflare host, a mesh-service host, an unlisted host) via a PAC evaluator
  (pacparser / a node harness) → expected directive incl. the `; DIRECT` fallback.
- **Precedence:** an operator override beats a service pattern for the same host.
- **Fail-safe:** a generation error preserves the previous `proxy.pac`; a malformed rule is
  rejected at the shadow-validate step, not swapped in.
- **Backward-compat:** a `pac`-less service offer round-trips signature-stable.
- **WPAD serving:** correct content-type; reachable on the LAN/mesh vhost only, `deny`
  elsewhere.

## Open questions (to resolve in planning, non-blocking)

1. Exact toolbox-MITM proxy address to emit (per-node toolbox listener) — read from the
   toolbox state file; confirm the field during planning.
2. Whether to ship a starter `rules.d` seed (e.g. `*.onion → socks5` when a tor-exit is
   active) — proposed yes, minimal.

## Follow-ons

- **Sub-project B** — mesh gateway + generative URLs for off-mesh clients (own spec).
- **#743** — Tor-hostile auto-learn detector feeding A's `candidates.json`.
- **#655** — webext wired to the override API.
