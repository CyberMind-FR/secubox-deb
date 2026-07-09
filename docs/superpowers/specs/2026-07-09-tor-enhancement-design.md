# Tor Module Enhancement — Design

**Date:** 2026-07-09
**Modules:** `secubox-toolbox` (Tor egress), `secubox-exposure` (emancipate/HS), `secubox-tor` (`/tor/` webui), Unbound drop-in
**Webui:** `https://admin.gk2.secubox.in/tor/`
**Status:** Design — pending user review

---

## Goal

Turn the box's Tor stack into a full **egress-VPN + hidden-service exposure**
control surface, driven from the `/tor/` dashboard:

1. **Country-restricted exit** — choose which countries Tor exits through.
2. **Emancipate the SecuBox webui as a `.onion`**, auto-detect all present
   `.onion`s, working **standalone** (no second mesh node).
3. **Persist** exposed `.onion` services across restarts (same address).
4. **Auto `.onion` DNS** — LAN clients resolve+reach `.onion` transparently.
5. **Tor-as-VPN** — route **selectable LAN clients** (per IP/MAC/subnet) out
   through Tor with the chosen exit country; the rest of the LAN stays direct.
6. **obfs4 bridges (Niveau-1 anti-censorship)** — operator-provided obfs4
   bridge lines let Tor connect when direct Tor is DPI-blocked (entry side).
   Just Niveau-1; Snowflake/webtunnel/conjure/Reality are a later spec.

Built on existing infra (no greenfield): the transparent egress
(`torrc-toolbox-egress.conf`: `TransPort 9040`, `DNSPort`, `AutomapHostsOnResolve`,
`VirtualAddrNetworkIPv4 10.192.0.0/10`), the `secubox-toolbox-tor-reconcile`
drop-in mechanism, the `#797` `ExcludeExitNodes` exclusion, the `#793` on-demand
Tor switch, and `secubox-exposure`'s `apply_tor`/`_tor_add_sync` hidden-service
creation.

---

## Board reality (verified 2026-07-09, drives the design)

- Tor egress is **on-demand / currently off** (`tor@default`, `secubox-toolbox-tor`
  dead; `.path`/`.timer` waiting — the `#793` switch).
- **No hidden services exist** yet (`/var/lib/tor/*/hostname` empty) — so there
  is **nothing pre-existing to "adopt"**; feature 2 *creates* the webui `.onion`
  ("kbin" = the box's own webui) and auto-detects it going forward.
- **`.onion` DNS is not wired** to Unbound, and **port `5353` is already bound by
  `avahi-daemon`** — a real conflict the egress `DNSPort` must move off.
- No `ExitNodes`/`ExcludeExitNodes` in the *active* torrc (applied by reconcile
  only when egress is on).
- `secubox-tor` webui already has `/status`, `/circuits`, `/hidden_services`
  (config-listed), `tor_control()`.
- `secubox-exposure` already has `apply_tor(service, port, onion)`,
  `_tor_add_sync(name, local_port, onion_port)`, `TOR_DATA=/var/lib/tor/hidden_services`,
  cert-pin-gated `/tor/add` + `/emancipate`, and federates offers into the annuaire.

---

## Architecture — who owns what

| Concern | Package | Extends |
|---|---|---|
| Global exit-country torrc + reconcile | `secubox-toolbox` | `torrc-toolbox-egress.conf`, `secubox-toolbox-tor-reconcile`, `#797` exclusion |
| Per-client Tor-VPN nft routing | `secubox-toolbox` | `nft-toolbox-tor.nft` |
| `.onion` DNS (DNSPort move + Unbound forward) | `secubox-toolbox` + Unbound drop-in | egress torrc |
| Emancipate webui `.onion` + auto-detect + persist | `secubox-exposure` | `apply_tor`/`_tor_add_sync`, reconcile-on-boot |
| Webui controls for all of the above | `secubox-tor` | `api/main.py`, `www/tor/index.html` |

All API handlers that shell out or touch tor are plain `def` if the module is
aggregator-mounted (avoid the loop-block SPOF); privileged actions go through the
existing sanctioned helpers (`secubox-toolbox-tor-reconcile`, exposure's tor-add
sync path), never ad-hoc root.

---

## Phase 1 (single tor daemon)

### ① Global exit-country

- New torrc drop-in **`/etc/tor/torrc.d/11-secubox-exit-country.conf`** emitting
  `ExitNodes {cc},{cc},… ` + `StrictNodes 1` (or empty/absent when no country is
  chosen → default Tor behavior). Ships as
  `packages/secubox-toolbox/conf/torrc-exit-country.conf` (template) written from
  operator state.
- Applied by an **extended `secubox-toolbox-tor-reconcile`** (same idempotent
  drop-in + `%include` + reload-now pattern it already uses for egress/exclusion),
  so it survives nft/tor reloads and loads via the control port without a full
  restart where possible.
- **State** lives in `/etc/secubox/toolbox/tor-exit-country.txt` (or the toolbox
  TOML) — a validated list of ISO-3166-1 alpha-2 codes (`^[A-Za-z]{2}$`, upper-cased).
  GeoIP data is tor's shipped `/usr/share/tor/geoip{,6}` (already a `tor` dep).
- **`StrictNodes 1` fails closed:** if the chosen country has no usable exit, Tor
  builds no exit circuit. The webui MUST show this state (bootstrap stuck / no
  exit) rather than silently degrade.
- Webui: a country multi-select (from a static ISO list) → `POST
  /api/v1/tor/exit_country {countries:[...]}` → writes state + runs reconcile;
  `GET /api/v1/tor/exit_country` returns current + the live exit relay's country
  (from `tor_control("GETINFO ...")` / circuit exit).

### ⑤ Tor-as-VPN — selectable LAN clients

- Webui manages **client selectors**: a list of `{selector, kind}` where kind ∈
  `{ip, cidr, mac}`, validated (`ip`/`cidr` via `ipaddress`, `mac` via regex).
- For each active selector, an nft rule in a **layered drop-in** (extending
  `nft-toolbox-tor.nft`) redirects that client's egress → Tor `TransPort 9040`
  and its DNS (udp/tcp 53) → the automap `DNSPort`; non-selected LAN traffic is
  untouched. The drop-in is `zz-`-sorted so it applies **after** the table
  creator (per the nft-layered-dropin persistence rule) and is re-applied by the
  reconcile / a postinst-safe path (survives dpkg upgrade + operator nft reloads).
- **Gated on the `#793` egress switch**: selectors only take effect while Tor
  egress is enabled; toggling the VPN on enables egress if needed.
- Combined with ①, selected clients egress via Tor in the chosen country.
- Webui: a "Route via Tor" client table (add/remove selector, on/off) →
  `POST /api/v1/tor/vpn/client`, `DELETE /api/v1/tor/vpn/client/{id}`,
  `GET /api/v1/tor/vpn/clients`. Shows each client's live routed state.
- **Audit:** every VPN-client add/remove and exit-country change appended to
  `/var/log/secubox/audit.log` (append-only) — a network-egress policy change is
  a security decision.

### ② Emancipate the webui `.onion` + auto-detect (standalone)

- **Create** a hidden service for the admin webui:
  `HiddenServiceDir /var/lib/tor/hidden_services/hidden_service_webui`,
  `HiddenServicePort 80 127.0.0.1:9080` (the nginx canonical-hub vhost). Reuses
  exposure's `_tor_add_sync(name="webui", local_port=9080, onion_port=80)` path
  (which already sanitizes the name + writes the HS torrc + reloads tor).
- **Standalone:** the existing `apply_tor` also publishes a signed offer into the
  annuaire (mesh federation). Add a **`federate: bool` (default from mesh
  presence)** so the HS is created + served **locally even with no mesh / second
  node**; federation becomes best-effort and never blocks the emancipation.
- **Auto-detect:** change `secubox-tor`'s `GET /hidden_services` from
  config-listed to **filesystem-discovering** — enumerate every
  `/var/lib/tor/**/hostname`, read the `.onion`, and cross-reference the
  configured/emancipated services for name+target. So the webui surfaces *every*
  `.onion` present (the webui's own + any future service), not just ones in a
  config list.
- Webui: an **"Emancipate this dashboard over Tor"** action → `POST
  /api/v1/tor/emancipate_webui` (JWT+cert-pin gated, via exposure) → creates the
  HS, shows the resulting `.onion`; a copy button + a QR is nice-to-have.

### ③ Persist exposed services

- Durable state = exposure's emancipated-services config (`config["emancipated"]`
  with `{name, local_port, onion_port, active}`) **plus** the on-disk HS key dirs
  (which already persist the `.onion` address).
- A **reconcile oneshot** (`secubox-exposure-tor-reconcile`, run on tor-start via
  a `.path`/drop-in and on boot) re-applies every `active` emancipated service to
  the HS torrc drop-in and reloads tor — so exposures survive tor restarts / box
  reboots with the **same `.onion`**. Mirrors the toolbox reconcile's
  drop-in-survival + reload-now pattern.
- Idempotent: an already-present HS dir is left untouched (key preserved); a
  removed-but-still-`active` service is re-added; an inactive one is dropped from
  torrc but its key dir is kept (so re-enabling restores the same address) unless
  explicitly purged.

### ④ Auto `.onion` DNS

- **Resolve the 5353 conflict:** change the egress `DNSPort` from
  `127.0.0.1:5353` to **`127.0.0.1:9053`** in `torrc-toolbox-egress.conf` (avahi
  owns 5353 for mDNS; do not touch avahi).
- **Unbound forward-zone drop-in**
  `/etc/unbound/unbound.conf.d/48-secubox-onion.conf`:
  ```
  forward-zone:
    name: "onion."
    forward-addr: 127.0.0.1@9053
  ```
  plus `do-not-query-localhost: no` if the global config would otherwise block
  loopback forwarding. So any LAN client resolving `foo.onion` through the Vortex
  resolver gets Tor's automap virtual IP (`10.192.0.0/10`); combined with the
  transparent `TransPort` redirect (for VPN clients) the `.onion` is reachable.
- **Gated on the egress switch:** the forward-zone is only meaningful when Tor
  egress + its `DNSPort` are up. When egress is off, `.onion` resolution fails
  cleanly (SERVFAIL/NXDOMAIN) rather than hanging — the reconcile installs the
  drop-in when egress goes on and can neutralize it when off (or the forward
  simply fails fast, acceptable).
- Webui: a `.onion`-DNS status line (DNSPort up? forward-zone installed?
  resolves a canary `.onion`?).

### ⑥ obfs4 bridges (Niveau-1 entry-side anti-censorship)

Distinct from ①⑤ (exit side): this is how Tor *reaches* the network when direct
Tor is DPI-blocked. Operator pastes obfs4 `Bridge` lines (from BridgeDB / Tor
Browser's moat / a private bridge). State in
`/etc/secubox/toolbox/tor-bridges.txt` (one `Bridge obfs4 <ip:port> <fp>
cert=… iat-mode=…` per line). When non-empty, the reconcile emits
`/etc/tor/torrc.d/12-secubox-bridges.conf` with `UseBridges 1`,
`ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy`, and the validated Bridge
lines; empty → no drop-in (direct Tor). Adds `obfs4proxy` as a toolbox dep.
Each bridge line is validated (`^Bridge obfs4 ` + a safe charset, no newline
injection into torrc). Webui `#tor` panel to add/list/remove bridges. Snowflake
(WebRTC), webtunnel, conjure, and out-of-Tor Reality/Xray are explicitly a
LATER spec (the full escalation ladder) — see the anti-censorship design.

---

## Phase 2 (deferred) — per-service exit-country override

Tor's `ExitNodes` is **global** to a tor instance, and a hidden service is
*inbound* (rendezvous — no exit node), so per-service exit-country only applies
to services that **egress outbound** through Tor, and varying it per service
requires **a separate tor SOCKS instance per exit policy** (one daemon cannot
vary `ExitNodes` per circuit by service). Phase 2 adds:
- A small pool of tor instances (or `tor` `SocksPort` isolation with per-instance
  `ExitNodes`), one per distinct country policy, and routes a service's outbound
  egress to the matching instance.
- Webui per-service exit-country override on top of the global default.

Deferred because it multiplies the tor-instance/systemd surface; Phase 1
delivers the global country policy that covers the common case.

---

## Error handling

- Country codes + client selectors validated **before** any torrc/nft write
  (ISO-3166 alpha-2; `ip`/`cidr`/`mac`). Invalid → 400, no state change.
- `StrictNodes 1` fail-closed is surfaced, not hidden: the webui distinguishes
  "no exit in chosen country" from "Tor down".
- Reconcile is idempotent + drop-in-survival; a reload failure leaves the prior
  working config (never a half-applied torrc).
- Emancipate/HS creation via the sanctioned exposure helper (keeps the cert-pin
  gate + name sanitization); federation is best-effort and never blocks.
- nft drop-ins `zz-`-sorted; postinst re-applies operator-relevant drop-ins
  (per the postinst-preserve-runtime-state rule); shared `/run/secubox`,
  `/etc/secubox`, `/var/log/secubox` parents never re-chowned/loosened.
- No `waf_bypass`: the emancipated webui `.onion` still routes the normal stack
  (HS `HiddenServicePort → 127.0.0.1:9080`, the canonical nginx hub).

## Testing

- **① country:** reconcile writes valid `ExitNodes {cc} StrictNodes 1`;
  bad country → rejected; live: set exit country, `tor_control` circuit exit is
  in that country; empty selection → drop-in absent, default behavior.
- **⑤ VPN:** selector validation matrix (ip/cidr/mac good+bad); nft drop-in
  redirects only the selected client; drop-in survives an nft reload; toggling
  off removes the redirect; gated on egress switch.
- **② emancipate:** HS created, `.onion` serves the webui over Tor; auto-detect
  lists every on-disk `.onion`; standalone (mesh down) still emancipates.
- **③ persist:** restart tor / reboot → emancipated HS present with the SAME
  `.onion`; inactive service dropped from torrc but key kept.
- **④ .onion DNS:** DNSPort on 9053 (no avahi conflict); Unbound forwards
  `onion.`; resolving a known `.onion` via the box resolver returns an automap
  IP; off-switch → clean failure.
- **webui:** `node --check` the inline script; XSS-escape all rendered `.onion`
  / country / client strings; JWT + cert-pin on privileged actions.
- **live e2e (gk2):** enable Tor VPN for one test client with exit country =
  a chosen CC; that client's public IP geolocates to the CC; a non-selected
  client stays direct; emancipate the webui, reach its `.onion`; reboot, `.onion`
  unchanged.

## Files (Phase 1)

- `packages/secubox-toolbox/conf/torrc-toolbox-egress.conf` — DNSPort → 9053.
- `packages/secubox-toolbox/conf/torrc-exit-country.conf` — new template.
- `packages/secubox-toolbox/conf/nft-toolbox-tor.nft` — per-client redirect
  additions (layered).
- `packages/secubox-toolbox/sbin/secubox-toolbox-tor-reconcile` — apply
  exit-country drop-in + per-client nft + install/neutralize the Unbound
  `.onion` forward-zone on egress on/off.
- `packages/secubox-toolbox/conf/48-secubox-onion.conf` — Unbound forward-zone
  (installed to `/etc/unbound/unbound.conf.d/`).
- `packages/secubox-exposure/api/*` — `federate` flag on emancipate;
  `secubox-exposure-tor-reconcile` + unit for persist-on-boot; webui-emancipate
  endpoint.
- `packages/secubox-tor/api/main.py` — exit-country get/set, VPN client CRUD,
  emancipate-webui, filesystem-discovering `/hidden_services`, `.onion`-DNS
  status.
- `packages/secubox-tor/www/tor/index.html` — country picker, VPN client table,
  emancipate button, `.onion` list, DNS status.

## Out of scope

- Phase 2 per-service exit override (sketched above).
- Remote-client WireGuard→Tor VPN (a distinct feature; `wg-toolbox` exists).
- Changing avahi, the `#793` switch mechanism, or the mesh/annuaire federation
  itself.
- New tor bridges/pluggable transports.

## Open decisions for the plan

1. **State store for exit-country + VPN selectors:** flat files under
   `/etc/secubox/toolbox/` (chosen — matches the existing tor-exempt-hosts /
   exclusion file pattern) vs the toolbox TOML. Lock in the plan.
2. **`.onion`-DNS off-switch handling:** reconcile removes the Unbound drop-in
   when egress goes off (clean) vs. leave it and let the forward fail fast
   (simpler). Lean: remove on off for cleanliness; decide in the plan.
