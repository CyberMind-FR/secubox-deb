<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Macro Subsystem (Milestone 2) — tor-exit reference kind — Design

**Date:** 2026-06-30
**Status:** Approved (brainstorming) — ready for implementation plan
**Scope:** Milestone 2 of the "services propose a macro subsystem" vision. First
increment: the framework + one reference kind (`tor-exit`).
**Builds on:** `2026-06-30-p2p-annuaire-service-registry-design.md` (M1, §7
deferred this), secubox-annuaire ≥0.2.1 (#766/#768 trustless federation),
secubox-p2p 1.8.0 (Service Registry live view), `packages/secubox/PUNK-EXPOSURE.md`.

---

## 1. Problem & goal

M1 made the p2p Service Registry a live view of the federated annuaire catalog,
but a consumer can only *see* and *subscribe to* a service — it cannot actually
*consume* it. The vision (the operator's words): *a service must propose a macro
subsystem for scripting and automating access to it — e.g. a Tor-activated node
proposes its Tor exit as a service and offers it to peers.*

M2 delivers that consumption layer as **vetted, parameterized, AppArmor-confined
plugins**: a service offer names a `kind` + typed `params`; the provider runs a
`grant` plugin to authorize an approved subscriber; the consumer runs an
`activate` plugin to start using it; `revoke` tears it down. The first increment
ships one real kind — **`tor-exit` as SOCKS-over-mesh** — and the framework that
makes adding more kinds a matter of shipping another vetted plugin package.

**Non-goals (this increment):** per-client Tor circuit isolation; consumer-side
transparent routing of all traffic (we surface the SOCKS endpoint, the operator
points clients at it); kinds beyond `tor-exit`; a GUI for composing macro params
(CLI only for offering); arbitrary/operator-authored or signed-portable macros
(explicitly rejected in M1 — only the vetted catalog); **`pending`-approval
macro offers** — increment 1 supports only `auto`-mode macro offers (see §7:
cross-node subscription/approval federation does not exist yet, so a provider
cannot consult a remote pending approval; `auto` mode carries the provider's
standing consent inside the signed offer).

## 2. Locked design decisions (from brainstorming)

- **Execution model:** a single root CLI `secubox-macroctl` invoked by p2p via a
  narrow sudoers allowlist; each kind runs under a per-kind AppArmor profile.
  (Not a daemon, not per-kind systemd units.)
- **Credential delivery:** the consumer **pulls** the grant credential from the
  provider over the mesh; secrets stay point-to-point and never enter the
  annuaire log.
- **Grant is lazy (at pull-time):** annuaire DIDs and wg-mesh IPs are different
  keyspaces, so the provider cannot scope an nft allow at *approve* time (it
  doesn't know the subscriber's mesh IP). Instead, when the authenticated
  subscriber pulls, the provider sees the DID **and** the pull's source mesh IP,
  and runs `grant` for that IP. No DID→IP directory is needed.
- **Trust model:** offers carry only an allowlisted `kind` + typed `params`,
  never code. `macroctl` never evaluates offer-supplied strings.

## 3. Architecture & packaging

```
┌── secubox-annuaire 0.3.0 ─────────────────────────────────────────────┐
│  ServiceOffer.macro = {kind: str, params: dict} | None  (signed,        │
│  federates). annuairectl offer --macro-kind tor-exit --macro-param k=v  │
└────────────────────────────────────────────────────────────────────────┘
┌── secubox-macro (NEW) ────────────────────────────────────────────────┐
│  /usr/sbin/secubox-macroctl                 (root CLI, dispatcher)      │
│  /usr/lib/secubox/macro/macros.d/tor-exit   (the vetted plugin)         │
│  /etc/apparmor.d/secubox-macroctl           (+ per-kind confinement)    │
│  /etc/sudoers.d/secubox-macro               (secubox → macroctl only)   │
│  /var/lib/secubox/macro/{active,grants}/    (state)                     │
│  /etc/tor/torrc.d/secubox-macro-tor-exit.conf (SocksPort on mesh IP)    │
└────────────────────────────────────────────────────────────────────────┘
┌── secubox-p2p 1.9.0 ──────────────────────────────────────────────────┐
│  mesh endpoint  GET /api/v1/p2p-macro/grant/{service_id}  (provider)    │
│     authenticates consumer DID + checks annuaire APPROVED → sudo        │
│     macroctl <kind> grant --sub DID --src-ip <peer> → returns cred      │
│  POST /services/{id}/activate (M1) → pull cred → sudo macroctl activate │
│  POST /services/{id}/revoke-access → sudo macroctl revoke               │
│  UI: Activate shows the SOCKS endpoint; Revoke on granted rows          │
└────────────────────────────────────────────────────────────────────────┘
```

Why a new `secubox-macro` package (not folded into p2p or annuaire): annuaire is
the pure trust substrate and must not execute privileged plugins; p2p runs
unprivileged as `secubox`. The privileged execution + the vetted plugin catalog
belong in their own package so future kinds ship as independent vetted plugins.

## 4. Components

### 4.1 annuaire — `ServiceOffer.macro` (0.3.0)
- New optional field `macro: Optional[MacroDescriptor]` where
  `MacroDescriptor = {kind: str (^[a-z][a-z0-9-]{1,31}$), params: Dict[str,str|int|bool]}`.
- Optional ⇒ existing offers stay valid. It is part of the signed canonical
  payload (so it federates trustlessly and `_enrich_offer`/ingest already carry
  it). `annuairectl offer` gains `--macro-kind` + repeatable `--macro-param k=v`.
- annuaire still executes nothing — it only stores/serves the descriptor.

### 4.2 `secubox-macroctl` (root dispatcher)
`secubox-macroctl <kind> <grant|activate|revoke> [--sub DID] [--src-ip IP] [--params JSON] [--cred JSON]`
- Resolves `<kind>` against the installed `macros.d/` directory listing — an
  **allowlist**; rejects unknown kinds, path separators, and anything not
  matching `^[a-z][a-z0-9-]{1,31}$`.
- Verifies the plugin file is root-owned and mode 0755 before exec (refuses
  otherwise — tamper guard).
- Validates `--src-ip` is a literal IPv4 inside `10.10.0.0/24` (reject else).
- Execs `macros.d/<kind> <verb>` with validated args passed as argv; captures
  stdout (must be a single JSON object for `grant`). Never passes args through a
  shell; never evaluates `params` content as code.
- Appends `{ts, kind, verb, sub, src_ip, result}` to `/var/log/secubox/audit.log`.

### 4.3 `macros.d/tor-exit` (the vetted plugin)
A plain executable implementing three verbs (stdin/argv in, JSON out):
- `grant --sub DID --src-ip IP --params {socks_port}`:
  add `IP` to nft set `secubox_macro_torexit` (allow `iifname wg-mesh ip saddr IP
  tcp dport <socks_port> accept`); idempotent; print
  `{"kind":"tor-exit","endpoint":"<mesh-ip>:<socks_port>"}`.
- `activate --cred {endpoint}`: write
  `/var/lib/secubox/macro/active/<service_id>.json`; print human guidance
  (`SOCKS proxy <endpoint>`).
- `revoke --sub DID --src-ip IP`: remove `IP` from the set; idempotent.
Provider prerequisite (postinst): Tor running with
`SocksPort <mesh-ip>:<port>` via `/etc/tor/torrc.d/secubox-macro-tor-exit.conf`;
the nft base set `secubox_macro_torexit` created in the `secubox_filter` table.

### 4.4 p2p — credential pull + actions (1.9.0)
- **Provider endpoint** `POST /api/v1/p2p-macro/grant/{service_id}` exposed ONLY
  on the wg-mesh listener (reuse M1/#766 mesh-listener pattern + nft). The
  consumer **presents its self-signed `Subscription`** (the annuaire Subscription
  object, signed by the subscriber) in the request body. The provider authorizes
  WITHOUT consulting any federated state (§7): it verifies (a) the Subscription's
  signature against the subscriber DID (self-certifying: `did_from_pubkey ==
  subscriber`), (b) the Subscription's `service_id` matches the path, (c) the
  local offer for that `service_id` exists and is `approval_mode == auto` (the
  provider's standing consent). On success it reads the offer's `macro` and runs
  `sudo secubox-macroctl <kind> grant --sub <subscriber-DID> --src-ip
  <peer-mesh-ip> --params <offer.macro.params>`, returning the credential JSON.
  The `src-ip` is the request's wg-mesh source address (provider-observed, not
  client-supplied).
- **Consumer activate** (extends M1 `/services/{id}/activate`): if the offer is
  remote + automatable, pull the credential from the provider's mesh endpoint,
  then `sudo secubox-macroctl <kind> activate --cred <json>`; store the active
  endpoint; mark `active`.
- **Consumer revoke-access** `POST /services/{id}/revoke-access`: `sudo
  secubox-macroctl <kind> revoke ...` + clear local active state. Provider-side
  revoke also fires when the provider revokes the offer (drops all grants for it).

## 5. Data flow (sequence)

```
provider:  annuairectl offer --macro-kind tor-exit --macro-param socks_port=9050
           → offer.macro={kind,params}; federates (M1 trustless pull)
consumer:  catalog shows "Tor exit (automatable: tor-exit)"; Subscribe → provider Approve → APPROVED
consumer:  click Activate
   p2p →  POST provider-mesh:8799 /api/v1/p2p-macro/grant/<sid>
              body = consumer's self-signed Subscription{service_id, subscriber, sig}
   provider: verify Subscription sig (self-cert) + service_id + local offer is auto
              → sudo macroctl tor-exit grant --sub <subscriber>
                   --src-ip <request-mesh-src> --params {socks_port:9050}
              → nft set += <request-mesh-src>; reply {endpoint:"10.10.0.1:9050"}
   p2p →  sudo macroctl tor-exit activate --cred {endpoint:...}
              → /var/lib/secubox/macro/active/<sid>.json; UI: "SOCKS 10.10.0.1:9050"
consumer/provider revoke:
   p2p →  sudo macroctl tor-exit revoke --sub DID --src-ip <ip>  → nft set -= ip
```

## 6. Error handling
- Unknown/invalid `kind` or non-mesh `src-ip` → macroctl exits non-zero with a
  JSON error; p2p surfaces it, no partial state.
- Provider Tor/SocksPort not configured → `grant` returns an error credential
  (`{"error":"tor-exit not provisioned"}`); consumer activate shows it.
- Pull when not `APPROVED` → provider endpoint returns 403; no grant runs.
- Provider unreachable on the mesh (e.g. the parked master→satellite case) → pull
  times out; activate reports "provider unreachable," local state unchanged.
- nft apply failure → `grant` non-zero; no endpoint returned; auditable.

## 7. Security model
- **No offer-supplied code.** Offers carry `kind` (allowlist) + typed `params`
  only. `macroctl` execs only vetted `macros.d/*`, never a shell, never offer
  strings. Self-certifying federation (M1) authenticates the offer's origin.
- **Grant authorization is self-certifying, no federated state.** The provider
  cannot consult a remote subscription (subscriptions/approvals live in the
  consumer's journal and do not federate in M1). Instead the consumer presents
  its self-signed `Subscription` at pull-time; the provider authorizes iff: (a)
  the Subscription signature verifies against `subscriber` and
  `did_from_pubkey(pubkey) == subscriber` (self-certifying — the pubkey rides in
  the request like a federated offer), (b) `Subscription.service_id` == the path
  service, and (c) the provider's local offer for it is `approval_mode == auto`
  (auto = the provider's standing, signed consent to serve any subscriber).
  `pending`-mode macro offers are therefore out of scope this increment (they
  need cross-node approval federation — §1 non-goals, OQ-1). This makes the
  signed Subscription a bearer-style capability: anyone replaying it can trigger
  a grant, but the grant only ever nft-allows the *request's own* wg-mesh source
  IP into one port — so a replay grants the replayer nothing it could not already
  request for itself, and the blast radius is one scoped, revocable allow.
- **nft scoping** — allow is per-source-mesh-IP into exactly one port, held in a
  named set, individually removable; never `0.0.0.0`, never the whole subnet.
  `src-ip` validated ∈ `10.10.0.0/24`.
- **Privilege isolation** — only `secubox-macroctl` is sudo-allowed for
  `secubox`; the dispatcher + each plugin run under enforce-mode AppArmor that
  permits only that kind's required tools (tor-exit: `nft`, read torrc.d, write
  its state dir).
- **Immutable audit** — every grant/revoke appended to
  `/var/log/secubox/audit.log` (append-only, CSPN).

## 8. Testing
- **macroctl:** kind allowlist (reject `../x`, unknown, bad pattern); plugin
  ownership/mode tamper guard; `src-ip` ∈ mesh check; grant stdout JSON parsed;
  audit line written. nft/exec mocked in unit tests.
- **tor-exit plugin:** grant emits the correct endpoint JSON + the expected nft
  set-add (captured via a fake `nft` on PATH); revoke does the symmetric remove;
  both idempotent.
- **annuaire:** `macro` descriptor round-trips through sign→serve→ingest
  (federation preserves it); offers without `macro` still validate.
- **p2p:** the grant endpoint returns 403 unless the presented Subscription
  signature verifies (self-cert) AND its service_id matches AND the local offer
  is `auto`; on success it calls macroctl grant (with the provider-observed mesh
  source IP) and returns the credential; a tampered/wrong-DID Subscription, a
  mismatched service_id, and a `pending` offer are each rejected. activate pulls
  + calls macroctl activate + records state; revoke-access calls macroctl revoke.
- **live (gk2 ↔ c3box):** gk2 offers tor-exit; c3box subscribes; gk2 approves;
  c3box activates → pulls → gk2 nft-allows c3box's mesh IP to :9050; verify
  c3box can reach `10.10.0.1:9050`; revoke removes the allow.

## 9. Decomposition note
This is one focused increment (framework + `tor-exit`). Subsequent kinds
(`wg-relay`, `dns-resolver`, `http-mirror`) are independent follow-up specs, each
shipping a vetted `macros.d/<kind>` plugin + AppArmor profile against this same
framework — no further changes to macroctl/annuaire/p2p expected.

## 10. Open questions
- **OQ-1 (Subscription-as-capability + pending mode):** increment 1 authorizes a
  grant from the consumer's self-signed Subscription + an `auto` offer, with no
  federated approval state. This makes the Subscription a replayable bearer
  capability, bounded because a grant only nft-allows the request's own mesh
  source IP (replay buys nothing). If stronger binding is wanted, add a
  provider-nonce challenge (sign nonce+service_id) before shipping. Supporting
  `pending`-mode macro offers requires cross-node subscription/approval
  federation (federate Subscription + SERVICE_APPROVE events, or a provider-side
  approval pull) — a separate follow-up, not this increment.
- **OQ-2 (SocksPort binding):** the provider binds Tor SocksPort to its wg-mesh
  IP. If a board runs Tor for other purposes, the macro adds a *dedicated*
  SocksPort line in its own torrc.d file rather than touching the existing one.
