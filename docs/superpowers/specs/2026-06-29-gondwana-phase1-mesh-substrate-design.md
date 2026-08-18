<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Gondwana Phase 1 — Mesh Transport + Node Identity (Substrate)

**Date:** 2026-06-29
**Status:** Design approved — pending spec review → implementation plan
**Scope:** Phase 1 of the gondwana program (substrate only). Phases 2–4 are
out of scope here and get their own spec → plan → build cycles.

---

## 1. Context & problem

SecuBox now runs on three nodes that should form one mesh ("gondwana"):

| Node  | Role            | Address              | Notes |
|-------|-----------------|----------------------|-------|
| gk2   | master / public hub | 192.168.1.200 (WAN via Freebox, public 82.67.100.75) | only node with a stable public ingress |
| c3box | reference (mochabin) | 192.168.1.94 (currently offline) | satellite |
| amd64 | live-USB        | 192.168.1.9          | satellite, ephemeral medium |

Goal of the wider program: **service mirroring/redundancy, redundant access,
and (above all) shared protections** across nodes, with a **zero-trust
GK-HAM ZKP** trust model (#762) as the target.

That program layers on a transport+identity substrate that does not cleanly
exist today. Two concrete defects block everything else:

1. **Two half-systems.** The live mesh is a hand-rolled `wg-quick` interface
   (`wg-mesh`, `10.10.0.0/24`, UDP `51822`, gk2=`.1` ↔ c3box=`.2`) created
   *outside* `secubox-p2p`. Meanwhile `secubox-p2p` has its own WireGuard
   provisioning code that is dormant and reports `enabled=false, 0 peers`.
2. **Subnet collision.** `secubox-p2p`'s WireGuard default network is
   `10.100.0.0/24` — **identical to the `br-lxc` LXC bridge**. If the p2p
   layer ever brought up its interface on the default, it would collide with
   every LXC (Lyrion, mail, mqtt, grafana, …). This is a primary reason the
   MirrorNet layer never took over the mesh.

Phase 1 makes "the live mesh" and "the MirrorNet layer" the **same thing**,
on a collision-free subnet, reachable multi-site, with a persistent
per-node identity that Phase 2 (ZKP/did:plc) will wrap.

### Decisions locked during brainstorming
- **Topology:** multi-site distributed (nodes on different sites/links).
- **Trust target:** zero-trust GK-HAM (#762) — but implemented in Phase 2;
  Phase 1 keeps the existing plain-auth join behind the same interface.
- **Rendezvous:** gk2 exposed via a **dedicated Freebox UDP `51822 → .200`**
  forward (separate from the toolbox VPN on 51820).
- **Rendezvous is a ROLE, not a hardwired hub (revised 2026-06-29).** Any
  node may hold the rendezvous role; the *active* rendezvous is whichever
  node is currently publicly reachable. Today only gk2 has a public ingress,
  so gk2 is the active rendezvous — but config/code must not hardwire "gk2
  is the master." Each node also carries a **DDNS name as part of its
  identity** (`<boxname>.secubox.in`), so reachability is name-based and the
  rendezvous can float later without reconfiguring peers. Phase 1 builds
  only this forward-compatibility; availability-based failover between
  multiple rendezvous nodes is Phase 4 (hub HA), and the shared state moving
  to a distributed ledger is Phase 2/3 (see §8).
- **Approach:** make `secubox-p2p` the mesh owner (vs. keep-wg-quick, vs. new
  daemon). "Owner" = the component that provisions WireGuard and holds the
  peer registry; the registry is **local-first/replicable**, not a
  gk2-exclusive source of truth, so it can migrate to the Phase-2/3 ledger.

---

## 2. Addressing model

- **Mesh subnet: `10.10.0.0/24`** (keep the interim subnet; already live and
  collision-free).
- **Hard collision guard:** the mesh subnet MUST NOT overlap `br-lxc`
  (10.100.0.0/24), `eye-br0` (10.55.0.0/24), `lxcbr0` (10.0.3.0/24), or
  `wg-toolbox` (10.99.0.0/24). The provisioner refuses to enable on overlap.
- **Allocation: master-assigned, deterministic.** gk2 = `10.10.0.1` (fixed
  master). Satellites are assigned the next free `.2–.254` *by gk2 at join*
  and recorded in gk2's peer registry. (Replaces the current
  hash-from-node-id scheme, which can silently collide.) c3box stays `.2`,
  amd64 becomes `.3`.

## 3. Identity model

- Each node owns a persistent **WireGuard keypair + stable `node-id`** under
  `/var/lib/secubox/p2p/`:
  - `wg_mesh.json` — holds the private key, `0600 secubox:secubox`.
  - `node.id` — stable node identifier.
- `(pubkey, node-id)` **is** the Phase-1 identity; Phase 2 GK-HAM ZKP /
  did:plc wraps it rather than replacing it.
- **Live-USB caveat (amd64):** identity is persisted on the persistence
  partition so it survives reboot. If absent, the node re-enrolls fresh and
  gk2 dedupes the stale peer entry by hostname.

## 4. Topology & routing — hub-and-spoke via gk2

- **gk2 (hub):** listens `:51822`; public `Endpoint = <gk2-public>:51822`.
  One `[Peer]` per satellite with `AllowedIPs = 10.10.0.<n>/32` and **no**
  Endpoint (learned from each satellite's handshake → roaming; nomadic amd64
  works with no reconfig).
- **Satellites (spokes):** a single `[Peer]` = gk2, `AllowedIPs =
  10.10.0.0/24`, `PersistentKeepalive = 25` (holds the NAT hole open).
- **Inter-satellite traffic** (e.g. threatmesh gossip c3box↔amd64) routes
  **through gk2**: spoke → `10.10.0.0/24` → gk2 → forward → other spoke.
  gk2 already has `ip_forward=1` and nftables `forward policy accept`, so the
  hairpin needs no new rule.
- Same-LAN nodes may later get direct peer entries as an optimization; the
  uniform baseline is hub-routed (correct behind any NAT).

---

## 5. secubox-p2p changes (the single reconciling change)

- **Config** — new `/etc/secubox/p2p.toml [wireguard]`:
  `interface="wg-mesh"`, `listen_port=51822`, `network="10.10.0.0/24"`,
  `role="master"|"satellite"`, `master_endpoint="<gk2-public>:51822"`
  (satellites only). Code defaults change `51820→51822` and
  `10.100.0.0/24→10.10.0.0/24`.
  - **`master_endpoint` is a free-form host:port** — it accepts either a
    DDNS hostname (future-proofing against a changing WAN IP) or a literal
    IP. WireGuard re-resolves a hostname on each handshake, so a DDNS name
    survives IP changes with no reconfig. **Current deployment pins the
    literal public IP: `82.67.100.75:51822`**; switching to a DDNS name is a
    one-line config change later.
- **Adoption (critical for zero cutover):** on enable, if
  `/etc/wireguard/wg-mesh.conf` already exists with the same subnet/port,
  **import its existing private key** into `wg_mesh.json` so the public key
  is unchanged → the gk2↔c3box handshake survives. Never regenerate a key
  when a valid one exists.
- **Provisioning:** `/wireguard/enable` (re)writes a standard `wg-quick`
  `wg-mesh.conf` from config + peer registry and `wg-quick up`s it
  idempotently. `/wireguard/peer` adds/removes a `[Peer]`.
- **Collision guard:** refuse to enable if `network` overlaps the bridges in
  §2.
- **Join wiring:** `master-link/join` assigns the next free `10.10.0.x`,
  returns it plus gk2's pubkey/endpoint, and adds the peer on both ends.
  Plain-auth for now; Phase 2 swaps in ZKP behind this same interface.

---

## 6. Cutover plan — zero disruption, in order

1. **gk2:** import the live `wg-mesh` private key into p2p state; set
   `role=master`, `10.10.0.0/24:51822`; switch to p2p-managed. Generated conf
   ≡ current conf → **c3box handshake preserved**.
2. **Freebox:** add UDP `51822 → 192.168.1.200` (operator action; until then
   satellites join only from the LAN).
3. **amd64 (.9):** generate identity → gk2 issues join (`.3`) → peer added
   both sides → satellite brings up `wg-mesh` with `Endpoint=<gk2-public>:51822`.
4. **Verify:** handshakes on all three; `10.10.0.1 ↔ .2 ↔ .3` ping through
   the hub; threatmesh `:8780` reachable spoke-to-spoke.
5. **Backport:** every step lands in source (p2p.toml defaults, provisioning,
   guard) — no live-only drift.

---

## 7. Failure modes & mitigations

| Failure | Mitigation |
|---------|------------|
| Key regenerated on adopt → breaks c3box | Import-or-keep existing privkey; never regen if a valid key exists |
| Subnet regression (overlap br-lxc etc.) | Collision guard refuses to start |
| gk2 (hub) down | Already-handshaked spokes keep roaming on last endpoint; *new* joins blocked (accepted for Phase 1; Phase 4 adds HA) |
| amd64 live-USB wiped | Re-enroll fresh; gk2 dedupes stale peer by hostname |
| NAT hole closes | `PersistentKeepalive=25` on spokes |

---

## 8. Out of scope (later phases)

- **Cross-cutting — Distributed directory (DNS-structured ledger, requested
  2026-06-29).** Shared mesh state (peers, services, threat-intel, name
  records) migrates from per-node JSON registries to a replicated,
  append-only, hierarchically-named directory every node holds — a
  blockchain/DID-style ledger "like DNS." This is the concrete form of the
  CLAUDE.md `did:plc` + "Chain of Hamiltonians → HamCoin" intent. It is the
  data-plane substrate for Phases 2–4 (identity records in P2, threat
  records in P3, name records in P4). Phase 1 keeps the registry
  **local-first/replicable** specifically so it can be backed by this ledger
  later without reworking the transport.
- **Phase 2** — GK-HAM ZKP enrollment (#762): hamiltonian ZKP join, did:plc
  identity, auto-discover / magic-invite over wg. Each node's
  `(pubkey, node-id, boxname)` from Phase 1 becomes its ledger identity
  record.
- **Phase 3** — Zero-trust protection sharing: signed threatmesh gossip,
  N-source consensus, peer-identity-gated ingestion, WAF-rule sharing.
- **Phase 4** — Service mirroring + access redundancy: service replication,
  multi-endpoint failover (DNS / HAProxy), hub HA.
  - **Auto-registration + per-node naming (requested 2026-06-29):** each
    node registers itself with the central `secubox.in` and automatically
    gets vhosts published as `<service>.<boxname>.secubox.in`. Architecture
    that falls out of Phase 1: DNS for `*.<boxname>.secubox.in` resolves to
    **gk2's public IP** (the only public ingress; satellites are behind
    NAT); gk2's HAProxy/mitmproxy routes by `Host:` **over the wg-mesh** to
    the owning node's service. Consumes the Phase-1 node identity
    (`boxname`/`node-id`) + mesh transport. **Open question for Phase 4
    design:** how `*.secubox.in` DNS records are authored — gk2 as an
    authoritative zone vs. a registrar/provider API. Must keep the
    no-waf_bypass rule (every published vhost routes through
    mitmproxy_inspector).

## 9. Success criteria (Phase 1)

1. `secubox-p2p` reports the mesh as enabled with the real peers (no more
   `enabled=false, 0 peers`); `/wireguard` truth matches `wg show wg-mesh`.
2. No subnet overlaps any bridge; collision guard proven to refuse a bad
   subnet.
3. gk2↔c3box handshake uninterrupted across cutover (same keys).
4. amd64 (`.3`) joins via the master flow and reaches `.1` and `.2`.
5. All changes present in source; a fresh install reproduces the topology.
