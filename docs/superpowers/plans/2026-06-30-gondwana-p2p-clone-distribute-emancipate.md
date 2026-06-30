# Gondwana P2P — Clone · Distribute · Emancipate (consolidated roadmap)

**Date:** 2026-06-30
**Status:** Roadmap (consolidation of gondwana Phases 2–4 for the "make secubox.in P2P" goal)
**Scope:** Tie the *already-built* transport (Phase 1) and the *already-built*
trust ledger (`secubox-annuaire`) into one distributed appliance — config &
service distribution, redundancy, multi-node access, multi-peer backup, and
mesh/Tor egress — **without inventing a new architecture** and **without
breaking the existing module pattern**.

This plan supersedes nothing: it is the bridge that wires together
`2026-06-29-gondwana-phase1-mesh-substrate-design.md` (transport, DONE),
`2026-06-30-annuaire-miroir-trust-substrate-design.md` (the ledger/directory),
and `2026-06-29-secubox-appstore-module-manager-sketch.md` (the federated
distribution UX). Each is grounded in a code audit (2026-06-30).

---

## 0. Verdict & invariants

**Feasible, incrementally, and most of the substrate already exists.** The hard
distributed-systems part is deliberately scoped *out* of v1.

**Non-negotiable invariants (these keep it simple and compatible):**

1. **Federation of sovereign nodes, not a cluster.** No leader election, no
   consensus protocol. CAP → choose **AP** (availability + partition
   tolerance) + **eventual consistency**.
2. **Single-writer per service + failover.** Each service has a *home* node
   that writes; other nodes are read replicas / standby. No active-active
   stateful writes in v1.
3. **The ledger is the directory.** Shared mesh state (peers, services,
   config, names) lives in the `secubox-annuaire` append-only signed log,
   replicated by pull-gossip. Per-node JSON registries stay as the local cache.
4. **Secrets never leave the node.** `/etc/secubox/secrets/*` is node-local;
   each node generates its own. Sync moves *config & data*, never secrets.
5. **Unprivileged API + root helper.** The FastAPI runs as `secubox`
   (NoNewPrivileges); privileged verbs go through a `sbx-*` root CLI + narrow
   sudoers or a root job-queue (proven by `sbx-mesh-up`, `<mod>ctl`).
6. **CSPN discipline.** Config writes go through the 4R double-buffer
   (shadow → validate → atomic swap → rollback); every distributed action is
   appended to `/var/log/secubox/audit.log`; **no `waf_bypass`** — every
   exposed vhost still routes through HAProxy → mitmproxy_inspector.

**User-facing grammar (the four verbs):**

| Verb | Meaning | Built on |
|------|---------|----------|
| **CLONE** | bring up a fresh node, identity-ready | image build + `node.id` + wg keypair |
| **JOIN** | enrol into the mesh + receive the directory | `master-link` (DONE) + directory pull |
| **DISTRIBUTE** | replicate config / packages / (opt.) data to peers | annuaire ledger + apt mirror + backup |
| **EMANCIPATE** | serve/expose a service from a peer or outward | `secubox-exposure` (Peek/Poke/Emancipate) made mesh-aware |

---

## 1. The linchpin — marry `p2p` registries to the `annuaire` ledger

This single bridge unlocks everything downstream. It is the concrete form of
the gondwana §8 "distributed directory (DNS-structured ledger)".

**Today (audited):**
- `secubox-p2p` holds peers in local JSON (`/var/lib/secubox/p2p/wg_mesh.json`,
  `peers.json`, `master-link/*.json`) — *not replicated*.
- `secubox-annuaire` is a signed, append-only, **replicable** log with
  `did:plc` identities, a `ServiceOffer/Subscription` model, a `can()`
  authorization resolver, and **pull federation** (`POST /services/pull` →
  fetch a peer's `/services` → verify Ed25519 sig → ingest).

**The bridge (minimal additions to annuaire):**
- New payload type `NodeRecord` `{did, node_id, boxname, pubkey_wg, mesh_ip,
  ddns, endpoint?}` — the Phase-1 identity `(pubkey, node-id, boxname, DDNS)`
  becomes a signed ledger record (gondwana Phase 2 "identity records").
- New payload type `ConfigBlob` `{config_id, publisher_did, scope, version,
  content_hash, payload|payload_uri, valid_from, valid_until?}` +
  `Op.CONFIG_PUBLISH / CONFIG_REVOKE`.
- Generalize pull federation from `/services` to the whole `/log` (verify each
  entry's sig before append, dedup by `entry_hash`, last-writer-wins per id).
- Extend `can()` rights with `config.publish` (already has `service.publish`,
  `name.bind`).

**The bridge (minimal additions to p2p):**
- On `wireguard/enable` and on join, publish this node's `NodeRecord` into the
  local annuaire log.
- A thin **`sbx-dir-sync`** loop (systemd timer, runs as `secubox`) pulls each
  peer's annuaire `/log` over the wg-mesh and ingests — the gossip layer.
  Reuses the existing verify-then-append path; no new crypto.

**Result:** every node holds the same signed directory of *who exists, what
they run, what config is current, and what name resolves where* — eventually
consistent, partition-tolerant, offline-verifiable.

---

## 2. Architecture (one picture)

```
                          ┌────────────────────────────────────────────┐
   CONTROL PLANE          │   secubox-annuaire  (signed append-only log) │
   (the directory)        │   peers · services · ConfigBlobs · names     │
                          └──────────────▲───────────────▲──────────────┘
                                         │ pull-gossip    │ publish
                          ┌──────────────┴───────┐ ┌──────┴───────────────┐
                          │ sbx-dir-sync (timer)  │ │ p2p / exposure / etc │
                          └───────────────────────┘ └──────────────────────┘
   ──────────────────────────────────────────────────────────────────────
   DATA PLANE     wg-mesh 10.10.0.0/24:51822   (secubox-p2p, DONE)
                  gk2 .1 (public ingress) ── c3box .2 ── amd64 .3 ── …
   ┌───────────┐  ┌────────────┐  ┌──────────────┐  ┌───────────────────┐
   │ apt mirror│  │ backup→peer│  │ HAProxy/nginx │  │ exposure / tor    │
   │ (P2P)     │  │ (restic)   │  │ mesh upstream │  │ mesh + relay egress│
   └───────────┘  └────────────┘  └──────────────┘  └───────────────────┘
```

- **Control plane** = annuaire ledger, replicated by pull-gossip (small, signed,
  eventually consistent).
- **Data plane** = wg-mesh transport (done) carrying everything: apt deltas,
  backups, service traffic (`<service>.<boxname>.secubox.in` hub-routed),
  egress.

---

## 3. Workstreams (each shippable on its own)

### WS-A — Directory (the substrate) · gondwana Phase 2 (identity records)
- annuaire: `NodeRecord` + `ConfigBlob` payload types; generalized `/log`
  pull; `config.publish` right. (~150 LoC, additive, back-compatible.)
- p2p: publish `NodeRecord` on enable/join; `sbx-dir-sync` timer pulling peers
  over wg-mesh. (~150 LoC + 1 timer unit.)
- **Ships:** every node holds a signed, replicated peer+service directory.

### WS-B — Config distribution · DISTRIBUTE(config)
- A `[mesh]` block added (additively) to module TOMLs:
  `role = primary|replica|gateway`, `sync = none|config|config+data`.
- Primary signs a `ConfigBlob(scope=<module>, version, payload)` → annuaire.
  Replicas pull → write `/etc/secubox/<m>.toml` **via the 4R double-buffer**
  (shadow → validate → atomic swap → rollback). Conffile rule respected
  (never clobber an operator edit without the new version winning by signed
  `version`); secrets excluded.
- Lives either in `secubox-p2p` or a thin new `secubox-mesh-sync` module
  (canonical skeleton). **Decision in §6.**
- **Ships:** edit config on the primary → propagates signed, with rollback.

### WS-C — Package / app distribution · DISTRIBUTE(software) + CLONE-ready
- **P2P-mirrored apt** (appstore §7): each node holds a **GPG-signed** mirror
  of `apt.secubox.in`, synced over wg-mesh (rsync / content-addressed deltas).
  Install source preference: **local → mesh-peer → upstream gk2/public**.
  Verify `InRelease`; never trust an unsigned peer mirror.
- **Federated catalog:** the `secubox-appstore` reads the 128 `debian/
  secubox.yaml` manifests + the directory → mesh-wide view ("install here" vs
  "running on c3box"). The directory's first big consumer.
- **Ships:** install a module from the nearest mirror; the repo survives gk2
  being offline (access redundancy).

### WS-D — Data replication + multi-peer backup · DISTRIBUTE(data, opt.)
- `secubox-backup` (already does tar + S3/SFTP + age/gpg + retention) gains a
  **`peer` remote type** = restic/scp over wg-mesh to `10.10.0.x`. Each node
  cross-backs-up to ≥1 peer. (~50 LoC, reuses the remote framework.)
- Opt-in live replicas per service (single-writer): SQLite → litestream /
  periodic snapshot pull (LXC snapshot or quiesced tar); Postgres (peertube)
  → standard streaming replica, 1 primary.
- **Ships:** multi-peer backups (cheap, high value); per-service read replicas
  where wanted.

### WS-E — Routing: LB, failover, multi-node browsing · USABLE
- Make HAProxy/nginx upstreams **directory-driven**: a generator reads the
  directory (who-runs-what + health) and renders upstreams that point at the
  owning node **over the wg-mesh** (`10.10.0.x`) instead of only `127.0.0.1`.
  This is today's #1 gap (all upstreams are localhost-hardcoded).
- Per-node naming `<service>.<boxname>.secubox.in` → DNS to gk2 (sole public
  ingress) → HAProxy routes by `Host:` over the mesh to the owner (gondwana
  Phase 4). Read-LB across replicas; dead home → failover to a replica.
  **mitmproxy_inspector stays in path (no waf_bypass).**
- **Ships:** any client reaches any service from any node; failover; read-LB.

### WS-F — Egress / Emancipate · EMANCIPATE
- `secubox-exposure` already implements Peek/Poke/**Emancipate** with Tor +
  DNS/SSL real and a **Mesh channel that is currently a stub**. Make the Mesh
  channel real: emancipating publishes a `ServiceOffer` into the directory and
  wires HAProxy/mitmproxy to route to it over the mesh.
- **Relay egress:** `secubox-tor` (real hidden-service lifecycle) gains a
  *relay* advertisement in the directory; a node can route its egress through
  a peer's Tor/relay → gateway redundancy. Alternative relays
  (yggdrasil / i2p / snowflake) slot in later as additional channels.
- **Ships:** emancipate a service to the mesh and/or outward (Tor/relay),
  multi-channel, from any node.

---

## 4. The minimal additions (the whole "new code" budget)

| Component | Addition | Size | Risk |
|-----------|----------|------|------|
| annuaire | `NodeRecord`+`ConfigBlob` types, `/log` pull, `config.publish` | ~150 LoC | low (additive) |
| p2p | publish NodeRecord, `sbx-dir-sync` timer | ~150 LoC | low |
| mesh-sync / p2p | `[mesh]` role field, config apply via 4R | ~120 LoC | medium (writes /etc) |
| backup | `peer` remote type (restic over wg) | ~50 LoC | low |
| exposure | real Mesh channel (publish + route) | ~100 LoC | medium |
| haproxy/nginx | directory-driven upstream generator | **biggest piece** | medium-high |
| appstore | federated catalog + P2P apt mirror | own workstream | medium |

Everything else is configuration and reuse. No new daemon paradigm; no new
crypto; no consensus engine.

---

## 5. Sequencing (incremental — each step is useful alone)

- **P0 — Unblock remote peers (operator, ~5 min):** Freebox UDP `51822 →
  192.168.1.200` forward. Until then the mesh joins only from the LAN.
- **P1 — Directory (WS-A):** the substrate everything consumes. *First.*
- **P2 — Config distribution (WS-B):** biggest ROI / lowest risk write path.
- **P3 — Backup-to-peers (WS-D, backups only):** cheap, high value, no service
  impact.
- **P4 — Mesh-aware routing (WS-E):** LB + failover + per-node naming → the
  "usable" multi-node experience.
- **P5 — P2P apt + federated appstore (WS-C):** distribution + access
  redundancy of the repo itself.
- **P6 — Emancipate (WS-F):** real mesh exposure + relay egress.
- **P7 (deferred, hard):** stateful active-active, ZKP/HamCoin (gondwana
  Phase 2 GK-HAM is its own track), conflict auto-heal. **Out of v1.**

---

## 6. Open decisions (for the user)

1. **mesh-sync home:** new `secubox-mesh-sync` package, or fold the sync
   loop + `[mesh]` field into `secubox-p2p`? *(Recommend: fold into p2p — it
   already owns the mesh + registries; fewer moving parts.)*
2. **Granularity first:** sovereign core only (annuaire, dns, hub, p2p
   redundant among themselves), or all services from the start? *(Recommend:
   sovereign core first.)*
3. **Config-only vs config+data in v1:** *(Recommend: config-only + backups;
   data replicas opt-in per service after P4.)*
4. **Active-active:** confirm we hold the line at single-writer + failover for
   v1 (and if any one service truly needs active-active, name it).
5. **Per-node DNS authorship (Phase 4 open question, inherited):** gk2 as an
   authoritative `*.secubox.in` zone vs a registrar/provider API.

---

## 7. Landmines (from the audits — the plan must respect these)

- **`/run/secubox` socket wipe:** any new unit needs
  `RuntimeDirectory=secubox` + `RuntimeDirectoryPreserve=yes`; never chown the
  shared parent (1777 / 0755).
- **Traversal perms:** `/var/lib/secubox` parent stays `0755`,
  `/var/log/secubox` stays `0755`; leaves may be `0750`.
- **Conffile handling:** the sync must not fight dpkg — a hand-edited
  `/etc/secubox/*.toml` plus a package upgrade prompts non-interactively and
  aborts; signed `version` ordering decides the winner, applied via 4R.
- **Secrets non-transmission:** `/etc/secubox/secrets/*` never syncs.
- **LXC consistency:** quiesce/snapshot before pulling container data.
- **gk2 SPOF:** single public ingress until Phase 4 hub-HA; document it.
- **Federation semantics:** pull-only, last-writer-wins, no auto-heal — fine
  under single-writer; surprising under concurrent writers (which we forbid).

---

## 8. Success criteria — what "clonable, distributable, emancipable, usable" means

1. **Clone:** a fresh node boots, gets a stable `node.id` + wg keypair.
2. **Join:** `sbx-mesh-join <rendezvous> <token>` → handshake + receives the
   signed directory.
3. **Distribute:** the node receives current signed config (4R-applied) and can
   install modules from the nearest signed mirror; **gk2 offline → installs and
   already-running services still work.**
4. **Backup:** the node cross-backs-up to ≥1 peer and can restore from one.
5. **Use:** any LAN client reaches any mesh service via
   `<service>.<boxname>.secubox.in`; a dead home service fails over to a
   replica; read traffic balances across replicas.
6. **Emancipate:** any node can expose a service to the mesh and/or outward
   (Tor / relay), multi-channel, through the WAF.
7. **All in source;** a fresh image reproduces a node that does the above.
