<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-p2p evolutions — Kademlia DHT + master-link + federation health-checks — Design

*2026-07-02 · CyberMind / SecuBox-Deb · module `secubox-p2p` · GitHub issue #774 · branch `feature/p2p-dht-federation`*

## Problem

`secubox-p2p` today discovers peers via mDNS + a managed WireGuard mesh
(`api/mesh.py`, `wg-mesh` / `10.10.0.0/24` / udp `51822`) and federates services
through the **secubox-annuaire signed ledger** (`api/registry.py` +
`api/annuaire_client.py`, issue #766 done). Three gaps remain (issue #774):

1. **Peer discovery is subnet-bound** — mDNS does not cross NAT/subnets, and there
   is no resilient, decentralized way to find a peer's current WireGuard endpoint
   before joining the mesh. This is the "discover" step of the zero-touch
   auto-enrollment flow (#762: discover → GK-HAM ZKP → WireGuard → master-link).
2. **No liveness on federated services** — the annuaire catalog says a service
   *exists*, not whether it is *up*. No periodic distributed health-checks (#766
   shipped without them).
3. **Flat topology** — full mesh only; no master/satellite hierarchy with
   election/failover (aligns #762).

## Goal

Add, on the existing base (never reinventing mesh/registry/annuaire):
1. A **custom minimal Kademlia DHT** (`api/dht.py`) for resilient cross-NAT peer
   discovery; keys = node DID hash, values = signed `{wg_pubkey, endpoint}`.
2. **Federation health-checks** (`api/federation.py`) layered over the annuaire
   federation: periodic liveness probes + status propagation.
3. A **hierarchical master-link** (`api/masterlink.py`): master/satellite roles,
   heartbeat, deterministic election + automatic failover.
Plus API endpoints in `api/main.py` and TDD tests.

## Non-goals (avoid duplication)
- NOT a second service catalog — the annuaire ledger (#768) stays the catalog; the
  DHT only maps node-id → reachability.
- NOT re-implementing federation registration (#766 done) — only add health-checks.
- NO libp2p, NO standalone aiohttp servers (the reverted attempt's mistake).

## Global Constraints
- **Import convention:** module code uses `from . import mesh, registry, annuaire_client` (as `api/main.py` does); tests use `from api import dht` etc. via `tests/conftest.py` (adds package root to `sys.path`). NEVER `secubox.p2p.api.*` (that was the reverted bug).
- **Minimal deps:** stdlib `asyncio` + existing deps only (`aiohttp` already present). No new heavy dependency. Kademlia is pure-Python over asyncio UDP (`asyncio.DatagramProtocol`).
- **Paths:** state under `P2P_DIR = /var/lib/secubox/p2p` (already used); config in `/etc/secubox/p2p.toml` (extend with `[dht]`, `[federation]`, `[masterlink]` sections; `api/mesh.py:load_p2p_config` is the reader pattern). Node identity fingerprint at `/var/lib/secubox/p2p/node.id`.
- **Mesh facts (verbatim):** interface `wg-mesh`, udp port `51822`, network `10.10.0.0/24` (`api/mesh.py:16-18`). DHT uses its **own** udp port (`[dht].port`, default `51823`) so it does not collide with WireGuard.
- **Annuaire:** reach it ONLY via `annuaire_client` (`/run/secubox/annuaire.sock`); DIDs via `annuaire_client.did_from_pubkey_hex` / `node_identity`.
- **OPAD:** passive by default; any active probe (health-checks, DHT announce of *others*) is opt-in via config flags; every security-relevant action (announce, promote, failover) is logged (`logging.getLogger("secubox.p2p")`) and appended to the audit trail `/var/log/secubox/p2p-audit.log` (append-only, one JSON object per line).
- **Auth:** mutating API endpoints require JWT via `secubox_core.auth.require_jwt` (matching `api/main.py`); read endpoints may be node-local.
- **Secrets / integrity:** DHT stored values are **signed** by the announcing node's key and **verified** on read (reject unsigned/invalid — prevents endpoint spoofing). No private keys in DHT. Persistence files `chmod 0600` owner the p2p service user.
- **License header** `LicenseRef-CMSD-1.0` on every new file.

---

## Component 1 — Kademlia DHT (`api/dht.py`)

**Responsibility:** decentralized node-reachability lookup. One clear unit; no HTTP server of its own — the UDP protocol + an in-process async API consumed by `main.py`.

### Identity & keys
- Node ID = 160-bit = `SHA1(did)` where `did = annuaire_client.did_from_pubkey_hex(wg_pubkey_hex)` (stable per node). XOR metric over 160-bit space (classic Kademlia).
- Stored record: key = `SHA1(did_target)`, value = JSON `{"did":…, "wg_pubkey":…, "endpoint":"host:port", "ts":…, "sig":…}` where `sig` = node's signature over the canonical `{did,wg_pubkey,endpoint,ts}`. Readers verify `sig` against `wg_pubkey`→`did` (`did_from_pubkey_hex` must equal `did`) before trusting.

### Structures
- `DHTNode(node_id: bytes, did: str, endpoint: tuple[str,int], last_seen: float)` — a contact.
- `DHTBucket` — a k-bucket (k = `KAD_K`, default 20): bounded deque of `DHTNode`, LRU eviction with liveness ping of the LRU before dropping.
- `RoutingTable` — 160 buckets indexed by XOR-distance prefix; `insert(node)`, `closest(target_id, count)`.
- `DHTNetwork` — owns the routing table, the UDP protocol, the local value store (`dict[bytes, dict]` with TTL `DHT_TTL` default 3600s), and the async RPC API.

### Wire protocol (UDP, JSON — NOT bencode, to avoid an injection-prone parser)
Datagram = JSON `{"t": <type>, "rpc_id": <hex>, "sender": {node_id_hex, did, endpoint}, ...}`.
Types: `ping`/`pong`, `find_node`(target_id)→`nodes`([contacts]), `find_value`(key)→`value`|`nodes`, `store`(key,value)→`ok`. Each request has a random `rpc_id`; responses echo it; a `pending: dict[rpc_id, Future]` resolves with `asyncio.wait_for(..., RPC_TIMEOUT=5s)`.
- **Hardening:** cap datagram size (`MAX_DGRAM=8192`, drop larger); validate every field type before use; ignore malformed JSON silently (log at debug); rate-limit per source IP (`token bucket`, `[dht].rps` default 50) to blunt amplification/DoS.

### Operations
- `bootstrap()`: seed the routing table from `[dht].bootstrap` endpoints AND from annuaire node records (`annuaire_client.get_catalog` → nodes with `endpoint`), then run an iterative `find_node(self_id)` to fill buckets.
- `iterative_find(target, mode)`: classic Kademlia α-parallel (`KAD_ALPHA`=3) lookup; returns k closest (mode=node) or the value (mode=value).
- `announce()`: `store(self_key, signed_self_record)` to the k closest nodes to `self_key`. Opt-in re-announce loop every `[dht].announce_interval` (default 900s) as an `asyncio.Task`.
- `find_peer(did) -> record | None`: `iterative_find(SHA1(did), value)`, verify `sig`, return record.
- **Persistence:** on shutdown/periodically, dump routing-table contacts to `P2P_DIR/dht-routing.json` (0600); reload on startup as bootstrap hints.

### Constants (module-level, tested)
`KAD_K=20`, `KAD_ALPHA=3`, `KAD_ID_BITS=160`, `RPC_TIMEOUT=5.0`, `PEER_TIMEOUT=900`, `DHT_TTL=3600`, `DHT_PORT=51823`, `MAX_DGRAM=8192`.

### OPAD
DHT runs passively (answers queries, maintains buckets) by default. `announce()` (publishing our own reachability) is gated by `[dht].announce = true` (opt-in). We never store records *about other nodes*. Every `store` accepted/rejected and every `announce` is audit-logged.

---

## Component 2 — Federation health-checks (`api/federation.py`)

**Responsibility:** liveness over the annuaire-federated services; does NOT own the catalog (that's the annuaire) nor registration (#766).

- `HealthChecker(interval=[federation].interval default 30s)`: an `asyncio.Task` that, each tick, pulls the current federated services via `registry.merge_services(annuaire_client.get_catalog(), annuaire_client.get_subscriptions(), …)`, and for each service with a reachable endpoint performs a **bounded** probe:
  - transport-appropriate: HTTP(S) `GET <health_path>` (default `/health`) with `aiohttp`, `timeout=[federation].probe_timeout` default 5s; TCP-connect fallback when no health path.
  - concurrency-capped with an `asyncio.Semaphore([federation].max_concurrency default 20)` so 1000 services don't fan out unbounded (perf criterion).
- `HealthStore`: in-memory `dict[service_id, {status: up|down|unknown, latency_ms, last_ok, last_check, consecutive_failures}]`, persisted to `P2P_DIR/federation-health.json` (0600). Status flips to `down` only after `[federation].fail_threshold` (default 3) consecutive failures (debounce).
- **Propagation:** health status is published into the DHT under `SHA1("health:"+service_id)` (signed), so peers can read cross-node liveness without probing themselves — reuses Component 1, no new transport.
- **OPAD:** health-checking is an *active* probe → opt-in via `[federation].health_checks = true` (default false; passive until consented). Every probe batch summarized to the audit log.
- **API-consumed accessors:** `get_services_with_health() -> list[dict]`, `status_of(service_id) -> dict`.

---

## Component 3 — Hierarchical master-link (`api/masterlink.py`)

**Responsibility:** master/satellite topology + election + failover over the existing mesh peers. Aligns #762.

- Roles: `MASTER`, `SATELLITE`, `CANDIDATE` (enum). Node config `[masterlink].role_preference` (auto|master|satellite).
- **Deterministic election** (no split-brain): among live mesh peers, the master is the node with the lowest `(priority, node_id_hex)` tuple where `priority` = `[masterlink].priority` (default 100; lower wins) — ties broken by node_id. Election is a pure function `elect(peers) -> node_id` (unit-testable, no I/O).
- **Heartbeat:** master multicasts a signed `heartbeat{term, master_id, ts}` to satellites over the mesh (UDP on `[masterlink].port` default 51824, or piggy-backed on DHT ping) every `[masterlink].heartbeat_interval` (default 5s). `term` is a monotonically increasing integer persisted at `P2P_DIR/masterlink-term` — a new election increments it; higher term wins (Raft-style, prevents stale masters).
- **Failover:** a satellite that misses `[masterlink].election_timeout / heartbeat_interval` (default election_timeout=15s) heartbeats becomes `CANDIDATE`, increments term, runs `elect()` over the peers it can see, and if it wins announces itself master. Convergence target < election_timeout.
- **Topology view:** `topology() -> {master, satellites:[…], term, self_role}` built from mesh peers (`mesh` helpers) + last-seen heartbeats.
- **OPAD/security:** promotion/demotion/failover are security-relevant → JWT-gated on the API, signed on the wire, and audit-logged with term + reason. A manual `promote(node_id)` respects term monotonicity.

---

## API endpoints (`api/main.py`, prefix `/api/v1/p2p`)
Matching the module's existing `@app.<verb>("/api/v1/p2p…")` style; wired to the async singletons created at app startup.
- `GET  /api/v1/p2p/dht/peers` → `{peers: [contact…], routing_buckets: n}` (node-local read).
- `POST /api/v1/p2p/dht/announce` *(require_jwt)* → triggers `DHTNetwork.announce()`; returns stored key + replica count.
- `GET  /api/v1/p2p/dht/find/{did}` → `find_peer(did)` (verified record or 404).
- `GET  /api/v1/p2p/federation/services` → `get_services_with_health()`.
- `POST /api/v1/p2p/federation/healthcheck` *(require_jwt)* → force one health sweep now.
- `GET  /api/v1/p2p/masterlink/topology` → `topology()`.
- `POST /api/v1/p2p/masterlink/promote` *(require_jwt)* → `promote(self|node_id)` (term-checked).
Lifecycle: `@app.on_event("startup")` creates `DHTNetwork`, `HealthChecker`, `MasterLink` as background tasks **guarded by config flags** (a module with the feature disabled starts nothing — backward compatible); `@app.on_event("shutdown")` cancels tasks + persists state.

## Config (`/etc/secubox/p2p.toml`, new sections; all default to safe/off)
```toml
[dht]
enabled = false
port = 51823
bootstrap = []          # ["host:51823", …]
announce = false        # OPAD opt-in
announce_interval = 900
rps = 50
[federation]
health_checks = false   # OPAD opt-in
interval = 30
probe_timeout = 5
max_concurrency = 20
fail_threshold = 3
[masterlink]
enabled = false
role_preference = "auto"
priority = 100
heartbeat_interval = 5
election_timeout = 15
port = 51824
```

## Testing (TDD, per-module; `from api import …`; run `cd packages/secubox-p2p && python3 -m pytest tests/test_<mod>.py -v`)
- `tests/test_dht.py`: XOR distance + bucket insert/evict/LRU; `RoutingTable.closest` ordering; JSON RPC encode/decode round-trip + malformed/oversized datagram rejected; signed-record verify (accept valid, reject tampered/unsigned/wrong-did); `iterative_find` over a set of in-process fake nodes (no real UDP — inject a transport double) converges to the target; TTL expiry. (Rewrite from scratch — the reverted one imported the wrong path and is gone.)
- `tests/test_federation.py`: health probe marks up/down; `fail_threshold` debounce (2 failures = still up, 3 = down); concurrency semaphore cap respected; status persisted/reloaded; probe respects opt-in flag (no probe when `health_checks=false`).
- `tests/test_masterlink.py`: `elect()` pure-function determinism (priority then node_id; stable under peer reordering); term monotonicity (stale-term heartbeat ignored); failover promotes the correct next node when master goes silent; JWT-gated promote respects term.
- Integration (best-effort, marked `@pytest.mark.integration`): two in-process `DHTNetwork`s over loopback UDP discover each other; a federated service transitions up→down→up.
- Performance sanity (asserted with generous bounds, not perf-CI): `elect()` over 1000 peers < 50ms; routing `closest` over full table < 5ms.

## Phasing (independently shippable; matches issue #774)
1. **Phase 1 — DHT** (`api/dht.py` + endpoints + `test_dht.py`). Deliverable: peers discover each other across subnets; convergence tested with fakes.
2. **Phase 2 — Federation health-checks** (`api/federation.py` + endpoints + `test_federation.py`), publishing status via Phase 1's DHT.
3. **Phase 3 — Master-link** (`api/masterlink.py` + endpoints + `test_masterlink.py`), using Phase 1 discovery + mesh peers.

## Edges / failure handling
- DHT bootstrap with zero reachable seeds → module starts, routing table empty, `find_peer` returns None (no crash); logs a warning.
- annuaire.sock down → bootstrap falls back to `[dht].bootstrap` only; health-checker skips the tick with a warning.
- Signature verification failure on a stored value → value dropped, source contact penalized (not inserted), audit-logged.
- Master heartbeat UDP loss / partition → higher-term election converges; on partition heal, the lower-term master steps down (term comparison).
- All background tasks are cancel-safe on shutdown and never block the event loop (every network op is `await`ed with a timeout; no synchronous `socket`/`requests`).
