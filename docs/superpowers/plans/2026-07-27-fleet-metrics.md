<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Fleet Metrics — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each node signs a compact current snapshot of its own state into a dedicated last-wins store; peers pull each other's snapshot over the `:8799` mesh read-path; a `/fleet` panel shows the whole gondwana mesh at a glance.

**Architecture:** A standalone Ed25519-signed `MetricSnapshot` record (NOT a journal op — the journal is immutable-chained). A pure `fleet.py` signs/verifies/resolves; `fleet_store.py` holds one overwritable `self.json`; `metrics_collect.py` gathers vitals+health+counters locally; the annuaire API serves `/fleet/self` (public signed, on `:8799`) and `/fleet` (JWT, pulls peers + verifies); a timer publishes ~60s; a `/fleet` panel renders the matrix.

**Tech Stack:** Python 3.11 (board 3.11.2), Ed25519 (`annuaire.crypto`), FastAPI, systemd, pytest (repo `.venv`).

## Global Constraints

- **SPDX 4-line header** verbatim on every new Python file (`LicenseRef-CMSD-1.0` / `Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>` / `Source-Disclosed License…` / `See LICENCE-CMSD-1.0.md for terms.`).
- **Sovereign signing, fail-closed:** every snapshot is Ed25519-signed with the node key; verification requires `crypto.verify(...)` AND `signer_did == node_did == issued_by`. A record failing either is DROPPED. A node serves ONLY its own `self.json`.
- **NOT in the journal:** the CSPN journal (`log.db`) is immutable-chained and MUST NOT be touched. Snapshots live in `/var/lib/secubox/annuaire/fleet/self.json`, overwritten in place (1 record/node, bounded).
- **No privileged action in-process; publisher runs as `secubox`** and signs with the box's own `node.key` (never root).
- **Transport = `:8799` mesh read-path over wg-mesh only** (allow 10.10.0.0/24 + deny-all — the existing gondwana listener posture). No new port, no new Freebox forward.
- Fixed record shape (`extra=forbid`). `modules_down` capped at 20 names. Opt-in `[metrics] fleet_publish` (default `true`).
- **Never chown the shared parents** `/run/secubox`, `/etc/secubox`, `/var/log/secubox`, `/var/lib/secubox`. `#DEBHELPER#` alone on its line.
- Commit messages end `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, NO AI/Claude references.
- Tests: repo `.venv`, `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/…`.

## Substrate reference

- `annuaire/crypto.py`: `sign(priv: bytes, msg: bytes) -> str`, `public_from_private(priv) -> bytes`, `verify(pub_hex: str, msg: bytes, sig_hex: str) -> bool`, `did_from_pubkey(pub: bytes) -> str`, `canonical_bytes(obj: dict) -> bytes`.
- `annuaire/mesh_sync.py`: `read_mesh_peers(path=DEFAULT_PEERS_PATH) -> [{"mesh_ip","name"}]`, `DEFAULT_MESH_PORT=8799`; peer pull idiom `http://{ip}:8799/api/v1/annuaire/log/export` via `urllib.request`.
- `api/main.py`: `@app.get("/log/export")` (public, returns `{"entries": …}`) — the model for `/fleet/self`. JWT dep is `_require_jwt`. `get_journal()` opens the journal. Peer-pull endpoint `post_node_import` uses `urllib` with a base_url.
- Counters: `annuaire.verbs.banned_ips(journal) -> list[str]`; `annuaire.assist_match.active_open_requests(entries, now_ts) -> list`; SOC alerts have no clean annuaire source → default 0 (best-effort).
- secubox-metrics cache: `/var/cache/secubox/metrics-cache.json` (JSON; `secubox-metrics/api/main.py` writes it). `collect_snapshot` reads it best-effort.
- Node key: `/etc/secubox/secrets/annuaire/node.key` (hex Ed25519 priv, env `ANNUAIRE_KEY_PATH`); public did file `/etc/secubox/annuaire/node.did`.
- Sibling patterns: `sbin/sbx-centersctl` (ctl shape), `www/centers/` (panel), `debian/rules` `override_dh_auto_install` (install idiom), `menu.d/570-centers.json` (`name`+`category`).

## File Structure (all in `packages/secubox-annuaire/`)

- `annuaire/model.py` — extend: `MetricSnapshot` pydantic model.
- `annuaire/fleet.py` (new, pure) — sign/verify/resolve/stale/health.
- `annuaire/fleet_store.py` (new) — atomic self.json read/write.
- `annuaire/metrics_collect.py` (new) — `collect_snapshot()` with injectable readers.
- `api/main.py` — extend: `GET /fleet/self`, `GET /fleet`.
- `sbin/sbx-fleetctl` (new) — `publish` (collect→sign→store, toggle, DRYRUN).
- `systemd/secubox-metrics-publish.{service,timer}` (new).
- `www/fleet/index.html`, `menu.d/595-fleet.json`, `nginx/fleet.conf` (new).
- `debian/{rules,postinst,changelog}` (modify).
- Tests: `tests/test_fleet_model.py`, `test_fleet.py`, `test_fleet_store.py`, `test_metrics_collect.py`, `test_fleet_api.py`, `test_fleetctl.py`, `test_fleet_packaging.py`.

---

## Task 1: `MetricSnapshot` model

**Files:** Modify `annuaire/model.py`; Test `tests/test_fleet_model.py`.

**Interfaces — Produces:** `MetricSnapshot(BaseModel)` with `ConfigDict(extra="forbid")`, fields: `node_did: str` (pattern `^did:plc:[0-9a-f]{32}$`), `hostname: str`, `ts: str`, `cpu_pct: float`, `mem_pct: float`, `disk_pct: float`, `load1: float`, `uptime_s: int`, `modules_up: int`, `modules_down: list[str]` (validator: truncate/cap to 20), `counters: dict` (keys bans/assist_sessions/soc_alerts, ints, default 0), `issued_by: str` (DID pattern), `sig: Optional[str]=None`, `signer_did: Optional[str]=None`.

- [ ] **Step 1: failing test**
```python
# packages/secubox-annuaire/tests/test_fleet_model.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest
from pydantic import ValidationError
from annuaire.model import MetricSnapshot

DID = "did:plc:" + "a" * 32


def test_snapshot_shape_and_extra_forbid():
    s = MetricSnapshot(node_did=DID, hostname="gk2", ts="2026-07-27T10:00:00Z",
                       cpu_pct=12.5, mem_pct=40.0, disk_pct=55.0, load1=0.7,
                       uptime_s=3600, modules_up=30, modules_down=["secubox-x"],
                       counters={"bans": 3, "assist_sessions": 0, "soc_alerts": 1},
                       issued_by=DID)
    assert s.node_did == DID and s.counters["bans"] == 3
    with pytest.raises(ValidationError):
        MetricSnapshot(node_did=DID, hostname="g", ts="t", cpu_pct=1, mem_pct=1,
                       disk_pct=1, load1=1, uptime_s=1, modules_up=1,
                       modules_down=[], counters={}, issued_by=DID, sneaky=True)


def test_modules_down_capped_at_20():
    s = MetricSnapshot(node_did=DID, hostname="g", ts="t", cpu_pct=1, mem_pct=1,
                       disk_pct=1, load1=1, uptime_s=1, modules_up=1,
                       modules_down=[f"m{i}" for i in range(40)], counters={},
                       issued_by=DID)
    assert len(s.modules_down) == 20
```

- [ ] **Step 2: RED** — `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/test_fleet_model.py -q` → ImportError.
- [ ] **Step 3: implement** — add `MetricSnapshot` to `model.py` (mirror the `extra="forbid"` + DID-pattern style of the existing models; `counters` defaults each key to 0 in a `field_validator`; `modules_down` validator truncates to `[:20]`). Ensure `field_validator`/`ConfigDict`/`Optional` are imported (they are).
- [ ] **Step 4: GREEN** + full suite (`../../.venv/bin/pytest tests/ -q`, no regressions).
- [ ] **Step 5: commit** `feat(annuaire): MetricSnapshot model (fleet-metrics)` + trailer.

---

## Task 2: `fleet.py` — sign / verify / resolve (security core)

**Files:** Create `annuaire/fleet.py`; Test `tests/test_fleet.py`.

**Interfaces:**
- Consumes: `crypto.sign/verify/public_from_private/did_from_pubkey/canonical_bytes`, `model.MetricSnapshot`.
- Produces:
  - `sign_snapshot(priv: bytes, fields: dict) -> dict` — `signer_did = did_from_pubkey(public_from_private(priv))`; validate `fields` through `MetricSnapshot` (minus sig/signer_did); `sig = sign(priv, canonical_bytes(payload_without_sig_signer))`; return the full dict incl `sig` + `signer_did`.
  - `verify_snapshot(rec: dict) -> bool` — recompute `canonical_bytes` of the record MINUS `sig`+`signer_did`; `crypto.verify(pubkey-from-signer, …, rec["sig"])` — BUT since we only have DIDs not pubkeys in the record, verification uses the embedded rule: **the record must carry `signer_did` AND the sig must verify against the pubkey the signer_did was derived from.** Since a DID is `did:plc:<hex(blake2b(pubkey))>` (not reversible to pubkey), the record MUST also carry the signer pubkey OR the verification is done by the PULLER who knows the peer's pubkey. **Decision:** add `signer_pub: str` (hex) to the signed record; `verify_snapshot` checks `did_from_pubkey(bytes.fromhex(signer_pub)) == signer_did == node_did == issued_by` AND `crypto.verify(signer_pub, canonical_bytes(payload), sig)`. Fail-closed on any mismatch/exception → False.
  - `fleet_snapshots(self_rec: dict|None, peer_recs: list[dict]) -> dict` — start `{}`; for each rec in `[self_rec, *peer_recs]` that is not None, if `verify_snapshot(rec)` keep `out[rec["node_did"]] = rec` (last verified wins). Never raises.
  - `is_stale(rec: dict, now_ts: str, ttl_s: int) -> bool` — parse `rec["ts"]` (RFC3339 Z), True if `now - ts > ttl_s` OR ts unparseable (fail-closed → stale).
  - `health(rec: dict) -> str` — `"down"` if `rec["modules_down"]`, else `"warn"` if `load1 > cpu-count-ish threshold` (use `load1 > 4.0` as a fixed heuristic) or `disk_pct > 90`, else `"ok"`.

- [ ] **Step 1: failing test**
```python
# packages/secubox-annuaire/tests/test_fleet.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import os
from annuaire import fleet
from annuaire.crypto import public_from_private, did_from_pubkey

FIELDS = dict(hostname="gk2", ts="2026-07-27T10:00:00Z", cpu_pct=10.0, mem_pct=20.0,
              disk_pct=30.0, load1=0.5, uptime_s=100, modules_up=5, modules_down=[],
              counters={"bans": 0, "assist_sessions": 0, "soc_alerts": 0})


def _signed(priv):
    did = did_from_pubkey(public_from_private(priv))
    return fleet.sign_snapshot(priv, {**FIELDS, "node_did": did, "issued_by": did})


def test_sign_then_verify_roundtrip():
    priv = os.urandom(32)
    rec = _signed(priv)
    assert fleet.verify_snapshot(rec) is True


def test_tampered_field_fails_verify():
    priv = os.urandom(32)
    rec = _signed(priv); rec["cpu_pct"] = 99.0   # tamper after signing
    assert fleet.verify_snapshot(rec) is False


def test_foreign_signer_did_rejected():
    priv = os.urandom(32); other = os.urandom(32)
    rec = _signed(priv)
    rec["node_did"] = did_from_pubkey(public_from_private(other))  # claim another did
    assert fleet.verify_snapshot(rec) is False


def test_fleet_snapshots_keeps_only_verified():
    p1, p2 = os.urandom(32), os.urandom(32)
    r1, r2 = _signed(p1), _signed(p2)
    forged = _signed(os.urandom(32)); forged["sig"] = "00" * 64  # broken sig
    out = fleet.fleet_snapshots(r1, [r2, forged])
    assert set(out) == {r1["node_did"], r2["node_did"]}


def test_is_stale_failclosed():
    assert fleet.is_stale({"ts": "garbage"}, "2026-07-27T10:00:00Z", 300) is True
    assert fleet.is_stale({"ts": "2026-07-27T10:00:00Z"}, "2026-07-27T10:02:00Z", 300) is False
    assert fleet.is_stale({"ts": "2026-07-27T10:00:00Z"}, "2026-07-27T10:10:00Z", 300) is True
```

- [ ] **Step 2: RED** — `ModuleNotFoundError: annuaire.fleet`.
- [ ] **Step 3: implement `fleet.py`** — per the Interfaces. Note the KEY design decision made explicit in the test: the signed record carries `signer_pub` (hex pubkey) so a puller can verify without a pubkey registry; `verify_snapshot` enforces `did_from_pubkey(signer_pub) == signer_did == node_did == issued_by` AND the Ed25519 sig over `canonical_bytes(payload-without-{sig,signer_did,signer_pub})`. Fail-closed (any exception/mismatch → False). Add `signer_pub: Optional[str]=None` to `MetricSnapshot` in Task 1 if not already (— UPDATE Task 1 to include `signer_pub`; see Self-Review).
- [ ] **Step 4: GREEN** + full suite.
- [ ] **Step 5: commit** `feat(annuaire): fleet.py — sign/verify/resolve snapshots, fail-closed signer binding (fleet-metrics)` + trailer.

---

## Task 3: `fleet_store.py` + `metrics_collect.py`

**Files:** Create `annuaire/fleet_store.py`, `annuaire/metrics_collect.py`; Test `tests/test_fleet_store.py`, `tests/test_metrics_collect.py`.

**Interfaces:**
- `fleet_store.SELF_PATH = "/var/lib/secubox/annuaire/fleet/self.json"` (env `FLEET_SELF_PATH` override for tests); `write(rec, path=SELF_PATH)` (atomic tmp+os.replace); `read(path=SELF_PATH) -> dict|None` (None on missing/corrupt, fail-safe).
- `metrics_collect.collect_snapshot(node_did, *, cache_reader=..., unit_lister=..., counter_reader=...) -> dict` — assemble the `MetricSnapshot` fields (minus sig/signer). Default readers: `cache_reader` reads `/var/cache/secubox/metrics-cache.json` (cpu/mem/disk/load/uptime/hostname; missing → zeros + `socket.gethostname()`); `unit_lister` runs `systemctl is-active` over `secubox-*` (→ modules_up count + down names cap 20); `counter_reader` returns `{bans, assist_sessions, soc_alerts}` (best-effort, 0 on error). Injectable readers make it fully unit-testable with fakes. `ts = now RFC3339 Z`.

- [ ] **Step 1-5 (fleet_store):** test atomic write + read-back + corrupt→None; implement; green.
- [ ] **Step 1-5 (metrics_collect):** test with injected fake readers → correct fixed-shape dict; a raising reader degrades to zeros/empty, never raises; `modules_down` capped. Implement with the injectable-reader signature; the production default readers guarded (每 source in try/except → default). Commit `feat(annuaire): fleet_store + metrics_collect (local snapshot IO + collection) (fleet-metrics)` + trailer.

---

## Task 4: API `/fleet/self` + `/fleet` + `sbx-fleetctl publish`

**Files:** Modify `api/main.py`; Create `sbin/sbx-fleetctl` (+x); Test `tests/test_fleet_api.py`, `tests/test_fleetctl.py`.

**Interfaces:**
- `GET /fleet/self` (PUBLIC, mirror `/log/export`): returns `fleet_store.read()` or `{}` — the local signed record verbatim (safe: it's signed). This is what peers pull on `:8799`.
- `GET /fleet` (JWT `_require_jwt`): `self_rec = fleet_store.read()`; `peers = mesh_sync.read_mesh_peers()`; for each peer pull `http://{ip}:8799/api/v1/annuaire/fleet/self` (a module-level `_fetch_peer(url, timeout=2)` using `urllib`, injectable/monkeypatchable, returns dict|None on any error); `snaps = fleet.fleet_snapshots(self_rec, peer_recs)`; return `{"nodes": [ {**snap, "health": fleet.health(snap), "stale": fleet.is_stale(snap, now, ttl)} for snap in snaps.values() ]}`. Read-only, never 500 → `{"nodes": []}` on error.
- `sbin/sbx-fleetctl publish` (mirror sbx-centersctl): load `[metrics] fleet_publish` from secubox.conf (default true) — if false, print `{"skipped": "fleet_publish disabled"}` and exit 0; else `node_did = _self_did()`, `rec = fleet.sign_snapshot(priv, collect_snapshot(node_did))`, `fleet_store.write(rec)`, print `{"published": node_did}`. `DRYRUN=1` → print plan, no write. Key from `ANNUAIRE_KEY_PATH` (never generated).

- [ ] **Steps (api):** `test_fleet_api.py` — `/fleet/self` public returns the stored rec (write a fake self.json via `FLEET_SELF_PATH`); `/fleet` without JWT → 401/403; `/fleet` with a monkeypatched `_fetch_peer` returning a verified peer rec → `nodes` includes self + peer, each with `health`/`stale`. Implement mirroring `/log/export` + `_require_jwt`. Red→green.
- [ ] **Steps (ctl):** `test_fleetctl.py` — subprocess: `publish` with a temp key + `FLEET_SELF_PATH` + fake collect env writes a verified self.json; `DRYRUN=1` writes nothing; `fleet_publish=false` in a temp secubox.conf → skipped. Implement; `chmod +x`. Red→green + full suite.
- [ ] **Commit** `feat(annuaire): /fleet API (self read-path + JWT aggregate pull) + sbx-fleetctl publish (fleet-metrics)` + trailer.

---

## Task 5: panel `/fleet` + publisher unit + packaging

**Files:** Create `www/fleet/index.html`, `menu.d/595-fleet.json`, `nginx/fleet.conf`, `systemd/secubox-metrics-publish.service`+`.timer`; Modify `debian/rules`, `debian/postinst`, `debian/changelog`; Test `tests/test_fleet_packaging.py`, `tests/test_fleet_menu.py`.

**Interfaces:** panel = matrix of `GET /api/v1/annuaire/fleet` `.nodes`, one row/node: hostname, health dot (down=red / warn=amber / ok=green), cpu/mem/disk/load bars, counters, "vu il y a Ns" from `ts` (stale → greyed). `sbx_token`, `/shared/sidebar.js`, event-delegation, NO inline `on*=`, NO `innerHTML` for API data (createElement/textContent/dataset). `menu.d/595-fleet.json` → `{name, category:"mesh"}`, path `/fleet`. `nginx/fleet.conf` → `location /fleet/ { alias …; }` + `/api/v1/annuaire/fleet` already routed via the annuaire API (reuses the existing annuaire route; the panel static alias is the only new nginx bit). publisher `.service` = `ExecStart=/usr/sbin/sbx-fleetctl publish`, `User=secubox`, `Type=oneshot`; `.timer` `OnUnitActiveSec=60s`, `OnBootSec=90s`.

- [ ] **Step 1 (packaging test):**
```python
# tests/test_fleet_packaging.py — key assertions
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
def test_publisher_unit_non_root_oneshot():
    svc = (ROOT / "systemd" / "secubox-metrics-publish.service").read_text()
    assert "User=secubox" in svc and "sbx-fleetctl publish" in svc
    tmr = (ROOT / "systemd" / "secubox-metrics-publish.timer").read_text()
    assert "OnUnitActiveSec" in tmr
def test_postinst_no_shared_parent_chown_and_fleetdir():
    p = (ROOT / "debian" / "postinst").read_text()
    for bad in ("chown -R secubox /run/secubox", "chown -R secubox /etc/secubox",
                "chown -R secubox /var/lib/secubox"):
        assert bad not in p
    assert "/var/lib/secubox/annuaire/fleet" in p and "#DEBHELPER#" in p
def test_menu_valid():
    import json
    m = json.loads((ROOT / "menu.d" / "595-fleet.json").read_text())
    assert m.get("category") in {"auth","wall","boot","mind","root","mesh"} and "/fleet" in json.dumps(m)
```
- [ ] **Steps 2-4:** build the panel (mirror `www/centers/index.html` skin + XSS discipline), menu, nginx alias, publisher unit/timer; extend `debian/rules` `override_dh_auto_install` to ship `annuaire/fleet.py`+`fleet_store.py`+`metrics_collect.py` (already globbed by `cp -r annuaire/*` — verify), `sbin/sbx-fleetctl`→`/usr/sbin` (755), `systemd/secubox-metrics-publish.*`→`/lib/systemd/system` (644), `www/fleet/*`, `menu.d/595-fleet.json`, `nginx/fleet.conf`; postinst `install -d /var/lib/secubox/annuaire/fleet` (owner secubox, so the publisher can write) + `systemctl enable --now secubox-metrics-publish.timer || true`; bump `debian/changelog` (next minor, e.g. 0.10.0). Run BOTH `cd packages/secubox-annuaire && ../../.venv/bin/pytest tests/ -q` green + `dpkg-buildpackage -us -uc -b`; `dpkg-deb -c` confirms fleet.py/fleet_store.py/metrics_collect.py, sbx-fleetctl, the units, www/fleet, menu, nginx ship.
- [ ] **Step 5: commit** `build(annuaire): package fleet panel + metrics-publish timer + /fleet routing (fleet-metrics)` + trailer.

---

## Self-Review

**1. Spec coverage:** MetricSnapshot model → T1. sign/verify/resolve fail-closed → T2. self.json store + collection → T3. `/fleet/self` (public signed :8799) + `/fleet` (JWT pull+verify) + ctl publish + opt-in toggle → T4. panel + publisher timer + packaging + no-journal + no-shared-parent-chown → T5. Sovereignty (signer_did==node_did) → T2 verify + T4 serve-only-own. Bounded (1 record/node, atomic overwrite) → T3 store. Transport :8799 → T4. ✅
**Correction folded in:** the signed record needs `signer_pub` (hex) so a puller can verify a peer's sig without a pubkey registry (a DID is a one-way hash of the pubkey). **Task 1 MUST add `signer_pub: Optional[str]=None` to `MetricSnapshot`**, and T2 `sign_snapshot` sets it, `verify_snapshot` enforces `did_from_pubkey(bytes.fromhex(signer_pub)) == signer_did == node_did == issued_by` before the Ed25519 check. (Mirrors how journal entries carry `author_pubkey_hex` for import verification.)

**2. Placeholder scan:** T3/T4/T5 compress Steps 2-4 into prose that mirrors the shipped sibling ctls/panels/packaging verbatim; the security-critical T1-T2 carry complete code. Flag to implementer: follow `sbx-centersctl` / `www/centers` / `api/main.py /log/export` as templates.

**3. Type consistency:** `MetricSnapshot` fields (incl `signer_pub`) consistent T1↔T2↔T3. `sign_snapshot(priv, fields)->dict` / `verify_snapshot(rec)->bool` / `fleet_snapshots(self_rec, peer_recs)->dict` / `is_stale(rec, now, ttl)` / `health(rec)` identical T2↔T4↔T5. `fleet_store.read/write`, `collect_snapshot(node_did, *readers)` consistent T3↔T4. `/fleet/self` + `/fleet` + `_fetch_peer` consistent T4↔T5.

**Cross-task note for the controller:** T2's `signer_pub` addition retro-updates T1's model — dispatch T1 with the `signer_pub` field already included (don't make T2 amend the model). The `:8799` serve of `/fleet/self` reuses the existing annuaire-API-on-mesh exposure (same as `/log/export`); no new listener. The `/fleet` panel API route reuses the existing `/api/v1/annuaire/` routing; only the static `/fleet/` alias is new nginx (may need the manual webui.conf location on gk2 — the recurring secubox.d-inert gotcha).
