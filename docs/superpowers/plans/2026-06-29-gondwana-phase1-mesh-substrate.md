<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Gondwana Phase 1 — Mesh Substrate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `secubox-p2p` the single, collision-free, multi-site WireGuard mesh owner with a persistent per-node identity, cutting over the live gk2↔c3box mesh with zero disruption and enrolling the amd64 node.

**Architecture:** Extract all pure mesh logic into a new privilege-free, FastAPI-free module `api/mesh.py` (unit-testable). The `secubox-p2p` FastAPI app (runs as user `secubox`) consumes `mesh.py` for state/read endpoints only. A new **root** CLI `sbx-mesh-up` performs the privileged provisioning (adopt existing key → collision-guard → render `wg-mesh.conf` → `wg-quick up`), because the service user cannot run `wg-quick`. Subnet moves `10.100.0.0/24 → 10.10.0.0/24`, port `51820 → 51822`.

**Tech Stack:** Python 3.11 (stdlib `tomllib`, `subprocess`, `ipaddress`), pytest, WireGuard (`wg`, `wg-quick`), Debian packaging (debhelper 13).

## Global Constraints

- Mesh subnet `10.10.0.0/24`, port `51822`, interface `wg-mesh` — exact values.
- Mesh subnet MUST NOT overlap `10.100.0.0/24` (br-lxc), `10.55.0.0/24` (eye-br0), `10.0.3.0/24` (lxcbr0), `10.99.0.0/24` (wg-toolbox) — provisioner refuses on overlap.
- gk2 = `10.10.0.1` (active rendezvous), c3box = `10.10.0.2`, amd64 = `10.10.0.3`.
- `master_endpoint` pinned `82.67.100.75:51822` (DDNS-ready, free-form host:port).
- Rendezvous is a **role** (`role="master"|"satellite"`) — never hardwire "gk2 is master".
- Private-key **adoption**: never regenerate a key when a valid `wg-mesh.conf`/state key exists (preserves gk2↔c3box handshake).
- Registry is **local-first/replicable** (forward-compat for the Phase 2/3 ledger).
- **no mass daemon restart on gk2**; **source-first** (every live change backported); **no Claude/AI references in commits**.
- Live boxes: gk2 `192.168.1.200` (master), amd64 live-USB `192.168.1.9` (satellite, `ssh root@…` pw `secubox`), c3box `192.168.1.94` (offline now).
- Service runs as `User=secubox`, `WorkingDirectory=/usr/lib/secubox/p2p`, `uvicorn api.main:app`. wg-quick/`/etc/wireguard`/nft need root → root CLI only.

---

## File structure

- Create `packages/secubox-p2p/api/mesh.py` — pure mesh logic (no FastAPI, no privilege).
- Create `packages/secubox-p2p/scripts/sbx-mesh-up` — root provisioning CLI.
- Create `packages/secubox-p2p/conf/p2p.toml.example` — `[wireguard]` config seed.
- Create `packages/secubox-p2p/tests/conftest.py` + `tests/test_mesh.py` — pytest.
- Modify `packages/secubox-p2p/api/main.py` — import `mesh`, fix defaults, wire endpoints + join allocation.
- Modify `packages/secubox-p2p/debian/rules` — install conf + `sbx-mesh-up`.
- Modify `packages/secubox-p2p/debian/control` — `Depends: wireguard-tools`.
- Modify `packages/secubox-p2p/debian/changelog` — version bump.

All `mesh.py` functions operate on an explicit `state: dict` (the parsed `wg_mesh.json`) and explicit paths, so tests pass `tmp_path` and never touch the real filesystem.

---

### Task 1: Pure mesh module — subnet collision guard

**Files:**
- Create: `packages/secubox-p2p/api/mesh.py`
- Test: `packages/secubox-p2p/tests/test_mesh.py`
- Create: `packages/secubox-p2p/tests/conftest.py`

**Interfaces:**
- Produces: `RESERVED_SUBNETS: dict[str,str]`; `subnet_overlap(network: str) -> str | None` (returns the *name* of the first reserved subnet that overlaps `network`, else `None`); `MESH_NETWORK = "10.10.0.0/24"`, `MESH_PORT = 51822`, `MESH_INTERFACE = "wg-mesh"`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-p2p/tests/test_mesh.py
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # repo package root
from api import mesh


def test_mesh_defaults():
    assert mesh.MESH_NETWORK == "10.10.0.0/24"
    assert mesh.MESH_PORT == 51822
    assert mesh.MESH_INTERFACE == "wg-mesh"


def test_subnet_overlap_detects_br_lxc():
    assert mesh.subnet_overlap("10.100.0.0/24") == "br-lxc"


def test_subnet_overlap_detects_partial_supernet():
    # a /16 that contains br-lxc must also be rejected
    assert mesh.subnet_overlap("10.100.0.0/16") == "br-lxc"


def test_subnet_overlap_clean_mesh_subnet():
    assert mesh.subnet_overlap("10.10.0.0/24") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.mesh'`

- [ ] **Step 3: Write minimal implementation**

```python
# packages/secubox-p2p/api/mesh.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox-Deb :: secubox-p2p :: mesh
Pure mesh logic — no FastAPI, no privilege. Imported by api/main.py (state
endpoints, runs as user secubox) and by sbx-mesh-up (root provisioner).
"""
from __future__ import annotations
import ipaddress

MESH_INTERFACE = "wg-mesh"
MESH_PORT = 51822
MESH_NETWORK = "10.10.0.0/24"

# Reserved subnets the mesh must never overlap (name -> CIDR).
RESERVED_SUBNETS = {
    "br-lxc": "10.100.0.0/24",
    "eye-br0": "10.55.0.0/24",
    "lxcbr0": "10.0.3.0/24",
    "wg-toolbox": "10.99.0.0/24",
}


def subnet_overlap(network: str) -> str | None:
    """Return the name of the first RESERVED_SUBNETS entry that overlaps
    `network`, or None if `network` is clear."""
    net = ipaddress.ip_network(network, strict=False)
    for name, cidr in RESERVED_SUBNETS.items():
        if net.overlaps(ipaddress.ip_network(cidr, strict=False)):
            return name
    return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Create conftest + commit**

```python
# packages/secubox-p2p/tests/conftest.py
# Ensures `from api import mesh` resolves from the package root during tests.
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
```

```bash
git add packages/secubox-p2p/api/mesh.py packages/secubox-p2p/tests/
git commit -m "feat(p2p): mesh module with subnet collision guard"
```

---

### Task 2: p2p.toml config loader + [wireguard] section

**Files:**
- Modify: `packages/secubox-p2p/api/mesh.py`
- Create: `packages/secubox-p2p/conf/p2p.toml.example`
- Test: `packages/secubox-p2p/tests/test_mesh.py`

**Interfaces:**
- Consumes: Task 1 constants.
- Produces: `load_p2p_config(path: pathlib.Path) -> dict` — reads `[wireguard]` from a TOML file, returns a dict with keys `interface, listen_port, network, role, master_endpoint`, filling defaults (`MESH_*`, `role="satellite"`, `master_endpoint=None`) for anything absent/missing-file.

- [ ] **Step 1: Write the failing test**

```python
def test_load_p2p_config_defaults_when_missing(tmp_path):
    cfg = mesh.load_p2p_config(tmp_path / "nope.toml")
    assert cfg["network"] == "10.10.0.0/24"
    assert cfg["listen_port"] == 51822
    assert cfg["interface"] == "wg-mesh"
    assert cfg["role"] == "satellite"
    assert cfg["master_endpoint"] is None


def test_load_p2p_config_reads_wireguard_section(tmp_path):
    p = tmp_path / "p2p.toml"
    p.write_text(
        "[wireguard]\n"
        'role = "master"\n'
        'listen_port = 51822\n'
        'network = "10.10.0.0/24"\n'
        'master_endpoint = "82.67.100.75:51822"\n'
    )
    cfg = mesh.load_p2p_config(p)
    assert cfg["role"] == "master"
    assert cfg["master_endpoint"] == "82.67.100.75:51822"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k load_p2p_config -v`
Expected: FAIL — `AttributeError: module 'api.mesh' has no attribute 'load_p2p_config'`

- [ ] **Step 3: Write minimal implementation**

```python
# add to api/mesh.py
import tomllib
import pathlib


def load_p2p_config(path: "pathlib.Path") -> dict:
    """Read the [wireguard] section of /etc/secubox/p2p.toml, with defaults."""
    defaults = {
        "interface": MESH_INTERFACE,
        "listen_port": MESH_PORT,
        "network": MESH_NETWORK,
        "role": "satellite",
        "master_endpoint": None,
    }
    try:
        with open(path, "rb") as f:
            wg = (tomllib.load(f) or {}).get("wireguard", {}) or {}
    except (FileNotFoundError, tomllib.TOMLDecodeError):
        wg = {}
    out = dict(defaults)
    for k in defaults:
        if wg.get(k) is not None:
            out[k] = wg[k]
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k load_p2p_config -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Create the example config + commit**

```toml
# packages/secubox-p2p/conf/p2p.toml.example
# Installed to /etc/secubox/p2p.toml.example by secubox-p2p.
# Copy to /etc/secubox/p2p.toml and edit per node.

[wireguard]
# Mesh transport. Do NOT change `network` to anything overlapping the LXC
# bridge (10.100.0.0/24) or other reserved subnets — sbx-mesh-up refuses.
interface      = "wg-mesh"
listen_port    = 51822
network        = "10.10.0.0/24"

# "master" = this node holds the rendezvous role (publicly reachable).
# "satellite" = this node dials the rendezvous. Rendezvous is a ROLE — any
# node may hold it; today only gk2 is publicly reachable.
role           = "satellite"

# Satellite only: where to reach the active rendezvous. Free-form host:port —
# a literal IP (pinned now) or a DDNS name (WireGuard re-resolves per
# handshake, so the rendezvous can change IP without reconfiguring peers).
master_endpoint = "82.67.100.75:51822"
```

```bash
git add packages/secubox-p2p/api/mesh.py packages/secubox-p2p/conf/p2p.toml.example packages/secubox-p2p/tests/test_mesh.py
git commit -m "feat(p2p): /etc/secubox/p2p.toml [wireguard] loader + example"
```

---

### Task 3: Master-assigned mesh IP allocation

**Files:**
- Modify: `packages/secubox-p2p/api/mesh.py`
- Test: `packages/secubox-p2p/tests/test_mesh.py`

**Interfaces:**
- Consumes: Task 1/2.
- Produces: `allocate_mesh_ip(network: str, taken: list[str]) -> str` — returns the lowest free host address in `network`, starting at `.2` (`.1` is reserved for the master), skipping any address already in `taken` (each `taken` item may be `"10.10.0.2"` or `"10.10.0.2/24"`). Raises `RuntimeError` if the pool is exhausted.

- [ ] **Step 1: Write the failing test**

```python
def test_allocate_mesh_ip_first_free_is_2():
    assert mesh.allocate_mesh_ip("10.10.0.0/24", []) == "10.10.0.2"


def test_allocate_mesh_ip_skips_taken_with_or_without_mask():
    got = mesh.allocate_mesh_ip("10.10.0.0/24", ["10.10.0.2/24", "10.10.0.3"])
    assert got == "10.10.0.4"


def test_allocate_mesh_ip_exhausted_raises():
    taken = [f"10.10.0.{n}" for n in range(2, 255)]
    import pytest
    with pytest.raises(RuntimeError):
        mesh.allocate_mesh_ip("10.10.0.0/24", taken)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k allocate -v`
Expected: FAIL — `AttributeError: ... 'allocate_mesh_ip'`

- [ ] **Step 3: Write minimal implementation**

```python
# add to api/mesh.py
def allocate_mesh_ip(network: str, taken: list[str]) -> str:
    """Lowest free host >= .2 in `network` (.1 reserved for master)."""
    taken_set = {t.split("/")[0] for t in taken}
    net = ipaddress.ip_network(network, strict=False)
    base = int(net.network_address)
    for off in range(2, net.num_addresses - 1):
        cand = str(ipaddress.ip_address(base + off))
        if cand not in taken_set:
            return cand
    raise RuntimeError(f"mesh address pool {network} exhausted")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k allocate -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/api/mesh.py packages/secubox-p2p/tests/test_mesh.py
git commit -m "feat(p2p): master-assigned mesh IP allocation (.2+, .1=master)"
```

---

### Task 4: Parse + render wg-mesh.conf (adoption + provisioning)

**Files:**
- Modify: `packages/secubox-p2p/api/mesh.py`
- Test: `packages/secubox-p2p/tests/test_mesh.py`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  - `parse_wg_conf(text: str) -> dict` — extracts `{"private_key", "address", "listen_port"}` from a `wg-quick` `[Interface]` block (values absent → key maps to `None`).
  - `render_wg_conf(state: dict) -> str` — builds a `wg-quick` config from a state dict with keys `private_key, address, listen_port, peers` (each peer: `public_key, endpoint(optional), allowed_ips`). Omits `Endpoint` when a peer has none (roaming spokes on the master).

- [ ] **Step 1: Write the failing test**

```python
def test_parse_wg_conf_extracts_interface_fields():
    text = (
        "[Interface]\n"
        "PrivateKey = ABC123=\n"
        "Address = 10.10.0.1/24\n"
        "ListenPort = 51822\n"
        "[Peer]\nPublicKey = X=\n"
    )
    got = mesh.parse_wg_conf(text)
    assert got == {"private_key": "ABC123=", "address": "10.10.0.1/24", "listen_port": 51822}


def test_render_wg_conf_master_with_roaming_peer():
    state = {
        "private_key": "PRIV=",
        "address": "10.10.0.1/24",
        "listen_port": 51822,
        "peers": [{"public_key": "PUB2=", "allowed_ips": "10.10.0.2/32"}],
    }
    out = mesh.render_wg_conf(state)
    assert "PrivateKey = PRIV=" in out
    assert "ListenPort = 51822" in out
    assert "AllowedIPs = 10.10.0.2/32" in out
    assert "Endpoint" not in out  # roaming peer => no Endpoint line


def test_render_wg_conf_satellite_with_endpoint_and_keepalive():
    state = {
        "private_key": "PRIV=", "address": "10.10.0.3/24", "listen_port": 51822,
        "peers": [{"public_key": "GK2=", "endpoint": "82.67.100.75:51822", "allowed_ips": "10.10.0.0/24"}],
    }
    out = mesh.render_wg_conf(state)
    assert "Endpoint = 82.67.100.75:51822" in out
    assert "PersistentKeepalive = 25" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k "parse_wg or render_wg" -v`
Expected: FAIL — missing `parse_wg_conf` / `render_wg_conf`

- [ ] **Step 3: Write minimal implementation**

```python
# add to api/mesh.py
import re


def parse_wg_conf(text: str) -> dict:
    """Extract Interface fields from a wg-quick config (first [Interface])."""
    out = {"private_key": None, "address": None, "listen_port": None}
    in_iface = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_iface = line.lower() == "[interface]"
            continue
        if not in_iface or "=" not in line:
            continue
        key, val = (p.strip() for p in line.split("=", 1))
        kl = key.lower()
        if kl == "privatekey":
            out["private_key"] = val
        elif kl == "address":
            out["address"] = val
        elif kl == "listenport":
            out["listen_port"] = int(val)
    return out


def render_wg_conf(state: dict) -> str:
    """Render a wg-quick config from mesh state."""
    lines = [
        "# Managed by secubox-p2p (sbx-mesh-up) — do not edit by hand.",
        "[Interface]",
        f"PrivateKey = {state['private_key']}",
        f"Address = {state['address']}",
        f"ListenPort = {state.get('listen_port', MESH_PORT)}",
    ]
    for peer in state.get("peers", []):
        lines += ["", "[Peer]", f"PublicKey = {peer['public_key']}"]
        if peer.get("endpoint"):
            lines.append(f"Endpoint = {peer['endpoint']}")
        lines.append(f"AllowedIPs = {peer.get('allowed_ips', MESH_NETWORK)}")
        lines.append("PersistentKeepalive = 25")
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k "parse_wg or render_wg" -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/api/mesh.py packages/secubox-p2p/tests/test_mesh.py
git commit -m "feat(p2p): parse/render wg-mesh.conf (key adoption + provisioning)"
```

---

### Task 5: DDNS name in node identity

**Files:**
- Modify: `packages/secubox-p2p/api/mesh.py`
- Test: `packages/secubox-p2p/tests/test_mesh.py`

**Interfaces:**
- Produces: `ddns_name(hostname: str, domain: str = "secubox.in") -> str` — returns `"<hostname>.secubox.in"`, lowercased, with any non-`[a-z0-9-]` in `hostname` replaced by `-`.

- [ ] **Step 1: Write the failing test**

```python
def test_ddns_name_basic():
    assert mesh.ddns_name("gk2") == "gk2.secubox.in"


def test_ddns_name_sanitizes():
    assert mesh.ddns_name("Secubox_Live!") == "secubox-live-.secubox.in"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k ddns -v`
Expected: FAIL — missing `ddns_name`

- [ ] **Step 3: Write minimal implementation**

```python
# add to api/mesh.py
def ddns_name(hostname: str, domain: str = "secubox.in") -> str:
    slug = re.sub(r"[^a-z0-9-]", "-", hostname.lower())
    return f"{slug}.{domain}"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k ddns -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/api/mesh.py packages/secubox-p2p/tests/test_mesh.py
git commit -m "feat(p2p): per-node DDNS identity name helper"
```

---

### Task 6: Wire mesh.py into api/main.py (defaults + endpoints + join allocation)

**Files:**
- Modify: `packages/secubox-p2p/api/main.py:977-1099` (WG constants, init, peer), `:1058-1062` (hash allocation), `:1746-1752` (join depth/peer).

**Interfaces:**
- Consumes: `api.mesh` (Tasks 1–5).
- Produces: `/wireguard` status reports `network=10.10.0.0/24, listen_port=51822` and a `ddns` field; `/wireguard/init` assigns `.1` for `role=master` else a master-allocated address; join records a `mesh_ip`.

- [ ] **Step 1: Replace the WG constants (main.py:977-980)**

```python
# was: WG_PORT = 51820 ; WG_NETWORK = "10.100.0.0/24"
from api import mesh

WG_MESH_CONFIG = P2P_DIR / "wg_mesh.json"
WG_INTERFACE = mesh.MESH_INTERFACE
WG_PORT = mesh.MESH_PORT
WG_NETWORK = mesh.MESH_NETWORK
```

- [ ] **Step 2: Make `/wireguard/init` role-aware + master-allocated (replace main.py:1058-1062)**

```python
    # Assign mesh IP: .1 for the master role, else allocate from the pool.
    p2p_cfg = mesh.load_p2p_config(CONFIG_FILE)
    if p2p_cfg["role"] == "master":
        addr = "10.10.0.1"
    else:
        taken = [p.get("allowed_ips", "") for p in config.get("peers", [])]
        addr = mesh.allocate_mesh_ip(WG_NETWORK, taken)
    config["address"] = f"{addr}/24"
    config["role"] = p2p_cfg["role"]
    config["ddns"] = mesh.ddns_name(get_hostname())
```

- [ ] **Step 3: Default peer allowed_ips to the mesh subnet (main.py:1078)**

```python
    allowed_ips: str = "10.10.0.0/24",
```

- [ ] **Step 4: Add a guarded refusal to `/wireguard/enable` (insert after main.py:1108)**

```python
    bad = mesh.subnet_overlap(config.get("network", WG_NETWORK))
    if bad:
        raise HTTPException(status_code=409,
            detail=f"mesh network overlaps reserved subnet {bad!r}; refusing")
```

- [ ] **Step 5: Record `mesh_ip` on approved join (insert in `ml_join` auto-approve block, main.py:1746)**

```python
        join_request["depth"] = peer_depth
        _taken = [p.get("address", "") for p in
                  load_json(PEERS_FILE, {"peers": []}).get("peers", [])]
        join_request["mesh_ip"] = mesh.allocate_mesh_ip(mesh.MESH_NETWORK, _taken)
```

- [ ] **Step 6: Smoke-test the import + app load**

Run: `cd packages/secubox-p2p && python3 -c "import sys; sys.path.insert(0,'.'); from api import main; print('ok', main.WG_NETWORK, main.WG_PORT)"`
Expected: `ok 10.10.0.0/24 51822`

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-p2p/api/main.py
git commit -m "feat(p2p): adopt mesh.py — 10.10.0.0/24:51822, role-aware addressing, collision guard"
```

---

### Task 7: Root provisioning CLI `sbx-mesh-up`

**Files:**
- Create: `packages/secubox-p2p/scripts/sbx-mesh-up`
- Test: `packages/secubox-p2p/tests/test_mesh.py` (logic already covered; this task adds an idempotency test for `adopt_state`)
- Modify: `packages/secubox-p2p/api/mesh.py` (add `adopt_state`)

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces: `adopt_state(state: dict, existing_conf_text: str | None) -> dict` — if `state` has no `private_key` but `existing_conf_text` parses one, import `private_key`/`address`/`listen_port` into `state` (so the public key is preserved); never overwrite an existing `private_key`. Returns the updated state. `sbx-mesh-up` (root) ties it together.

- [ ] **Step 1: Write the failing test**

```python
def test_adopt_state_imports_existing_key_when_absent():
    state = {"private_key": None, "peers": []}
    conf = "[Interface]\nPrivateKey = LIVEKEY=\nAddress = 10.10.0.1/24\nListenPort = 51822\n"
    out = mesh.adopt_state(state, conf)
    assert out["private_key"] == "LIVEKEY="
    assert out["address"] == "10.10.0.1/24"


def test_adopt_state_never_overwrites_existing_key():
    state = {"private_key": "KEEP=", "peers": []}
    conf = "[Interface]\nPrivateKey = OTHER=\n"
    out = mesh.adopt_state(state, conf)
    assert out["private_key"] == "KEEP="
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k adopt -v`
Expected: FAIL — missing `adopt_state`

- [ ] **Step 3: Implement `adopt_state` in api/mesh.py**

```python
def adopt_state(state: dict, existing_conf_text: str | None) -> dict:
    """Import the live wg-mesh private key so the public key is preserved.
    Never overwrites a key already present in state."""
    if state.get("private_key"):
        return state
    if not existing_conf_text:
        return state
    parsed = parse_wg_conf(existing_conf_text)
    if parsed["private_key"]:
        state["private_key"] = parsed["private_key"]
        if not state.get("address") and parsed["address"]:
            state["address"] = parsed["address"]
        if parsed["listen_port"]:
            state["listen_port"] = parsed["listen_port"]
    return state
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_mesh.py -k adopt -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Write the root CLI**

```bash
# packages/secubox-p2p/scripts/sbx-mesh-up
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-p2p :: sbx-mesh-up
# Root provisioner: adopt existing key -> collision guard -> render -> up.
# The secubox-p2p service runs as user `secubox` and cannot do this.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

STATE=/var/lib/secubox/p2p/wg_mesh.json
CONF=/etc/wireguard/wg-mesh.conf
PKG=/usr/lib/secubox/p2p

python3 - "$STATE" "$CONF" <<'PY'
import json, sys, subprocess, pathlib
sys.path.insert(0, "/usr/lib/secubox/p2p")
from api import mesh

state_path, conf_path = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
state = json.loads(state_path.read_text()) if state_path.exists() else {"peers": []}

# Adopt the live key if state has none (preserves the gk2<->c3box handshake).
existing = conf_path.read_text() if conf_path.exists() else None
state = mesh.adopt_state(state, existing)

net = state.get("network", mesh.MESH_NETWORK)
bad = mesh.subnet_overlap(net)
if bad:
    sys.exit(f"REFUSING: mesh network {net} overlaps reserved subnet {bad!r}")

if not state.get("private_key"):
    sys.exit("no private key in state and none to adopt; run /wireguard/init first")

conf_path.parent.mkdir(parents=True, exist_ok=True)
conf_path.write_text(mesh.render_wg_conf(state))
conf_path.chmod(0o600)
state_path.write_text(json.dumps(state, indent=2))
print(f"rendered {conf_path} (addr {state.get('address')}, peers {len(state.get('peers', []))})")
PY

wg-quick down wg-mesh 2>/dev/null || true
wg-quick up wg-mesh
wg show wg-mesh
```

- [ ] **Step 6: Lint the script**

Run: `bash -n packages/secubox-p2p/scripts/sbx-mesh-up && echo OK`
Expected: `OK`

- [ ] **Step 7: Commit**

```bash
chmod +x packages/secubox-p2p/scripts/sbx-mesh-up
git add packages/secubox-p2p/api/mesh.py packages/secubox-p2p/scripts/sbx-mesh-up packages/secubox-p2p/tests/test_mesh.py
git commit -m "feat(p2p): root sbx-mesh-up provisioner (adopt key, guard, render, up)"
```

---

### Task 8: Packaging — ship config + CLI, depend on wireguard-tools, bump

**Files:**
- Modify: `packages/secubox-p2p/debian/rules`, `debian/control`, `debian/changelog`

**Interfaces:**
- Consumes: Tasks 1–7 artifacts.
- Produces: installed `/etc/secubox/p2p.toml.example`, `/usr/bin/sbx-mesh-up`, runtime dep `wireguard-tools`, version `1.7.6`.

- [ ] **Step 1: Add install lines to `override_dh_auto_install` (debian/rules, before "Create runtime directory")**

```makefile
	# Install p2p.toml example
	install -d $(CURDIR)/debian/secubox-p2p/etc/secubox
	install -m 644 $(CURDIR)/conf/p2p.toml.example $(CURDIR)/debian/secubox-p2p/etc/secubox/

	# Install root mesh provisioner CLI
	install -m 755 $(CURDIR)/scripts/sbx-mesh-up $(CURDIR)/debian/secubox-p2p/usr/bin/
```

- [ ] **Step 2: Add `wireguard-tools` to Depends (debian/control)**

```
Depends: ${misc:Depends}, secubox-core (>= 1.0), python3, python3-fastapi | python3-pip, python3-uvicorn | python3-pip, avahi-daemon, avahi-utils, wireguard-tools
```

- [ ] **Step 3: Add changelog entry (top of debian/changelog)**

```
secubox-p2p (1.7.6-1~bookworm1) bookworm; urgency=medium

  * feat(gondwana P1): adopt secubox-p2p as the single mesh owner.
    - api/mesh.py: pure mesh logic (subnet collision guard, p2p.toml
      [wireguard] loader, master-assigned IP allocation, wg.conf
      parse/render, key adoption, per-node DDNS name).
    - WireGuard defaults fixed 10.100.0.0/24->10.10.0.0/24 (br-lxc
      collision), 51820->51822. Role-aware addressing (.1 master).
    - sbx-mesh-up: root provisioner (adopt live key -> guard -> render ->
      wg-quick up); the service user cannot run wg-quick.
    - Depends: wireguard-tools. Ships /etc/secubox/p2p.toml.example.

 -- Gerald KERMA <devel@cybermind.fr>  Mon, 29 Jun 2026 14:00:00 +0200
```

- [ ] **Step 4: Build the package (arch:all)**

Run: `cd packages/secubox-p2p && dpkg-buildpackage -us -uc -b 2>&1 | tail -5`
Expected: `dpkg-deb: building package 'secubox-p2p' in '../secubox-p2p_1.7.6-1~bookworm1_all.deb'.`

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/debian/
git commit -m "build(p2p): ship p2p.toml.example + sbx-mesh-up, dep wireguard-tools, 1.7.6"
```

---

### Task 9: Cutover on gk2 — adopt + master, handshake preserved

**Files:** none (live operation; uses Task 8's `.deb`).

**Interfaces:** Consumes the built `secubox-p2p_1.7.6` deb.

- [ ] **Step 1: Snapshot the live wg-mesh public key BEFORE**

Run: `ssh root@192.168.1.200 'wg show wg-mesh public-key; wg show wg-mesh latest-handshakes'`
Record the public key and that c3box's handshake is recent.

- [ ] **Step 2: Install the new package on gk2 (single unit, no mass restart)**

Run: `scp ../secubox-p2p_1.7.6-1~bookworm1_all.deb root@192.168.1.200:/tmp/ && ssh root@192.168.1.200 'dpkg -i /tmp/secubox-p2p_1.7.6-1~bookworm1_all.deb && systemctl try-restart secubox-p2p'`
Expected: unpacked + configured; only `secubox-p2p` restarts.

- [ ] **Step 3: Write gk2's p2p.toml as master**

Run:
```bash
ssh root@192.168.1.200 'cat > /etc/secubox/p2p.toml <<EOF
[wireguard]
interface = "wg-mesh"
listen_port = 51822
network = "10.10.0.0/24"
role = "master"
EOF
chown secubox:secubox /etc/secubox/p2p.toml'
```

- [ ] **Step 4: Run the provisioner — it must ADOPT the live key**

Run: `ssh root@192.168.1.200 'sbx-mesh-up'`
Expected: `rendered /etc/wireguard/wg-mesh.conf (addr 10.10.0.1/24, peers 1)` then `wg show wg-mesh` output.

- [ ] **Step 5: Verify the public key is UNCHANGED and c3box still configured**

Run: `ssh root@192.168.1.200 'wg show wg-mesh public-key'`
Expected: **identical** to Step 1's key. (If different, adoption failed — restore `/etc/wireguard/wg-mesh.conf.pre` and stop.)

- [ ] **Step 6: Confirm `/wireguard` API truth now matches reality**

Run: `ssh root@192.168.1.200 'curl -s --unix-socket /run/secubox/p2p.sock http://x/wireguard'`
Expected: JSON with `"network":"10.10.0.0/24","listen_port":51822` and `status.running=true`.

- [ ] **Step 7: Commit a note (no code) — record cutover done**

No commit; proceed to Task 10. (Source already carries the change from Task 8.)

---

### Task 10: Freebox forward + enroll amd64 (.3) + verify mesh

**Files:** none (live operation + operator action).

- [ ] **Step 1: OPERATOR ACTION — add Freebox UDP 51822 → 192.168.1.200**

Manual: Freebox OS → Ports → add `UDP 51822 → 192.168.1.200:51822`.
Verify from outside is optional now (amd64 is on the LAN); required when a node goes remote.

- [ ] **Step 2: Install the new package on amd64 (.9)**

Run: `scp ../secubox-p2p_1.7.6-1~bookworm1_all.deb root@192.168.1.9:/tmp/ && ssh root@192.168.1.9 'dpkg -i /tmp/secubox-p2p_1.7.6-1~bookworm1_all.deb'`
Expected: configured.

- [ ] **Step 3: Write amd64's p2p.toml as satellite + init identity**

Run:
```bash
ssh root@192.168.1.9 'cat > /etc/secubox/p2p.toml <<EOF
[wireguard]
interface = "wg-mesh"
listen_port = 51822
network = "10.10.0.0/24"
role = "satellite"
master_endpoint = "82.67.100.75:51822"
EOF
chown secubox:secubox /etc/secubox/p2p.toml
curl -s --unix-socket /run/secubox/p2p.sock -X POST http://x/wireguard/init -H "Authorization: Bearer $(cat /etc/secubox/secrets/*jwt* 2>/dev/null | head -1)"'
```
Expected: JSON with `public_key` and `address` (allocated; will be `.3` once gk2 assigns — see Step 4 note).

- [ ] **Step 4: Register amd64 as a peer on gk2 (.3) and on amd64 (gk2)**

Run (capture amd64 pubkey, then add on gk2; add gk2 on amd64):
```bash
AMD_PUB=$(ssh root@192.168.1.9 'wg show wg-mesh public-key 2>/dev/null || python3 -c "import json;print(json.load(open(\"/var/lib/secubox/p2p/wg_mesh.json\"))[\"public_key\"])"')
GK2_PUB=$(ssh root@192.168.1.200 'wg show wg-mesh public-key')
# gk2: add amd64 as roaming spoke .3/32 (edit state, re-provision)
ssh root@192.168.1.200 "python3 -c \"import json;p='/var/lib/secubox/p2p/wg_mesh.json';d=json.load(open(p));d.setdefault('peers',[]).append({'public_key':'$AMD_PUB','allowed_ips':'10.10.0.3/32'});json.dump(d,open(p,'w'),indent=2)\" && sbx-mesh-up"
# amd64: set address .3 + gk2 peer, provision
ssh root@192.168.1.9 "python3 -c \"import json;p='/var/lib/secubox/p2p/wg_mesh.json';d=json.load(open(p));d['address']='10.10.0.3/24';d['peers']=[{'public_key':'$GK2_PUB','endpoint':'82.67.100.75:51822','allowed_ips':'10.10.0.0/24'}];json.dump(d,open(p,'w'),indent=2)\" && sbx-mesh-up"
```
Expected: both `wg show wg-mesh` list each other.

- [ ] **Step 5: Verify handshakes + inter-node reachability**

Run:
```bash
ssh root@192.168.1.9 'ping -c2 -W2 10.10.0.1'        # amd64 -> gk2
ssh root@192.168.1.200 'ping -c2 -W2 10.10.0.3'      # gk2 -> amd64
ssh root@192.168.1.9 'wg show wg-mesh latest-handshakes'
```
Expected: pings succeed; handshake with gk2 is recent.

- [ ] **Step 6: Verify threatmesh reachability over the mesh**

Run: `ssh root@192.168.1.9 'curl -s -m4 -o /dev/null -w "%{http_code}\n" http://10.10.0.1:8780/api/v1/threatmesh/mesh/ingest -X POST -H "Content-Type: application/json" -d "{}"'`
Expected: a HTTP code (e.g. `400/422/200`) — **not** a timeout/`000` — proving spoke→hub service reachability over wg-mesh.

- [ ] **Step 7: Final source sync check**

Confirm the live `/etc/secubox/p2p.toml` contents and `sbx-mesh-up` behavior match the packaged source (Task 8). If any live tweak was needed, backport it to `conf/p2p.toml.example` or `scripts/sbx-mesh-up` and commit:

```bash
git add -A packages/secubox-p2p/
git commit -m "fix(p2p): backport gondwana P1 cutover tweaks from gk2/amd64"
```

---

## Self-review

**Spec coverage:**
- §2 addressing (10.10.0.0/24, master-assigned, .1/.2/.3) → Tasks 1,3,6,9,10. ✓
- §2 collision guard → Tasks 1,6,7. ✓
- §3 identity (persistent keypair, node-id, DDNS name, live-USB persistence) → Tasks 5,6; persistence is `/var/lib/secubox/p2p` on amd64 partition (Task 10 writes there). ✓
- §4 topology (master roaming peers, satellite endpoint+keepalive, hub routing) → Tasks 4,6,10. ✓
- §5 secubox-p2p changes (config, adoption, provisioning, guard, join wiring) → Tasks 2,4,6,7. ✓
- §6 cutover (gk2 adopt+master, Freebox, amd64 .3, verify, backport) → Tasks 9,10. ✓
- §7 failure modes (key-regen guarded by adopt_state; collision guard; keepalive) → Tasks 7,1,4. ✓

**Placeholder scan:** no TBD/TODO; every code step shows full code; verification steps show exact commands + expected output. ✓

**Type consistency:** `mesh.MESH_NETWORK/MESH_PORT/MESH_INTERFACE`, `subnet_overlap`, `load_p2p_config`, `allocate_mesh_ip`, `parse_wg_conf`, `render_wg_conf`, `ddns_name`, `adopt_state` used consistently across Tasks 1–10. ✓

**Known limitation (documented, not a gap):** inter-satellite (c3box↔amd64) traffic relies on gk2 hub routing; with c3box offline this is unverifiable now — Step 6 verifies spoke→hub, which is the testable subset. Direct spoke-to-spoke verification waits for c3box online.
