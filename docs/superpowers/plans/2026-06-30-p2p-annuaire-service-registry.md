# P2P Service Registry ↔ Annuaire Catalog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the secubox-p2p Service Registry a live, no-drift view of the secubox-annuaire service catalog, with an "Auto register all" action that activates local services and subscribes to remote ones through the existing invite/approval workflow.

**Architecture:** A new pure module (`api/registry.py`) merges three inputs — the annuaire catalog, my annuaire subscriptions, and a thin local "activation overlay" — plus legacy p2p-local services, into the rows the UI shows. A new I/O module (`api/annuaire_client.py`) talks to the local `annuaire.sock` and subscribes *as the node* using the 0600 node key. Four endpoints in `api/main.py` expose the merged view and the activate/subscribe actions. The UI Service Registry tab renders states and adds the "Auto register all" button. annuaire is unchanged.

**Tech Stack:** Python 3.11, FastAPI, `urllib` over a unix-socket HTTP connection (no new deps), pytest, vanilla JS UI.

## Global Constraints

- SPDX header on every new file: `# SPDX-License-Identifier: LicenseRef-CMSD-1.0` + the CyberMind copyright block (copy from `api/mesh.py`).
- secubox-p2p runs as `User=secubox`; both it and secubox-annuaire are `secubox`, so reading `/etc/secubox/secrets/annuaire/node.key` (0600 secubox) is in-policy.
- annuaire is read over **its own** socket `/run/secubox/annuaire.sock`, NEVER the aggregator.
- No new Python dependencies (stdlib `urllib`/`http.client` only).
- No new annuaire model fields, no provider-side macro execution (Milestone 2).
- Debian version bump: `1.7.8` → `1.8.0-1~bookworm1`. Changelog entry required.
- Tests live in `packages/secubox-p2p/tests/`, imported as `from api import <mod>` (see `tests/conftest.py`).
- Never raise into the request path on annuaire-unavailable — degrade gracefully.
- Escape all API-derived strings in the UI via the existing `escapeHtml`.

---

### Task 1: Pure registry merge + activation overlay (`api/registry.py`)

**Files:**
- Create: `packages/secubox-p2p/api/registry.py`
- Test: `packages/secubox-p2p/tests/test_registry.py`

**Interfaces:**
- Consumes: nothing (pure functions + file I/O on an injected path).
- Produces:
  - `load_overlay(path) -> dict` / `save_overlay(path, data) -> None`
  - `set_active(path, service_id, local_port) -> dict`
  - `port_from_endpoint(endpoint: str) -> int | None`
  - `merge_services(catalog: list[dict], subscriptions: list[dict], overlay: dict, legacy: list[dict], local_did: str | None) -> list[dict]`
  - Each merged row: `{service_id, name, type, provider, provider_label, port, approval_mode, subscription_state, active, source, automatable}`
  - `MACRO_KINDS: set[str]` (forward hint set: `{"tor-exit","wg-relay","dns-resolver","http-mirror"}`)

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-p2p/tests/test_registry.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import json
from api import registry


def test_port_from_endpoint():
    assert registry.port_from_endpoint("http://10.10.0.1:9050/x") == 9050
    assert registry.port_from_endpoint("10.10.0.2:3483") == 3483
    assert registry.port_from_endpoint("/local/path") is None
    assert registry.port_from_endpoint("") is None


def test_merge_local_vs_remote_and_state():
    local_did = "did:plc:" + "a" * 32
    remote_did = "did:plc:" + "b" * 32
    catalog = [
        {"service_id": "s1", "name": "WAF mirror", "kind": "module",
         "provider": local_did, "endpoint": "http://10.10.0.1:8085",
         "approval_mode": "auto"},
        {"service_id": "s2", "name": "Tor exit", "kind": "tor-exit",
         "provider": remote_did, "endpoint": "10.10.0.2:9050",
         "approval_mode": "pending"},
    ]
    subs = [{"service_id": "s2", "state": "pending"}]
    overlay = {"s1": {"active": True, "local_port": 8085, "subscription_id": None}}
    rows = registry.merge_services(catalog, subs, overlay, [], local_did)
    by_id = {r["service_id"]: r for r in rows}
    assert by_id["s1"]["provider_label"] == "local"
    assert by_id["s1"]["active"] is True
    assert by_id["s1"]["subscription_state"] == "not-subscribed"
    assert by_id["s2"]["provider_label"] != "local"
    assert by_id["s2"]["subscription_state"] == "pending"
    assert by_id["s2"]["automatable"] is True       # tor-exit ∈ MACRO_KINDS
    assert by_id["s1"]["automatable"] is False


def test_merge_includes_legacy_local():
    legacy = [{"name": "old-svc", "port": 1234, "protocol": "tcp", "active": True}]
    rows = registry.merge_services([], [], {}, legacy, None)
    assert len(rows) == 1
    assert rows[0]["source"] == "p2p-local"
    assert rows[0]["provider_label"] == "local"
    assert rows[0]["port"] == 1234


def test_overlay_roundtrip_and_prune(tmp_path):
    p = tmp_path / "activation.json"
    registry.set_active(str(p), "s1", 8085)
    data = registry.load_overlay(str(p))
    assert data["s1"]["active"] is True and data["s1"]["local_port"] == 8085
    # prune: merge drops overlay-only entries with no catalog/legacy backing
    rows = registry.merge_services([], [], data, [], None)
    assert rows == []


def test_load_overlay_missing_or_corrupt(tmp_path):
    assert registry.load_overlay(str(tmp_path / "nope.json")) == {}
    bad = tmp_path / "bad.json"; bad.write_text("{not json")
    assert registry.load_overlay(str(bad)) == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_registry.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'api.registry'`.

- [ ] **Step 3: Write minimal implementation**

```python
# packages/secubox-p2p/api/registry.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: registry

Pure merge logic for the Service Registry: combines the annuaire catalog, my
subscriptions, the local activation overlay, and legacy p2p-local services into
the rows the UI renders. No network I/O lives here (see annuaire_client.py) so
the merge is fully unit-testable.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Service kinds that (in Milestone 2) carry an executable access macro. In M1
# this only drives a cosmetic "automatable" badge.
MACRO_KINDS = {"tor-exit", "wg-relay", "dns-resolver", "http-mirror"}

_PORT_RE = re.compile(r":(\d{1,5})(?:/|$)")


def port_from_endpoint(endpoint: str) -> Optional[int]:
    """Best-effort extract a TCP port from a host:port or URL endpoint."""
    if not endpoint:
        return None
    m = _PORT_RE.search(endpoint)
    if not m:
        return None
    try:
        p = int(m.group(1))
    except ValueError:
        return None
    return p if 0 < p < 65536 else None


def load_overlay(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_overlay(path: str, data: Dict[str, Any]) -> None:
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def set_active(path: str, service_id: str, local_port: Optional[int],
               subscription_id: Optional[str] = None) -> Dict[str, Any]:
    data = load_overlay(path)
    entry = data.get(service_id, {})
    entry["active"] = True
    entry["local_port"] = local_port
    if subscription_id is not None:
        entry["subscription_id"] = subscription_id
    entry.setdefault("subscription_id", None)
    entry["activated_at"] = datetime.now(timezone.utc).isoformat()
    data[service_id] = entry
    save_overlay(path, data)
    return data


def set_subscription(path: str, service_id: str, subscription_id: str) -> Dict[str, Any]:
    data = load_overlay(path)
    entry = data.get(service_id, {})
    entry["subscription_id"] = subscription_id
    entry.setdefault("active", False)
    entry.setdefault("local_port", None)
    data[service_id] = entry
    save_overlay(path, data)
    return data


def merge_services(catalog: List[Dict], subscriptions: List[Dict],
                   overlay: Dict[str, Any], legacy: List[Dict],
                   local_did: Optional[str]) -> List[Dict]:
    sub_state = {}
    for s in subscriptions or []:
        sid = s.get("service_id")
        if sid:
            sub_state[sid] = s.get("state", "pending")

    rows: List[Dict] = []
    for offer in catalog or []:
        sid = offer.get("service_id")
        if not sid:
            continue
        provider = offer.get("provider")
        is_local = bool(local_did) and provider == local_did
        ov = overlay.get(sid, {})
        kind = offer.get("kind", "")
        rows.append({
            "service_id": sid,
            "name": offer.get("name", ""),
            "type": kind,
            "provider": provider,
            "provider_label": "local" if is_local else _short_did(provider),
            "port": ov.get("local_port") or port_from_endpoint(offer.get("endpoint", "")),
            "approval_mode": offer.get("approval_mode", "auto"),
            "subscription_state": sub_state.get(sid, "not-subscribed"),
            "active": bool(ov.get("active", False)),
            "source": "annuaire",
            "automatable": kind in MACRO_KINDS,
        })

    for svc in legacy or []:
        rows.append({
            "service_id": None,
            "name": svc.get("name", ""),
            "type": svc.get("protocol", svc.get("type", "")),
            "provider": None,
            "provider_label": "local",
            "port": svc.get("port"),
            "approval_mode": None,
            "subscription_state": "n/a",
            "active": bool(svc.get("active", True)),
            "source": "p2p-local",
            "automatable": False,
        })

    rows.sort(key=lambda r: (r["provider_label"] != "local", r["name"].lower()))
    return rows


def _short_did(did: Optional[str]) -> str:
    if not did:
        return "unknown"
    return did[:20] + "…" if len(did) > 21 else did
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_registry.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/api/registry.py packages/secubox-p2p/tests/test_registry.py
git commit -m "feat(p2p): pure registry merge + activation overlay (ref #<issue>)"
```

---

### Task 2: Annuaire client over unix socket (`api/annuaire_client.py`)

**Files:**
- Create: `packages/secubox-p2p/api/annuaire_client.py`
- Test: `packages/secubox-p2p/tests/test_annuaire_client.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `node_identity(key_path=NODE_KEY_PATH) -> tuple[str|None, str|None]` → `(did, priv_hex)` or `(None, None)` if no key.
  - `get_catalog(sock=ANNUAIRE_SOCK) -> tuple[list[dict], str|None]` → `(offers, error)`.
  - `get_subscriptions(mine_did, sock=...) -> tuple[list[dict], str|None]`.
  - `subscribe(service_id, did, priv_hex, sock=...) -> tuple[dict|None, str|None]`.
  - Constants `ANNUAIRE_SOCK = "/run/secubox/annuaire.sock"`, `NODE_KEY_PATH = "/etc/secubox/secrets/annuaire/node.key"`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-p2p/tests/test_annuaire_client.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import http.server, json, socket, threading, os
from api import annuaire_client as ac


def _serve_unix(sock_path, routes):
    """Tiny unix-socket HTTP server. routes: {path: (status, json_obj)}."""
    class H(http.server.BaseHTTPRequestHandler):
        def _send(self):
            body = b""
            for p, (st, obj) in routes.items():
                if self.path == p:
                    body = json.dumps(obj).encode(); st_code = st; break
            else:
                st_code = 404; body = b'{"detail":"nf"}'
            self.send_response(st_code)
            self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(body)
        do_GET = _send
        do_POST = _send
        def log_message(self, *a): pass
    srv = http.server.HTTPServer.__new__(http.server.HTTPServer)
    # bind a unix socket manually
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(sock_path): os.unlink(sock_path)
    s.bind(sock_path); s.listen(8)
    http.server.HTTPServer.__init__(srv, ("localhost", 0), H, bind_and_activate=False)
    srv.socket = s
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    return srv


def test_get_catalog_reads_services(tmp_path):
    sp = str(tmp_path / "ann.sock")
    srv = _serve_unix(sp, {"/api/v1/annuaire/services": (200, {"services": [{"service_id": "s1", "name": "WAF"}]})})
    try:
        offers, err = ac.get_catalog(sock=sp)
        assert err is None
        assert offers[0]["service_id"] == "s1"
    finally:
        srv.shutdown()


def test_get_catalog_socket_missing_returns_error(tmp_path):
    offers, err = ac.get_catalog(sock=str(tmp_path / "nope.sock"))
    assert offers == [] and err is not None


def test_node_identity_reads_key(tmp_path):
    # a 32-byte key hex → deterministic did
    key = tmp_path / "node.key"; key.write_text("11" * 32 + "\n")
    did, priv = ac.node_identity(key_path=str(key))
    assert priv == "11" * 32
    assert did and did.startswith("did:plc:")


def test_node_identity_missing(tmp_path):
    did, priv = ac.node_identity(key_path=str(tmp_path / "nope"))
    assert did is None and priv is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_annuaire_client.py -q`
Expected: FAIL — `No module named 'api.annuaire_client'`.

- [ ] **Step 3: Write minimal implementation**

```python
# packages/secubox-p2p/api/annuaire_client.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-p2p :: annuaire_client

Thin client to the LOCAL secubox-annuaire over its own unix socket
(/run/secubox/annuaire.sock — never the aggregator). Subscribes AS THE NODE
using the 0600 node key shared by the secubox user. Never raises into the
request path: every call returns (data, error).
"""
from __future__ import annotations

import hashlib
import http.client
import json
import socket as _socket
from typing import Any, Dict, List, Optional, Tuple

ANNUAIRE_SOCK = "/run/secubox/annuaire.sock"
NODE_KEY_PATH = "/etc/secubox/secrets/annuaire/node.key"
_TIMEOUT = 3.0


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, sock_path: str, timeout: float = _TIMEOUT):
        super().__init__("localhost", timeout=timeout)
        self._sock_path = sock_path

    def connect(self):
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._sock_path)
        self.sock = s


def _request(method: str, path: str, sock: str,
             body: Optional[dict] = None) -> Tuple[Optional[Any], Optional[str]]:
    try:
        conn = _UnixHTTPConnection(sock)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        if resp.status >= 400:
            return None, f"annuaire {method} {path} -> {resp.status}"
        return (json.loads(raw) if raw else {}), None
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


def did_from_pubkey_hex(pub_hex: str) -> str:
    return "did:plc:" + hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:32]


def node_identity(key_path: str = NODE_KEY_PATH) -> Tuple[Optional[str], Optional[str]]:
    """Return (did, priv_hex) from the node key, or (None, None) if absent."""
    try:
        with open(key_path, "r", encoding="ascii") as fh:
            priv_hex = fh.read().strip()
        priv = bytes.fromhex(priv_hex)
        if len(priv) != 32:
            return None, None
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        pub = ed25519.Ed25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return did_from_pubkey_hex(pub.hex()), priv_hex
    except Exception:
        return None, None


def get_catalog(sock: str = ANNUAIRE_SOCK) -> Tuple[List[Dict], Optional[str]]:
    data, err = _request("GET", "/api/v1/annuaire/services", sock)
    if err:
        return [], err
    return (data or {}).get("services", []), None


def get_subscriptions(mine_did: Optional[str] = None,
                      sock: str = ANNUAIRE_SOCK) -> Tuple[List[Dict], Optional[str]]:
    path = "/api/v1/annuaire/subscriptions"
    if mine_did:
        path += f"?mine={mine_did}"
    data, err = _request("GET", path, sock)
    if err:
        return [], err
    return (data or {}).get("subscriptions", []), None


def subscribe(service_id: str, did: str, priv_hex: str,
              sock: str = ANNUAIRE_SOCK) -> Tuple[Optional[Dict], Optional[str]]:
    return _request("POST", f"/api/v1/annuaire/service/{service_id}/subscribe", sock,
                    body={"subscriber_did": did, "subscriber_priv_hex": priv_hex})
```

Note: `did_from_pubkey_hex` mirrors `annuaire/crypto.did_from_pubkey` exactly (sha256(pubkey)[:32]); the test pins it.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_annuaire_client.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/api/annuaire_client.py packages/secubox-p2p/tests/test_annuaire_client.py
git commit -m "feat(p2p): annuaire unix-socket client + node-key identity (ref #<issue>)"
```

---

### Task 3: Wire the endpoints in `api/main.py`

**Files:**
- Modify: `packages/secubox-p2p/api/main.py` (add `ACTIVATION_FILE`, replace `GET /services`, add 3 endpoints; import the two new modules)
- Test: `packages/secubox-p2p/tests/test_services_endpoints.py`

**Interfaces:**
- Consumes: `registry.merge_services/load_overlay/set_active/set_subscription/port_from_endpoint`, `annuaire_client.get_catalog/get_subscriptions/subscribe/node_identity`.
- Produces (HTTP): `GET /services`, `POST /services/auto-register`, `POST /services/{service_id}/request`, `POST /services/{service_id}/activate`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-p2p/tests/test_services_endpoints.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
import pytest
from fastapi.testclient import TestClient
from api import main, annuaire_client, registry


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ACTIVATION_FILE", tmp_path / "activation.json")
    monkeypatch.setattr(main, "SERVICES_FILE", tmp_path / "services.json")
    local = "did:plc:" + "a" * 32
    remote = "did:plc:" + "b" * 32
    monkeypatch.setattr(annuaire_client, "node_identity", lambda *a, **k: (local, "11" * 32))
    monkeypatch.setattr(annuaire_client, "get_catalog", lambda *a, **k: ([
        {"service_id": "s1", "name": "WAF", "kind": "module", "provider": local,
         "endpoint": "http://10.10.0.1:8085", "approval_mode": "auto"},
        {"service_id": "s2", "name": "Tor", "kind": "tor-exit", "provider": remote,
         "endpoint": "10.10.0.2:9050", "approval_mode": "auto"},
    ], None))
    monkeypatch.setattr(annuaire_client, "get_subscriptions", lambda *a, **k: ([], None))
    calls = []
    def fake_sub(sid, did, priv, **k):
        calls.append(sid); return ({"subscription_id": "sub-" + sid, "state": "approved"}, None)
    monkeypatch.setattr(annuaire_client, "subscribe", fake_sub)
    main._test_sub_calls = calls
    return TestClient(main.app)


def test_services_merges_catalog(client):
    r = client.get("/services")
    assert r.status_code == 200
    rows = r.json()["services"]
    ids = {row["service_id"] for row in rows}
    assert "s1" in ids and "s2" in ids


def test_auto_register_activates_local_and_subscribes_remote(client):
    r = client.post("/services/auto-register")
    assert r.status_code == 200
    body = r.json()
    assert body["activated"] >= 1     # s1 local
    assert body["requested"] >= 1     # s2 remote subscribed
    assert "s2" in main._test_sub_calls
    # s1 now active in the overlay-backed view
    rows = {x["service_id"]: x for x in client.get("/services").json()["services"]}
    assert rows["s1"]["active"] is True


def test_catalog_unavailable_degrades(client, monkeypatch):
    monkeypatch.setattr(annuaire_client, "get_catalog", lambda *a, **k: ([], "socket down"))
    r = client.get("/services")
    assert r.status_code == 200
    assert r.json().get("catalog_unavailable") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_services_endpoints.py -q`
Expected: FAIL — `AttributeError: module 'api.main' has no attribute 'ACTIVATION_FILE'` (or the new endpoints 404 / return the old shape).

- [ ] **Step 3: Write minimal implementation**

In `api/main.py`, near the other `_FILE` constants (after line ~46) add:

```python
ACTIVATION_FILE = P2P_DIR / "activation.json"
```

Near the top imports (after `from api import mesh` if present, else add):

```python
from api import registry, annuaire_client
```

Replace the existing `GET /services` handler (the `list_services` function) with:

```python
@app.get("/services")
async def list_services():
    """Live view: annuaire catalog ⨝ my subscriptions ⨝ activation overlay ⨝ legacy."""
    init_dirs()
    local_did, _ = annuaire_client.node_identity()
    catalog, cat_err = annuaire_client.get_catalog()
    subs, _ = annuaire_client.get_subscriptions(local_did)
    overlay = registry.load_overlay(str(ACTIVATION_FILE))
    legacy = load_json(SERVICES_FILE, [])
    legacy = legacy if isinstance(legacy, list) else []
    rows = registry.merge_services(catalog, subs, overlay, legacy, local_did)
    out = {"services": rows}
    if cat_err:
        out["catalog_unavailable"] = True
        out["catalog_error"] = cat_err
    return out
```

After the `unregister_service` handler, add:

```python
@app.post("/services/auto-register")
async def auto_register(user: dict = Depends(require_jwt)):
    """Activate local catalog services + subscribe to remote ones (per approval mode)."""
    init_dirs()
    local_did, priv = annuaire_client.node_identity()
    catalog, cat_err = annuaire_client.get_catalog()
    if cat_err:
        return {"activated": 0, "requested": 0, "pending": 0, "already": 0,
                "errors": [cat_err]}
    subs, _ = annuaire_client.get_subscriptions(local_did)
    subscribed = {s.get("service_id") for s in subs}
    overlay = registry.load_overlay(str(ACTIVATION_FILE))
    activated = requested = pending = already = 0
    errors = []
    for offer in catalog:
        sid = offer.get("service_id")
        if not sid:
            continue
        if offer.get("provider") == local_did:
            registry.set_active(str(ACTIVATION_FILE), sid,
                                registry.port_from_endpoint(offer.get("endpoint", "")))
            activated += 1
            continue
        if sid in subscribed or (overlay.get(sid, {}).get("subscription_id")):
            already += 1
            continue
        if not priv or not local_did:
            errors.append(f"{sid}: node has no annuaire identity (run annuairectl init)")
            continue
        res, err = annuaire_client.subscribe(sid, local_did, priv)
        if err:
            errors.append(f"{sid}: {err}")
            continue
        registry.set_subscription(str(ACTIVATION_FILE), sid, res.get("subscription_id", ""))
        requested += 1
        if res.get("state") == "pending":
            pending += 1
    return {"activated": activated, "requested": requested, "pending": pending,
            "already": already, "errors": errors}


@app.post("/services/{service_id}/request")
async def request_access(service_id: str, user: dict = Depends(require_jwt)):
    """Subscribe to a single remote service offer."""
    init_dirs()
    local_did, priv = annuaire_client.node_identity()
    if not priv or not local_did:
        return {"status": "error", "error": "node has no annuaire identity (run annuairectl init)"}
    res, err = annuaire_client.subscribe(service_id, local_did, priv)
    if err:
        return {"status": "error", "error": err}
    registry.set_subscription(str(ACTIVATION_FILE), service_id, res.get("subscription_id", ""))
    return {"status": "ok", "subscription": res}


@app.post("/services/{service_id}/activate")
async def activate_service(service_id: str, user: dict = Depends(require_jwt)):
    """Mark a catalog service locally active (binds the derived local port)."""
    init_dirs()
    catalog, _ = annuaire_client.get_catalog()
    offer = next((o for o in catalog if o.get("service_id") == service_id), None)
    if offer is None:
        return {"status": "error", "error": "service not in catalog"}
    local_did, _ = annuaire_client.node_identity()
    if offer.get("provider") != local_did:
        subs, _ = annuaire_client.get_subscriptions(local_did)
        st = next((s.get("state") for s in subs if s.get("service_id") == service_id), None)
        if st != "approved":
            return {"status": "error", "error": f"remote service not approved (state={st})"}
    registry.set_active(str(ACTIVATION_FILE), service_id,
                        registry.port_from_endpoint(offer.get("endpoint", "")))
    return {"status": "ok"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-p2p && python3 -m pytest tests/test_services_endpoints.py -q`
Expected: PASS (3 tests). Then run the whole suite: `python3 -m pytest tests/ -q` — all green.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/api/main.py packages/secubox-p2p/tests/test_services_endpoints.py
git commit -m "feat(p2p): /services live merge + auto-register/request/activate endpoints (ref #<issue>)"
```

---

### Task 4: UI — Service Registry tab live view + Auto register all

**Files:**
- Modify: `packages/secubox-p2p/www/p2p/index.html` (the Services tab header + `loadServices()` render + new action functions)

**Interfaces:**
- Consumes (HTTP): `GET /services` (new row shape), `POST /services/auto-register`, `POST /services/{id}/request`, `POST /services/{id}/activate`.

- [ ] **Step 1: Add the "Auto register all" button to the Services tab header**

Find the Services tab `section-header` (around line 554) and change it to:

```html
            <div class="section-header">
                <h2>Service Registry</h2>
                <div>
                    <button class="btn" onclick="autoRegisterAll()">Auto register all</button>
                    <button class="btn" onclick="showRegisterServiceModal()">+ Register Service</button>
                </div>
            </div>
```

- [ ] **Step 2: Replace `loadServices()` render to the new row shape**

Replace the `loadServices()` body (around line 784) with:

```javascript
        async function loadServices() {
            const data = await apiGet('/services');
            const services = Array.isArray(data) ? data : (data && Array.isArray(data.services) ? data.services : []);
            const tbody = document.getElementById('services-table');
            if (data && data.catalog_unavailable) {
                showNotice && showNotice('Annuaire catalog unavailable — showing local services only');
            }
            if (services.length > 0) {
                tbody.innerHTML = services.map(svc => {
                    const state = svc.subscription_state || 'n/a';
                    const statusLabel = svc.active ? 'active' : (state === 'n/a' ? (svc.active ? 'active' : 'inactive') : state);
                    const badge = svc.automatable ? ' <span class="status-badge">automatable</span>' : '';
                    let actions = '';
                    if (svc.source === 'p2p-local') {
                        actions = `<button class="btn btn-small btn-danger" onclick="unregisterService('${encodeURIComponent(svc.name)}')">Unregister</button>`;
                    } else if (svc.provider_label !== 'local' && state === 'not-subscribed') {
                        actions = `<button class="btn btn-small" onclick="requestAccess('${svc.service_id}')">Request access</button>`;
                    } else if (state === 'pending') {
                        actions = `<span class="text-muted">awaiting approval</span>`;
                    } else if (!svc.active) {
                        actions = `<button class="btn btn-small" onclick="activateService('${svc.service_id}')">Activate</button>`;
                    } else {
                        actions = `<span class="status-badge active">active</span>`;
                    }
                    return `
                    <tr>
                        <td>${escapeHtml(svc.name)}${badge}</td>
                        <td>${escapeHtml(svc.type || '')}</td>
                        <td>${escapeHtml(svc.provider_label || 'local')}</td>
                        <td>${svc.port != null ? svc.port : '—'}</td>
                        <td><span class="status-badge ${svc.active ? 'active' : ''}">${escapeHtml(statusLabel)}</span></td>
                        <td>${actions}</td>
                    </tr>`;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="6">No services in catalog</td></tr>';
            }
        }
```

- [ ] **Step 3: Add the action functions** (next to `loadServices`)

```javascript
        async function autoRegisterAll() {
            const res = await apiPost('/services/auto-register', {});
            const msg = `Activated ${res.activated||0}, requested ${res.requested||0}` +
                        (res.pending ? `, ${res.pending} pending approval` : '') +
                        (res.errors && res.errors.length ? `, ${res.errors.length} error(s)` : '');
            (showNotice ? showNotice(msg) : alert(msg));
            loadServices();
        }
        async function requestAccess(sid) {
            const res = await apiPost('/services/' + encodeURIComponent(sid) + '/request', {});
            (showNotice ? showNotice(res.status === 'ok' ? 'Subscription requested' : (res.error||'failed')) : 0);
            loadServices();
        }
        async function activateService(sid) {
            const res = await apiPost('/services/' + encodeURIComponent(sid) + '/activate', {});
            (showNotice ? showNotice(res.status === 'ok' ? 'Activated' : (res.error||'failed')) : 0);
            loadServices();
        }
```

(If `showNotice` does not exist in this file, replace the `showNotice ? ... : 0` calls with `console.log(...)` — check the file first and match the existing notification pattern.)

- [ ] **Step 4: Syntax-check the JS**

Run: `cd packages/secubox-p2p && node --check www/p2p/index.html 2>/dev/null || python3 -c "import re,sys;h=open('www/p2p/index.html').read();print('script blocks:',h.count('<script'))"`
Expected: no JS parse error (or, if `node --check` rejects HTML, extract the `<script>` block and `node --check` that). Manually confirm braces balance.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-p2p/www/p2p/index.html
git commit -m "feat(p2p): Service Registry live catalog view + Auto register all UI (ref #<issue>)"
```

---

### Task 5: Packaging, build, deploy, live verify

**Files:**
- Modify: `packages/secubox-p2p/debian/changelog`
- Verify: `packages/secubox-p2p/debian/rules` installs `api/*.py` (confirm `api/registry.py` + `api/annuaire_client.py` are copied — they will be if rules does `cp -r api/* …/api/`).

- [ ] **Step 1: Confirm rules ships the new modules**

Run: `grep -nE "cp -r .*api|api/\*|install.*api" packages/secubox-p2p/debian/rules`
Expected: a recursive copy of `api/` (so new `.py` files ship automatically). If rules lists individual files, add `api/registry.py` and `api/annuaire_client.py`.

- [ ] **Step 2: Add the changelog entry**

Prepend to `packages/secubox-p2p/debian/changelog`:

```
secubox-p2p (1.8.0-1~bookworm1) bookworm; urgency=medium

  * feat: Service Registry is now a live view of the secubox-annuaire catalog
    (#<issue>). New api/registry.py (pure merge of catalog + subscriptions +
    activation overlay + legacy local services) and api/annuaire_client.py
    (reads /run/secubox/annuaire.sock — never the aggregator — and subscribes
    as the node using the 0600 node key). New endpoints: GET /services (live
    merge), POST /services/auto-register (activate locals + subscribe remotes
    per approval mode), /services/{id}/request, /services/{id}/activate. UI:
    "Auto register all" button + per-service Request access / Activate + state
    badges. annuaire unchanged; provider-side macro execution deferred (M2).

 -- Gerald Kerma <devel@cybermind.fr>  Tue, 30 Jun 2026 18:00:00 +0200
```

- [ ] **Step 3: Build the package**

Run: `cd packages/secubox-p2p && dpkg-buildpackage -us -uc -b 2>&1 | grep -iE "dpkg-deb: building|error"`
Expected: `secubox-p2p_1.8.0-1~bookworm1_all.deb` built (or `_arm64` if arch-specific — match the existing control Architecture).

- [ ] **Step 4: Deploy to gk2 + c3box and verify**

```bash
DEB=packages/secubox-p2p_1.8.0-1~bookworm1_all.deb
for H in 192.168.1.200 192.168.1.94; do
  scp "$DEB" root@$H:/tmp/
  ssh root@$H 'dpkg -i /tmp/secubox-p2p_1.8.0-1~bookworm1_all.deb && systemctl restart secubox-p2p && sleep 1 && \
    curl -s --unix-socket /run/secubox/p2p.sock http://x/services | python3 -c "import sys,json;d=json.load(sys.stdin);print(\"rows:\",len(d[\"services\"]),\"unavailable:\",d.get(\"catalog_unavailable\",False))"'
done
```
Expected: gk2 shows ≥1 row (the `WAF mirror` it offers + the federated `Suricata IDS feed`); c3box shows its offers + federated ones. `catalog_unavailable: False`.

- [ ] **Step 5: Live auto-register check + commit**

```bash
ssh root@192.168.1.200 'curl -s -X POST --unix-socket /run/secubox/p2p.sock http://x/services/auto-register | python3 -m json.tool'
```
Expected: `{"activated": N, "requested": M, ...}` with no fatal errors (local WAF mirror activated; remote offers subscribed).

```bash
git add packages/secubox-p2p/debian/changelog
git commit -m "release(p2p): 1.8.0 — annuaire-backed Service Registry (ref #<issue>)"
```

---

## Notes for the executor
- Replace `#<issue>` with the GitHub issue number created for this work.
- Run the **full** p2p test suite (`pytest tests/ -q`) after Task 3 and again after Task 4 — `test_mesh.py` must stay green.
- The UI step has no automated test (repo convention); verify by loading `/p2p/` and clicking Auto register all after deploy.
- Do NOT touch annuaire, the macro subsystem, or the gk2→c3box reverse-federation issue — all out of scope for this plan.
