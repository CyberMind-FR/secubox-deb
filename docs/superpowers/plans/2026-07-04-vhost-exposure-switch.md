# Per-vhost Exposure Switch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A per-vhost exposure switch — network reach `localhost|lan|wan` + additive `mesh`/`tor` — configured in secubox-exposure (which writes a per-vhost nginx include snippet) and displayed in secubox-vhost.

**Architecture:** secubox-exposure owns the per-vhost exposure record and translates `reach + mesh` into an nginx `allow`/`deny` snippet at `/etc/nginx/snippets/exposure/<vhost>.conf` (real_ip-aware), applied atomically with `nginx -t` before reload. Each vhost includes that snippet once. secubox-vhost derives and shows the exposure state by reading the snippet. Tor/mesh channels reuse the existing exposure mechanisms.

**Tech Stack:** Python 3.11 (stdlib + pydantic v2), FastAPI on a unix socket, nginx snippets, existing secubox-exposure/secubox-vhost modules.

## Global Constraints

- Reach values are exactly `"localhost"`, `"lan"`, `"wan"`. Default record: `reach="lan", mesh=False, tor=False`.
- Snippet path: `/etc/nginx/snippets/exposure/<vhost>.conf`. LAN CIDRs: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, plus `127.0.0.1`. Mesh CIDR: `10.10.0.0/24`. `wan` → empty snippet (no restriction).
- The `allow`/`deny` gate matches `$remote_addr`; it is only effective because of the GLOBAL `set_real_ip_from`/`real_ip_header X-Forwarded-For` shipped by secubox-hub (`nginx/secubox-lan-geo.conf`). Do not re-declare real_ip per vhost.
- NEVER edit a vhost's own config file — only the per-vhost snippet.
- Apply is fail-safe: write to a temp file, `nginx -t`, then `os.replace`; on any error keep the last-good snippet. Every exposure change appends to `/var/log/secubox/audit.log`.
- Default LAN-only, but NO silent re-confinement: a vhost's first exposure record is created from its CURRENT effective reach (a currently-public vhost → `wan`), not blindly `lan`.
- Python SPDX header block on every new `.py`. Endpoints guarded by `Depends(require_jwt)`.
- An `include` of a missing file is a hard nginx error → the snippet file MUST exist before a vhost includes it (packaging ships a default, and the generator always writes one).

---

## File Structure

- `packages/secubox-exposure/api/reach.py` — NEW: reach constants, `reach_snippet()` (pure), `snippet_path()`, `write_snippet()` (atomic), `read_snippet_reach()`.
- `packages/secubox-exposure/api/main.py` — MODIFY: `Reach` values on the record, `GET/POST /exposure/{vhost}`, apply (snippet + `nginx -t` + reload + audit).
- `packages/secubox-exposure/tests/test_reach.py` — snippet golden + round-trip.
- `packages/secubox-exposure/tests/test_exposure_api.py` — API set/get.
- `packages/secubox-vhost/api/exposure_read.py` — NEW: `read_exposure(vhost)` (pure, reads the snippet).
- `packages/secubox-vhost/api/main.py` — MODIFY: add `exposure` to each `/vhosts` entry.
- `packages/secubox-vhost/tests/test_exposure_read.py` — tests.
- `packages/secubox-exposure/www/exposure/index.html` — MODIFY/ADD: reach slider + mesh/Tor toggles per vhost.
- `packages/secubox-vhost/www/…/index.html` — MODIFY: per-vhost exposure badge.
- `packages/secubox-exposure/conf/nginx-exposure-default.conf` — NEW: default `lan` snippet shipped by packaging (fallback so includes never 500).
- Wiring: secubox-vhost's generated-vhost template + the zigbee/lyrion hand-vhosts get one `include` line.

Run Python tests from the package dir with `PYTHONPATH="$(git rev-parse --show-toplevel)/common:."`.

---

## Task 1: reach snippet generator (pure)

**Files:**
- Create: `packages/secubox-exposure/api/reach.py`
- Test: `packages/secubox-exposure/tests/test_reach.py`

**Interfaces:**
- Produces: `REACH_LEVELS=("localhost","lan","wan")`, `reach_snippet(reach:str, mesh:bool)->str`, `snippet_path(vhost:str)->Path`, `SNIPPET_DIR`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-exposure/tests/test_reach.py
from api.reach import reach_snippet, snippet_path, REACH_LEVELS
import pytest

def test_localhost():
    assert reach_snippet("localhost", False) == "allow 127.0.0.1;\ndeny all;\n"

def test_lan_has_rfc1918_and_localhost():
    s = reach_snippet("lan", False)
    for frag in ("allow 127.0.0.1;", "allow 10.0.0.0/8;", "allow 172.16.0.0/12;",
                 "allow 192.168.0.0/16;", "deny all;"):
        assert frag in s
    assert "10.10.0.0/24" not in s   # mesh off

def test_wan_is_empty_public():
    assert reach_snippet("wan", False) == ""

def test_mesh_adds_mesh_cidr_and_still_denies():
    s = reach_snippet("localhost", True)
    assert "allow 10.10.0.0/24;" in s and "deny all;" in s

def test_wan_plus_mesh_still_public():
    assert reach_snippet("wan", True) == ""   # public already covers mesh

def test_invalid_reach_raises():
    with pytest.raises(ValueError):
        reach_snippet("internet", False)

def test_snippet_path():
    assert str(snippet_path("zigbee.gk2.secubox.in")).endswith(
        "/etc/nginx/snippets/exposure/zigbee.gk2.secubox.in.conf")

def test_reach_levels():
    assert REACH_LEVELS == ("localhost", "lan", "wan")
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-exposure && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_reach.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```python
# packages/secubox-exposure/api/reach.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure.reach — per-vhost nginx reach snippet (pure + atomic)."""
import os
from pathlib import Path

REACH_LEVELS = ("localhost", "lan", "wan")
LAN_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
MESH_CIDR = "10.10.0.0/24"
SNIPPET_DIR = Path(os.environ.get("EXPOSURE_SNIPPET_DIR", "/etc/nginx/snippets/exposure"))


def reach_snippet(reach: str, mesh: bool) -> str:
    """Build the nginx allow/deny block for a reach level (+ mesh CIDR).

    Matches $remote_addr — only effective with the global real_ip rewrite.
    wan → "" (public). localhost/lan → allow-list + terminal `deny all;`.
    """
    if reach not in REACH_LEVELS:
        raise ValueError(f"invalid reach: {reach!r}")
    if reach == "wan":
        return ""  # public; mesh adds nothing to an already-open gate
    lines = ["allow 127.0.0.1;"]
    if reach == "lan":
        lines += [f"allow {c};" for c in LAN_CIDRS]
    if mesh:
        lines.append(f"allow {MESH_CIDR};")
    lines.append("deny all;")
    return "\n".join(lines) + "\n"


def snippet_path(vhost: str) -> Path:
    return SNIPPET_DIR / f"{vhost}.conf"
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-exposure && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_reach.py -q`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-exposure/api/reach.py packages/secubox-exposure/tests/test_reach.py
git commit -m "feat(exposure): pure reach snippet generator (ref #793)"
```

---

## Task 2: atomic snippet write + read-back

**Files:**
- Modify: `packages/secubox-exposure/api/reach.py`
- Test: `packages/secubox-exposure/tests/test_reach.py` (add)

**Interfaces:**
- Consumes: `reach_snippet`, `snippet_path`.
- Produces: `write_snippet(vhost, reach, mesh)->None`; `read_snippet_reach(vhost)->dict` returning `{"reach":str,"mesh":bool}` (or `{"reach":"wan","mesh":False}` when the file is missing/empty).

- [ ] **Step 1: Write the failing test**

```python
# append to packages/secubox-exposure/tests/test_reach.py
def test_write_and_read_roundtrip(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    r.write_snippet("a.example", "lan", True)
    got = r.read_snippet_reach("a.example")
    assert got == {"reach": "lan", "mesh": True}

def test_read_missing_is_wan(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    assert r.read_snippet_reach("nope.example") == {"reach": "wan", "mesh": False}

def test_write_wan_then_read(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    r.write_snippet("b.example", "wan", False)
    assert r.read_snippet_reach("b.example") == {"reach": "wan", "mesh": False}

def test_write_localhost(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    r.write_snippet("c.example", "localhost", False)
    assert r.read_snippet_reach("c.example") == {"reach": "localhost", "mesh": False}
    assert not (tmp_path / "c.example.conf.tmp").exists()
```

Note: the read/write must reference `SNIPPET_DIR` at call time (so tests can monkeypatch it), not a value captured at import — use `snippet_path` recomputed inside, or `r.SNIPPET_DIR / f"{vhost}.conf"` directly.

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-exposure && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_reach.py -q`
Expected: FAIL — `write_snippet` undefined.

- [ ] **Step 3: Implement (append to reach.py)**

```python
def write_snippet(vhost: str, reach: str, mesh: bool) -> None:
    """Atomically write the vhost's exposure snippet (temp + os.replace)."""
    content = reach_snippet(reach, mesh)
    SNIPPET_DIR.mkdir(parents=True, exist_ok=True)
    dst = SNIPPET_DIR / f"{vhost}.conf"
    tmp = SNIPPET_DIR / f"{vhost}.conf.tmp"
    tmp.write_text(content)
    os.replace(tmp, dst)


def read_snippet_reach(vhost: str) -> dict:
    """Derive {reach, mesh} from the on-disk snippet. Missing/empty → wan."""
    p = SNIPPET_DIR / f"{vhost}.conf"
    try:
        content = p.read_text()
    except OSError:
        return {"reach": "wan", "mesh": False}
    mesh = MESH_CIDR in content
    if content.strip() == "":
        reach = "wan"
    elif any(c in content for c in LAN_CIDRS):
        reach = "lan"
    else:
        reach = "localhost"
    return {"reach": reach, "mesh": mesh}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-exposure && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_reach.py -q`
Expected: PASS (12 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-exposure/api/reach.py packages/secubox-exposure/tests/test_reach.py
git commit -m "feat(exposure): atomic snippet write + reach read-back (ref #793)"
```

---

## Task 3: exposure record store (per-vhost, default from current reach)

**Files:**
- Modify: `packages/secubox-exposure/api/reach.py`
- Test: `packages/secubox-exposure/tests/test_reach.py` (add)

**Interfaces:**
- Produces: `load_record(vhost, is_public_now:bool)->dict` returning `{"vhost","reach","mesh","tor"}` — reads the snippet if present, else defaults (`reach="wan"` if `is_public_now` else `"lan"`; mesh/tor False). `tor` comes from the caller (Task 4 passes the tor state); here default `False`.

- [ ] **Step 1: Write the failing test**

```python
# append to test_reach.py
def test_load_record_defaults_public_to_wan(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    rec = r.load_record("pub.example", is_public_now=True)
    assert rec == {"vhost": "pub.example", "reach": "wan", "mesh": False, "tor": False}

def test_load_record_defaults_private_to_lan(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    rec = r.load_record("priv.example", is_public_now=False)
    assert rec == {"vhost": "priv.example", "reach": "lan", "mesh": False, "tor": False}

def test_load_record_reads_existing_snippet(tmp_path, monkeypatch):
    import api.reach as r
    monkeypatch.setattr(r, "SNIPPET_DIR", tmp_path)
    r.write_snippet("x.example", "localhost", True)
    rec = r.load_record("x.example", is_public_now=True)
    assert rec["reach"] == "localhost" and rec["mesh"] is True
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-exposure && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_reach.py -q`
Expected: FAIL — `load_record` undefined.

- [ ] **Step 3: Implement (append to reach.py)**

```python
def load_record(vhost: str, is_public_now: bool) -> dict:
    """Current exposure record for a vhost.

    If a snippet exists, derive from it. Otherwise the DEFAULT is 'lan' — except
    a currently-public vhost defaults to 'wan' so first adoption never silently
    re-confines a live public service. tor is False here (the API overlays state).
    """
    p = SNIPPET_DIR / f"{vhost}.conf"
    if p.exists():
        rr = read_snippet_reach(vhost)
        return {"vhost": vhost, "reach": rr["reach"], "mesh": rr["mesh"], "tor": False}
    return {"vhost": vhost, "reach": "wan" if is_public_now else "lan",
            "mesh": False, "tor": False}
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-exposure && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_reach.py -q`
Expected: PASS (15 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-exposure/api/reach.py packages/secubox-exposure/tests/test_reach.py
git commit -m "feat(exposure): per-vhost record with safe default (ref #793)"
```

---

## Task 4: exposure API — GET/POST /exposure/{vhost} + apply

**Files:**
- Modify: `packages/secubox-exposure/api/main.py`
- Test: `packages/secubox-exposure/tests/test_exposure_api.py`

**Interfaces:**
- Consumes: `reach.load_record`, `reach.write_snippet`, `reach.REACH_LEVELS`.
- Produces endpoints (aggregator-mounted at `/api/v1/exposure/`): `GET /exposure/{vhost}` → the record; `POST /exposure/{vhost}` body `{reach, mesh, tor}` → applies (write snippet, `nginx -t` && reload, audit) and returns the new record. `_apply_reach(vhost, reach, mesh)` runs `nginx -t` before reload and is fail-safe.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-exposure/tests/test_exposure_api.py
import importlib, sys
from pathlib import Path
from fastapi.testclient import TestClient
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "common")); sys.path.insert(0, str(ROOT / "packages" / "secubox-exposure"))

def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPOSURE_SNIPPET_DIR", str(tmp_path / "snip"))
    import api.reach as r; importlib.reload(r)
    import api.main as m; importlib.reload(m)
    monkeypatch.setattr(m, "_reload_nginx", lambda: True)     # no live reload in tests
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    return TestClient(m.app)

def test_post_sets_reach_and_writes_snippet(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    r = c.post("/exposure/z.example", json={"reach": "lan", "mesh": True, "tor": False})
    assert r.status_code == 200
    body = r.json()
    assert body["reach"] == "lan" and body["mesh"] is True
    snip = (tmp_path / "snip" / "z.example.conf").read_text()
    assert "allow 10.10.0.0/24;" in snip and "deny all;" in snip

def test_get_reflects_written_state(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    c.post("/exposure/z.example", json={"reach": "localhost", "mesh": False, "tor": False})
    got = c.get("/exposure/z.example").json()
    assert got["reach"] == "localhost"

def test_post_rejects_bad_reach(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.post("/exposure/z.example", json={"reach": "moon", "mesh": False, "tor": False}).status_code == 422
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-exposure && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_exposure_api.py -q`
Expected: FAIL — endpoints/`_reload_nginx` undefined.

- [ ] **Step 3: Implement (add to main.py)**

Add near the other imports:

```python
import subprocess
from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel
from api import reach as _reach


class ExposureSet(BaseModel):
    reach: Literal["localhost", "lan", "wan"]
    mesh: bool = False
    tor: bool = False


def _reload_nginx() -> bool:
    """nginx -t then reload. Returns True on success (fail-safe: no raise)."""
    try:
        if subprocess.run(["nginx", "-t"], capture_output=True, timeout=10).returncode != 0:
            return False
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=15)
        return True
    except Exception:
        return False


def _audit_exposure(vhost: str, rec: dict, user: str) -> None:
    try:
        ap = Path("/var/log/secubox/audit.log")
        ap.parent.mkdir(parents=True, exist_ok=True)
        with ap.open("a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} exposure {vhost} "
                    f"reach={rec['reach']} mesh={rec['mesh']} tor={rec['tor']} by={user}\n")
    except OSError:
        pass


@app.get("/exposure/{vhost}")
async def get_exposure(vhost: str, user: dict = Depends(require_jwt)):
    # is_public_now: unknown here without the vhost list; default False (→ lan) when
    # no snippet — the vhost module seeds public vhosts to wan on first adoption.
    return _reach.load_record(vhost, is_public_now=False)


@app.post("/exposure/{vhost}")
async def set_exposure(vhost: str, body: ExposureSet, user: dict = Depends(require_jwt)):
    _reach.write_snippet(vhost, body.reach, body.mesh)
    _reload_nginx()
    rec = {"vhost": vhost, "reach": body.reach, "mesh": body.mesh, "tor": body.tor}
    _audit_exposure(vhost, rec, user.get("sub", "?"))
    # tor toggle reuses existing /tor/add|remove; wired by the webui, not duplicated here.
    return rec
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-exposure && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_exposure_api.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-exposure/api/main.py packages/secubox-exposure/tests/test_exposure_api.py
git commit -m "feat(exposure): /exposure/{vhost} get+set with fail-safe apply + audit (ref #793)"
```

---

## Task 5: secubox-vhost — read exposure (pure) + expose on /vhosts

**Files:**
- Create: `packages/secubox-vhost/api/exposure_read.py`
- Modify: `packages/secubox-vhost/api/main.py` (the `/vhosts` entry dict)
- Test: `packages/secubox-vhost/tests/test_exposure_read.py`

**Interfaces:**
- Produces: `read_exposure(vhost, snippet_dir=None)->dict` `{"reach","mesh"}` (mirrors exposure's read; missing → wan). Each `/vhosts` entry gains `"exposure": {"reach","mesh"}`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-vhost/tests/test_exposure_read.py
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages" / "secubox-vhost"))
from api.exposure_read import read_exposure

def test_missing_is_wan(tmp_path):
    assert read_exposure("x.example", snippet_dir=tmp_path) == {"reach": "wan", "mesh": False}

def test_lan_with_mesh(tmp_path):
    (tmp_path / "x.example.conf").write_text(
        "allow 127.0.0.1;\nallow 10.0.0.0/8;\nallow 192.168.0.0/16;\nallow 10.10.0.0/24;\ndeny all;\n")
    assert read_exposure("x.example", snippet_dir=tmp_path) == {"reach": "lan", "mesh": True}

def test_localhost(tmp_path):
    (tmp_path / "x.example.conf").write_text("allow 127.0.0.1;\ndeny all;\n")
    assert read_exposure("x.example", snippet_dir=tmp_path) == {"reach": "localhost", "mesh": False}

def test_empty_is_wan(tmp_path):
    (tmp_path / "x.example.conf").write_text("")
    assert read_exposure("x.example", snippet_dir=tmp_path) == {"reach": "wan", "mesh": False}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-vhost && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_exposure_read.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```python
# packages/secubox-vhost/api/exposure_read.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: vhost.exposure_read — derive a vhost's exposure from its snippet."""
from pathlib import Path

_SNIPPET_DIR = Path("/etc/nginx/snippets/exposure")
_LAN = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
_MESH = "10.10.0.0/24"


def read_exposure(vhost: str, snippet_dir=None) -> dict:
    d = Path(snippet_dir) if snippet_dir is not None else _SNIPPET_DIR
    try:
        content = (d / f"{vhost}.conf").read_text()
    except OSError:
        return {"reach": "wan", "mesh": False}
    mesh = _MESH in content
    if content.strip() == "":
        reach = "wan"
    elif any(c in content for c in _LAN):
        reach = "lan"
    else:
        reach = "localhost"
    return {"reach": reach, "mesh": mesh}
```

Then in `packages/secubox-vhost/api/main.py`, in the `/vhosts` loop where each entry dict is built (`vhosts.append({... "domain": domain, ...})`), add the field:

```python
                "exposure": __import__("api.exposure_read", fromlist=["read_exposure"]).read_exposure(domain),
```

(or add `from api.exposure_read import read_exposure` at the top and use `"exposure": read_exposure(domain),`).

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-vhost && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_exposure_read.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-vhost/api/exposure_read.py packages/secubox-vhost/api/main.py packages/secubox-vhost/tests/test_exposure_read.py
git commit -m "feat(vhost): expose per-vhost exposure state on /vhosts (ref #793)"
```

---

## Task 6: default snippet + include wiring (packaging)

**Files:**
- Create: `packages/secubox-exposure/conf/nginx-exposure-default.conf`
- Modify: `packages/secubox-exposure/debian/rules` (create the snippet dir + a default lan snippet at install)
- Test: `packages/secubox-exposure/tests/test_exposure_packaging.py`

Because `include` of a missing file is a hard nginx error, the exposure package must create `/etc/nginx/snippets/exposure/` and a shared default so a vhost can `include /etc/nginx/snippets/exposure/default.conf;` before it has its own file (used by the generated-vhost template as the initial include target, later switched to `<vhost>.conf`). Ship the default = `lan`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-exposure/tests/test_exposure_packaging.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_default_snippet_is_lan():
    s = (ROOT / "conf" / "nginx-exposure-default.conf").read_text()
    assert "allow 192.168.0.0/16;" in s and "deny all;" in s
    assert "10.10.0.0/24" not in s   # mesh off by default

def test_rules_installs_snippet_dir_and_default():
    r = (ROOT / "debian" / "rules").read_text()
    assert "snippets/exposure" in r
    assert "nginx-exposure-default.conf" in r
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-exposure && PYTHONPATH=. python -m pytest tests/test_exposure_packaging.py -q`
Expected: FAIL — files missing.

- [ ] **Step 3: Implement**

`packages/secubox-exposure/conf/nginx-exposure-default.conf` (default = lan):

```
allow 127.0.0.1;
allow 10.0.0.0/8;
allow 172.16.0.0/12;
allow 192.168.0.0/16;
deny all;
```

In `packages/secubox-exposure/debian/rules` `override_dh_auto_install:` add:

```makefile
	install -d debian/secubox-exposure/etc/nginx/snippets/exposure
	install -m 644 conf/nginx-exposure-default.conf \
	   debian/secubox-exposure/etc/nginx/snippets/exposure/default.conf
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-exposure && PYTHONPATH=. python -m pytest tests/test_exposure_packaging.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-exposure/conf/nginx-exposure-default.conf packages/secubox-exposure/debian/rules packages/secubox-exposure/tests/test_exposure_packaging.py
git commit -m "feat(exposure): ship snippet dir + default lan snippet (ref #793)"
```

---

## Task 7: exposure webui — reach slider + mesh/Tor toggles

**Files:**
- Modify: `packages/secubox-exposure/www/exposure/index.html` (add a per-vhost exposure control; create the file/section if absent)
- Test: `packages/secubox-exposure/tests/test_exposure_webui.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-exposure/tests/test_exposure_webui.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_panel_calls_exposure_api_with_reach_options():
    html = (ROOT / "www" / "exposure" / "index.html").read_text()
    assert "/api/v1/exposure/" in html
    for v in ("localhost", "lan", "wan"):
        assert v in html
    assert "mesh" in html and "tor" in html.lower()
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-exposure && PYTHONPATH=. python -m pytest tests/test_exposure_webui.py -q`
Expected: FAIL — assertion/file.

- [ ] **Step 3: Implement**

Add to `packages/secubox-exposure/www/exposure/index.html` a section (if the file exists, append inside `<body>`; if not, create a minimal page). Minimal functional control:

```html
<section id="exposure-switch">
  <h2>Exposition par vhost</h2>
  <input id="exp-vhost" placeholder="vhost (ex: zigbee.gk2.secubox.in)">
  <label>Portée
    <select id="exp-reach">
      <option value="localhost">localhost</option>
      <option value="lan" selected>LAN</option>
      <option value="wan">WAN</option>
    </select>
  </label>
  <label><input type="checkbox" id="exp-mesh"> mesh</label>
  <label><input type="checkbox" id="exp-tor"> Tor</label>
  <button onclick="applyExposure()">Appliquer</button>
  <pre id="exp-out"></pre>
  <script>
  const EXP_API='/api/v1/exposure';
  async function applyExposure(){
    const vhost=document.getElementById('exp-vhost').value.trim();
    const body={reach:document.getElementById('exp-reach').value,
                mesh:document.getElementById('exp-mesh').checked,
                tor:document.getElementById('exp-tor').checked};
    const r=await fetch(`${EXP_API}/${encodeURIComponent(vhost)}`,
      {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    document.getElementById('exp-out').textContent=JSON.stringify(await r.json(),null,2);
  }
  </script>
</section>
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-exposure && PYTHONPATH=. python -m pytest tests/test_exposure_webui.py -q`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-exposure/www/exposure/index.html packages/secubox-exposure/tests/test_exposure_webui.py
git commit -m "feat(exposure): webui reach slider + mesh/Tor toggles (ref #793)"
```

---

## Task 8: vhost webui — exposure badge + README + full suite

**Files:**
- Modify: `packages/secubox-vhost/www/…/index.html` (render the `exposure` field per vhost)
- Create: `packages/secubox-exposure/README.md` section (document the switch, snippet path, real_ip dependency, default LAN, the include line vhosts must add)
- Test: run both packages' suites.

- [ ] **Step 1: Add the badge** — in the vhost list rendering, for each vhost show `exposure.reach` (localhost/LAN/WAN) and a 🕸️ marker when `exposure.mesh`. Locate the vhost-row template in `packages/secubox-vhost/www/*/index.html` (search for where `domain`/`tls_mode` are rendered) and add an exposure cell reading `v.exposure.reach` + `v.exposure.mesh`.

- [ ] **Step 2: Document** — in `packages/secubox-exposure/README.md` add an "Exposure switch" section: reach levels + default `lan`; the snippet at `/etc/nginx/snippets/exposure/<vhost>.conf`; the **real_ip dependency** (needs secubox-hub lan-geo `set_real_ip_from`/`real_ip_header` for WAN-deny to be effective); the **one-line include** a vhost adds to opt in: `include /etc/nginx/snippets/exposure/<vhost>.conf;` inside its gated `location`; and that a currently-public vhost is seeded to `wan` (no silent re-confinement).

- [ ] **Step 3: Run both suites**

Run:
`cd packages/secubox-exposure && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/ -q`
`cd packages/secubox-vhost && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/ -q`
Expected: PASS (both).

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-vhost/www packages/secubox-exposure/README.md
git commit -m "feat(vhost): exposure badge + docs (ref #793)"
```

---

## Self-Review (plan vs spec)

- **Spec coverage:** reach model+snippet (T1), atomic write/read (T2), safe default from current reach (T3), API get/set + fail-safe apply + audit (T4), vhost display (T5), missing-snippet safety + packaging default (T6), exposure webui control (T7), vhost badge + real_ip doc (T8). mesh/tor reuse existing (`/tor/add`, emancipate) — the reach snippet adds the mesh-CIDR line; the deep mesh-direct stays on emancipate (spec out-of-scope). The include-wiring of the two hand-vhosts (zigbee/lyrion) is an APPLY step done at deploy (documented in T8 README), not a source task, since those live-vhost files are board-managed (source-first: the generated-vhost template is the source path, covered by T6/T8 docs).
- **Placeholder scan:** none — every code step has full code; config/webui have full content.
- **Type consistency:** `reach_snippet(reach,mesh)`, `write_snippet(vhost,reach,mesh)`, `read_snippet_reach(vhost)`, `load_record(vhost,is_public_now)`, `read_exposure(vhost,snippet_dir)` are used identically across tasks; `{reach,mesh,tor}` record shape stable T3→T4→T5.
- **Gap noted (non-blocking):** `GET /exposure/{vhost}` can't know `is_public_now` (no vhost list in the exposure module) → defaults `lan` when no snippet; the safe-default-to-wan-for-public happens at first *adoption* via the vhost module seeding. Acceptable; the live migration step (seed public vhosts to `wan`) is a deploy action, flagged in T8.
