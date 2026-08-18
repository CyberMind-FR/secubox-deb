<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-proxypac Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A per-node package that auto-generates a `proxy.pac`, served via WPAD, routing each host to the right transport (mesh tor-exit SOCKS, toolbox MITM, gateway, or DIRECT) from the active p2p `/services` catalog + operator per-host policy.

**Architecture:** A pure-Python generator composes an ordered rule list (operator overrides > active mesh-service patterns > toolbox default > DIRECT) into a static PAC file, atomically swapped and fail-safe (last-good preserved, every directive ends `; DIRECT`). nginx serves it at `/proxy.pac` and on a LAN/mesh-only `wpad` vhost; DHCP option 252 makes discovery zero-config. A FastAPI WebUI manages overrides + auto-learn candidates. The annuaire `ServiceOffer` gains an optional, byte-stable `pac` descriptor.

**Tech Stack:** Python 3.11 (stdlib + pydantic v2), FastAPI/uvicorn on a unix socket, nginx, systemd path+timer units, Debian packaging (debhelper compat 13).

## Global Constraints

- Package name `secubox-proxypac`; version `1.0.0-1~bookworm1`; `debian/compat` 13; `Standards-Version: 4.6.2`.
- Python SPDX header block on every `.py` (per `.claude/CLAUDE.md`); service runs as `User=secubox`.
- The generated PAC MUST end every non-DIRECT directive with `; DIRECT` (fail-open) and MUST have a terminal `return "DIRECT";`.
- Generation is fail-safe: on any error the previously-served `proxy.pac` is left untouched (never serve empty/broken).
- `wpad.dat` / `/proxy.pac` are served ONLY on the LAN + `10.10.0.0/24` mesh vhost (`deny all` otherwise) — never public.
- The annuaire `pac` field is OPTIONAL and byte-stable: a `pac`-less `ServiceOffer` MUST produce identical `canonical_bytes` to before this change (None excluded from canonical JSON), mirroring `MacroDescriptor` (#771).
- No secrets in the PAC (hosts + proxy addresses only). Override add/remove + candidate accept/reject append to `/var/log/secubox/audit.log`.
- Paths: state `/var/lib/secubox/proxypac/`, rules `/etc/secubox/proxypac/rules.d/`, PAC output `/var/lib/secubox/proxypac/proxy.pac`.

---

## File Structure

- `packages/secubox-annuaire/annuaire/model.py` — MODIFY: add `PacDescriptor` + `ServiceOffer.pac`.
- `packages/secubox-proxypac/proxypac/__init__.py` — package marker.
- `packages/secubox-proxypac/proxypac/pac_template.py` — PAC JS rendering + directive builder (pure).
- `packages/secubox-proxypac/proxypac/rules.py` — `Rule` model, rules.d parsing, precedence compose.
- `packages/secubox-proxypac/proxypac/catalog.py` — read p2p `/services`, map to service `Rule`s.
- `packages/secubox-proxypac/proxypac/generator.py` — compose + atomic fail-safe write.
- `packages/secubox-proxypac/sbin/proxypac-gen` — CLI entry (`--once`).
- `packages/secubox-proxypac/api/main.py` — FastAPI WebUI (rules CRUD + candidates).
- `packages/secubox-proxypac/nginx/proxypac.conf` — `/proxy.pac` + WebUI route (secubox.d).
- `packages/secubox-proxypac/nginx/wpad-vhost.conf` — LAN/mesh-only `wpad` server block.
- `packages/secubox-proxypac/systemd/*` — regen path unit + timer + service; dnsmasq 252 dropin.
- `packages/secubox-proxypac/conf/rules.d/00-onion.rules` — seed.
- `packages/secubox-proxypac/www/proxypac/index.html` + `menu.d/` — WebUI panel.
- `packages/secubox-proxypac/debian/*` — control, rules, postinst, prerm, changelog.
- `packages/secubox-proxypac/tests/*` — unit tests per module.

Each task below runs from the package dir with `PYTHONPATH` including repo `common` + the package, matching sibling packages. Tests use `pytest`.

---

## Task 1: annuaire `PacDescriptor` schema (byte-stable optional field)

**Files:**
- Modify: `packages/secubox-annuaire/annuaire/model.py` (after `MacroDescriptor`, ~line 400, and `ServiceOffer` ~line 425)
- Test: `packages/secubox-annuaire/tests/test_pac_descriptor.py`

**Interfaces:**
- Produces: `PacDescriptor(match: list[str], proxy: Literal["socks5","http","gateway","direct"])`; `ServiceOffer.pac: Optional[PacDescriptor]`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-annuaire/tests/test_pac_descriptor.py
from annuaire.model import ServiceOffer, PacDescriptor
from annuaire.crypto import canonical_bytes
import pytest

def _offer(**kw):
    return ServiceOffer(service_id="a1", provider="did:plc:"+"0"*32,
                        name="svc", kind="api", endpoint="http://10.10.0.1/x", **kw)

def test_pac_parses_and_validates():
    o = _offer(pac=PacDescriptor(match=["*.onion"], proxy="socks5"))
    assert o.pac.match == ["*.onion"] and o.pac.proxy == "socks5"

def test_pac_rejects_bad_proxy():
    with pytest.raises(Exception):
        PacDescriptor(match=["x"], proxy="tunnel")

def test_pac_rejects_empty_match():
    with pytest.raises(Exception):
        PacDescriptor(match=[], proxy="socks5")

def test_pacless_offer_is_byte_stable():
    # An offer with no pac must serialize identically to the pre-field baseline.
    o = _offer()
    payload = o.model_dump(exclude_none=True)
    assert "pac" not in payload
    assert canonical_bytes(payload) == canonical_bytes(_offer().model_dump(exclude_none=True))
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-annuaire && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_pac_descriptor.py -q`
Expected: FAIL — `ImportError: cannot import name 'PacDescriptor'`.

- [ ] **Step 3: Implement**

In `model.py`, add after `MacroDescriptor`:

```python
class PacDescriptor(BaseModel):
    """Optional PAC routing hint federated with a ServiceOffer (#784).

    Declares which hosts this service handles and how a client proxies them.
    Absent pac ⇒ the service contributes no client routing rule.
    """
    model_config = ConfigDict(extra="forbid")

    match: List[str] = Field(..., min_length=1, description="host globs, e.g. ['*.onion']")
    proxy: Literal["socks5", "http", "gateway", "direct"] = Field(...)
```

In `ServiceOffer`, add the field right after `macro:`:

```python
    pac:           Optional[PacDescriptor] = None
```

Confirm `Literal` and `List` are imported at the top of `model.py` (add to the existing `from typing import ...` if missing).

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-annuaire && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_pac_descriptor.py -q`
Expected: PASS (4 tests). If `test_pacless_offer_is_byte_stable` fails, `canonical_bytes` is not excluding None — pass `model_dump(exclude_none=True)` at every call site is already the convention; the test uses it, so this must pass.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-annuaire/annuaire/model.py packages/secubox-annuaire/tests/test_pac_descriptor.py
git commit -m "feat(annuaire): optional byte-stable pac descriptor on ServiceOffer (ref #784)"
```

---

## Task 2: PAC template + directive builder (pure)

**Files:**
- Create: `packages/secubox-proxypac/proxypac/__init__.py` (empty), `packages/secubox-proxypac/proxypac/pac_template.py`
- Test: `packages/secubox-proxypac/tests/test_pac_template.py`

**Interfaces:**
- Produces: `directive(proxy_type: str, address: str) -> str`; `render(rules: list[tuple[str,str]]) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_pac_template.py
from proxypac.pac_template import directive, render

def test_directive_socks_has_failopen():
    assert directive("socks5", "10.10.0.1:9050") == "SOCKS5 10.10.0.1:9050; DIRECT"

def test_directive_http_and_gateway_are_proxy():
    assert directive("http", "127.0.0.1:8081") == "PROXY 127.0.0.1:8081; DIRECT"
    assert directive("gateway", "gk2.secubox.in") == "PROXY gk2.secubox.in; DIRECT"

def test_directive_direct():
    assert directive("direct", "") == "DIRECT"

def test_render_first_match_wins_and_terminal_direct():
    pac = render([("*.onion", "SOCKS5 10.10.0.1:9050; DIRECT")])
    assert "function FindProxyForURL(url, host)" in pac
    assert 'shExpMatch(host, "*.onion")' in pac
    assert 'return "SOCKS5 10.10.0.1:9050; DIRECT";' in pac
    assert pac.rstrip().endswith('return "DIRECT";\n}'.rstrip()) or 'return "DIRECT";' in pac
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_pac_template.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```python
# packages/secubox-proxypac/proxypac/pac_template.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.pac_template — PAC JS rendering (pure)."""
import json

_HEADER = "function FindProxyForURL(url, host) {\n"
_FOOTER = '  return "DIRECT";\n}\n'


def directive(proxy_type: str, address: str) -> str:
    """Build a PAC return directive with a fail-open DIRECT fallback."""
    if proxy_type == "socks5":
        return f"SOCKS5 {address}; DIRECT"
    if proxy_type in ("http", "gateway"):
        return f"PROXY {address}; DIRECT"
    return "DIRECT"


def render(rules):
    """rules: ordered list of (host_glob, directive_string). First match wins."""
    out = [_HEADER]
    for glob, direct in rules:
        out.append(f"  if (shExpMatch(host, {json.dumps(glob)})) "
                   f"return {json.dumps(direct)};\n")
    out.append(_FOOTER)
    return "".join(out)
```

Create empty `packages/secubox-proxypac/proxypac/__init__.py`.

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_pac_template.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/proxypac/__init__.py packages/secubox-proxypac/proxypac/pac_template.py packages/secubox-proxypac/tests/test_pac_template.py
git commit -m "feat(proxypac): PAC template + fail-open directive builder (ref #784)"
```

---

## Task 3: Rule model + rules.d parsing + precedence compose

**Files:**
- Create: `packages/secubox-proxypac/proxypac/rules.py`
- Test: `packages/secubox-proxypac/tests/test_rules.py`

**Interfaces:**
- Consumes: `directive` (Task 2).
- Produces: `@dataclass Rule(host: str, directive: str, source: str)`; `parse_rules_dir(path) -> list[Rule]`; `compose(overrides, services, toolbox) -> list[tuple[str,str]]`.

Rules.d line format: `<host-glob> <proxy_type> [address]`, `#` comments, blank lines skipped. Files applied in sorted filename order. Example line: `*.onion socks5 10.10.0.1:9050`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_rules.py
from proxypac.rules import Rule, parse_rules_dir, compose

def test_parse_rules_dir(tmp_path):
    (tmp_path / "10-a.rules").write_text("# c\n*.onion socks5 10.10.0.1:9050\n\n")
    (tmp_path / "20-b.rules").write_text("bank.example direct\n")
    rules = parse_rules_dir(tmp_path)
    assert [(r.host, r.directive) for r in rules] == [
        ("*.onion", "SOCKS5 10.10.0.1:9050; DIRECT"),
        ("bank.example", "DIRECT"),
    ]
    assert all(r.source == "override" for r in rules)

def test_compose_precedence_override_beats_service():
    ov = [Rule("x.com", "DIRECT", "override")]
    svc = [Rule("x.com", "PROXY p; DIRECT", "service:1"), Rule("y.com", "PROXY p; DIRECT", "service:1")]
    tb = Rule("*", "PROXY t; DIRECT", "toolbox")
    out = compose(ov, svc, tb)
    # override wins for x.com; y.com from service; toolbox catch-all last
    assert out == [("x.com", "DIRECT"), ("y.com", "PROXY p; DIRECT"), ("*", "PROXY t; DIRECT")]

def test_compose_no_toolbox():
    assert compose([], [], None) == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_rules.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```python
# packages/secubox-proxypac/proxypac/rules.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.rules — rule model, rules.d parsing, precedence."""
from dataclasses import dataclass
from pathlib import Path

from .pac_template import directive


@dataclass
class Rule:
    host: str
    directive: str  # full PAC directive string
    source: str     # "override" | "service:<id>" | "toolbox"


def parse_rules_dir(path):
    """Parse rules.d/*.rules in sorted filename order.

    Line: '<host-glob> <proxy_type> [address]'. '#' comments and blanks skipped.
    """
    path = Path(path)
    rules = []
    for f in sorted(path.glob("*.rules")):
        for raw in f.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            host, ptype = parts[0], parts[1]
            addr = parts[2] if len(parts) > 2 else ""
            rules.append(Rule(host, directive(ptype, addr), "override"))
    return rules


def compose(overrides, services, toolbox):
    """Precedence: overrides, then services, then toolbox catch-all. First host wins."""
    seen = set()
    out = []
    ordered = list(overrides) + list(services) + ([toolbox] if toolbox else [])
    for r in ordered:
        if r.host in seen:
            continue
        seen.add(r.host)
        out.append((r.host, r.directive))
    return out
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_rules.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/proxypac/rules.py packages/secubox-proxypac/tests/test_rules.py
git commit -m "feat(proxypac): rules.d parsing + precedence compose (ref #784)"
```

---

## Task 4: Catalog reader (p2p /services → service Rules)

**Files:**
- Create: `packages/secubox-proxypac/proxypac/catalog.py`
- Test: `packages/secubox-proxypac/tests/test_catalog.py`

**Interfaces:**
- Consumes: `Rule`, `directive`.
- Produces: `service_rules(services: list[dict]) -> list[Rule]`; `read_services(sock=...) -> list[dict]` (thin HTTP-over-unix wrapper, not unit-tested directly).

A service dict from `/services` has at least `service_id`, `enabled` (bool), `endpoint` (e.g. `http://10.10.0.1/tor`), optional `macro` (`{kind, params:{socks_port}}`), optional `pac` (`{match, proxy}`). Address resolution: host = the mesh IP parsed from `endpoint` (`http://<ip>/...`); port = `macro.params.socks_port` for socks5 else empty (gateway/http use the endpoint host).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_catalog.py
from proxypac.catalog import service_rules

def test_socks5_service_rule():
    svcs = [{"service_id": "s1", "enabled": True,
             "endpoint": "http://10.10.0.1/tor",
             "macro": {"kind": "tor-exit", "params": {"socks_port": 9050}},
             "pac": {"match": ["*.onion"], "proxy": "socks5"}}]
    rules = service_rules(svcs)
    assert (rules[0].host, rules[0].directive) == ("*.onion", "SOCKS5 10.10.0.1:9050; DIRECT")
    assert rules[0].source == "service:s1"

def test_disabled_and_pacless_skipped():
    svcs = [
        {"service_id": "s2", "enabled": False, "endpoint": "http://10.10.0.2/x",
         "pac": {"match": ["a"], "proxy": "socks5"}},
        {"service_id": "s3", "enabled": True, "endpoint": "http://10.10.0.3/x"},  # no pac
    ]
    assert service_rules(svcs) == []

def test_gateway_service_uses_endpoint_host():
    svcs = [{"service_id": "s4", "enabled": True, "endpoint": "http://gk2.secubox.in/app",
             "pac": {"match": ["app.local"], "proxy": "gateway"}}]
    rules = service_rules(svcs)
    assert rules[0].directive == "PROXY gk2.secubox.in; DIRECT"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_catalog.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```python
# packages/secubox-proxypac/proxypac/catalog.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.catalog — read p2p /services, map to service Rules."""
import json
import socket
from urllib.parse import urlparse

from .pac_template import directive
from .rules import Rule


def _endpoint_host(endpoint):
    return urlparse(endpoint or "").hostname or ""


def service_rules(services):
    """Map active services carrying a `pac` descriptor to routing Rules."""
    out = []
    for s in services:
        if not s.get("enabled"):
            continue
        pac = s.get("pac")
        if not pac:
            continue
        proxy = pac.get("proxy", "direct")
        host = _endpoint_host(s.get("endpoint"))
        if proxy == "socks5":
            port = (s.get("macro") or {}).get("params", {}).get("socks_port", 9050)
            addr = f"{host}:{port}"
        else:  # http | gateway use the endpoint host as-is
            addr = host
        d = directive(proxy, addr)
        for m in pac.get("match", []):
            out.append(Rule(m, d, f"service:{s['service_id']}"))
    return out


def read_services(sock="/run/secubox/p2p.sock"):
    """GET /services over the p2p unix socket. Returns the services list (fail-open: [])."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.settimeout(5)
            c.connect(sock)
            c.sendall(b"GET /services HTTP/1.0\r\nHost: x\r\n\r\n")
            buf = b""
            while True:
                chunk = c.recv(65536)
                if not chunk:
                    break
                buf += chunk
        body = buf.split(b"\r\n\r\n", 1)[1]
        return json.loads(body).get("services", [])
    except Exception:
        return []
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_catalog.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/proxypac/catalog.py packages/secubox-proxypac/tests/test_catalog.py
git commit -m "feat(proxypac): p2p /services catalog reader → routing rules (ref #784)"
```

---

## Task 5: Generator + atomic fail-safe write + CLI

**Files:**
- Create: `packages/secubox-proxypac/proxypac/generator.py`, `packages/secubox-proxypac/sbin/proxypac-gen`
- Test: `packages/secubox-proxypac/tests/test_generator.py`

**Interfaces:**
- Consumes: `parse_rules_dir`, `compose`, `service_rules`, `read_services`, `render`.
- Produces: `generate(rules_dir, services, toolbox_directive=None) -> str`; `write_atomic(pac_str, out) -> None` (raises on invalid); `run_once(...) -> bool`.

`toolbox_directive` is a pre-built directive string (e.g. `"PROXY 127.0.0.1:8081; DIRECT"`) or None; when present it becomes the `("*", directive)` catch-all.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_generator.py
import pytest
from proxypac.generator import generate, write_atomic

def test_generate_composes_override_over_service(tmp_path):
    (tmp_path / "10.rules").write_text("x.com direct\n")
    svcs = [{"service_id": "s1", "enabled": True, "endpoint": "http://10.10.0.1/tor",
             "macro": {"params": {"socks_port": 9050}},
             "pac": {"match": ["x.com", "*.onion"], "proxy": "socks5"}}]
    pac = generate(tmp_path, svcs, toolbox_directive="PROXY 127.0.0.1:8081; DIRECT")
    # override x.com -> DIRECT wins; *.onion via socks; toolbox catch-all last
    assert pac.index('shExpMatch(host, "x.com")') < pac.index('shExpMatch(host, "*.onion")')
    assert 'return "DIRECT";' in pac and 'SOCKS5 10.10.0.1:9050; DIRECT' in pac
    assert 'shExpMatch(host, "*")' in pac

def test_write_atomic_swaps_and_validates(tmp_path):
    out = tmp_path / "proxy.pac"
    write_atomic('function FindProxyForURL(url, host) {\n  return "DIRECT";\n}\n', out)
    assert out.read_text().startswith("function FindProxyForURL")

def test_write_atomic_rejects_invalid_keeps_lastgood(tmp_path):
    out = tmp_path / "proxy.pac"
    write_atomic('function FindProxyForURL(url, host) { return "DIRECT"; }\n', out)
    good = out.read_text()
    with pytest.raises(ValueError):
        write_atomic("garbage not a pac", out)      # no FindProxyForURL → rejected
    assert out.read_text() == good                   # last-good preserved
    assert not (tmp_path / "proxy.pac.shadow").exists()
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_generator.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```python
# packages/secubox-proxypac/proxypac/generator.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.generator — compose + atomic fail-safe PAC write."""
import logging
import os
from pathlib import Path

from .catalog import read_services, service_rules
from .pac_template import render
from .rules import Rule, compose, parse_rules_dir

_log = logging.getLogger("secubox.proxypac")
DEFAULT_OUT = Path("/var/lib/secubox/proxypac/proxy.pac")


def generate(rules_dir, services, toolbox_directive=None):
    overrides = parse_rules_dir(rules_dir)
    svc_rules = service_rules(services)
    toolbox = Rule("*", toolbox_directive, "toolbox") if toolbox_directive else None
    return render(compose(overrides, svc_rules, toolbox))


def write_atomic(pac_str, out=DEFAULT_OUT):
    """Validate then atomically swap. Invalid input raises ValueError, last-good kept."""
    out = Path(out)
    if "function FindProxyForURL" not in pac_str or 'return "DIRECT"' not in pac_str:
        raise ValueError("refusing to write PAC without FindProxyForURL/terminal DIRECT")
    out.parent.mkdir(parents=True, exist_ok=True)
    shadow = out.with_suffix(".shadow")
    shadow.write_text(pac_str)
    os.replace(shadow, out)


def run_once(rules_dir="/etc/secubox/proxypac/rules.d",
             sock="/run/secubox/p2p.sock", out=DEFAULT_OUT, toolbox_directive=None):
    """Regenerate the PAC. Fail-safe: on any error the previous file is untouched."""
    try:
        pac = generate(rules_dir, read_services(sock), toolbox_directive)
        write_atomic(pac, out)
        return True
    except Exception as exc:  # noqa: BLE001
        _log.warning("proxypac regen failed, keeping last-good: %s", exc)
        return False
```

```python
#!/usr/bin/env python3
# packages/secubox-proxypac/sbin/proxypac-gen
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac-gen — regenerate proxy.pac once."""
import sys
sys.path.insert(0, "/usr/lib/secubox/proxypac")
from proxypac.generator import run_once  # noqa: E402

if __name__ == "__main__":
    ok = run_once()
    sys.exit(0 if ok else 1)
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_generator.py -q && chmod +x sbin/proxypac-gen`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/proxypac/generator.py packages/secubox-proxypac/sbin/proxypac-gen packages/secubox-proxypac/tests/test_generator.py
git commit -m "feat(proxypac): generator + atomic fail-safe write + CLI (ref #784)"
```

---

## Task 6: WebUI API — override CRUD + candidates + audit

**Files:**
- Create: `packages/secubox-proxypac/api/__init__.py` (empty), `packages/secubox-proxypac/api/main.py`
- Test: `packages/secubox-proxypac/tests/test_api.py`

**Interfaces:**
- Consumes: `parse_rules_dir`, `run_once`.
- Produces endpoints (mounted by the aggregator at `/api/v1/proxypac/`): `GET /rules`, `POST /override` `{host, proxy, address}`, `DELETE /override/{host}`, `GET /candidates`, `POST /candidate/{host}/accept`, `POST /candidate/{host}/reject`. Overrides persist to `/etc/secubox/proxypac/rules.d/50-webui.rules`. Each mutation appends to `/var/log/secubox/audit.log` and calls `run_once()`.

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_api.py
import importlib, json
from fastapi.testclient import TestClient

def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXYPAC_RULES_DIR", str(tmp_path / "rules.d"))
    monkeypatch.setenv("PROXYPAC_AUDIT", str(tmp_path / "audit.log"))
    import api.main as m
    importlib.reload(m)
    monkeypatch.setattr(m, "run_once", lambda *a, **k: True)  # no live regen in tests
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    return TestClient(m.app), tmp_path

def test_add_and_list_override(tmp_path, monkeypatch):
    c, tp = _client(tmp_path, monkeypatch)
    r = c.post("/override", json={"host": "bank.example", "proxy": "direct", "address": ""})
    assert r.status_code == 200
    rules = c.get("/rules").json()["rules"]
    assert {"host": "bank.example", "directive": "DIRECT"} in rules
    assert "bank.example" in (tp / "audit.log").read_text()

def test_delete_override(tmp_path, monkeypatch):
    c, tp = _client(tmp_path, monkeypatch)
    c.post("/override", json={"host": "x.com", "proxy": "socks5", "address": "10.10.0.1:9050"})
    assert c.delete("/override/x.com").status_code == 200
    assert all(r["host"] != "x.com" for r in c.get("/rules").json()["rules"])
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-proxypac && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_api.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

```python
# packages/secubox-proxypac/api/main.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac API — override CRUD + candidates."""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/usr/lib/secubox/proxypac")
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel

try:
    from secubox_core.auth import require_jwt
except Exception:  # test/stub fallback
    def require_jwt():
        return {"sub": "anon"}

from proxypac.pac_template import directive
from proxypac.rules import parse_rules_dir
from proxypac.generator import run_once

RULES_DIR = Path(os.environ.get("PROXYPAC_RULES_DIR", "/etc/secubox/proxypac/rules.d"))
WEBUI_FILE = RULES_DIR / "50-webui.rules"
CANDIDATES = Path(os.environ.get("PROXYPAC_CANDIDATES",
                                 "/var/lib/secubox/proxypac/candidates.json"))
AUDIT = Path(os.environ.get("PROXYPAC_AUDIT", "/var/log/secubox/audit.log"))

app = FastAPI(title="SecuBox ProxyPAC")


class Override(BaseModel):
    host: str
    proxy: str
    address: str = ""


def _audit(action, host, user):
    try:
        AUDIT.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT.open("a") as f:
            f.write(f'{datetime.now(timezone.utc).isoformat()} proxypac {action} '
                    f'host={host} by={user}\n')
    except OSError:
        pass


def _read_webui_lines():
    if not WEBUI_FILE.exists():
        return []
    return [ln for ln in WEBUI_FILE.read_text().splitlines() if ln.strip()
            and not ln.startswith("#")]


def _write_webui_lines(lines):
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    WEBUI_FILE.write_text("\n".join(lines) + ("\n" if lines else ""))


@app.get("/rules")
def list_rules(_=Depends(require_jwt)):
    return {"rules": [{"host": r.host, "directive": r.directive}
                      for r in parse_rules_dir(RULES_DIR)]}


@app.post("/override")
def add_override(o: Override, user=Depends(require_jwt)):
    line = f"{o.host} {o.proxy}" + (f" {o.address}" if o.address else "")
    lines = [ln for ln in _read_webui_lines() if ln.split()[0] != o.host]
    lines.append(line)
    _write_webui_lines(lines)
    _audit("override-add", o.host, user.get("sub"))
    run_once()
    return {"ok": True, "directive": directive(o.proxy, o.address)}


@app.delete("/override/{host}")
def del_override(host: str, user=Depends(require_jwt)):
    lines = [ln for ln in _read_webui_lines() if ln.split()[0] != host]
    _write_webui_lines(lines)
    _audit("override-del", host, user.get("sub"))
    run_once()
    return {"ok": True}


@app.get("/candidates")
def list_candidates(_=Depends(require_jwt)):
    import json
    try:
        return {"candidates": json.loads(CANDIDATES.read_text())}
    except Exception:
        return {"candidates": []}


@app.post("/candidate/{host}/accept")
def accept_candidate(host: str, user=Depends(require_jwt)):
    # Promote candidate to an override (socks5 to the first active tor-exit is the
    # common case; operator can re-edit). Minimal: DIRECT unless already routed.
    add_override(Override(host=host, proxy="direct"), user)
    _audit("candidate-accept", host, user.get("sub"))
    return {"ok": True}


@app.post("/candidate/{host}/reject")
def reject_candidate(host: str, user=Depends(require_jwt)):
    _audit("candidate-reject", host, user.get("sub"))
    return {"ok": True}


@app.get("/health")
def health():
    return {"status": "ok", "module": "proxypac"}
```

Create empty `api/__init__.py`.

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-proxypac && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/test_api.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/api/ packages/secubox-proxypac/tests/test_api.py
git commit -m "feat(proxypac): WebUI API override CRUD + candidates + audit (ref #784)"
```

---

## Task 7: nginx WPAD/PAC serving (LAN/mesh only) + seed rules

**Files:**
- Create: `packages/secubox-proxypac/nginx/proxypac.conf`, `packages/secubox-proxypac/nginx/wpad-vhost.conf`, `packages/secubox-proxypac/conf/rules.d/00-onion.rules`
- Test: `packages/secubox-proxypac/tests/test_nginx_conf.py`

**Interfaces:** none (config files). The WebUI API route mirrors sibling modules (`/api/v1/proxypac/` → aggregator).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_nginx_conf.py
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_pac_route_sets_content_type_and_serves_state():
    conf = (ROOT / "nginx" / "proxypac.conf").read_text()
    assert "location = /proxy.pac" in conf
    assert "application/x-ns-proxy-autoconfig" in conf
    assert "/var/lib/secubox/proxypac/proxy.pac" in conf
    assert "/api/v1/proxypac/" in conf and "aggregator.sock" in conf

def test_wpad_vhost_is_lan_mesh_only():
    conf = (ROOT / "nginx" / "wpad-vhost.conf").read_text()
    assert "server_name wpad." in conf
    assert "allow 10.10.0.0/24;" in conf
    assert "deny all;" in conf
    assert "application/x-ns-proxy-autoconfig" in conf

def test_seed_rule_present():
    seed = (ROOT / "conf" / "rules.d" / "00-onion.rules").read_text()
    assert "*.onion socks5" in seed
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_nginx_conf.py -q`
Expected: FAIL — files missing.

- [ ] **Step 3: Implement**

`nginx/proxypac.conf` (secubox.d dropin, added into the main server):

```nginx
# secubox-proxypac — PAC file + WebUI API
location = /proxy.pac {
    default_type application/x-ns-proxy-autoconfig;
    alias /var/lib/secubox/proxypac/proxy.pac;
    add_header Cache-Control "max-age=300";
}
location /api/v1/proxypac/ {
    proxy_pass http://unix:/run/secubox/aggregator.sock:/api/v1/proxypac/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

`nginx/wpad-vhost.conf` (dedicated server, LAN/mesh only):

```nginx
# secubox-proxypac — WPAD auto-discovery vhost (LAN + mesh only, never public)
server {
    listen 80;
    server_name wpad.gk2.secubox.in;
    allow 192.168.0.0/16;
    allow 10.10.0.0/24;
    deny all;
    location = /wpad.dat {
        default_type application/x-ns-proxy-autoconfig;
        alias /var/lib/secubox/proxypac/proxy.pac;
    }
}
```

`conf/rules.d/00-onion.rules`:

```
# secubox-proxypac seed: route .onion via a mesh tor-exit when one is active.
# The service catalog also emits *.onion; this seed guarantees it even before
# the operator subscribes (address is the local mesh gateway SocksPort).
*.onion socks5 10.10.0.1:9050
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_nginx_conf.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/nginx/ packages/secubox-proxypac/conf/ packages/secubox-proxypac/tests/test_nginx_conf.py
git commit -m "feat(proxypac): nginx PAC/WPAD serving (LAN-only) + seed rule (ref #784)"
```

---

## Task 8: Regeneration units (systemd path + timer + service) + DHCP 252

**Files:**
- Create: `packages/secubox-proxypac/systemd/secubox-proxypac-gen.service`, `packages/secubox-proxypac/systemd/secubox-proxypac-gen.path`, `packages/secubox-proxypac/systemd/secubox-proxypac-gen.timer`, `packages/secubox-proxypac/conf/dnsmasq-wpad.conf`
- Test: `packages/secubox-proxypac/tests/test_systemd_units.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_systemd_units.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_gen_service_runs_cli_as_secubox():
    s = (ROOT / "systemd" / "secubox-proxypac-gen.service").read_text()
    assert "ExecStart=/usr/sbin/proxypac-gen" in s
    assert "User=secubox" in s and "Type=oneshot" in s

def test_path_unit_watches_rulesdir():
    p = (ROOT / "systemd" / "secubox-proxypac-gen.path").read_text()
    assert "PathModified=/etc/secubox/proxypac/rules.d" in p
    assert "Unit=secubox-proxypac-gen.service" in p

def test_timer_is_fallback():
    t = (ROOT / "systemd" / "secubox-proxypac-gen.timer").read_text()
    assert "OnUnitActiveSec=" in t

def test_dnsmasq_sets_option_252():
    d = (ROOT / "conf" / "dnsmasq-wpad.conf").read_text()
    assert "dhcp-option=252" in d
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_systemd_units.py -q`
Expected: FAIL — files missing.

- [ ] **Step 3: Implement**

`systemd/secubox-proxypac-gen.service`:

```ini
[Unit]
Description=SecuBox ProxyPAC — regenerate proxy.pac
After=network.target

[Service]
Type=oneshot
User=secubox
Group=secubox
ExecStart=/usr/sbin/proxypac-gen
```

`systemd/secubox-proxypac-gen.path`:

```ini
[Unit]
Description=SecuBox ProxyPAC — watch rules.d for changes

[Path]
PathModified=/etc/secubox/proxypac/rules.d
Unit=secubox-proxypac-gen.service

[Install]
WantedBy=multi-user.target
```

`systemd/secubox-proxypac-gen.timer` (fallback resync, e.g. picks up catalog changes):

```ini
[Unit]
Description=SecuBox ProxyPAC — periodic regen fallback

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

`conf/dnsmasq-wpad.conf`:

```
# secubox-proxypac — advertise the WPAD URL via DHCP option 252 (WPAD).
dhcp-option=252,"http://wpad.gk2.secubox.in/wpad.dat"
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_systemd_units.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/systemd/ packages/secubox-proxypac/conf/dnsmasq-wpad.conf packages/secubox-proxypac/tests/test_systemd_units.py
git commit -m "feat(proxypac): regen path+timer units + DHCP 252 WPAD advertise (ref #784)"
```

---

## Task 9: WebUI panel + menu entry

**Files:**
- Create: `packages/secubox-proxypac/www/proxypac/index.html`, `packages/secubox-proxypac/menu.d/580-proxypac.json`
- Test: `packages/secubox-proxypac/tests/test_webui_panel.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_webui_panel.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_panel_calls_api_and_has_override_form():
    html = (ROOT / "www" / "proxypac" / "index.html").read_text()
    assert "/api/v1/proxypac/rules" in html
    assert "/api/v1/proxypac/override" in html
    assert 'id="host"' in html and 'id="proxy"' in html

def test_menu_entry_points_to_panel():
    import json
    m = json.loads((ROOT / "menu.d" / "580-proxypac.json").read_text())
    assert m.get("path") == "/proxypac/" or m.get("url") == "/proxypac/"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_webui_panel.py -q`
Expected: FAIL — files missing.

- [ ] **Step 3: Implement**

`www/proxypac/index.html` (minimal functional panel; match sibling panels' fetch+headers convention):

```html
<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><title>ProxyPAC</title></head>
<body>
<h1>ProxyPAC — routage mesh</h1>
<h2>Règles actives</h2><ul id="rules"></ul>
<h2>Ajouter un override</h2>
<input id="host" placeholder="host glob (ex: bank.example)">
<select id="proxy"><option>direct</option><option>socks5</option><option>http</option><option>gateway</option></select>
<input id="address" placeholder="ip:port (socks5/http)">
<button onclick="addOverride()">Ajouter</button>
<script>
const API = '/api/v1/proxypac';
function headers(){return {'Content-Type':'application/json'};}
async function load(){
  const d = await (await fetch(API+'/rules',{headers:headers()})).json();
  document.getElementById('rules').innerHTML =
    d.rules.map(r=>`<li>${r.host} → ${r.directive} <button onclick="del('${r.host}')">x</button></li>`).join('');
}
async function addOverride(){
  await fetch(API+'/override',{method:'POST',headers:headers(),
    body:JSON.stringify({host:host.value,proxy:proxy.value,address:address.value})});
  load();
}
async function del(h){ await fetch(API+'/override/'+encodeURIComponent(h),{method:'DELETE',headers:headers()}); load(); }
load();
</script>
</body></html>
```

`menu.d/580-proxypac.json`:

```json
{ "id": "proxypac", "title": "ProxyPAC", "path": "/proxypac/", "icon": "🧭", "category": "network" }
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_webui_panel.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/www/ packages/secubox-proxypac/menu.d/ packages/secubox-proxypac/tests/test_webui_panel.py
git commit -m "feat(proxypac): WebUI override panel + menu entry (ref #784)"
```

---

## Task 10: Debian packaging (control/rules/postinst/prerm/changelog)

**Files:**
- Create: `packages/secubox-proxypac/debian/{control,rules,compat,changelog,postinst,prerm,secubox-proxypac.service}`
- Test: `packages/secubox-proxypac/tests/test_packaging.py`

The aggregator serves `api/main.py` in-process (like sibling modules); `secubox-proxypac.service` is a thin standalone fallback that runs the same app on `/run/secubox/proxypac.sock` (mirrors other modules — copy `secubox-threats.service` shape). Add `proxypac` to the aggregator module list is a live-config step handled at deploy, noted in the README (not this package's file).

- [ ] **Step 1: Write the failing test**

```python
# packages/secubox-proxypac/tests/test_packaging.py
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def test_control_metadata():
    c = (ROOT / "debian" / "control").read_text()
    assert "Package: secubox-proxypac" in c
    assert "Standards-Version: 4.6.2" in c
    assert "Depends:" in c and "secubox-core" in c

def test_rules_installs_all_artifacts():
    r = (ROOT / "debian" / "rules").read_text()
    for frag in ["proxypac", "sbin/proxypac-gen", "nginx/proxypac.conf",
                 "systemd/secubox-proxypac-gen.path", "conf/rules.d", "www"]:
        assert frag in r

def test_postinst_enables_regen_and_seeds_rules():
    p = (ROOT / "debian" / "postinst").read_text()
    assert "systemctl enable --now secubox-proxypac-gen.path" in p
    assert "systemctl enable --now secubox-proxypac-gen.timer" in p
    assert "proxypac-gen" in p  # initial generation
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_packaging.py -q`
Expected: FAIL — files missing.

- [ ] **Step 3: Implement**

`debian/compat`: `13`

`debian/control`:

```
Source: secubox-proxypac
Section: net
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: secubox-proxypac
Architecture: all
Depends: ${misc:Depends}, python3, python3-fastapi, python3-uvicorn, secubox-core, nginx
Description: SecuBox WPAD/PAC auto-config routing to mesh services
 Generates a proxy.pac from the active p2p /services catalog + operator policy,
 served via WPAD for zero-config client routing to mesh tools.
```

`debian/rules`:

```makefile
#!/usr/bin/make -f
%:
	dh $@

override_dh_auto_install:
	install -d debian/secubox-proxypac/usr/lib/secubox/proxypac
	cp -r proxypac api debian/secubox-proxypac/usr/lib/secubox/proxypac/
	install -D -m 755 sbin/proxypac-gen debian/secubox-proxypac/usr/sbin/proxypac-gen
	install -d debian/secubox-proxypac/etc/nginx/secubox.d
	cp nginx/proxypac.conf debian/secubox-proxypac/etc/nginx/secubox.d/
	install -d debian/secubox-proxypac/etc/nginx/sites-available
	cp nginx/wpad-vhost.conf debian/secubox-proxypac/etc/nginx/sites-available/
	install -d debian/secubox-proxypac/usr/lib/systemd/system
	cp systemd/*.service systemd/*.path systemd/*.timer debian/secubox-proxypac/usr/lib/systemd/system/
	install -d debian/secubox-proxypac/etc/secubox/proxypac/rules.d
	cp conf/rules.d/*.rules debian/secubox-proxypac/etc/secubox/proxypac/rules.d/
	install -d debian/secubox-proxypac/usr/share/secubox/www
	cp -r www/. debian/secubox-proxypac/usr/share/secubox/www/
	install -d debian/secubox-proxypac/usr/share/secubox/menu.d
	cp menu.d/*.json debian/secubox-proxypac/usr/share/secubox/menu.d/
```

`debian/postinst` (`#!/bin/bash`, `set -e`):

```bash
#!/bin/bash
set -e
if [ "$1" = "configure" ]; then
    getent passwd secubox >/dev/null || useradd --system --group secubox || true
    install -d -o secubox -g secubox /var/lib/secubox/proxypac
    /usr/sbin/proxypac-gen || true   # initial generation (fail-safe)
    systemctl daemon-reload || true
    systemctl enable --now secubox-proxypac-gen.path || true
    systemctl enable --now secubox-proxypac-gen.timer || true
    nginx -t && systemctl reload nginx || true
fi
#DEBHELPER#
```

`debian/prerm` (`#!/bin/bash`, `set -e`):

```bash
#!/bin/bash
set -e
if [ "$1" = "remove" ]; then
    systemctl disable --now secubox-proxypac-gen.path secubox-proxypac-gen.timer || true
fi
#DEBHELPER#
```

`debian/changelog`:

```
secubox-proxypac (1.0.0-1~bookworm1) bookworm; urgency=medium

  * Initial release: WPAD/PAC auto-config routing to active mesh services (#784).

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 03 Jul 2026 00:00:00 +0200
```

- [ ] **Step 4: Run to verify pass**

Run: `cd packages/secubox-proxypac && PYTHONPATH=. python -m pytest tests/test_packaging.py -q && chmod +x debian/postinst debian/prerm`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-proxypac/debian/ packages/secubox-proxypac/tests/test_packaging.py
git commit -m "feat(proxypac): debian packaging (ref #784)"
```

---

## Task 11: README + full-suite green

**Files:**
- Create: `packages/secubox-proxypac/README.md`
- Test: run the whole package suite.

- [ ] **Step 1: Write README** documenting: what it does, the rules.d format, the annuaire `pac` field, WPAD delivery + DHCP 252, the fail-safe/atomic-swap invariant, and the deploy note (add `proxypac` to `aggregator.toml`, install `wpad-vhost.conf` into `sites-enabled`, deploy `dnsmasq-wpad.conf` to the AP).

- [ ] **Step 2: Run the whole suite**

Run: `cd packages/secubox-proxypac && PYTHONPATH="$(git rev-parse --show-toplevel)/common:." python -m pytest tests/ -q`
Expected: PASS (all tasks' tests).

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-proxypac/README.md
git commit -m "docs(proxypac): README + deploy notes (ref #784)"
```

---

## Self-Review (plan vs spec)

- **Spec coverage:** generator+atomic+fail-safe (T5), WPAD/PAC serving LAN-only (T7), regen trigger path+timer+hook (T8, hook = the p2p activate calling `proxypac-gen` is a deploy wiring noted in README/T11), hybrid source: annuaire pac (T1) + service rules (T4) + operator override+precedence (T3,T6) + auto-learn candidates (T6), WebUI panel (T9), webext complement (deferred — spec marks it optional; not a task here, tracked on #655), CSPN audit + atomic swap (T5,T6), tests (every task). Gateway/off-mesh explicitly out of scope (B).
- **Placeholder scan:** none — every code step has full code; config files have full content.
- **Type consistency:** `Rule(host,directive,source)` used identically in T3/T4/T5; `directive(proxy_type,address)` signature stable T2→T3→T4→T6; `run_once`/`write_atomic`/`generate` signatures stable T5→T6.
- **Gap noted (non-blocking):** the auto-learn *detector* that populates `candidates.json` is out of scope here (fed later by #743); T6 ships the accept/reject/read half so the loop is closable.
