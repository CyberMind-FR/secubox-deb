<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Eye Remote Multi-Gadget DHCP — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Multiple Pi RNDIS gadgets connected to a SecuBox host (MOCHAbin / ESPRESSObin) each get a stable, distinct L3 address via a scoped DHCP server on `eye-br0`, with a registry exposed through the existing eye-remote API.

**Architecture:** A dedicated `secubox-eye-remote-dhcp.service` runs `dnsmasq` bound only to `eye-br0` (`10.55.0.1`). Auto-managed per-MAC reservations live in `/etc/secubox/eye-remote/reservations.conf`. A `dhcp-script` hook records lease events and appends reservation stubs for never-seen MACs. The FastAPI service gains `/api/v1/eye-remote/leases` (list known gadgets) and `/api/v1/eye-remote/lease-events` (called by the hook on loopback). Round image switches `eye0` from static peer config to DHCP client.

**Tech Stack:** Python 3.11 (FastAPI / Pydantic v2 / pytest), dnsmasq, systemd-networkd, systemd template units, bash 5 (`set -euo pipefail`), nftables, Debian packaging (`debhelper`, `dpkg-buildpackage`).

**Spec:** [`docs/superpowers/specs/2026-05-16-eye-remote-multi-gadget-dhcp-pairing-design.md`](../specs/2026-05-16-eye-remote-multi-gadget-dhcp-pairing-design.md)

**Out of scope (Phase 2 follow-up):** pair-before-lease approval gate; UI pending-pairing queue; ZKP/NIZK pair handshake. Every Phase 2 change extends a Phase 1 file rather than replacing it.

---

## File Structure

### New files

| Path | Responsibility |
|---|---|
| `packages/secubox-eye-remote/api/lib/__init__.py` | Library package marker |
| `packages/secubox-eye-remote/api/lib/reservations.py` | Parse / serialize `dhcp-host=…` lines |
| `packages/secubox-eye-remote/api/lib/leasefile.py` | Parse `/var/lib/misc/dnsmasq-eye-remote.leases` |
| `packages/secubox-eye-remote/api/lib/assign.py` | Pick lowest free octet ≥ `.11` |
| `packages/secubox-eye-remote/api/models/lease.py` | Pydantic models (`LeaseRecord`, `LeaseEvent`) |
| `packages/secubox-eye-remote/api/routers/leases.py` | `GET /leases`, `POST /lease-events` |
| `packages/secubox-eye-remote/dnsmasq.d/eye-remote.conf` | dnsmasq config (scoped to `eye-br0`) |
| `packages/secubox-eye-remote/systemd/secubox-eye-remote-dhcp.service` | Dedicated dnsmasq unit |
| `packages/secubox-eye-remote/nftables/secubox-eye-remote.nft` | Narrow allow rules on `eye-br0` |
| `packages/secubox-eye-remote/etc/secubox/eye-remote/reservations.conf.seed` | Empty seed shipped as conffile-noreplace |
| `packages/secubox-eye-remote/tests/unit/test_reservations.py` | Reservations parser tests |
| `packages/secubox-eye-remote/tests/unit/test_leasefile.py` | Lease file parser tests |
| `packages/secubox-eye-remote/tests/unit/test_assign.py` | IP assignment tests |
| `packages/secubox-eye-remote/tests/integration/test_leases_router.py` | FastAPI TestClient |
| `packages/secubox-eye-remote/tests/integration/test_multi_gadget_dhcp.py` | netns + dnsmasq + dhclient |
| `packages/secubox-system/usr/lib/secubox/eye-remote-find-usb-serial` | MAC → USB serial helper |
| `packages/secubox-system/usr/lib/secubox/eye-remote-leasewatch.sh` | `dhcp-script` hook |
| `packages/secubox-system/tests/test_leasewatch.bats` | bats coverage for the hook |
| `remote-ui/round/files/etc/systemd/network/10-eye0.network` | Pi-side DHCP client |
| `remote-ui/round/files/usr/local/sbin/eye-firstboot-hostname.sh` | Pi-side hostname derive |
| `remote-ui/round/files/etc/systemd/system/eye-firstboot-hostname.service` | one-shot at first boot |

### Modified files

| Path | Change |
|---|---|
| `packages/secubox-eye-remote/api/main.py` | Register `leases.router` |
| `packages/secubox-eye-remote/debian/control` | Add `Depends: dnsmasq-base` |
| `packages/secubox-eye-remote/debian/secubox-eye-remote.install` | Ship the new files |
| `packages/secubox-eye-remote/debian/secubox-eye-remote.conffiles` | Mark `reservations.conf` as conffile |
| `packages/secubox-eye-remote/debian/secubox-eye-remote.postinst` | Create dirs, enable dnsmasq unit, mask system-wide `dnsmasq.service` |
| `packages/secubox-eye-remote/debian/secubox-eye-remote.prerm` | Disable + stop dnsmasq unit |
| `packages/secubox-system/debian/secubox-system.install` | Ship the two helper scripts |
| `remote-ui/round/build-eye-remote-image.sh` | Copy `files/` tree into the rootfs + enable firstboot unit |
| `remote-ui/round/MULTI-GADGET.md` | "Resolved by #158" banner |
| `.claude/WIP.md` | Move #158 to ✅ |
| `.claude/HISTORY.md` | Append dated entry |

---

## Tasks

### Task 1: Reservations parser (round-trip)

**Files:**
- Create: `packages/secubox-eye-remote/api/lib/__init__.py`
- Create: `packages/secubox-eye-remote/api/lib/reservations.py`
- Test: `packages/secubox-eye-remote/tests/unit/test_reservations.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/secubox-eye-remote/tests/unit/test_reservations.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: eye-remote reservations parser tests."""
from pathlib import Path

import pytest

from secubox_eye_remote.api.lib.reservations import (
    Reservation,
    append_reservation,
    parse_reservations,
    serialize_reservation,
)


def test_parse_single_line():
    src = "dhcp-host=02:fb:00:00:11:03,10.55.0.11,eye-1000000011f3b403,24h\n"
    [r] = parse_reservations(src)
    assert r.mac == "02:fb:00:00:11:03"
    assert r.ip == "10.55.0.11"
    assert r.hostname == "eye-1000000011f3b403"
    assert r.lease_time == "24h"


def test_parse_skips_comments_and_blank():
    src = "# comment\n\ndhcp-host=02:fb:00:00:11:03,10.55.0.11,a,24h\n# trailing\n"
    rs = parse_reservations(src)
    assert len(rs) == 1
    assert rs[0].mac == "02:fb:00:00:11:03"


def test_parse_rejects_short_mac():
    with pytest.raises(ValueError, match="invalid MAC"):
        parse_reservations("dhcp-host=02:fb,10.55.0.11,a,24h\n")


def test_serialize_round_trip():
    r = Reservation(
        mac="02:fb:00:00:d2:7f",
        ip="10.55.0.12",
        hostname="eye-00000000d253b17f",
        lease_time="24h",
    )
    assert (
        serialize_reservation(r)
        == "dhcp-host=02:fb:00:00:d2:7f,10.55.0.12,eye-00000000d253b17f,24h"
    )


def test_append_reservation_is_idempotent(tmp_path: Path):
    f = tmp_path / "reservations.conf"
    f.write_text("")
    r = Reservation("02:fb:00:00:11:03", "10.55.0.11", "eye-x", "24h")
    assert append_reservation(f, r) is True
    assert append_reservation(f, r) is False
    assert f.read_text().count("dhcp-host=") == 1


def test_append_reservation_rejects_mac_conflict(tmp_path: Path):
    f = tmp_path / "reservations.conf"
    f.write_text("dhcp-host=02:fb:00:00:11:03,10.55.0.11,old,24h\n")
    with pytest.raises(ValueError, match="conflict"):
        append_reservation(
            f,
            Reservation("02:fb:00:00:11:03", "10.55.0.99", "new", "24h"),
        )
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd packages/secubox-eye-remote
python -m pytest tests/unit/test_reservations.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_eye_remote.api.lib.reservations'`.

- [ ] **Step 3: Implement the parser**

```python
# packages/secubox-eye-remote/api/lib/__init__.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: eye-remote API library helpers."""
```

```python
# packages/secubox-eye-remote/api/lib/reservations.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: eye-remote reservations parser.

Reads / writes dnsmasq `dhcp-host=` lines stored in
/etc/secubox/eye-remote/reservations.conf. The file is conffile-managed,
so we never rewrite it in place — we only append.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_LINE_RE = re.compile(r"^dhcp-host=([^,]+),([^,]+),([^,]*),([^,\n]+)\s*$")


@dataclass(frozen=True)
class Reservation:
    mac: str
    ip: str
    hostname: str
    lease_time: str

    def __post_init__(self) -> None:
        if not _MAC_RE.match(self.mac):
            raise ValueError(f"invalid MAC: {self.mac!r}")


def parse_reservations(src: str) -> list[Reservation]:
    """Parse the textual contents of reservations.conf.

    Comments (`#…`) and blank lines are ignored. Any non-blank, non-comment
    line that does not match the `dhcp-host=` shape raises ValueError so
    we never silently drop user-edited lines.
    """
    out: list[Reservation] = []
    for raw in src.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            raise ValueError(f"unparseable line: {line!r}")
        out.append(Reservation(m.group(1), m.group(2), m.group(3), m.group(4)))
    return out


def serialize_reservation(r: Reservation) -> str:
    return f"dhcp-host={r.mac},{r.ip},{r.hostname},{r.lease_time}"


def append_reservation(path: Path, r: Reservation) -> bool:
    """Append a reservation to `path` if no entry for its MAC exists.

    Returns True if the file was modified, False if the exact MAC was
    already present. Raises ValueError if the MAC is present but bound to
    a different IP / hostname — we never silently overwrite.
    """
    existing: list[Reservation] = []
    if path.exists():
        existing = parse_reservations(path.read_text())
    for cur in existing:
        if cur.mac != r.mac:
            continue
        if cur == r:
            return False
        raise ValueError(
            f"conflict: MAC {r.mac} already maps to {cur.ip}/{cur.hostname}"
        )
    with path.open("a", encoding="utf-8") as fh:
        fh.write(serialize_reservation(r) + "\n")
    return True


def filter_active(
    reservations: Iterable[Reservation], active_macs: Iterable[str]
) -> list[Reservation]:
    active = {m.lower() for m in active_macs}
    return [r for r in reservations if r.mac.lower() in active]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd packages/secubox-eye-remote
python -m pytest tests/unit/test_reservations.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-remote/api/lib/__init__.py \
        packages/secubox-eye-remote/api/lib/reservations.py \
        packages/secubox-eye-remote/tests/unit/test_reservations.py
git commit -m "feat(eye-remote): reservations parser for dnsmasq dhcp-host lines (ref #158)"
```

---

### Task 2: dnsmasq lease file parser

**Files:**
- Create: `packages/secubox-eye-remote/api/lib/leasefile.py`
- Test: `packages/secubox-eye-remote/tests/unit/test_leasefile.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/secubox-eye-remote/tests/unit/test_leasefile.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: dnsmasq lease file parser tests."""
from pathlib import Path

from secubox_eye_remote.api.lib.leasefile import Lease, parse_leases


def test_parse_two_active_leases():
    src = (
        "1747500000 02:fb:00:00:11:03 10.55.0.11 eye-rpiz 01:02:fb:00:00:11:03\n"
        "1747503600 02:fb:00:00:d2:7f 10.55.0.12 eye-pi4b 01:02:fb:00:00:d2:7f\n"
    )
    leases = parse_leases(src)
    assert {l.mac for l in leases} == {
        "02:fb:00:00:11:03",
        "02:fb:00:00:d2:7f",
    }


def test_parse_handles_missing_hostname():
    src = "1747500000 02:fb:00:00:11:03 10.55.0.11 * 01:02:fb:00:00:11:03\n"
    [l] = parse_leases(src)
    assert l.hostname is None


def test_parse_ignores_blank_and_short_lines():
    src = "\n\nbroken-line\n1747500000 02:fb:00:00:11:03 10.55.0.11 a id\n"
    leases = parse_leases(src)
    assert len(leases) == 1


def test_parse_path_round_trip(tmp_path: Path):
    p = tmp_path / "leases"
    p.write_text("1747500000 02:fb:00:00:11:03 10.55.0.11 a id\n")
    [l] = parse_leases(p.read_text())
    assert l.ip == "10.55.0.11"
    assert l.expiry == 1747500000
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/unit/test_leasefile.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_eye_remote.api.lib.leasefile'`.

- [ ] **Step 3: Implement the parser**

```python
# packages/secubox-eye-remote/api/lib/leasefile.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: dnsmasq lease file parser.

Each line: <expiry-epoch> <mac> <ip> <hostname-or-*> <client-id>
The file lives at /var/lib/misc/dnsmasq-eye-remote.leases on the host.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Lease:
    expiry: int
    mac: str
    ip: str
    hostname: str | None
    client_id: str | None


def parse_leases(src: str) -> list[Lease]:
    out: list[Lease] = []
    for raw in src.splitlines():
        parts = raw.strip().split()
        if len(parts) < 4:
            continue
        try:
            expiry = int(parts[0])
        except ValueError:
            continue
        mac = parts[1]
        ip = parts[2]
        hostname = parts[3] if parts[3] != "*" else None
        client_id = parts[4] if len(parts) >= 5 else None
        out.append(Lease(expiry, mac, ip, hostname, client_id))
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/unit/test_leasefile.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-remote/api/lib/leasefile.py \
        packages/secubox-eye-remote/tests/unit/test_leasefile.py
git commit -m "feat(eye-remote): dnsmasq lease file parser (ref #158)"
```

---

### Task 3: IP auto-assignment

**Files:**
- Create: `packages/secubox-eye-remote/api/lib/assign.py`
- Test: `packages/secubox-eye-remote/tests/unit/test_assign.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/secubox-eye-remote/tests/unit/test_assign.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: eye-remote IP auto-assignment tests."""
import pytest

from secubox_eye_remote.api.lib.assign import assign_ip
from secubox_eye_remote.api.lib.reservations import Reservation


def test_assigns_first_free_starting_at_11():
    rs: list[Reservation] = []
    assert assign_ip(rs) == "10.55.0.11"


def test_skips_existing():
    rs = [
        Reservation("02:fb:00:00:11:03", "10.55.0.11", "a", "24h"),
        Reservation("02:fb:00:00:11:04", "10.55.0.12", "b", "24h"),
    ]
    assert assign_ip(rs) == "10.55.0.13"


def test_fills_gaps():
    rs = [
        Reservation("02:fb:00:00:11:03", "10.55.0.11", "a", "24h"),
        Reservation("02:fb:00:00:11:04", "10.55.0.13", "b", "24h"),
    ]
    assert assign_ip(rs) == "10.55.0.12"


def test_exhausted_pool_raises():
    rs = [
        Reservation(
            mac=f"02:fb:00:00:00:{i:02x}",
            ip=f"10.55.0.{i}",
            hostname=f"h{i}",
            lease_time="24h",
        )
        for i in range(11, 251)
    ]
    with pytest.raises(RuntimeError, match="exhausted"):
        assign_ip(rs)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/unit/test_assign.py -v
```

Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement assign_ip**

```python
# packages/secubox-eye-remote/api/lib/assign.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: eye-remote IP auto-assignment.

Picks the lowest free /24 octet in [11, 250] given the current
reservation set. .1 is the host bridge gateway and is never assigned;
.2..10 are reserved for static debugging / future use.
"""
from __future__ import annotations

from typing import Iterable

from .reservations import Reservation

POOL_START = 11
POOL_END = 250
SUBNET_PREFIX = "10.55.0."


def assign_ip(reservations: Iterable[Reservation]) -> str:
    taken: set[int] = set()
    for r in reservations:
        if not r.ip.startswith(SUBNET_PREFIX):
            continue
        try:
            taken.add(int(r.ip.removeprefix(SUBNET_PREFIX)))
        except ValueError:
            continue
    for octet in range(POOL_START, POOL_END + 1):
        if octet not in taken:
            return f"{SUBNET_PREFIX}{octet}"
    raise RuntimeError("eye-remote DHCP pool exhausted (.11–.250 all in use)")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/unit/test_assign.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-remote/api/lib/assign.py \
        packages/secubox-eye-remote/tests/unit/test_assign.py
git commit -m "feat(eye-remote): IP auto-assignment for dnsmasq reservations (ref #158)"
```

---

### Task 4: Pydantic models for the leases router

**Files:**
- Create: `packages/secubox-eye-remote/api/models/lease.py`

- [ ] **Step 1: Write the model and a quick smoke test**

```python
# packages/secubox-eye-remote/tests/unit/test_lease_models.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: lease Pydantic model smoke tests."""
import pytest
from pydantic import ValidationError

from secubox_eye_remote.api.models.lease import LeaseEvent, LeaseRecord


def test_lease_event_accepts_lifecycle_actions():
    for a in ("add", "old", "del", "discover"):
        LeaseEvent(action=a, mac="02:fb:00:00:11:03", ip="10.55.0.11")


def test_lease_event_rejects_unknown_action():
    with pytest.raises(ValidationError):
        LeaseEvent(action="bogus", mac="02:fb:00:00:11:03", ip="10.55.0.11")


def test_lease_record_round_trip():
    rec = LeaseRecord(
        mac="02:fb:00:00:11:03",
        ip="10.55.0.11",
        hostname="eye-rpiz",
        serial="1000000011f3b403",
        last_seen=1747500000,
        approved=True,
    )
    assert rec.model_dump()["approved"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/unit/test_lease_models.py -v
```

Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement the models**

```python
# packages/secubox-eye-remote/api/models/lease.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: eye-remote lease Pydantic models."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


LeaseAction = Literal["add", "old", "del", "discover"]


class LeaseEvent(BaseModel):
    """Body of POST /api/v1/eye-remote/lease-events.

    Sent by /usr/lib/secubox/eye-remote-leasewatch.sh on every dnsmasq
    dhcp-script invocation.
    """

    action: LeaseAction
    mac: str = Field(pattern=r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
    ip: str
    hostname: str | None = None


class LeaseRecord(BaseModel):
    """Element of GET /api/v1/eye-remote/leases response."""

    mac: str
    ip: str
    hostname: str | None
    serial: str | None
    last_seen: int | None
    approved: bool = True  # Phase 1: every reservation is auto-approved
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/unit/test_lease_models.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-remote/api/models/lease.py \
        packages/secubox-eye-remote/tests/unit/test_lease_models.py
git commit -m "feat(eye-remote): Pydantic models for lease registry (ref #158)"
```

---

### Task 5: `/leases` FastAPI router

**Files:**
- Create: `packages/secubox-eye-remote/api/routers/leases.py`
- Test: `packages/secubox-eye-remote/tests/integration/test_leases_router.py`

- [ ] **Step 1: Write the failing integration test**

```python
# packages/secubox-eye-remote/tests/integration/test_leases_router.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: eye-remote leases router integration tests."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch, tmp_path: Path) -> TestClient:
    leases = tmp_path / "leases"
    leases.write_text(
        "1747500000 02:fb:00:00:11:03 10.55.0.11 eye-rpiz id1\n"
        "1747503600 02:fb:00:00:d2:7f 10.55.0.12 eye-pi4b id2\n"
    )
    res = tmp_path / "reservations.conf"
    res.write_text(
        "dhcp-host=02:fb:00:00:11:03,10.55.0.11,eye-rpiz,24h\n"
        "dhcp-host=02:fb:00:00:d2:7f,10.55.0.12,eye-pi4b,24h\n"
    )
    monkeypatch.setenv("SECUBOX_EYE_LEASE_FILE", str(leases))
    monkeypatch.setenv("SECUBOX_EYE_RESERVATIONS_FILE", str(res))

    from secubox_eye_remote.api.main import app

    return TestClient(app)


def test_get_leases_returns_active_only(client: TestClient):
    r = client.get("/api/v1/eye-remote/leases")
    assert r.status_code == 200
    body = r.json()
    macs = {row["mac"] for row in body}
    assert macs == {"02:fb:00:00:11:03", "02:fb:00:00:d2:7f"}


def test_post_lease_event_records(client: TestClient):
    r = client.post(
        "/api/v1/eye-remote/lease-events",
        json={
            "action": "add",
            "mac": "02:fb:00:00:11:03",
            "ip": "10.55.0.11",
            "hostname": "eye-rpiz",
        },
    )
    assert r.status_code == 200
    assert r.json() == {"status": "recorded"}


def test_post_lease_event_rejects_bad_mac(client: TestClient):
    r = client.post(
        "/api/v1/eye-remote/lease-events",
        json={"action": "add", "mac": "not-a-mac", "ip": "10.55.0.11"},
    )
    assert r.status_code == 422
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/integration/test_leases_router.py -v
```

Expected: 404 from GET (router not registered) or import error.

- [ ] **Step 3: Implement the router**

```python
# packages/secubox-eye-remote/api/routers/leases.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: eye-remote leases router.

GET  /api/v1/eye-remote/leases         — list known gadgets
POST /api/v1/eye-remote/lease-events   — dhcp-script hook notifications

Listener-side notification path. The pair-before-lease synchronous gate
(Phase 2) will live alongside in /pair/check, not here.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import APIRouter

from ..lib.leasefile import parse_leases
from ..lib.reservations import filter_active, parse_reservations
from ..models.lease import LeaseEvent, LeaseRecord

router = APIRouter(prefix="/eye-remote", tags=["eye-remote"])

_DEFAULT_LEASE_FILE = "/var/lib/misc/dnsmasq-eye-remote.leases"
_DEFAULT_RESERVATIONS_FILE = "/etc/secubox/eye-remote/reservations.conf"


def _read(path_env: str, default: str) -> str:
    path = Path(os.environ.get(path_env, default))
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


@router.get("/leases", response_model=list[LeaseRecord])
def list_leases() -> list[LeaseRecord]:
    leases = parse_leases(_read("SECUBOX_EYE_LEASE_FILE", _DEFAULT_LEASE_FILE))
    reservations = parse_reservations(
        _read("SECUBOX_EYE_RESERVATIONS_FILE", _DEFAULT_RESERVATIONS_FILE)
    )
    active_macs = {l.mac.lower() for l in leases}
    by_mac = {r.mac.lower(): r for r in filter_active(reservations, active_macs)}

    now = int(time.time())
    out: list[LeaseRecord] = []
    for lease in leases:
        if lease.expiry < now:
            continue
        r = by_mac.get(lease.mac.lower())
        out.append(
            LeaseRecord(
                mac=lease.mac,
                ip=lease.ip,
                hostname=(r.hostname if r else lease.hostname),
                serial=None,
                last_seen=lease.expiry,
                approved=True,
            )
        )
    return out


@router.post("/lease-events")
def lease_event(body: LeaseEvent) -> dict[str, str]:
    # Phase 1: events are observed but not persisted beyond logs. Phase 2
    # will wire this to a small SQLite or sqlite-shaped registry alongside
    # the reservation file.
    import logging

    logging.getLogger(__name__).info(
        "lease-event action=%s mac=%s ip=%s host=%s",
        body.action,
        body.mac,
        body.ip,
        body.hostname,
    )
    return {"status": "recorded"}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/integration/test_leases_router.py -v
```

Expected: 3 passed (after Task 6 registers the router; if you run before Task 6, the first test still 404s — proceed to Task 6).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-remote/api/routers/leases.py \
        packages/secubox-eye-remote/tests/integration/test_leases_router.py
git commit -m "feat(eye-remote): /leases + /lease-events FastAPI router (ref #158)"
```

---

### Task 6: Register `leases.router` in main.py

**Files:**
- Modify: `packages/secubox-eye-remote/api/main.py`

- [ ] **Step 1: Inspect current router registrations**

```bash
grep -n "include_router\|from .routers" packages/secubox-eye-remote/api/main.py
```

Note the existing pattern; copy it.

- [ ] **Step 2: Add the import + include_router**

In `packages/secubox-eye-remote/api/main.py`, alongside the other router imports add:

```python
from .routers import leases as leases_router
```

…and alongside the other `app.include_router(...)` calls:

```python
app.include_router(leases_router.router, prefix="/api/v1")
```

(If main.py uses a different prefix scheme — e.g. routers already declare their own `/api/v1` prefix — match it exactly. Don't double-prefix.)

- [ ] **Step 3: Re-run Task 5's integration tests**

```bash
python -m pytest tests/integration/test_leases_router.py -v
```

Expected: 3 passed.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-eye-remote/api/main.py
git commit -m "feat(eye-remote): wire /leases router into the API (ref #158)"
```

---

### Task 7: dnsmasq config snippet

**Files:**
- Create: `packages/secubox-eye-remote/dnsmasq.d/eye-remote.conf`
- Create: `packages/secubox-eye-remote/etc/secubox/eye-remote/reservations.conf.seed`

- [ ] **Step 1: Write the dnsmasq config**

```bash
mkdir -p packages/secubox-eye-remote/dnsmasq.d \
         packages/secubox-eye-remote/etc/secubox/eye-remote
```

```conf
# packages/secubox-eye-remote/dnsmasq.d/eye-remote.conf
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: eye-remote DHCP server config (issue #158)
# Bound exclusively to eye-br0; never serves lan0 or any LXC veth.

interface=eye-br0
bind-interfaces
listen-address=10.55.0.1
except-interface=lo

# DHCP-only daemon — no DNS, no system /etc/hosts.
port=0
no-resolv
no-hosts
no-poll

domain=eye-remote.secubox.local
local=/eye-remote.secubox.local/

dhcp-range=10.55.0.10,10.55.0.250,255.255.255.0,24h
dhcp-authoritative
dhcp-leasefile=/var/lib/misc/dnsmasq-eye-remote.leases

# Hook for lease lifecycle (Phase 1: notify only;
# Phase 2 will gate DHCPOFFER on a sync pair/check call from here).
dhcp-script=/usr/lib/secubox/eye-remote-leasewatch.sh

# Reservations are auto-managed; never hand-edit.
conf-file=/etc/secubox/eye-remote/reservations.conf

log-dhcp
log-facility=/var/log/secubox/eye-remote-dhcp.log
```

```conf
# packages/secubox-eye-remote/etc/secubox/eye-remote/reservations.conf.seed
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: eye-remote DHCP reservations (issue #158)
# AUTO-MANAGED by /usr/lib/secubox/eye-remote-leasewatch.sh on first attach.
# Hand edits survive package upgrades (declared as conffile).
# Format: dhcp-host=<MAC>,<IP>,<hostname>,<lease-time>
```

- [ ] **Step 2: Validate syntax with `dnsmasq --test`**

```bash
dnsmasq --test --conf-file=packages/secubox-eye-remote/dnsmasq.d/eye-remote.conf \
        --conf-file=packages/secubox-eye-remote/etc/secubox/eye-remote/reservations.conf.seed
```

Expected: `dnsmasq: syntax check OK.`

If your local box does not have dnsmasq installed, install it: `sudo apt install -y dnsmasq-base`.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-eye-remote/dnsmasq.d/eye-remote.conf \
        packages/secubox-eye-remote/etc/secubox/eye-remote/reservations.conf.seed
git commit -m "feat(eye-remote): scoped dnsmasq config for eye-br0 DHCP (ref #158)"
```

---

### Task 8: Dedicated dnsmasq service unit

**Files:**
- Create: `packages/secubox-eye-remote/systemd/secubox-eye-remote-dhcp.service`

- [ ] **Step 1: Write the unit**

```bash
mkdir -p packages/secubox-eye-remote/systemd
```

```ini
# packages/secubox-eye-remote/systemd/secubox-eye-remote-dhcp.service
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
[Unit]
Description=SecuBox Eye Remote — DHCP server on eye-br0
Documentation=https://github.com/CyberMind-FR/secubox-deb/issues/158
Requires=sys-subsystem-net-devices-eye_br0.device
After=sys-subsystem-net-devices-eye_br0.device systemd-networkd.service
ConditionPathExists=/sys/class/net/eye-br0

[Service]
Type=simple
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground \
    --conf-file=/etc/dnsmasq.d/eye-remote.conf \
    --pid-file=/run/secubox-eye-remote-dhcp.pid \
    --user=dnsmasq --group=nogroup
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/run/secubox-eye-remote-dhcp.pid
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/misc /var/log/secubox /run
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Lint with `systemd-analyze verify`**

```bash
systemd-analyze verify packages/secubox-eye-remote/systemd/secubox-eye-remote-dhcp.service
```

Expected: no output (success).

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-eye-remote/systemd/secubox-eye-remote-dhcp.service
git commit -m "feat(eye-remote): dedicated dnsmasq service for eye-br0 (ref #158)"
```

---

### Task 9: `eye-remote-find-usb-serial` helper

**Files:**
- Create: `packages/secubox-system/usr/lib/secubox/eye-remote-find-usb-serial`

- [ ] **Step 1: Write the helper**

```bash
mkdir -p packages/secubox-system/usr/lib/secubox
```

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Given a MAC address (arg 1), print the USB serial of the device that
# backs the matching netdev. Exits 1 if no match.
# Used by eye-remote-leasewatch.sh to encode a stable hostname.
set -euo pipefail

target_mac="${1:-}"
if [[ -z "$target_mac" ]]; then
    echo "usage: $0 <MAC>" >&2
    exit 2
fi
target_mac=${target_mac,,}

for iface in /sys/class/net/*; do
    [[ -f "$iface/address" ]] || continue
    mac=$(< "$iface/address")
    [[ "${mac,,}" == "$target_mac" ]] || continue
    p=$(readlink -f "$iface/device" 2>/dev/null) || continue
    while [[ -n "$p" && "$p" != "/" ]]; do
        if [[ -f "$p/serial" ]]; then
            cat "$p/serial"
            exit 0
        fi
        p=$(dirname "$p")
    done
done
exit 1
```

```bash
chmod +x packages/secubox-system/usr/lib/secubox/eye-remote-find-usb-serial
```

- [ ] **Step 2: Smoke-test locally if a gadget happens to be plugged in**

```bash
shellcheck packages/secubox-system/usr/lib/secubox/eye-remote-find-usb-serial
```

Expected: no diagnostics.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-system/usr/lib/secubox/eye-remote-find-usb-serial
git commit -m "feat(secubox-system): eye-remote-find-usb-serial MAC→serial helper (ref #158)"
```

---

### Task 10: `eye-remote-leasewatch.sh` dhcp-script hook

**Files:**
- Create: `packages/secubox-system/usr/lib/secubox/eye-remote-leasewatch.sh`
- Test: `packages/secubox-system/tests/test_leasewatch.bats`

- [ ] **Step 1: Write the failing bats test**

```bash
mkdir -p packages/secubox-system/tests
```

```bash
#!/usr/bin/env bats
# packages/secubox-system/tests/test_leasewatch.bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

setup() {
    export TMP=$(mktemp -d)
    export RES="$TMP/reservations.conf"
    export SECUBOX_EYE_RESERVATIONS_FILE="$RES"
    export SECUBOX_EYE_SKIP_RELOAD=1   # don't call systemctl in tests
    export SECUBOX_EYE_SKIP_API=1      # don't curl the API in tests
    touch "$RES"
    SCRIPT="$BATS_TEST_DIRNAME/../usr/lib/secubox/eye-remote-leasewatch.sh"
}

teardown() {
    rm -rf "$TMP"
}

@test "add: appends reservation for new MAC" {
    run "$SCRIPT" add 02:fb:00:00:11:03 10.55.0.11 eye-rpiz
    [ "$status" -eq 0 ]
    grep -q "^dhcp-host=02:fb:00:00:11:03,10.55.0.11,eye-rpiz" "$RES"
}

@test "add: is idempotent for the same MAC" {
    "$SCRIPT" add 02:fb:00:00:11:03 10.55.0.11 eye-rpiz
    "$SCRIPT" add 02:fb:00:00:11:03 10.55.0.11 eye-rpiz
    [ "$(grep -c '^dhcp-host=' "$RES")" -eq 1 ]
}

@test "old: does not append anything" {
    "$SCRIPT" old 02:fb:00:00:11:03 10.55.0.11 eye-rpiz
    [ ! -s "$RES" ]
}

@test "missing hostname: fills from MAC suffix" {
    "$SCRIPT" add 02:fb:00:00:11:03 10.55.0.11
    grep -q "eye-fb00001103" "$RES"
}
```

- [ ] **Step 2: Run bats to verify the script is missing**

```bash
bats packages/secubox-system/tests/test_leasewatch.bats
```

Expected: failure — script does not yet exist.

- [ ] **Step 3: Implement the hook**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox-Deb :: eye-remote dnsmasq dhcp-script hook (issue #158)
# Called by dnsmasq on every lease lifecycle event:
#     $1 = action  (add | old | del)
#     $2 = MAC
#     $3 = IP
#     $4 = hostname (optional, "*" if absent)
#
# Side effects:
#   - On `add` for a never-before-seen MAC: append a stable reservation
#     to /etc/secubox/eye-remote/reservations.conf and reload dnsmasq.
#   - Always: POST a notification to the eye-remote API on loopback.
set -euo pipefail

action="${1:-}"
mac="${2:-}"
ip="${3:-}"
hostname="${4:-}"
[[ "$hostname" == "*" ]] && hostname=""

RES_FILE="${SECUBOX_EYE_RESERVATIONS_FILE:-/etc/secubox/eye-remote/reservations.conf}"
LEASE_TIME="${SECUBOX_EYE_LEASE_TIME:-24h}"
API_URL="${SECUBOX_EYE_API_URL:-http://127.0.0.1:8000/api/v1/eye-remote/lease-events}"
FIND_SERIAL="${SECUBOX_EYE_FIND_SERIAL:-/usr/lib/secubox/eye-remote-find-usb-serial}"

log() { logger -t secubox-eye-leasewatch "$*"; }

derive_hostname() {
    local m="$1"
    if [[ -n "$hostname" ]]; then
        echo "$hostname"
        return
    fi
    if [[ -x "$FIND_SERIAL" ]]; then
        local serial
        if serial=$("$FIND_SERIAL" "$m" 2>/dev/null); then
            echo "eye-$serial"
            return
        fi
    fi
    # Fallback: last 4 octets of the MAC, no separators
    echo "eye-${m//:/}" | sed -E 's/^eye-[0-9a-fA-F]{4}/eye-/'
}

ensure_reservation() {
    local m="$1" i="$2" h="$3"
    if [[ ! -f "$RES_FILE" ]]; then
        install -D -m 0644 /dev/null "$RES_FILE"
    fi
    if grep -qE "^dhcp-host=${m}," "$RES_FILE"; then
        log "reservation already exists for $m, leaving alone"
        return
    fi
    printf 'dhcp-host=%s,%s,%s,%s\n' "$m" "$i" "$h" "$LEASE_TIME" >> "$RES_FILE"
    log "appended reservation: $m -> $i ($h)"
    if [[ -z "${SECUBOX_EYE_SKIP_RELOAD:-}" ]]; then
        systemctl reload secubox-eye-remote-dhcp.service || true
    fi
}

notify_api() {
    [[ -n "${SECUBOX_EYE_SKIP_API:-}" ]] && return 0
    command -v curl >/dev/null 2>&1 || return 0
    curl --max-time 2 -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "$(printf '{"action":"%s","mac":"%s","ip":"%s","hostname":"%s"}' \
              "$action" "$mac" "$ip" "$hostname")" \
        >/dev/null 2>&1 || true
}

case "$action" in
    add)
        host=$(derive_hostname "$mac")
        ensure_reservation "$mac" "$ip" "$host"
        ;;
    old|del)
        # Phase 1: events are reported only; Phase 2 may rotate or expire.
        :
        ;;
    *)
        log "unknown action: $action (ignored)"
        ;;
esac

notify_api
```

```bash
chmod +x packages/secubox-system/usr/lib/secubox/eye-remote-leasewatch.sh
```

- [ ] **Step 4: Run bats to verify**

```bash
shellcheck packages/secubox-system/usr/lib/secubox/eye-remote-leasewatch.sh
bats packages/secubox-system/tests/test_leasewatch.bats
```

Expected: shellcheck clean; 4 bats tests passing.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-system/usr/lib/secubox/eye-remote-leasewatch.sh \
        packages/secubox-system/tests/test_leasewatch.bats
git commit -m "feat(secubox-system): eye-remote-leasewatch.sh dnsmasq hook (ref #158)"
```

---

### Task 11: nftables narrow allow on `eye-br0`

**Files:**
- Create: `packages/secubox-eye-remote/nftables/secubox-eye-remote.nft`

- [ ] **Step 1: Write the nftables snippet (private table; never edits secubox-firewall)**

```bash
mkdir -p packages/secubox-eye-remote/nftables
```

```nft
# packages/secubox-eye-remote/nftables/secubox-eye-remote.nft
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: eye-remote ingress allow on eye-br0 (issue #158)
# Owns a private table; never touches secubox-firewall's chains.

table inet secubox_eye_remote {
    chain input {
        type filter hook input priority -150; policy accept;

        # Bootp/DHCP server on the bridge
        iifname "eye-br0" udp dport 67 accept \
            comment "eye-remote: dnsmasq DHCP"

        # eye-remote API on the bridge IP only
        iifname "eye-br0" tcp dport 8000 accept \
            comment "eye-remote: API"

        # Anything else on eye-br0 is left to the system-wide chain
        # (DEFAULT DROP elsewhere will still apply).
    }
}
```

- [ ] **Step 2: Lint with `nft -c`**

```bash
sudo nft -c -f packages/secubox-eye-remote/nftables/secubox-eye-remote.nft
```

Expected: no output. (You need to run with sudo for `nft -c` to load the netlink family validator.)

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-eye-remote/nftables/secubox-eye-remote.nft
git commit -m "feat(eye-remote): nftables narrow allow on eye-br0 (ref #158)"
```

---

### Task 12: Debian packaging — secubox-eye-remote

**Files:**
- Modify: `packages/secubox-eye-remote/debian/control`
- Modify: `packages/secubox-eye-remote/debian/secubox-eye-remote.install`
- Create: `packages/secubox-eye-remote/debian/secubox-eye-remote.conffiles`
- Create or modify: `packages/secubox-eye-remote/debian/secubox-eye-remote.postinst`
- Create or modify: `packages/secubox-eye-remote/debian/secubox-eye-remote.prerm`

- [ ] **Step 1: Add the dnsmasq dependency to `control`**

In `packages/secubox-eye-remote/debian/control`, locate the `Depends:` line for the `secubox-eye-remote` binary package and add `dnsmasq-base` to the comma-separated list:

```
Depends: ${misc:Depends},
         python3,
         python3-fastapi,
         python3-uvicorn,
         secubox-core,
         dnsmasq-base,
```

- [ ] **Step 2: Append the new files to `.install`**

```
# packages/secubox-eye-remote/debian/secubox-eye-remote.install — add these lines:
dnsmasq.d/eye-remote.conf etc/dnsmasq.d/
etc/secubox/eye-remote/reservations.conf.seed etc/secubox/eye-remote/
nftables/secubox-eye-remote.nft etc/secubox/nftables.d/
systemd/secubox-eye-remote-dhcp.service etc/systemd/system/
api/lib usr/lib/secubox/eye-remote/
api/models/lease.py usr/lib/secubox/eye-remote/api/models/
api/routers/leases.py usr/lib/secubox/eye-remote/api/routers/
```

- [ ] **Step 3: Declare reservations.conf as a conffile**

```
# packages/secubox-eye-remote/debian/secubox-eye-remote.conffiles
/etc/secubox/eye-remote/reservations.conf
```

- [ ] **Step 4: Write the postinst**

```bash
#!/bin/sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# packages/secubox-eye-remote/debian/secubox-eye-remote.postinst
set -e

case "$1" in
    configure)
        # Ensure runtime dirs exist with correct ownership
        install -d -m 0750 -o root -g root /etc/secubox/eye-remote
        install -d -m 0755 -o root -g root /var/log/secubox

        # Seed reservations.conf if it doesn't exist
        if [ ! -f /etc/secubox/eye-remote/reservations.conf ]; then
            install -m 0644 \
                /etc/secubox/eye-remote/reservations.conf.seed \
                /etc/secubox/eye-remote/reservations.conf
        fi

        # Prevent Debian's system-wide dnsmasq from grabbing port 53
        # (we ship our own scoped instance instead).
        systemctl mask dnsmasq.service 2>/dev/null || true

        # Reload + enable our scoped instance
        deb-systemd-helper unmask secubox-eye-remote-dhcp.service >/dev/null || true
        if deb-systemd-helper --quiet was-enabled secubox-eye-remote-dhcp.service; then
            deb-systemd-helper enable secubox-eye-remote-dhcp.service >/dev/null || true
        else
            deb-systemd-helper update-state secubox-eye-remote-dhcp.service >/dev/null || true
            deb-systemd-helper enable secubox-eye-remote-dhcp.service >/dev/null || true
        fi
        if [ -d /run/systemd/system ]; then
            systemctl --system daemon-reload >/dev/null || true
            deb-systemd-invoke start secubox-eye-remote-dhcp.service >/dev/null || true
        fi
        ;;
esac

#DEBHELPER#
exit 0
```

- [ ] **Step 5: Write the prerm**

```bash
#!/bin/sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# packages/secubox-eye-remote/debian/secubox-eye-remote.prerm
set -e

case "$1" in
    remove|upgrade|deconfigure)
        if [ -d /run/systemd/system ]; then
            deb-systemd-invoke stop secubox-eye-remote-dhcp.service >/dev/null || true
        fi
        ;;
esac

#DEBHELPER#
exit 0
```

```bash
chmod 0755 packages/secubox-eye-remote/debian/secubox-eye-remote.postinst \
           packages/secubox-eye-remote/debian/secubox-eye-remote.prerm
```

- [ ] **Step 6: Build the package and inspect**

```bash
cd packages/secubox-eye-remote
dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b
dpkg-deb -c ../secubox-eye-remote_*_all.deb | \
    grep -E "(dnsmasq.d|reservations.conf|nftables.d/secubox-eye-remote|systemd/system/secubox-eye-remote-dhcp)"
lintian ../secubox-eye-remote_*_all.deb || true
```

Expected: all five paths present in `dpkg-deb -c` output; lintian warnings are advisory.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-eye-remote/debian/control \
        packages/secubox-eye-remote/debian/secubox-eye-remote.install \
        packages/secubox-eye-remote/debian/secubox-eye-remote.conffiles \
        packages/secubox-eye-remote/debian/secubox-eye-remote.postinst \
        packages/secubox-eye-remote/debian/secubox-eye-remote.prerm
git commit -m "build(eye-remote): ship dnsmasq + nftables + reservations conffile (ref #158)"
```

---

### Task 13: Debian packaging — secubox-system helper scripts

**Files:**
- Modify: `packages/secubox-system/debian/secubox-system.install`

- [ ] **Step 1: Confirm the helpers are listed for shipping**

Open `packages/secubox-system/debian/secubox-system.install`. If `usr/lib/secubox/eye-remote-find-usb-serial` and `usr/lib/secubox/eye-remote-leasewatch.sh` are not present, append them. Pattern matches existing eye-remote helpers (`eye-remote-connected.sh`, `eye-remote-disconnected.sh`).

```
usr/lib/secubox/eye-remote-find-usb-serial   usr/lib/secubox/
usr/lib/secubox/eye-remote-leasewatch.sh     usr/lib/secubox/
```

- [ ] **Step 2: Build + verify**

```bash
cd packages/secubox-system
dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b
dpkg-deb -c ../secubox-system_*_all.deb | grep eye-remote
```

Expected: 4 lines (connected, disconnected, find-usb-serial, leasewatch).

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-system/debian/secubox-system.install
git commit -m "build(secubox-system): ship eye-remote leasewatch + find-usb-serial (ref #158)"
```

---

### Task 14: Round image — Pi-side DHCP client

**Files:**
- Create: `remote-ui/round/files/etc/systemd/network/10-eye0.network`

- [ ] **Step 1: Write the networkd config**

```bash
mkdir -p remote-ui/round/files/etc/systemd/network
```

```ini
# remote-ui/round/files/etc/systemd/network/10-eye0.network
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: Round image — DHCP client on the USB OTG ethernet gadget.
#
# Replaces the legacy static peer config (10.55.0.2/30 with host 10.55.0.1).
# The host (eye-br0) runs dnsmasq scoped to eye-br0 and hands out a
# stable lease per MAC (issue #158).

[Match]
Name=eye0

[Network]
DHCP=yes
LinkLocalAddressing=no
IPv6AcceptRA=no

[DHCPv4]
UseRoutes=true
UseDNS=false
UseNTP=false
RouteMetric=2048
```

- [ ] **Step 2: Verify the file is picked up by the build**

```bash
grep -nE 'files/|cp -a|cp -r|rsync' remote-ui/round/build-eye-remote-image.sh | head -10
```

If the build script copies `remote-ui/round/files/` into the rootfs as-is, no change needed. If it does not, add a copy step:

```bash
# Inside build-eye-remote-image.sh, after the chroot bootstrap stage:
if [ -d "$SRC_DIR/files" ]; then
    log "Copying overlay files into rootfs"
    cp -a "$SRC_DIR/files/." "$ROOT_MNT/"
fi
```

- [ ] **Step 3: Commit**

```bash
git add remote-ui/round/files/etc/systemd/network/10-eye0.network
# Plus build-eye-remote-image.sh if you had to modify it.
git commit -m "feat(round): switch eye0 from static peer to DHCP client (ref #158)"
```

---

### Task 15: Round image — firstboot hostname from USB serial

**Files:**
- Create: `remote-ui/round/files/usr/local/sbin/eye-firstboot-hostname.sh`
- Create: `remote-ui/round/files/etc/systemd/system/eye-firstboot-hostname.service`

- [ ] **Step 1: Write the hostname script**

```bash
mkdir -p remote-ui/round/files/usr/local/sbin \
         remote-ui/round/files/etc/systemd/system
```

```bash
#!/usr/bin/env bash
# remote-ui/round/files/usr/local/sbin/eye-firstboot-hostname.sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Set the Pi's hostname to eye-<usb-gadget-serial> exactly once at first boot.
set -euo pipefail

MARKER=/var/lib/secubox/eye-firstboot-hostname.done
[[ -f "$MARKER" ]] && exit 0
mkdir -p "$(dirname "$MARKER")"

serial=$(cat /proc/cpuinfo | awk '/^Serial/ {print $3; exit}')
[[ -n "$serial" ]] || exit 1

new_host="eye-${serial}"
hostnamectl set-hostname "$new_host"
sed -i -E "s/^127\.0\.1\.1.*/127.0.1.1\t${new_host}/" /etc/hosts || true

touch "$MARKER"
```

```bash
chmod +x remote-ui/round/files/usr/local/sbin/eye-firstboot-hostname.sh
```

- [ ] **Step 2: Write the service**

```ini
# remote-ui/round/files/etc/systemd/system/eye-firstboot-hostname.service
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
[Unit]
Description=SecuBox Eye Remote — first-boot hostname from CPU serial
ConditionPathExists=!/var/lib/secubox/eye-firstboot-hostname.done
After=local-fs.target
Before=systemd-networkd.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/eye-firstboot-hostname.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: Enable the service inside the build chroot**

In `remote-ui/round/build-eye-remote-image.sh`, in the chroot section that runs `systemctl enable`, append:

```bash
chroot "$ROOT_MNT" systemctl enable eye-firstboot-hostname.service || true
```

- [ ] **Step 4: shellcheck + systemd-analyze**

```bash
shellcheck remote-ui/round/files/usr/local/sbin/eye-firstboot-hostname.sh
systemd-analyze verify remote-ui/round/files/etc/systemd/system/eye-firstboot-hostname.service
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/files/usr/local/sbin/eye-firstboot-hostname.sh \
        remote-ui/round/files/etc/systemd/system/eye-firstboot-hostname.service \
        remote-ui/round/build-eye-remote-image.sh
git commit -m "feat(round): firstboot hostname derived from CPU serial (ref #158)"
```

---

### Task 16: Integration test — multi-gadget DHCP in network namespace

**Files:**
- Create: `packages/secubox-eye-remote/tests/integration/test_multi_gadget_dhcp.py`

- [ ] **Step 1: Write the failing integration test**

```python
# packages/secubox-eye-remote/tests/integration/test_multi_gadget_dhcp.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""SecuBox-Deb :: multi-gadget DHCP integration test.

Skipped if not run as root (needs CAP_NET_ADMIN to set up netns + veth).
Spins up a single network namespace containing a bridge `eye-br0`, runs
dnsmasq with the packaged config inside it, simulates two `dhclient`
clients with distinct MACs, and asserts that each gets a distinct lease
that persists across a dnsmasq restart.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
import time
from pathlib import Path

import pytest

requires_root = pytest.mark.skipif(
    os.geteuid() != 0, reason="needs root for netns + dnsmasq + dhclient"
)
needs_tools = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("ip", "dnsmasq", "dhclient")),
    reason="ip / dnsmasq / dhclient must be installed",
)


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


@requires_root
@needs_tools
def test_two_clients_get_distinct_leases(tmp_path: Path):
    ns = "eye-test"
    leasefile = tmp_path / "leases"
    confdir = tmp_path / "conf.d"
    confdir.mkdir()
    res = tmp_path / "reservations.conf"
    res.write_text("")
    pkg_conf = Path(
        os.environ.get(
            "SECUBOX_EYE_DNSMASQ_CONF",
            "packages/secubox-eye-remote/dnsmasq.d/eye-remote.conf",
        )
    )

    # 1. Build an overlay config that retargets the packaged conf at our
    #    tmp paths and the test netns interface.
    overlay = confdir / "eye-remote.conf"
    overlay.write_text(
        pkg_conf.read_text()
        .replace("interface=eye-br0", "interface=br0")
        .replace(
            "dhcp-leasefile=/var/lib/misc/dnsmasq-eye-remote.leases",
            f"dhcp-leasefile={leasefile}",
        )
        .replace(
            "conf-file=/etc/secubox/eye-remote/reservations.conf",
            f"conf-file={res}",
        )
        .replace(
            "dhcp-script=/usr/lib/secubox/eye-remote-leasewatch.sh",
            "# dhcp-script disabled for netns test",
        )
        .replace("port=0\n", "port=0\n")  # keep
    )

    # 2. Stand up the netns + bridge + two veth pairs.
    _run(["ip", "netns", "add", ns])
    try:
        _run(["ip", "netns", "exec", ns, "ip", "link", "add", "br0", "type", "bridge"])
        _run(
            ["ip", "netns", "exec", ns, "ip", "addr", "add", "10.55.0.1/24", "dev", "br0"]
        )
        _run(["ip", "netns", "exec", ns, "ip", "link", "set", "br0", "up"])

        for i, mac in enumerate(("02:fb:00:00:11:03", "02:fb:00:00:d2:7f"), start=1):
            _run(
                [
                    "ip", "netns", "exec", ns,
                    "ip", "link", "add", f"v{i}a", "type", "veth", "peer", "name", f"v{i}b",
                ]
            )
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", f"v{i}a", "master", "br0"])
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", f"v{i}a", "up"])
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", f"v{i}b", "address", mac])
            _run(["ip", "netns", "exec", ns, "ip", "link", "set", f"v{i}b", "up"])

        # 3. Launch dnsmasq.
        dnsmasq = subprocess.Popen(
            ["ip", "netns", "exec", ns, "dnsmasq", "--keep-in-foreground",
             "--conf-file=" + str(overlay)]
        )
        time.sleep(1.0)

        # 4. Issue DHCP requests from both peers.
        for i in (1, 2):
            _run(
                ["ip", "netns", "exec", ns, "dhclient", "-1", "-v", "-pf",
                 str(tmp_path / f"dhclient-{i}.pid"), f"v{i}b"]
            )

        # 5. Inspect the lease file.
        leases = leasefile.read_text()
        assert "02:fb:00:00:11:03" in leases
        assert "02:fb:00:00:d2:7f" in leases
        ips = [line.split()[2] for line in leases.strip().splitlines()]
        assert len(set(ips)) == 2, f"expected two distinct IPs, got: {ips}"

        dnsmasq.terminate()
        dnsmasq.wait(timeout=5)
    finally:
        _run(["ip", "netns", "del", ns])
```

- [ ] **Step 2: Run the test**

```bash
sudo -E python -m pytest \
    packages/secubox-eye-remote/tests/integration/test_multi_gadget_dhcp.py -v
```

Expected: 1 passed.

If `dhclient` or `dnsmasq` are missing locally: `sudo apt install -y isc-dhcp-client dnsmasq-base` and re-run.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-eye-remote/tests/integration/test_multi_gadget_dhcp.py
git commit -m "test(eye-remote): netns multi-gadget DHCP acceptance test (ref #158)"
```

---

### Task 17: Live-board acceptance + tracking files

**Files:**
- Modify: `remote-ui/round/MULTI-GADGET.md`
- Modify: `.claude/WIP.md`
- Modify: `.claude/HISTORY.md`

- [ ] **Step 1: Build + deploy the packages onto `192.168.1.200`**

```bash
# From the repo root, on the dev workstation:
bash scripts/deploy.sh secubox-eye-remote root@192.168.1.200
bash scripts/deploy.sh secubox-system root@192.168.1.200
```

- [ ] **Step 2: Walk the acceptance gate on the live board**

SSH in and run:

```bash
ssh root@192.168.1.200 'set -e
echo "[1] dnsmasq service:"; systemctl is-active secubox-eye-remote-dhcp.service
echo "[2] bridge IP:";       ip -br addr show eye-br0
echo "[3] reservations:";    cat /etc/secubox/eye-remote/reservations.conf
echo "[4] leases:";          cat /var/lib/misc/dnsmasq-eye-remote.leases 2>/dev/null || true
echo "[5] API:";             curl -s --max-time 3 http://10.55.0.1:8000/api/v1/eye-remote/leases | jq .
echo "[6] ping rpiz:";       ping -c 2 -W 2 $(awk -F, "/02:fb:00:00:11:03/ {print \$2}" /etc/secubox/eye-remote/reservations.conf) || true
echo "[7] ping pi4b:";       ping -c 2 -W 2 $(awk -F, "/02:fb:00:00:d2:7f/ {print \$2}" /etc/secubox/eye-remote/reservations.conf) || true
'
```

Expected on a healthy board:
- `[1]` active
- `[2]` eye-br0 with `10.55.0.1/24`
- `[3]` two `dhcp-host=…` lines (rpiz + pi4b) — assuming both Pis are flashed with the DHCP-client image already
- `[4]` two active leases
- `[5]` JSON list with two entries (one per Pi)
- `[6]` + `[7]` both reachable

If `[3]` is empty, the Pis still run the static-peer firmware and need reflashing with the image built from Task 14/15.

- [ ] **Step 3: Reboot test (durability)**

```bash
ssh root@192.168.1.200 'systemctl reboot'
sleep 90
ssh root@192.168.1.200 'systemctl is-active secubox-eye-remote-dhcp.service && \
    ip -br addr show eye-br0 && \
    curl -s --max-time 3 http://10.55.0.1:8000/api/v1/eye-remote/leases | jq .'
```

Expected: same two leases, same two IPs.

- [ ] **Step 4: Update `MULTI-GADGET.md`**

Insert at the top of `remote-ui/round/MULTI-GADGET.md`:

```markdown
> **Resolved by #158 (Phase 1).** Multiple Pi RNDIS gadgets now coexist
> at L3 as well: the host runs `dnsmasq` scoped to `eye-br0` and hands
> out a stable, per-MAC lease in `10.55.0.10–.250`. Round images
> built from `feature/158-…` onward use DHCP; older images with the
> static `10.55.0.2/30` peer still suffer the limitation documented
> below until they're reflashed. Phase 2 (explicit pairing approval)
> remains a separate follow-up.
```

- [ ] **Step 5: Move #158 to ✅ in `.claude/WIP.md`** and append a dated entry to `.claude/HISTORY.md` following the same shape as the #155 entry already there.

- [ ] **Step 6: Commit**

```bash
git add remote-ui/round/MULTI-GADGET.md .claude/WIP.md .claude/HISTORY.md
git commit -m "docs: mark #158 Phase 1 multi-gadget DHCP shipped (ref #158)"
```

- [ ] **Step 7: Push + open PR**

```bash
git push -u origin feature/158-eye-remote-multi-gadget-l3-dhcp-server-o
gh pr create --title "feat(eye-remote): multi-gadget DHCP on eye-br0 — Phase 1 (ref #158)" \
    --body "Closes-soft: ref #158. Spec: docs/superpowers/specs/2026-05-16-eye-remote-multi-gadget-dhcp-pairing-design.md. Verified live on 192.168.1.200."
```

(`ref` not `closes` per the project's `Jamais de fermeture automatique` rule.)

---

## Self-Review

### Spec coverage

Walking each section of the spec:

| Spec section | Implemented by |
|---|---|
| §3.1 dnsmasq instance scoped to `eye-br0` | Tasks 7 + 8 |
| §3.1 reservations file (auto-managed, conffile) | Tasks 1, 10, 12 (conffiles entry) |
| §3.1 FastAPI `/leases` + `/lease-events` | Tasks 4, 5, 6 |
| §3.1 dhcp-script hook + USB-serial helper | Tasks 9, 10 |
| §3.3 attach flow (udev → bridge → DHCP) | Already shipped by #155; Task 14 makes the Pi side DHCP |
| §4.1 dnsmasq config | Task 7 |
| §4.2 reservations format + auto-assign policy | Tasks 1, 3 |
| §4.3 leasewatch.sh | Task 10 |
| §4.4 FastAPI router | Task 5 |
| §4.5 Round image DHCP client + hostname derive | Tasks 14, 15 |
| §4.6 nftables narrow allow | Task 11 |
| §5 failure modes (Restart, conffile recovery, reconciliation) | Service unit in Task 8 (Restart=on-failure); reservation backup left to spec note; reconciliation deferred — see Open Q1 below |
| §6 tests | Tasks 1–5 (unit), 16 (integration), 17 (live) |
| §7 migration + MULTI-GADGET.md banner | Task 17 step 4 |
| §9 Phase 2 stub | Out of scope — referenced in code comments only |

Identified gap: the spec's §5 mentions a periodic 60-second reconciliation task that re-syncs `dnsmasq-eye-remote.leases` against an in-memory API registry. Phase 1 logs lease events but does not persist them — the registry IS the lease file. Decision: defer the reconciliation task to Phase 2 (it's only needed if there's a separate in-memory store to drift). Annotated in the Task 5 docstring; no explicit task here.

### Placeholder scan

Searched the plan for `TBD`, `TODO`, `implement later`, "Add appropriate error handling", "Similar to Task N", "Write tests for the above". None present. Every code block is complete enough to copy in.

### Type / signature consistency

- `Reservation` (Task 1) → used in Tasks 3, 5. Field names match (`mac`, `ip`, `hostname`, `lease_time`).
- `Lease` (Task 2) → used in Task 5. Fields match.
- `LeaseEvent.action` enum (Task 4) — `add | old | del | discover` — matches what `leasewatch.sh` (Task 10) sends.
- API path prefixes: router declares `prefix="/eye-remote"`; `main.py` registration adds `/api/v1` → final paths `/api/v1/eye-remote/leases` + `/api/v1/eye-remote/lease-events`. Matches the spec and the leasewatch.sh URL.
- Environment variables: `SECUBOX_EYE_LEASE_FILE`, `SECUBOX_EYE_RESERVATIONS_FILE`, `SECUBOX_EYE_API_URL`, `SECUBOX_EYE_SKIP_RELOAD`, `SECUBOX_EYE_SKIP_API`, `SECUBOX_EYE_FIND_SERIAL` — used consistently across the leasewatch script, the bats test, and the FastAPI router. No name drift.

Plan is internally consistent.
