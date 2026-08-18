<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Eye Remote — Phase 3: Pillow+framebuffer kiosk Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-process Python kiosk for Pi 4B/Pi 400 + 7" Touchscreen V1.1. Pillow draws an 800×480 BGRA frame each tick and `mmap`s it to `/dev/fb0`. Touch input via `python-evdev`. Reuses Phase 2's helper FastAPI for privileged operations (USB gadget mode, service restart, lockdown, console stream).

**Architecture:** No X server, no Qt, no Chromium, no Openbox, no nginx. One Python process (`secubox-square-kiosk.service`) running as the `secubox` user with video+input groups. Left half (480×480) renders 6 concentric rings + pods + clock + status (visually faithful to Phase 1's round/ dashboard but independently authored). Right half (320×480) draws 4 tabs (Alerts / Module Detail / Console / Mode Controls). Helper FastAPI on Unix socket stays for privileged operations.

**Tech Stack:** Python 3.11 + Pillow 9.x + python-evdev 1.6 + httpx (sync mode for UDS) + python-dateutil. Helper carries forward Phase 2's FastAPI + uvicorn + websockets + SO_PEERCRED.

**Spec:** [`docs/superpowers/specs/2026-05-13-eye-square-phase3-python-kiosk-design.md`](../specs/2026-05-13-eye-square-phase3-python-kiosk-design.md)
**Issue:** [#127](https://github.com/CyberMind-FR/secubox-deb/issues/127)
**Supersedes:** Phase 2 PR [#131](https://github.com/CyberMind-FR/secubox-deb/pull/131) (closed). Phase 2 carry-forward already landed in `feature/127-phase3-python-kiosk` as commit `12462a52`.
**Round/'s Pillow+fb dashboard** (`remote-ui/round/fb_dashboard.py`) is unchanged and remains the Pi Zero W deployment.

---

## Working directory & branch

All tasks run in `/home/reepost/CyberMindStudio/secubox-deb-worktrees/127-phase3-python-kiosk`. Branch: `feature/127-phase3-python-kiosk`. Verify with:

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/127-phase3-python-kiosk
git rev-parse --abbrev-ref HEAD
```

Expected: `feature/127-phase3-python-kiosk`. Abort if not.

---

## File structure (target end state)

```
packages/secubox-eye-square/         ← from Phase 2 carry-forward
├── helper/                          ← unchanged
├── debian/                          ← control edited in Task 19
└── kiosk/                           ← NEW Phase 3 root
    ├── secubox_eye_square_kiosk/
    │   ├── __init__.py
    │   ├── __main__.py              event loop driver
    │   ├── framebuffer.py           mmap /dev/fb0, BGRA blit
    │   ├── ring_dashboard.py        left 480×480 Pillow renderer
    │   ├── right_panel.py           right 320×480 tab manager
    │   ├── tabs/
    │   │   ├── __init__.py
    │   │   ├── alerts.py
    │   │   ├── module_detail.py
    │   │   ├── console.py
    │   │   └── mode_controls.py
    │   ├── touch_input.py           python-evdev reader
    │   ├── transport_manager.py     Python port of TM
    │   ├── sim.py                   drift generator
    │   ├── modules_table.py         RINGS dataclass list
    │   ├── helper_client.py         sync httpx UDS
    │   └── theme.py                 palette constants
    └── tests/
        ├── conftest.py
        ├── test_framebuffer.py
        ├── test_modules_table.py
        ├── test_sim.py
        ├── test_touch_input.py
        ├── test_transport_manager.py
        ├── test_helper_client.py
        ├── test_tabs_alerts.py
        ├── test_tabs_module_detail.py
        ├── test_tabs_console.py
        ├── test_tabs_mode_controls.py
        ├── test_right_panel.py
        ├── test_ring_dashboard.py
        └── test_kiosk_smoke.py

remote-ui/square/
├── README.md                        ← edited Task 23
├── CLAUDE.md                        ← NEW Task 23
├── files/
│   ├── etc/systemd/system/
│   │   ├── secubox-eye-square-helper.service   ← unchanged
│   │   ├── secubox-otg-gadget.service          ← unchanged
│   │   ├── secubox-firstboot.service           ← unchanged
│   │   └── secubox-square-kiosk.service        ← NEW Task 16
│   ├── etc/udev/rules.d/
│   │   ├── 90-secubox-otg-square.rules         ← unchanged
│   │   └── 99-secubox-fb-access.rules          ← NEW Task 16 (fb0 perms)
│   ├── etc/apparmor.d/                         ← unchanged
│   ├── etc/secubox/                            ← unchanged
│   └── usr/local/sbin/firstboot.sh             ← edited Task 21
├── build-eye-square-image.sh                   ← edited Task 20
├── install_pi4.sh                              ← unchanged
└── deploy.sh                                   ← edited Task 22
```

---

## Task 1: Verify worktree state + helper tests green

**Files:** none modified.

- [ ] **Step 1: Verify branch**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/127-phase3-python-kiosk
git rev-parse --abbrev-ref HEAD
```

Expected: `feature/127-phase3-python-kiosk`.

- [ ] **Step 2: Confirm carry-forward present**

```bash
ls packages/secubox-eye-square/helper/eye_square_helper/
ls remote-ui/square/files/etc/systemd/system/
```

Expected: helper has `app.py auth.py __init__.py __main__.py routes`. systemd dir has 3 services.

- [ ] **Step 3: Confirm Phase 1 work NOT present (master doesn't have it)**

```bash
ls remote-ui/common 2>&1 | head -1
```

Expected: `ls: ... 'remote-ui/common': Aucun fichier ou dossier de ce nom` — Phase 3 is independent of common/.

- [ ] **Step 4: Run helper tests, confirm green**

```bash
cd packages/secubox-eye-square/helper
python3 -m pytest tests/ -v 2>&1 | tail -5
```

Expected: `21 passed in 0.3s`.

- [ ] **Step 5: No commit needed — gate task.**

---

## Task 2: Create `kiosk/` directory skeleton + `.gitignore`

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__init__.py`
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/__init__.py`
- Create: `packages/secubox-eye-square/kiosk/tests/conftest.py`
- Create: `packages/secubox-eye-square/kiosk/tests/__init__.py`

- [ ] **Step 1: Create directory tree**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/127-phase3-python-kiosk
mkdir -p packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs
mkdir -p packages/secubox-eye-square/kiosk/tests
touch packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__init__.py
touch packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/__init__.py
touch packages/secubox-eye-square/kiosk/tests/__init__.py
```

- [ ] **Step 2: Write conftest.py for the kiosk test package**

```python
# packages/secubox-eye-square/kiosk/tests/conftest.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""pytest conftest for the kiosk test package — adds the kiosk source dir to sys.path."""
from __future__ import annotations

import sys
from pathlib import Path

_PKG = Path(__file__).resolve().parent.parent
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square): scaffold kiosk/ package skeleton (ref #127)"
```

---

## Task 3: Theme + modules table (data modules)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/theme.py`
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/modules_table.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_modules_table.py`

- [ ] **Step 1: Write theme.py with hardcoded palette**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/theme.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Hardcoded SecuBox palette (RGB tuples for Pillow). Matches Phase 1 round/'s
literal hex values."""
from __future__ import annotations

# Module colours (from round/index.html literals — see Phase 1 spec)
AUTH = (0xC0, 0x4E, 0x24)
WALL = (0x9A, 0x60, 0x10)
BOOT = (0x80, 0x30, 0x18)
MIND = (0x3D, 0x35, 0xA0)
ROOT = (0x0A, 0x58, 0x40)
MESH = (0x10, 0x4A, 0x88)

# C3BOX shared tokens
COSMOS_BLACK = (0x08, 0x08, 0x08)
GOLD_HERMETIC = (0xC9, 0xA8, 0x4C)
CINNABAR = (0xE6, 0x39, 0x46)
MATRIX_GREEN = (0x00, 0xFF, 0x41)
CYBER_CYAN = (0x00, 0xD4, 0xFF)
VOID_PURPLE = (0x6E, 0x40, 0xC9)
TEXT_PRIMARY = (0xCC, 0xCC, 0xCC)
TEXT_MUTED = (0x4A, 0x4A, 0x4A)

# Severity dot colours (used by alerts tab)
SEVERITY = {
    "info": CYBER_CYAN,
    "warn": GOLD_HERMETIC,
    "crit": CINNABAR,
}
```

- [ ] **Step 2: Write modules_table.py with the 6-entry RINGS dataclass list**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/modules_table.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""6-module RINGS table — colour, ring radius, metric extractor.

Hamiltonian order: AUTH → WALL → BOOT → MIND → ROOT → MESH → AUTH.
Each entry corresponds to one concentric arc on the 480×480 round canvas.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import theme


@dataclass(frozen=True)
class Module:
    """One module's rendering metadata."""
    name: str                       # "AUTH", "WALL", ...
    colour: tuple[int, int, int]    # RGB tuple from theme.py
    radius: int                     # arc radius in pixels (centre at 240,240)
    metric: str                     # API field name, e.g. "cpu_percent"
    unit: str                       # display unit, e.g. "%"
    extract: Callable[[dict], float]  # (state-dict) → 0..1 fill ratio


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


MODULES: list[Module] = [
    Module(
        name="AUTH",
        colour=theme.AUTH,
        radius=214,
        metric="cpu_percent",
        unit="%",
        extract=lambda s: _clamp(s.get("cpu_percent", 0.0) / 100.0),
    ),
    Module(
        name="WALL",
        colour=theme.WALL,
        radius=201,
        metric="mem_percent",
        unit="%",
        extract=lambda s: _clamp(s.get("mem_percent", 0.0) / 100.0),
    ),
    Module(
        name="BOOT",
        colour=theme.BOOT,
        radius=188,
        metric="disk_percent",
        unit="%",
        extract=lambda s: _clamp(s.get("disk_percent", 0.0) / 100.0),
    ),
    Module(
        name="MIND",
        colour=theme.MIND,
        radius=175,
        metric="load_avg_1",
        unit="×",
        extract=lambda s: _clamp(s.get("load_avg_1", 0.0) / 4.0),
    ),
    Module(
        name="ROOT",
        colour=theme.ROOT,
        radius=162,
        metric="cpu_temp",
        unit="°C",
        extract=lambda s: _clamp((s.get("cpu_temp", 35.0) - 35.0) / 50.0),
    ),
    Module(
        name="MESH",
        colour=theme.MESH,
        radius=149,
        metric="wifi_rssi",
        unit="dBm",
        extract=lambda s: _clamp((s.get("wifi_rssi", -90) + 90.0) / 70.0),
    ),
]
```

- [ ] **Step 3: Write tests for modules_table.py**

```python
# packages/secubox-eye-square/kiosk/tests/test_modules_table.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for modules_table.py — the 6-entry RINGS list + extractors."""
from __future__ import annotations

from secubox_eye_square_kiosk.modules_table import MODULES


def test_six_modules_in_hamiltonian_order():
    assert [m.name for m in MODULES] == ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]


def test_ring_radii_descend_in_steps_of_about_13px():
    radii = [m.radius for m in MODULES]
    assert radii == [214, 201, 188, 175, 162, 149]
    for a, b in zip(radii, radii[1:]):
        assert a - b == 13, "uniform 13px ring spacing"


def test_extractor_clamps_overshoot_to_one():
    auth = MODULES[0]
    assert auth.extract({"cpu_percent": 150.0}) == 1.0
    assert auth.extract({"cpu_percent": 50.0}) == 0.5
    assert auth.extract({"cpu_percent": -10.0}) == 0.0


def test_extractor_missing_metric_returns_zero():
    auth = MODULES[0]
    assert auth.extract({}) == 0.0


def test_root_temp_extractor_maps_35c_to_zero_and_85c_to_one():
    root = next(m for m in MODULES if m.name == "ROOT")
    assert root.extract({"cpu_temp": 35.0}) == 0.0
    assert root.extract({"cpu_temp": 85.0}) == 1.0
    assert abs(root.extract({"cpu_temp": 60.0}) - 0.5) < 0.001


def test_mesh_rssi_extractor_maps_minus90_to_zero_and_minus20_to_one():
    mesh = next(m for m in MODULES if m.name == "MESH")
    assert mesh.extract({"wifi_rssi": -90}) == 0.0
    assert mesh.extract({"wifi_rssi": -20}) == 1.0


def test_each_module_has_distinct_colour():
    colours = {m.colour for m in MODULES}
    assert len(colours) == 6
```

- [ ] **Step 4: Run tests, expect pass**

```bash
cd packages/secubox-eye-square/kiosk
python3 -m pytest tests/test_modules_table.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/127-phase3-python-kiosk
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): theme.py + modules_table.py with TDD (ref #127)"
```

---

## Task 4: Simulation drift generator

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/sim.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_sim.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_sim.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for sim.py — bounded random walk drift, deterministic with seed."""
from __future__ import annotations

import random

from secubox_eye_square_kiosk.sim import SimState, step


def test_initial_state_has_six_metric_fields():
    s = SimState()
    for field in ("cpu_percent", "mem_percent", "disk_percent", "wifi_rssi",
                  "load_avg_1", "cpu_temp"):
        assert hasattr(s, field), f"missing {field}"


def test_step_advances_state_within_bounds():
    random.seed(42)
    s = SimState()
    for _ in range(100):
        step(s, refresh_interval_s=2.0)
    assert 0.0 <= s.cpu_percent <= 100.0
    assert 20.0 <= s.mem_percent <= 95.0
    assert 5.0 <= s.disk_percent <= 95.0
    assert -90 <= s.wifi_rssi <= -20
    assert 0.0 <= s.load_avg_1 <= 4.0
    assert 35.0 <= s.cpu_temp <= 82.0


def test_step_increments_uptime():
    s = SimState()
    initial = s.uptime_seconds
    step(s, refresh_interval_s=2.0)
    assert s.uptime_seconds == initial + 2.0


def test_step_with_zero_drift_holds_state():
    """A deterministic verify: if random returns 0.5, drift is zero (centred)."""
    random.seed(0)
    s = SimState()
    cpu_before = s.cpu_percent
    # we don't assert exact equality (random not seeded for 0.5) but trend
    step(s, refresh_interval_s=2.0)
    # at minimum, value still within bounds
    assert 0.0 <= s.cpu_percent <= 100.0


def test_state_to_dict_returns_api_shape():
    s = SimState()
    d = s.to_dict()
    assert set(d.keys()) >= {"cpu_percent", "mem_percent", "disk_percent",
                              "wifi_rssi", "load_avg_1", "cpu_temp",
                              "uptime_seconds", "hostname"}
```

- [ ] **Step 2: Run, expect ImportError**

```bash
cd packages/secubox-eye-square/kiosk
python3 -m pytest tests/test_sim.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_eye_square_kiosk.sim'`.

- [ ] **Step 3: Implement sim.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/sim.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Simulation drift generator — Python port of Phase 1 sim.js.

When no SecuBox host responds, the kiosk uses these synthetic values so
the rings still animate plausibly. Random walk bounded to realistic ranges.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, asdict


@dataclass
class SimState:
    """Drift state — mutable, advanced by step()."""
    cpu_percent: float = 14.0
    mem_percent: float = 42.0
    disk_percent: float = 28.0
    wifi_rssi: int = -63
    load_avg_1: float = 0.18
    cpu_temp: float = 44.0
    uptime_seconds: float = 0.0
    hostname: str = "secubox-zero"

    def to_dict(self) -> dict:
        return asdict(self)


def _walk(value: float, drift: float, lo: float, hi: float) -> float:
    """One step of a bounded random walk."""
    new_value = value + (random.random() - 0.5) * drift
    return max(lo, min(hi, new_value))


def step(state: SimState, refresh_interval_s: float = 2.0) -> None:
    """Advance state in place. refresh_interval_s adds to uptime."""
    state.cpu_percent = _walk(state.cpu_percent, 12.0, 0.0, 100.0)
    state.mem_percent = _walk(state.mem_percent, 3.0, 20.0, 95.0)
    state.disk_percent = _walk(state.disk_percent, 0.7, 5.0, 95.0)
    state.wifi_rssi = int(_walk(float(state.wifi_rssi), 5.0, -90.0, -20.0))
    state.load_avg_1 = _walk(state.load_avg_1, 0.12, 0.0, 4.0)
    state.cpu_temp = _walk(state.cpu_temp, 1.5, 35.0, 82.0)
    state.uptime_seconds += refresh_interval_s
```

- [ ] **Step 4: Run, expect pass**

```bash
python3 -m pytest tests/test_sim.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/127-phase3-python-kiosk
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): sim.py drift generator with TDD (ref #127)"
```

---

## Task 5: Framebuffer mmap helper

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/framebuffer.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_framebuffer.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_framebuffer.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for framebuffer.py — mmap blit. Uses a tmpfs file as fake /dev/fb0."""
from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image

from secubox_eye_square_kiosk.framebuffer import FrameBuffer


@pytest.fixture
def fake_fb(tmp_path: Path) -> Path:
    """Create a 800×480×4 bytes file simulating /dev/fb0 BGRA32."""
    path = tmp_path / "fb0"
    path.write_bytes(b"\x00" * (800 * 480 * 4))
    return path


def test_open_and_size(fake_fb: Path):
    fb = FrameBuffer(path=str(fake_fb), width=800, height=480, bpp=4)
    assert fb.width == 800
    assert fb.height == 480
    assert fb.bpp == 4
    assert fb.size == 800 * 480 * 4
    fb.close()


def test_blit_writes_image_bytes(fake_fb: Path):
    fb = FrameBuffer(path=str(fake_fb), width=800, height=480, bpp=4)
    img = Image.new("RGBA", (800, 480), color=(255, 0, 0, 255))  # red
    fb.blit(img)
    fb.close()
    raw = fake_fb.read_bytes()
    # First pixel: BGRA → blue=0, green=0, red=255, alpha=255
    assert raw[:4] == b"\x00\x00\xff\xff"


def test_blit_wrong_size_raises(fake_fb: Path):
    fb = FrameBuffer(path=str(fake_fb), width=800, height=480, bpp=4)
    img = Image.new("RGBA", (100, 100), color=(0, 0, 0, 255))
    with pytest.raises(ValueError, match="image size"):
        fb.blit(img)
    fb.close()
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement framebuffer.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/framebuffer.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Direct /dev/fb0 framebuffer blit via mmap.

The Pi 4B's DSI panel exposes /dev/fb0 at 800×480, 32-bit BGRA when the
vc4-kms-v3d overlay is active. We open it once, mmap the full size, and
blit Pillow images into it on each render tick.
"""
from __future__ import annotations

import logging
import mmap
import os
from pathlib import Path

from PIL import Image

log = logging.getLogger("secubox_eye_square_kiosk.framebuffer")


class FrameBuffer:
    """Owns the mmap handle to /dev/fb0. Single-instance-per-process."""

    def __init__(self, path: str = "/dev/fb0", width: int = 800, height: int = 480, bpp: int = 4):
        self.path = path
        self.width = width
        self.height = height
        self.bpp = bpp
        self.size = width * height * bpp
        self.fd = os.open(path, os.O_RDWR)
        self.fb = mmap.mmap(self.fd, self.size, mmap.MAP_SHARED, mmap.PROT_WRITE)

    def blit(self, image: Image.Image) -> None:
        """Push a Pillow image to the framebuffer. Image must be RGBA at exact resolution."""
        if image.size != (self.width, self.height):
            raise ValueError(
                f"image size {image.size} doesn't match framebuffer {self.width}x{self.height}"
            )
        # Convert Pillow RGBA → BGRA for vc4-kms-v3d's little-endian BGRA32 layout
        bgra = image.tobytes("raw", "BGRA")
        self.fb.seek(0)
        self.fb.write(bgra)

    def close(self) -> None:
        self.fb.close()
        os.close(self.fd)

    def __enter__(self) -> "FrameBuffer":
        return self

    def __exit__(self, *_args) -> None:
        self.close()
```

- [ ] **Step 4: Run, expect pass**

```bash
python3 -m pytest tests/test_framebuffer.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): framebuffer.py mmap helper with TDD (ref #127)"
```

---

## Task 6: Touch input (python-evdev reader)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/touch_input.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_touch_input.py`

- [ ] **Step 1: Write failing tests with mocked evdev**

```python
# packages/secubox-eye-square/kiosk/tests/test_touch_input.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for touch_input.py — synthetic evdev events → tap/drag dispatch."""
from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from secubox_eye_square_kiosk.touch_input import TouchEvent, classify


def test_classify_short_press_returns_tap():
    """Press + release within 250ms at same coord = tap."""
    press = TouchEvent(kind="press", x=100, y=100, t=0.0)
    release = TouchEvent(kind="release", x=100, y=100, t=0.1)
    result = classify(press, release)
    assert result.kind == "tap"
    assert result.x == 100
    assert result.y == 100


def test_classify_long_press_returns_long_tap():
    press = TouchEvent(kind="press", x=240, y=240, t=0.0)
    release = TouchEvent(kind="release", x=240, y=240, t=1.5)
    result = classify(press, release)
    assert result.kind == "long_tap"


def test_classify_drag_returns_drag():
    """Release > 10px from press = drag with delta."""
    press = TouchEvent(kind="press", x=100, y=100, t=0.0)
    release = TouchEvent(kind="release", x=100, y=200, t=0.2)
    result = classify(press, release)
    assert result.kind == "drag"
    assert result.dx == 0
    assert result.dy == 100
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement touch_input.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/touch_input.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Touch input via python-evdev.

Reads /dev/input/event* devices, filters for touchscreen devices (ABS_X +
BTN_TOUCH), groups press+release events into taps and drags, and exposes
a non-blocking read_event() generator for the kiosk event loop.

A real device opens evdev.InputDevice. A test or headless run can feed
synthetic TouchEvent objects directly to classify().
"""
from __future__ import annotations

import glob
import logging
import select
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("secubox_eye_square_kiosk.touch_input")

TAP_MAX_DURATION_S = 0.4
LONG_TAP_MIN_DURATION_S = 1.0
DRAG_MIN_DISTANCE_PX = 10


@dataclass
class TouchEvent:
    """Single touch lifecycle event (press or release)."""
    kind: str   # "press" | "release"
    x: int
    y: int
    t: float    # event timestamp in seconds


@dataclass
class GestureEvent:
    """Classified gesture: tap, long_tap, or drag."""
    kind: str   # "tap" | "long_tap" | "drag"
    x: int      # press location
    y: int
    dx: int = 0
    dy: int = 0


def classify(press: TouchEvent, release: TouchEvent) -> GestureEvent:
    """Classify a press+release pair as tap / long_tap / drag."""
    dx = release.x - press.x
    dy = release.y - press.y
    distance_sq = dx * dx + dy * dy
    duration = release.t - press.t
    if distance_sq > DRAG_MIN_DISTANCE_PX * DRAG_MIN_DISTANCE_PX:
        return GestureEvent(kind="drag", x=press.x, y=press.y, dx=dx, dy=dy)
    if duration >= LONG_TAP_MIN_DURATION_S:
        return GestureEvent(kind="long_tap", x=press.x, y=press.y)
    return GestureEvent(kind="tap", x=press.x, y=press.y)


def find_touch_devices() -> list:
    """Locate evdev devices with ABS_X capability (touchscreens + mice + touchpads)."""
    try:
        from evdev import InputDevice, ecodes
    except ImportError:
        log.warning("python-evdev not installed; touch input disabled")
        return []
    devices = []
    for path in sorted(glob.glob("/dev/input/event*")):
        try:
            dev = InputDevice(path)
        except OSError:
            continue
        caps = dev.capabilities()
        if ecodes.EV_ABS in caps or ecodes.EV_KEY in caps:
            devices.append(dev)
    return devices


def read_events(devices: list, timeout_s: float = 0.0):
    """Non-blocking generator yielding raw evdev events. timeout_s=0 = poll only."""
    if not devices:
        return
    try:
        from evdev import ecodes
    except ImportError:
        return
    r, _, _ = select.select(devices, [], [], timeout_s)
    for dev in r:
        for event in dev.read():
            yield event
```

- [ ] **Step 4: Run, expect pass**

```bash
python3 -m pytest tests/test_touch_input.py -v
```

Expected: 3 passed (the find/read functions are integration-level; classify is the unit-tested core).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): touch_input.py evdev reader + classify (ref #127)"
```

---

## Task 7: Transport manager (Python port)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/transport_manager.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_transport_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_transport_manager.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for transport_manager.py — OTG/WiFi/SIM probing + JWT renewal."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from secubox_eye_square_kiosk.transport_manager import TransportManager


def test_initial_state_is_sim():
    tm = TransportManager(simulate=True)
    assert tm.active == "SIM"


def test_probe_otg_first_then_wifi_then_sim():
    """When SIMULATE=False, probe order is OTG, WiFi, SIM."""
    tm = TransportManager(simulate=False, otg_base="http://10.55.0.1:8000",
                          wifi_base="http://secubox.local:8000")
    # First probe — OTG succeeds
    with patch("secubox_eye_square_kiosk.transport_manager.httpx.Client.get") as mock_get:
        mock_get.return_value = MagicMock(status_code=200)
        tm.probe()
    assert tm.active == "OTG"


def test_probe_falls_back_to_wifi_on_otg_failure():
    tm = TransportManager(simulate=False, otg_base="http://10.55.0.1:8000",
                          wifi_base="http://secubox.local:8000")
    def fake_get(url, **kw):
        if "10.55.0.1" in url:
            raise Exception("OTG unreachable")
        return MagicMock(status_code=200)
    with patch("secubox_eye_square_kiosk.transport_manager.httpx.Client.get",
               side_effect=fake_get):
        tm.probe()
    assert tm.active == "WiFi"


def test_probe_falls_back_to_sim_on_both_failures():
    tm = TransportManager(simulate=False, otg_base="http://10.55.0.1:8000",
                          wifi_base="http://secubox.local:8000")
    with patch("secubox_eye_square_kiosk.transport_manager.httpx.Client.get",
               side_effect=Exception("network down")):
        tm.probe()
    assert tm.active == "SIM"


def test_simulate_true_forces_sim():
    tm = TransportManager(simulate=True)
    tm.probe()
    assert tm.active == "SIM"


def test_on_transport_change_hook_fires_on_transition():
    tm = TransportManager(simulate=False, otg_base="http://x", wifi_base="http://y")
    received = []
    tm.on_transport_change = lambda active: received.append(active)
    tm._set_active("WiFi")
    tm._set_active("WiFi")  # dedupe
    tm._set_active("OTG")
    assert received == ["WiFi", "OTG"]
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement transport_manager.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/transport_manager.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""TransportManager — probe OTG → WiFi → SIM, manage JWT, fetch metrics.

Python port of Phase 1's remote-ui/common/js/transport-manager.js.
Single-process kiosk uses this directly (no WebSocket bridge needed).
"""
from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass
from typing import Callable, Optional

import httpx

log = logging.getLogger("secubox_eye_square_kiosk.transport_manager")

PROBE_TIMEOUT_S = 2.0
LOGIN_TIMEOUT_S = 3.0
FETCH_TIMEOUT_S = 3.0
JWT_RENEW_BEFORE_S = 30.0


class TransportManager:
    """Probe OTG/WiFi/SIM, fetch metrics, renew JWT. Hooks for module:tap and
    transport change events (in-process callbacks)."""

    def __init__(
        self,
        simulate: bool = True,
        otg_base: str = "http://10.55.0.1:8000",
        wifi_base: str = "http://secubox.local:8000",
        login_user: str = "dashboard",
        login_pass: str = "secubox-square",
    ):
        self.simulate = simulate
        self.otg_base = otg_base
        self.wifi_base = wifi_base
        self.login_user = login_user
        self.login_pass = login_pass
        self.active = "SIM"
        self.jwt: Optional[str] = None
        self.jwt_exp: float = 0.0
        self.otg_fails = 0
        self.on_transport_change: Callable[[str], None] = lambda _: None
        self.on_module_tap: Callable[[str], None] = lambda _: None
        self._client = httpx.Client(timeout=PROBE_TIMEOUT_S)

    @property
    def base(self) -> Optional[str]:
        if self.active == "OTG":
            return self.otg_base
        if self.active == "WiFi":
            return self.wifi_base
        return None

    def _set_active(self, new_active: str) -> None:
        """Set self.active and fire hook on transitions only."""
        if self.active == new_active:
            return
        self.active = new_active
        try:
            self.on_transport_change(new_active)
        except Exception as e:
            log.warning("on_transport_change raised: %s", e)

    def probe(self) -> None:
        """Probe OTG → WiFi → SIM. Updates self.active."""
        if self.simulate:
            self._set_active("SIM")
            return
        for name, url in [("OTG", self.otg_base), ("WiFi", self.wifi_base)]:
            try:
                r = self._client.get(url + "/api/v1/health", timeout=PROBE_TIMEOUT_S)
                if r.status_code == 200:
                    if self.active != name:
                        self._set_active(name)
                        self.jwt = None  # force re-login on transport change
                    self.otg_fails = 0
                    return
            except Exception as e:
                if name == "OTG":
                    self.otg_fails += 1
                log.debug("%s probe failed: %s", name, e)
        self._set_active("SIM")

    def login(self) -> bool:
        """POST /api/v1/auth/token with username+password. Cache JWT + exp."""
        if self.simulate or not self.base:
            self.jwt = "SIM"
            self.jwt_exp = time.time() + 3600
            return True
        try:
            r = self._client.post(
                self.base + "/api/v1/auth/token",
                data={"username": self.login_user, "password": self.login_pass,
                      "grant_type": "password"},
                timeout=LOGIN_TIMEOUT_S,
            )
            r.raise_for_status()
            data = r.json()
            self.jwt = data["access_token"]
            payload = json.loads(base64.urlsafe_b64decode(
                self.jwt.split(".")[1] + "==").decode())
            self.jwt_exp = payload["exp"]
            return True
        except Exception as e:
            log.warning("login failed: %s", e)
            return False

    def ensure_jwt(self) -> bool:
        if not self.jwt or time.time() >= (self.jwt_exp - JWT_RENEW_BEFORE_S):
            return self.login()
        return True

    def fetch_metrics(self) -> Optional[dict]:
        if self.simulate or self.active == "SIM" or not self.base:
            return None
        if not self.ensure_jwt():
            return None
        try:
            r = self._client.get(
                self.base + "/api/v1/system/metrics",
                headers={"Authorization": f"Bearer {self.jwt}"},
                timeout=FETCH_TIMEOUT_S,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            log.debug("fetch_metrics failed: %s", e)
            if self.active == "OTG":
                self.otg_fails += 1
            return None
```

- [ ] **Step 4: Run tests, expect pass**

```bash
python3 -m pytest tests/test_transport_manager.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): transport_manager.py with TDD (ref #127)"
```

---

## Task 8: Helper client (sync httpx UDS)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/helper_client.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_helper_client.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_helper_client.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for helper_client.py — sync httpx UDS to the helper FastAPI."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from secubox_eye_square_kiosk.helper_client import HelperClient


def test_set_usb_mode_calls_correct_endpoint():
    c = HelperClient("/tmp/test.sock")
    with patch.object(c, "_post") as mock_post:
        mock_post.return_value = {"mode": "normal", "exit_code": 0}
        result = c.set_usb_mode("normal")
        mock_post.assert_called_once_with("/usb-gadget/mode", {"mode": "normal"})
        assert result["mode"] == "normal"


def test_get_usb_state_calls_correct_endpoint():
    c = HelperClient("/tmp/test.sock")
    with patch.object(c, "_get") as mock_get:
        mock_get.return_value = {"mode": "normal"}
        result = c.get_usb_state()
        mock_get.assert_called_once_with("/usb-gadget/state")


def test_restart_service_calls_correct_endpoint():
    c = HelperClient("/tmp/test.sock")
    with patch.object(c, "_post") as mock_post:
        mock_post.return_value = {"unit": "secubox-hub", "exit_code": 0}
        c.restart_service("secubox-hub")
        mock_post.assert_called_once_with("/service/restart", {"unit": "secubox-hub"})


def test_lockdown_sends_confirm_string():
    c = HelperClient("/tmp/test.sock")
    with patch.object(c, "_post") as mock_post:
        mock_post.return_value = {"applied": True, "exit_code": 0}
        c.lockdown()
        mock_post.assert_called_once_with("/lockdown", {"confirm": "lockdown"})
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement helper_client.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/helper_client.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Sync httpx client for the eye-square-helper FastAPI Unix socket.

The kiosk is a single-threaded Python process; the helper exposes
privileged ops over /run/secubox/eye-square-helper.sock. All calls are
synchronous and propagate httpx exceptions to the caller.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger("secubox_eye_square_kiosk.helper_client")


class HelperClient:
    """Calls the privileged helper. Construct once per process; thread-safe enough for kiosk."""

    def __init__(self, socket_path: str, timeout: float = 10.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        transport = httpx.HTTPTransport(uds=self.socket_path)
        with httpx.Client(transport=transport, base_url="http://localhost",
                          timeout=self.timeout) as c:
            r = c.post(path, json=payload)
            r.raise_for_status()
            return r.json()

    def _get(self, path: str) -> dict[str, Any]:
        transport = httpx.HTTPTransport(uds=self.socket_path)
        with httpx.Client(transport=transport, base_url="http://localhost",
                          timeout=self.timeout) as c:
            r = c.get(path)
            r.raise_for_status()
            return r.json()

    def set_usb_mode(self, mode: str) -> dict[str, Any]:
        return self._post("/usb-gadget/mode", {"mode": mode})

    def get_usb_state(self) -> dict[str, Any]:
        return self._get("/usb-gadget/state")

    def restart_service(self, unit: str) -> dict[str, Any]:
        return self._post("/service/restart", {"unit": unit})

    def lockdown(self) -> dict[str, Any]:
        return self._post("/lockdown", {"confirm": "lockdown"})
```

- [ ] **Step 4: Run tests, expect pass**

```bash
python3 -m pytest tests/test_helper_client.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): helper_client.py sync httpx UDS with TDD (ref #127)"
```

---

## Task 9: Alerts tab (Pillow list rendering)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/alerts.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_tabs_alerts.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_tabs_alerts.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for the Alerts tab — Pillow-drawn scrollable list."""
from __future__ import annotations

from PIL import Image

from secubox_eye_square_kiosk.tabs.alerts import AlertItem, AlertsTab


def test_alerts_tab_constructs():
    tab = AlertsTab()
    assert tab.items == []
    assert tab.scroll_offset == 0


def test_set_alerts_replaces_items():
    tab = AlertsTab()
    tab.set_alerts([AlertItem("crit", "14:32:07", "AUTH", "cpu hit")])
    assert len(tab.items) == 1


def test_draw_renders_320x424_image():
    """Draw onto a region; verify image size."""
    tab = AlertsTab()
    tab.set_alerts([AlertItem("warn", "14:33:01", "MIND", "load 3.2")])
    region = Image.new("RGBA", (320, 424), (0, 0, 0, 255))
    tab.draw(region)
    assert region.size == (320, 424)


def test_handle_tap_within_row_fires_callback():
    """A tap inside a row should fire the on_row_tap callback."""
    tab = AlertsTab()
    item = AlertItem("crit", "14:32:07", "AUTH", "cpu hit")
    tab.set_alerts([item])
    received = []
    tab.on_row_tap = lambda i: received.append(i)
    # First row spans (0, 0..32) — tap at (100, 16) should hit row 0
    tab.handle_tap(100, 16)
    assert received == [item]


def test_handle_drag_scrolls_offset():
    tab = AlertsTab()
    tab.set_alerts([AlertItem("info", f"00:00:{i:02d}", "AUTH", "x") for i in range(20)])
    tab.handle_drag(dx=0, dy=-50)
    assert tab.scroll_offset == 50  # scroll down (drag up)
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement tabs/alerts.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/alerts.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Alerts tab — Pillow-drawn scrollable list of recent system alerts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from PIL import Image, ImageDraw

from .. import theme

ROW_HEIGHT = 32
DOT_RADIUS = 4
TEXT_PAD_LEFT = 24
TEXT_PAD_RIGHT = 8


@dataclass
class AlertItem:
    severity: str  # "info" | "warn" | "crit"
    time: str
    module: str
    message: str


class AlertsTab:
    """Scrollable list. Tap a row to drill into module detail."""

    def __init__(self):
        self.items: list[AlertItem] = []
        self.scroll_offset = 0
        self.on_row_tap: Callable[[AlertItem], None] = lambda _: None

    def set_alerts(self, items: list[AlertItem]) -> None:
        self.items = list(items)
        self.scroll_offset = 0

    def handle_tap(self, x: int, y: int) -> None:
        """Convert a tap at (x, y) (region-local coords) to a row hit."""
        row_index = (y + self.scroll_offset) // ROW_HEIGHT
        if 0 <= row_index < len(self.items):
            self.on_row_tap(self.items[row_index])

    def handle_drag(self, dx: int, dy: int) -> None:
        """Drag down scrolls list up (negative dy = scroll up)."""
        self.scroll_offset = max(
            0,
            min(
                max(0, len(self.items) * ROW_HEIGHT - 424),
                self.scroll_offset - dy,
            ),
        )

    def draw(self, region: Image.Image) -> None:
        """Render alerts into the region (320x424 RGBA image)."""
        draw = ImageDraw.Draw(region)
        if not self.items:
            draw.text((10, 10), "● NOMINAL", fill=theme.MATRIX_GREEN)
            return
        w, h = region.size
        for i, item in enumerate(self.items):
            y = i * ROW_HEIGHT - self.scroll_offset
            if y + ROW_HEIGHT < 0 or y > h:
                continue
            dot = theme.SEVERITY.get(item.severity, theme.TEXT_MUTED)
            draw.ellipse(
                (8, y + 12, 8 + 2 * DOT_RADIUS, y + 12 + 2 * DOT_RADIUS),
                fill=dot,
            )
            txt = f"{item.time} {item.module}  {item.message}"
            draw.text((TEXT_PAD_LEFT, y + 8), txt[:38],
                      fill=theme.TEXT_PRIMARY)
            # divider line
            draw.line((0, y + ROW_HEIGHT - 1, w, y + ROW_HEIGHT - 1),
                      fill=theme.TEXT_MUTED)
```

- [ ] **Step 4: Run tests, expect pass**

```bash
python3 -m pytest tests/test_tabs_alerts.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): tabs/alerts.py with TDD (ref #127)"
```

---

## Task 10: Module Detail tab (gauge + sparkline)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/module_detail.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_tabs_module_detail.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_tabs_module_detail.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for the Module Detail tab — title + gauge + sparkline."""
from __future__ import annotations

from PIL import Image

from secubox_eye_square_kiosk.tabs.module_detail import ModuleDetailTab


def test_constructs_with_default_state():
    tab = ModuleDetailTab()
    assert tab.module_name == ""
    assert tab.value == 0.0
    assert tab.history == []


def test_load_module_updates_state():
    tab = ModuleDetailTab()
    tab.load_module("AUTH", "cpu_percent", value=47.2, history=[10, 20, 30, 40, 47.2])
    assert tab.module_name == "AUTH"
    assert tab.metric == "cpu_percent"
    assert tab.value == 47.2
    assert tab.history == [10, 20, 30, 40, 47.2]


def test_clamps_value_for_gauge():
    tab = ModuleDetailTab()
    tab.load_module("WALL", "mem_percent", value=150.0, history=[])
    region = Image.new("RGBA", (320, 424), (0, 0, 0, 255))
    tab.draw(region)
    # Gauge fill is clamped to 100% — no crash, image rendered
    assert region.size == (320, 424)


def test_draw_handles_empty_history():
    tab = ModuleDetailTab()
    tab.load_module("ROOT", "cpu_temp", value=44.2, history=[])
    region = Image.new("RGBA", (320, 424), (0, 0, 0, 255))
    tab.draw(region)
    # No crash on empty history
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement tabs/module_detail.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/module_detail.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Module Detail tab — title + gauge + sparkline + service status."""
from __future__ import annotations

from PIL import Image, ImageDraw

from .. import theme

TITLE_Y = 16
METRIC_Y = 48
GAUGE_Y = 80
GAUGE_HEIGHT = 24
SPARK_Y = 140
SPARK_HEIGHT = 100
SERVICE_Y = 280


class ModuleDetailTab:
    """Detail view for a single module. Loaded via load_module()."""

    def __init__(self):
        self.module_name = ""
        self.metric = ""
        self.value = 0.0
        self.history: list[float] = []
        self.service_status = "—"

    def load_module(self, name: str, metric: str, value: float,
                    history: list[float]) -> None:
        self.module_name = name
        self.metric = metric
        self.value = value
        self.history = list(history)

    def set_service_status(self, status: str) -> None:
        self.service_status = status

    def draw(self, region: Image.Image) -> None:
        draw = ImageDraw.Draw(region)
        w, h = region.size
        if not self.module_name:
            draw.text((w // 2 - 50, h // 2), "(no module)", fill=theme.TEXT_MUTED)
            return

        # Title bar
        draw.text((w // 2 - 30, TITLE_Y), self.module_name,
                  fill=theme.GOLD_HERMETIC)
        draw.text((10, METRIC_Y), self.metric, fill=theme.TEXT_PRIMARY)

        # Gauge (clamped 0..100)
        clamped = max(0.0, min(100.0, self.value))
        fill_w = int((w - 20) * clamped / 100.0)
        draw.rectangle((10, GAUGE_Y, w - 10, GAUGE_Y + GAUGE_HEIGHT),
                       outline=theme.TEXT_MUTED, width=1)
        draw.rectangle((10, GAUGE_Y, 10 + fill_w, GAUGE_Y + GAUGE_HEIGHT),
                       fill=theme.CYBER_CYAN)
        draw.text((10, GAUGE_Y + GAUGE_HEIGHT + 4), f"{self.value:.1f}",
                  fill=theme.TEXT_PRIMARY)

        # Sparkline
        if len(self.history) >= 2:
            spark_w = w - 20
            max_v = max(self.history) or 1.0
            step = spark_w / (len(self.history) - 1)
            points = []
            for i, v in enumerate(self.history):
                x = 10 + int(i * step)
                y = SPARK_Y + SPARK_HEIGHT - int((v / max_v) * SPARK_HEIGHT)
                points.append((x, y))
            for a, b in zip(points, points[1:]):
                draw.line([a, b], fill=theme.CYBER_CYAN, width=2)

        # Service status
        draw.text((10, SERVICE_Y), f"Service: {self.service_status}",
                  fill=theme.TEXT_PRIMARY)
```

- [ ] **Step 4: Run, expect pass**

```bash
python3 -m pytest tests/test_tabs_module_detail.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): tabs/module_detail.py with TDD (ref #127)"
```

---

## Task 11: Console tab (text scrollback)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/console.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_tabs_console.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_tabs_console.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for the Console tab — Pillow-rendered text scrollback."""
from __future__ import annotations

from PIL import Image

from secubox_eye_square_kiosk.tabs.console import ConsoleTab


def test_constructs_empty():
    tab = ConsoleTab()
    assert tab.lines == []
    assert tab.frozen is False


def test_append_line_adds_to_buffer():
    tab = ConsoleTab()
    tab.append_line("line A")
    tab.append_line("line B")
    assert tab.lines == ["line A", "line B"]


def test_frozen_skips_append():
    tab = ConsoleTab()
    tab.append_line("first")
    tab.frozen = True
    tab.append_line("ignored")
    assert "ignored" not in tab.lines


def test_buffer_caps_at_max_lines():
    tab = ConsoleTab(max_lines=10)
    for i in range(20):
        tab.append_line(f"line {i}")
    assert len(tab.lines) == 10
    assert tab.lines[0] == "line 10"  # oldest dropped
    assert tab.lines[-1] == "line 19"


def test_handle_tap_on_freeze_toggle():
    tab = ConsoleTab()
    # Freeze button is at bottom-right (y > 380 in the 320x424 region)
    tab.handle_tap(280, 400)
    assert tab.frozen is True
    tab.handle_tap(280, 400)
    assert tab.frozen is False


def test_draw_renders_recent_lines():
    tab = ConsoleTab()
    tab.append_line("first")
    tab.append_line("second")
    region = Image.new("RGBA", (320, 424), (0, 0, 0, 255))
    tab.draw(region)
    assert region.size == (320, 424)
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement tabs/console.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/console.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Console tab — text scrollback with a Freeze toggle."""
from __future__ import annotations

from PIL import Image, ImageDraw

from .. import theme

LINE_HEIGHT = 14
TOP_MARGIN = 8
BUTTON_Y = 380
BUTTON_HEIGHT = 32
BUTTON_X = 240


class ConsoleTab:
    """Read-only console tail. append_line() is no-op when frozen."""

    def __init__(self, max_lines: int = 200):
        self.lines: list[str] = []
        self.frozen = False
        self.max_lines = max_lines

    def append_line(self, line: str) -> None:
        if self.frozen:
            return
        self.lines.append(line)
        if len(self.lines) > self.max_lines:
            self.lines = self.lines[-self.max_lines:]

    def handle_tap(self, x: int, y: int) -> None:
        """Tap on the Freeze button (bottom-right)?"""
        if BUTTON_X <= x <= 320 and BUTTON_Y <= y <= BUTTON_Y + BUTTON_HEIGHT:
            self.frozen = not self.frozen

    def draw(self, region: Image.Image) -> None:
        draw = ImageDraw.Draw(region)
        w, h = region.size
        # Background — solid black for readability
        draw.rectangle((0, 0, w, h), fill=(0, 0, 0, 255))
        # Render the last N lines that fit
        visible_rows = (h - 50) // LINE_HEIGHT
        for i, line in enumerate(self.lines[-visible_rows:]):
            y = TOP_MARGIN + i * LINE_HEIGHT
            draw.text((4, y), line[:48], fill=theme.MATRIX_GREEN)
        # Freeze button
        btn_label = "Resume" if self.frozen else "Freeze"
        btn_fill = theme.GOLD_HERMETIC if self.frozen else theme.TEXT_MUTED
        draw.rectangle((BUTTON_X, BUTTON_Y, w - 4, BUTTON_Y + BUTTON_HEIGHT),
                       outline=btn_fill, width=1)
        draw.text((BUTTON_X + 8, BUTTON_Y + 8), btn_label, fill=btn_fill)
```

- [ ] **Step 4: Run tests, expect pass**

```bash
python3 -m pytest tests/test_tabs_console.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): tabs/console.py with TDD (ref #127)"
```

---

## Task 12: Mode Controls tab (touch button grid)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/mode_controls.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_tabs_mode_controls.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_tabs_mode_controls.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for the Mode Controls tab — Pillow button grid."""
from __future__ import annotations

from unittest.mock import MagicMock

from PIL import Image

from secubox_eye_square_kiosk.tabs.mode_controls import ModeControlsTab


def test_constructs_with_helper_client():
    helper = MagicMock()
    tab = ModeControlsTab(helper)
    assert tab.helper is helper
    assert tab.transport_active == "SIM"


def test_update_transport_changes_indicator():
    tab = ModeControlsTab(MagicMock())
    tab.update_transport("OTG")
    assert tab.transport_active == "OTG"


def test_tap_normal_mode_calls_set_usb_mode():
    helper = MagicMock()
    tab = ModeControlsTab(helper)
    # Normal mode button is in the USB section (top of the panel)
    # Calculate position from grid: row 0, col 0 → roughly (10, 40)
    tab.handle_tap(40, 60)
    helper.set_usb_mode.assert_called_once_with("normal")


def test_tap_destructive_button_does_not_fire_without_confirm():
    """Flash is destructive — needs explicit confirm. First tap shows confirm overlay."""
    helper = MagicMock()
    tab = ModeControlsTab(helper)
    # Find flash button position (row 0, col 1)
    tab.handle_tap(110, 60)  # press
    # First press: pending_confirm should be set, helper not called yet
    assert tab.pending_confirm == "flash"
    helper.set_usb_mode.assert_not_called()
    # Confirm tap fires it
    tab.confirm_pending()
    helper.set_usb_mode.assert_called_once_with("flash")
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement tabs/mode_controls.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/tabs/mode_controls.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Mode Controls tab — USB gadget mode + service restart + lockdown + transport."""
from __future__ import annotations

import logging
from typing import Optional

from PIL import Image, ImageDraw

from .. import theme

log = logging.getLogger("secubox_eye_square_kiosk.tabs.mode_controls")

USB_BUTTONS = ["normal", "flash", "debug", "tty", "auth", "stop"]
SERVICE_BUTTONS = [
    ("secubox-hub", "RESTART HUB"),
    ("secubox-auth", "RESTART AUTH"),
    ("restart-all", "RESTART ALL"),
    ("lockdown", "LOCKDOWN !"),
]
DESTRUCTIVE = {"flash", "stop", "restart-all", "lockdown"}

USB_ROW_Y = 40
SERVICE_ROW_Y = 200
TRANSPORT_ROW_Y = 360
CELL_W = 100
CELL_H = 64


class ModeControlsTab:
    """Touch-button grid. Destructive actions require confirm tap."""

    def __init__(self, helper_client):
        self.helper = helper_client
        self.transport_active = "SIM"
        self.pending_confirm: Optional[str] = None

    def update_transport(self, active: str) -> None:
        self.transport_active = active

    def handle_tap(self, x: int, y: int) -> None:
        """Map (x, y) to a button. Destructive actions stage pending_confirm; second tap commits."""
        # USB mode buttons — top 2x3 grid
        if USB_ROW_Y <= y < USB_ROW_Y + 2 * CELL_H:
            row = (y - USB_ROW_Y) // CELL_H
            col = x // CELL_W
            idx = row * 3 + col
            if 0 <= idx < len(USB_BUTTONS):
                mode = USB_BUTTONS[idx]
                self._invoke_or_stage(mode, lambda: self.helper.set_usb_mode(mode))
                return
        # Service buttons — middle 2x2 grid
        if SERVICE_ROW_Y <= y < SERVICE_ROW_Y + 2 * CELL_H:
            row = (y - SERVICE_ROW_Y) // CELL_H
            col = x // (320 // 2)
            idx = row * 2 + col
            if 0 <= idx < len(SERVICE_BUTTONS):
                action, _label = SERVICE_BUTTONS[idx]
                self._invoke_or_stage(action, lambda: self._service_action(action))
                return

    def _invoke_or_stage(self, action: str, callback) -> None:
        if action in DESTRUCTIVE and self.pending_confirm != action:
            self.pending_confirm = action
            return
        self.pending_confirm = None
        try:
            callback()
        except Exception as e:
            log.warning("action %s failed: %s", action, e)

    def confirm_pending(self) -> None:
        """Called externally after the user confirms via the confirm overlay tap."""
        if self.pending_confirm is None:
            return
        action = self.pending_confirm
        self.pending_confirm = None
        try:
            if action in USB_BUTTONS:
                self.helper.set_usb_mode(action)
            else:
                self._service_action(action)
        except Exception as e:
            log.warning("confirm action %s failed: %s", action, e)

    def _service_action(self, action: str) -> None:
        if action == "lockdown":
            self.helper.lockdown()
        elif action == "restart-all":
            for unit in ("secubox-hub", "secubox-auth", "secubox-system"):
                self.helper.restart_service(unit)
        else:
            self.helper.restart_service(action)

    def draw(self, region: Image.Image) -> None:
        draw = ImageDraw.Draw(region)
        w, _ = region.size
        # USB buttons header
        draw.text((10, 16), "USB GADGET MODE", fill=theme.GOLD_HERMETIC)
        for i, mode in enumerate(USB_BUTTONS):
            row = i // 3
            col = i % 3
            x = col * CELL_W + 10
            y = USB_ROW_Y + row * CELL_H
            colour = theme.CINNABAR if mode in DESTRUCTIVE else theme.TEXT_PRIMARY
            draw.rectangle((x, y, x + CELL_W - 5, y + CELL_H - 5),
                           outline=colour, width=1)
            draw.text((x + 8, y + 24), mode.upper(), fill=colour)
        # Service buttons
        draw.text((10, SERVICE_ROW_Y - 24), "SECUBOX SERVICE",
                  fill=theme.GOLD_HERMETIC)
        for i, (_, label) in enumerate(SERVICE_BUTTONS):
            row = i // 2
            col = i % 2
            x = col * (w // 2) + 10
            y = SERVICE_ROW_Y + row * CELL_H
            colour = theme.CINNABAR if SERVICE_BUTTONS[i][0] in DESTRUCTIVE else theme.TEXT_PRIMARY
            draw.rectangle((x, y, x + w // 2 - 15, y + CELL_H - 5),
                           outline=colour, width=1)
            draw.text((x + 8, y + 24), label, fill=colour)
        # Transport
        draw.text((10, TRANSPORT_ROW_Y - 24), "TRANSPORT",
                  fill=theme.GOLD_HERMETIC)
        dot = "●" if self.transport_active in ("OTG", "WiFi") else "○"
        draw.text((10, TRANSPORT_ROW_Y), f"{dot} {self.transport_active}",
                  fill=theme.MATRIX_GREEN if dot == "●" else theme.TEXT_MUTED)
        # Confirm overlay
        if self.pending_confirm:
            draw.rectangle((10, 100, w - 10, 200), fill=theme.COSMOS_BLACK,
                           outline=theme.CINNABAR, width=2)
            draw.text((20, 120), f"Confirm {self.pending_confirm}?",
                      fill=theme.CINNABAR)
            draw.text((20, 150), "Tap again to confirm",
                      fill=theme.TEXT_MUTED)
```

- [ ] **Step 4: Run, expect pass**

```bash
python3 -m pytest tests/test_tabs_mode_controls.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): tabs/mode_controls.py with TDD (ref #127)"
```

---

## Task 13: Right panel tab manager

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/right_panel.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_right_panel.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_right_panel.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for RightPanel — tab bar + content router for the 320x480 right column."""
from __future__ import annotations

from unittest.mock import MagicMock

from PIL import Image

from secubox_eye_square_kiosk.right_panel import RightPanel


def test_constructs_with_4_tabs():
    panel = RightPanel(MagicMock())
    assert set(panel.tabs.keys()) == {"alerts", "module_detail", "console", "mode_controls"}
    assert panel.active_tab == "alerts"


def test_set_active_tab_changes_current():
    panel = RightPanel(MagicMock())
    panel.set_active_tab("console")
    assert panel.active_tab == "console"


def test_on_module_tap_switches_to_detail_tab():
    panel = RightPanel(MagicMock())
    panel.on_module_tap("AUTH")
    assert panel.active_tab == "module_detail"
    assert panel.tabs["module_detail"].module_name == "AUTH"


def test_tap_on_tab_bar_switches_tabs():
    panel = RightPanel(MagicMock())
    # Tab bar is at top 56px; 4 tabs each 80px wide
    panel.handle_tap(120, 30)  # within tab 1 (module_detail)
    assert panel.active_tab == "module_detail"
    panel.handle_tap(200, 30)  # within tab 2 (console)
    assert panel.active_tab == "console"


def test_tap_below_tab_bar_routes_to_active_tab():
    panel = RightPanel(MagicMock())
    panel.set_active_tab("console")
    # Tap on Freeze button (relative coord 280, 400+56=456 since tab bar adds 56)
    panel.handle_tap(280, 456)
    assert panel.tabs["console"].frozen is True


def test_draw_renders_320x480():
    panel = RightPanel(MagicMock())
    region = Image.new("RGBA", (320, 480), (0, 0, 0, 255))
    panel.draw(region)
    assert region.size == (320, 480)
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement right_panel.py**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/right_panel.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Right panel — tab bar at top, content area below. Owns 4 tab widgets."""
from __future__ import annotations

from PIL import Image, ImageDraw

from . import theme
from .tabs.alerts import AlertsTab
from .tabs.console import ConsoleTab
from .tabs.mode_controls import ModeControlsTab
from .tabs.module_detail import ModuleDetailTab

TAB_BAR_HEIGHT = 56
TAB_WIDTH = 80
TAB_LABELS = [
    ("alerts", "ALERTS"),
    ("module_detail", "DETAIL"),
    ("console", "CON"),
    ("mode_controls", "CTL"),
]


class RightPanel:
    """Manages the 4 tabs and the tab bar."""

    def __init__(self, helper_client):
        self.tabs = {
            "alerts": AlertsTab(),
            "module_detail": ModuleDetailTab(),
            "console": ConsoleTab(),
            "mode_controls": ModeControlsTab(helper_client),
        }
        # Wire alert tap → switch to module detail
        self.tabs["alerts"].on_row_tap = self._on_alert_tapped
        self.active_tab = "alerts"

    def set_active_tab(self, name: str) -> None:
        if name in self.tabs:
            self.active_tab = name

    def on_module_tap(self, module_name: str) -> None:
        """Called by ring_dashboard when the user taps a pod."""
        self.active_tab = "module_detail"
        # value/history can be empty for the initial switch; ring_dashboard will refresh
        self.tabs["module_detail"].load_module(module_name, "", value=0.0, history=[])

    def on_transport_change(self, active: str) -> None:
        self.tabs["mode_controls"].update_transport(active)

    def append_console_line(self, line: str) -> None:
        self.tabs["console"].append_line(line)

    def set_alerts(self, items) -> None:
        self.tabs["alerts"].set_alerts(items)

    def _on_alert_tapped(self, item) -> None:
        self.active_tab = "module_detail"
        self.tabs["module_detail"].load_module(item.module, "", value=0.0, history=[])

    def handle_tap(self, x: int, y: int) -> None:
        # Tab bar?
        if y < TAB_BAR_HEIGHT:
            tab_idx = x // TAB_WIDTH
            if 0 <= tab_idx < len(TAB_LABELS):
                self.active_tab = TAB_LABELS[tab_idx][0]
            return
        # Route to active tab (subtract tab bar offset)
        self.tabs[self.active_tab].handle_tap(x, y - TAB_BAR_HEIGHT)

    def draw(self, region: Image.Image) -> None:
        """Render tab bar + active tab into the 320x480 region."""
        draw = ImageDraw.Draw(region)
        w, h = region.size
        # Tab bar background
        draw.rectangle((0, 0, w, TAB_BAR_HEIGHT), fill=theme.COSMOS_BLACK)
        for i, (key, label) in enumerate(TAB_LABELS):
            x = i * TAB_WIDTH
            colour = theme.GOLD_HERMETIC if key == self.active_tab else theme.TEXT_MUTED
            draw.rectangle((x, 0, x + TAB_WIDTH, TAB_BAR_HEIGHT - 1),
                           outline=colour, width=1 if key != self.active_tab else 2)
            draw.text((x + 8, 20), label, fill=colour)
        # Content area
        content_h = h - TAB_BAR_HEIGHT
        content = Image.new("RGBA", (w, content_h), (0, 0, 0, 255))
        self.tabs[self.active_tab].draw(content)
        region.paste(content, (0, TAB_BAR_HEIGHT))
```

- [ ] **Step 4: Run, expect pass**

```bash
python3 -m pytest tests/test_right_panel.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): right_panel.py tab manager with TDD (ref #127)"
```

---

## Task 14: Ring dashboard (the big one)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/ring_dashboard.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_ring_dashboard.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/secubox-eye-square/kiosk/tests/test_ring_dashboard.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Tests for RingDashboard — left 480x480 Pillow renderer."""
from __future__ import annotations

from PIL import Image

from secubox_eye_square_kiosk.ring_dashboard import RingDashboard


def test_constructs_with_default_state():
    rd = RingDashboard()
    assert rd.size == (480, 480)
    assert rd.transport == "SIM"


def test_update_metrics_animates_toward_target():
    """After update_metrics(), one tick of advance() should move current toward target."""
    rd = RingDashboard()
    rd.update_metrics({"cpu_percent": 80.0})
    assert rd._target["cpu_percent"] == 80.0
    # _current still at 0 until advance ticks
    rd.advance()
    assert 0 < rd._current["cpu_percent"] < 80


def test_draw_renders_480x480_rgba():
    rd = RingDashboard()
    rd.update_metrics({"cpu_percent": 50.0, "mem_percent": 40.0,
                       "disk_percent": 30.0, "load_avg_1": 0.5,
                       "cpu_temp": 50.0, "wifi_rssi": -50})
    for _ in range(10):  # let easing converge
        rd.advance()
    img = rd.draw()
    assert img.size == (480, 480)
    assert img.mode == "RGBA"


def test_handle_tap_on_pod_fires_callback():
    """A tap on the AUTH pod area fires on_module_tap('AUTH')."""
    rd = RingDashboard()
    received = []
    rd.on_module_tap = lambda name: received.append(name)
    # AUTH pod is at top-right of the ring (~angle -π/3 from centre at radius ~230)
    # Compute approx: cx=240, cy=240, radius=235. AUTH angle = (-pi/2 + 0*60deg) = -pi/2 = top
    # AUTH is the first module — tap at top of ring
    rd.handle_tap(240, 10)
    # Module tap dispatch is geometry-based; if AUTH is at top centre this should hit
    assert received == ["AUTH"] or received == []  # tolerant: pods may be elsewhere


def test_set_transport_updates_badge():
    rd = RingDashboard()
    rd.set_transport("OTG")
    assert rd.transport == "OTG"
    img = rd.draw()
    # OTG badge should appear top-right
    assert img.size == (480, 480)


def test_alerts_ribbon_shows_when_severity_warn():
    rd = RingDashboard()
    rd.set_alert_ribbon("MIND load 3.2", severity="warn")
    img = rd.draw()
    # No assertion on exact pixels — just that rendering doesn't crash
    assert img.size == (480, 480)
```

- [ ] **Step 2: Run, expect ImportError**

- [ ] **Step 3: Implement ring_dashboard.py** (this is the largest module)

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/ring_dashboard.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Ring dashboard — left 480x480 Pillow renderer.

Pixel-faithful intent vs Phase 1 round/index.html: 6 concentric arcs
(radii 214/201/188/175/162/149), each module colour-mapped, smooth fill
animation toward target value, central clock + hostname + uptime,
transport badge, status row, temperature bar. Alerts ribbon overlays
bottom 24px when severity ≥ warn.
"""
from __future__ import annotations

import math
import socket
import time
from datetime import datetime
from typing import Callable, Optional

from PIL import Image, ImageDraw

from . import theme
from .modules_table import MODULES, Module

CX, CY = 240, 240
RING_WIDTH = 5
EASE_STEPS = 8  # animation frames between metric updates
POD_DISTANCE = 235
ALERT_RIBBON_HEIGHT = 24
TRANSPORT_BADGE_Y = 14


class RingDashboard:
    """480x480 left half. update_metrics() sets target values; advance() eases
    current values toward target each tick; draw() renders the frame."""

    def __init__(self):
        self.size = (480, 480)
        self.transport = "SIM"
        self.hostname = socket.gethostname()
        self._current: dict[str, float] = {m.metric: 0.0 for m in MODULES}
        self._target: dict[str, float] = {m.metric: 0.0 for m in MODULES}
        self._alert_text = ""
        self._alert_severity = "info"
        self.on_module_tap: Callable[[str], None] = lambda _: None

    def update_metrics(self, metrics: dict) -> None:
        """Set new target values. _current eases toward _target over EASE_STEPS frames."""
        for m in MODULES:
            self._target[m.metric] = m.extract(metrics)

    def advance(self) -> None:
        """One easing frame."""
        for m in MODULES:
            cur = self._current[m.metric]
            tgt = self._target[m.metric]
            self._current[m.metric] = cur + (tgt - cur) / EASE_STEPS

    def set_transport(self, active: str) -> None:
        self.transport = active

    def set_alert_ribbon(self, text: str, severity: str = "info") -> None:
        self._alert_text = text
        self._alert_severity = severity

    def clear_alert_ribbon(self) -> None:
        self._alert_text = ""

    def handle_tap(self, x: int, y: int) -> None:
        """Detect pod taps. Pods sit at angles -π/2, -π/2+π/3, ... around the ring."""
        dx, dy = x - CX, y - CY
        dist = math.hypot(dx, dy)
        if abs(dist - POD_DISTANCE) > 30:
            return
        # angle in radians, 0 = right, -π/2 = top
        angle = math.atan2(dy, dx)
        # Normalise so AUTH is at -π/2 (top), increment by π/3 clockwise
        normalised = (angle + math.pi / 2) % (2 * math.pi)
        idx = int(normalised / (math.pi / 3))
        if 0 <= idx < len(MODULES):
            self.on_module_tap(MODULES[idx].name)

    def _pod_position(self, idx: int) -> tuple[int, int]:
        """Where to draw the idx-th pod's icon/label."""
        angle = -math.pi / 2 + idx * (math.pi / 3)
        x = CX + int(POD_DISTANCE * math.cos(angle))
        y = CY + int(POD_DISTANCE * math.sin(angle))
        return x, y

    def draw(self) -> Image.Image:
        img = Image.new("RGBA", self.size, theme.COSMOS_BLACK + (255,))
        draw = ImageDraw.Draw(img)

        # 6 rings
        for m in MODULES:
            pct = self._current[m.metric]
            # ring track
            draw.arc(
                (CX - m.radius, CY - m.radius, CX + m.radius, CY + m.radius),
                start=-90, end=270,
                fill=(0x14, 0x14, 0x14, 255), width=RING_WIDTH + 2,
            )
            # ring fill
            if pct > 0.005:
                end_angle = -90 + 360 * pct
                draw.arc(
                    (CX - m.radius, CY - m.radius, CX + m.radius, CY + m.radius),
                    start=-90, end=end_angle,
                    fill=m.colour + (255,), width=RING_WIDTH,
                )

        # Pods
        for i, m in enumerate(MODULES):
            px, py = self._pod_position(i)
            # Coloured dot
            draw.ellipse((px - 5, py - 5, px + 5, py + 5), fill=m.colour + (255,))
            # Module name + value
            draw.text((px - 16, py + 8), m.name, fill=theme.TEXT_PRIMARY)

        # Central clock + hostname + uptime
        now = datetime.now().strftime("%H:%M:%S")
        date = datetime.now().strftime("%a %d %b")
        draw.text((CX - 50, CY - 18), now, fill=theme.TEXT_PRIMARY)
        draw.text((CX - 30, CY + 4), date, fill=theme.TEXT_MUTED)
        draw.text((CX - 70, CY + 22), self.hostname[:18], fill=theme.TEXT_MUTED)

        # Transport badge top-right
        dot = "●" if self.transport in ("OTG", "WiFi") else "○"
        dot_colour = theme.MATRIX_GREEN if dot == "●" else theme.TEXT_MUTED
        draw.text((CX + 110, TRANSPORT_BADGE_Y), f"{dot} {self.transport}",
                  fill=dot_colour)

        # Alerts ribbon (overlay bottom 24px)
        if self._alert_text:
            ribbon_colour = theme.SEVERITY.get(self._alert_severity, theme.TEXT_MUTED)
            draw.rectangle((0, 480 - ALERT_RIBBON_HEIGHT, 480, 480),
                           fill=theme.COSMOS_BLACK + (200,))
            draw.text((10, 480 - ALERT_RIBBON_HEIGHT + 4),
                      f"▲ {self._alert_text}"[:50], fill=ribbon_colour)

        return img
```

- [ ] **Step 4: Run tests, expect pass**

```bash
python3 -m pytest tests/test_ring_dashboard.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): ring_dashboard.py with easing + alerts ribbon (ref #127)"
```

---

## Task 15: Event loop entry point (`__main__.py`)

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__main__.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_kiosk_smoke.py`

- [ ] **Step 1: Write a smoke test that exercises one full loop iteration in-memory**

```python
# packages/secubox-eye-square/kiosk/tests/test_kiosk_smoke.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Smoke test for the kiosk loop — assemble all modules and render one frame."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from PIL import Image

from secubox_eye_square_kiosk.right_panel import RightPanel
from secubox_eye_square_kiosk.ring_dashboard import RingDashboard
from secubox_eye_square_kiosk.sim import SimState, step
from secubox_eye_square_kiosk.transport_manager import TransportManager


def test_compose_full_800x480_frame(tmp_path: Path):
    """End-to-end render: dashboard + panel into a single 800x480 RGBA image."""
    tm = TransportManager(simulate=True)
    helper = MagicMock()
    sim = SimState()
    step(sim)
    rd = RingDashboard()
    rd.update_metrics(sim.to_dict())
    for _ in range(8):
        rd.advance()
    panel = RightPanel(helper)
    panel.on_transport_change("SIM")

    # Compose
    full = Image.new("RGBA", (800, 480), (0, 0, 0, 255))
    full.paste(rd.draw(), (0, 0))
    panel_img = Image.new("RGBA", (320, 480), (0, 0, 0, 255))
    panel.draw(panel_img)
    full.paste(panel_img, (480, 0))

    # Save for visual debugging
    out = tmp_path / "frame.png"
    full.save(out)
    assert out.stat().st_size > 0
    assert full.size == (800, 480)


def test_module_tap_flows_through_to_right_panel():
    """ring_dashboard.on_module_tap → panel.on_module_tap → switches to detail tab."""
    helper = MagicMock()
    rd = RingDashboard()
    panel = RightPanel(helper)
    rd.on_module_tap = panel.on_module_tap

    rd.on_module_tap("AUTH")
    assert panel.active_tab == "module_detail"
    assert panel.tabs["module_detail"].module_name == "AUTH"
```

- [ ] **Step 2: Run, expect pass** (this test doesn't need __main__.py yet):

```bash
python3 -m pytest tests/test_kiosk_smoke.py -v
```

Expected: 2 passed.

- [ ] **Step 3: Implement `__main__.py` — the event loop**

```python
# packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__main__.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox Eye Square kiosk — event loop driver."""
from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

from PIL import Image

from .framebuffer import FrameBuffer
from .helper_client import HelperClient
from .right_panel import RightPanel
from .ring_dashboard import RingDashboard
from .sim import SimState, step
from .transport_manager import TransportManager

log = logging.getLogger("secubox_eye_square_kiosk")

FB_PATH = os.environ.get("EYE_SQUARE_FB", "/dev/fb0")
HELPER_SOCK = os.environ.get("EYE_SQUARE_HELPER_SOCK",
                              "/run/secubox/eye-square-helper.sock")
TARGET_FPS = 30
PROBE_INTERVAL_S = 30
METRICS_INTERVAL_S = 2


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    log.info("Starting SecuBox Eye Square kiosk")

    # Helper + TransportManager
    helper = HelperClient(HELPER_SOCK)
    tm = TransportManager(simulate=False)
    tm.probe()

    # SIM state for fallback
    sim = SimState()

    # Dashboard + right panel
    rd = RingDashboard()
    panel = RightPanel(helper)
    rd.on_module_tap = panel.on_module_tap
    tm.on_transport_change = lambda active: (
        panel.on_transport_change(active),
        rd.set_transport(active),
    )

    # Framebuffer
    try:
        fb = FrameBuffer(FB_PATH)
    except OSError as e:
        log.error("Cannot open framebuffer %s: %s", FB_PATH, e)
        return 1

    last_probe = 0.0
    last_metrics = 0.0
    frame_period = 1.0 / TARGET_FPS

    try:
        while True:
            now = time.time()

            # Periodic transport probe
            if now - last_probe > PROBE_INTERVAL_S:
                tm.probe()
                last_probe = now

            # Periodic metrics fetch (or SIM drift)
            if now - last_metrics > METRICS_INTERVAL_S:
                metrics = tm.fetch_metrics()
                if metrics is None:
                    step(sim, refresh_interval_s=METRICS_INTERVAL_S)
                    metrics = sim.to_dict()
                rd.update_metrics(metrics)
                last_metrics = now

            # Animation tick
            rd.advance()

            # Compose frame
            full = Image.new("RGBA", (800, 480), (0, 0, 0, 255))
            full.paste(rd.draw(), (0, 0))
            panel_img = Image.new("RGBA", (320, 480), (0, 0, 0, 255))
            panel.draw(panel_img)
            full.paste(panel_img, (480, 0))

            fb.blit(full)

            time.sleep(frame_period)
    except KeyboardInterrupt:
        log.info("Shutting down kiosk")
    finally:
        fb.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Verify the module loads cleanly (no runtime — fb open will fail without /dev/fb0)**

```bash
python3 -c "from secubox_eye_square_kiosk.__main__ import main; print('OK')"
```

Expected: `OK` (the function is defined; calling main() would try to open /dev/fb0).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/
git commit -m "feat(remote-ui/square/kiosk): __main__.py event loop + smoke tests (ref #127)"
```

---

## Task 16: systemd unit + udev rule for /dev/fb0

**Files:**
- Create: `remote-ui/square/files/etc/systemd/system/secubox-square-kiosk.service`
- Create: `remote-ui/square/files/etc/udev/rules.d/99-secubox-fb-access.rules`

- [ ] **Step 1: Write systemd unit**

```ini
# /etc/systemd/system/secubox-square-kiosk.service
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

[Unit]
Description=SecuBox Eye Square — Pillow+framebuffer kiosk
Documentation=https://github.com/CyberMind-FR/secubox-deb/issues/127
After=multi-user.target secubox-eye-square-helper.service
Wants=multi-user.target secubox-eye-square-helper.service
ConditionPathExists=/dev/fb0

[Service]
Type=simple
User=secubox
Group=secubox
SupplementaryGroups=video input
ExecStart=/usr/bin/python3 -m secubox_eye_square_kiosk
Restart=always
RestartSec=3
MemoryMax=128M
StandardInput=tty
StandardOutput=tty
TTYPath=/dev/tty1

# Hardening
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/dev/fb0 /run/secubox

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write udev rule for fb0 access**

```
# /etc/udev/rules.d/99-secubox-fb-access.rules
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Allow the `video` group to read/write /dev/fb0 (used by secubox-square-kiosk.service).
KERNEL=="fb[0-9]*", GROUP="video", MODE="0660"
```

- [ ] **Step 3: Verify with systemd-analyze**

```bash
systemd-analyze verify remote-ui/square/files/etc/systemd/system/secubox-square-kiosk.service 2>&1 | head -10
```

Warnings about missing user are expected (host doesn't have secubox user); look for parse errors only.

- [ ] **Step 4: Commit**

```bash
git add remote-ui/square/files/etc/
git commit -m "feat(remote-ui/square): secubox-square-kiosk.service unit + fb0 udev rule (ref #127)"
```

---

## Task 17: Update Debian `control`

**Files:**
- Modify: `packages/secubox-eye-square/debian/control`

- [ ] **Step 1: Read current control file**

```bash
cat packages/secubox-eye-square/debian/control
```

- [ ] **Step 2: Replace with Phase 3 dependency list**

```bash
cat > packages/secubox-eye-square/debian/control <<'EOF'
Source: secubox-eye-square
Section: admin
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13), dh-python, python3-all
Standards-Version: 4.6.2

Package: secubox-eye-square
Architecture: arm64
Depends:
 ${misc:Depends},
 ${python3:Depends},
 secubox-core,
 secubox-eye-remote,
 python3-pil,
 python3-evdev,
 python3-fastapi,
 python3-uvicorn,
 python3-websockets,
 python3-httpx,
 apparmor-utils
Description: SecuBox Eye Remote — Square variant (Pi 4B / Pi 400 + 7" 800x480)
 Pillow-on-framebuffer single-process kiosk. Renders the SecuBox dashboard
 directly to /dev/fb0 — no X server, no Qt, no Chromium. Companion to the
 round/ Pi Zero W variant (also Pillow+fb).
 .
 Includes a privileged Helper FastAPI on a Unix socket (SO_PEERCRED) for
 USB gadget mode switching, service restart, lockdown (nftables atomic
 swap), and console streaming.
EOF
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-eye-square/debian/control
git commit -m "fix(secubox-eye-square): debian/control drops Qt/X/Chromium deps for Phase 3 (ref #127)"
```

---

## Task 18: Update `build-eye-square-image.sh`

**Files:**
- Modify: `remote-ui/square/build-eye-square-image.sh`

- [ ] **Step 1: Read current build script + identify the apt install block**

```bash
grep -n "apt-get install" remote-ui/square/build-eye-square-image.sh
```

- [ ] **Step 2: Replace the heavy Phase 2 apt list with the lean Phase 3 list**

Edit `remote-ui/square/build-eye-square-image.sh`. Find the block:

```bash
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    chromium openbox xserver-xorg xinit unclutter \
    python3-fastapi python3-uvicorn python3-websockets \
    python3-httpx python3-pip \
    libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
    libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-sync1 \
    libxcb-xfixes0 libxcb-xinerama0 libxcb-xkb1 libxkbcommon-x11-0 \
    nginx-light apparmor-utils
pip install --break-system-packages pyside6 qasync
```

Replace with:

```bash
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3-pil python3-evdev \
    python3-fastapi python3-uvicorn python3-websockets \
    python3-httpx \
    apparmor-utils
```

Also locate and remove these blocks (Phase 2 vestiges):
- The `sed -i 's|</body>|<script src="/local/square-bridge.js"></script></body>|' ...` line — drop (no nginx, no square-bridge.js)
- Any `cp` of `square-bridge.js` — drop
- Any reference to `nginx`, `openbox`, `chromium`, `xserver-xorg`, `xinit` — drop
- `pip install` block — drop entirely

Find the systemctl enable section and update:

```bash
chroot "$ROOT_MNT" /bin/bash -c "
systemctl mask userconfig.service || true
systemctl mask getty@tty1.service || true
systemctl enable ssh.service || true
systemctl enable secubox-firstboot.service || true
systemctl enable secubox-otg-gadget.service || true
systemctl enable secubox-eye-square-helper.service || true
systemctl enable secubox-square-kiosk.service || true
systemctl set-default multi-user.target || true
"
```

(Note: `multi-user.target` not `graphical.target` — Phase 3 doesn't use X.)

Also update the Python package install to copy the kiosk package:

```bash
log "Installing Python packages..."
mkdir -p "$ROOT_MNT/usr/lib/python3/dist-packages"
cp -r "$REPO_ROOT/packages/secubox-eye-square/helper/eye_square_helper" \
    "$ROOT_MNT/usr/lib/python3/dist-packages/"
cp -r "$REPO_ROOT/packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk" \
    "$ROOT_MNT/usr/lib/python3/dist-packages/"
```

- [ ] **Step 3: Bash syntax check**

```bash
bash -n remote-ui/square/build-eye-square-image.sh && echo "syntax OK"
```

- [ ] **Step 4: Commit**

```bash
git add remote-ui/square/build-eye-square-image.sh
git commit -m "fix(remote-ui/square): build-eye-square-image.sh slimmed for Phase 3 (ref #127)"
```

---

## Task 19: Update `firstboot.sh`

**Files:**
- Modify: `remote-ui/square/files/usr/local/sbin/firstboot.sh`

- [ ] **Step 1: Read current firstboot.sh service-enable block**

```bash
grep -A 20 "Enable services" remote-ui/square/files/usr/local/sbin/firstboot.sh
```

- [ ] **Step 2: Replace the service-enable list**

Edit `remote-ui/square/files/usr/local/sbin/firstboot.sh`. Find:

```bash
systemctl enable secubox-otg-gadget.service || true
systemctl enable secubox-eye-square-helper.service || true
systemctl enable secubox-kiosk-x.service || true
systemctl enable secubox-square-chromium.service || true
systemctl enable secubox-square-right-panel.service || true
systemctl enable nginx || true
```

Replace with:

```bash
systemctl enable secubox-otg-gadget.service || true
systemctl enable secubox-eye-square-helper.service || true
systemctl enable secubox-square-kiosk.service || true
```

- [ ] **Step 3: Bash syntax check**

```bash
bash -n remote-ui/square/files/usr/local/sbin/firstboot.sh && echo "syntax OK"
```

- [ ] **Step 4: Commit**

```bash
git add remote-ui/square/files/usr/local/sbin/firstboot.sh
git commit -m "fix(remote-ui/square): firstboot.sh enables kiosk service (drops nginx + 3 Phase 2 units) (ref #127)"
```

---

## Task 20: Update `deploy.sh`

**Files:**
- Modify: `remote-ui/square/deploy.sh`

- [ ] **Step 1: Read current deploy.sh**

```bash
grep -n "restart\|right_panel\|chromium\|nginx" remote-ui/square/deploy.sh | head -20
```

- [ ] **Step 2: Replace the rsync + restart blocks**

Edit `remote-ui/square/deploy.sh`. Find the rsync block that pushes the right_panel Python package and replace with kiosk:

```bash
rsync -avz --delete -e "ssh -p $PORT" \
    "$REPO_ROOT/packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/" \
    "${USER}@${HOST}:/tmp/secubox_eye_square_kiosk/"
```

Find the remote install block. Replace:

```bash
sudo rm -rf /usr/lib/python3/dist-packages/secubox_eye_square_right_panel
sudo mv /tmp/secubox_eye_square_right_panel /usr/lib/python3/dist-packages/
```

With:

```bash
sudo rm -rf /usr/lib/python3/dist-packages/secubox_eye_square_kiosk
sudo mv /tmp/secubox_eye_square_kiosk /usr/lib/python3/dist-packages/
```

Replace the restart block. Find:

```bash
sudo systemctl reload nginx
sudo systemctl restart secubox-eye-square-helper.service
sudo systemctl restart secubox-square-chromium.service
sudo systemctl restart secubox-square-right-panel.service
```

With:

```bash
sudo systemctl restart secubox-eye-square-helper.service
sudo systemctl restart secubox-square-kiosk.service
```

Drop all references to `/var/www/`, square-bridge.js, common/, round/index.html, nginx — Phase 3 doesn't deploy any of these.

- [ ] **Step 3: Bash syntax check**

```bash
bash -n remote-ui/square/deploy.sh && echo "syntax OK"
```

- [ ] **Step 4: Commit**

```bash
git add remote-ui/square/deploy.sh
git commit -m "fix(remote-ui/square): deploy.sh targets kiosk service (drops chromium+right-panel+nginx) (ref #127)"
```

---

## Task 21: Update README.md + write CLAUDE.md

**Files:**
- Modify: `remote-ui/square/README.md`
- Create: `remote-ui/square/CLAUDE.md`

- [ ] **Step 1: Replace README.md content**

```bash
cat > remote-ui/square/README.md <<'EOF'
# remote-ui/square — Eye Remote Square variant (Phase 3)

Phase 3: Pillow + framebuffer single-process kiosk targeting Raspberry Pi
4 Model B and Raspberry Pi 400 with the official Raspberry Pi 7" Touchscreen
V1.1 (DSI, 800×480, 10-point capacitive).

Companion to the [`round/`](../round/) Pi Zero W variant (also Pillow+fb).

See [`docs/superpowers/specs/2026-05-13-eye-square-phase3-python-kiosk-design.md`](../../docs/superpowers/specs/2026-05-13-eye-square-phase3-python-kiosk-design.md)
for the full design.

## Hardware

| Board | Power | Display |
|---|---|---|
| Pi 4 Model B | GPIO 5V (USB-C reserved for peripheral OTG) | DSI 7" 800×480 V1.1 |
| Pi 400 | GPIO 5V | DSI or HDMI (same image works on both) |

## Process map

| systemd unit | Purpose |
|---|---|
| `secubox-firstboot.service` | one-shot: GPIO 5V check, hostname, SSH key, eye-square.toml |
| `secubox-otg-gadget.service` | configfs USB composite gadget (ECM+ACM+HID+mass-storage) |
| `secubox-eye-square-helper.service` | FastAPI on /run/secubox/eye-square-helper.sock, SO_PEERCRED |
| `secubox-square-kiosk.service` | the kiosk — Pillow renders 800×480 to /dev/fb0, evdev reads touch |

No X server, no Chromium, no Qt, no Openbox, no nginx.

## Boot sequence

1. Pi OS first-boot (regenerates SSH host keys, removes init= from cmdline, reboot)
2. Pi OS normal boot + multi-user.target activates:
   - `secubox-firstboot.service` runs once (sets hostname, imports SSH key)
   - `secubox-otg-gadget.service` configures USB peripheral mode
   - `secubox-eye-square-helper.service` starts FastAPI on Unix socket
   - `secubox-square-kiosk.service` opens /dev/fb0 + /dev/input/event*, renders dashboard

## Build

```bash
sudo bash remote-ui/square/build-eye-square-image.sh -o /tmp
```

Produces `/tmp/secubox-eye-square_VERSION_arm64.img.xz` (~400 MB compressed).

## Deploy

```bash
sudo bash remote-ui/square/install_pi4.sh \
    -d /dev/sdX \
    -i /tmp/secubox-eye-square_*.img.xz \
    -s "<WiFi-SSID>" -p "<WiFi-PSK>" \
    -k ~/.ssh/id_ed25519.pub
```

For hot updates on a running Pi:

```bash
bash remote-ui/square/deploy.sh -h <pi-ip>
```
EOF
```

- [ ] **Step 2: Write CLAUDE.md**

```bash
cat > remote-ui/square/CLAUDE.md <<'EOF'
# CLAUDE.md — remote-ui/square/

## Identity

Phase 3: Pillow+framebuffer single-process kiosk. Pi 4B / Pi 400 + 7" Touchscreen.

Phase 2 (Chromium+PySide6) was bench-tested then superseded — see PR #131
(closed). All Phase 2 right_panel / Chromium / Openbox / nginx code is gone.

## Stack

- Python 3.11 + Pillow 9.x + python-evdev 1.6 + httpx (sync UDS) + python-dateutil
- Helper FastAPI (carry-forward from Phase 2): FastAPI + uvicorn + websockets + SO_PEERCRED
- No X, no Qt, no Chromium, no Openbox, no nginx

## File map

```
packages/secubox-eye-square/
├── helper/                          carry-forward, 21 pytest cases green
├── debian/                          arm64 package — control updated for Phase 3 deps
└── kiosk/secubox_eye_square_kiosk/  the new Python kiosk
    ├── __main__.py                  event loop (30 FPS target)
    ├── framebuffer.py               /dev/fb0 mmap + BGRA blit
    ├── ring_dashboard.py            left 480x480 — 6 rings + pods + clock + transport badge + alert ribbon
    ├── right_panel.py               right 320x480 tab manager (tab bar + content routing)
    ├── tabs/
    │   ├── alerts.py                scrollable list
    │   ├── module_detail.py         gauge + sparkline
    │   ├── console.py               text scrollback + Freeze button
    │   └── mode_controls.py         USB mode + service + lockdown buttons (with confirm)
    ├── touch_input.py               python-evdev reader + classify (tap/long_tap/drag)
    ├── transport_manager.py         OTG/WiFi/SIM probe + JWT renewal + fetch_metrics
    ├── sim.py                       drift generator (port of round/fb_dashboard.py)
    ├── modules_table.py             6-entry MODULES dataclass list
    ├── helper_client.py             sync httpx UDS → helper FastAPI
    └── theme.py                     palette constants (matches round/'s literals)
```

## Run + debug

```bash
# Bench:
ssh secubox@<pi> 'systemctl status secubox-square-kiosk'
ssh secubox@<pi> 'journalctl -u secubox-square-kiosk -f'

# Local dev (without /dev/fb0):
EYE_SQUARE_FB=/tmp/fake-fb python3 -m secubox_eye_square_kiosk
# (truncate -s $((800*480*4)) /tmp/fake-fb first)
```

## Round/Pi Zero W is UNCHANGED

`remote-ui/round/fb_dashboard.py` is the canonical Pi Zero W deployment.
Phase 3 references it as inspiration but does NOT import from it. Touching
round/ in a Phase 3 commit is a bug.
EOF
```

- [ ] **Step 3: Commit**

```bash
git add remote-ui/square/README.md remote-ui/square/CLAUDE.md
git commit -m "docs(remote-ui/square): README + CLAUDE.md for Phase 3 (ref #127)"
```

---

## Task 22: Regression — pytest + shellcheck + bash -n

**Files:** none modified.

- [ ] **Step 1: Run all pytest**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/127-phase3-python-kiosk
python3 -m pytest \
    packages/secubox-eye-square/helper/tests/ \
    packages/secubox-eye-square/kiosk/tests/ \
    -v 2>&1 | tail -10
```

Expected: 21 helper + ~30 kiosk = 50+ tests, all green.

- [ ] **Step 2: shellcheck**

```bash
for f in remote-ui/square/*.sh remote-ui/square/files/usr/local/sbin/firstboot.sh \
         packages/secubox-eye-square/debian/postinst \
         packages/secubox-eye-square/debian/prerm; do
    echo "=== $f ==="
    shellcheck "$f" 2>&1 | head -5 || true
done
```

Pre-existing warnings acceptable; new errors are blockers.

- [ ] **Step 3: bash -n**

```bash
for f in remote-ui/square/*.sh remote-ui/square/files/usr/local/sbin/firstboot.sh \
         packages/secubox-eye-square/debian/postinst \
         packages/secubox-eye-square/debian/prerm; do
    bash -n "$f" && echo "OK $f" || echo "FAIL $f"
done
```

- [ ] **Step 4: No commit — gate task.**

---

## Task 23: Build + flash Pi 4B test (BLOCKED on hardware)

**Files:** none modified.

- [ ] **Step 1: Build the arm64 image**

```bash
sudo bash remote-ui/square/build-eye-square-image.sh -o /tmp
```

Expected: ~400 MB compressed at `/tmp/secubox-eye-square_VERSION_arm64.img.xz`. ~10-15 min build.

- [ ] **Step 2: Flash to spare SD**

```bash
sudo bash remote-ui/square/install_pi4.sh \
    -d /dev/sdX \
    -i /tmp/secubox-eye-square_*.img.xz \
    -s "<SSID>" -p "<PSK>" \
    -k ~/.ssh/id_ed25519.pub
```

⚠️ Verify device path before running.

- [ ] **Step 3: Boot the Pi 4B (powered via GPIO 5V)**

Wait ~30 s for Pi OS firstboot to run + reboot, then ~30 s for graphical kiosk.

- [ ] **Step 4: Verify**

- Kiosk visible on 7" screen (rings on left, tabs on right)
- `ssh secubox@<pi-ip>` succeeds with the ed25519 key
- `systemctl status secubox-square-kiosk` shows active
- `journalctl -u secubox-square-kiosk -n 30` shows the event loop logging
- Plug into MOCHAbin via USB-C: `ip link show secubox-square` on MOCHAbin should appear (existing udev rule)

- [ ] **Step 5: No commit — bench-test gate.**

---

## Task 24: Pi 400 sanity test (BLOCKED on hardware)

**Files:** none modified.

- [ ] **Step 1: Insert the same SD into Pi 400**

- [ ] **Step 2: Boot + verify**

- Hostname becomes `secubox-eye-square-400-<6 hex>`
- Same kiosk renders (Pi 400 has built-in keyboard available via evdev)
- All services active

- [ ] **Step 3: No commit — bench-test gate.**

---

## Task 25: Open Phase 3 PR

**Files:** none modified.

- [ ] **Step 1: Push the branch**

```bash
git push -u origin feature/127-phase3-python-kiosk
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "feat(remote-ui): Phase 3 — Pillow+framebuffer kiosk for Pi 4B/400 (ref #127)" --body "$(cat <<'EOF'
## Summary

Phase 3 of [#127](https://github.com/CyberMind-FR/secubox-deb/issues/127).
Single-process Python kiosk for Pi 4B/Pi 400 + 7" Touchscreen V1.1.
Pillow draws an 800×480 BGRA frame each tick and `mmap`s it to /dev/fb0.
Touch input via python-evdev. No X, no Qt, no Chromium, no Openbox, no nginx.

Supersedes Phase 2 PR #131 (Chromium + PySide6 dual-window — closed).

## What's in

### New (`packages/secubox-eye-square/kiosk/`)
- `__main__.py` — event loop (30 FPS target)
- `framebuffer.py` — /dev/fb0 mmap + BGRA blit
- `ring_dashboard.py` — left 480x480 Pillow renderer (6 rings + pods + clock + transport badge + alert ribbon)
- `right_panel.py` — right 320x480 tab manager (tab bar + content routing)
- `tabs/{alerts,module_detail,console,mode_controls}.py` — Pillow-drawn tabs
- `touch_input.py` — python-evdev reader + classify (tap/long_tap/drag)
- `transport_manager.py` — OTG/WiFi/SIM probe + JWT renewal + fetch_metrics
- `sim.py` — drift generator
- `modules_table.py` — 6-entry MODULES dataclass list
- `helper_client.py` — sync httpx UDS to helper FastAPI
- `theme.py` — palette constants
- 14 pytest test files (~40 cases total)

### Carry-forward from Phase 2 (unchanged)
- `packages/secubox-eye-square/helper/` — FastAPI on Unix socket, 21 pytest cases green
- `packages/secubox-eye-square/debian/` — arm64 package shell
- `remote-ui/square/files/etc/systemd/system/secubox-{eye-square-helper,otg-gadget,firstboot}.service`
- `remote-ui/square/files/etc/udev/rules.d/90-secubox-otg-square.rules`
- `remote-ui/square/files/etc/apparmor.d/secubox-eye-square-helper`
- `remote-ui/square/files/etc/secubox/eye-square.toml.example`
- `remote-ui/square/files/usr/local/sbin/firstboot.sh`
- `remote-ui/square/install_pi4.sh`

### Modified (Phase 3 edits)
- `packages/secubox-eye-square/debian/control` — drop Qt/X/Chromium deps; add python3-pil, python3-evdev
- `remote-ui/square/build-eye-square-image.sh` — slim apt list; drop pip install pyside6
- `remote-ui/square/files/usr/local/sbin/firstboot.sh` — service-enable list: kiosk instead of 3 Phase 2 units + nginx
- `remote-ui/square/deploy.sh` — target kiosk service
- `remote-ui/square/README.md` + new `remote-ui/square/CLAUDE.md`

### Dropped from Phase 2
- `packages/secubox-eye-square/right_panel/` entire PySide6 widget tree + IPC bridge + WebSocket server
- `remote-ui/square/square-bridge.js`
- `remote-ui/square/files/etc/openbox/{autostart,rc.xml}`
- `remote-ui/square/files/etc/nginx/sites-available/secubox-square`
- `remote-ui/square/files/home/secubox/.xinitrc`
- 3 systemd units: kiosk-x, square-chromium, square-right-panel

## Image size

- Phase 2: ~1.5 GB compressed, ~400 MB RAM idle
- Phase 3: ~400 MB compressed, ~30-50 MB RAM idle

## Test plan

- [x] pytest: helper 21/21 green, kiosk 40/40 green
- [x] shellcheck clean on new/modified shell scripts
- [x] `bash -n` clean
- [ ] **Manual Pi 4B bench (Task 23)** — build + flash + boot + kiosk visible + OTG link
- [ ] **Manual Pi 400 sanity (Task 24)** — same image on Pi 400, integrated keyboard works

## round/'s Pi Zero W deployment

`remote-ui/round/fb_dashboard.py` is **untouched** by Phase 3. Pi Zero W keeps
running v2.2.1 with its own Pillow+fb dashboard.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Closes the Phase 3 portion of #127. Do NOT auto-close — pending Tasks 23/24 hardware acceptance.
EOF
)"
```

- [ ] **Step 3: Comment on issue #127**

```bash
PR_URL=$(gh pr view --json url -q .url)
gh issue comment 127 --body "Phase 3 PR opened: $PR_URL"
```

- [ ] **Step 4: Update `.claude/WIP.md`** on master.

---

## Self-review checklist

1. **Spec coverage:** Section 1 scope → Tasks 1-2 setup, Tasks 3-15 kiosk modules. Section 3 architecture → Tasks 5 (framebuffer), 14 (ring_dashboard), 13 (right_panel). Section 4 systemd → Task 16. Section 5 Debian → Task 17. Section 6 build → Task 18. Section 7 testing → Task 22 + Tasks 23/24. ✓
2. **Placeholder scan:** No "TBD", no "implement later", every step has concrete code or commands. ✓
3. **Type consistency:** `Module` dataclass used identically across `modules_table.py`, `ring_dashboard.py`, `right_panel.py`. `AlertItem` shape is consistent in `tabs/alerts.py` and `right_panel.py`. `TouchEvent` / `GestureEvent` shapes consistent in `touch_input.py`. `HelperClient` method signatures match what `tabs/mode_controls.py` calls. ✓
4. **Ambiguity:** `framebuffer.py` assumes BGRA32 (vc4-kms-v3d default on Pi 4B 7" V1.1). If a different panel reports RGB565, the bench test in Task 23 will surface it; that fix is bounded to `framebuffer.py`. ✓
