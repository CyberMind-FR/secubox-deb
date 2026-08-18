<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Converged Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract a shared `secubox_common` Python package under `remote-ui/common/python/` containing theme, modules, icons, and `DashboardCanvas` drawing primitives; refactor `remote-ui/round/fb_dashboard.py` and `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/` to consume it; add `pointer_input.py` + `cursor.py` (mouse/touchpad + auto-hide sprite) on square/ only; ship `secubox_common` to `/var/www/common/python/` on both images via systemd `PYTHONPATH`. Fixes round/'s missing-module-icon bug by construction.

**Architecture:** OO layout classes. `DashboardCanvas` base in common/python/secubox_common/canvas.py owns stateless drawing primitives. `RoundDashboard(DashboardCanvas)` paints a 480×480 round canvas (plus its 3 extra view modes for terminal/flash/auth). `SquareDashboard(DashboardCanvas)` paints the left 480×480 region of the 800×480 canvas using the same primitives, then composes the right_panel.draw(...) into the remaining 320×480. Both kiosks become thin event loops on top of the same drawing layer.

**Tech Stack:** Python 3.11, Pillow (PIL), numpy (RGB565 packing), python-evdev (touch + pointer), pytest, systemd, mmap to `/dev/fb0`.

**Spec:** `docs/superpowers/specs/2026-05-14-converged-dashboard-design.md` (master `b5e44e72`)
**Tracking issue:** [#135](https://github.com/CyberMind-FR/secubox-deb/issues/135)
**Prerequisite:** PR [#134](https://github.com/CyberMind-FR/secubox-deb/pull/134) must merge first — it ships `framebuffer.py` with numpy + size auto-detect that the converged square/ kiosk depends on.

---

## File map

### NEW

```
remote-ui/common/python/secubox_common/
├── __init__.py                  # version + imports re-export
├── theme.py                     # palette + DEFAULT_FONT loader
├── modules.py                   # Module dataclass + MODULES list
├── icons.py                     # load_module_icon(name, size)
├── canvas.py                    # DashboardCanvas base class
└── tests/
    ├── __init__.py
    ├── conftest.py              # shared fixtures
    ├── test_theme.py
    ├── test_modules.py
    ├── test_icons.py
    └── test_canvas.py

remote-ui/round/
├── round_dashboard.py           # class RoundDashboard(DashboardCanvas)
└── tests/test_round_dashboard.py

packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/
├── square_dashboard.py          # class SquareDashboard(DashboardCanvas)
├── pointer_input.py             # mouse/touchpad → InputEvent
└── cursor.py                    # arrow sprite

packages/secubox-eye-square/kiosk/tests/
├── test_square_dashboard.py
├── test_pointer_input.py
├── test_cursor.py
└── test_common_api_stable.py    # round/ + square/ both import canvas correctly
```

### MODIFIED

- `remote-ui/round/fb_dashboard.py` — replace inline drawing with `RoundDashboard.layout(metrics)` and `.layout_terminal/_flash/_auth(state)` calls; keep main loop + metrics sources.
- `remote-ui/round/build-eye-remote-image.sh` — ship `remote-ui/common/python/` to `/var/www/common/python/`; verify `python3-numpy` is in apt-install (it already is for round/). Add `Environment="PYTHONPATH=/var/www/common/python"` to relevant systemd units.
- `remote-ui/round/files/etc/systemd/system/secubox-fb-dashboard.service` — add `Environment="PYTHONPATH=/var/www/common/python"`.
- `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__main__.py` — use `SquareDashboard` + `PointerInput` + cursor overlay; dispatch taps from both touch + pointer.
- `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/theme.py` — keep file but make it a thin re-export from `secubox_common.theme` for backward compatibility with tests / other callers.
- `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/modules_table.py` — re-export from `secubox_common.modules`.
- `remote-ui/square/build-eye-square-image.sh` — ship `remote-ui/common/python/` to `/var/www/common/python/`; PYTHONPATH already needed.
- `remote-ui/square/files/etc/systemd/system/secubox-square-kiosk.service` — add `Environment="PYTHONPATH=/var/www/common/python"`.

### DELETED

- `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/ring_dashboard.py` — superseded by `square_dashboard.py`.
- `packages/secubox-eye-square/kiosk/tests/test_ring_dashboard.py` — superseded by `test_square_dashboard.py`.

(Keep `modules_table.py` and `theme.py` as compatibility re-export shims so any callers in the codebase that import them via the old path keep working.)

---

## Task 1: Worktree + branch setup

**Files:**
- Worktree: `~/CyberMindStudio/secubox-deb-worktrees/135-converged-dashboard/`
- Branch: `feature/135-converged-dashboard`

- [ ] **Step 1: Verify prerequisite PR #134 is merged**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb
git fetch origin master
gh pr view 134 --json state --jq .state
```

Expected: `MERGED`. If `OPEN`, stop and ask the user — this plan depends on PR #134's framebuffer.py.

- [ ] **Step 2: Pull latest master**

```bash
git checkout master
git pull --ff-only origin master
```

- [ ] **Step 3: Create worktree via agent-worktree.sh**

```bash
./scripts/agent-worktree.sh start --issue 135
```

Expected output ends with: `next: cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/135-converged-dashboard`

- [ ] **Step 4: Switch into the worktree**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/135-converged-dashboard
git status
```

Expected: `On branch feature/135-converged-dashboard`, working tree clean.

- [ ] **Step 5: Commit the empty marker (optional, skip if worktree is clean)**

(No-op if there's nothing to commit; this task has no code.)

---

## Task 2: secubox_common package skeleton

**Files:**
- Create: `remote-ui/common/python/secubox_common/__init__.py`
- Create: `remote-ui/common/python/secubox_common/tests/__init__.py`
- Create: `remote-ui/common/python/secubox_common/tests/conftest.py`
- Create: `remote-ui/common/python/pytest.ini`

- [ ] **Step 1: Create the package directory with __init__.py**

`remote-ui/common/python/secubox_common/__init__.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Shared Python primitives for SecuBox Eye Remote kiosks.

Both remote-ui/round/ (Pi Zero W) and packages/secubox-eye-square/kiosk/
(Pi 4B/400) import drawing primitives, theme constants, the module table,
and the icon loader from here.
"""
__version__ = "0.1.0"
```

- [ ] **Step 2: Create tests/__init__.py (empty)**

`remote-ui/common/python/secubox_common/tests/__init__.py`:
```python
```

- [ ] **Step 3: Create pytest config**

`remote-ui/common/python/pytest.ini`:
```ini
[pytest]
testpaths = secubox_common/tests
python_files = test_*.py
```

- [ ] **Step 4: Create conftest.py for shared fixtures**

`remote-ui/common/python/secubox_common/tests/conftest.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Shared pytest fixtures for secubox_common."""
import pytest
from PIL import Image


@pytest.fixture
def blank_round() -> Image.Image:
    """480×480 RGBA black canvas — round form factor."""
    return Image.new("RGBA", (480, 480), (0, 0, 0, 255))


@pytest.fixture
def blank_square() -> Image.Image:
    """800×480 RGBA black canvas — square form factor."""
    return Image.new("RGBA", (800, 480), (0, 0, 0, 255))
```

- [ ] **Step 5: Verify pytest discovers the empty test dir**

```bash
cd remote-ui/common/python && python3 -m pytest --collect-only
```

Expected: `no tests collected` (we haven't written any tests yet).

- [ ] **Step 6: Commit**

```bash
git add remote-ui/common/python/
git commit -m "feat(common): seed secubox_common package skeleton (ref #135)"
```

---

## Task 3: theme.py — palette + DEFAULT_FONT

**Files:**
- Create: `remote-ui/common/python/secubox_common/theme.py`
- Create: `remote-ui/common/python/secubox_common/tests/test_theme.py`

- [ ] **Step 1: Write the failing tests**

`remote-ui/common/python/secubox_common/tests/test_theme.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for secubox_common.theme — palette + DEFAULT_FONT loader."""
from PIL import ImageDraw, ImageFont, Image

from secubox_common import theme


def test_module_colors_are_rgb_byte_tuples():
    for name in ("AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"):
        c = getattr(theme, name)
        assert isinstance(c, tuple) and len(c) == 3
        assert all(isinstance(b, int) and 0 <= b <= 255 for b in c)


def test_token_colors_present():
    for name in ("COSMOS_BLACK", "GOLD_HERMETIC", "CINNABAR",
                 "MATRIX_GREEN", "CYBER_CYAN", "VOID_PURPLE",
                 "TEXT_PRIMARY", "TEXT_MUTED"):
        c = getattr(theme, name)
        assert isinstance(c, tuple) and len(c) == 3


def test_severity_table_has_three_keys():
    assert set(theme.SEVERITY.keys()) == {"info", "warn", "crit"}


def test_load_default_font_returns_usable_font():
    font = theme.load_default_font(12)
    # Must be either a TrueType (DejaVu) or the legacy bitmap default.
    assert hasattr(font, "getbbox") or hasattr(font, "getmask")


def test_load_default_font_renders_unicode_without_crash():
    """Regression for the latin-1 bitmap default crash from PR #134."""
    img = Image.new("RGB", (60, 20), color=(0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.text((2, 2), "○ NOMINAL", fill=(0, 255, 0),
              font=theme.load_default_font(12))
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_theme.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_common.theme'`.

- [ ] **Step 3: Implement theme.py**

`remote-ui/common/python/secubox_common/theme.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox palette + DEFAULT_FONT loader.

Carried over from packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/theme.py
and remote-ui/round/fb_dashboard.py module color constants. Single source of truth.
"""
from __future__ import annotations

from PIL import ImageFont

# Module colours (round/index.html / Phase 1 spec literal hex)
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

SEVERITY = {
    "info": CYBER_CYAN,
    "warn": GOLD_HERMETIC,
    "crit": CINNABAR,
}

_DEJAVU = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def load_default_font(size: int = 12):
    """Load DejaVuSans at the requested size, fall back to load_default().

    Falls back when fonts-dejavu-core isn't installed (e.g., unit test
    hosts without the apt package). Callers should not assume Unicode
    support when the fallback is active — only ASCII renders reliably
    on Pillow's legacy bitmap default.
    """
    try:
        return ImageFont.truetype(_DEJAVU, size)
    except OSError:
        return ImageFont.load_default()
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_theme.py -v
```

Expected: `5 passed`.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/common/python/secubox_common/theme.py \
        remote-ui/common/python/secubox_common/tests/test_theme.py
git commit -m "feat(common): theme.py — palette constants + DEFAULT_FONT loader (ref #135)"
```

---

## Task 4: modules.py — Module dataclass + MODULES list

**Files:**
- Create: `remote-ui/common/python/secubox_common/modules.py`
- Create: `remote-ui/common/python/secubox_common/tests/test_modules.py`

- [ ] **Step 1: Write the failing tests**

`remote-ui/common/python/secubox_common/tests/test_modules.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for secubox_common.modules — canonical Hamiltonian module table."""
from secubox_common import modules, theme


def test_modules_hamiltonian_order():
    names = [m.name for m in modules.MODULES]
    assert names == ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]


def test_each_module_has_required_fields():
    for m in modules.MODULES:
        assert m.name
        assert isinstance(m.colour, tuple) and len(m.colour) == 3
        assert m.icon_name == m.name.lower()
        assert m.metric
        assert callable(m.extract)


def test_extract_returns_unit_interval_for_typical_values():
    sample = {
        "cpu_percent": 50,
        "mem_percent": 75,
        "disk_percent": 30,
        "load_avg_1": 2.0,
        "cpu_temp": 60,
        "wifi_rssi": -60,
    }
    for m in modules.MODULES:
        v = m.extract(sample)
        assert 0.0 <= v <= 1.0, f"{m.name} extract returned {v} out of [0,1]"


def test_extract_clamps_high_values():
    high = {
        "cpu_percent": 999, "mem_percent": 999, "disk_percent": 999,
        "load_avg_1": 999, "cpu_temp": 999, "wifi_rssi": 999,
    }
    for m in modules.MODULES:
        assert m.extract(high) == 1.0


def test_extract_clamps_low_values_and_missing():
    low = {}  # all metrics missing → defaults
    for m in modules.MODULES:
        v = m.extract(low)
        assert 0.0 <= v <= 1.0


def test_modules_use_theme_colours():
    expected = {
        "AUTH": theme.AUTH, "WALL": theme.WALL, "BOOT": theme.BOOT,
        "MIND": theme.MIND, "ROOT": theme.ROOT, "MESH": theme.MESH,
    }
    for m in modules.MODULES:
        assert m.colour == expected[m.name]
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_modules.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_common.modules'`.

- [ ] **Step 3: Implement modules.py**

`remote-ui/common/python/secubox_common/modules.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Canonical 6-module table (Hamiltonian: AUTH → WALL → BOOT → MIND → ROOT → MESH).

Each Module bundles its rendering colour, the icon name used by
secubox_common.icons.load_module_icon, the metric key it reads from a
metrics dict, and an `extract` callable returning a 0..1 normalised
ratio for ring/arc fill.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import theme


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


@dataclass(frozen=True)
class Module:
    name: str
    colour: tuple[int, int, int]
    icon_name: str
    metric: str
    extract: Callable[[dict], float]


MODULES: list[Module] = [
    Module(
        name="AUTH", colour=theme.AUTH, icon_name="auth",
        metric="cpu_percent",
        extract=lambda s: _clamp(s.get("cpu_percent", 0.0) / 100.0),
    ),
    Module(
        name="WALL", colour=theme.WALL, icon_name="wall",
        metric="mem_percent",
        extract=lambda s: _clamp(s.get("mem_percent", 0.0) / 100.0),
    ),
    Module(
        name="BOOT", colour=theme.BOOT, icon_name="boot",
        metric="disk_percent",
        extract=lambda s: _clamp(s.get("disk_percent", 0.0) / 100.0),
    ),
    Module(
        name="MIND", colour=theme.MIND, icon_name="mind",
        metric="load_avg_1",
        extract=lambda s: _clamp(s.get("load_avg_1", 0.0) / 4.0),
    ),
    Module(
        name="ROOT", colour=theme.ROOT, icon_name="root",
        metric="cpu_temp",
        extract=lambda s: _clamp((s.get("cpu_temp", 35.0) - 35.0) / 50.0),
    ),
    Module(
        name="MESH", colour=theme.MESH, icon_name="mesh",
        metric="wifi_rssi",
        extract=lambda s: _clamp((s.get("wifi_rssi", -90) + 90.0) / 70.0),
    ),
]
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_modules.py -v
```

Expected: `6 passed`.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/common/python/secubox_common/modules.py \
        remote-ui/common/python/secubox_common/tests/test_modules.py
git commit -m "feat(common): modules.py — canonical Hamiltonian module table (ref #135)"
```

---

## Task 5: icons.py — module icon loader with path resolution

**Files:**
- Create: `remote-ui/common/python/secubox_common/icons.py`
- Create: `remote-ui/common/python/secubox_common/tests/test_icons.py`

- [ ] **Step 1: Write the failing tests**

`remote-ui/common/python/secubox_common/tests/test_icons.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for secubox_common.icons — path resolution + LRU cache."""
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from secubox_common import icons


def test_load_missing_icon_returns_none(monkeypatch, tmp_path):
    """No icon file anywhere → None, no exception."""
    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS",
                        [tmp_path / "does-not-exist"])
    icons._cache_clear()
    assert icons.load_module_icon("auth", 48) is None


def test_load_existing_icon_returns_pil_image(monkeypatch, tmp_path):
    """Icon found in the search path is returned as a Pillow image."""
    iconsdir = tmp_path / "icons"
    iconsdir.mkdir()
    fake = Image.new("RGBA", (48, 48), (255, 0, 0, 255))
    fake.save(iconsdir / "auth-48.png")

    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS", [iconsdir])
    icons._cache_clear()

    img = icons.load_module_icon("auth", 48)
    assert img is not None
    assert img.size == (48, 48)


def test_load_caches_by_name_and_size(monkeypatch, tmp_path):
    """Second call with same (name, size) returns the same object."""
    iconsdir = tmp_path / "icons"
    iconsdir.mkdir()
    Image.new("RGBA", (48, 48), (0, 255, 0, 255)).save(iconsdir / "wall-48.png")

    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS", [iconsdir])
    icons._cache_clear()

    a = icons.load_module_icon("wall", 48)
    b = icons.load_module_icon("wall", 48)
    assert a is b


def test_search_paths_in_order(monkeypatch, tmp_path):
    """First path with the icon wins, even if later paths also have one."""
    first = tmp_path / "first"; first.mkdir()
    second = tmp_path / "second"; second.mkdir()
    Image.new("RGBA", (48, 48), (255, 0, 0, 255)).save(first / "boot-48.png")
    Image.new("RGBA", (48, 48), (0, 0, 255, 255)).save(second / "boot-48.png")

    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS", [first, second])
    icons._cache_clear()

    img = icons.load_module_icon("boot", 48)
    # Pixel-sample to confirm we got the RED one (first path)
    px = img.getpixel((0, 0))
    assert px[:3] == (255, 0, 0)


def test_lowercase_name_normalisation(monkeypatch, tmp_path):
    """Caller can pass 'AUTH' or 'auth' — both find auth-48.png."""
    iconsdir = tmp_path / "icons"
    iconsdir.mkdir()
    Image.new("RGBA", (48, 48), (1, 2, 3, 255)).save(iconsdir / "auth-48.png")
    monkeypatch.setattr(icons, "ICON_SEARCH_PATHS", [iconsdir])
    icons._cache_clear()

    assert icons.load_module_icon("AUTH", 48) is not None
    assert icons.load_module_icon("auth", 48) is not None
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_icons.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_common.icons'`.

- [ ] **Step 3: Implement icons.py**

`remote-ui/common/python/secubox_common/icons.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Module icon loader.

Resolves `<name>-<size>.png` across a search path list. The default
search order is:
  1. /var/www/common/assets/icons      (deployed image location — set by
                                        the build script when it embeds
                                        remote-ui/common/assets/icons/)
  2. <git-checkout>/remote-ui/common/assets/icons   (dev mode)

This fixes the bug where remote-ui/round/fb_dashboard.py hardcoded
ICONS_DIR = SCRIPT_DIR/assets/icons (which on the image points at
remote-ui/round/assets/icons/ — a directory without module icons) and
always fell back to first-letter placeholders.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from PIL import Image

log = logging.getLogger("secubox_common.icons")


# Mutable so tests + tools can override.
ICON_SEARCH_PATHS: list[Path] = [
    Path("/var/www/common/assets/icons"),
    # Dev checkout — secubox_common is at <repo>/remote-ui/common/python/secubox_common
    Path(__file__).resolve().parents[2] / "assets" / "icons",
]


_cache: dict[tuple[str, int], Optional[Image.Image]] = {}


def _cache_clear() -> None:
    """Test helper — invalidates the in-process cache."""
    _cache.clear()


def load_module_icon(name: str, size: int = 48) -> Optional[Image.Image]:
    """Return the PNG icon for the named module at the requested size.

    `name` is case-insensitive — `"AUTH"` and `"auth"` both find
    `auth-<size>.png`. Returns None if no file is found in any search
    path. The first call for a (name, size) miss is logged at WARNING;
    subsequent calls hit the negative cache and stay silent.
    """
    key = (name.lower(), int(size))
    if key in _cache:
        return _cache[key]

    filename = f"{key[0]}-{key[1]}.png"
    for d in ICON_SEARCH_PATHS:
        p = d / filename
        if p.exists():
            try:
                img = Image.open(p).convert("RGBA")
                _cache[key] = img
                return img
            except (OSError, ValueError) as e:
                log.warning("failed to load %s: %s", p, e)
                continue

    log.warning("module icon not found: %s (searched %s)",
                filename, [str(d) for d in ICON_SEARCH_PATHS])
    _cache[key] = None
    return None
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_icons.py -v
```

Expected: `5 passed`.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/common/python/secubox_common/icons.py \
        remote-ui/common/python/secubox_common/tests/test_icons.py
git commit -m "feat(common): icons.py — module icon loader with multi-path resolution (closes round/ ICONS_DIR bug, ref #135)"
```

---

## Task 6: canvas.py base + paint_background

**Files:**
- Create: `remote-ui/common/python/secubox_common/canvas.py`
- Create: `remote-ui/common/python/secubox_common/tests/test_canvas.py`

- [ ] **Step 1: Write the failing tests for canvas + paint_background**

`remote-ui/common/python/secubox_common/tests/test_canvas.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for secubox_common.canvas — DashboardCanvas primitives."""
from PIL import Image

from secubox_common import theme
from secubox_common.canvas import DashboardCanvas


def test_paint_background_fills_with_colour(blank_round):
    canvas = DashboardCanvas()
    canvas.paint_background(blank_round, colour=(255, 0, 0))
    assert blank_round.getpixel((0, 0))[:3] == (255, 0, 0)
    assert blank_round.getpixel((239, 239))[:3] == (255, 0, 0)


def test_paint_background_default_is_cosmos_black(blank_round):
    canvas = DashboardCanvas()
    canvas.paint_background(blank_round)
    assert blank_round.getpixel((100, 100))[:3] == theme.COSMOS_BLACK


def test_dashboard_canvas_layout_is_abstract():
    canvas = DashboardCanvas()
    try:
        canvas.layout({})
    except NotImplementedError:
        return
    assert False, "DashboardCanvas.layout() must raise NotImplementedError"
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_common.canvas'`.

- [ ] **Step 3: Implement canvas.py base + paint_background**

`remote-ui/common/python/secubox_common/canvas.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""DashboardCanvas base class.

Subclasses implement `layout(metrics)` to compose the form-factor-specific
frame. The base class owns the drawing primitives — stateless from the
canvas's perspective, all state passed in via arguments.
"""
from __future__ import annotations

from PIL import Image, ImageDraw

from . import theme


class DashboardCanvas:
    """Drawing primitives + abstract layout."""

    def paint_background(self, img: Image.Image,
                         colour: tuple[int, int, int] = theme.COSMOS_BLACK) -> None:
        """Fill the entire image with a solid colour (alpha=255)."""
        draw = ImageDraw.Draw(img)
        draw.rectangle((0, 0, img.size[0], img.size[1]), fill=colour + (255,))

    def layout(self, metrics: dict) -> Image.Image:
        """Compose the form-factor-specific dashboard. Override in subclass."""
        raise NotImplementedError(
            "DashboardCanvas.layout() must be overridden in subclasses"
        )
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py -v
```

Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/common/python/secubox_common/canvas.py \
        remote-ui/common/python/secubox_common/tests/test_canvas.py
git commit -m "feat(common): canvas.py — DashboardCanvas base + paint_background (ref #135)"
```

---

## Task 7: paint_rainbow_ring

**Files:**
- Modify: `remote-ui/common/python/secubox_common/canvas.py`
- Modify: `remote-ui/common/python/secubox_common/tests/test_canvas.py`

- [ ] **Step 1: Append failing test for paint_rainbow_ring**

Append to `secubox_common/tests/test_canvas.py`:
```python
def test_paint_rainbow_ring_pixels_in_band_are_colored(blank_round):
    """A pixel exactly on the rainbow band radius is non-black; pixels
    inside and outside the band remain black."""
    canvas = DashboardCanvas()
    canvas.paint_rainbow_ring(blank_round, center=(240, 240),
                              radius_outer=235, radius_inner=220)

    # Centre pixel = inside the inner radius, should still be black.
    assert blank_round.getpixel((240, 240))[:3] == (0, 0, 0)

    # Pixel at radius 230 (between inner=220 and outer=235): coloured.
    px = blank_round.getpixel((240 + 230, 240))
    assert px[:3] != (0, 0, 0), \
        f"expected coloured pixel at band radius 230, got {px[:3]}"

    # Pixel at radius 250 (outside outer=235): still black.
    px = blank_round.getpixel((240 + 250 if 240 + 250 < 480 else 479, 240))
    if 240 + 250 < 480:
        assert px[:3] == (0, 0, 0)


def test_paint_rainbow_ring_spans_hue_around_circle(blank_round):
    """Sample 4 points on the band at 0°, 90°, 180°, 270° — they should
    differ in colour (rainbow hue rotates with angle)."""
    import math
    canvas = DashboardCanvas()
    canvas.paint_rainbow_ring(blank_round, center=(240, 240),
                              radius_outer=235, radius_inner=220)

    R = 227  # middle of the band
    samples = []
    for angle_deg in (0, 90, 180, 270):
        rad = math.radians(angle_deg)
        x = int(240 + R * math.cos(rad))
        y = int(240 + R * math.sin(rad))
        samples.append(blank_round.getpixel((x, y))[:3])

    # All 4 samples must be different colours.
    assert len(set(samples)) == 4, f"rainbow band hue is not rotating: {samples}"
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py::test_paint_rainbow_ring_pixels_in_band_are_colored -v
```

Expected: `AttributeError: 'DashboardCanvas' object has no attribute 'paint_rainbow_ring'`.

- [ ] **Step 3: Implement paint_rainbow_ring**

Add to `secubox_common/canvas.py` inside `DashboardCanvas`:
```python
    def paint_rainbow_ring(self, img: Image.Image,
                           center: tuple[int, int],
                           radius_outer: int,
                           radius_inner: int,
                           stops: int = 256) -> None:
        """Annular rainbow gradient — HSV hue rotates 0..360° around the centre,
        rendered as `stops` thin arc segments between radius_inner and radius_outer."""
        import colorsys
        import math

        draw = ImageDraw.Draw(img)
        cx, cy = center
        bbox = (cx - radius_outer, cy - radius_outer,
                cx + radius_outer, cy + radius_outer)
        step_deg = 360.0 / stops
        # Pillow needs an outline at least 1px thick; use a filled pieslice
        # for each step, then erase the inner disc once.
        for i in range(stops):
            hue = i / stops
            r, g, b = colorsys.hsv_to_rgb(hue, 1.0, 1.0)
            colour = (int(r * 255), int(g * 255), int(b * 255), 255)
            start = i * step_deg - 90.0
            end = (i + 1) * step_deg - 90.0
            draw.pieslice(bbox, start=start, end=end, fill=colour)

        # Erase the inner disc back to transparent / background.
        inner_bbox = (cx - radius_inner, cy - radius_inner,
                      cx + radius_inner, cy + radius_inner)
        draw.ellipse(inner_bbox, fill=(0, 0, 0, 255))
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py -v
```

Expected: `5 passed`.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/common/python/secubox_common/canvas.py \
        remote-ui/common/python/secubox_common/tests/test_canvas.py
git commit -m "feat(common): canvas — paint_rainbow_ring (HSV hue rotation) (ref #135)"
```

---

## Task 8: paint_concentric_arcs

**Files:**
- Modify: `remote-ui/common/python/secubox_common/canvas.py`
- Modify: `remote-ui/common/python/secubox_common/tests/test_canvas.py`

- [ ] **Step 1: Append failing test for paint_concentric_arcs**

Append to `secubox_common/tests/test_canvas.py`:
```python
def test_paint_concentric_arcs_six_rings_present(blank_round):
    """Six different ring colors must appear on the canvas after painting."""
    from secubox_common.modules import MODULES
    canvas = DashboardCanvas()
    metrics = {
        "cpu_percent": 100, "mem_percent": 100, "disk_percent": 100,
        "load_avg_1": 4.0, "cpu_temp": 85, "wifi_rssi": -20,
    }
    radii = [200, 185, 170, 155, 140, 125]
    canvas.paint_concentric_arcs(blank_round, center=(240, 240),
                                  modules=MODULES, metrics=metrics, radii=radii)
    # Sample on the right edge of each ring at angle 0° (3 o'clock).
    for m, r in zip(MODULES, radii):
        px = blank_round.getpixel((240 + r, 240))[:3]
        # Pixel must match the module colour (or be very close — antialiasing).
        dr = abs(px[0] - m.colour[0])
        dg = abs(px[1] - m.colour[1])
        db = abs(px[2] - m.colour[2])
        assert dr + dg + db < 60, \
            f"ring {m.name}: expected near {m.colour}, got {px}"


def test_paint_concentric_arcs_zero_metric_draws_only_track(blank_round):
    """With metric=0, no fill arc is drawn — only the dark track."""
    from secubox_common.modules import MODULES
    canvas = DashboardCanvas()
    metrics = {}  # all metrics missing → extract returns 0 (after clamp)
    radii = [200] * 6
    canvas.paint_concentric_arcs(blank_round, center=(240, 240),
                                  modules=MODULES, metrics=metrics, radii=radii)
    # At 0° on the ring the fill arc starts but covers ~0°, so the
    # track colour (very dark) should be there.
    px = blank_round.getpixel((240 + 200, 240))[:3]
    assert max(px) < 50, f"expected dark track at zero-fill, got {px}"
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py::test_paint_concentric_arcs_six_rings_present -v
```

Expected: `AttributeError: 'DashboardCanvas' object has no attribute 'paint_concentric_arcs'`.

- [ ] **Step 3: Implement paint_concentric_arcs**

Add to `secubox_common/canvas.py` inside `DashboardCanvas`:
```python
    RING_WIDTH = 5
    RING_TRACK_COLOUR = (0x14, 0x14, 0x14, 255)

    def paint_concentric_arcs(self, img: Image.Image,
                              center: tuple[int, int],
                              modules,
                              metrics: dict,
                              radii: list[int]) -> None:
        """One concentric arc per module at each radius. Each ring has a
        very dark full-circle track and a coloured fill arc proportional
        to `module.extract(metrics)` (0..1), starting at 12 o'clock and
        sweeping clockwise."""
        draw = ImageDraw.Draw(img)
        cx, cy = center
        for m, r in zip(modules, radii):
            pct = m.extract(metrics)
            bbox = (cx - r, cy - r, cx + r, cy + r)
            # Dark track (full circle, slightly thicker for visual weight).
            draw.arc(bbox, start=-90, end=270,
                     fill=self.RING_TRACK_COLOUR,
                     width=self.RING_WIDTH + 2)
            # Coloured fill (only if > ~0.5%).
            if pct > 0.005:
                end_angle = -90 + 360 * pct
                draw.arc(bbox, start=-90, end=end_angle,
                         fill=m.colour + (255,), width=self.RING_WIDTH)
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py -v
```

Expected: `7 passed`.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/common/python/secubox_common/canvas.py \
        remote-ui/common/python/secubox_common/tests/test_canvas.py
git commit -m "feat(common): canvas — paint_concentric_arcs (per-module ring fill) (ref #135)"
```

---

## Task 9: paint_pod_cluster

**Files:**
- Modify: `remote-ui/common/python/secubox_common/canvas.py`
- Modify: `remote-ui/common/python/secubox_common/tests/test_canvas.py`

- [ ] **Step 1: Append failing test for paint_pod_cluster**

Append to `secubox_common/tests/test_canvas.py`:
```python
def test_paint_pod_cluster_six_coloured_circles(blank_round):
    """Six pod circles, each in its module colour, arranged on a circle
    of given radius."""
    import math
    from secubox_common.modules import MODULES
    canvas = DashboardCanvas()
    canvas.paint_pod_cluster(blank_round, MODULES, center=(240, 240),
                              radius=100, pod_size=20)
    # Pods are at -90° + i*60° per module index.
    for i, m in enumerate(MODULES):
        angle = math.radians(-90 + i * 60)
        px = int(240 + 100 * math.cos(angle))
        py = int(240 + 100 * math.sin(angle))
        pixel = blank_round.getpixel((px, py))[:3]
        # Pod centre should be coloured by module.colour (icon overlay may
        # be transparent, but the colored disc shows through; tolerance for
        # icon center pixel).
        dr = abs(pixel[0] - m.colour[0])
        dg = abs(pixel[1] - m.colour[1])
        db = abs(pixel[2] - m.colour[2])
        # Loose tolerance — icon may dominate centre. Accept any non-black.
        assert pixel != (0, 0, 0), \
            f"pod {m.name} at ({px},{py}) is black (expected coloured)"


def test_paint_pod_cluster_no_icon_falls_back_to_letter(blank_round, monkeypatch):
    """When the icon loader returns None, pod still draws and shows the
    first letter."""
    from secubox_common import icons
    from secubox_common.modules import MODULES
    monkeypatch.setattr(icons, "load_module_icon", lambda *a, **kw: None)

    canvas = DashboardCanvas()
    canvas.paint_pod_cluster(blank_round, MODULES, center=(240, 240),
                              radius=100, pod_size=30)
    # Just verify it didn't crash and pods are drawn (non-black at pod centres).
    import math
    for i, m in enumerate(MODULES):
        angle = math.radians(-90 + i * 60)
        px = int(240 + 100 * math.cos(angle))
        py = int(240 + 100 * math.sin(angle))
        assert blank_round.getpixel((px, py)) != (0, 0, 0, 255)
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py::test_paint_pod_cluster_six_coloured_circles -v
```

Expected: `AttributeError: 'DashboardCanvas' object has no attribute 'paint_pod_cluster'`.

- [ ] **Step 3: Implement paint_pod_cluster**

Add to `secubox_common/canvas.py` inside `DashboardCanvas`:
```python
    def paint_pod_cluster(self, img: Image.Image, modules, center: tuple[int, int],
                          radius: int, pod_size: int = 48) -> None:
        """Six pods arranged at angles 60° apart on a circle of the given
        radius. Each pod is a filled circle of `module.colour`; if the
        module's icon is present it's pasted on top, otherwise the first
        letter of the module name is drawn centred in white.
        """
        from . import icons as _icons
        import math

        draw = ImageDraw.Draw(img)
        cx, cy = center
        half = pod_size // 2

        for i, m in enumerate(modules):
            angle = math.radians(-90 + i * 60)
            px = int(cx + radius * math.cos(angle))
            py = int(cy + radius * math.sin(angle))

            # Colored disc background.
            draw.ellipse((px - half, py - half, px + half, py + half),
                         fill=m.colour + (255,))

            icon = _icons.load_module_icon(m.icon_name, pod_size)
            if icon is not None:
                # Centre the icon on the pod, alpha-composited.
                ix = px - icon.size[0] // 2
                iy = py - icon.size[1] // 2
                img.paste(icon, (ix, iy), icon)
            else:
                # Fallback: first letter in white.
                font = theme.load_default_font(max(10, pod_size // 2))
                letter = m.name[0]
                bbox = font.getbbox(letter)
                lw = bbox[2] - bbox[0]
                lh = bbox[3] - bbox[1]
                draw.text((px - lw // 2, py - lh // 2 - bbox[1]),
                          letter, fill=(255, 255, 255, 255), font=font)
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py -v
```

Expected: `9 passed`.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/common/python/secubox_common/canvas.py \
        remote-ui/common/python/secubox_common/tests/test_canvas.py
git commit -m "feat(common): canvas — paint_pod_cluster (icon or letter on coloured disc) (ref #135)"
```

---

## Task 10: paint_central_button + paint_alert_ribbon

**Files:**
- Modify: `remote-ui/common/python/secubox_common/canvas.py`
- Modify: `remote-ui/common/python/secubox_common/tests/test_canvas.py`

- [ ] **Step 1: Append failing tests**

Append to `secubox_common/tests/test_canvas.py`:
```python
def test_paint_central_button_draws_hollow_white_circle(blank_round):
    canvas = DashboardCanvas()
    canvas.paint_central_button(blank_round, center=(240, 240), size=20)
    # Centre of the button should be black (hollow).
    assert blank_round.getpixel((240, 240))[:3] == (0, 0, 0)
    # Edge of the button at radius=20 should be white.
    px = blank_round.getpixel((240 + 20, 240))[:3]
    assert max(px) > 200, f"button edge expected white-ish, got {px}"


def test_paint_alert_ribbon_renders_text(blank_round):
    canvas = DashboardCanvas()
    canvas.paint_alert_ribbon(blank_round, region_y=460,
                               text="TEST ALERT", severity="warn")
    # Bottom region should be no longer fully black.
    found_nonblack = False
    for y in range(460, 480):
        for x in range(0, 480, 10):
            if blank_round.getpixel((x, y))[:3] != (0, 0, 0):
                found_nonblack = True
                break
        if found_nonblack:
            break
    assert found_nonblack, "alert ribbon did not draw any non-black pixels"
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py::test_paint_central_button_draws_hollow_white_circle -v
```

Expected: `AttributeError: 'DashboardCanvas' object has no attribute 'paint_central_button'`.

- [ ] **Step 3: Implement paint_central_button + paint_alert_ribbon**

Add to `secubox_common/canvas.py` inside `DashboardCanvas`:
```python
    def paint_central_button(self, img: Image.Image,
                             center: tuple[int, int], size: int,
                             label: str = "") -> None:
        """Hollow white circle at `center` of radius `size`. Optional
        label drawn below in TEXT_PRIMARY."""
        draw = ImageDraw.Draw(img)
        cx, cy = center
        draw.ellipse((cx - size, cy - size, cx + size, cy + size),
                     outline=(255, 255, 255, 255), width=2)
        if label:
            font = theme.load_default_font(11)
            bbox = font.getbbox(label)
            lw = bbox[2] - bbox[0]
            draw.text((cx - lw // 2, cy + size + 4),
                      label, fill=theme.TEXT_PRIMARY + (255,), font=font)

    ALERT_RIBBON_HEIGHT = 20

    def paint_alert_ribbon(self, img: Image.Image, region_y: int,
                           text: str, severity: str) -> None:
        """Bottom strip: dark semi-transparent fill + coloured text.
        `region_y` is the top of the ribbon (typically img.height - 20)."""
        draw = ImageDraw.Draw(img)
        w = img.size[0]
        colour = theme.SEVERITY.get(severity, theme.TEXT_MUTED) + (255,)
        draw.rectangle((0, region_y, w, region_y + self.ALERT_RIBBON_HEIGHT),
                       fill=(0, 0, 0, 200))
        font = theme.load_default_font(11)
        draw.text((10, region_y + 4),
                  f"▲ {text}"[:50], fill=colour, font=font)
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd remote-ui/common/python && python3 -m pytest secubox_common/tests/test_canvas.py -v
```

Expected: `11 passed`.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/common/python/secubox_common/canvas.py \
        remote-ui/common/python/secubox_common/tests/test_canvas.py
git commit -m "feat(common): canvas — paint_central_button + paint_alert_ribbon (ref #135)"
```

---

## Task 11: SquareDashboard subclass

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/square_dashboard.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_square_dashboard.py`
- Delete: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/ring_dashboard.py`
- Delete: `packages/secubox-eye-square/kiosk/tests/test_ring_dashboard.py`

- [ ] **Step 1: Write failing tests for SquareDashboard**

`packages/secubox-eye-square/kiosk/tests/test_square_dashboard.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for SquareDashboard — composes round-style dashboard + right_panel."""
import sys
from pathlib import Path

# secubox_common is at <repo>/remote-ui/common/python/ on dev hosts and
# at /var/www/common/python/ on the image. Add the dev path for tests.
_DEV = Path(__file__).resolve().parents[4] / "remote-ui" / "common" / "python"
if str(_DEV) not in sys.path:
    sys.path.insert(0, str(_DEV))

from PIL import Image

from secubox_eye_square_kiosk.square_dashboard import SquareDashboard


class _FakeRightPanel:
    """Stand-in for right_panel.RightPanel."""
    def __init__(self):
        self.draw_called_with = None

    def draw(self, region: Image.Image) -> None:
        self.draw_called_with = region.size
        # Paint a known-colour pixel so test can detect that right panel ran.
        region.putpixel((10, 10), (0xAA, 0xBB, 0xCC, 255))


def test_square_dashboard_size_is_800x480():
    sd = SquareDashboard(right_panel=_FakeRightPanel())
    assert sd.SIZE == (800, 480)


def test_square_dashboard_layout_calls_right_panel():
    panel = _FakeRightPanel()
    sd = SquareDashboard(right_panel=panel)
    img = sd.layout({})
    assert panel.draw_called_with == (320, 480)
    # The fake right panel painted (0xAA, 0xBB, 0xCC) at panel-local (10, 10);
    # in the composed image that lands at (480 + 10, 10).
    assert img.getpixel((490, 10))[:3] == (0xAA, 0xBB, 0xCC)


def test_square_dashboard_layout_paints_left_dashboard_region():
    """The 480×480 left region must have non-black pixels (rainbow ring etc.)."""
    sd = SquareDashboard(right_panel=_FakeRightPanel())
    img = sd.layout({})
    # Sample at 12 o'clock on the rainbow ring (around y=10, x=240).
    nonblack = 0
    for x in range(200, 280):
        if img.getpixel((x, 10))[:3] != (0, 0, 0):
            nonblack += 1
    assert nonblack > 0, "no non-black pixels at top of left dashboard"


def test_square_dashboard_output_is_rgba_image():
    sd = SquareDashboard(right_panel=_FakeRightPanel())
    img = sd.layout({})
    assert img.mode == "RGBA"
    assert img.size == (800, 480)
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd packages/secubox-eye-square/kiosk && python3 -m pytest tests/test_square_dashboard.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_eye_square_kiosk.square_dashboard'`.

- [ ] **Step 3: Implement SquareDashboard**

`packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/square_dashboard.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SquareDashboard — 800×480 landscape kiosk for Pi 4B/400.

Composes a 480×480 round-style dashboard (using secubox_common
primitives) into the left half, then pastes the right_panel's tab bar
+ active tab content (320×480) into the right half.
"""
from __future__ import annotations

from PIL import Image

from secubox_common import theme
from secubox_common.canvas import DashboardCanvas
from secubox_common.modules import MODULES


class SquareDashboard(DashboardCanvas):
    SIZE = (800, 480)
    DASHBOARD_REGION_SIZE = (480, 480)
    PANEL_REGION_SIZE = (320, 480)
    CENTER = (240, 240)
    RING_RADII = [200, 185, 170, 155, 140, 125]

    def __init__(self, right_panel):
        self.right_panel = right_panel

    def layout(self, metrics: dict) -> Image.Image:
        img = Image.new("RGBA", self.SIZE, theme.COSMOS_BLACK + (255,))

        # Left dashboard region.
        dash = Image.new("RGBA", self.DASHBOARD_REGION_SIZE,
                         theme.COSMOS_BLACK + (255,))
        self.paint_rainbow_ring(dash, self.CENTER, 235, 220)
        self.paint_concentric_arcs(dash, self.CENTER, MODULES, metrics,
                                    self.RING_RADII)
        self.paint_pod_cluster(dash, MODULES, self.CENTER, radius=70, pod_size=40)
        self.paint_central_button(dash, self.CENTER, size=44)
        img.paste(dash, (0, 0))

        # Right panel.
        panel = Image.new("RGBA", self.PANEL_REGION_SIZE,
                          theme.COSMOS_BLACK + (255,))
        self.right_panel.draw(panel)
        img.paste(panel, (480, 0))

        return img
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd packages/secubox-eye-square/kiosk && python3 -m pytest tests/test_square_dashboard.py -v
```

Expected: `4 passed`.

- [ ] **Step 5: Delete old ring_dashboard files**

```bash
rm packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/ring_dashboard.py
rm packages/secubox-eye-square/kiosk/tests/test_ring_dashboard.py
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/square_dashboard.py \
        packages/secubox-eye-square/kiosk/tests/test_square_dashboard.py
git rm packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/ring_dashboard.py \
        packages/secubox-eye-square/kiosk/tests/test_ring_dashboard.py
git commit -m "feat(square): SquareDashboard via secubox_common; drop ring_dashboard.py (ref #135)"
```

---

## Task 12: PointerInput

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/pointer_input.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_pointer_input.py`

- [ ] **Step 1: Write failing tests**

`packages/secubox-eye-square/kiosk/tests/test_pointer_input.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for PointerInput — mouse + touchpad → InputEvent."""
import time

import pytest

from secubox_eye_square_kiosk.pointer_input import PointerInput, InputEvent


@pytest.fixture
def pointer():
    p = PointerInput(fb_size=(800, 480))
    return p


def _feed_evdev(pointer, events: list[tuple]):
    """Inject (code_name, value) events as if from a single evdev device."""
    pointer._inject_for_tests(events)


def test_initial_cursor_at_centre(pointer):
    assert pointer.cursor_xy == (400, 240)


def test_relative_motion_updates_cursor(pointer):
    _feed_evdev(pointer, [("EV_REL_X", 10), ("EV_REL_Y", -5), ("EV_SYN", 0)])
    events = pointer.poll()
    assert pointer.cursor_xy == (410, 235)
    assert any(e.kind == "motion" for e in events)


def test_relative_motion_clamps_to_fb_bounds(pointer):
    _feed_evdev(pointer, [("EV_REL_X", -1000), ("EV_REL_Y", -1000), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_xy == (0, 0)
    _feed_evdev(pointer, [("EV_REL_X", 9999), ("EV_REL_Y", 9999), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_xy == (799, 479)


def test_btn_left_emits_tap_at_cursor(pointer):
    _feed_evdev(pointer, [("EV_REL_X", 50), ("EV_REL_Y", 50)])
    pointer.poll()  # consume motion
    _feed_evdev(pointer, [("EV_KEY_BTN_LEFT", 1), ("EV_SYN", 0)])
    events = pointer.poll()
    taps = [e for e in events if e.kind == "tap"]
    assert len(taps) == 1
    assert taps[0].x == 450 and taps[0].y == 290


def test_absolute_motion_sets_cursor_directly(pointer):
    _feed_evdev(pointer, [("EV_ABS_X", 600), ("EV_ABS_Y", 300), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_xy == (600, 300)


def test_btn_touch_emits_tap(pointer):
    _feed_evdev(pointer, [
        ("EV_ABS_X", 100), ("EV_ABS_Y", 100),
        ("EV_KEY_BTN_TOUCH", 1), ("EV_SYN", 0),
    ])
    events = pointer.poll()
    taps = [e for e in events if e.kind == "tap"]
    assert len(taps) == 1
    assert taps[0].x == 100 and taps[0].y == 100


def test_cursor_visible_after_motion(pointer):
    _feed_evdev(pointer, [("EV_REL_X", 5), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_visible is True


def test_cursor_auto_hides_after_timeout(pointer, monkeypatch):
    _feed_evdev(pointer, [("EV_REL_X", 5), ("EV_SYN", 0)])
    pointer.poll()
    assert pointer.cursor_visible is True

    # Advance the clock by AUTO_HIDE_S + 1.
    real_time = time.time
    monkeypatch.setattr(time, "time",
                        lambda: real_time() + PointerInput.AUTO_HIDE_S + 1.0)
    assert pointer.cursor_visible is False


def test_oserror_in_poll_does_not_propagate(pointer):
    """Simulated USB unplug (read raises OSError) is swallowed."""
    pointer._mark_device_gone_for_tests()
    pointer.poll()  # should not raise
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd packages/secubox-eye-square/kiosk && python3 -m pytest tests/test_pointer_input.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_eye_square_kiosk.pointer_input'`.

- [ ] **Step 3: Implement PointerInput**

`packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/pointer_input.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""PointerInput — mouse + touchpad via python-evdev.

Reads /dev/input/event* devices that expose BTN_LEFT or BTN_TOUCH,
emits InputEvent("motion"/"tap", x, y) at the current cursor position.

The cursor position is clamped to the framebuffer bounds passed in at
construction. Mouse devices send relative motion (REL_X/Y); touchpads
send absolute (ABS_X/Y). Both are mapped through to (cursor_x, cursor_y).

Auto-hide: `cursor_visible` returns False if no motion in the last
AUTO_HIDE_S seconds. The kiosk overlay logic uses this to skip drawing
the cursor sprite when idle.

USB unplug: OSError on read marks the device gone; `poll()` keeps
running and re-tries device discovery every 30 s.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

log = logging.getLogger("secubox_eye_square_kiosk.pointer_input")

try:
    from evdev import InputDevice, list_devices, ecodes
    HAS_EVDEV = True
except ImportError:
    HAS_EVDEV = False


@dataclass
class InputEvent:
    kind: str  # "tap" | "motion"
    x: int
    y: int


# Event-code names used by tests' _inject_for_tests helper.
_TEST_CODE_TO_TYPE_CODE = {
    "EV_REL_X": ("REL", "REL_X"),
    "EV_REL_Y": ("REL", "REL_Y"),
    "EV_ABS_X": ("ABS", "ABS_X"),
    "EV_ABS_Y": ("ABS", "ABS_Y"),
    "EV_KEY_BTN_LEFT": ("KEY", "BTN_LEFT"),
    "EV_KEY_BTN_TOUCH": ("KEY", "BTN_TOUCH"),
    "EV_SYN": ("SYN", "SYN_REPORT"),
}


class PointerInput:
    AUTO_HIDE_S = 3.0
    REDISCOVERY_INTERVAL_S = 30.0

    def __init__(self, fb_size: tuple[int, int]):
        self.fb_w, self.fb_h = fb_size
        self._x = fb_size[0] // 2
        self._y = fb_size[1] // 2
        self._last_motion = 0.0
        self._last_rediscovery = 0.0
        self._test_queue: list[tuple] = []
        self._device_gone = False
        self._devices = []
        if HAS_EVDEV:
            self._devices = self._discover_devices()

    @property
    def cursor_xy(self) -> tuple[int, int]:
        return (self._x, self._y)

    @property
    def cursor_visible(self) -> bool:
        return (time.time() - self._last_motion) < self.AUTO_HIDE_S

    def poll(self) -> list[InputEvent]:
        out: list[InputEvent] = []
        # Drain test queue first.
        out.extend(self._drain_test_queue())
        # Real devices.
        for dev in list(self._devices):
            try:
                for ev in dev.read():
                    e = self._handle_evdev_event(ev)
                    if e is not None:
                        out.append(e)
            except BlockingIOError:
                continue  # nothing queued, normal
            except OSError as ose:
                log.warning("pointer device %s gone: %s", dev.path, ose)
                self._devices.remove(dev)
                self._device_gone = True
        # Periodic re-discovery if any device was lost.
        if self._device_gone and HAS_EVDEV:
            now = time.time()
            if now - self._last_rediscovery > self.REDISCOVERY_INTERVAL_S:
                self._devices = self._discover_devices()
                self._last_rediscovery = now
                if self._devices:
                    self._device_gone = False
        return out

    # ---- internals ----

    def _discover_devices(self) -> list:
        if not HAS_EVDEV:
            return []
        devices = []
        for path in list_devices():
            try:
                dev = InputDevice(path)
                caps = dev.capabilities()
                key_caps = caps.get(ecodes.EV_KEY, [])
                if ecodes.BTN_LEFT in key_caps or ecodes.BTN_TOUCH in key_caps:
                    # Make it non-blocking so poll() can drain without hanging.
                    import os, fcntl
                    flags = fcntl.fcntl(dev.fd, fcntl.F_GETFL)
                    fcntl.fcntl(dev.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                    devices.append(dev)
            except (OSError, PermissionError):
                continue
        log.warning("pointer devices found: %s", [d.path for d in devices])
        return devices

    def _handle_evdev_event(self, ev) -> "InputEvent | None":
        if not HAS_EVDEV:
            return None
        if ev.type == ecodes.EV_REL:
            if ev.code == ecodes.REL_X:
                self._x = self._clamp_x(self._x + ev.value)
                self._touch_motion()
            elif ev.code == ecodes.REL_Y:
                self._y = self._clamp_y(self._y + ev.value)
                self._touch_motion()
        elif ev.type == ecodes.EV_ABS:
            if ev.code == ecodes.ABS_X:
                self._x = self._clamp_x(ev.value)
                self._touch_motion()
            elif ev.code == ecodes.ABS_Y:
                self._y = self._clamp_y(ev.value)
                self._touch_motion()
        elif ev.type == ecodes.EV_KEY:
            if ev.code in (ecodes.BTN_LEFT, ecodes.BTN_TOUCH) and ev.value == 1:
                return InputEvent("tap", self._x, self._y)
        return None

    def _drain_test_queue(self) -> list[InputEvent]:
        out: list[InputEvent] = []
        had_motion = False
        for name, value in self._test_queue:
            kind, code = _TEST_CODE_TO_TYPE_CODE.get(name, (None, None))
            if kind is None:
                continue
            if kind == "REL":
                if code == "REL_X":
                    self._x = self._clamp_x(self._x + value); had_motion = True
                elif code == "REL_Y":
                    self._y = self._clamp_y(self._y + value); had_motion = True
            elif kind == "ABS":
                if code == "ABS_X":
                    self._x = self._clamp_x(value); had_motion = True
                elif code == "ABS_Y":
                    self._y = self._clamp_y(value); had_motion = True
            elif kind == "KEY":
                if value == 1 and code in ("BTN_LEFT", "BTN_TOUCH"):
                    out.append(InputEvent("tap", self._x, self._y))
        if had_motion:
            self._touch_motion()
            out.append(InputEvent("motion", self._x, self._y))
        self._test_queue.clear()
        return out

    def _touch_motion(self) -> None:
        self._last_motion = time.time()

    def _clamp_x(self, x: int) -> int:
        return max(0, min(self.fb_w - 1, int(x)))

    def _clamp_y(self, y: int) -> int:
        return max(0, min(self.fb_h - 1, int(y)))

    # ---- test hooks ----

    def _inject_for_tests(self, events: list[tuple]) -> None:
        self._test_queue.extend(events)

    def _mark_device_gone_for_tests(self) -> None:
        self._device_gone = True
        self._devices = []
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd packages/secubox-eye-square/kiosk && python3 -m pytest tests/test_pointer_input.py -v
```

Expected: `9 passed`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/pointer_input.py \
        packages/secubox-eye-square/kiosk/tests/test_pointer_input.py
git commit -m "feat(square): pointer_input — mouse + touchpad via python-evdev (ref #135)"
```

---

## Task 13: cursor sprite

**Files:**
- Create: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/cursor.py`
- Create: `packages/secubox-eye-square/kiosk/tests/test_cursor.py`

- [ ] **Step 1: Write failing tests**

`packages/secubox-eye-square/kiosk/tests/test_cursor.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for cursor.draw_cursor — overlay sprite."""
from PIL import Image

from secubox_eye_square_kiosk.cursor import draw_cursor


def test_cursor_pixels_at_origin():
    img = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    draw_cursor(img, 50, 50)
    # At least one non-black pixel near (50, 50).
    nonblack = sum(1 for dy in range(0, 16) for dx in range(0, 12)
                   if img.getpixel((50 + dx, 50 + dy))[:3] != (0, 0, 0))
    assert nonblack > 0


def test_cursor_clamped_to_image_bounds():
    img = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    draw_cursor(img, 95, 95)
    # Must not raise. Sprite is partially drawn within bounds.


def test_cursor_negative_coords_dont_crash():
    img = Image.new("RGBA", (100, 100), (0, 0, 0, 255))
    draw_cursor(img, -10, -10)  # off-canvas — should be a no-op
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd packages/secubox-eye-square/kiosk && python3 -m pytest tests/test_cursor.py -v
```

Expected: `ModuleNotFoundError: No module named 'secubox_eye_square_kiosk.cursor'`.

- [ ] **Step 3: Implement cursor.draw_cursor**

`packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/cursor.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Cursor sprite — drawn as the last overlay each frame when the pointer
has moved within the AUTO_HIDE_S window."""
from __future__ import annotations

from PIL import Image, ImageDraw

# 12×16 arrow: gold outline (GOLD_HERMETIC) + black fill. Hand-drawn
# polygon, top-left origin.
_OUTLINE = (0xC9, 0xA8, 0x4C, 255)
_FILL = (0x00, 0x00, 0x00, 255)

_POLY = [
    (0, 0), (10, 6), (5, 6), (8, 14), (5, 15), (3, 8), (0, 11),
]


def draw_cursor(img: Image.Image, x: int, y: int) -> None:
    """Draw the cursor sprite with hot-spot at (x, y).

    Sprite extends 0..11 px right and 0..15 px down from the hot-spot.
    Partial off-canvas placement is fine — Pillow's polygon clips itself.
    Coordinates with x < 0 or y < 0 fully off-canvas: no-op."""
    if x + 12 < 0 or y + 16 < 0 or x >= img.size[0] or y >= img.size[1]:
        return
    draw = ImageDraw.Draw(img)
    shifted = [(x + px, y + py) for (px, py) in _POLY]
    draw.polygon(shifted, fill=_FILL, outline=_OUTLINE)
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd packages/secubox-eye-square/kiosk && python3 -m pytest tests/test_cursor.py -v
```

Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/cursor.py \
        packages/secubox-eye-square/kiosk/tests/test_cursor.py
git commit -m "feat(square): cursor.py — 12×16 arrow sprite for pointer overlay (ref #135)"
```

---

## Task 14: theme.py + modules_table.py compat shims

**Files:**
- Modify: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/theme.py`
- Modify: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/modules_table.py`

These shims keep `from secubox_eye_square_kiosk.theme import COSMOS_BLACK` working in the existing tabs/* code without forcing a sweeping import rewrite in this PR.

- [ ] **Step 1: Replace square/'s theme.py with a re-export shim**

`packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/theme.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Backward-compat shim — re-exports secubox_common.theme.

Square/ kiosk modules and tests historically import from
secubox_eye_square_kiosk.theme. This shim keeps those imports working
while the canonical palette + DEFAULT_FONT live in secubox_common.theme.
"""
from secubox_common.theme import *  # noqa: F401,F403
from secubox_common.theme import (  # noqa: F401
    AUTH, WALL, BOOT, MIND, ROOT, MESH,
    COSMOS_BLACK, GOLD_HERMETIC, CINNABAR, MATRIX_GREEN,
    CYBER_CYAN, VOID_PURPLE, TEXT_PRIMARY, TEXT_MUTED,
    SEVERITY, load_default_font,
)

# Older callers expected a module-level constant DEFAULT_FONT.
DEFAULT_FONT = load_default_font(12)
```

- [ ] **Step 2: Replace square/'s modules_table.py with a re-export shim**

`packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/modules_table.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Backward-compat shim — re-exports secubox_common.modules."""
from secubox_common.modules import Module, MODULES  # noqa: F401
```

- [ ] **Step 3: Run all square/ kiosk tests to verify nothing broke**

```bash
cd packages/secubox-eye-square/kiosk && PYTHONPATH=../../../remote-ui/common/python python3 -m pytest tests/ -v
```

Expected: all tests pass (existing 71 plus new SquareDashboard / pointer / cursor tests).

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/theme.py \
        packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/modules_table.py
git commit -m "refactor(square): theme + modules_table become re-export shims for secubox_common (ref #135)"
```

---

## Task 15: Square/ kiosk __main__.py wires SquareDashboard + PointerInput + cursor

**Files:**
- Modify: `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__main__.py`

- [ ] **Step 1: Read current __main__.py to capture context**

```bash
cat packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__main__.py
```

- [ ] **Step 2: Replace __main__.py with the converged version**

`packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__main__.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox Eye Square kiosk — event loop driver (converged)."""
from __future__ import annotations

import logging
import os
import sys
import time

from .cursor import draw_cursor
from .framebuffer import FrameBuffer
from .helper_client import HelperClient
from .pointer_input import PointerInput
from .right_panel import RightPanel
from .sim import SimState, step
from .square_dashboard import SquareDashboard
from .touch_input import TouchInput
from .transport_manager import TransportManager

log = logging.getLogger("secubox_eye_square_kiosk")

FB_PATH = os.environ.get("EYE_SQUARE_FB", "/dev/fb0")
HELPER_SOCK = os.environ.get(
    "EYE_SQUARE_HELPER_SOCK", "/run/secubox/eye-square-helper.sock"
)
TARGET_FPS = 30
PROBE_INTERVAL_S = 30
METRICS_INTERVAL_S = 2


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    log.info("Starting SecuBox Eye Square kiosk (converged)")

    helper = HelperClient(HELPER_SOCK)
    tm = TransportManager(simulate=False)
    tm.probe()

    sim = SimState()

    panel = RightPanel(helper)
    dashboard = SquareDashboard(right_panel=panel)
    tm.on_transport_change = lambda active: panel.on_transport_change(active)

    try:
        fb = FrameBuffer(FB_PATH)
    except OSError as e:
        log.error("Cannot open framebuffer %s: %s", FB_PATH, e)
        return 1

    touch = TouchInput()
    pointer = PointerInput(fb_size=(fb.width, fb.height))

    last_probe = 0.0
    last_metrics = 0.0
    frame_period = 1.0 / TARGET_FPS

    try:
        while True:
            now = time.time()

            # Periodic transport probe + metrics refresh.
            if now - last_probe > PROBE_INTERVAL_S:
                tm.probe()
                last_probe = now
            if now - last_metrics > METRICS_INTERVAL_S:
                metrics = tm.fetch_metrics()
                if metrics is None:
                    step(sim, refresh_interval_s=METRICS_INTERVAL_S)
                    metrics = sim.to_dict()
                last_metrics = now

            # Input poll + dispatch.
            for tap in touch.poll():
                _dispatch_tap(tap.x, tap.y, panel, dashboard)
            for ev in pointer.poll():
                if ev.kind == "tap":
                    _dispatch_tap(ev.x, ev.y, panel, dashboard)

            # Render.
            full = dashboard.layout(metrics)
            if pointer.cursor_visible:
                draw_cursor(full, *pointer.cursor_xy)
            fb.blit(full)

            time.sleep(frame_period)
    except KeyboardInterrupt:
        log.info("Shutting down kiosk")
    finally:
        fb.close()
    return 0


def _dispatch_tap(x: int, y: int, panel: RightPanel, dashboard) -> None:
    if x >= 480:
        panel.handle_tap(x - 480, y)
    else:
        # Future: dashboard.handle_tap(x, y) — pod cluster interaction.
        # For now the dashboard is read-only; only the tab bar takes taps.
        pass


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 3: Run all square/ kiosk tests**

```bash
cd packages/secubox-eye-square/kiosk && PYTHONPATH=../../../remote-ui/common/python python3 -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/__main__.py
git commit -m "feat(square): __main__ wires SquareDashboard + PointerInput + cursor overlay (ref #135)"
```

---

## Task 16: Cross-form-factor API stability test

**Files:**
- Create: `packages/secubox-eye-square/kiosk/tests/test_common_api_stable.py`

- [ ] **Step 1: Write the test**

`packages/secubox-eye-square/kiosk/tests/test_common_api_stable.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Catches API drift between secubox_common and its consumers."""
import inspect

import pytest

from secubox_common import canvas as common_canvas
from secubox_common import modules as common_modules
from secubox_common import theme as common_theme


def test_dashboard_canvas_has_documented_primitives():
    expected = {
        "paint_background", "paint_rainbow_ring", "paint_concentric_arcs",
        "paint_pod_cluster", "paint_central_button", "paint_alert_ribbon",
        "layout",
    }
    actual = {
        name for name, member in inspect.getmembers(common_canvas.DashboardCanvas)
        if not name.startswith("_") and callable(member)
    }
    missing = expected - actual
    assert not missing, f"DashboardCanvas missing methods: {missing}"


def test_six_canonical_modules():
    names = [m.name for m in common_modules.MODULES]
    assert names == ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]


def test_module_dataclass_fields():
    m = common_modules.MODULES[0]
    for field in ("name", "colour", "icon_name", "metric", "extract"):
        assert hasattr(m, field)


def test_theme_required_constants():
    for c in ("COSMOS_BLACK", "GOLD_HERMETIC", "CINNABAR",
              "MATRIX_GREEN", "CYBER_CYAN", "VOID_PURPLE",
              "TEXT_PRIMARY", "TEXT_MUTED",
              "AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"):
        assert hasattr(common_theme, c), f"theme missing {c}"


def test_square_dashboard_subclasses_canvas():
    from secubox_eye_square_kiosk.square_dashboard import SquareDashboard
    assert issubclass(SquareDashboard, common_canvas.DashboardCanvas)
```

- [ ] **Step 2: Run the test**

```bash
cd packages/secubox-eye-square/kiosk && PYTHONPATH=../../../remote-ui/common/python python3 -m pytest tests/test_common_api_stable.py -v
```

Expected: `5 passed`.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-eye-square/kiosk/tests/test_common_api_stable.py
git commit -m "test(square): cross-form-factor API stability check (ref #135)"
```

---

## Task 17: RoundDashboard subclass

**Files:**
- Create: `remote-ui/round/round_dashboard.py`
- Create: `remote-ui/round/tests/test_round_dashboard.py`

- [ ] **Step 1: Write failing tests**

`remote-ui/round/tests/test_round_dashboard.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for RoundDashboard — Pi Zero W 480×480 layout via secubox_common."""
import sys
from pathlib import Path

_DEV = Path(__file__).resolve().parents[3] / "remote-ui" / "common" / "python"
if str(_DEV) not in sys.path:
    sys.path.insert(0, str(_DEV))

from round_dashboard import RoundDashboard
from secubox_common.canvas import DashboardCanvas


def test_round_dashboard_subclasses_canvas():
    assert issubclass(RoundDashboard, DashboardCanvas)


def test_round_dashboard_size_is_480():
    rd = RoundDashboard()
    assert rd.SIZE == (480, 480)


def test_round_dashboard_layout_returns_rgba_480x480():
    rd = RoundDashboard()
    img = rd.layout({})
    assert img.mode == "RGBA"
    assert img.size == (480, 480)


def test_round_dashboard_layout_paints_rainbow_ring():
    rd = RoundDashboard()
    img = rd.layout({})
    # Rainbow ring is at radius 220-235; sample at radius 227 angle 0.
    px = img.getpixel((240 + 227, 240))
    assert px[:3] != (0, 0, 0), "rainbow ring not painted at 3 o'clock"
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd remote-ui/round && PYTHONPATH=../common/python python3 -m pytest tests/test_round_dashboard.py -v
```

Expected: `ModuleNotFoundError: No module named 'round_dashboard'`.

- [ ] **Step 3: Implement RoundDashboard**

`remote-ui/round/round_dashboard.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""RoundDashboard — 480×480 Pi Zero W kiosk using secubox_common primitives."""
from __future__ import annotations

from PIL import Image

from secubox_common import theme
from secubox_common.canvas import DashboardCanvas
from secubox_common.modules import MODULES


class RoundDashboard(DashboardCanvas):
    SIZE = (480, 480)
    CENTER = (240, 240)
    RING_RADII = [200, 185, 170, 155, 140, 125]

    def layout(self, metrics: dict) -> Image.Image:
        img = Image.new("RGBA", self.SIZE, theme.COSMOS_BLACK + (255,))
        self.paint_rainbow_ring(img, self.CENTER, 235, 220)
        self.paint_concentric_arcs(img, self.CENTER, MODULES, metrics,
                                    self.RING_RADII)
        self.paint_pod_cluster(img, MODULES, self.CENTER, radius=70, pod_size=40)
        self.paint_central_button(img, self.CENTER, size=44)
        return img

    # Round-only additional view modes (called by fb_dashboard.py's main
    # loop when the user long-presses center → radial menu → terminal/flash/auth).
    def layout_terminal(self, term_state) -> Image.Image:
        # Delegates to the existing draw_terminal() helper for now;
        # extracted into a method to give the main loop a class-based API.
        from fb_dashboard import draw_terminal
        return draw_terminal(term_state)

    def layout_flash(self, flash_state) -> Image.Image:
        from fb_dashboard import draw_flash_progress
        return draw_flash_progress(flash_state)

    def layout_auth(self, auth_state) -> Image.Image:
        from fb_dashboard import draw_auth_mode
        return draw_auth_mode(auth_state)
```

- [ ] **Step 4: Run tests to verify pass**

```bash
cd remote-ui/round && PYTHONPATH=../common/python python3 -m pytest tests/test_round_dashboard.py -v
```

Expected: `4 passed`.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/round_dashboard.py \
        remote-ui/round/tests/test_round_dashboard.py
git commit -m "feat(round): RoundDashboard via secubox_common (ref #135)"
```

---

## Task 18: Refactor fb_dashboard.py to delegate to RoundDashboard

**Files:**
- Modify: `remote-ui/round/fb_dashboard.py` (heavy refactor — replace inline `draw_dashboard()` body with `RoundDashboard.layout(metrics)`)

- [ ] **Step 1: Read the current draw_dashboard() function**

```bash
sed -n '/^def draw_dashboard/,/^def get_fb_info/p' remote-ui/round/fb_dashboard.py | head -60
```

Capture the function for context — its parameters are `(metrics, mode='SIM', host='', device_name='')`.

- [ ] **Step 2: Replace the body of draw_dashboard with a delegation**

Edit `remote-ui/round/fb_dashboard.py` — replace the entire `def draw_dashboard(metrics, mode='SIM', host='', device_name=''):` function body with:

```python
def draw_dashboard(metrics, mode='SIM', host='', device_name=''):
    """Render the main dashboard view via RoundDashboard.

    Mode/host/device_name are passed through to the dashboard via the
    metrics dict (the canvas reads them under the keys "_mode", "_host",
    "_device_name") — keeps the call-site backwards-compatible.
    """
    from round_dashboard import RoundDashboard
    rd = RoundDashboard()
    extended = dict(metrics)
    extended.setdefault("_mode", mode)
    extended.setdefault("_host", host)
    extended.setdefault("_device_name", device_name)
    return rd.layout(extended)
```

- [ ] **Step 3: Remove now-dead helper code in fb_dashboard.py**

Inside `fb_dashboard.py`, the following module-level helpers are now unused by the dashboard path (they were inlined into the old `draw_dashboard()`):
- `load_module_icon` — replaced by `secubox_common.icons.load_module_icon`. **Delete this function.**
- `ICONS_DIR`, `_icon_cache` — same. **Delete.**

Update any remaining callers (the terminal / flash / auth `draw_*` functions still use Pillow primitives, leave them alone for this PR; they'll be migrated in a followup that's tracked separately).

- [ ] **Step 4: Run round/ tests**

```bash
cd remote-ui/round && PYTHONPATH=../common/python python3 -m pytest tests/ -v
```

Expected: all tests pass. Pre-existing tests in `remote-ui/round/tests/test_touch_handler.py`, `test_failover.py`, etc. are unaffected by this refactor — they don't test `draw_dashboard()` directly.

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/fb_dashboard.py
git commit -m "refactor(round): fb_dashboard.draw_dashboard delegates to RoundDashboard (ref #135)"
```

---

## Task 19: Build scripts ship secubox_common to /var/www/common/python/

**Files:**
- Modify: `remote-ui/round/build-eye-remote-image.sh`
- Modify: `remote-ui/square/build-eye-square-image.sh`

- [ ] **Step 1: Find where round/ already embeds common/**

```bash
grep -n "var/www/common\|COMMON_SRC" remote-ui/round/build-eye-remote-image.sh
```

Expected: a section near line 916-925 that does `mkdir -p $ROOT_MNT/var/www/common; cp -r "$COMMON_SRC/." "$ROOT_MNT/var/www/common/"`. Confirm it already copies `assets/icons` and other static.

- [ ] **Step 2: Add secubox_common.python check to that section**

Edit `remote-ui/round/build-eye-remote-image.sh` — locate the line that does `cp -r "$COMMON_SRC/." "$ROOT_MNT/var/www/common/"` and right after it, add:

```bash
# secubox_common Python package needs to be importable from a directory
# that's on sys.path. Ship at /var/www/common/python/ and put PYTHONPATH
# on the relevant systemd units (see Environment="PYTHONPATH=..." lines).
log "Embedded common/python/secubox_common/ at /var/www/common/python/secubox_common/"
test -d "$ROOT_MNT/var/www/common/python/secubox_common" || \
    { log "ERR: secubox_common not in /var/www/common/python — common/ source incomplete"; exit 2; }
```

- [ ] **Step 3: Apply the same check to square/'s build script**

Edit `remote-ui/square/build-eye-square-image.sh` — find where `cp -r "$REPO_ROOT/remote-ui/square/files/." "$ROOT_MNT/"` happens. Just below, add:

```bash
# Ship the shared secubox_common package.
log "Embedding remote-ui/common/python at /var/www/common/python/..."
mkdir -p "$ROOT_MNT/var/www/common/python"
cp -r "$REPO_ROOT/remote-ui/common/python/." "$ROOT_MNT/var/www/common/python/"
test -d "$ROOT_MNT/var/www/common/python/secubox_common" || \
    { err "secubox_common not in /var/www/common/python — common/ source incomplete"; exit 2; }
```

- [ ] **Step 4: Commit**

```bash
git add remote-ui/round/build-eye-remote-image.sh \
        remote-ui/square/build-eye-square-image.sh
git commit -m "build(images): ship secubox_common to /var/www/common/python/ on both images (ref #135)"
```

---

## Task 20: systemd units add PYTHONPATH

**Files:**
- Modify: `remote-ui/round/files/etc/systemd/system/secubox-fb-dashboard.service` (or wherever the round kiosk service is)
- Modify: `remote-ui/square/files/etc/systemd/system/secubox-square-kiosk.service`

- [ ] **Step 1: Find the round/ kiosk service file**

```bash
grep -rln "ExecStart.*fb_dashboard\|ExecStart.*secubox.*dashboard" remote-ui/round/files/etc/systemd/system/
```

Note the file name(s) returned — call it `<round-unit>`.

- [ ] **Step 2: Add Environment=PYTHONPATH to round/ unit**

In `remote-ui/round/files/etc/systemd/system/<round-unit>` under `[Service]`, add:

```
Environment="PYTHONPATH=/var/www/common/python"
```

(Add as a new line; no replacement.)

- [ ] **Step 3: Add Environment=PYTHONPATH to square/ kiosk unit**

In `remote-ui/square/files/etc/systemd/system/secubox-square-kiosk.service` under `[Service]`, add:

```
Environment="PYTHONPATH=/var/www/common/python"
```

- [ ] **Step 4: Commit**

```bash
git add remote-ui/round/files/etc/systemd/system/<round-unit> \
        remote-ui/square/files/etc/systemd/system/secubox-square-kiosk.service
git commit -m "build(systemd): PYTHONPATH=/var/www/common/python for both kiosks (ref #135)"
```

---

## Task 21: Full test suite sweep

**Files:** — (no files modified; running existing tests)

- [ ] **Step 1: Run secubox_common tests**

```bash
cd remote-ui/common/python && python3 -m pytest -v
```

Expected: ~30 tests pass.

- [ ] **Step 2: Run square/ kiosk tests**

```bash
cd packages/secubox-eye-square/kiosk && PYTHONPATH=../../../remote-ui/common/python python3 -m pytest tests/ -v
```

Expected: ~75-80 tests pass.

- [ ] **Step 3: Run round/ tests**

```bash
cd remote-ui/round && PYTHONPATH=../common/python python3 -m pytest tests/ -v
```

Expected: existing round/ tests pass + new `test_round_dashboard.py` passes.

- [ ] **Step 4: If anything fails, fix and re-run before moving on**

Treat the test run as one atomic gate. If a regression surfaces, fix in this task before continuing to the hardware bench.

- [ ] **Step 5: Commit test fixes if any**

```bash
git add <changed files>
git commit -m "fix(test): post-sweep regression fixes (ref #135)"
```

(If nothing to commit, skip.)

---

## Task 22: Build images locally + hardware bench

**Files:** — (build artifacts, not committed)

This task is gated on hardware availability and is **manual**. Steps are the bench protocol.

- [ ] **Step 1: Build the square/ image**

```bash
cd remote-ui/square
sudo ./build-eye-square-image.sh -o /tmp 2>&1 | tee /tmp/square-build.log
```

Expected output ends with `Built: /tmp/secubox-eye-square_0.2.0_arm64.img.xz`.

- [ ] **Step 2: Build the round/ image via CI**

Push the branch — `build-eye-remote.yml` runs automatically. Wait for `gh run watch` to return green.

```bash
gh run list --workflow build-eye-remote.yml --branch feature/135-converged-dashboard --limit 1 --json databaseId,status,conclusion --jq '.[0]'
```

When `conclusion: SUCCESS`, download the artifact:

```bash
gh run download <id> --name secubox-eye-remote-2.2.1 -D /tmp/round-image/
```

- [ ] **Step 3: Flash + boot the square/ image on a Pi 4B**

User pops uSD into laptop. Flash:

```bash
sudo bash -c 'xzcat /tmp/secubox-eye-square_0.2.0_arm64.img.xz | dd of=/dev/mmcblk0 bs=4M status=progress conv=fsync'
```

User pops uSD into Pi 4B + 7" DSI. Boot. Verify:
- Black background, rainbow ring outer, 6 distinct module pods with **icons** (not letters) clustered near center, central hollow white circle.
- Right panel shows ALERTS / DETAIL / CON / CTL tabs; ALERTS highlighted by default.
- Touch on tab bar switches tabs.
- **USB mouse plugged into the Pi 4B**: cursor sprite appears when moving the mouse, hides after 3 s of idle. Mouse click on a tab switches it.

- [ ] **Step 4: Boot the same uSD on a Pi 400 + HDMI monitor**

User pops the uSD from the Pi 4B into a Pi 400 (USB-C power, HDMI to monitor, USB mouse). Boot. Verify:
- 800×480 dashboard appears center-padded with black letterbox on the larger HDMI fb (e.g., 1920×1080).
- Mouse clicks on tabs work.

- [ ] **Step 5: Flash + boot the round/ image on a Pi Zero W**

User uses a separate uSD. Flash + insert into Pi Zero W + HyperPixel 2.1 round. Boot. Verify:
- Rainbow ring dashboard renders.
- **Module pods show icons, not single-letter placeholders** (Task 5 fix — closes the icon-loading bug).
- Long-press center still opens the radial mode menu (terminal/flash/auth views still navigable).

- [ ] **Step 6: Document the bench results**

Append a comment on issue #135 with the three boot results + photos.

---

## Task 23: Push branch, open PR

**Files:** — (no files; git operations)

- [ ] **Step 1: Verify worktree is clean and on the right branch**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/135-converged-dashboard
git status
git log --oneline origin/master..HEAD
```

Expected: working tree clean; commit history shows tasks 2-21 (and 19-20).

- [ ] **Step 2: Push branch**

```bash
git push -u origin feature/135-converged-dashboard
```

- [ ] **Step 3: Use agent-worktree.sh finish to open the PR**

```bash
./scripts/agent-worktree.sh finish
```

Expected: prints the PR URL.

- [ ] **Step 4: Add bench-result photos / notes to the PR description**

```bash
gh pr edit <#> --add-label "enhancement,eye-remote"
gh pr comment <#> --body "Hardware bench results: <paste Task 22 photos / notes here>"
```

- [ ] **Step 5: Hand off for review**

Tell user the PR URL. Stop. Do not merge.

---

## Self-review (writing-plans inline)

**Spec coverage check** — every spec section mapped to tasks:

- Spec §1 Scope & non-goals → Tasks 1 (worktree), all subsequent tasks satisfy scope.
- Spec §2 Architecture → Tasks 2-10 build the canvas + theme + modules + icons in `secubox_common`; Tasks 11 and 17 build the subclasses; Task 18 ports round/.
- Spec §3 Components (signatures) → Tasks 3, 4, 5, 6-10, 11, 12, 13, 17, 18 all line up with the listed components.
- Spec §4 Data flow → Task 15 puts the event loop together for square/; Task 18 keeps round/'s loop, only swaps the renderer.
- Spec §5 Error handling → Tier 1 (fatal at startup) baked into Task 15's `if cannot open fb: return 1`. Tier 2 (icons missing, font fallback, no input device) baked into Tasks 5, 3, 12. Tier 3 (transient) baked into Task 12 (USB unplug) and the helper client wrapper unchanged.
- Spec §6 Testing → Tasks 3, 4, 5, 6-10, 11, 12, 13, 16, 17, 21.
- Spec §7 Migration & rollout → Tasks 1 (worktree), 19 (build script), 20 (systemd), 22 (hardware bench), 23 (PR).
- Spec §8 Out-of-scope followups → Honoured (not in this plan).

**Placeholder scan** — searched for "TBD" / "TODO" / "implement later" / "similar to" — none found. The only deferred work in Task 18 ("layout_terminal/_flash/_auth delegate to existing helpers; migrated in a followup") is **explicitly out-of-scope per spec §1**, not a placeholder.

**Type consistency** — method names match: `paint_rainbow_ring`, `paint_concentric_arcs`, `paint_pod_cluster`, `paint_central_button`, `paint_alert_ribbon`, `layout`, `layout_terminal`, `layout_flash`, `layout_auth` are spelled identically across spec §3 and Tasks 3-13, 17. Attribute names match: `cursor_xy`, `cursor_visible`, `AUTO_HIDE_S`, `InputEvent("tap"|"motion", x, y)` consistent across Tasks 12 and 15. Module name `secubox_common` consistent throughout.
