<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Eye Remote — Converged Dashboard (round/ + square/) + Pointer Input

**Tracking issue:** [#135](https://github.com/CyberMind-FR/secubox-deb/issues/135)
**Date:** 2026-05-14
**Author:** Gerald KERMA · CyberMind
**Status:** Draft, pending user review
**Predecessors:**
- `remote-ui/round/fb_dashboard.py` (Pi Zero W Pillow+fb dashboard, **refactored in this work**)
- `packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/` (Pi 4B/400 Phase 3 kiosk, **refactored in this work**)
- `remote-ui/common/` (Phase 1 JS/CSS/icons/shell extraction, **adds python/** sibling)
- PR [#134](https://github.com/CyberMind-FR/secubox-deb/pull/134) — square/ Phase 3 four-bug fix, expected to land before this work starts

---

## 1. Scope & non-goals

### Why converge

Three working kiosks today, three different code paths:

- Round/ Pi Zero W: monolithic 1367-line `fb_dashboard.py` with 4 view modes (dashboard / terminal / flash / auth).
- Square/ Pi 4B/400: 16-module Python package with one ring dashboard + a 4-tab right panel.
- Common/: JS/CSS/icons/shell only (Phase 1). No Python.

Validated live this session that both kiosks render correctly on hardware — but they're visually divergent. Operator review (Pi Zero W round next to Pi 4B + 7" DSI) flagged square/'s aesthetic as the odd one out: square/ uses widely-spaced concentric rings with full-text pod labels at the perimeter, where round/ uses a rainbow gradient outer ring, tight pod cluster near center, central home button.

Operator wants Pi 4B/400 to **look like** round/ while keeping its tab bar functionality. Also wants the Pi 4B/400 kiosk operable via **mouse + touchpad**, not just touch.

A small bug surfaced during round/'s validation: `load_module_icon` resolves `ICONS_DIR = SCRIPT_DIR/assets/icons/`, which on the deployed image points to `remote-ui/round/assets/icons/` — a directory containing clock/sleep/wifi icons but **no module icons**. The module icons (auth/wall/boot/mind/root/mesh × 22/48/96/128 px) exist only in `remote-ui/common/assets/icons/`, deployed to `/var/www/common/assets/icons/`. So round/ falls back to first-letter placeholders ("M F B W V" instead of icons). The convergence fixes this by construction.

### In scope

1. Extract drawing primitives + theme + module table + icon loader into `remote-ui/common/python/`.
2. Repaint Pi 4B/400 dashboard area (left 480×480) with round/'s aesthetic via OO layout classes (`DashboardCanvas` base, `RoundDashboard` and `SquareDashboard` subclasses).
3. Keep square/'s tab bar — only the central 480×480 changes; the right 320×480 panel and its 4 tabs (ALERTS / DETAIL / CON / CTL) stay.
4. Add pointer (mouse + touchpad) input on Pi 4B/400, fully equivalent to touch, with auto-hiding cursor sprite (visible only when motion in last 3 s).
5. Refactor round/ in the same PR — round/ retains its 4 view modes but imports drawing primitives from `common/python/`. Big-bang convergence, both form factors land at once.
6. Fix `load_module_icon` path resolution — naturally resolved by `common/python/icons.py` knowing about `/var/www/common/assets/icons/`.

### Non-goals

- New tab content or new view modes.
- Round/ pointer input (Pi Zero W doesn't have a mouse).
- Touchscreen recalibration.
- CI workflow for square/ image builds (separate followup).
- Performance changes — current Pi 4B 30 fps budget is preserved.

---

## 2. Architecture

### Directory layout post-merge

```
remote-ui/common/python/
└── secubox_common/          # importable namespace
    ├── __init__.py
    ├── theme.py     # color constants + DEFAULT_FONT loader
    ├── modules.py   # Module dataclass + canonical 6 MODULES (Hamiltonian order)
    ├── icons.py     # load_module_icon resolves /var/www/common/assets/icons/
    └── canvas.py    # class DashboardCanvas — drawing primitives

remote-ui/round/
└── round_dashboard.py        # class RoundDashboard(DashboardCanvas)
                              # + layout_terminal / layout_flash / layout_auth
                              # + main loop

packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/
├── square_dashboard.py       # class SquareDashboard(DashboardCanvas)
│                             # composes left 480×480 + right_panel.draw(...)
├── pointer_input.py          # NEW — BTN_LEFT + REL/ABS X/Y, cursor auto-hide
├── cursor.py                 # NEW — arrow sprite, drawn post-composition
├── right_panel.py            # unchanged — tab bar + 4 tab views
├── framebuffer.py            # unchanged from PR #134 (numpy RGB565 + size auto-detect)
├── touch_input.py            # unchanged
└── __main__.py               # event loop: touch + pointer poll → dispatch
                              # → SquareDashboard.layout(metrics) → cursor overlay → blit
```

### Class hierarchy

`DashboardCanvas` is the OO seam. It owns the drawing primitives (stateless from the canvas's POV — pure functions of input args), takes a Pillow `Image` to paint into, and reads from `theme` / `modules` / `icons`. Subclasses override `layout(metrics)` to compose primitives for their form factor.

- `RoundDashboard.layout(metrics)` → 480×480 round canvas: rainbow ring, concentric arcs (6 modules), pod cluster (6 small pods near center), central home button.
- `RoundDashboard.layout_terminal(state)` / `layout_flash(state)` / `layout_auth(state)` — round-only view modes, not part of base class.
- `SquareDashboard.layout(metrics)` → 800×480 landscape canvas: paints the 480×480 round-style dashboard into the left region using the same primitives, then composes the right panel (320×480 from `right_panel.draw(...)`).

---

## 3. Components (signatures)

### `remote-ui/common/python/theme.py`

```python
COSMOS_BLACK = (0x08, 0x08, 0x08)
GOLD_HERMETIC = (0xC9, 0xA8, 0x4C)
CINNABAR = (0xE6, 0x39, 0x46)
MATRIX_GREEN = (0x00, 0xFF, 0x41)
CYBER_CYAN = (0x00, 0xD4, 0xFF)
VOID_PURPLE = (0x6E, 0x40, 0xC9)
TEXT_PRIMARY = (0xCC, 0xCC, 0xCC)
TEXT_MUTED = (0x4A, 0x4A, 0x4A)

# Module colors (carried over from square/'s theme.py)
AUTH = (0xC0, 0x4E, 0x24)
WALL = (0x9A, 0x60, 0x10)
BOOT = (0x80, 0x30, 0x18)
MIND = (0x3D, 0x35, 0xA0)
ROOT = (0x0A, 0x58, 0x40)
MESH = (0x10, 0x4A, 0x88)

SEVERITY = {"info": CYBER_CYAN, "warn": GOLD_HERMETIC, "crit": CINNABAR}

def load_default_font(size: int = 12) -> ImageFont.FreeTypeFont:
    """DejaVuSans from fonts-dejavu-core; falls back to load_default()."""
```

### `remote-ui/common/python/modules.py`

```python
@dataclass(frozen=True)
class Module:
    name: str           # "AUTH"
    colour: tuple[int, int, int]
    icon_name: str      # "auth" (passed to icons.load_module_icon)
    metric: str         # "cpu_percent"
    extract: Callable[[dict], float]   # 0..1 normaliser

MODULES: list[Module] = [
    Module("AUTH", theme.AUTH, "auth", "cpu_percent",  lambda s: clamp(s.get("cpu_percent", 0) / 100)),
    Module("WALL", theme.WALL, "wall", "mem_percent",  lambda s: clamp(s.get("mem_percent", 0) / 100)),
    Module("BOOT", theme.BOOT, "boot", "disk_percent", lambda s: clamp(s.get("disk_percent", 0) / 100)),
    Module("MIND", theme.MIND, "mind", "load_avg_1",   lambda s: clamp(s.get("load_avg_1", 0) / 4)),
    Module("ROOT", theme.ROOT, "root", "cpu_temp",     lambda s: clamp((s.get("cpu_temp", 35) - 35) / 50)),
    Module("MESH", theme.MESH, "mesh", "wifi_rssi",    lambda s: clamp((s.get("wifi_rssi", -90) + 90) / 70)),
]
```

### `remote-ui/common/python/icons.py`

```python
ICON_SEARCH_PATHS = [
    "/var/www/common/assets/icons",                          # deployed image
    Path(__file__).parents[2] / "common" / "assets" / "icons", # dev checkout
]

def load_module_icon(name: str, size: int = 48) -> Image.Image | None:
    """Resolve <name>-<size>.png across search paths. LRU-cached. None if missing."""
```

### `remote-ui/common/python/canvas.py`

```python
class DashboardCanvas:
    """Drawing primitives — subclasses define layout()."""

    def paint_background(self, img: Image.Image, colour=theme.COSMOS_BLACK) -> None: ...

    def paint_rainbow_ring(self, img: Image.Image, center: tuple[int, int],
                            radius_outer: int, radius_inner: int,
                            stops: int = 256) -> None:
        """Annular rainbow gradient (HSV hue rotation across stops)."""

    def paint_concentric_arcs(self, img: Image.Image, center: tuple[int, int],
                              modules: list[Module], metrics: dict,
                              radii: list[int]) -> None:
        """6 arcs, one per module; pct from module.extract(metrics)."""

    def paint_pod_cluster(self, img: Image.Image, modules: list[Module],
                          center: tuple[int, int], radius: int,
                          pod_size: int = 48) -> None:
        """6 pods arranged at angles 60° apart on a circle of given radius
        around center. Each pod is a filled circle of module.colour with
        the icon (loaded via icons.load_module_icon at the appropriate size)
        composited on top; if the icon is missing, falls back to drawing
        the first letter of module.name in white centered on the pod."""

    def paint_central_button(self, img: Image.Image, center: tuple[int, int],
                             size: int, label: str = "") -> None:
        """Hollow white circle, optional label below."""

    def paint_alert_ribbon(self, img: Image.Image, region_y: int,
                           text: str, severity: str) -> None: ...

    def layout(self, metrics: dict) -> Image.Image:
        raise NotImplementedError
```

### `remote-ui/round/round_dashboard.py`

```python
class RoundDashboard(DashboardCanvas):
    SIZE = (480, 480)
    CENTER = (240, 240)

    def layout(self, metrics: dict) -> Image.Image:
        img = Image.new("RGBA", self.SIZE, theme.COSMOS_BLACK + (255,))
        self.paint_rainbow_ring(img, self.CENTER, 235, 220)
        self.paint_concentric_arcs(img, self.CENTER, MODULES, metrics,
                                    radii=[200, 185, 170, 155, 140, 125])
        self.paint_pod_cluster(img, MODULES, self.CENTER, radius=70, pod_size=40)
        self.paint_central_button(img, self.CENTER, size=44)
        return img

    def layout_terminal(self, term_state) -> Image.Image: ...
    def layout_flash(self, flash_state) -> Image.Image: ...
    def layout_auth(self, auth_state) -> Image.Image: ...
```

### `packages/secubox-eye-square/.../square_dashboard.py`

```python
class SquareDashboard(DashboardCanvas):
    SIZE = (800, 480)
    DASHBOARD_REGION = (0, 0, 480, 480)
    PANEL_REGION = (480, 0, 800, 480)

    def __init__(self, right_panel):
        self.right_panel = right_panel

    def layout(self, metrics: dict) -> Image.Image:
        img = Image.new("RGBA", self.SIZE, theme.COSMOS_BLACK + (255,))
        dash = Image.new("RGBA", (480, 480), theme.COSMOS_BLACK + (255,))
        self.paint_rainbow_ring(dash, (240, 240), 235, 220)
        self.paint_concentric_arcs(dash, (240, 240), MODULES, metrics,
                                    radii=[200, 185, 170, 155, 140, 125])
        self.paint_pod_cluster(dash, MODULES, (240, 240), radius=70, pod_size=40)
        self.paint_central_button(dash, (240, 240), size=44)
        img.paste(dash, (0, 0))

        panel = Image.new("RGBA", (320, 480), theme.COSMOS_BLACK + (255,))
        self.right_panel.draw(panel)
        img.paste(panel, (480, 0))
        return img
```

### `packages/secubox-eye-square/.../pointer_input.py`

```python
@dataclass
class InputEvent:
    kind: str               # "tap" | "motion"
    x: int
    y: int


class PointerInput:
    """Wraps /dev/input/event* for mouse + touchpad.

    BTN_LEFT down → emit InputEvent("tap", cursor_xy)
    REL_X/Y      → accumulate cursor_xy, clamp to fb bounds, emit Motion
    ABS_X/Y      → set cursor_xy directly (touchpad), emit Motion
    BTN_TOUCH    → emit Tap at cursor_xy (touchpad)
    """

    AUTO_HIDE_S = 3.0

    def __init__(self, fb_size: tuple[int, int]):
        self.fb_w, self.fb_h = fb_size
        self.cursor_xy = (fb_size[0] // 2, fb_size[1] // 2)
        self._last_motion = 0.0
        self._devices = self._discover_devices()

    def poll(self) -> list[InputEvent]:
        """Non-blocking. Returns whatever's queued. Logs and re-opens
        devices that raise OSError (USB unplug). Rate-limited 30s."""

    @property
    def cursor_visible(self) -> bool:
        return (time.time() - self._last_motion) < self.AUTO_HIDE_S
```

### `packages/secubox-eye-square/.../cursor.py`

```python
def draw_cursor(img: Image.Image, x: int, y: int) -> None:
    """12×16 arrow sprite, GOLD_HERMETIC outline + black fill.
    Drawn post-composition so it's always on top."""
```

---

## 4. Data flow

```
Square/ Pi 4B/400 — single process, 30 fps event loop

Per-tick (every ~33 ms):

  1. INPUT POLL (non-blocking)
       TouchInput.poll()    → list[Tap(x, y)]
       PointerInput.poll()  → list[Motion(x, y), Tap(x, y)]

  2. TAP DISPATCH
       For each Tap(x, y):
           if x >= 480:  → right_panel.handle_tap(x - 480, y)   # tab bar
           else:          → square_dashboard.handle_tap(x, y)    # pod cluster

  3. METRICS REFRESH (every 2 s, not every tick)
       metrics = helper_client.fetch_metrics()
       if metrics is None: metrics = sim.step().to_dict()

  4. RENDER (every tick)
       full = square_dashboard.layout(metrics)
       if pointer_input.cursor_visible:
           cursor.draw_cursor(full, *pointer_input.cursor_xy)

  5. BLIT
       framebuffer.blit(full)   # pads to actual fb size, RGB565 numpy pack
```

Round/'s event loop has the same shape, with `TouchInput` only (no PointerInput), and single-view → mode dispatch (long-press center → `layout_terminal` / `_flash` / `_auth`).

### Decision points implicit in this flow

- **No partial repaint.** Each tick the canvas is rebuilt from scratch (`Image.new(...)`). Simple, predictable, ~5-10 ms numpy pack + Pillow draws on Pi 4B fit the 33 ms budget.
- **Metrics cache outlives render.** Drawing reads from `metrics` dict that updates every 2 s, decoupled from frame rate. No I/O on the hot path.
- **Input is polled, not interrupt-driven.** evdev devices opened non-blocking; `poll()` returns immediately. No threads, no asyncio.
- **Cursor draws after dashboard.** Cursor is overlaid post-composition so it's always on top. Auto-hide is internal state (cleared 3 s after last motion).

---

## 5. Error handling

Three tiers. Principle: log and fall back; never crash the kiosk.

### Tier 1 — Fatal at startup (log.error + exit 1, systemd restarts after 3 s)

- `/dev/fb0` cannot be opened (no display).
- Pillow / numpy / evdev import error (build-time bug).

### Tier 2 — Recoverable at startup, degraded mode logged at WARNING

- `/var/www/common/assets/icons/<name>-<size>.png` missing → `load_module_icon` returns `None`, `paint_pod_cluster` falls back to colored circle + first-letter placeholder. Logged once per (name, size) miss.
- `DejaVuSans.ttf` missing → `theme.load_default_font` returns `ImageFont.load_default()` (latin-1 bitmap). Logged once; Unicode glyphs in `paint_*` calls are pre-sanitized to ASCII when this fallback is active.
- No `/dev/input/event*` matching touch device → `TouchInput.poll()` returns `[]` forever. Logged once. Same for `PointerInput` — square/ can run pointer-less.

### Tier 3 — Transient per-tick, rate-limited every 30 s

- `HelperClient` Unix socket connect refused → `metrics is None` → `sim.step()` provides fallback values.
- `helper_client.fetch_metrics()` timeout → cached last-good metrics (if within 10 s) else SIM.
- Pointer device disappears mid-session (USB unplug) → `PointerInput.poll()` catches `OSError`, marks device gone, attempts re-open every 30 s. Cursor auto-hides on next motion timeout.
- Single `paint_*` raises (bad metrics value, out-of-bounds coord) → caught at `layout()` level, that frame falls back to last-good frame + one-line "render error" overlay. Next tick tries again with fresh metrics.

### Deliberately NOT handled

- Disk full when writing logs — kiosk doesn't write log files, just stderr → journald.
- AppArmor denial — install-time concern.
- OOM kill — `MemoryMax=128M` is on the unit; numpy packs of 800×480 use ~3 MB. Anything else is a leak, crash-restart is correct.

---

## 6. Testing

### Unit tests in `remote-ui/common/python/secubox_common/tests/` (NEW dir, ~30 tests)

- `test_theme.py` — palette tuples are 3-channel RGB, font loader returns usable font, smoke render of `○ ● ▶ ⚠` (regression for the Unicode crash fixed in PR #134).
- `test_modules.py` — MODULES has exactly 6 entries in Hamiltonian order, each `extract` returns 0..1.
- `test_icons.py` — `load_module_icon` resolves `/var/www/common/assets/icons/` first, falls back to dev checkout, returns `None` for missing icon. Cache hit returns same object.
- `test_canvas.py` — each primitive called against a 480×480 fake Image without raising, plus pixel-level smoke (rainbow_ring covers correct radial band via pixel sampling).

### Square/ kiosk tests (existing 71 + new — target 75-80 total)

- `test_framebuffer.py` (10 tests) — untouched. Already validates bpp + size detect, RGB565 numpy pack, center-pad (from PR #134).
- `test_theme.py` (3 tests) — keep, expand Unicode smoke.
- `test_ring_dashboard.py` → **rename → `test_square_dashboard.py`**, rewrite for `SquareDashboard(DashboardCanvas)`. Asserts layout composes left dashboard + right panel via common primitives.
- `test_pointer_input.py` (NEW, ~8 tests) — mock evdev `read_loop()`, feed synthetic BTN_LEFT + REL/ABS X/Y, assert correct Tap/Motion events, cursor auto-hides after 3 s, USB-unplug OSError doesn't raise.
- `test_cursor.py` (NEW, ~3 tests) — sprite renders at (x, y), no-op when invisible, no out-of-bounds.
- Tab tests (`tabs/*`) unchanged.

### Round/ tests (refactor existing — no net loss of surface)

- `test_touch_handler.py`, `test_failover.py`, `test_mode_dashboard.py`, etc. — rewrite to test `RoundDashboard` subclass calling common primitives.
- New `test_round_dashboard.py` validating the 4 view modes compose without raising.

### Cross-form-factor invariant tests (NEW)

- `test_common_api_stable.py` — assert both `RoundDashboard` and `SquareDashboard` import the same `DashboardCanvas` and that the canonical primitives have the documented signatures. Catches API drift in either direction.

### Hardware bench gates (manual, before merge)

- **Pi 4B + 7" DSI 800×480**: same image, kiosk renders with new round-like look on left, tab bar on right; tab clicks via touch AND via USB mouse work.
- **Pi 400 + HDMI 1920×1080**: same image, center-padded, same checks via USB mouse.
- **Pi Zero W round/**: refactored round/ image renders the rainbow ring dashboard with actual module icons (NOT placeholder letters) — fixes the bug surfaced this session.

### CI

- `build-eye-remote.yml` runs on round/ changes — confirms refactored round/ image still builds clean.
- No new CI job needed for square/ image (still no workflow — separate followup tracked under #127 area).

### Target counts post-merge

- `common/python/secubox_common/tests/`: ~30
- `square/ kiosk tests/`: 75-80 (71 base + new pointer/cursor − ring_dashboard rename net-neutral)
- `round/ tests`: roughly equivalent to current
- All green = release-ready.

---

## 7. Migration & rollout

### Order of work

1. Add `remote-ui/common/python/` with new modules + tests.
2. Refactor square/ kiosk to use `common/python/` (rename `ring_dashboard.py` → `square_dashboard.py`, update `__main__.py`, add `pointer_input.py` + `cursor.py`).
3. Refactor round/ `fb_dashboard.py` to use `common/python/` (extract drawing into `RoundDashboard` subclass, keep view-mode helpers, keep main loop).
4. Update both build scripts (`build-eye-remote-image.sh` for round/, `build-eye-square-image.sh` for square/) to install `python3-numpy` if not already present (square/ already adds it via PR #134) and to ship `remote-ui/common/python/` to `/var/www/common/python/` on the image. Both kiosk systemd units get `Environment="PYTHONPATH=/var/www/common/python"` so `from secubox_common import …` resolves at runtime. No need for a separate `python3-secubox-common` Debian package — keeps the source-on-disk fast-iteration model that round/ and square/ already use.
5. Hardware bench all three boards.
6. Single PR merges all of the above.

### Why big-bang vs staged

User explicitly chose "Extract → both consume in same PR" over "square/ first, round/ later". Risk: round/ regression. Mitigation: dedicated Pi Zero W bench gate before merge + visual side-by-side comparison with the existing production round/ image. This session captured photos of the working round/ kiosk that serve as visual reference.

### Rollback plan

If round/ regression is observed post-merge, revert the whole PR — round/ and square/ converge or diverge together; we don't ship a half-converged state.

---

## 8. Out-of-scope followups

- Add `python3-numpy` + `fonts-dejavu-core` + tmpfiles.d to source on the round/ build path (mirrors PR #134's square/ work). Round/ already has DejaVu via its own apt-install path, so check before duplicating.
- Square/ image CI workflow (`build-eye-square-image.yml`) — track separately.
- New view modes (e.g., terminal access on square/, alerts list on round/) — separate brainstorm if/when needed.
- Touchscreen recalibration tooling.
