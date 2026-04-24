# Eye Remote Touchscreen Controller Design

> **SecuBox Eye Remote** — Touch-accessible configuration panel for controlling SecuBox via RPi Zero W + HyperPixel 2.1 Round display

**Author:** Gérald Kerma (CyberMind)
**Date:** 2026-04-24
**Status:** Approved for Implementation

---

## Overview

The Eye Remote Touchscreen Controller transforms the circular HyperPixel 2.1 Round display into an interactive configuration interface. Users navigate a radial menu system using touch gestures to access both local Pi Zero settings and remote SecuBox device controls.

### Goals

1. **Intuitive radial navigation** — Leverage the circular display for natural pie-slice menus
2. **Dual-scope control** — Manage both local Eye Remote and connected SecuBox devices
3. **Responsive feedback** — Visual highlights and haptic-style animations for touch events
4. **Graceful degradation** — Handle network disconnections without crashes

### Constraints

- 480×480 circular display (HyperPixel 2.1 Round)
- Single-touch capacitive touchscreen (no multi-touch)
- USB gadget networking (10.55.0.0/30)
- Framebuffer rendering via Pillow
- Python 3.11+ on Raspberry Pi Zero W

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Eye Remote Agent                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ TouchHandler │→ │MenuNavigator │→ │  RadialRenderer  │   │
│  │   (evdev)    │  │  (state)     │  │  (framebuffer)   │   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│         ↑                 ↓                    ↓             │
│    Touch Events      Menu Actions       Display Output       │
│                           │                                  │
│                    ┌──────┴───────┐                         │
│                    │ActionExecutor│                          │
│                    └──────┬───────┘                         │
│              ┌────────────┼────────────┐                    │
│              ↓            ↓            ↓                    │
│         LocalAPI    SecuBoxClient   SystemCmd               │
│        (settings)     (REST)        (shell)                 │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

#### 1. TouchHandler (existing, extend)
- **File:** `touch_handler.py`
- **Role:** Translate raw evdev events into semantic gestures
- **Gestures:**
  - Tap → Select current slice
  - Long press center → Enter/exit menu mode
  - Swipe clockwise → Navigate forward through slices
  - Swipe counter-clockwise → Navigate backward
  - Long press slice → Quick action (context-dependent)
  - 3-finger tap → Emergency exit to dashboard

#### 2. MenuNavigator (new)
- **File:** `menu_navigator.py`
- **Role:** Manage menu state and navigation stack
- **State:**
  ```python
  @dataclass
  class MenuState:
      mode: Literal['dashboard', 'menu']
      current_menu: str           # e.g., "root", "DEVICES", "SECUBOX.STATUS"
      selected_index: int         # Currently highlighted slice (0-5)
      breadcrumb: list[str]       # Navigation path for back
      animation_frame: int        # For transitions
  ```

#### 3. RadialRenderer (new)
- **File:** `radial_renderer.py`
- **Role:** Draw radial menus to framebuffer
- **Features:**
  - 6-slice pie layout (60° each)
  - Center button for back/exit
  - Slice highlighting on selection
  - Icon + label per slice
  - Smooth rotation animations

#### 4. ActionExecutor (new)
- **File:** `action_executor.py`
- **Role:** Execute menu actions
- **Handlers:**
  - `LocalAPI` — Local Pi Zero settings (brightness, WiFi, etc.)
  - `SecuBoxClient` — REST calls to SecuBox API
  - `SystemCmd` — Shell commands (reboot, shutdown)

---

## Menu Structure

### Root Menu (6 slices)

```
        [DEVICES]
           ↑
  [EXIT] ←─●─→ [SECUBOX]
           ↓
      [SECURITY]
    ↙           ↘
[NETWORK]    [LOCAL]
```

| Slice | Icon | Label | Description |
|-------|------|-------|-------------|
| 0 (top) | `devices-48.png` | DEVICES | Connected SecuBox devices |
| 1 (top-right) | `secubox-48.png` | SECUBOX | SecuBox status & control |
| 2 (bottom-right) | `local-48.png` | LOCAL | Local Eye Remote settings |
| 3 (bottom) | `network-48.png` | NETWORK | Network configuration |
| 4 (bottom-left) | `security-48.png` | SECURITY | Security modules |
| 5 (top-left) | `exit-48.png` | EXIT | Return to dashboard / shutdown |

### Sub-Menus

#### DEVICES (slice 0)
```python
DEVICES_MENU = [
    MenuItem("SCAN", icon="scan", action="devices.scan"),
    MenuItem("SECUBOX-1", icon="connected", action="devices.select:secubox-1"),
    MenuItem("SECUBOX-2", icon="offline", action="devices.select:secubox-2"),
    MenuItem("ADD NEW", icon="plus", action="devices.pair"),
    MenuItem("FORGET", icon="trash", action="devices.forget"),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

#### SECUBOX (slice 1) — Requires device selected
```python
SECUBOX_MENU = [
    MenuItem("STATUS", icon="status", submenu="SECUBOX.STATUS"),
    MenuItem("MODULES", icon="modules", submenu="SECUBOX.MODULES"),
    MenuItem("LOGS", icon="logs", action="secubox.logs"),
    MenuItem("RESTART", icon="restart", action="secubox.restart", confirm=True),
    MenuItem("UPDATE", icon="update", action="secubox.update"),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

##### SECUBOX.STATUS
```python
SECUBOX_STATUS_MENU = [
    MenuItem("CPU: {cpu}%", icon="cpu", action="secubox.detail:cpu"),
    MenuItem("MEM: {mem}%", icon="memory", action="secubox.detail:mem"),
    MenuItem("DISK: {disk}%", icon="disk", action="secubox.detail:disk"),
    MenuItem("TEMP: {temp}°C", icon="temp", action="secubox.detail:temp"),
    MenuItem("UPTIME", icon="clock", action="secubox.detail:uptime"),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

##### SECUBOX.MODULES
```python
SECUBOX_MODULES_MENU = [
    MenuItem("CROWDSEC", icon="crowdsec", submenu="SECUBOX.MODULES.CROWDSEC"),
    MenuItem("WIREGUARD", icon="wireguard", submenu="SECUBOX.MODULES.WIREGUARD"),
    MenuItem("FIREWALL", icon="firewall", submenu="SECUBOX.MODULES.FIREWALL"),
    MenuItem("DPI", icon="dpi", submenu="SECUBOX.MODULES.DPI"),
    MenuItem("DNS", icon="dns", submenu="SECUBOX.MODULES.DNS"),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

#### LOCAL (slice 2)
```python
LOCAL_MENU = [
    MenuItem("DISPLAY", icon="display", submenu="LOCAL.DISPLAY"),
    MenuItem("NETWORK", icon="network", submenu="LOCAL.NETWORK"),
    MenuItem("SYSTEM", icon="system", submenu="LOCAL.SYSTEM"),
    MenuItem("ABOUT", icon="info", action="local.about"),
    MenuItem("LOGS", icon="logs", action="local.logs"),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

##### LOCAL.DISPLAY
```python
LOCAL_DISPLAY_MENU = [
    MenuItem("BRIGHTNESS", icon="brightness", action="local.brightness"),
    MenuItem("THEME", icon="theme", submenu="LOCAL.DISPLAY.THEME"),
    MenuItem("TIMEOUT", icon="timeout", action="local.timeout"),
    MenuItem("ROTATION", icon="rotate", action="local.rotation"),
    MenuItem("TEST", icon="test", action="local.display_test"),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

##### LOCAL.NETWORK
```python
LOCAL_NETWORK_MENU = [
    MenuItem("USB IP", icon="usb", action="local.usb_ip"),
    MenuItem("WIFI", icon="wifi", submenu="LOCAL.NETWORK.WIFI"),
    MenuItem("HOSTNAME", icon="hostname", action="local.hostname"),
    MenuItem("DNS", icon="dns", action="local.dns"),
    MenuItem("STATUS", icon="status", action="local.net_status"),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

#### NETWORK (slice 3)
```python
NETWORK_MENU = [
    MenuItem("INTERFACES", icon="interfaces", action="network.interfaces"),
    MenuItem("ROUTES", icon="routes", action="network.routes"),
    MenuItem("DNS", icon="dns", action="network.dns"),
    MenuItem("FIREWALL", icon="firewall", action="network.firewall"),
    MenuItem("TRAFFIC", icon="traffic", action="network.traffic"),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

#### SECURITY (slice 4)
```python
SECURITY_MENU = [
    MenuItem("ALERTS", icon="alert", action="security.alerts"),
    MenuItem("BANS", icon="ban", action="security.bans"),
    MenuItem("RULES", icon="rules", action="security.rules"),
    MenuItem("AUDIT", icon="audit", action="security.audit"),
    MenuItem("LOCKDOWN", icon="lock", action="security.lockdown", confirm=True),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

#### EXIT (slice 5)
```python
EXIT_MENU = [
    MenuItem("DASHBOARD", icon="dashboard", action="nav.dashboard"),
    MenuItem("SLEEP", icon="sleep", action="system.sleep"),
    MenuItem("REBOOT PI", icon="reboot", action="system.reboot", confirm=True),
    MenuItem("SHUTDOWN PI", icon="shutdown", action="system.shutdown", confirm=True),
    MenuItem("REBOOT BOX", icon="reboot", action="secubox.reboot", confirm=True),
    MenuItem("← BACK", icon="back", action="nav.back"),
]
```

---

## Interaction Design

### Gesture Detection

```python
# Slice detection from touch coordinates
def get_slice_from_touch(x: int, y: int) -> int | None:
    """
    Convert touch coordinates to slice index (0-5).
    Returns None if touch is in center zone.
    """
    cx, cy = 240, 240  # Display center
    dx, dy = x - cx, y - cy
    distance = math.sqrt(dx*dx + dy*dy)

    # Center zone (radius < 60px) → not a slice
    if distance < 60:
        return None

    # Outside visible circle → ignore
    if distance > 220:
        return None

    # Calculate angle (0° = top, clockwise)
    angle = math.degrees(math.atan2(dx, -dy))
    if angle < 0:
        angle += 360

    # Each slice is 60° wide, offset by 30° so slice 0 is centered at top
    slice_index = int((angle + 30) % 360 // 60)
    return slice_index
```

### State Transitions

```
┌──────────────────────────────────────────────────────────┐
│                    State Machine                          │
│                                                           │
│  [DASHBOARD] ──long press center──→ [ROOT_MENU]          │
│       ↑                                   │               │
│       │                              tap slice            │
│       │                                   ↓               │
│       │                            [SUB_MENU]             │
│       │                                   │               │
│       │                              tap slice            │
│       │                                   ↓               │
│       │                            [ACTION] or            │
│       │                            [DEEPER_MENU]          │
│       │                                   │               │
│       └──────── tap "BACK" or ────────────┘               │
│                 3-finger tap                              │
└──────────────────────────────────────────────────────────┘
```

### Visual Feedback

1. **Slice Highlight:** Selected slice pulses with brighter color
2. **Touch Ripple:** Brief radial animation from touch point
3. **Transition Animation:** Slices rotate in/out during navigation
4. **Loading Indicator:** Center spinner during async operations
5. **Confirmation Dialog:** Red/green slice overlay for confirm actions

### Long Press Actions

| Location | Duration | Action |
|----------|----------|--------|
| Center | 1.5s | Toggle menu mode ↔ dashboard |
| Any slice | 1.0s | Quick action (if defined) |
| Outside circle | 2.0s | Emergency reboot (with confirmation) |

---

## Data Flow

### Touch Event → Action Execution

```
1. evdev event arrives (EV_ABS, ABS_MT_POSITION_X/Y)
         ↓
2. TouchHandler processes → Gesture detected
         ↓
3. MenuNavigator.handle_gesture(gesture)
   - Updates menu state
   - Returns action if slice selected
         ↓
4. ActionExecutor.execute(action)
   - Parses action string "module.method:param"
   - Routes to appropriate handler
         ↓
5. Handler executes (LocalAPI / SecuBoxClient / SystemCmd)
         ↓
6. Result returned → RadialRenderer.show_result()
```

### Menu Data Loading

```python
# Dynamic menu items (e.g., device list, status values)
async def load_menu_data(menu_id: str) -> list[MenuItem]:
    """Load menu items, fetching dynamic data as needed."""

    if menu_id == "DEVICES":
        devices = await secubox_client.scan_devices()
        return [
            MenuItem("SCAN", icon="scan", action="devices.scan"),
            *[MenuItem(d.name, icon=d.status, action=f"devices.select:{d.id}")
              for d in devices],
            MenuItem("← BACK", icon="back", action="nav.back"),
        ]

    if menu_id == "SECUBOX.STATUS":
        status = await secubox_client.get_status()
        return [
            MenuItem(f"CPU: {status.cpu}%", icon="cpu", ...),
            MenuItem(f"MEM: {status.mem}%", icon="memory", ...),
            # ... etc
        ]

    return STATIC_MENUS.get(menu_id, [])
```

---

## Error Handling

### Network Failures

```python
class SecuBoxClient:
    async def request(self, endpoint: str, **kwargs):
        try:
            async with self.session.request(...) as resp:
                return await resp.json()
        except aiohttp.ClientError as e:
            # Show connection error on display
            self.renderer.show_error("Connection Lost")
            # Cache last known state
            return self.cache.get(endpoint)
        except asyncio.TimeoutError:
            self.renderer.show_error("Timeout")
            return None
```

### Invalid Touch

- Touches outside visible circle: Ignored silently
- Touches during animation: Queued until animation completes
- Rapid repeated taps: Debounced (200ms)

### Action Failures

```python
async def execute_with_feedback(self, action: str):
    """Execute action with visual feedback."""
    self.renderer.show_loading()
    try:
        result = await self.execute(action)
        if result.success:
            self.renderer.show_success(result.message)
        else:
            self.renderer.show_error(result.error)
    except Exception as e:
        self.renderer.show_error(f"Failed: {e}")
    finally:
        self.renderer.hide_loading()
```

---

## File Structure

```
remote-ui/round/agent/
├── main.py                  # Entry point (existing)
├── fb_dashboard.py          # Dashboard renderer (existing)
├── touch_handler.py         # Touch gesture detection (existing, extend)
├── menu_navigator.py        # Menu state machine (new)
├── radial_renderer.py       # Radial menu rendering (new)
├── action_executor.py       # Action dispatch (new)
├── secubox_client.py        # SecuBox REST client (new)
├── local_api.py             # Local settings API (new)
├── menu_definitions.py      # Static menu structures (new)
├── assets/
│   ├── icons/               # Menu icons (existing)
│   │   ├── scan-48.png
│   │   ├── back-48.png
│   │   └── ...
│   └── fonts/               # UI fonts
│       └── JetBrainsMono.ttf
└── tests/
    ├── test_menu_navigator.py
    ├── test_radial_renderer.py
    └── test_action_executor.py
```

---

## Testing Approach

### Unit Tests

1. **MenuNavigator:**
   - State transitions (dashboard ↔ menu)
   - Navigation stack (push/pop breadcrumb)
   - Slice selection wrapping

2. **RadialRenderer:**
   - Slice geometry calculation
   - Touch-to-slice mapping
   - Animation frame generation

3. **ActionExecutor:**
   - Action string parsing
   - Handler routing
   - Error propagation

### Integration Tests

1. **Touch → Display:**
   - Simulate evdev events → verify display updates
   - Test gesture sequences (tap, swipe, long press)

2. **Menu → API:**
   - Mock SecuBox API → verify correct requests
   - Test timeout/error handling

### Hardware Tests (on device)

1. **Visual inspection:** All 6 slices render correctly
2. **Touch accuracy:** Slice detection matches visual
3. **Performance:** <100ms response time
4. **Edge cases:** Touches at slice boundaries

---

## Implementation Notes

### Performance Considerations

- Pre-render static menu backgrounds to cache
- Use dirty-rectangle updates (only redraw changed areas)
- Limit animation frames to 30fps
- Async I/O for all network operations

### Accessibility

- High contrast colors (gold on black)
- Large touch targets (60° slices = ~120px arc at edge)
- Optional audio feedback (beeps) for blind users

### Future Enhancements

- Swipe-to-scroll for menus with >6 items
- Custom slice layouts (4, 8 slices)
- Gesture customization
- Multi-device dashboard view

---

## Approval

- [x] Architecture — Approved 2026-04-24
- [x] Menu Structure — Approved 2026-04-24
- [x] Interaction Design — Approved 2026-04-24
- [x] Data Flow — Per this document
- [x] Error Handling — Per this document
- [x] Testing Approach — Per this document

**Ready for implementation planning.**
