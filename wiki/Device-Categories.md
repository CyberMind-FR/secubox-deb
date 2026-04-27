# Device Categories — SecuBox 6-Icon System

SecuBox uses a unified 6-category icon system across all devices and interfaces. This **Hamiltonian path** (AUTH → MESH) represents the security flow from authentication to network mesh.

## The Six Categories

| Index | Icon | Name | Role | Color | Hex |
|-------|------|------|------|-------|-----|
| 0 | 🔐 | **AUTH** | Authentication / VPN / Encryption | Rust | `#C04E24` |
| 1 | 🛡️ | **WALL** | Firewall / nftables / CrowdSec | Amber | `#9A6010` |
| 2 | ⚙️ | **BOOT** | System / OS / Services | Crimson | `#803018` |
| 3 | 🧠 | **MIND** | AI / CPU / Processing | Indigo | `#3D35A0` |
| 4 | 🌳 | **ROOT** | Privileges / Integrity / Trust | Teal | `#0A5840` |
| 5 | 🌐 | **MESH** | Network / WireGuard / Tailscale | Navy | `#104A88` |

## Hamiltonian Path

The order AUTH → WALL → BOOT → MIND → ROOT → MESH follows the **Hamiltonian path** defined in the SecuBox security charter:

```
AUTH ─────► WALL ─────► BOOT
  │                       │
  │   ┌─────────────────┐ │
  │   │   SecuBox Core  │ │
  │   └─────────────────┘ │
  │                       │
MESH ◄───── ROOT ◄───── MIND
```

1. **AUTH** — Entry point: user authenticates
2. **WALL** — Traffic filtered by firewall rules
3. **BOOT** — System services respond
4. **MIND** — AI/processing analyzes request
5. **ROOT** — Privileges verified, integrity checked
6. **MESH** — Connected to network mesh

## Device Implementations

### Smart-Strip (SBX-STR-01)

Physical HMI module with 6 RGB LEDs and capacitive touch zones.

| Feature | Description |
|---------|-------------|
| LEDs | 6× SK6812-MINI-E (RGB, 5V) |
| Touch | 6× capacitive pads (AT42QT2120) |
| Interface | USB-C / I²C |
| Animations | Sweep, breathing, panic |

**LED Behaviors:**
- **Solid** — Status OK
- **Flash** — Error or event
- **Pulse** — Operation in progress
- **Sweep** — Hamiltonian animation

See: [Smart-Strip](Smart-Strip)

### Eye Remote (Pi Zero W)

Remote dashboard with HyperPixel 2.1 Round display.

| Category | Display Element |
|----------|-----------------|
| AUTH | VPN status indicator |
| WALL | Firewall activity graph |
| BOOT | System health gauge |
| MIND | CPU/AI load meter |
| ROOT | Integrity status |
| MESH | Network topology |

See: [Eye-Remote](Eye-Remote)

### C3BOX Dashboard

Web-based dashboard using the 6-category layout.

| Category | Panel Content |
|----------|--------------|
| AUTH | Active sessions, certificates |
| WALL | Firewall rules, blocked IPs |
| BOOT | Services status, uptime |
| MIND | AI insights, CPU graphs |
| ROOT | Audit log, integrity checks |
| MESH | Peers, bandwidth, latency |

### Console TUI

Terminal-based interface with 6-panel layout.

```
┌─────────────────────────────────────────────────┐
│ AUTH │ WALL │ BOOT │ MIND │ ROOT │ MESH │
├──────┴──────┴──────┴──────┴──────┴──────┤
│                                         │
│           SecuBox Console               │
│                                         │
└─────────────────────────────────────────┘
```

## Color Palette CSS

```css
:root {
  --auth: #C04E24;  /* Rust */
  --wall: #9A6010;  /* Amber */
  --boot: #803018;  /* Crimson */
  --mind: #3D35A0;  /* Indigo */
  --root: #0A5840;  /* Teal */
  --mesh: #104A88;  /* Navy */
}
```

## HID Mapping (Smart-Strip)

| Pad | HID Usage | Linux Key |
|-----|-----------|-----------|
| AUTH | `0x0220` | KEY_F13 |
| WALL | `0x021F` | KEY_F14 |
| BOOT | `0x0192` | KEY_F15 |
| MIND | `0x019C` | KEY_F16 |
| ROOT | `0x0194` | KEY_F17 |
| MESH | `0x023D` | KEY_F18 |

## I²C Register Map

| Register | Category | Description |
|----------|----------|-------------|
| `0x10` | AUTH | LED0 RGB (3 bytes) |
| `0x13` | WALL | LED1 RGB (3 bytes) |
| `0x16` | BOOT | LED2 RGB (3 bytes) |
| `0x19` | MIND | LED3 RGB (3 bytes) |
| `0x1C` | ROOT | LED4 RGB (3 bytes) |
| `0x1F` | MESH | LED5 RGB (3 bytes) |

## Animation Patterns

| ID | Name | Pattern |
|----|------|---------|
| 0 | Manual | Direct control |
| 1 | Sweep | Hamiltonian sweep AUTH→MESH |
| 2 | Panic | ROOT flashes red, reverse sweep |
| 3 | Breathing | All LEDs pulse in sync |
| 4 | Boot | Sequential light-up |

## See Also

- [Smart-Strip](Smart-Strip) — HMI module
- [Eye-Remote](Eye-Remote) — Remote dashboard
- [UI Comparison](UI-COMPARISON) — Interface comparison
