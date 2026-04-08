# SecuBox Design Charter (Charte Graphique)

*Version 1.0 — April 2026*

---

## Six Module Color System

SecuBox uses **complementary color pairs** for its six modules:

| Module | Code | Color | Hex | Description |
|--------|------|-------|-----|-------------|
| **AUTH** | 01 | Orange (Coral Auth) | `#C04E24` | Authentication, zero-trust |
| **WALL** | 02 | Yellow (Amber Shield) | `#9A6010` | Firewall, nftables |
| **BOOT** | 03 | Red (Coral Launch) | `#803018` | Deployment, provisioning |
| **MIND** | 04 | Violet (Violet Mind) | `#3D35A0` | AI, behavioral analysis, nDPId |
| **ROOT** | 05 | Green (Teal Root) | `#0A5840` | Terminal CLI, Debian system |
| **MESH** | 06 | Blue (Blue Mesh) | `#104A88` | Network, WireGuard, Tailscale |

### Complementary Pairs
- Red ↔ Green (BOOT ↔ ROOT)
- Yellow ↔ Violet (WALL ↔ MIND)
- Blue ↔ Orange (MESH ↔ AUTH)

---

## Color Palette Details

### AUTH (Orange)
```css
--auth-main:  #C04E24;
--auth-light: #E8845A;
--auth-xlt:   #FAECE7;
--auth-dark:  #7A2A10;
```

### WALL (Yellow/Amber)
```css
--wall-main:  #9A6010;
--wall-light: #CC8820;
--wall-xlt:   #FDF3E0;
--wall-dark:  #5A3808;
```

### BOOT (Red)
```css
--boot-main:  #803018;
--boot-light: #C06040;
--boot-xlt:   #FAECE7;
--boot-dark:  #5A1E0A;
```

### MIND (Violet)
```css
--mind-main:  #3D35A0;
--mind-light: #7068D0;
--mind-xlt:   #EEEDFE;
--mind-dark:  #241D6A;
```

### ROOT (Green/Teal)
```css
--root-main:  #0A5840;
--root-light: #148C66;
--root-xlt:   #E1F5EE;
--root-dark:  #063828;
```

### MESH (Blue)
```css
--mesh-main:  #104A88;
--mesh-light: #2C70C0;
--mesh-xlt:   #E6F1FB;
--mesh-dark:  #08305A;
```

---

## Light Theme Base Colors

```css
--bg:       #FFFFFF;
--surface:  #FAFAF8;
--surface2: #F4F3EF;
--border:   #E2E0D8;
--border2:  #C8C6BE;
--text:     #1A1A18;
--muted:    #6B6963;
```

---

## Typography

### Font Stack
- **Display/Heading**: Space Grotesk (300-700)
- **Body**: Space Grotesk 400
- **Monospace/Code**: JetBrains Mono (400, 700)

### Usage
```css
/* Display - titles */
font-size: 56px;
font-weight: 700;
letter-spacing: -2px;
color: var(--root-main);

/* Heading */
font-size: 24px;
font-weight: 600;
letter-spacing: -0.4px;

/* Body */
font-size: 14-16px;
font-weight: 400;
line-height: 1.6-1.7;

/* Code/Terminal */
font-family: 'JetBrains Mono', monospace;
font-size: 12px;
```

---

## Brand Identities

| Brand | Color | Usage |
|-------|-------|-------|
| **SecuBox·** | Green (Root) | Main product brand |
| **Gondwana** | Violet (Mind) | Public/external brand |
| **CyberMind** | Orange (Auth) | Internal/confidential brand |

---

## Spacing System

| Size | Pixels | Usage |
|------|--------|-------|
| XS | 4px | Icon gaps |
| S | 8px | Chips |
| M | 16px | Padding |
| L | 24px | Sections |
| XL | 40px | Margins |
| 2XL | 56px | Cover |

---

## Grid System

- 12-column grid
- Gap: 8px
- Border radius: 14px (cards), 6px (swatches), 3px (small elements)

---

## Module Icons/Symbols

| Module | Symbol | Description |
|--------|--------|-------------|
| AUTH | Hexagonal target | Controlled access, verified identity |
| WALL | Flaming brick wall | nftables, inbound/outbound rules |
| BOOT | Rocket | Provisioning, fast boot, deployment |
| MIND | Robot | Automation, behavioral analysis |
| ROOT | $>_ prompt | Console access, low-level system |
| MESH | Network gear | WireGuard, Tailscale, mesh topology |

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie*
