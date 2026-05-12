<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox WebUI Skin Rework — Mockup Proposals

**Date**: 2026-05-08
**Author**: Claude Code / CyberMind

---

## Current State Analysis

### What Works
- Six-module color system (well-defined palette)
- Dark theme foundation
- Responsive sidebar
- CSS variables architecture

### Pain Points
- Inconsistent spacing
- Too many competing visual elements
- CRT effects can feel dated
- Cards lack visual hierarchy
- Status indicators small/hard to read
- Typography could be more refined

---

## Proposal A: "Glass Morphism Cyber"

### Concept
Modern glass-blur aesthetic with vibrant accent colors. Clean, spacious, professional.

```
┌──────────────────────────────────────────────────────────────────┐
│  ┌────────────┐  ┌──────────────────────────────────────────────┐│
│  │            │  │ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ ││
│  │  SECUBOX   │  │        DASHBOARD                             ││
│  │    🔒      │  │  ┌─────────────┬─────────────┬─────────────┐ ││
│  │            │  │  │ 🛡️ WAF     │ 👁️ CrowdSec │ 🌐 Traffic  │ ││
│  │ ─────────  │  │  │ ████████   │ ████████    │ ████████    │ ││
│  │ 🏠 Hub     │  │  │ 150 rules  │ 2.1k alerts │ 45 MB/s     │ ││
│  │ 🛡️ WAF    │  │  └─────────────┴─────────────┴─────────────┘ ││
│  │ 👁️ Crowd  │  │                                              ││
│  │ 🔐 Auth   │  │  ┌────────────────────────────────────────┐  ││
│  │ 🌐 Net    │  │  │  THREATS TODAY          ▲ +12%        │  ││
│  │ ─────────  │  │  │  ████████████████████████████          │  ││
│  │ ⚙️ System │  │  │  3,152                                  │  ││
│  │            │  │  └────────────────────────────────────────┘  ││
│  │            │  │                                              ││
│  └────────────┘  └──────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────┘
```

### Key Changes
- **Background**: Deep gradient (#0a0e14 → #141a24)
- **Cards**: Frosted glass effect (`backdrop-filter: blur(20px)`)
- **Borders**: 1px rgba(255,255,255,0.1)
- **Shadows**: Larger, softer (0 8px 32px rgba(0,0,0,0.3))
- **Accents**: Vibrant module colors with glow
- **Spacing**: More generous padding (24px cards)
- **Typography**: Lighter weight, more contrast

### CSS Preview
```css
.card-glass {
  background: rgba(20, 26, 36, 0.6);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 16px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
}

.metric-glow {
  text-shadow: 0 0 20px currentColor;
}
```

---

## Proposal B: "Minimal Matrix"

### Concept
Ultra-clean, terminal-inspired. Maximum data density with minimal chrome.

```
┌──────────────────────────────────────────────────────────────────┐
│ SECUBOX ──────────────────────────────────────── admin@mochabin │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  WAF ═══════════════════════════════════════════════════════════│
│  ● ACTIVE   150 rules   17 categories   3152 threats today      │
│  ├─ Top: 🇨🇳 CN (523)  🇷🇺 RU (312)  🇺🇸 US (201)              │
│  └─ Last: 2s ago from 45.33.32.156 (RCE attempt)               │
│                                                                  │
│  CROWDSEC ══════════════════════════════════════════════════════│
│  ● ACTIVE   v1.7.7   LAPI ✓   CAPI ✓   2 bouncers              │
│  ├─ Decisions: 100 active   Alerts: 50 (24h)                    │
│  └─ Last sync: 5m ago                                           │
│                                                                  │
│  NETWORK ═══════════════════════════════════════════════════════│
│  eth0 ↓ 12.4 MB/s  ↑ 3.2 MB/s   wan0 ↓ 45.2 MB/s  ↑ 8.1 MB/s  │
│  Connections: 1,247 active   Firewall: 12 rules matched/min     │
│                                                                  │
│  SYSTEM ════════════════════════════════════════════════════════│
│  CPU: ████████░░ 78%   RAM: ██████░░░░ 62%   Disk: ███░░░░░░ 34%│
│  Uptime: 47d 12h 34m   Load: 2.4 1.8 1.2                        │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│ [Tab] Switch  [/] Search  [?] Help  [Q] Logout        15:32:45 │
└──────────────────────────────────────────────────────────────────┘
```

### Key Changes
- **Layout**: Single-column, terminal-like
- **Navigation**: Keyboard-driven, minimal sidebar
- **Colors**: Monochrome base + single accent (green)
- **Typography**: All monospace (JetBrains Mono)
- **Effects**: No shadows, no gradients, just borders
- **Density**: Maximum information per screen

### CSS Preview
```css
:root {
  --bg: #0c0c0c;
  --text: #c0c0c0;
  --accent: #00ff41;
  --border: #333;
}

body {
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  line-height: 1.5;
}

.section-title {
  color: var(--accent);
  border-bottom: 1px double var(--accent);
}
```

---

## Proposal C: "Neon Gradient"

### Concept
Bold, vibrant, modern cyberpunk. Eye-catching with animated gradients.

```
┌──────────────────────────────────────────────────────────────────┐
│ ╔══════════════════════════════════════════════════════════════╗ │
│ ║  ┌───────┐                                                   ║ │
│ ║  │ 🔒    │  S E C U B O X                                   ║ │
│ ║  │SECUBOX│  ═══════════════════════════════════════         ║ │
│ ║  └───────┘  Cyber Defense Platform                          ║ │
│ ╠══════════════════════════════════════════════════════════════╣ │
│ ║                                                              ║ │
│ ║  ╭──────────────────╮  ╭──────────────────╮                 ║ │
│ ║  │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ │  │ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ │                 ║ │
│ ║  │   WAF ACTIVE     │  │  CROWDSEC OK     │                 ║ │
│ ║  │   ════════════   │  │  ════════════    │                 ║ │
│ ║  │   3,152 BLOCKED  │  │  100 DECISIONS   │                 ║ │
│ ║  │   ↗ +12% today   │  │  2 BOUNCERS      │                 ║ │
│ ║  ╰──────────────────╯  ╰──────────────────╯                 ║ │
│ ║                                                              ║ │
│ ║  ╭────────────────────────────────────────────────────────╮ ║ │
│ ║  │  THREAT ACTIVITY                                        │ ║ │
│ ║  │  ▁▂▃▅▆▇█▇▆▅▃▂▁▂▃▅▆▇█▇▆▅▃▂▁▂▃▅▆▇█▇▆▅▃▂▁               │ ║ │
│ ║  │  00:00                12:00                 24:00       │ ║ │
│ ║  ╰────────────────────────────────────────────────────────╯ ║ │
│ ╚══════════════════════════════════════════════════════════════╝ │
└──────────────────────────────────────────────────────────────────┘
```

### Key Changes
- **Borders**: Double-line box drawing characters
- **Gradients**: Animated purple→cyan→green
- **Cards**: Thick neon borders with glow
- **Typography**: Bold, uppercase headings
- **Effects**: Pulsing animations, hover glows
- **Icons**: Larger, more prominent

### CSS Preview
```css
.neon-card {
  border: 2px solid transparent;
  background:
    linear-gradient(var(--bg), var(--bg)) padding-box,
    linear-gradient(90deg, #6e40c9, #00d4ff, #00ff41) border-box;
  animation: gradient-shift 3s ease infinite;
}

@keyframes gradient-shift {
  0%, 100% { filter: hue-rotate(0deg); }
  50% { filter: hue-rotate(30deg); }
}

.metric-big {
  font-size: 48px;
  font-weight: 700;
  background: linear-gradient(90deg, #00d4ff, #00ff41);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
```

---

## Proposal D: "Corporate Clean"

### Concept
Professional, enterprise-ready. Less "hacker", more "security dashboard".

```
┌──────────────────────────────────────────────────────────────────┐
│  SecuBox                                         🔔 👤 Admin ▾  │
├────────────┬─────────────────────────────────────────────────────┤
│            │                                                     │
│  Dashboard │   Security Overview                                 │
│  ─────────-│   ─────────────────────────────────────────────     │
│            │                                                     │
│  📊 Overview│   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │
│  🛡️ WAF     │   │ Threats │ │ Blocked │ │ Active  │ │ Uptime  │ │
│  👁️ IDS     │   │  3,152  │ │  2,847  │ │   91    │ │  99.9%  │ │
│  🌐 Network │   │ +12% ↑  │ │ +8% ↑   │ │ services│ │ 47 days │ │
│  📈 Reports │   └─────────┘ └─────────┘ └─────────┘ └─────────┘ │
│  ⚙️ Settings│                                                    │
│            │   Recent Activity                                   │
│  ─────────-│   ───────────────────────────────────────────────   │
│            │   15:32  WAF blocked RCE from 45.33.32.156         │
│  SYSTEM    │   15:31  CrowdSec synced 12 new decisions          │
│  └ Services│   15:30  SSL cert renewed for git.secubox.in       │
│  └ Logs    │   15:28  User admin logged in from 192.168.1.10    │
│  └ Backup  │                                                     │
│            │                                                     │
└────────────┴─────────────────────────────────────────────────────┘
```

### Key Changes
- **Colors**: Neutral grays + single brand color
- **Layout**: Traditional sidebar + content
- **Cards**: Subtle shadows, rounded corners
- **Typography**: System fonts (Inter/SF Pro)
- **Effects**: Minimal, professional
- **Icons**: Outlined style, consistent sizing

### CSS Preview
```css
:root {
  --bg: #f8f9fa;
  --card: #ffffff;
  --text: #212529;
  --muted: #6c757d;
  --primary: #0d6efd;
  --border: #dee2e6;
}

.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.08);
}
```

---

## Comparison Matrix

| Aspect | A: Glass | B: Matrix | C: Neon | D: Corporate |
|--------|----------|-----------|---------|--------------|
| **Vibe** | Modern | Terminal | Cyberpunk | Enterprise |
| **Dark Mode** | Primary | Only | Primary | Secondary |
| **Data Density** | Medium | High | Low | Medium |
| **Animations** | Subtle | None | Heavy | Minimal |
| **Learning Curve** | Low | Medium | Low | Low |
| **Performance** | Good | Best | Heaviest | Best |
| **Mobile** | Good | Fair | Good | Excellent |
| **Target User** | DevOps | Sysadmin | Enthusiast | Enterprise |

---

## Recommendation

**Hybrid Approach: Glass Morphism base (A) + Matrix data views (B)**

- Use **Proposal A** for dashboard, overview pages
- Use **Proposal B** styling for logs, terminal, detailed views
- Keep the **Six-Module color system** as accent colors
- Add subtle **Neon gradients (C)** for status indicators
- Ensure **Corporate (D)** fallback for light mode

### Implementation Priority

1. **Phase 1**: Update design-tokens.css with new variables
2. **Phase 2**: Rework card components (glass effect)
3. **Phase 3**: Update sidebar (cleaner, more spacious)
4. **Phase 4**: Metric cards with better hierarchy
5. **Phase 5**: Status indicators (larger, glowing)
6. **Phase 6**: Typography refinement
7. **Phase 7**: Animations & micro-interactions

---

## Next Steps

1. Choose preferred direction (A/B/C/D or hybrid)
2. Create Figma/HTML prototype of key screens
3. Implement design tokens first
4. Iterate on one module (dashboard) as pilot
5. Roll out to all modules

---

*Mockups created by Claude Code for CyberMind SecuBox*
