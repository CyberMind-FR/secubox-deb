# WIKI-STYLE-GUIDE.md — SecuBox Wiki Design Conformity

*Based on SecuBox Charte Graphique v1.0 — April 2026*

---

## Six-Module Color System for Wiki

Since GitHub wiki uses Markdown (no CSS), we use **emoji badges** and **consistent categories** to represent the six-module structure:

| Module | Badge | Hex | Category Focus |
|--------|-------|-----|----------------|
| **AUTH** | `🟠` | `#C04E24` | Authentication, ZeroTrust, MFA |
| **WALL** | `🟡` | `#9A6010` | Firewall, nftables, CrowdSec, IDS/IPS |
| **BOOT** | `🔴` | `#803018` | Deployment, provisioning, installation |
| **MIND** | `🟣` | `#3D35A0` | AI, behavioral analysis, nDPId, ML |
| **ROOT** | `🟢` | `#0A5840` | Terminal CLI, Debian system, hardening |
| **MESH** | `🔵` | `#104A88` | Network, WireGuard, Tailscale, mesh |

---

## Complementary Pairs

Always group related modules by their complementary relationships:

- **Red ↔ Green** (BOOT ↔ ROOT) — Deployment & System
- **Yellow ↔ Violet** (WALL ↔ MIND) — Security & Intelligence
- **Blue ↔ Orange** (MESH ↔ AUTH) — Network & Access

---

## Section Organization

### Home Page Structure

```markdown
# SecuBox

**CyberMind · Gondwana · Savoie** | Version X.X.X

[eyebrow description]

---

## 🔴 Quick Start (BOOT)
[Installation paths]

## 🟢 System Requirements (ROOT)
[Hardware, OS requirements]

## 🟣 Features Overview (MIND)
[Module summary table]

## 🔵 Documentation (MESH)
[Links to guides]
```

### Module Page Structure

Organize modules into these six stacks:

```markdown
## 🟠 AUTH — Authentication Stack
- secubox-auth
- secubox-portal
- secubox-users
- secubox-nac

## 🟡 WALL — Security Stack
- secubox-crowdsec
- secubox-waf
- secubox-threats
- secubox-ipblock
- secubox-ai-insights

## 🔴 BOOT — Deployment Stack
- secubox-cloner
- secubox-vault
- secubox-vm
- secubox-rezapp

## 🟣 MIND — Intelligence Stack
- secubox-dpi
- secubox-netifyd
- secubox-soc-agent
- secubox-soc-gateway
- secubox-soc-web

## 🟢 ROOT — System Stack
- secubox-core
- secubox-hub
- secubox-system
- secubox-hardening
- secubox-console

## 🔵 MESH — Network Stack
- secubox-wireguard
- secubox-haproxy
- secubox-netmodes
- secubox-qos
- secubox-turn
```

---

## Typography Guidelines

### Headers
- **H1**: Page title only (one per page)
- **H2**: Major sections with emoji badge
- **H3**: Subsections
- **H4**: Module names

### Code Blocks
- Use triple backticks with language identifier
- `bash` for shell commands
- `yaml` for configuration
- `python` for API examples

### Tables
- Use for structured data (modules, endpoints, options)
- Align columns consistently
- Include emoji badges in category columns

---

## Module Entry Format

Each module entry should follow this template:

```markdown
### secubox-<name>
**[Category Badge] Short Description**

- Feature 1
- Feature 2
- Feature 3

**Endpoints:** `/api/v1/<name>/`
```

---

## Page Header Format

Every page should start with:

```markdown
# Page Title

**[EN](Page)** | [FR](Page-FR) | [中文](Page-ZH) | **vX.X.X**

[Brief description]

---
```

---

## Badges Reference

### Status Badges
- `⭐` — Recommended / Featured
- `⚡` — ARM/Hardware specific
- `🔒` — Security critical
- `📱` — Mobile/responsive
- `🖥️` — VM specific

### Module Stack Badges
- `🟠` AUTH — Orange (Coral Auth)
- `🟡` WALL — Yellow (Amber Shield)
- `🔴` BOOT — Red (Coral Launch)
- `🟣` MIND — Violet (Violet Mind)
- `🟢` ROOT — Green (Teal Root)
- `🔵` MESH — Blue (Blue Mesh)

---

## Brand References

| Brand | Color | Usage |
|-------|-------|-------|
| **SecuBox** | 🟢 Green (Root) | Main product brand |
| **Gondwana** | 🟣 Violet (Mind) | Public/external brand |
| **CyberMind** | 🟠 Orange (Auth) | Internal/developer brand |

---

## Footer

Every major page should end with:

```markdown
---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie*
```

---

*Last updated: 2026-04-08*
