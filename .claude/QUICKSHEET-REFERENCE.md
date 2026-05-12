<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# QUICKSHEET-REFERENCE.md — SecuBox Quick Reference Sheet Summary

*Source: secubox_quicksheet(2).html — April 2026*

---

## Overview

The SecuBox Quick Reference Sheet is a visual guide showing the **Six-Stack Architecture** with detailed cards for each module. It uses the SecuBox Charte Graphique Light v1.0 styling.

---

## Six-Stack Security Architecture

| # | Code | Name (FR) | Name (EN) | Color | Icon |
|---|------|-----------|-----------|-------|------|
| 01 | AUTH | Authentification | Authentication | Orange `#C04E24` | Cible hexagonale |
| 02 | WALL | Pare-feu | Firewall | Yellow `#9A6010` | Briques enflammées |
| 03 | BOOT | Déploiement | Deployment | Red `#803018` | Fusée |
| 04 | MIND | Intelligence | Intelligence | Violet `#3D35A0` | Robot — IA |
| 05 | ROOT | Terminal CLI | Terminal CLI | Green `#0A5840` | Invite $>_ |
| 06 | MESH | Réseau & Config | Network & Config | Blue `#104A88` | Engrenage réseau |

---

## Module Descriptions

### 🟠 AUTH — Authentification (01)
**Tagline:** Accès contrôlé · Identité vérifiée · Zero-Trust

Accès conditionnel basé sur l'identité vérifiée. Authentification multi-facteur, certificats X.509, protocole hamiltonien ZKP. Aucun accès sans preuve cryptographique.

**Tags:** ZeroTrust, MFA, GK·HAM-HASH, ZKP, X.509

---

### 🟡 WALL — Pare-feu (02)
**Tagline:** nftables · CrowdSec · IDS/IPS actif

Règles nftables stateless, détection comportementale CrowdSec, blocage automatique. Analyse trafic réseau temps réel avec nDPId.

**Tags:** nftables, CrowdSec, nDPId, IDS/IPS, Stateless

---

### 🔴 BOOT — Déploiement (03)
**Tagline:** Provisioning · Boot rapide · Terrain

Mise en production terrain en moins de 30 min. Image Debian préconfigurée, scripts d'installation automatisés, déploiement offline.

**Tags:** FastAPI, Uvicorn, HAProxy, Ansible, Offline

---

### 🟣 MIND — Intelligence (04)
**Tagline:** Automatisation · Analyse comportementale · nDPId

Moteur IA comportemental, détection d'anomalies temps réel. Corrélation d'événements, réponse automatique aux incidents, apprentissage adaptatif.

**Tags:** nDPId, ML, SIEM, Alertes, Adaptive

---

### 🟢 ROOT — Terminal CLI (05)
**Tagline:** Debian durci · Accès console · Bas niveau

Socle Debian 12 minimal et durci. Shell sécurisé, gestion packages offline, audit système. Zéro service inutile, surface d'attaque minimale.

**Tags:** Debian 12, Hardening, CLI, LUKS, Auditd

---

### 🔵 MESH — Réseau & Config (06)
**Tagline:** WireGuard · Tailscale · Topologie mesh

Interconnexion sécurisée multi-sites. Tunnels WireGuard natifs, intégration Tailscale, topologie mesh auto-découverte. DNS dynamique intégré.

**Tags:** WireGuard, Tailscale, Mesh, DDNS, netplan

---

## Complementary Pairs

The six modules form three complementary color pairs:

1. **Red ↔ Green** (BOOT ↔ ROOT) — Deployment & System
2. **Yellow ↔ Violet** (WALL ↔ MIND) — Security & Intelligence
3. **Blue ↔ Orange** (MESH ↔ AUTH) — Network & Access

---

## Visual Elements

### Card Structure
Each module card contains:
- Color stripe (gradient from main to light)
- Dice face image (with module number overlay)
- Module ID and name
- Icon label
- Tagline with module colors
- Description text
- Tags with module colors
- Footer links (Config, Docs, API)

### Typography
- **Display/Heading:** Space Grotesk (300-700)
- **Body:** Space Grotesk 400
- **Monospace/Code:** JetBrains Mono (400, 700)

### Spacing
- XS: 4px (icon gaps)
- S: 8px (chips)
- M: 16px (padding)
- L: 24px (sections)
- XL: 40px (margins)
- 2XL: 56px (cover)

---

## 🚨 Emergency Recovery — Busybox Anti-Crash

### Problem: `/lib` symlink broken (libc inaccessible)

On modern Debian, `/lib` is a symlink to `/usr/lib`. If a tarball extraction replaces this symlink with a directory, ALL external commands fail:

```
-bash: /usr/bin/ls: cannot execute: required file not found
```

### Solution: Busybox (statically linked)

Busybox is often compiled statically and doesn't need libc:

```bash
# Check if busybox exists
echo /bin/busybox
echo /usr/bin/busybox

# If found, use it to repair:
/bin/busybox rm -rf /lib
/bin/busybox ln -s usr/lib /lib

# Verify
/bin/busybox ls -la /lib
```

### Prevention: Safe module tarball extraction

```bash
# WRONG - can overwrite /lib symlink
cd / && tar xzf modules.tar.gz

# RIGHT - extract to specific path
tar xzf modules.tar.gz -C /lib/modules/ --strip-components=2
```

### Shell built-ins when nothing works

If no busybox, use bash built-ins to diagnose:

```bash
# List files (glob expansion)
echo /lib/*
echo /usr/lib/aarch64-linux-gnu/libc*

# Read file content
while IFS= read -r line; do echo "$line"; done < /etc/os-release

# Check if path exists
[[ -e /lib/aarch64-linux-gnu ]] && echo "exists" || echo "missing"
```

### Last resort: Rescue boot

Boot from USB/SD rescue media:
```bash
mount /dev/mmcblk0p2 /mnt
rm -rf /mnt/lib
ln -s usr/lib /mnt/lib
umount /mnt
reboot
```

---

## Brand Footer

*CyberMind · Gondwana · Notre-Dame-du-Cruet · Savoie*

---

*Reference extracted: 2026-04-08*
*Emergency recovery added: 2026-05-08*
