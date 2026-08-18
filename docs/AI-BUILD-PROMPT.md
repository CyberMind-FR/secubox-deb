<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox-DEB Build System — AI Assistant Prompt

Use this prompt with GPT, Gemini, or other AI assistants to get help building SecuBox images.

---

## Copy This Prompt

```
You are helping build SecuBox-DEB, a Debian-based cybersecurity appliance platform.

## Project Overview

SecuBox-DEB is a migration from OpenWrt to Debian bookworm (arm64/amd64) targeting:
- MOCHAbin (Armada 7040) - SecuBox Pro
- ESPRESSObin (Armada 3720) - SecuBox Lite
- x64 VM/Live USB - Development/Testing

Target: ANSSI CSPN security certification.

## Build Scripts

| Script | Target | Command |
|--------|--------|---------|
| Live USB x64 | Bootable USB with kiosk | `sudo bash image/build-live-usb.sh` |
| ARM64 board | MOCHAbin/ESPRESSObin | `sudo bash image/build-image.sh --board mochabin` |
| VirtualBox | Development VM | `sudo bash image/build-image.sh --board vm-x64 --vdi` |

## Live USB Options

```bash
sudo bash image/build-live-usb.sh [OPTIONS]
  --no-kiosk         # Disable GUI kiosk (default: enabled)
  --no-compress      # Skip gzip compression (faster)
  --local-cache      # Use local APT cache
  --slipstream       # Include local .deb packages
  --preseed FILE     # Include config archive
```

## ARM64 Board Options

```bash
sudo bash image/build-image.sh --board <BOARD> [OPTIONS]
  --board mochabin|espressobin-v7|espressobin-ultra|vm-x64
  --vdi              # Create VirtualBox disk
  --local-cache      # Use local APT cache
  --slipstream       # Include local .deb packages
```

## VirtualBox Workflow

```bash
# Build image
sudo bash image/build-image.sh --board vm-x64 --vdi

# Create and start VM
bash scripts/run-vbox.sh

# Or manually
bash image/create-vbox-vm.sh output/secubox-vm-x64-bookworm.vdi
VBoxManage startvm "SecuBox-Dev" --type gui

# SSH access
ssh -p 2222 root@localhost  # Password: secubox
```

## Features Enabled by Default

- Root autologin (TTY1-6)
- GUI kiosk mode (TTY7) - Chromium fullscreen
- Network auto-detection
- 125+ SecuBox modules pre-installed
- nftables firewall (DEFAULT DROP)
- HAProxy + CrowdSec security stack

## Flash to USB

```bash
# Compressed
zcat output/secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress

# Raw
sudo dd if=output/secubox-live-amd64-bookworm.img of=/dev/sdX bs=4M status=progress
```

## Local Package Cache (faster builds)

```bash
# Setup once
sudo bash scripts/setup-local-cache.sh

# Build with cache
sudo bash image/build-live-usb.sh --local-cache
```

## Troubleshooting

1. **Build fails**: Clear `/tmp/secubox-rootfs` and retry
2. **VBox NVRAM error**: Delete `.nvram` file in VM folder
3. **SSH timeout**: Wait for VM to fully boot, check port 2222
4. **Kiosk not starting**: Check `journalctl -u secubox-kiosk`

## Tech Stack

- Debian 12 bookworm (arm64/amd64)
- Python 3.11+ / FastAPI / Uvicorn
- nftables (not iptables)
- HAProxy + CrowdSec + Suricata
- WireGuard VPN
- Chromium kiosk (X11)

## Security Rules

- nftables DEFAULT DROP policy
- No secrets in code (use /etc/secubox/secrets/)
- TLS 1.3 minimum
- All services run as unprivileged users
- AppArmor profiles enforced

When helping with builds, always:
1. Use the correct script for the target platform
2. Include --slipstream for local packages
3. Use --no-compress for faster testing
4. Check output in /tmp/build-*.log for errors
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────┐
│                  SecuBox Build Quick Ref                    │
├─────────────────────────────────────────────────────────────┤
│  Live USB (x64):                                            │
│    sudo bash image/build-live-usb.sh                        │
│                                                             │
│  ARM64 (MOCHAbin):                                          │
│    sudo bash image/build-image.sh --board mochabin          │
│                                                             │
│  VirtualBox:                                                │
│    sudo bash image/build-image.sh --board vm-x64 --vdi      │
│    bash scripts/run-vbox.sh                                 │
│                                                             │
│  SSH: ssh -p 2222 root@localhost (pass: secubox)            │
│  Web: https://localhost:9443                                │
├─────────────────────────────────────────────────────────────┤
│  Flags:                                                     │
│    --no-kiosk      Disable GUI                              │
│    --no-compress   Faster build                             │
│    --local-cache   Use APT cache                            │
│    --slipstream    Include local .debs                      │
└─────────────────────────────────────────────────────────────┘
```
