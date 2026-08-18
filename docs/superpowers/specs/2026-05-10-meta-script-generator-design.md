<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Meta-Script Generator v2.0.0

**Design Specification**
**Date:** 2026-05-10
**Author:** Claude + Gérald Kerma
**Status:** Draft

---

## Overview

The Meta-Script Generator is a Go-based CLI tool (`secubox`) that provides profile-based, modular image generation with version tracking for SecuBox appliances.

### Goals

- Unified CLI for image generation, building, fetching, and OTA updates
- Profile hierarchy with hardware detection and user override
- Self-describing packages with `debian/secubox.yaml`
- Multi-format output (img, gz, xz, vdi, qcow2, iso)
- A/B partition OTA with automatic rollback
- Dual APT repository (public + internal)

---

## Architecture

### File Structure

```
secubox-deb/
├── cmd/secubox/              ← Go CLI source
│   ├── main.go
│   ├── cmd/
│   │   ├── gen.go            ← secubox gen
│   │   ├── build.go          ← secubox build
│   │   ├── fetch.go          ← secubox fetch
│   │   └── ota.go            ← secubox ota
│   └── internal/
│       ├── profile/          ← profile loader/resolver
│       ├── manifest/         ← manifest generator
│       ├── builder/          ← image builder orchestration
│       └── hardware/         ← hardware detection
├── profiles/                 ← Centralized profile definitions
│   ├── base.yaml             ← Common to all
│   ├── tier-lite.yaml        ← 1-2GB RAM devices
│   ├── tier-standard.yaml    ← 4GB RAM devices
│   ├── tier-pro.yaml         ← 8GB+ RAM devices
│   └── arch/
│       ├── arm64.yaml        ← ARM64 base
│       └── amd64.yaml        ← x64 base
├── board/
│   └── <board>/
│       ├── config.mk         ← Legacy (kept for compatibility)
│       ��── board.yaml        ← Board metadata for generator
│       └── tweaks.yaml       ← Board-specific overrides
├── packages/
│   └── secubox-*/
│       └── debian/
│           ├── control
│           └── secubox.yaml  ← Component self-description
└── output/
    ├── manifest.yaml         ← Generated manifest
    ├── Makefile              ← Generated Makefile
    └── images/               ← Built images
```

---

## Profile System

### Inheritance Chain

```
base.yaml → arch/{arm64,amd64}.yaml → tier-{lite,standard,pro}.yaml → board/{name}/tweaks.yaml
```

### Profile Schema

**profiles/base.yaml:**
```yaml
version: "2.8.0"
name: base
description: Common SecuBox foundation

packages:
  required:
    - secubox-core
    - secubox-hub
    - secubox-portal
    - secubox-system
    - secubox-hardening

kernel:
  version: "6.6"
  modules:
    enable: [wireguard, nf_tables, nft_nat]
    blacklist: []

services:
  enable: [secubox-hub, nginx, nftables]

sysctl:
  net.ipv4.ip_forward: 1
  kernel.randomize_va_space: 2
```

**profiles/tier-lite.yaml:**
```yaml
inherits: base
name: tier-lite
description: For 1-2GB RAM devices
constraints:
  min_ram: 1G
  max_ram: 2G

packages:
  required:
    - secubox-crowdsec
    - secubox-wireguard
    - secubox-netmodes
    - secubox-nac
  excluded:
    - secubox-dpi
    - secubox-ollama
    - secubox-*-lxc

features:
  dpi: false
  lxc: false
  swap: 512M
```

**profiles/tier-standard.yaml:**
```yaml
inherits: base
name: tier-standard
description: For 4GB RAM devices
constraints:
  min_ram: 4G
  max_ram: 8G

packages:
  required:
    - secubox-crowdsec
    - secubox-wireguard
    - secubox-netmodes
    - secubox-nac
    - secubox-dpi
    - secubox-qos
    - secubox-waf

features:
  dpi: mirror
  lxc: true
  swap: 0
```

**profiles/tier-pro.yaml:**
```yaml
inherits: base
name: tier-pro
description: For 8GB+ RAM devices (MOCHAbin)
constraints:
  min_ram: 8G

packages:
  required:
    - secubox-full

features:
  dpi: inline
  lxc: true
  swap: 0
```

### Board Schema

**board/mochabin/board.yaml:**
```yaml
name: mochabin
arch: arm64
tier: pro
soc: armada-7040

hardware:
  ram: 4G-8G
  emmc: 8G
  interfaces:
    wan: eth0
    lan: [eth1, eth2, eth3, eth4]
    sfp: [eth5, eth6]

boot:
  method: uboot
  kernel_image: Image
  dts: armada-7040-mochabin
```

---

## Package Self-Description

Each package includes `debian/secubox.yaml` for component metadata.

**Example: packages/secubox-ollama/debian/secubox.yaml:**
```yaml
name: secubox-ollama
category: ai
description:
  en: LLM inference with Ollama
  fr: Inférence LLM avec Ollama

requirements:
  min_ram: 4G
  arch: [arm64, amd64]
  features: []

tags:
  - ai
  - llm
  - heavy

conflicts:
  - secubox-localai

services:
  - secubox-ollama.service

ports:
  - 11434/tcp
```

**Example: packages/secubox-dpi/debian/secubox.yaml:**
```yaml
name: secubox-dpi
category: network
description:
  en: Deep Packet Inspection with nDPId
  fr: Inspection profonde de paquets avec nDPId

requirements:
  min_ram: 1G
  arch: [arm64, amd64]
  kernel_modules: [nf_conntrack, cls_flower, act_mirred]

tags:
  - network
  - dpi
  - heavy

modes:
  inline:
    min_ram: 2G
    description: Full line-rate inspection
  mirror:
    min_ram: 512M
    description: Passive monitoring only

services:
  - secubox-dpi.service
  - ndpid.service
```

---

## CLI Interface

### Command Structure

```
secubox <command> [options]

Commands:
  gen       Generate manifest + Makefile
  build     Build image from manifest
  fetch     Download pre-built image from GitHub
  ota       Manage OTA updates
  info      Show system/hardware info
  config    Manage configuration
```

### secubox gen

```bash
# Interactive wizard (default)
secubox gen

# One-liner with flags
secubox gen --board mochabin --tier pro --enable ollama,jellyfin --out ./build

# From config file
secubox gen --config secubox-build.yaml

# Auto-detect hardware (on target device)
secubox gen --auto
```

### secubox build

```bash
# Build from manifest in current dir
secubox build

# Build specific manifest
secubox build ./my-manifest.yaml

# Build with parallel jobs
secubox build -j4

# Dry-run
secubox build --dry-run
```

### secubox fetch

```bash
# Download latest for board
secubox fetch --board mochabin

# Specific version
secubox fetch --board mochabin --version 2.8.0

# List available images
secubox fetch --list
```

### secubox ota

```bash
# Check for updates
secubox ota --check

# Apply package updates (APT)
secubox ota --packages

# Apply kernel/boot update (A/B swap)
secubox ota --system

# Full update
secubox ota --all

# Rollback to previous
secubox ota --rollback
```

---

## Build Pipeline

### Generated Manifest

```yaml
# Auto-generated by secubox gen v2.8.0
secubox_version: "2.8.0"
board: mochabin
tier: pro
arch: arm64

packages:
  - secubox-full
  - secubox-ollama
  - secubox-jellyfin

kernel:
  version: "6.6"
  dts: armada-7040-mochabin
  modules:
    enable: [wireguard, nf_tables, mvpp2, mvneta]
    blacklist: [mv88e6xxx]

partitions:
  esp: 256M
  root: 6G
  data: 2G

boot:
  method: uboot

output:
  formats: [img.gz, img.xz]
  checksums: [sha256, sha512]
```

### Generated Makefile

```makefile
# Auto-generated by secubox gen v2.8.0
MANIFEST := manifest.yaml
VERSION := 2.8.0
BOARD := mochabin
ARCH := arm64
IMAGE_NAME := secubox-$(BOARD)-$(VERSION)

.PHONY: all image rootfs partition boot compress checksums clean

all: image

image: rootfs partition boot compress checksums
	@echo "✓ Build complete: $(IMAGE_NAME).img.gz"

rootfs:
	secubox build --stage rootfs --manifest $(MANIFEST)

partition:
	secubox build --stage partition --manifest $(MANIFEST)

boot:
	secubox build --stage boot --manifest $(MANIFEST)

compress:
	gzip -k $(IMAGE_NAME).img
	xz -k $(IMAGE_NAME).img

checksums:
	sha256sum $(IMAGE_NAME).img* > SHA256SUMS
	sha512sum $(IMAGE_NAME).img* > SHA512SUMS

clean:
	rm -rf rootfs/ *.img *.img.gz *.img.xz SHA*SUMS

vdi: image
	qemu-img convert -f raw -O vdi $(IMAGE_NAME).img $(IMAGE_NAME).vdi

qcow2: image
	qemu-img convert -f raw -O qcow2 $(IMAGE_NAME).img $(IMAGE_NAME).qcow2

iso: rootfs
	secubox build --stage iso --manifest $(MANIFEST)
```

### Build Stages

| Stage | Action |
|-------|--------|
| `rootfs` | debootstrap + apt install packages |
| `partition` | Create .img, GPT, format ESP/root/data |
| `boot` | Install U-Boot/GRUB, DTB, kernel |
| `compress` | gzip/xz compression |
| `checksums` | SHA256/SHA512 |

---

## OTA Update System

### A/B Partition Layout

```
GPT:
  1: ESP        256M   FAT32    /boot/efi
  2: root-a     6G     ext4     /           (active)
  3: root-b     6G     ext4     (inactive)
  4: data       rest   ext4     /srv        (persistent)
```

### Boot Control

```
/boot/efi/secubox/
├── active       ← Contains "a" or "b"
├── fallback     ← Previous working slot
└���─ boot-count   ← Rollback after 3 failed boots
```

### OTA Workflow

1. **secubox ota --check**: Query repos for updates
2. **secubox ota --packages**: APT upgrade (live, no reboot)
3. **secubox ota --system**:
   - Download kernel/dtb/bootloader to inactive slot
   - Verify SHA256 signature
   - Write to root-b (if active=a)
   - Update ESP: active=b, fallback=a
   - Reboot
4. **secubox ota --rollback**: Swap active ↔ fallback, reboot

### Auto-Rollback Watchdog

```yaml
# /etc/secubox/ota.yaml
watchdog:
  enabled: true
  max_boot_failures: 3
  health_check: /usr/lib/secubox/health-check.sh
  rollback_on_failure: true
```

Boot sequence:
1. Increment boot-count
2. Run health-check.sh
3. If healthy → reset boot-count to 0
4. If boot-count >= 3 → auto-rollback

---

## APT Repository Architecture

### Dual-Repo Setup

| Repository | URL | Purpose |
|------------|-----|---------|
| **Public** | apt.secubox.in | Release packages, GPG signed |
| **Internal** | apt.gk2.secubox.in | Dev/staging + mirror of public |

### apt.gk2.secubox.in Features

- **Multi-arch support**: arm64, amd64, all
- **Components**: main (stable), dev (development), staging (pre-release)
- **Lintian compliance**: All packages validated before publish
- **Sync to public**: Manual trigger to push staging → apt.secubox.in

### Repository Structure

```
apt.gk2.secubox.in/
├── dists/
│   └── bookworm/
│       ├── main/
│       │   └── binary-{arm64,amd64,all}/
│       ├── dev/
│       │   └── binary-{arm64,amd64,all}/
│       └── staging/
│           └── binary-{arm64,amd64,all}/
├── pool/
│   ├── main/
│   ├── dev/
│   └── staging/
├── Release
├── Release.gpg
└── InRelease
```

### Lintian Integration

All packages must pass lintian before publish:

```bash
# In CI/build pipeline
lintian --fail-on warning,error *.deb

# Allowed overrides in debian/lintian-overrides
```

Required lintian checks:
- No critical errors
- No privacy breaches
- Valid control files
- Correct permissions
- No embedded libraries (unless justified)

### sources.list Configuration

```bash
# Production devices
deb https://apt.secubox.in bookworm main

# Dev/internal devices
deb https://apt.gk2.secubox.in bookworm main dev staging
```

### CLI Integration

```bash
# Configure repo source
secubox config set apt.mirror internal   # apt.gk2.secubox.in
secubox config set apt.mirror public     # apt.secubox.in (default)
```

### Server Configuration

```yaml
# /etc/secubox/apt-repo.yaml (on apt.gk2.secubox.in)
repo:
  path: /srv/apt
  architectures: [arm64, amd64, all]
  components: [main, dev, staging]

gpg:
  key: /etc/secubox/secrets/apt-signing.key

upstream:
  url: https://apt.secubox.in
  sync_interval: 1h

lintian:
  enabled: true
  fail_on: [error, warning]
  profile: debian
```

---

## Versioning

All packages share the unified SecuBox version (e.g., 2.8.0). Individual package changes are tracked via changelog but version bumps are synchronized across the project.

---

## Implementation Phases

1. **Phase 1**: Go CLI skeleton with `gen` command
2. **Phase 2**: Profile loader and merger
3. **Phase 3**: Package scanner (debian/secubox.yaml)
4. **Phase 4**: Manifest + Makefile generation
5. **Phase 5**: `build` command with stage orchestration
6. **Phase 6**: `fetch` command (GitHub releases)
7. **Phase 7**: `ota` command with A/B partition support
8. **Phase 8**: APT repo setup (apt.gk2.secubox.in)
9. **Phase 9**: Lintian integration in CI

---

## Success Criteria

- [ ] `secubox gen --board mochabin` produces valid manifest.yaml + Makefile
- [ ] `make image` builds bootable image from manifest
- [ ] Interactive wizard works for all 8 boards
- [ ] Profile inheritance resolves correctly
- [ ] Package requirements validated against tier constraints
- [ ] OTA updates work with A/B rollback
- [ ] apt.gk2.secubox.in serves multi-arch packages
- [ ] All packages pass lintian before publish
