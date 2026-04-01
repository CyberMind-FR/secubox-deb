# SecuBox-DEB Tools Reference

This document describes the build, deployment, and utility scripts in `image/` and `scripts/` directories.

---

## Image Building Tools (`image/`)

### build-live-usb.sh

Build a bootable live USB image for **amd64** systems (x86_64).

```bash
sudo bash image/build-live-usb.sh [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--suite SUITE` | Debian suite (default: bookworm) |
| `--out DIR` | Output directory (default: ./output) |
| `--size SIZE` | Total image size (default: 8G) |
| `--local-cache` | Use local APT cache for faster builds |
| `--no-kiosk` | Disable GUI kiosk mode |
| `--no-persistence` | Don't include persistent storage partition |
| `--no-compress` | Skip gzip compression (faster for testing) |
| `--preseed FILE` | Include preseed config archive |

**Output:**
- `secubox-live-amd64-bookworm.img` - Raw bootable image
- `secubox-live-amd64-bookworm.img.gz` - Compressed image

**Features:**
- UEFI + Legacy BIOS hybrid boot
- All SecuBox packages pre-installed
- Root autologin on console
- Optional GUI kiosk mode (Chromium-based)
- Network auto-detection at first boot

**Flash to USB:**
```bash
zcat output/secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

---

### build-rpi-usb.sh

Build a bootable USB/SD image for **Raspberry Pi** (arm64).

```bash
sudo bash image/build-rpi-usb.sh [OPTIONS]
```

**Options:**
| Option | Description |
|--------|-------------|
| `--board BOARD` | Target board: rpi4, rpi5, rpi400 (default: rpi4) |
| `--suite SUITE` | Debian suite (default: bookworm) |
| `--out DIR` | Output directory |
| `--size SIZE` | Image size (default: 8G) |
| `--local-cache` | Use local APT cache |
| `--no-kiosk` | Console-only mode |

**Supported Boards:**
- Raspberry Pi 4 Model B
- Raspberry Pi 400
- Raspberry Pi 5

**Output:**
- `secubox-rpi4-bookworm.img.gz` - Compressed bootable image

---

### build-image.sh

Build SecuBox images for **Marvell ARM boards** (MOCHAbin, ESPRESSObin).

```bash
sudo bash image/build-image.sh --board <BOARD> --out <OUTPUT>
```

**Options:**
| Option | Description |
|--------|-------------|
| `--board BOARD` | Target: mochabin, espressobin-v7, espressobin-ultra |
| `--out FILE` | Output .img path |
| `--suite SUITE` | Debian suite (default: bookworm) |

**Boards:**
- `mochabin` - Armada 7040, SecuBox Pro
- `espressobin-v7` - Armada 3720, SecuBox Lite
- `espressobin-ultra` - Armada 3720 Ultra

---

### build-installer-iso.sh

Build a Debian installer ISO with SecuBox preseed.

```bash
sudo bash image/build-installer-iso.sh [OPTIONS]
```

Creates an unattended Debian installer that:
- Partitions disk automatically
- Installs base Debian + SecuBox packages
- Configures network and services

---

### build-c3box-clone.sh

Clone an existing C3BOX installation for deployment.

```bash
sudo bash image/build-c3box-clone.sh <source-ip> <output-img>
```

---

### firstboot.sh

First boot initialization script (runs on target device).

- Generates SSH host keys
- Creates JWT secrets
- Sets unique hostname
- Initializes network config

---

### preseed-apply.sh

Apply preseed configuration to a running system.

```bash
sudo bash image/preseed-apply.sh <preseed-archive.tar.gz>
```

---

### create-vbox-vm.sh

Create a VirtualBox VM from a SecuBox image.

```bash
bash image/create-vbox-vm.sh <image.img> <vm-name>
```

---

## Package Building (`scripts/`)

### build-packages.sh

Build all SecuBox .deb packages.

```bash
bash scripts/build-packages.sh [SUITE] [ARCH]
```

**Arguments:**
- `SUITE` - Debian suite: bookworm, trixie (default: bookworm)
- `ARCH` - Architecture: amd64, arm64 (default: host arch)

**Output:** `output/debs/`

Builds packages in dependency order, starting with `secubox-core`.

---

### build-all-local.sh

Build all packages using local APT cache.

```bash
bash scripts/build-all-local.sh
```

---

### build-add-local.sh

Build and add a single package to the local repo.

```bash
bash scripts/build-add-local.sh <package-name>
```

---

## Deployment (`scripts/`)

### deploy.sh

Deploy packages to a SecuBox device via SSH.

```bash
bash scripts/deploy.sh <package|--all> <user@host> [--restart]
```

**Examples:**
```bash
# Deploy single package
bash scripts/deploy.sh secubox-crowdsec root@192.168.1.1

# Deploy and restart service
bash scripts/deploy.sh secubox-hub root@192.168.1.1 --restart

# Deploy all packages
bash scripts/deploy.sh --all root@192.168.1.1
```

---

## Frontend Porting (`scripts/`)

### port-frontend.sh

Copy frontend assets from secubox-openwrt source.

```bash
bash scripts/port-frontend.sh <module-name>
```

Copies `htdocs/` from the OpenWrt luci-app to `www/` in the Debian package.

---

### rewrite-xhr.py

Rewrite LuCI ubus calls to REST API calls.

```bash
python3 scripts/rewrite-xhr.py packages/secubox-<module>/www/
```

Transforms:
```javascript
// Before (LuCI/ubus)
rpc.declare({object: 'luci.crowdsec', method: 'get_stats'})

// After (REST)
fetch('/api/v1/crowdsec/stats')
```

---

## Theme Tools (`scripts/`)

### apply-crt-theme.py

Apply CRT/retro terminal theme to console CSS.

```bash
python3 scripts/apply-crt-theme.py <input.css> <output.css>
```

---

### apply-light-theme.py

Generate light mode variant of SecuBox theme.

```bash
python3 scripts/apply-light-theme.py
```

---

## Documentation (`scripts/`)

### generate-docs.py

Generate API documentation from FastAPI modules.

```bash
python3 scripts/generate-docs.py
```

Scans all `packages/*/api/main.py` and generates OpenAPI docs.

---

### screenshot-tool.py

Capture screenshots of SecuBox dashboards for documentation.

```bash
python3 scripts/screenshot-tool.py --url http://localhost:8080
```

Requires: `pip install -r scripts/requirements-screenshot.txt`

---

## Module Scaffolding (`scripts/`)

### new-package.sh

Scaffold a new SecuBox Debian package.

```bash
bash scripts/new-package.sh <module-name>
```

Creates:
```
packages/secubox-<module>/
├── api/main.py           # FastAPI stub
├── debian/
│   ├── control
│   ├── rules
│   ├── changelog
│   └── ...
└── www/                   # Frontend placeholder
```

---

### new-module.sh

Extended module scaffolding with tests and config.

```bash
bash scripts/new-module.sh <module-name>
```

---

## System Setup (`scripts/`)

### setup-local-cache.sh

Set up local APT cache for offline/faster builds.

```bash
bash scripts/setup-local-cache.sh
```

Creates `cache/repo/` with pooled .deb files.

---

### local-repo-add.sh

Add a .deb to the local repository.

```bash
bash scripts/local-repo-add.sh <package.deb>
```

---

### install-apparmor.sh

Install AppArmor profiles for SecuBox services.

```bash
sudo bash scripts/install-apparmor.sh
```

---

### install-audit.sh

Configure audit logging for CSPN compliance.

```bash
sudo bash scripts/install-audit.sh
```

---

## Nginx Tools (`scripts/`)

### retrofit-nginx-modular.sh

Convert monolithic nginx.conf to modular includes.

```bash
bash scripts/retrofit-nginx-modular.sh
```

---

### update-nginx-modular.sh

Update nginx module configs after package changes.

```bash
bash scripts/update-nginx-modular.sh
```

---

### fix-navbar.sh

Fix navigation bar links across all frontend modules.

```bash
bash scripts/fix-navbar.sh
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Build all packages | `bash scripts/build-packages.sh` |
| Build live USB (x86) | `sudo bash image/build-live-usb.sh` |
| Build RPi image | `sudo bash image/build-rpi-usb.sh --board rpi4` |
| Deploy to device | `bash scripts/deploy.sh --all root@192.168.1.1` |
| Create new package | `bash scripts/new-package.sh mymodule` |
| Setup local cache | `bash scripts/setup-local-cache.sh` |

---

## Environment Requirements

**Build Host:**
- Debian 12+ or Ubuntu 22.04+
- Packages: `debootstrap qemu-user-static dpkg-dev debhelper dh-python`
- Root access for image building

**Cross-compilation (arm64 on amd64):**
```bash
sudo apt install qemu-user-static binfmt-support
```

---

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind — https://cybermind.fr
