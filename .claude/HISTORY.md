# HISTORY — SecuBox-DEB Migration Log
*Tracking completed milestones with dates*

---

## 2026-04-30

### Session 79 — Performance Benchmark Suite

**Feature:** Created comprehensive performance testing infrastructure for ARM64 optimization

**Files Created:**
- `scripts/bench/api-latency.py` — API endpoint latency measurement (P50/P95/P99)
- `scripts/bench/memory-baseline.sh` — Per-service memory tracking (RSS/PSS/USS)
- `scripts/bench/startup-time.sh` — Service cold-start measurement via systemd
- `scripts/bench/cpu-profile.sh` — Flame graph generation with py-spy
- `scripts/bench/locustfile.py` — Load test scenarios for Locust framework
- `scripts/bench/README.md` — Documentation for benchmark suite

**Files Modified:**
- `scripts/README.md` — Added performance benchmarks section
- `remote-ui/round/agent/display/fallback/fallback_manager.py` — Changed disk icon to floppy

**Performance Targets Established:**
| Metric | ESPRESSObin | MOCHAbin |
|--------|-------------|----------|
| API P50 | < 100ms | < 50ms |
| API P99 | < 500ms | < 200ms |
| Service RSS | < 50MB | < 100MB |
| Cold start | < 5s | < 3s |

**MOCHAbin Analysis:**
- Identified critical state: Load 9.47, swap 99% exhausted
- Gitea using 7.6GB (93% VSZ) — memory leak or misconfiguration
- Created optimization plan in `.claude/plans/shimmering-chasing-abelson.md`

---

## 2026-04-29

### Session 78 — Migration Tools v2.1.0 + Services Module

**Feature:** Extended migration with 19 modules covering all SecuBox services

**Files Modified:**
- `scripts/migration-export.sh` — Added dns, databases, scripts, services modules (v2.1.0)
- `scripts/migration-import.sh` — Added import functions for all new modules (v2.1.0)

**New Migration Modules:**
| Module | Export | Import |
|--------|--------|--------|
| `dns` | BIND zones, Vortex RPZ, Unbound, AdGuard, Pi-hole | BIND/Unbound configs, zones |
| `databases` | SQLite, MySQL, PostgreSQL, Redis dumps | DB restoration with permissions |
| `scripts` | Custom scripts, systemd units, cron jobs, rc.local | Scripts, systemd service creation |
| `services` | All /srv/* directories (50+ services) | Service restoration, Docker compose |

**Services Module Captures:**
- Streamlit instances (`/srv/streamlit/*`)
- Metablogizer/Metabolizer apps
- Gitea/Git repositories with full history
- Docker compose configurations
- LXC container configs
- mitmproxy, config-vault, saas-relay

**Enhanced HAProxy Export:**
- conf.d modular architecture
- Certificate management
- Lua scripts and maps
- mitmproxy route integration

**Total Modules:** 19 (network, firewall, wireguard, crowdsec, dhcp, haproxy, nginx, certs, content, vhosts, users, state, git, media, mail, accounts, dns, databases, scripts, services)

**Eye Remote Deployment:**
- Deployed agent to ESPRESSObin at `/opt/eye-remote/`
- Fixed `secubox-status` to handle VLAN interfaces (`wan@eth0`)
- Restored WAN connectivity after migration via `/etc/netplan/10-wan.yaml`

---

### Session 77 — Migration Tools Extended (v2.0.0)

**Feature:** Extended migration to include Git, Media, Email, and User Accounts

**Files Modified:**
- `scripts/migration-export.sh` — Added git, media, mail, accounts modules (v2.0.0)
- `scripts/migration-import.sh` — Added import functions for new modules (v2.0.0)

**New Migration Modules:**
| Module | Export | Import |
|--------|--------|--------|
| `git` | /srv/git, /var/lib/git, Gitea/Gogs/GitLab | /srv/git, service configs |
| `media` | /srv/media, PeerTube, Jellyfin, Nextcloud | /srv/media, service restarts |
| `mail` | Maildir, Postfix, Dovecot, DKIM | Mail dirs, configs, crontabs |
| `accounts` | Home dirs, passwd/shadow, sudo, cron | User creation, home dirs |

**Export Test Results:**
- Git repositories: 4K
- Media files: 8K
- Email data: 4K
- User accounts: 6 users, 96K
- Total archive: 72K

**Note:** VBox VM SSH issue (banner timeout) prevented import test.

---

### Session 76 — Migration Tools Validation on VirtualBox

**Feature:** Tested migration import on VirtualBox VM

**Test Results:**
- Export: 66KB archive from SecuBox-OpenWrt (192.168.255.1)
- Transform: UCI → Debian format (netplan, nftables, dnsmasq, vhost.toml)
- Import: All modules successfully imported to VBox VM

**Imported Configurations:**
| Config | Destination | Status |
|--------|-------------|--------|
| Network | `/etc/netplan/00-secubox.yaml` | ✅ Imported |
| Firewall | `/etc/nftables.conf` | ✅ Imported (78 rules) |
| DNS/DHCP | `/etc/dnsmasq.d/secubox.conf` | ✅ Imported |
| VHosts | `/etc/secubox/vhosts/vhost.toml` | ✅ Imported (4 services, 3 redirects) |
| Content | `/srv/www/` | ✅ Imported (8KB) |
| Auth | `/etc/secubox/auth.toml` | ✅ Imported |

**Rollback Snapshot:**
- `/var/lib/secubox/rollback/pre-migration-20260429-112849`

**Expected Warnings:** Services not installed on test VM (CrowdSec, dnsmasq, HAProxy)

---

### Session 75 — Eye Remote Recovery System + Design Charter Update

**Feature:** Board recovery via serial boot protocols + unified design charter

**Files Created:**
- `remote-ui/round/agent/recovery/protocols/mvebu64boot.py` — 64-bit Marvell boot protocol
- `remote-ui/round/agent/recovery/protocols/xmodem.py` — XMODEM-CRC file transfer (prior session)
- `remote-ui/round/agent/recovery/protocols/kwboot.py` — Armada 3720 serial boot (prior session)
- `remote-ui/round/agent/recovery/recovery_controller.py` — Main recovery controller (prior session)

**Files Modified:**
- `remote-ui/round/agent/recovery/protocols/__init__.py` — Added Mvebu64Protocol export
- `remote-ui/round/agent/recovery/__init__.py` — Added RecoveryMethod + Mvebu64Protocol
- `docs/design/graphic-charter.md` — Updated to v2.0, synced with Eye Remote metrics
- `docs/hardware/smart-strip-v1.1.md` — Updated to v1.2, synced with graphic charter

**Recovery Protocols:**
| Protocol | SoC | Use Case |
|----------|-----|----------|
| kwboot | Armada 3720 | ESPRESSObin serial boot |
| mvebu64boot | Armada 7040/8040 | MOCHAbin 64-bit serial boot |
| XMODEM-CRC | All | File transfer to BootROM |

**Design Charter Updates:**
- Module → Metric mapping table for Eye Remote dashboard
- Alert thresholds unified across Eye Remote and Smart-Strip
- RGB values for SK6812 LEDs documented
- Pod layout diagram for round display
- Transport badge colors (OTG=ROOT, WiFi=MESH, SIM=gray)

**GitHub Issue #34:** Confirmed fixed (closed with resolution comment)

---

### Session 74 — Migration Data Saver v1.0.0

**Feature:** OpenWrt → SecuBox-DEB migration tools

**Files Created:**
- `scripts/migration-export.sh` — SSH export from SecuBox-OpenWrt
- `scripts/migration-import.sh` — Import to SecuBox-DEB with transformations
- `scripts/migration-transform.py` — UCI parser and format converters

**Files Modified:**
- `scripts/README.md` — Added migration documentation
- `.claude/WIP.md` — Updated with session 74

**Components:**
- UCIParser: Parse OpenWrt UCI config format
- NetworkTransformer: UCI network → netplan YAML
- FirewallTransformer: UCI firewall → nftables
- DHCPTransformer: UCI dhcp → dnsmasq.conf

**Supported Modules:**
network, firewall, wireguard, crowdsec, dhcp, haproxy, nginx, certs, content, vhosts, users, state

**Security Features:**
- AES-256 archive encryption
- SHA256 checksums
- Pre-import rollback snapshots
- Secrets separation

---

### Session 73 — Eye Remote Interactive v1.9.0

**Feature:** Multi-mode USB gadget display system for Eye Remote

**Files Modified:**
- `remote-ui/round/fb_dashboard.py` — Added mode detection, TTY terminal, flash progress, auth QR
- `packages/secubox-hub/debian/secubox-hub.service` — Changed to TCP binding (port 8001)
- `packages/secubox-hub/nginx/hub.conf` — Changed to TCP proxy
- `common/nginx/modules.d/hub.conf` — Changed to TCP proxy

**New Classes:**
- `SerialTerminal` — Read serial console output for TTY mode
- `FlashProgress` — Track USB mass storage transfer progress
- `AuthState` — QR code generation for backup authentication

**New Functions:**
- `get_gadget_mode()` — Read current USB gadget mode from /etc/secubox/gadget-mode
- `draw_terminal()` — Render serial terminal output on round display
- `draw_flash_progress()` — Render flash transfer progress bar
- `draw_auth_mode()` — Render QR code authentication screen

**Fixes:**
- Hub service changed from Unix socket to TCP (VM compatibility)
- FAQ and wiki updated with troubleshooting for common issues
- Kiosk launcher fixed for VM sandbox issues (--no-sandbox flag)
- Added public menu endpoint (`/api/v1/hub/public/menu`) for WebUI sidebar
- Fixed Pydantic 1.x compatibility in auth.py for require_jwt dependency
- Fixed "Failed to load menu: Invalid menu data" WebUI error

---

## 2026-04-28

### Session 72 — v2.1.1 Release: Build and API Fixes

**Release:** v2.1.1 — Critical fixes for VirtualBox and ESPRESSObin builds

**Issues Fixed:**

1. **Python Dependencies (Debian Bookworm Compatibility)**
   - Debian ships pydantic v1, but SecuBox requires v2
   - Added pip upgrade in build scripts: `pydantic>=2.0`, `fastapi>=0.100`, `uvicorn>=0.25`
   - Updated `secubox-core` postinst to auto-upgrade on install

2. **CORS Headers**
   - Added CORS headers to `common/nginx/secubox-proxy.conf`
   - Fixes cross-origin API requests from web UI

3. **Login Endpoint Path**
   - Fixed `login.html`: `/auth/login` → `/login`
   - Affects both main and portal login pages

4. **Eye Remote Display Imports**
   - Fixed `display/__init__.py` to import existing modules only
   - Changed service to use `display_manager.py` instead of `main.py`

5. **Eye Remote Rainbow Dashboard**
   - Icons in rainbow circle: BOOT, AUTH, WALL, ROOT, MESH, MIND
   - Radar sweep syncs with targeted module glow
   - Metric arcs aligned with corresponding icon colors
   - Concentric rings: red (outer) → purple (inner)

**Files Modified:**
- `common/nginx/secubox-proxy.conf` — CORS headers
- `packages/secubox-core/debian/postinst` — pip upgrade
- `packages/secubox-hub/www/login.html` — endpoint fix
- `packages/secubox-hub/www/portal/login.html` — endpoint fix
- `image/build-live-usb.sh` — version constraints
- `image/build-ebin-live-usb.sh` — version constraints
- `image/multiboot/build-amd64-rootfs.sh` — pip upgrade
- `remote-ui/round/agent/display/__init__.py` — import fix

**Wiki Updated:**
- `Home.md` — v2.1.1 announcement
- `Troubleshooting.md` — API 502/auth fix section
- `Eye-Remote.md` — HyperPixel dashboard info
- `Live-USB-VirtualBox.md` — troubleshooting section

**ESPRESSObin Live USB Rebuilt with Installer:**
- Built with `--embed-image` option for one-step eMMC flashing
- Embedded: `secubox-espressobin-v7-bookworm.img.gz` (573MB)
- Output: `secubox-espressobin-v7-live-usb.img.gz` (1.8GB)
- Flash command: `secubox-flash-emmc` from live USB
- Includes all v2.1.1 fixes (pydantic v2, CORS, login endpoints)

### Session 73 — Eye Remote Real Metrics Integration

**Feature:** Real metrics fetching from connected SecuBox via OTG/WiFi

**Components Created:**

1. **Metrics Fetcher** (`remote-ui/round/agent/api/metrics_fetcher.py`)
   - Async fetcher using aiohttp
   - Aggregates data from multiple SecuBox API endpoints
   - Connection state detection (OTG/WiFi/Disconnected)
   - Module-specific metrics (AUTH, WALL, MESH, etc.)
   - Double buffer for non-blocking display updates

2. **OTG Host Support for ESPRESSObin** (`packages/secubox-system/`)
   - `etc/udev/rules.d/90-secubox-eye-remote.rules` — Detects Pi Zero CDC-ECM
   - `usr/lib/secubox/eye-remote-connected.sh` — Configures 10.55.0.1/30
   - `usr/lib/secubox/eye-remote-disconnected.sh` — Cleanup handler

3. **Display Integration** (`remote-ui/round/agent/display/fallback/fallback_manager.py`)
   - Integrated MetricsFetcher for real data
   - Mode indicator shows connection type + latency
   - Module details show real vs local data source
   - Targeted metrics display with extra details

**API Endpoints Used:**
- `/api/v1/system/metrics` — System metrics
- `/api/v1/auth/stats` — Authentication stats
- `/api/v1/crowdsec/metrics` — CrowdSec decisions
- `/api/v1/wireguard/status` — WireGuard peers
- `/api/v1/dpi/stats` — DPI flow data

**Feature Plan Created:**
- `.claude/plans/eye-remote-otg-features.md` — 5 features roadmap:
  1. Real Metrics Display (implemented)
  2. OTG Tools Dashboard
  3. Gadget Parameters Control
  4. Storage Sync for Configs
  5. Self-Setup Portal

---

### Session 71 — Eye Remote Display System v2.3.0

**Feature:** Complete display state machine with fallback, splash, and radar modes

**Description:**
Implemented full Eye Remote display system with multiple visualization modes for Pi Zero W HyperPixel 2.1 Round (480x480). Includes connection state detection, animated splash screens, and local metrics radar visualization.

**Components Created:**

1. **Splash Screen System** (`display/splash.py`)
   - Animated phoenix logo for boot/halt/start/reboot states
   - Pulsing glow effects with fire colors
   - Progress indicator ring
   - Fallback phoenix symbol if logo missing

2. **Fallback Display Manager** (`display/fallback/fallback_manager.py`)
   - Connection state detection (OTG 10.55.0.1, WiFi secubox.local)
   - Four modes: OFFLINE, CONNECTING, ONLINE, COMMUNICATING
   - Local metrics radar with 6 concentric rings (AUTH, WALL, BOOT, MIND, ROOT, MESH)
   - 3D rotating cube with module icons when connected
   - Rainbow sweep line animation

3. **Touch Pattern Analyzer** (`display/fallback/touch_analyzer.py`)
   - Noise pattern analysis for HyperPixel touch panel
   - Coordinate and delta frequency tracking
   - Discovered Y-axis oscillation at stable X (~240-250)

4. **Touch Calibration Tool** (`display/fallback/touch_calibrate.py`)
   - Corner target display for manual calibration
   - Real-time coordinate overlay

5. **Radar Variants**
   - `radar_flashy.py` — Vibrant colors with 3D cube and icons
   - `radar_concentric.py` — Balanced metric arcs centered at 12 o'clock
   - `radar_rainbow.py` — Rainbow colorization with sweep
   - `radar_full.py` — Complete feature set

**Package Build:**
- Built all 128 SecuBox Debian packages successfully
- ESPRESSObin V7 image rebuild with packages slipstreamed

**Files Created:**
- `remote-ui/round/agent/display/splash.py`
- `remote-ui/round/agent/display/fallback/__init__.py`
- `remote-ui/round/agent/display/fallback/fallback_manager.py`
- `remote-ui/round/agent/display/fallback/touch_analyzer.py`
- `remote-ui/round/agent/display/fallback/touch_calibrate.py`
- `remote-ui/round/agent/display/fallback/radar_*.py` (5 variants)

**Version:** v2.3.0

---

## 2026-04-27

### Session 70 — Live Boot Complete Setup (v2.2.4-live)

**Feature:** Full live-boot implementation with squashfs and RAM boot

**Description:**
Completed full live-boot setup for Pi Zero Eye Remote storage.img. Installed live-boot package, rebuilt initramfs with live-boot scripts, created squashfs filesystem, and updated boot.scr with proper live boot parameters.

**Changes Made:**
1. Installed `live-boot` and `busybox` packages on ARM64 rootfs
2. Rebuilt initramfs with live-boot scripts included
3. Created `/live/filesystem.squashfs` (878MB) on data partition (sda4)
4. Updated boot.scr with live boot parameters:
   - `boot=live` - enables live-boot mode
   - `live-media=/dev/sda4` - partition with squashfs
   - `live-media-path=/live` - path to squashfs
   - `toram` - loads entire squashfs into RAM
   - DSA blacklist parameters preserved

**Partition Layout:**
- sda1 (512MB): EFI - kernel, initrd, dtbs, boot.scr
- sda2 (3GB): ARM64 rootfs (for reference)
- sda3 (3GB): x86 rootfs (for VirtualBox/QEMU)
- sda4 (9.5GB): Data + /live/filesystem.squashfs

**Wiki Fix:** Fixed sidebar link syntax from `[[Page|Display]]` to `[Display](Page)`

**Version:** v2.2.4-live

---

### Session 69 — Live RAM Boot Cmdline Fix (v2.2.4-pre2)

**Fix:** Added missing `boot=live live-media-path=/live` parameters to bootargs

**Description:**
Fixed critical issue where multiboot image was not configured for live RAM boot. The kernel command line was missing the required `boot=live` and `live-media-path=/live` parameters that the live-boot initramfs needs to work properly.

**Files Modified:**
- `image/multiboot/build-multiboot.sh` — Added live boot parameters to setenv bootargs

**Before:**
```bash
setenv bootargs "root=${rootpart} rootfstype=ext4 rootwait rootdelay=10 ..."
```

**After:**
```bash
setenv bootargs "boot=live live-media-path=/live root=${rootpart} rootfstype=ext4 rootwait rootdelay=10 ..."
```

**Version:** v2.2.4-pre2

---

### Session 68 — Multiboot Dual Boot Menu & Kernel Fix (v2.2.4-pre1)

**Feature:** Fixed ARM64 kernel installation and added interactive boot menu

**Description:**
Fixed critical bug where ARM64 kernel, initrd, and DTB files were not being copied to the EFI partition. Added interactive dual boot menu with 5-second timeout, offering Live RAM Boot (default) or Flash to eMMC option.

**Files Modified:**
- `image/multiboot/build-multiboot.sh` — Major fixes:
  - Fixed loop device release bug in `install_arm64_rootfs()` (was releasing before copying kernel)
  - Added `build_arm64_rootfs_debootstrap()` function with kernel installation
  - Added `copy_arm64_kernel_to_efi()` function to properly copy Image, initrd, DTBs
  - Updated boot.scr with interactive dual boot menu (5s timeout)
  - Added qemu-debootstrap and other optional dependency warnings
- `.github/workflows/build-multiboot.yml` — Added prerelease support, bumped version
- `wiki/_Sidebar.md` — Bumped version to v2.2.4-pre1

**Boot Menu Options:**
1. Live RAM Boot (default with 5s timeout)
2. Flash SecuBox to eMMC

**Version:** v2.2.4-pre1 (prerelease)

---

### Session 67 — Multiboot Wiki & Eye Remote Docs (v2.2.3)

**Feature:** Wiki documentation for multiboot live OS and Eye Remote integration

**Description:**
Added comprehensive wiki documentation for the multi-architecture boot system, including the new Multiboot wiki page, home page announcement banner, and sidebar navigation updates.

**Files Created:**
- `wiki/Multiboot.md` — Full documentation for multiboot live OS

**Files Modified:**
- `wiki/Home.md` — Added announcement banner for v2.2.3 multiboot
- `wiki/_Sidebar.md` — Added Multiboot and Eye Remote links, bumped version
- `image/multiboot/README.md` — Added Eye Remote integration section

**Changes:**
- Eye Remote Pi Zero architecture documented with ASCII diagrams
- Partition layout and boot flow explained
- Build instructions and GitHub Actions CI docs
- Troubleshooting section for common boot issues

---

### Session 66 — Multiboot GitHub Action (v2.2.3)

**Feature:** GitHub Actions workflow for automated multiboot image builds

**Description:**
Created automated CI/CD pipeline for building the multiboot live OS image with all SecuBox packages slipstreamed. Workflow builds .deb packages first, then creates the 16GB multiboot image with ARM64 and AMD64 rootfs partitions.

**Files Created:**
- `.github/workflows/build-multiboot.yml` — CI workflow for multiboot image

**Workflow Features:**
- Manual dispatch with configurable image size (8/16/32GB)
- Optional desktop environment inclusion
- Automatic .deb package builds from packages/
- Debootstrap-based ARM64 and AMD64 rootfs creation
- QEMU user-mode emulation for cross-arch chroot
- XZ compression for releases
- GitHub Release integration

**Version:** v2.2.3

---

### Session 65 — Multi-Boot Storage System (v2.2.2)

**Feature:** Multi-architecture boot system for Pi Zero Eye Remote storage

**Description:**
Created a multi-boot storage system that supports ARM64 (ESPRESSObin/MOCHAbin via U-Boot) and AMD64 (UEFI systems via GRUB) from a single USB storage device, with shared application data across both architectures.

**Partition Layout (16GB+):**
- P1: EFI/FAT32 (512MB) — Boot files for both architectures
- P2: ext4 (3GB) — ARM64 SecuBox rootfs
- P3: ext4 (3GB) — AMD64 SecuBox rootfs
- P4: ext4 (remaining) — Shared data partition

**Features:**
- U-Boot boot.scr with USB/MMC auto-detection for ARM64
- GRUB BOOTX64.EFI for AMD64 UEFI boot
- Shared data partition with bind mounts for /etc/secubox, /var/lib/secubox, /srv/secubox
- eMMC flasher image included for ARM64 installation
- Debootstrap-based AMD64 rootfs builder with SecuBox packages

**Files Created:**
- `image/multiboot/README.md` — Documentation
- `image/multiboot/build-multiboot.sh` — Main build script
- `image/multiboot/build-amd64-rootfs.sh` — AMD64 rootfs builder

**Commits:**
- `5cf69c0` — feat(multiboot): Add multi-architecture boot system with shared data

**Version:** v2.2.2

---

### Session 65 — Eye Remote USB Boot Fix (v2.2.1)

**Issue:** ESPRESSObin would not boot from Eye Remote USB mass storage. mv88e6xxx driver in infinite detection loop.

**Root Cause:** Live USB kernel had mv88e6xxx built-in (not a module), making `modprobe.blacklist` ineffective. The eMMC kernel has mv88e6xxx as a loadable module where blacklist works.

**Fix:**
- Replaced storage.img boot partition with eMMC kernel/initrd/DTB
- Replaced storage.img rootfs with working eMMC rootfs
- Updated boot scripts with extended blacklist for future builds

**Files Modified:**
- `board/espressobin-v7/boot-live-usb.cmd`
- `board/espressobin-v7/boot-usb.cmd`
- `board/espressobin-v7/boot.cmd`

**Commits:**
- `942196b` — fix(boot): Add mv88e6085 and initcall_blacklist to boot scripts

**Version:** v2.2.1

### Session 65 — HAProxy Service Restart Loop Fix

**Issue:** `secubox-haproxy.service` in restart loop with NAMESPACE error.

**Root Cause:** `RuntimeDirectory=haproxy` triggers systemd namespace setup which expects `/etc/haproxy` to exist. HAProxy is `Recommends:` not `Depends:`.

**Fix:**
- postinst creates `/etc/haproxy` if not present
- Removed `RuntimeDirectory=haproxy` from service
- Moved directory creation from import-time to startup event
- Increased RestartSec 5→30s

**Commits:**
- `4321a7c` — fix(haproxy): Prevent service restart loop
- `9f47e54` — fix(haproxy): Create /etc/haproxy and remove RuntimeDirectory=haproxy

---

## 2026-04-23

### Session 64 — Eye Remote USB OTG Network Fix (v2.1.1)

**Issue:** USB OTG network connection showed NO-CARRIER on Linux hosts despite Pi Zero interface being UP.

**Root Cause Analysis:**
The USB composite gadget creates two network interfaces on the Pi Zero:
- `usb0` → RNDIS function (Windows compatible)
- `usb1` → ECM function (Linux/Mac via cdc_ether driver)

Linux hosts use the ECM driver which maps to `usb1`. The old scripts configured `usb0` only, or both interfaces with the same IP (10.55.0.2/30), causing asymmetric routing where packets received on `usb1` could be replied via `usb0`.

**Fix Applied:**
- Configure only `usb1` (ECM) for Linux host compatibility
- Fallback to `usb0` only if `usb1` doesn't exist

**Files Modified:**
- `remote-ui/round/secubox-otg-gadget.sh` — Wait for and configure usb1
- `remote-ui/round/files/etc/secubox/eye-remote/gadget-setup.sh` — Same fix
- `remote-ui/round/agent/main.py` — `ensure_usb_network()` prefers usb1
- `remote-ui/round/agent/network_debug.py` — New debug script

**Results:**
- ✅ USB OTG network connectivity working (0.3ms latency)
- ✅ Display shows OTG mode instead of SIM
- ✅ Host NetworkManager connection persisted ("SecuBox OTG")

**Commits:**
- `48de244` — fix(eye-remote): Use usb1 (ECM) instead of usb0 for Linux hosts
- `f7b4bb4` — style(eye-remote): Adjust pod positions for hexagonal ring layout

**Version:** v2.1.1

---

## 2026-04-15

### Session 59 — EspressoBin eMMC Flasher & VirtualBox Graphics Fix

**v1.7.0 — EspressoBin Live USB with eMMC Flasher**
- Built EspressoBin V7 live USB image with embedded eMMC flasher
- Fixed SquashFS path issue (`/filesystem.squashfs` → `/live/filesystem.squashfs`)
- Fixed boot partition sizing for embedded images (dynamic sizing)
- Added `secubox-flash-emmc` command for easy eMMC flashing
- Successfully booted live USB and flashed to eMMC on real hardware

**v1.6.7.14 — VirtualBox VMSVGA Graphics Fix (Issue #29)**
- Root cause: VirtualBox with VMSVGA controller (default since VBox 6) needs `vmware` X11 driver
- `systemd-detect-virt` returns "oracle" but GPU shows "VMware SVGA" in lspci
- Created `secubox-x11-setup.service` for boot-time VM detection and X11 driver selection
- Updated kiosk launcher (v3.3) to defer to X11 setup service
- Driver selection: VBox+VMSVGA→vmware, VBox+VBoxVGA→modesetting, VMware→vmware, KVM→modesetting

**Slipstream Default Change**
- Changed `SLIPSTREAM_DEBS` default from 0 to 1 in `build-image.sh`
- All images now include 126 SecuBox packages by default

**Files Modified**
- `image/build-live-usb.sh` — X11 auto-setup service, vmware driver install
- `image/build-ebin-live-usb.sh` — Dynamic boot partition sizing, SquashFS path fix
- `image/build-image.sh` — SLIPSTREAM_DEBS=1 default
- `image/sbin/secubox-kiosk-launcher` — v3.3, vmware driver for VBox VMSVGA
- `image/systemd/secubox-kiosk.service` — depends on x11-setup service

**Builds In Progress**
- AMD64 live USB with VBox graphics fix
- EspressoBin eMMC image with 126 packages

---

## 2026-04-14

### Session 57 — Live USB Fixes & VirtualBox Testing

**v1.6.7.12 — Lenovo Boot Fix (Issue #26)**
- Added fallback EFI bootloader at `/EFI/BOOT/BOOTX64.EFI` for Lenovo/HP/Dell
- Fixed CI `--slipstream` flag in build-live-usb.sh
- Fixed banner alignment in secubox-flash-disk
- Tested and confirmed working on real Lenovo hardware

**v1.6.7.13 — VirtualBox Detection Fix (Issue #27)**
- Fixed VM detection using `systemd-detect-virt` ("oracle") instead of lspci
- VBox with VMSVGA was incorrectly detected as VMware
- Result: WebUI works in VBox, kiosk works on real hardware

**v1.6.7.14 — Network Auto-Discovery (Issue #28)**
- Enhanced `secubox-net-fallback` with LAN auto-discovery
- Probes common gateways (192.168.1.1, 192.168.0.1, 192.168.255.1, 10.0.0.1...)
- Auto-configures IP .250 on discovered subnet when DHCP fails
- Only uses 169.254.1.1 as last resort

**Wiki Updates**
- All Home pages (EN, FR, DE, ZH) now use `/releases/latest/download/` URLs
- Fixed script paths (scripts/ → image/)
- Removed hardcoded version numbers

**Builds Completed**
- x64: `secubox-live-amd64-bookworm.img` (8GB)
- ARM64: `secubox-espressobin-v7-live-usb.img` (539MB)

**GitHub Issues Closed**
- #26 Lenovo Error 1962 boot fix ✅
- #27 VBox kiosk not starting ✅
- #28 Network fallback 169.254.1.1 ✅

**Tags:** v1.6.7.12, v1.6.7.13, v1.6.7.14

---

## 2026-04-03

### Session 34 — Build Timestamp & System Fixes

**secubox-hub v1.2.0 — Build Timestamp Display**
- Added `_get_build_info()` API function to read `/etc/secubox/build-info.json`
- Dashboard header now displays build timestamp badge (date + time)
- Tooltip shows git commit hash, branch, and board type on hover
- Build scripts create `build-info.json` during image generation

**Build System Improvements**
- Fixed `build-live-usb.sh` package priority (prefers `output/debs` over cache)
- Fixed secubox-soc-web nginx config (installs to `secubox.d/` not `sites-available/`)
- Removed broken `secubox-repo.conf` symlink creation from postinst scripts

**Packages Updated**
- `secubox-hub_1.2.0-1~bookworm1_all.deb` — Build timestamp feature
- `secubox-soc-web_1.1.0-1_all.deb` — Nginx config path fix

**Release v1.4.0**
- Tag: `v1.4.0`
- Commit: `19ca292`
- All changes pushed to `origin/master`

---

## 2026-03-30

### Plymouth Boot Splash & Kiosk Fixes
- Added Plymouth boot splash with VT100/DEC PDP-style green phosphor theme
- Boot graphics now show DURING boot (not just at login)
- Fixed kiosk mode service configuration:
  - Changed from tty1 to tty7 (like standard display managers)
  - Proper VT allocation and switching
  - Better wlroots environment variables for VMs
  - Added tty supplementary group for DRM access
- Updated GRUB menu entries with `splash` parameter
- Added initramfs configuration for Plymouth framebuffer
- RPi 400 build: Added Plymouth support with ARM64 theme
- Tags: v1.3.6

### Previous Boot Fixes (v1.3.2-v1.3.5)
- Added VT100 retro CRT DEC PDP-style cyber splash
- Added hardware auto-check boot mode (`secubox.hwcheck=1`)
- Fixed boot hanging services with timeouts
- RPi 400 image builder with HDMI console autologin

---

## 2026-03-29

### Kiosk Mode Bug Fixes
- Fixed UID mismatch issue — service now detects actual kiosk user UID
- Fixed timing issue — cmdline handler defers package installation to after network
- Fixed marker file confusion (`.kiosk-installed` vs `.kiosk-enabled`)
- Updated build-live-usb.sh to fully setup kiosk when --kiosk flag used
- Improved start-kiosk.sh to wait for nginx/hub services (30s max)
- Service now uses `ConditionPathExists` to check enabled state

---

## 2026-03-28

### Network Auto-Detection & Preseed System
- Created `secubox-net-detect` — Auto-detection of WAN/LAN interfaces
  - Board detection: MochaBin, ESPRESSObin v7/Ultra, x64 VM/baremetal
  - Interface mapping based on device model (eth0=WAN, lan*=LAN)
  - Netplan generation for router/bridge/single modes
  - Link detection for x64 auto-discovery
- Board configurations created:
  - `board/x64-live/config.mk` — Live USB settings
  - `board/x64-vm/config.mk` — VM-specific settings
  - Netplan templates for each board
- Kernel cmdline handler:
  - `secubox-cmdline-handler` — Parses secubox.* kernel params
  - `secubox.netmode=router|bridge|single`
  - `secubox.kiosk=1` for GUI mode
- Kiosk GUI mode:
  - `secubox-kiosk-setup` — Install/enable/disable minimal GUI
  - Cage Wayland compositor + Chromium fullscreen
  - Perfect for touchscreen/kiosk deployments
- Updated `build-live-usb.sh`:
  - GRUB menu entries for Kiosk Mode, Bridge Mode
  - Installs net-detect, cmdline-handler, kiosk-setup
  - Systemd services for early boot configuration
- Updated `firstboot.sh` with network auto-detection integration

### secubox-localai v1.0.0 Complete
- Fifth Phase 8 package ported from OpenWRT
- FastAPI backend with 15+ endpoints
- Features: Container management, model gallery, chat completion
- OpenAI-compatible API proxy (/v1/chat/completions, /v1/completions)
- Model gallery with popular LLMs (Llama, Phi, Gemma, Mistral)
- CRT-light P31 phosphor theme with LocalAI purple accents
- Deployed to VM at https://localhost:9443/localai/
- **Total modules: 59**

### secubox-zigbee v1.0.0 Complete
- Fourth Phase 8 package ported from OpenWRT
- FastAPI backend with 20+ endpoints
- Features: Container management, device pairing, MQTT integration
- USB serial dongle detection and passthrough (/dev/ttyUSB*, /dev/ttyACM*)
- Device management: rename, remove, permit_join toggling
- CRT-light P31 phosphor theme with Zigbee green accents
- Deployed to VM at https://localhost:9443/zigbee/
- **Total modules: 58**

### secubox-lyrion v1.0.0 Complete
- Third Phase 8 package ported from OpenWRT
- FastAPI backend with 18+ endpoints
- Features: Container management, player control, library scanning
- Squeezebox JSON-RPC API integration for library stats
- CRT-light P31 phosphor theme with Lyrion orange accents
- Backup and restore functionality
- Deployed to VM at https://localhost:9443/lyrion/
- **Total modules: 57**

### secubox-jellyfin v1.0.0 Complete
- Second Phase 8 package ported from OpenWRT
- FastAPI backend with 15+ endpoints
- Features: Container management, library config, backup/restore
- CRT-light theme with Jellyfin blue accents
- Deployed to VM at https://localhost:9443/jellyfin/
- **Total modules: 56**

### secubox-ollama v1.0.0 Complete
- First Phase 8 package ported from OpenWRT
- FastAPI backend with 15+ endpoints
- Features: Container management, model pulling, chat, generation
- CRT-light P31 phosphor theme frontend
- Deployed to VM at https://localhost:9443/ollama/

### Migration Preparation Workflow Complete
- Created `.claude/REMAINING-PACKAGES.md` — 53 packages remaining inventory
- Classified packages by complexity: Easy (25), Medium (18), Complex (10)
- Identified 25 packages with different naming (already ported)
- Defined Phase 8 (21 apps), Phase 9 (22 tools), Phase 10 (10 security)
- Set priority: ollama → jellyfin → vault → homeassistant

### Previous Session Highlights
- 52 Debian packages complete (~1000+ API endpoints)
- All Phases 1-7 completed
- CVE Triage enhanced with CISA KEV, NVD, EPSS feeds
- CRT-light theme standardized across all modules
- Master-Link admin dashboard with P31 phosphor theme

---

## 2026-03-27

### Live ISO Boot Console Fixes
- Fixed flickering console on live ISO boot
- Masked 14 incompatible services for live mode
- Fixed getty autologin conflict
- Disabled martian packet logging

### C3Box Clone System
- `build-installer-iso.sh` — Hybrid Live USB / Headless Installer (886 lines)
- `export-c3box-clone.sh` — Export device configuration
- `build-c3box-clone.sh` — Combined export + ISO workflow

---

## 2026-03-26

### Master-Link System Complete
- Admin dashboard at `/master-link/admin.html`
- Token-based mesh enrollment
- Multi-master support (Debian + OpenWRT)
- `sbx-mesh-invite` and `sbx-mesh-join` CLI tools

### Socket Directory Fix
- `secubox-runtime.service` ensures `/run/secubox` exists

### ReDroid Integration
- Android in Container LXC setup scripts

---

## 2026-03-25

### Documentation Phase Complete
- API Reference in 3 languages (EN/FR/ZH)
- Module documentation for all 48 modules
- UI Guide with CRT theme documentation
- 45 module screenshots captured

### Go Daemon Organization
- Moved to `daemon/` directory structure
- Unix socket control server implemented
- `secuboxd` and `secuboxctl` binaries

---

## 2026-03-22

### Phase 5 — CSPN Hardening Complete
- AppArmor profiles for all services
- Kernel sysctl hardening
- Module blacklist
- auditd rules
- nftables DEFAULT DROP policy

---

## 2026-03-21

### Phase 3 — All 33 Modules Complete
- 1000+ API endpoints total
- All services running on VM
- Dynamic menu system
- Shared sidebar.js

### Phase 4 — APT Repo Complete
- apt.secubox.in configured
- reprepro + GPG signing
- CI publish workflow
- Metapackages (full/lite)

---

## 2026-03-20

### Phase 2 — Infrastructure Complete
- secubox_core Python library
- nginx reverse proxy template
- rewrite-xhr.py script

### Phase 1 — Hardware Bootstrap Complete
- build-image.sh for arm64 + amd64
- VirtualBox VM support
- Board configs (MOCHAbin, ESPRESSObin, VM)

---

## Project Statistics

| Metric | Value |
|--------|-------|
| Debian packages | 61 |
| API endpoints | ~1200+ |
| OpenWRT packages (total) | 103 |
| Remaining to port | 46 |
| Phases completed | 7 of 10 (Phase 8: 9/21) |
| Current release | v1.4.0 |
| Target completion | Phases 8-10 remaining |
