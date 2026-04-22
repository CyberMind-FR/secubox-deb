# WIP — Work In Progress
*Mis à jour : 2026-04-21 (Session 63)*

---

## 🔄 En cours — Eye Remote Full Integration v2.0.0

### Feature: Real Metrics + SecuBox WebUI + Multi-SecuBox Support

**Status:** 📋 Design complete, ready for implementation

**Spec:** `docs/superpowers/specs/2026-04-21-eye-remote-integration-design.md`

**GitHub Issue:** #31

#### Components to Implement

1. **secubox-eye-agent** (Eye Remote side)
   - [ ] Multi-SecuBox connection manager
   - [ ] Device token auto-authentication
   - [ ] Metrics bridge to dashboard
   - [ ] WebSocket command handler
   - [ ] Touchless pairing with QR
   - [ ] SSH auto-provisioning
   - [ ] Touch gestures for control

2. **secubox-eye-remote** (SecuBox module)
   - [ ] FastAPI endpoints for device management
   - [ ] Device registry + token manager
   - [ ] Pairing flow with QR generation
   - [ ] WebSocket for bidirectional commands
   - [ ] Serial console bridge (xterm.js)
   - [ ] WebUI management dashboard

3. **secubox-eye-gateway** (Dev tool)
   - [ ] Emulator mode (fake SecuBox API)
   - [ ] Gateway mode (proxy to real hardware)
   - [ ] Fleet mode (multi-SecuBox aggregation)
   - [ ] Metrics profiles (idle/normal/busy/stressed)

#### Key Features
- One Eye Remote → Multiple SecuBoxes
- Touchless pairing via QR code
- Eye Remote as controller (restart services, lockdown, etc.)
- Screenshot capture, OTA updates, serial console
- Device token authentication (no manual login)

#### Implementation Order
1. Phase 1: Eye Remote Agent — basic metrics from single SecuBox
2. Phase 2: SecuBox Module — API + device registry + pairing
3. Phase 3: WebUI — management dashboard
4. Phase 4: Control — bidirectional commands
5. Phase 5: Multi-SecuBox — device manager
6. Phase 6: Gateway — emulator and fleet tool
7. Phase 7: Polish — OTA, serial console, screenshot

---

## ✅ Complété (Session 63) — Framebuffer Dashboard v1.11.0

### S63-02 — Framebuffer Dashboard for Pi Zero W ✅

**Status:** ✅ Complete

#### Problem (v1.10.0)
Chromium browser requires NEON SIMD instructions which are not available on Pi Zero W (ARMv6). Error displayed:
> "The hardware on this system lacks support for NEON SIMD extensions"

#### Solution (v1.11.0)
Created Python framebuffer dashboard that renders directly to `/dev/fb0`:

1. **fb_dashboard.py** — PIL-based renderer
   - 6 circular module rings (AUTH/WALL/BOOT/MIND/ROOT/MESH)
   - Real-time clock and date
   - Hostname and uptime display
   - Animated metrics with realistic drift
   - OTG/WiFi/SIM mode indicator
   - SecuBox branding

2. **secubox-fb-dashboard.service** — systemd service
   - Starts after `hyperpixel2r-init.service`
   - Auto-restart on failure
   - Runs as root for framebuffer access

3. **Build script updated** (v1.11.0)
   - Installs `fb_dashboard.py` to `/usr/local/bin/`
   - Enables framebuffer dashboard service
   - No longer requires X11/Chromium for display

#### Files Created
- `remote-ui/round/fb_dashboard.py` — Framebuffer renderer
- `remote-ui/round/secubox-fb-dashboard.service` — systemd service

#### Test Results
- ✅ Dashboard auto-starts on boot
- ✅ All 3 services active: `pigpiod`, `hyperpixel2r-init`, `secubox-fb-dashboard`
- ✅ 6 module rings animate correctly
- ✅ Clock updates in real-time
- ✅ Simulation mode works (API integration ready)

---

## ✅ Complété (Session 63) — HyperPixel Display Fix v1.10.0

### S63-01 — Fix HyperPixel 2.1 Round Display Not Working ✅

**Status:** ✅ Complete

**Issue:** [GitHub Issue #30](https://github.com/CyberMind-FR/secubox-deb/issues/30)

#### Problem (v1.9.0)
HyperPixel 2.1 Round display was not showing any content despite framebuffer being correctly configured at 480x480. Two root causes identified:

1. **Wrong device tree overlay**: `/boot/firmware/config.txt` was using `dtoverlay=hyperpixel4` (rectangular HyperPixel 4.0) instead of `dtoverlay=hyperpixel2r` (round display)

2. **LCD init script failure**: The `hyperpixel2r-init` script used RPi.GPIO which relies on lgpio on Raspberry Pi OS Bookworm. lgpio throws "GPIO not allocated" errors when DPI overlay is active because the GPIO pins are claimed by the kernel for DPI output.

#### Solution (v1.10.0)

1. **Fixed overlay name**: Changed `dtoverlay=hyperpixel4` → `dtoverlay=hyperpixel2r` in config.txt generation

2. **Replaced RPi.GPIO with pigpio**: Rewrote `hyperpixel2r-init` script to use pigpio library which works correctly with Bookworm. pigpio accesses GPIO via the pigpiod daemon, bypassing lgpio's allocation issues.

3. **Fixed service dependencies**: Updated `hyperpixel2r-init.service` to:
   - Require `pigpiod.service`
   - Start after pigpiod is running
   - Enable both services at boot

4. **Added pigpio packages**: Added `python3-pigpio` and `pigpio` to the package list for QEMU chroot installation

5. **Fixed config.txt settings**:
   - Removed `,disable-i2c` flag from overlay
   - Added `display_default_lcd=1` setting

#### Files Modified
- `remote-ui/round/build-eye-remote-image.sh` — v1.9.0 → v1.10.0
- `remote-ui/round/hyperpixel2r-init` — Rewritten to use pigpio instead of RPi.GPIO
- `remote-ui/round/hyperpixel2r-init.service` — Added pigpiod dependency

#### Working config.txt (verified on hardware)
```
dtoverlay=hyperpixel2r
enable_dpi_lcd=1
display_default_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 55 480 0 15 60 15 0 0 0 60 0 19200000 6
framebuffer_width=480
framebuffer_height=480
dtparam=i2c_arm=on
dtparam=spi=on
dtoverlay=dwc2
```

#### Test Results
- ✅ GPIO pins correctly set to ALT2 (DPI function) after boot
- ✅ pigpiod service starts successfully
- ✅ hyperpixel2r-init script runs without errors
- ✅ ST7701S LCD controller initialized via software SPI
- ✅ Backlight ON (GPIO 19)
- ✅ Display shows framebuffer content (tested with solid colors and stripes)

---

## ✅ Complété (Session 62) — Eye Remote OFFLINE Image Builder

### S62-01 — Fix build-eye-remote-image.sh ✅

**Status:** ✅ Complete

**Issue:** [GitHub Issue #30](https://github.com/CyberMind-FR/secubox-deb/issues/30)

#### Problem (v1.8.0)
The script was incomplete, missing critical components for a working Eye Remote SD image.

#### Solution v1.8.1
Added firstrun script (rc.local) with package installation at first boot.

### S62-02 — OFFLINE Mode (v1.9.0) ✅

**Status:** ✅ Complete

#### Problem
v1.8.1 required internet at first boot to download ~500MB of packages (chromium, nginx, lightdm, etc.). This is not acceptable for field deployment.

#### Solution (v1.9.0 OFFLINE MODE)
Complete rewrite to pre-install all packages via QEMU chroot during image build:

1. ✅ **QEMU ARM emulation** — Uses qemu-user-static to run ARM binaries in chroot
2. ✅ **Image expansion** — Adds 1GB to rootfs for pre-installed packages
3. ✅ **Package pre-installation** — All dependencies installed at build time:
   - chromium-browser, xserver-xorg, xinit, lightdm, openbox
   - nginx, python3-pil, python3-pip, git, i2c-tools
   - fonts-dejavu-core, unclutter, x11-xserver-utils
4. ✅ **User creation in chroot** — secubox user with all groups configured
5. ✅ **All configurations pre-applied:**
   - LightDM autologin
   - Openbox autostart with Chromium kiosk
   - nginx site configuration
   - USB OTG gadget services
6. ✅ **No rc.local/firstrun** — System boots directly into kiosk mode
7. ✅ **GitHub Actions updated** — Added qemu-user-static, increased timeout to 60min

#### Files Modified
- `remote-ui/round/build-eye-remote-image.sh` — v1.8.1 → v1.9.0 (complete rewrite)
- `.github/workflows/build-eye-remote.yml` — Added QEMU deps, VERSION 1.9.0

#### Build Requirements
```bash
# Host system needs:
sudo apt install qemu-user-static binfmt-support parted e2fsprogs
```

#### Build & Test
```bash
# Download Raspberry Pi OS Lite (32-bit armhf)
wget https://downloads.raspberrypi.com/raspios_lite_armhf/images/\
raspios_lite_armhf-2024-11-19/2024-11-19-raspios-bookworm-armhf-lite.img.xz

# Build OFFLINE image
cd remote-ui/round
sudo ./build-eye-remote-image.sh \
    -i /path/to/raspios-lite.img.xz \
    -s "WiFiSSID" -p "WiFiPassword"

# Flash to SD card
sudo dd if=/tmp/secubox-eye-remote-1.9.0.img of=/dev/sdX bs=4M status=progress
```

#### Boot Time Comparison

| Version | First Boot | Requires Internet |
|---------|------------|-------------------|
| v1.8.0 | ~10 min (package download) | Yes |
| v1.8.1 | ~10 min (package download) | Yes |
| v1.9.0 | ~60 sec (ready immediately) | **No** |

---

## ✅ Completed (Session 61) — Eye Remote Documentation & Modes

### S61-01 — README.md Enhancement ✅

**Status:** ✅ Complete

Updated README.md with:
- Eye Remote concept (transformation from clock to remote control)
- 5 USB gadget modes documentation (Normal, Flash, Debug, TTY, Auth)
- ASCII mockups for each mode
- x64/amd64 live boot support
- Architecture diagrams showing USB OTG flow
- Script documentation for secubox-otg-gadget.sh and secubox-hid-keyboard.sh

### S61-02 — WIKI.md Enhancement ✅

**Status:** ✅ Complete

Added to WIKI.md:
- Complete modes documentation with technical details
- Visual mockups for all 5 modes (ASCII art)
- ConfigFS USB gadget configuration examples
- x64 Live Boot section with build instructions
- Quick command reference appendix

### S61-03 — Infographic Prompt File ✅

**Status:** ✅ Complete

Created `INFOGRAPHIC-PROMPT.md` with 7 Claude.ai prompts for:
1. Hero infographic (Eye Remote overview)
2. Mode comparison infographic
3. Quick Start howto
4. Architecture diagram
5. x64 Live Boot platforms
6. Auth Mode (Security Key) infographic
7. Social media banner

#### Files Created/Modified
- `remote-ui/round/README.md` — Enhanced with Eye Remote documentation
- `remote-ui/round/WIKI.md` — Enhanced with modes, mockups, x64 support
- `remote-ui/round/INFOGRAPHIC-PROMPT.md` — New file for image generation

---

## ✅ Completed (Session 60) — EspressoBin eMMC Boot Fixes

### S60-01 — HAProxy Service Restart Loop Fix ✅

**Status:** ✅ Complete

#### Problem
secubox-haproxy.service was failing with NAMESPACE errors:
```
Failed to set up mount namespacing: /run/systemd/unit-root/etc/haproxy: No such file or directory
```

#### Root Cause
`ReadWritePaths=/etc/haproxy /run/haproxy` in service file requires directories to exist for namespace setup, but haproxy is only `Recommends:` not `Depends:`.

#### Fix
Removed sandboxing directives that cause issues when haproxy not installed.

#### Files Modified
- `packages/secubox-haproxy/debian/secubox-haproxy.service`

---

### S60-02 — Network Fallback Script Fix ✅

**Status:** ✅ Complete

#### Problem
secubox-net-fallback was trying DHCP on `lan0`, `lan1` interfaces which are downstream LAN ports where SecuBox provides DHCP (not receives it).

#### Root Cause
Script processed `lan*` interfaces for DHCP, but these are LAN downstream ports on EspressoBin DSA switch.

#### Fix
Added logic to skip `lan*` interfaces and bridged interfaces:
```bash
case "$IFACE" in
    lan*)
        logger -t secubox-net "Skipping LAN interface $IFACE (downstream port)"
        continue
        ;;
esac
```

#### Files Modified
- `image/build-image.sh` — Updated secubox-net-fallback script

---

### S60-03 — Network Configuration Fix ✅

**Status:** ✅ Complete

#### Problem
1. dummy0 had IP 192.168.255.1/24 which conflicted with gateway
2. IP was assigned to eth0 (CPU port) instead of wan (physical DSA port)

#### Root Cause
- dummy0 IP overlapped with upstream gateway IP
- EspressoBin DSA topology: eth0 is CPU port, wan/lan0/lan1 are physical ports

#### Fix
- Changed dummy0 to use 10.55.255.1/24 (non-conflicting)
- Updated all board netplan configs to include dummy0
- Fixed IP assignment to wan interface instead of eth0

#### Files Modified
- `board/espressobin-v7/netplan/00-secubox.yaml`
- `board/espressobin-ultra/netplan/00-secubox.yaml`
- `board/mochabin/netplan/00-secubox.yaml`

---

### S60-04 — EspressoBin V7 Device Mapping Notes

**Important for future reference:**
- **U-Boot**: eMMC is `mmc 1`, SD card is `mmc 0`
- **Linux**: eMMC is `/dev/mmcblk0`, detected by presence of `boot0` partition
- **DSA Switch**: eth0 is CPU port (master), wan/lan0/lan1 are physical ports (slaves)
- **Network**: Assign IPs to `wan` interface, not `eth0`

---

## ✅ Completed (Session 59) — v1.7.0 Image Builds & Fixes

### S59-01 — EspressoBin Live USB with eMMC Flasher ✅

**Status:** ✅ Complete

#### Changes
- Built EspressoBin V7 live USB image with embedded eMMC flasher
- Fixed SquashFS path issue (`/filesystem.squashfs` → `/live/filesystem.squashfs`)
- Fixed boot partition sizing for embedded images (dynamic sizing based on embed size)
- Successfully booted live USB and flashed to eMMC on real hardware
- Added `secubox-flash-emmc` command for easy eMMC flashing

#### Files Modified
- `image/build-ebin-live-usb.sh` — Dynamic boot partition sizing, fixed SquashFS copy path
- `board/espressobin-v7/boot-live-usb.cmd` — Boot script for live USB

---

### S59-02 — Slipstream Packages by Default ✅

**Status:** ✅ Complete

#### Changes
- Changed `SLIPSTREAM_DEBS` default from 0 to 1 in `build-image.sh`
- All images now include 126 SecuBox packages by default
- Rebuilding EspressoBin eMMC image with full package set (in progress)

#### Files Modified
- `image/build-image.sh` — Default SLIPSTREAM_DEBS=1

---

### S59-03 — VirtualBox AMD64 Image Test ✅

**Status:** ✅ Working (console mode)

#### Notes
- AMD64 live USB boots in VirtualBox with bridged networking
- All 30+ SecuBox services start successfully
- Kiosk mode doesn't launch (expected - VirtualBox graphics drivers)
- Console mode works, Web UI accessible via port forwarding

---

### S59-04 — VBox Kiosk/WebUI Fix 🔄

**Status:** 🔄 In Progress (v1.6.7.14)

#### Issue
- Kiosk (Chromium) didn't launch in VirtualBox
- Root cause: VirtualBox VMSVGA controller needs `vmware` X11 driver, not `modesetting`
- The `systemd-detect-virt` returns "oracle" but lspci shows "VMware SVGA"

#### Fix Applied
1. Created `secubox-x11-setup.service` — runs before kiosk, auto-detects VM and configures X11 driver
2. Updated `build-live-usb.sh`:
   - Install `xserver-xorg-video-vmware` for VMSVGA support
   - Create `/usr/local/bin/secubox-x11-setup` for boot-time detection
   - Enable `secubox-x11-setup.service` in multi-user.target
3. Updated `secubox-kiosk.service`:
   - Added dependency: `After=secubox-x11-setup.service`
4. Updated `secubox-kiosk-launcher` (v3.3):
   - Defers to X11 setup service if config exists
   - VirtualBox + VMSVGA → `vmware` driver
   - VirtualBox + VBoxVGA → `modesetting` driver

#### Driver Selection Logic
| VM Type | GPU in lspci | X11 Driver |
|---------|--------------|------------|
| VirtualBox (oracle) | VMware SVGA | vmware |
| VirtualBox (oracle) | VBox VGA | modesetting |
| VMware | * | vmware |
| KVM/QEMU | * | modesetting |
| Bare metal | Intel/AMD/NVIDIA | modesetting |

#### Files Modified
- `image/build-live-usb.sh` — X11 auto-setup service
- `image/sbin/secubox-kiosk-launcher` — v3.3, vmware driver for VBox VMSVGA
- `image/systemd/secubox-kiosk.service` — depends on x11-setup service

#### Testing
- Rebuilding AMD64 live USB (in progress)
- Will test in VirtualBox with VMSVGA controller

---

### S59-05 — Remote UI / HyperPixel 2.1 Round Dashboard ✅

**Status:** ✅ Complete

#### Summary
Complete implementation of the SecuBox Remote UI — Round Edition dashboard for HyperPixel 2.1 Round Touch (480×480 px) on RPi Zero W. Provides real-time metrics visualization via concentric rings UI.

#### Deliverables (10/10)
1. ✅ **Backend metrics** — `packages/secubox-system/core/metrics.py` (no psutil, /proc only)
2. ✅ **Alerts engine** — `packages/secubox-system/core/alerts.py` (configurable thresholds)
3. ✅ **Pydantic schemas** — `packages/secubox-system/models/system.py` (AlertLevel, AlertItem, etc.)
4. ✅ **FastAPI router** — `packages/secubox-system/api/routers/metrics.py` (5 endpoints)
5. ✅ **Frontend dashboard** — `remote-ui/round/index.html` (480×480 SVG rings)
6. ✅ **Installation script** — `remote-ui/round/install_zerow.sh` (safe SD flash)
7. ✅ **Deployment script** — `remote-ui/round/deploy.sh` (SSH + nginx patch)
8. ✅ **systemd service** — `remote-ui/round/secubox-remote-ui.service` (memory limited)
9. ✅ **API integration** — Already in `api/main.py` (metrics router included)
10. ✅ **Documentation** — `[remote_ui]` section in `secubox.conf.example`

#### Key Features
- Lightweight metrics collection via /proc filesystem (no psutil overhead)
- 6-ring concentric display: AUTH → WALL → BOOT → MIND → ROOT → MESH
- Central CPU percentage with color-coded alerts (nominal/warn/crit)
- JWT authentication with scope-based access control
- Simulation mode for offline testing
- Safe install script (refuses /dev/sda, /dev/nvme0n1, /dev/mmcblk0)

#### Files Created/Modified
- `packages/secubox-system/core/metrics.py` — SystemMetrics class
- `packages/secubox-system/core/alerts.py` — AlertsEngine class
- `packages/secubox-system/models/system.py` — Pydantic response models
- `packages/secubox-system/models/__init__.py` — Exports
- `packages/secubox-system/api/routers/metrics.py` — 5 FastAPI endpoints
- `packages/secubox-system/api/routers/__init__.py` — Router exports
- `remote-ui/round/index.html` — Full circular dashboard
- `remote-ui/round/install_zerow.sh` — SD card flash script
- `remote-ui/round/deploy.sh` — SSH deployment script
- `remote-ui/round/secubox-remote-ui.service` — systemd unit
- `secubox.conf.example` — Added [remote_ui] section with thresholds config

---

### S59-06 — Remote UI OTG Composite Connection ✅

**Status:** ✅ Complete

#### Summary
Implemented USB OTG composite gadget connection between RPi Zero W (Remote UI) and SecuBox host. Provides CDC-ECM (Ethernet over USB @ 10.55.0.0/30) plus CDC-ACM (serial console @ 115200 baud) with automatic WiFi fallback.

#### Deliverables

**Gadget Side (RPi Zero W):**
1. ✅ `remote-ui/round/secubox-otg-gadget.sh` — configfs libcomposite setup script
2. ✅ `remote-ui/round/secubox-otg-gadget.service` — systemd oneshot (loads libcomposite, usb_f_ecm, usb_f_acm)
3. ✅ `remote-ui/round/secubox-serial-console.service` — Getty on /dev/ttyGS0 @ 115200

**Host Side (SecuBox):**
4. ✅ `remote-ui/round/90-secubox-otg.rules` — udev rules (renames interface to secubox-round, creates /dev/secubox-console symlink)
5. ✅ `remote-ui/round/secubox-otg-host-up.sh` — udev hook (configures 10.55.0.1/30, notifies API)

**Backend API:**
6. ✅ `packages/secubox-system/models/system.py` — TransportType enum, RemoteUIConnectedRequest, RemoteUIStatusResponse
7. ✅ `packages/secubox-system/core/remote_ui.py` — RemoteUIManager singleton with probe/failover logic
8. ✅ `packages/secubox-system/api/routers/remote_ui.py` — REST endpoints (/status, /connected, /disconnected, /probe, /serial/info)

**Frontend:**
9. ✅ `remote-ui/round/index.html` — TransportManager class with OTG/WiFi failover, transport badge UI

**Documentation:**
10. ✅ `remote-ui/round/README.md` — Quick-start guide
11. ✅ `remote-ui/round/WIKI.md` — Comprehensive technical documentation

#### Key Features
- **Deterministic MAC addresses** from RPi serial number (02:sb:xx:xx:xx:xx)
- **OTG priority transport** with 3-timeout failover to WiFi
- **Separate JWT tokens** per transport
- **30-second reprobe** interval to resume OTG when reconnected
- **Transport badge** visual indicator (green OTG / blue WiFi / gray SIM)

#### Files Created/Modified
- `remote-ui/round/secubox-otg-gadget.sh` (new)
- `remote-ui/round/secubox-otg-gadget.service` (new)
- `remote-ui/round/secubox-serial-console.service` (new)
- `remote-ui/round/90-secubox-otg.rules` (new)
- `remote-ui/round/secubox-otg-host-up.sh` (new)
- `packages/secubox-system/models/system.py` (updated)
- `packages/secubox-system/models/__init__.py` (updated)
- `packages/secubox-system/core/remote_ui.py` (new)
- `packages/secubox-system/api/routers/remote_ui.py` (new)
- `packages/secubox-system/api/routers/__init__.py` (updated)
- `packages/secubox-system/api/main.py` (updated)
- `remote-ui/round/index.html` (updated - TransportManager)
- `remote-ui/round/README.md` (new)
- `remote-ui/round/WIKI.md` (new)
- `secubox.conf.example` (updated - [remote_ui] section)

---

### S59-07 — Remote UI RPi Zero W + HyperPixel Debugging ✅

**Status:** ✅ Complete (April 15, 2026)

#### Issues Discovered & Fixed

1. **Wrong RPi image (64-bit)** — Zero W requires 32-bit armhf, not arm64
   - Correct URL: `https://downloads.raspberrypi.com/raspios_lite_armhf/images/raspios_lite_armhf-2024-11-19/2024-11-19-raspios-bookworm-armhf-lite.img.xz`

2. **HyperPixel black screen — KMS overlay is the solution!**
   - Non-KMS overlay (hyperpixel2r) has GPIO conflicts on Bookworm
   - The non-KMS overlay's i2c@0 claims GPIO 10,11 which are needed for SPI init
   - The backlight driver also has pinctrl conflicts with SPI/I2C
   - **SOLUTION:** Use KMS overlay (`vc4-kms-v3d` + `vc4-kms-dpi-hyperpixel2r`)
   - KMS handles panel init in kernel — no userspace script needed
   - Config.txt:
     ```
     dtoverlay=vc4-kms-v3d
     dtoverlay=vc4-kms-dpi-hyperpixel2r
     display_auto_detect=0
     hdmi_blanking=2
     gpu_mem=128
     ```

3. **USB OTG network NO-CARRIER**
   - NetworkManager ignores ifupdown config on Bookworm
   - Fix: Created `usb0-up.sh` script that directly configures the interface
   - Service: `usb0-up.service` runs after `secubox-otg-gadget.service`

4. **SSH Permission denied**
   - RPi OS Bookworm requires `userconf` file in boot partition
   - Format: `user:hashed_password`
   - Default: `pi:raspberry` (hash in install script)

5. **install_zerow.sh refusing mmcblk0**
   - Script's FORBIDDEN_DEVICES check too conservative
   - Fix: Smart detection based on actual root filesystem location

6. **Host IP keeps disappearing**
   - NetworkManager removes manually added IPs on USB interfaces
   - Fix: `sudo nmcli device set enxXXXX managed no` before adding IP

#### Files Modified
- `remote-ui/round/install_zerow.sh` — Use KMS overlay by default, all fixes integrated
- `remote-ui/round/README.md` — Updated troubleshooting for KMS overlay
- `remote-ui/round/secubox_dashboard.py` — **NEW** Python/PIL dashboard (no Chromium!)

#### Testing Status
- [x] SD card flashing works
- [x] USB OTG interface appears on host
- [x] SSH connection works (pi:raspberry via userconf)
- [x] HyperPixel display works with KMS overlay
- [x] Python dashboard running with live metrics

#### Technical Notes
- Framebuffer is RGB565 (16-bit), not 32-bit BGRA
- KMS overlay provides DRM `/dev/fb0` at 480x480
- Dashboard uses PIL for rendering, direct FB write for display
- No X11, no Chromium = lightweight (~18MB RAM)

---

## ⬜ Next Up

1. **Deploy dashboard to Zero W** — Now that display works
2. **Rebuild EspressoBin eMMC with 126 packages** — In progress
3. **Test VBox kiosk after rebuild** — Verify vmware driver works
4. **Dashboard real data display** — Memory, storage, IPs, versions

---

## ✅ Fait (Session 58) — v1.7.0 Phase 11

### P11-01 — Version Display in Kiosk Header/Footer ✅

**Status:** ✅ Implemented

#### Changes
- Added **footer bar** to dashboard (`index.html`) showing:
  - SecuBox version
  - Boot mode (kiosk/console)
  - Auth mode (ZKP/Standard)
  - System uptime
- Added new API endpoints:
  - `GET /api/v1/hub/boot_mode` — Returns kiosk/console status
  - `GET /api/v1/hub/auth_mode` — Returns ZKP/Standard auth status
- Updated version to **v1.7.0** across:
  - `image/build-live-usb.sh` (SECUBOX_VERSION)
  - `packages/secubox-hub/api/main.py` (FastAPI version)
  - `packages/secubox-hub/www/shared/sidebar.js` (VERSION constant)
  - `packages/secubox-hub/www/index.html` (footer default)

#### Files Modified
- `packages/secubox-hub/www/index.html` — Footer with version/mode display
- `packages/secubox-hub/api/main.py` — boot_mode + auth_mode endpoints
- `packages/secubox-hub/www/shared/sidebar.js` — Version constant
- `image/build-live-usb.sh` — Version bump to 1.7.0

---

### P11-03 — Boot Mode Indicator on Splash ✅

**Status:** ✅ Implemented

#### Changes
- Updated Plymouth theme (`secubox-simple.script`) to show boot mode
- Added `send_plymouth_mode()` function to cmdline-handler
- Sends "KIOSK MODE", "TUI MODE", or "CONSOLE MODE" to Plymouth during boot

#### Files Modified
- `image/plymouth/secubox-simple/secubox-simple.script` — Boot mode display
- `image/sbin/secubox-cmdline-handler` — Plymouth message function

---

### P11-07/P11-08 — Plymouth & GRUB Version Display ✅

**Status:** ✅ Implemented

#### Changes
- Plymouth theme updated to show v1.7.0
- GRUB menu entries already use `${SECUBOX_VERSION}` variable

#### Files Modified
- `image/plymouth/secubox-simple/secubox-simple.script` — Version v1.7.0

---

### P11-09 — Boot Mode Selection Descriptions ✅

**Status:** ✅ Implemented

#### Changes
- Added descriptive echo messages to GRUB menu entries
- Each boot option now shows brief explanation when selected:
  - Console: "Access via SSH or Web UI"
  - Kiosk: "Fullscreen GUI on HDMI/display"
  - TUI: "Text User Interface mode - keyboard navigation"
  - Bridge: "Transparent inline sniffer"
  - Safe Mode: "Basic video driver, no persistence"
  - Install: "WARNING: This will erase the target disk!"
  - To RAM: "Faster operation, USB can be removed after boot"

#### Files Modified
- `image/build-live-usb.sh` — GRUB menu entry descriptions

---

### P11-04 — Auth Mode Feedback on Login Page ✅

**Status:** ✅ Implemented

#### Changes
- Added auth mode indicator to login page showing "Standard" or "ZKP"
- Added version badge at bottom of login form
- Created public API endpoint: `GET /api/v1/hub/public/info`
  - Returns version, auth_mode, name (no auth required)
- Login page fetches and displays auth mode dynamically

#### Files Modified
- `packages/secubox-hub/www/portal/login.html` — Auth mode badge + version
- `packages/secubox-hub/api/main.py` — Public info endpoint

---

### Emoji Icon Fix ✅

**Status:** ✅ Implemented — USB ready for testing

#### Issue
- Icons/emojis in sidebar menus rendering as empty boxes (□)
- Missing emoji font-family CSS declarations

#### Fix Applied
- Added `Noto Color Emoji` as first font in font-family stack
- Wrapped category icons in `.cat-icon` span element with emoji font
- Updated both `sidebar.css` (dark) and `sidebar-light.css` (light) themes
- Added explicit `fonts-noto-color-emoji` installation in build script
- Applied to: `.logo-icon`, `.nav-section-title .cat-icon`, `.nav-item .icon`

#### Files Modified
- `packages/secubox-hub/www/shared/sidebar.css` — Emoji font-family for icons
- `packages/secubox-hub/www/shared/sidebar-light.css` — Same for light theme
- `packages/secubox-hub/www/shared/sidebar.js` — Cat-icon wrapper span
- `image/build-live-usb.sh` — Explicit emoji font installation

#### Build & Flash
- ✅ Image built: `output/secubox-live-amd64-bookworm.img.gz` (1.2G)
- ✅ USB flashed to `/dev/sda` (DataTraveler 3.0, 28.8G)
- ❌ Hardware test revealed service crashes (see below)

---

### Boot Service Crashes — v1.7.0.1 Fix 🔄

**Status:** 🔄 Building with fixes

#### Issues Found (from USB boot test screenshots)

| Service | Error | Root Cause |
|---------|-------|------------|
| `secubox-avatar.service` | `ImportError: email-validator is not installed` | pydantic `EmailStr` requires `email-validator` |
| `secubox-hardening.service` | `OSError: [Errno 30] Read-only file system: /var/lib/secubox/` | Live squashfs is read-only |
| `secubox-jitsi/matrix/mesh.service` | `Failed to locate executable /usr/bin/uvicorn` | pip installs to `/usr/local/bin/` |
| `secubox-haproxy/threats/metrics.service` | `Failed at step NAMESPACE` | Sandboxing on read-only fs |

#### Fixes Applied

1. **Missing email-validator** — Added to pip install:
   ```bash
   pip3 install 'pydantic[email]' email-validator
   ```

2. **Read-only filesystem** — Created systemd tmpfs mount:
   ```ini
   # /etc/systemd/system/var-lib-secubox.mount
   [Mount]
   What=tmpfs
   Where=/var/lib/secubox
   Type=tmpfs
   Options=mode=0755,uid=secubox,gid=secubox,size=100M
   ```

3. **uvicorn PATH mismatch** — Added symlink:
   ```bash
   ln -sf /usr/local/bin/uvicorn /usr/bin/uvicorn
   ```

4. **Network still getting 169.254.x.x** — Fixed grep bug in fallback script:
   ```bash
   # BUG: grep -q produces no output to pipe
   if ip addr show "$IFACE" | grep -q "inet " | grep -v "169.254"; then
   # FIX: Remove -q from first grep
   if ip addr show "$IFACE" | grep "inet " | grep -qv "169.254"; then
   ```

5. **Enhanced emoji font support** — Added:
   - `fonts-symbola`, `fonts-noto-core`, `fonts-noto` packages
   - Symbola as fontconfig fallback
   - @font-face with system emoji fallback in CSS

#### Files Modified
- `image/build-live-usb.sh` — pip packages, symlinks, tmpfs mount unit, fonts

#### Build Status
- 🔄 Rebuilding image with fixes...

---

### ⬜ Next Up (Phase 11)

| ID | Task | Status |
|----|------|--------|
| P11-02 | Auth mode indicator in kiosk UI | ✅ (via P11-01 footer) |
| P11-05 | Auth mode toggle in settings | ⬜ |
| P11-06 | ZKP status in dashboard | ⬜ |

---

## ✅ Terminé (Session 57)

### v1.6.7.14 — Network Auto-Discovery (GitHub Issue #28)

**Status:** ✅ Released

#### Fix Applied
- **LAN auto-discovery** when DHCP fails
- Probes common gateways: `192.168.1.1`, `192.168.0.1`, `192.168.255.1`, `10.0.0.1`...
- If gateway responds → auto-configure IP `.250` on that subnet
- Only falls back to `169.254.1.1` as last resort

#### Files Modified
- `image/build-live-usb.sh` — Enhanced `secubox-net-fallback` script

---

### v1.6.7.13 — VirtualBox Kiosk Fix (GitHub Issue #27) ✅

**Status:** ✅ Closed (semi-fixed)

#### Test Results
- ✅ **Real hardware kiosk** — Works perfectly
- ✅ **VirtualBox WebUI** — Works (https://localhost:9443)
- ❌ **VirtualBox kiosk** — Console only (acceptable limitation)

#### Fix Applied
- **VirtualBox detection** — Use `systemd-detect-virt` ("oracle") instead of lspci
- VBox with VMSVGA was incorrectly detected as VMware

---

### v1.6.7.12 — Lenovo Boot Fix (GitHub Issue #26) ✅

**Status:** ✅ Released and tested

#### Test Results
- ✅ **Kiosk on real hardware** — Works!
- ✅ **Lenovo install test** — PASSED! Error 1962 fix confirmed

#### Fixes
- Fallback EFI bootloader at `/EFI/BOOT/BOOTX64.EFI`
- CI `--slipstream` flag fix
- Wiki updated to use `/releases/latest/` URLs

---

### Builds Completed ✅

| Build | Image | Size |
|-------|-------|------|
| x64 | `secubox-live-amd64-bookworm.img` | 8.0G |
| ARM64 | `secubox-espressobin-v7-live-usb.img` | 539M |

---

### GitHub Issues (Session 57)

| Issue | Title | Status |
|-------|-------|--------|
| #26 | Lenovo Error 1962 boot fix | ✅ Closed |
| #27 | VBox kiosk not starting | ✅ Closed |
| #28 | Network fallback 169.254.1.1 | 📝 Addressed |

---

## ✅ Terminé (Session 56)

### v1.6.7.11 — Kiosk Bug Fixes ✅ (GitHub Issue #24 CLOSED)

**Tested on real hardware: KIOSK LOADING OK ✅**

#### Fixes Applied
1. ✅ **systemd `StartLimitIntervalSec`** — fixed syntax (was `StartLimitInterval`)
2. ✅ **Platform detection message** — shows "bare-metal (native)" instead of "none"
3. ✅ **Lock file cleanup** — PID-based tracking, auto-removes stale locks
4. ✅ **Services masked** — picobrew, voip, zigbee, newsbin (already in build script)

#### Files Modified
- `image/systemd/secubox-kiosk.service` — StartLimitIntervalSec fix
- `image/sbin/secubox-kiosk-launcher` — v3.2 with platform name + PID lock

#### Release
- Git commit: `66ad146`
- Git tag: `v1.6.7.11` pushed to origin
- USB image built and tested successfully

---

## ✅ Terminé (Session 55)

### v1.6.7.10 — KIOSK WORKING ON REAL HARDWARE ✅

**Tested on real hardware (Intel HD Graphics 630):**
- ✅ X.Org started with modesetting driver
- ✅ Chromium launched in fullscreen kiosk mode
- ✅ WebUI loaded and displayed
- ✅ Authentication worked
- ✅ No VT freeze
- ✅ VT switching works (Ctrl+Alt+F1/F7)

**Key fixes that worked:**
- VM vs real hardware GPU detection
- Systemd restart rate limiting (even with syntax warning)
- Longer restart delay (15s)
- Console feedback before X11 start
- Lock file mechanism (though needs cleanup fix)

### v1.6.7.9 — Real Hardware Kiosk Fix (Partial)

#### Fixes Applied
**`image/sbin/secubox-kiosk-launcher`**:
- Removed `pipefail` for graceful degradation
- Added **failure tracking** with 3-attempt limit
- Auto-disables kiosk after 3 failures (prevents boot loop)
- Added real hardware GPU detection (Intel, AMD, NVIDIA, fbdev, vesa)

**`image/build-live-usb.sh`**:
- Added `secubox-ui-manager` and `secubox-ui-health` to masked services

---

## ✅ Terminé (Session 54-55)

### v1.6.7.8 — Kiosk Improvements ❌
- Built and flashed to USB
- Tested on VirtualBox: FAILED (same issues as real HW)
- Tested on real hardware: FAILED (VT freeze)
- **Both environments:** Kiosk not starting at all

### v1.6.7.6 — cmdline-handler Fix for X11 ✅

---

## ✅ Terminé cette session (Session 53)

### v1.6.7.4 — Fix Boot Input Freeze (Critical) ✅

#### Problem
Both VirtualBox AND real hardware frozen at boot:
- No keyboard input working
- No login prompt visible
- No VT switching
- Kiosk not starting

#### Root Cause (ACTUAL)
GRUB Kiosk entry used `systemd.unit=graphical.target` but **no display manager** was installed.
systemd waited forever for graphical.target → getty never started → no input.

#### Fix Applied (v1.6.7.4)
**`image/build-live-usb.sh`** — Removed `systemd.unit=graphical.target` from Kiosk GRUB entry:
```bash
# BROKEN:
linux ... secubox.kiosk=1 systemd.unit=graphical.target

# FIXED:
linux ... secubox.kiosk=1
# (kiosk service is in multi-user.target, not graphical.target)
```

Also applied in v1.6.7.3:
- Reverted getty `Type=idle` to simple service
- Enabled backup TTYs (tty2-6) for emergency access

---

## ✅ Terminé cette session (Session 52)

### VirtualBox Debug Logging ✅

#### Problem
VirtualBox VM boots to console instead of kiosk, while real hardware works fine.
Need diagnostic info to trace X11/graphics issues in VirtualBox.

#### Fix Applied
**`image/sbin/secubox-kiosk-launcher`** — Added comprehensive debug logging:
1. `generate_debug_report()` function creates `/tmp/kiosk-debug-YYYYMMDD-HHMMSS.log`
2. Debug report captures:
   - System info (hostname, kernel, arch)
   - Virtualization detection (systemd-detect-virt, DMI)
   - Graphics hardware (lspci VGA/display)
   - DRM/KMS devices (/dev/dri/)
   - Framebuffer status
   - TTY status
   - Kiosk flag files
   - X11 config and binaries
   - Loaded kernel modules (video-related)
   - Systemd kiosk service status
   - Journal logs
   - Xorg.0.log (when available)
3. VM detection logging at X11 start
4. Enhanced error reporting when Xorg fails:
   - Appends failure details to debug report
   - Logs dmesg graphics entries
   - Captures VT status

#### Debug Report Location
```
/tmp/kiosk-debug-latest.log → symlink to most recent
/tmp/kiosk-debug-YYYYMMDD-HHMMSS.log → timestamped reports
```

#### To Read Debug Info After Failed Boot
1. Login via TTY1 (autologin)
2. Run: `cat /tmp/kiosk-debug-latest.log`
3. Or check journalctl: `journalctl -t secubox-kiosk`

---

## ✅ Terminé cette session (Session 51)

### SecuBox v1.6.7.2 — Advanced Overlay Installer ✅

#### Overview
Transformed SecuBox from a simple live-boot system to a production-grade appliance with:
- Multi-layer overlay architecture for clean separation of system/config/data
- Versioned snapshots for rollback capability
- RAM acceleration for responsive UI
- Factory reset without full reinstall

#### Files Created
1. **`image/partition-overlay.sh`** — GPT partition layout script for overlay mode
2. **`image/sbin/secubox-overlay-init`** — Boot-time overlay filesystem composer
3. **`image/sbin/secubox-snapshot`** — Versioned snapshot manager (create/restore/delete/prune)
4. **`image/sbin/secubox-ramcache`** — RAM cache preload utility for fast UI
5. **`image/sbin/secubox-factory-reset`** — Clean reset without reflashing
6. **`image/initramfs/overlay-hooks`** — Initramfs hooks installer
7. **`image/initramfs/overlay-init-premount`** — Early boot overlay preparation
8. **`image/initramfs/overlay-local-bottom`** — Persistent mount setup

#### Files Modified
- **`image/build-live-usb.sh`** — Added `--overlay` flag, overlay partition layout, initramfs hooks
- **`packages/secubox-hub/api/main.py`** — Version bump to 1.6.7.2
- **`image/sbin/secubox-kiosk-launcher`** — Version bump

#### Overlay Partition Layout (--overlay flag)
```
ESP (512MB)      — UEFI boot
SYSTEM (2GB)     — SquashFS read-only base
CONFIG (512MB)   — Persistent config (/etc/secubox, nginx, systemd)
DATA (2GB)       — Persistent data/logs (/var/lib/secubox, /var/log)
SNAPSHOTS (1GB)  — Versioned config/data backups
SWAP (512MB)     — RAM extension
```

#### GRUB Boot Options Added
- `secubox.persist=no` — RAM-only mode
- `secubox.factory-reset=1` — Factory reset on boot
- `secubox.recovery=1` — Recovery mode

#### Status
- ✅ All scripts created and made executable
- ✅ Build script updated with --overlay option
- ✅ Version bumped to 1.6.7.2
- ⬜ Test overlay mode build pending

---

### Navbar Icons Fix ✅

#### Problem
Sidebar menu items showing small colored squares instead of emoji icons

#### Root Cause
- Noto Color Emoji font installed but not configured in fontconfig
- Chromium not finding emoji glyphs

#### Fix Applied
1. **sidebar.css / sidebar-light.css** — Added emoji font-family to `.nav-item .icon`
2. **design-tokens.css** — Added `--font-emoji` variable
3. **debian/control** — Added `fonts-noto-color-emoji` dependency
4. **build-live-usb.sh** — Added fontconfig setup for Noto Color Emoji
5. **scripts/fix-emoji-fonts.sh** — Quick-fix script for existing VMs

#### To Apply on Running VM
```bash
bash /tmp/fix-emoji-fonts.sh
pkill chromium
```

---

### Kiosk Mode Race Condition Fix ✅

#### Problem
Kiosk mode stopped working since v1.6.7.1 - VM boots to console instead of Chromium kiosk

#### Root Cause
Race condition between two competing kiosk startup mechanisms:
1. `secubox-kiosk.service` (systemd) runs `/usr/sbin/secubox-kiosk-launcher`
2. `.bash_profile` runs `/usr/local/bin/start-kiosk` on tty1 autologin

Both could try to start X11 simultaneously because `start-kiosk` checks for `/tmp/.kiosk-starting` lock file, but `secubox-kiosk-launcher` never created it.

#### Fix Applied
1. **`image/sbin/secubox-kiosk-launcher`** — Added lock file creation at startup
   - Creates `/tmp/.kiosk-starting` before doing anything
   - Checks if lock exists to avoid double-start
   - Uses trap to clean up on exit

2. **`image/build-live-usb.sh`** (start-kiosk script) — Added systemd service checks
   - Checks if `secubox-kiosk.service` is active before starting
   - Checks if service is activating to avoid race
   - Only runs as fallback when systemd service isn't handling it

#### Files Modified
- `image/sbin/secubox-kiosk-launcher` — Lock file mechanism
- `image/build-live-usb.sh` — Updated start-kiosk and .xsession version

---

## ✅ Terminé session précédente (Session 50)

### Auth Login 404 Fix ✅

#### Problem
- Login page showing 404 for `POST /api/v1/hub/auth/login`
- Browser console: `https://localhost/api/v1/hub/auth/login 404 (Not Found)`

#### Root Cause Investigation
1. **Initial suspicion**: nginx not routing to hub socket — **WRONG**
2. **Second suspicion**: secubox-hub service not running — **PARTIALLY RIGHT** (permission error crash loop)
3. **Third suspicion**: Socket permission issue — **FIXED** with `chown secubox:secubox /run/secubox/`
4. **Final root cause**: Double `/auth` prefix — route was `/auth/auth/login` not `/auth/login`

#### Diagnostic Steps
- `systemctl status secubox-hub` → crash loop with PermissionError
- `curl --unix-socket /run/secubox/hub.sock http://localhost/health` → `{"status":"ok"}`
- `curl --unix-socket /run/secubox/hub.sock http://localhost/auth/login` → `{"detail":"Not Found"}`
- OpenAPI inspection revealed route at `/auth/auth/login` (double prefix!)

#### Fix Applied
- **Removed** `prefix="/auth"` from `common/secubox_core/auth.py` router definition
- **Added** `prefix="/auth"` to `app.include_router(auth_router, prefix="/auth")` in `packages/secubox-hub/api/main.py`

#### Files Modified
- `common/secubox_core/auth.py` — removed router prefix
- `packages/secubox-hub/api/main.py` — added prefix on include

#### Commit
- `35c9340` — fix(auth): Remove duplicate /auth prefix from login endpoint

#### Status
- ✅ Image rebuilt with fix
- ✅ USB flashed and tested
- ✅ Login working with root/secubox

---

## ✅ Terminé session précédente (Session 49)

### SecuBox Live v1.6.5 x64 Fixes ✅

#### Problems Fixed
1. **Sandbox warning banner**: `--no-sandbox` flag caused warning at top of screen
2. **No keyboard/mouse input**: X11 wasn't detecting input devices
3. **Plymouth splash**: Re-enabled after v1.6.4 disabled it for boot freeze debugging

#### Fixes Applied
- **Removed** `--no-sandbox` from Chromium flags
- **Added** `--disable-infobars` to hide any remaining info bars
- **Added** X11 InputClass sections for libinput keyboard/pointer/touchpad
- **Added** ServerFlags: `AutoAddDevices=true`, `AllowEmptyInput=false`
- **Restored** `splash` to kernel cmdline in GRUB entries

#### Files Modified
- `image/build-live-usb.sh` — version bump + splash restored
- `image/sbin/secubox-kiosk-launcher` — input devices + Chromium flags
- `image/plymouth/secubox-simple/secubox-simple.script` — version update

#### Commit
- `f8d8bac` — fix(live): v1.6.5 remove sandbox warning, fix input devices, restore splash

#### Status
- ✅ USB flashed with v1.6.5
- ⬜ Test on real hardware pending

---

## ✅ Terminé session précédente (Session 48)

### Plymouth Cube Theme Integration ✅

- **Integrated** secubox-cube theme with 3D rotating module icons
- **Updated** `build-live-usb.sh` and `build-rpi-usb.sh` to use cube theme
- **Assets**: logo, scanlines, progress-bar, 6 module icons (BOOT, AUTH, ROOT, MIND, MESH, WALL)

### Portal Authentication Fix ✅

- **Problem**: admin/secubox login not working (users.json missing)
- **Fix**: Build script now creates `/etc/secubox/users.json` with SHA256 hashed passwords
- **Credentials**: admin/secubox, root/secubox

### secubox-flash-disk Script Fix ✅

- **Problem**: `line 236: local: can only be used in a function`
- **Fix**: Removed `local` keyword from variables outside function scope

### x64-live Netplan Update ✅

- **Added** br-lan/wan structure similar to ARM boards
- **WAN**: DHCP on first interface
- **br-lan**: Static 192.168.1.1/24 for LAN gateway

### Commit
- `3898816` — fix(live): Plymouth cube theme, auth, flash-disk, netplan

### Status
- ✅ Kiosk working on Lenovo hardware (v1.6.1)
- ✅ USB flashed with v1.6.2 fixes
- ⚠️ QEMU test frozen (KVM issue, real hardware OK)

---

## ⬜ Next Up

1. Test full dashboard functionality after login
2. Verify all API endpoints work via authenticated requests
3. Test module status/control from dashboard
4. Verify JWT token persistence across page refreshes

---

## ✅ Terminé session précédente (Session 47)

### Kiosk Service Systemd Enable Fix ✅

#### Problem
- Kiosk service was not starting automatically despite being configured
- User reported "ko pareil" (still not working) after previous fixes
- Root cause: Wrong path in service symlink creation

#### Root Cause Found
The `build-live-usb.sh` script:
- **Copied** service file to: `/etc/systemd/system/secubox-kiosk.service` (line 1412)
- **Checked and symlinked** from: `/usr/lib/systemd/system/secubox-kiosk.service` (line 1567)
- The condition was **never true** because the file doesn't exist at that path

#### Fix Applied
Fixed symlink paths in `image/build-live-usb.sh`:
```bash
# BEFORE (wrong path):
if [[ -f "${ROOTFS}/usr/lib/systemd/system/secubox-kiosk.service" ]]; then
    ln -sf /usr/lib/systemd/system/secubox-kiosk.service ...

# AFTER (correct path):
if [[ -f "${ROOTFS}/etc/systemd/system/secubox-kiosk.service" ]]; then
    ln -sf /etc/systemd/system/secubox-kiosk.service ...
```

#### Verification
- ✅ Rebuilt live USB image
- ✅ Booted in QEMU KVM
- ✅ `secubox-kiosk.service` is **active (running)** and **enabled**
- ✅ Xorg running on VT7 with modesetting driver
- ✅ Chromium in kiosk mode displaying `https://localhost/`

---

## ⬜ Next Up

1. Commit and push the kiosk service fix
2. Flash USB and test on Lenovo hardware
3. Run full integration test suite
4. Prepare release v1.6.2 with all fixes

---

## ✅ Terminé session précédente (Session 46)

### Kiosk "Can't Be Reached" Fix ✅

#### Problem
- Kiosk on real hardware (Lenovo) showed "secubox.local" URL that couldn't be reached
- nginx config was invalid due to missing/broken symlinks in `secubox.d/`

#### Fixes Applied
1. **Kiosk URL** → Changed from `https://localhost/` to `https://127.0.0.1/`
   - Avoids DNS resolution issues on fresh systems
   - File: `image/kiosk/secubox-kiosk.sh`

2. **`/etc/hosts`** → Added `secubox.local` to all build scripts
   - Files: `build-live-usb.sh`, `build-image.sh`, `build-rpi-usb.sh`, `build-installer-iso.sh`

3. **nginx config cleanup** → Aggressive broken symlink removal
   - Uses `find` to remove ALL broken symlinks in `secubox.d/`
   - Creates placeholder `repo.conf` if missing
   - Auto-detects missing configs from nginx error output
   - File: `image/build-live-usb.sh`

#### Commits
- `09526c4` — fix(kiosk): Use IP address and add secubox.local to hosts
- `1ff368c` — fix(build): Add aggressive nginx config cleanup for live image

#### Verified
- ✅ QEMU KVM test passed — kiosk displays dashboard correctly
- ✅ nginx config valid in build log
- ✅ USB flashed and ready for Lenovo hardware test

---

## ✅ Terminé session précédente (Session 45)

### Wiki Cleanup & German Translations ✅

#### Cleanup Completed
- **Removed `docs/wiki/`** — Eliminated duplicate wiki folder
- **Removed old module docs** — Deleted fragmented `Modules.md`, `Modules-FR.md`, `Modules-ZH.md`
- **Consolidated** — Now only `MODULES-*.md` (comprehensive versions) remain

#### German Translations Created (8 new files)
- `wiki/Home-DE.md` — Hauptseite
- `wiki/Installation-DE.md` — Installationsanleitung
- `wiki/Live-USB-DE.md` — Live USB Anleitung
- `wiki/ARM-Installation-DE.md` — ARM U-Boot Installation
- `wiki/ESPRESSObin-DE.md` — ESPRESSObin Guide
- `wiki/Configuration-DE.md` — Konfiguration
- `wiki/Troubleshooting-DE.md` — Fehlerbehebung
- `wiki/API-Reference-DE.md` — API-Referenz

#### Sidebar Updated
- Added German (DE) links to all pages in `wiki/_Sidebar.md`

#### Translation Coverage (Updated)

| Page | EN | FR | ZH | DE |
|------|:--:|:--:|:--:|:--:|
| Home | ✅ | ✅ | ✅ | ✅ |
| Installation | ✅ | ✅ | ✅ | ✅ |
| Live-USB | ✅ | ✅ | ✅ | ✅ |
| ARM-Installation | ✅ | ✅ | ✅ | ✅ |
| ESPRESSObin | ✅ | ✅ | ✅ | ✅ |
| Configuration | ✅ | ✅ | ✅ | ✅ |
| Troubleshooting | ✅ | ✅ | ✅ | ✅ |
| API-Reference | ✅ | ✅ | ✅ | ✅ |
| MODULES | ✅ | ✅ | ✅ | ✅ |
| UI-COMPARISON | ✅ | — | — | — |

**Translation coverage:** EN 100%, FR 100%, ZH 100%, DE 100%

---

## ✅ Also Completed This Session

### Package Rebuild & USB Flash ✅

#### 11 Packages Rebuilt with UI Fixes
- secubox-cloner, secubox-magicmirror, secubox-mmpm
- secubox-ndpid, secubox-ossec, secubox-p2p
- secubox-redroid, secubox-rezapp
- secubox-vault, secubox-vm, secubox-wazuh

#### Live Image Rebuilt
- `output/secubox-live-amd64-bookworm.img.gz` (1.2GB)
- Includes all 11 UI-fixed packages

#### USB Flash Completed
- Target: `/dev/sda` (28.8GB DataTraveler 3.0)
- Written: 8.6GB in ~5.8 minutes
- Partitions verified:
  - sda1: 2M (BIOS boot)
  - sda2: 512M vfat ESP
  - sda3: 5.5G ext4 LIVE
  - sda4: 2G ext4 persistence
- Boot credentials: `root` / `secubox`
- Web UI: `https://<IP>:8443`

### Previous Tasks Completed
1. ~~Fix 13 modules missing sidebar container~~ ✅ Done (11 fixed, 3 excluded)
2. ~~Complete German wiki translations~~ ✅ Done
3. ~~Consolidate module documentation~~ ✅ Done
4. ~~Run integration tests on VM~~ ✅ QEMU tested
5. ~~Rebuild all packages with UI fixes~~ ✅ Done

---

## ✅ Terminé session précédente (Session 44)

### UI Audit & Documentation Review ✅

#### Documentation Status Report
- Created `REPORT-2026-04-10.md` — Comprehensive board/financer report
- **124 modules** complete (100%)
- **147 documentation files** total

#### UI Compliance Audit
- Created `scripts/ui-screenshot-capture.py` — Playwright-based screenshot capture
- Created `scripts/ui-fix-checker.sh` — UI guideline compliance checker

**Results:** 107/120 modules pass UI guidelines

**11 modules fixed (sidebar added):**
- secubox-cloner, secubox-magicmirror, secubox-mmpm
- secubox-ndpid, secubox-ossec, secubox-p2p
- secubox-redroid, secubox-rezapp
- secubox-vault, secubox-vm, secubox-wazuh

**3 modules excluded (intentional - no sidebar):**
- secubox-portal (login.html) — login pages don't need nav
- secubox-system (dev-status-standalone.html) — standalone embed
- secubox-p2p (master-link/index.html) — mesh onboarding wizard

---

## ✅ Terminé session précédente (Session 43)

### Critical Bug Fix: ARM Images Missing Kernel ✅

#### Issue Discovered
- **Problem:** ARM images (ESPRESSObin, MOCHAbin) had empty `/boot` directory
- **Root cause:** `build-image.sh` only installed `linux-image-arm64` for `vm-arm64`, not physical ARM boards
- **Impact:** gzwrite flash succeeded but system couldn't boot (no kernel)

#### Solution
- Modified `image/build-image.sh` to install `linux-image-arm64` for ALL ARM boards
- Added kernel copy: `/boot/vmlinuz-*` → `/boot/Image` (U-Boot format)
- Added DTB copy: `/usr/lib/linux-image-*/marvell/` → `/boot/dtbs/marvell/`
- Generated `extlinux.conf` for distroboot
- Generated `boot.scr` for U-Boot autoboot (requires `mkimage`)

#### Files Modified
- `image/build-image.sh:185-191` — Add linux-image-arm64 for all ARM
- `image/build-image.sh:503-550` — Kernel/DTB copy + bootscript generation

### Wiki ESPRESSObin Pages ✅

#### New Pages Created
- `wiki/ESPRESSObin.md` — Complete U-Boot guide (EN)
- `wiki/ESPRESSObin-FR.md` — French translation
- `wiki/ESPRESSObin-ZH.md` — Chinese translation

#### Content
- Hardware variants table (v5/v7/Ultra)
- eMMC storage limits
- Board layout diagram with UART pinout
- DIP switches boot modes
- 4 flash methods: USB gzwrite, SD gzwrite, TFTP, mmc write
- Automatic boot methods (boot.scr, extlinux.conf, manual)
- DSA switch network interfaces
- Troubleshooting & UART recovery
- Performance comparison ESPRESSObin vs MOCHAbin

### Wiki Translations Complete ✅

#### New Pages
- `wiki/ARM-Installation-FR.md` — French translation
- `wiki/ARM-Installation-ZH.md` — Chinese translation
- `wiki/UI-COMPARISON.md` — Moved from docs/wiki/

#### Sidebar Updated
- Added multilingual links for ARM-Installation (EN/FR/ZH)
- Added multilingual links for ESPRESSObin (EN/FR/ZH)

### Wiki Coverage

| Page | EN | FR | ZH | DE |
|------|:--:|:--:|:--:|:--:|
| Home | ✅ | ✅ | ✅ | — |
| Installation | ✅ | ✅ | ✅ | — |
| Live-USB | ✅ | ✅ | ✅ | — |
| ARM-Installation | ✅ | ✅ | ✅ | — |
| ESPRESSObin | ✅ | ✅ | ✅ | — |
| Modules | ✅ | ✅ | ✅ | ✅ |
| API-Reference | ✅ | ✅ | ✅ | — |
| UI-COMPARISON | ✅ | — | — | — |

**Commits:**
- `1ee6513` docs: Add ESPRESSObin wiki pages (EN/FR)
- `823a84d` fix: Install linux-image-arm64 for all ARM boards
- `43b6231` docs: Complete wiki translations (FR/ZH)

---

## ✅ Terminé session précédente (Session 42)

### Build Script Fixes

#### Live USB Missing Dependencies ✅
- **Issue:** `secubox-install` script in live USB image failed — missing `parted`
- **Root cause:** `build-live-usb.sh` debootstrap didn't include disk tools
- **Solution:** Added `parted`, `dosfstools`, `grub-pc-bin` to INCLUDE_PKGS
- **File:** `image/build-live-usb.sh:147`

#### RPi 400 Missing Dependencies ✅
- **Issue:** Same missing tools in Raspberry Pi image
- **Solution:** Added `parted`, `dosfstools`, `e2fsprogs`, `pciutils`, `usbutils`
- **File:** `image/build-rpi-usb.sh:122`

### Documentation

#### ESPRESSObin v7 Installation Guide ✅
- Created `board/espressobin-v7/README.md`
- Documented U-Boot flash procedure (USB → eMMC via `gzwrite`)
- Includes: boot targets, network interfaces, troubleshooting, serial console settings

#### Wiki ARM Installation Page ✅
- Created `wiki/ARM-Installation.md`
- Complete U-Boot flash guide for all ARM boards
- Covers ESPRESSObin v7/Ultra and MOCHAbin
- Added to wiki sidebar

#### Wiki Modules Update ✅
- Added 73 missing modules to `wiki/MODULES-EN.md`
- **Total documented modules: 119** (was 46)
- New categories: AI, Automation, Communication, Media
- All 124 packages now have wiki documentation

### eMMC Size Compatibility Fix ✅

#### Board-Specific Image Sizes
- **Issue:** Default 4GB/8GB images too large for 4GB eMMC ESPRESSObin boards
- **Solution:** Added `IMG_SIZE` to board configs:
  - ESPRESSObin v7: **3584M** (3.5GB) — fits 4GB eMMC
  - ESPRESSObin Ultra: 4G (8GB eMMC)
  - MOCHAbin: 4G (8GB eMMC + SATA option)

#### CI Workflow Update
- Removed hardcoded `--size 8G` from build-image.yml
- CI now uses board-specific sizes from `board/*/config.mk`

#### Documentation
- Added eMMC storage limits to `wiki/ARM-Installation.md`
- Created `board/mochabin/README.md` with U-Boot guide
- Updated `board/espressobin-v7/README.md` with size table

### Release v1.5.2 ✅
- Tag created and pushed
- CI building images with correct eMMC-compatible sizes
- https://github.com/CyberMind-FR/secubox-deb/releases/tag/v1.5.2

**Commits:**
- `271f27e` fix: Add missing parted/dosfstools deps to live USB image
- `75f0406` fix: Add parted/dosfstools to RPi 400 image
- `81fa1d7` docs: Add ESPRESSObin v7 installation guide
- `b8ab323` docs: Add ARM installation wiki page
- `37c8d75` docs: Add 73 missing modules to wiki
- `41011c5` docs: Add eMMC size limits for ESPRESSObin/MOCHAbin
- `4772fc2` fix: Use board-specific image sizes for eMMC compatibility

---

## ✅ Terminé session précédente (Session 41)

### Phase 9 Modules — 11 New System/Infrastructure Tools ✅

Created 11 new modules via parallel Task agents, all with FastAPI backends, P31 Phosphor light theme frontends, and Debian packaging:

| Module | Description | Size |
|--------|-------------|------|
| **secubox-nettweak** | Network tuning (sysctl, TCP/IP optimization) | 14KB |
| **secubox-ksm** | KSM memory optimization (runs as root) | 10KB |
| **secubox-avatar** | Identity manager (avatar upload, service sync) | 13KB |
| **secubox-admin** | System administration (services, logs, disk, reboot) | 15KB |
| **secubox-metabolizer** | Log processor (pattern detection, trends) | 16KB |
| **secubox-metacatalog** | Service registry (discovery, health, deps) | 15KB |
| **secubox-cyberfeed** | Threat intelligence (12 feeds, nftables export) | 14KB |
| **secubox-mirror** | APT/CDN cache (APT, NPM, PyPI, Docker) | 12KB |
| **secubox-saas-relay** | API proxy (Fernet encryption, rate limiting) | 16KB |
| **secubox-rezapp** | App deployment (Docker/LXC, 8 templates) | 12KB |
| **secubox-picobrew** | Homebrew controller (sensors, fermentation) | 18KB |

All packages built successfully and added to packages/ directory.

**Total SecuBox Packages: 124** (was 93)

---

## ✅ Terminé session précédente (Session 40)

### VirtualBox EFI Boot Fix ✅
- **Issue:** VirtualBox EFI firmware wasn't finding the GRUB bootloader, showing PXE boot instead
- **Root cause:** VirtualBox EFI shell doesn't always auto-detect `/EFI/BOOT/BOOTX64.EFI`
- **Solution:** Added `startup.nsh` script to ESP root for EFI shell auto-boot
- **Files Modified:**
  - `image/build-live-usb.sh` — Added startup.nsh creation after GRUB EFI install

### TUI Mode Boot Fix ✅
- **Issue:** Selecting TUI mode from GRUB menu loaded Kiosk GUI instead
- **Root cause:** Kiosk service started before cmdline handler could disable it
- **Solution:**
  - Use `systemctl mask` to prevent kiosk from starting
  - Kill X11/Chromium if already running
  - Create generator drop-in for correct systemd target
  - Add `Requires=secubox-cmdline.service` to kiosk and TUI services
- **Files Modified:**
  - `image/sbin/secubox-cmdline-handler` — Mask kiosk, kill X11
  - `image/systemd/secubox-kiosk.service` — Require cmdline handler
  - `image/systemd/secubox-console-tui.service` — Require cmdline handler

### CI Workflows — Package Slipstream Fix ✅
- **Issue:** CI-built images didn't include SecuBox packages
- **Root cause:** `build-image.yml` didn't download packages or pass `--slipstream` flag
- **Solution:**
  - Added package download step using `dawidd6/action-download-artifact`
  - Added `--slipstream` flag to build command
  - Updated package count from 33/93 to **124 packages**
- **Files Modified:**
  - `.github/workflows/build-image.yml` — Download packages + slipstream
  - `.github/workflows/build-live-usb.yml` — Remove redundant cache copy
  - `.github/workflows/release.yml` — Update package count

### Wiki Update ✅
- Updated all wiki pages to v1.5.1
- Package count updated from 93 to 124
- Updated Home.md, Home-FR.md, Home-ZH.md, _Sidebar.md

### Release v1.5.1 ✅
- Tag created and pushed
- 248 package build jobs succeeded
- Only `publish` (APT repo) failed due to missing secrets
- **Release assets available:**
  - secubox-live-amd64-bookworm.img.gz (1.1GB)
  - secubox-vm-x64-bookworm.img.gz
  - secubox-mochabin-bookworm.img.gz
  - secubox-espressobin-v7-bookworm.img.gz
  - secubox-espressobin-ultra-bookworm.img.gz
  - secubox-installer-amd64-bookworm.img.gz
  - secubox-installer-amd64-bookworm.iso.gz
  - SHA256SUMS

### v1.5.1 Image Test ✅
- Downloaded from GitHub release
- Verified `startup.nsh` present in ESP partition
- VirtualBox VM boots successfully with UEFI
- Kiosk GUI mode working
- SSH access confirmed
- **URL:** https://github.com/CyberMind-FR/secubox-deb/releases/tag/v1.5.1

### Mode Switching Test ✅
- **Kiosk → TUI:** `secubox-mode tui --now` ✅
- **TUI persists after reboot:** ✅
- **TUI → Kiosk:** `secubox-mode kiosk --now` ✅
- Both modes work correctly with immediate switching
- Modes persist across reboots via marker files

### CI Workflow Chain (Fixed)
```
build-packages.yml → secubox-debs-all (124 packages)
         ↓
build-image.yml    → Downloads + slipstreams
build-live-usb.yml → Downloads + slipstreams
         ↓
release.yml        → All packages + images
```

**Commits:**
- `70961cb` - fix(build): Add startup.nsh for VirtualBox EFI compatibility
- `38841a9` - fix(ci): Include all SecuBox packages in image builds
- `df8c984` - fix(boot): TUI mode now properly overrides kiosk
- `10d09e3` - docs: Update to v1.5.1 with 124 packages (wiki)

---

## ✅ Terminé session précédente (Session 39)

### Boot Banner Improvements — CRT Style with Colors & Emojis ✅
- **`/etc/issue`** — Pre-login banner with ANSI colors (gold/cyan)
  - ASCII art SecuBox logo
  - Default credentials display
  - Web UI and SSH info
- **`/etc/motd`** — Post-login MOTD with colored ASCII art
  - LIVE USB badge in green
  - Access info with color highlights
- **`/usr/bin/secubox-status`** — System status command with CRT colors
  - System info (hostname, uptime, memory, disk)
  - Network interfaces with IP addresses
  - Core services status (nginx, haproxy, crowdsec, etc.)
  - Display mode indicator (kiosk/TUI/console)
  - Quick access links
- **`/usr/sbin/secubox-boot-banner`** — Boot-time banner script
  - Boot progress indicators with checkmarks
  - Network/Nginx/API status at boot

### Profile.d Login Status ✅
- **`/etc/profile.d/secubox-login.sh`** — Login status display
  - Quick status line showing mode, service count, IP
  - Only displays on TTY login (not SSH/tmux)
- **`/usr/bin/secubox-help`** — Quick help command
  - Lists common secubox-* commands by category
  - System, Network, Security, Modes sections
- **`/usr/bin/secubox-logs`** — Live security logs shortcut

### secubox-cmdline-handler Improvements ✅
- **TUI mode fix** — Now properly starts TUI service, not just enables it
- **Console mode** — Enables standard getty on tty1
- **Default mode detection** — Checks for build-time kiosk marker
- **Better logging** — Mode transitions logged to journal

### secubox-mode CRT Styling ✅
- Updated with CRT-style colors (gold, cyan, green, red)
- Emoji status indicators (✓, ✗, ⚠, ●)
- Improved status display with mode details and help text
- Better visual formatting for mode selection

### GRUB Menu Improvements ✅
- **Dynamic default** — Kiosk GUI (entry 1) is default when `--kiosk` flag used
- **Emoji indicators** — All menu entries have relevant emojis:
  - ⚡ SecuBox Live (standard)
  - 🖼️ Kiosk GUI [DEFAULT]
  - 📟 Console TUI
  - 🌉 Bridge Mode
  - 🛡️ Safe Mode
  - 💾 Install to Disk
  - 🚀 To RAM
  - 🔧 HW Check
  - 🚨 Emergency Shell
  - 🐛 Debug modes
- **CRT menu colors** — Cyan on black with yellow highlights

### Files Modified
- `image/build-live-usb.sh` — Banner, profile.d, GRUB config updates
- `image/sbin/secubox-cmdline-handler` — Mode switching improvements
- `image/sbin/secubox-mode` — CRT style colors and emoji status

---

## ✅ Terminé session précédente (Session 38)

### Wiki Documentation — VirtualBox Quick Start ✅
- **wiki/Home.md** — Updated with VirtualBox (2 Minutes) quick start section
- **wiki/Home-FR.md** — French translation of VirtualBox quick start
- **wiki/Home-ZH.md** — Chinese translation of VirtualBox quick start
- **wiki/_Sidebar.md** — Updated with v1.5.0 and improved VirtualBox link
- All pages updated to v1.5.0 with 93 packages count
- Complete VM creation script options documented
- One-liner download commands included

**Commits:**
- `2265d7c` — docs(wiki): Add VirtualBox quick start to all wiki home pages
- `5d8c327` — docs(wiki): Update sidebar with v1.5.0 and VirtualBox link text

---

## ✅ Terminé session précédente (Session 37)

### Phase 10 — Security Extensions COMPLETE (10/10)

**New Modules Created & Built (8):**
- `secubox-ai-insights_1.0.0-1~bookworm1_all.deb` (18KB) — ML threat detection
- `secubox-ipblock_1.0.0-1~bookworm1_all.deb` (15KB) — IP blocklist manager
- `secubox-interceptor_1.0.0-1~bookworm1_all.deb` (15KB) — Traffic interception
- `secubox-cookies_1.0.0-1~bookworm1_all.deb` (16KB) — Cookie tracking/analysis
- `secubox-mac-guard_1.0.0-1~bookworm1_all.deb` (16KB) — MAC address control
- `secubox-dns-provider_1.0.0-1~bookworm1_all.deb` (18KB) — DNS API (OVH, Gandi, Cloudflare)
- `secubox-threats_1.0.0-1~bookworm1_all.deb` (17KB) — Unified threat dashboard
- `secubox-openclaw_1.0.0-1~bookworm1_all.deb` (17KB) — OSINT reconnaissance

**Previously Built:**
- `secubox-wazuh_1.0.0-1_all.deb` — SIEM (Session 24)
- `secubox-ossec_1.0.0-1_all.deb` — Host IDS (Session 24)

**Total Packages: 93** (was 85)

---

### Phase 8 — Applications COMPLETE (21/21)

**New Modules Created & Built (13):**
- `secubox-hexo_1.0.0-1~bookworm1_all.deb` (17KB) — Static blog generator (Hexo)
- `secubox-webradio_1.0.0-1~bookworm1_all.deb` (16KB) — Internet radio streaming
- `secubox-torrent_1.0.0-1~bookworm1_all.deb` (18KB) — BitTorrent client (Transmission)
- `secubox-newsbin_1.0.0-1~bookworm1_all.deb` (17KB) — Usenet downloader (SABnzbd)
- `secubox-domoticz_1.0.0-1~bookworm1_all.deb` (16KB) — Home automation
- `secubox-gotosocial_1.0.0-1~bookworm1_all.deb` (16KB) — Fediverse/ActivityPub server
- `secubox-simplex_1.0.0-2_all.deb` (15KB) — SimpleX secure messaging
- `secubox-photoprism_1.0.0-1~bookworm1_all.deb` (16KB) — Photo management
- `secubox-homeassistant_1.0.0-1~bookworm1_all.deb` (16KB) — IoT/Home automation hub
- `secubox-matrix_1.0.0-1_all.deb` (18KB) — Matrix chat server (Synapse)
- `secubox-jitsi_1.0.0-1~bookworm1_all.deb` (18KB) — Video conferencing
- `secubox-peertube_1.0.0-1~bookworm1_all.deb` (17KB) — Video platform
- `secubox-voip_1.0.0-1~bookworm1_all.deb` (17KB) — VoIP/PBX (Asterisk/FreePBX)

**Phase 8 Summary (21 modules total):**
- Previously complete: ollama, localai, jellyfin, zigbee, lyrion, jabber, magicmirror, mmpm (8)
- Session 37: hexo, webradio, torrent, newsbin, domoticz, gotosocial, simplex, photoprism, homeassistant, matrix, jitsi, peertube, voip (13)

**Total Packages: 85** (was 72)

---

## ✅ Terminé session précédente (Session 36)

### Phase 9 — System Tools COMPLETE (22/22)

**CI/CD Fix:**
- Fixed `build-live-usb.sh` pipefail issue with non-existent directories
- `find` commands now check directory existence before running
- Commit: `a1c0d56` - Pushed to master

**READMEs Added:**
- `secubox-ksm/README.md` — KSM documentation
- `secubox-admin/README.md` — Admin module documentation

**New Modules Created & Built (7):**
- `secubox-metabolizer_1.0.0-1~bookworm1_all.deb` (16KB) — Log processor/analyzer
- `secubox-metacatalog_1.0.0-1~bookworm1_all.deb` (15KB) — Service catalog/registry
- `secubox-cyberfeed_1.0.0-1~bookworm1_all.deb` (14KB) — Threat feed aggregator
- `secubox-mirror_1.0.0-1~bookworm1_all.deb` (12KB) — Mirror/CDN caching
- `secubox-saas-relay_1.0.0-1~bookworm1_all.deb` (16KB) — SaaS API proxy
- `secubox-rezapp_1.0.0-1_all.deb` (12KB) — App deployment manager
- `secubox-picobrew_1.0.0-1~bookworm1_all.deb` (19KB) — Homebrew/fermentation controller

**Commits:**
- `a1c0d56` — fix(ci): Handle non-existent directories in build-live-usb.sh
- `17e40e0` — feat(phase9): Complete all 22 System Tools modules

**Total Packages: 72** (was 65)

---

## ✅ Terminé session précédente (Session 35)

### Phase 9 — System Tools (15/22 complete)

**Modules Built (Session 35):**
- `secubox-rtty_1.0.0-1~bookworm1_all.deb` — Remote terminal
- `secubox-routes_1.0.0-1~bookworm1_all.deb` — Routing table view
- `secubox-reporter_1.0.0-1~bookworm1_all.deb` — System reports
- `secubox-smtp-relay_1.0.0-1~bookworm1_all.deb` — Mail relay
- `secubox-nettweak_1.0.0-1~bookworm1_all.deb` — Network tuning
- `secubox-ksm_1.0.0-1~bookworm1_all.deb` — Kernel same-page merging
- `secubox-avatar_1.0.0-1~bookworm1_all.deb` — Identity management
- `secubox-admin_1.0.0-1~bookworm1_all.deb` — Admin dashboard

**New Modules Created (Session 35 earlier):**
- `secubox-glances` v1.0.0 — System monitoring (Glances wrapper)
  - Real-time CPU/memory/disk/network stats
  - Process list, sensor readings
  - Historical data with charts
- `secubox-mqtt` v1.0.0 — MQTT broker management (Mosquitto)
  - Client list, topic tree view
  - User/ACL management
  - Message statistics
- `secubox-turn` v1.0.0 — TURN/STUN server (coturn)
  - Session monitoring
  - Credential generation (HMAC)
  - User/realm management
- `secubox-netdiag` v1.0.0 — Network diagnostics
  - Ping, traceroute, DNS, WHOIS, MTR
  - Port scanning, nmap
  - Interface/route/connection views

**Packages Built:**
- `secubox-glances_1.0.0-1~bookworm1_all.deb` (15KB)
- `secubox-mqtt_1.0.0-1~bookworm1_all.deb` (15KB)
- `secubox-turn_1.0.0-1~bookworm1_all.deb` (14KB)
- `secubox-netdiag_1.0.0-1~bookworm1_all.deb` (16KB)

**Previously Built (Session 24):**
- `secubox-vault_1.0.0-1_all.deb` — Config backup/restore
- `secubox-cloner_1.0.0-1_all.deb` — System imaging
- `secubox-vm_1.0.0-1_all.deb` — KVM/LXC virtualization

**Total Packages:** 65 (was 61)

---

## ✅ Terminé session précédente (Session 34)

### Build Timestamp Display — secubox-hub v1.2.0 ✅
- **API**: Added `_get_build_info()` function to read `/etc/secubox/build-info.json`
- **Dashboard**: Build timestamp badge displayed in header (date + time)
- **Tooltip**: Shows git commit, branch, board info on hover
- **Build script**: Creates `build-info.json` with timestamp, git info, board type

### Build System Fixes ✅
- **Package priority**: Fixed `build-live-usb.sh` to prefer `output/debs` over cache
- **nginx config**: Fixed secubox-soc-web to install in `secubox.d/` not `sites-available/`
- **Symlink fix**: Removed broken `secubox-repo.conf` symlink creation from postinst

### Packages Updated (Session 34)
- `secubox-hub_1.2.0-1~bookworm1_all.deb` — Build timestamp feature
- `secubox-soc-web_1.1.0-1_all.deb` — Nginx config fix (secubox.d/)

### Release v1.4.0 ✅
- Tag: `v1.4.0`
- Commit: `19ca292`
- Pushed to: `origin/master`

### Wiki Update ✅
- Updated `wiki/Home.md` — v1.4.0 version, 61 packages, SOC feature
- Updated `wiki/Home-FR.md` — French version sync
- Updated `wiki/Home-ZH.md` — Chinese version sync
- Updated `wiki/Modules.md` — Added SOC modules, secubox-console, hub v1.2.0 features
- Updated `.claude/HISTORY.md` — Session 34 entry, statistics (61 packages, v1.4.0)

---

## ✅ Terminé session précédente (Session 33)

### SecuBox SOC — Hierarchical Security Operations Center (Phases 1-4) ✅

**Phase 1: secubox-soc-agent v1.0.0** — Edge Node Metrics Agent
- **Collector**: CPU, memory, disk, network, CrowdSec/Suricata/WAF alerts
- **Upstreamer**: HMAC-SHA256 signed push to gateway (60s interval)
- **Command Handler**: Whitelist-based remote command execution
- **Enrollment**: One-time token workflow with HMAC key generation
- **Files**: `packages/secubox-soc-agent/{api/main.py, lib/{collector,upstreamer,command_handler}.py}`

**Phase 2: secubox-soc-gateway v1.0.0** — SOC Aggregation Gateway
- **Node Registry**: Enrollment, health tracking, HMAC token validation
- **Aggregator**: Fleet-wide metrics aggregation with StatsCache pattern
- **Alert Correlator**: Cross-node threat correlation (multi-node attack detection)
- **Remote Command**: Proxy commands to edge nodes via secure channel
- **WebSocket**: Real-time `/ws/alerts` stream for live monitoring
- **Files**: `packages/secubox-soc-gateway/{api/main.py, lib/{node_registry,aggregator,alert_correlator,remote_command}.py}`

**Phase 3: secubox-console v1.1.0** — TUI Extension
- **SOC Client**: Gateway API client for console
- **Fleet Screen**: Node grid with health indicators (f key)
- **Alerts Screen**: Unified alert stream with correlation toggle (a key)
- **Node Screen**: Remote node detail with service management
- **Files**: `packages/secubox-console/console/{soc_client.py, screens/soc_{fleet,alerts,node}.py}`

**Phase 4: secubox-soc-web v1.0.0** — React Web Dashboard
- **Stack**: React 18 + Vite + TypeScript + lucide-react
- **Pages**: FleetOverview, AlertStream, ThreatMap, NodeDetail
- **Components**: Sidebar, Header, NodeCard, AlertItem, StatCard
- **Hooks**: useWebSocket (reconnect), useFleet/useAlerts (data)
- **Theme**: Full cyberpunk CSS (--cosmos-black, --cyber-cyan, etc.)
- **Nginx**: /soc/ location with proxy to gateway API
- **Files**: `packages/secubox-soc-web/src/{App.tsx, pages/*, components/*, hooks/*}`

**Packages Built (Phases 1-4):**
- `secubox-soc-agent_1.0.0-1_all.deb` (12KB)
- `secubox-soc-gateway_1.0.0-1_all.deb` (15KB)
- `secubox-console_1.1.0-1_all.deb` (24KB)
- `secubox-soc-web_1.0.0-1_all.deb` (62KB)

**Phase 5: Hierarchical Mode** ✅
- **hierarchy.py**: Mode management (edge/regional/central), regional SOC enrollment
- **cross_region_correlator.py**: Cross-region threat correlation, global summary
- **Gateway API v1.1.0**: 11 new endpoints for hierarchy management
- **Web Dashboard v1.1.0**: GlobalView page, Settings page, mode indicators

**New API Endpoints (Gateway v1.1.0):**
- `GET /hierarchy/status` - Get hierarchy mode
- `POST /hierarchy/mode` - Set mode (edge/regional/central)
- `POST /regional/token` - Generate regional enrollment token (central)
- `POST /regional/enroll` - Enroll regional SOC (central)
- `POST /regional/ingest` - Receive regional data (central)
- `GET /regional/socs` - List regional SOCs (central)
- `POST /upstream/enroll` - Enroll with central (regional)
- `GET /upstream/status` - Upstream connection status (regional)
- `GET /global/summary` - Global cross-region summary (central)
- `GET /global/regions` - Regional breakdown (central)
- `GET /global/threats` - Cross-region threats (central)

**Packages Updated (Phase 5):**
- `secubox-soc-gateway_1.1.0-1_all.deb` (21KB)
- `secubox-soc-web_1.1.0-1_all.deb` (67KB)

---

## ✅ Terminé session précédente (Session 32)

### secubox-console v1.0.0 — Console TUI Dashboard
- **New package** providing terminal-based dashboard using Python Textual
- **Features**:
  - Dashboard screen with live metrics (CPU, memory, disk), uptime, health score
  - Services screen with start/stop/restart/enable/disable actions
  - Network screen with interface classification (WAN/LAN/SFP)
  - Logs screen with real-time streaming and unit filter
  - Menu screen with system info and quick actions (reboot, shutdown)
- **Board-specific theming** matching secubox-portal colors:
  - MOCHAbin (Pro) — Sky blue
  - ESPRESSObin (Lite) — Green
  - ESPRESSObin Ultra — Teal
  - x64-vm — Purple
  - x64-baremetal — Orange
  - Raspberry Pi — Pink
- **Vim-style navigation**: j/k for up/down, h for back, Enter to select
- **Auto-start on TTY1** when GUI kiosk is disabled
- **Files created**:
  - `packages/secubox-console/` — Complete package structure
  - `packages/secubox-console/console/app.py` — Main Textual App
  - `packages/secubox-console/console/api_client.py` — Async Unix socket client
  - `packages/secubox-console/console/theme.py` — Board-specific colors
  - `packages/secubox-console/console/screens/` — Dashboard, Services, Network, Logs, Menu
  - `packages/secubox-console/console/widgets/` — Header, Metrics, ServiceList
  - `packages/secubox-console/debian/` — Full Debian packaging

### secubox-kiosk-setup — Console Mode Integration
- **New commands**: `console`, `no-console`
- **Updated `status`** to show kiosk/console/none mode
- **Files modified**:
  - `image/sbin/secubox-kiosk-setup` — Added console mode support
  - `common/secubox_core/kiosk.py` — Added `console_status()`, `display_mode()`
  - `common/secubox_core/__init__.py` — Export new functions

---

## ✅ Terminé cette session (Session 31)

### secubox-portal v2.1.0 — Device-Specific Theming ✅
- **New API endpoints**:
  - `GET /theme` — Returns device-specific theme (colors, badge, name)
  - `GET /branding` — Full branding info with capabilities
- **7 board themes**:
  - MOCHAbin (Pro) — Sky blue accent (#0ea5e9)
  - ESPRESSObin (Lite) — Green accent (#22c55e)
  - x64-vm (Virtual) — Violet accent (#8b5cf6)
  - x64-baremetal (Server) — Orange accent (#f97316)
  - RPi (Maker) — Pink accent (#ec4899)
  - unknown (Standard) — Amber accent (#f59e0b)
  - default — Blue accent (#58a6ff)
- **Login page enhancements**:
  - Dynamic CSS variables applied from theme
  - Device badge shows board edition (PRO, LITE, VM, SERVER, PI)
  - Subtitle shows "SecuBox [Edition] Edition"
  - Gradient colors match board theme
- **Files modified**:
  - `packages/secubox-portal/api/main.py` — Theme endpoints
  - `packages/secubox-portal/www/login.html` — Dynamic theming JS
  - `packages/secubox-portal/debian/changelog` — v2.1.0

---

## ✅ Terminé cette session (Session 30)

### secubox-core v1.1.0 — Kiosk & Board Detection Library ✅
- **New module `kiosk.py`** in secubox_core with reusable functions:
  - `kiosk_status()` — Get kiosk mode status
  - `kiosk_enable(mode)` — Enable kiosk (x11/wayland)
  - `kiosk_disable()` — Disable kiosk mode
  - `detect_board_type()` — Auto-detect board type
  - `get_board_profile()` — Get profile (full/lite)
  - `get_board_capabilities()` — Board-specific capabilities
  - `get_board_model()` — Get full model string
  - `get_physical_interfaces()` — List physical network interfaces
  - `get_interface_classification()` — Classify WAN/LAN/SFP
  - `check_interface_carrier()` — Check if cable connected
- **Supported boards**: MOCHAbin, ESPRESSObin v7/Ultra, x64-vm, x64-baremetal, RPi
- **Files created/modified**:
  - `common/secubox_core/kiosk.py` — New module (350+ lines)
  - `common/secubox_core/__init__.py` — Export new functions, v1.1.0
  - `packages/secubox-core/debian/changelog` — v1.1.0

### secubox-hub v1.1.0 — Network Mode Selection ✅
- **New API endpoints**:
  - `GET /network_mode` — Current mode, available modes, interfaces
  - `POST /network_mode` — Change mode (proxies to secubox-netmodes)
  - `GET /network_mode/preview` — Preview YAML config for a mode
  - `GET /board_summary` — Quick board info for widgets
- **Frontend updates**:
  - New "Network Mode" card on dashboard
  - Mode selector with all available modes (Router, Inline Sniffer, Passive Sniffer, AP, Relay)
  - Preview button shows YAML config
  - Apply button changes mode with confirmation
  - Real-time WAN/LAN interface display
- **Integration**:
  - Uses secubox_core.kiosk for board/interface detection
  - Communicates with secubox-netmodes via Unix socket
- **Files modified**:
  - `packages/secubox-hub/api/main.py` — +150 lines for network mode
  - `packages/secubox-hub/www/index.html` — New Network Mode card + JS
  - `packages/secubox-hub/debian/changelog` — v1.1.0

### secubox-system v1.2.0 — Board Detection Integration ✅
- **Refactored to use secubox_core.kiosk** functions (no code duplication)
- **New API endpoints**:
  - `GET /board` — Detailed board detection (type, profile, interfaces)
  - `POST /board/detect` — Refresh detection (runs secubox-net-detect)
  - `GET /board/capabilities` — Board-specific capabilities and features
  - `GET /kiosk/status` — Kiosk mode status (enabled, mode, service state)
  - `POST /kiosk/enable` — Enable kiosk mode (x11 or wayland)
  - `POST /kiosk/disable` — Disable kiosk mode
- **Frontend updates**:
  - New "Board Detection" card with WAN/LAN/SFP classification
  - Interface details with carrier status (●/○)
  - Refresh detection button
  - New "Kiosk Mode" card with enable/disable controls
  - Mode selection (X11 for VMs, Wayland for native hardware)
- **Files modified**:
  - `packages/secubox-system/api/main.py` — Uses secubox_core.kiosk
  - `packages/secubox-system/www/system/index.html` — New UI cards
  - `packages/secubox-system/debian/changelog` — v1.2.0

---

## ✅ Terminé cette session (Session 29)

### Kiosk X11 Mode — Integrated into Build Scripts ✅
- **Problem**: Cage/Wayland kiosk fails on VMs (VirtualBox, VMware) with "Basic output test failed"
- **Solution**: Switched default kiosk mode from Wayland to X11
- **Files updated**:
  - `image/sbin/secubox-kiosk-setup` — Now supports `--x11` (default) and `--wayland` modes
  - `image/systemd/secubox-kiosk.service` — X11/startx service (default)
  - `image/systemd/secubox-kiosk-wayland.service` — Wayland/Cage service (optional)
  - `image/build-live-usb.sh` — Uses X11 kiosk mode with .xinitrc
- **New features**:
  - Mode auto-detection saved in `/var/lib/secubox/.kiosk-mode`
  - `secubox-kiosk-setup status` shows current mode
  - Automatic package installation for selected mode (xorg/xinit vs cage)
- **Usage**:
  ```bash
  # Default X11 mode (recommended)
  secubox-kiosk-setup install
  secubox-kiosk-setup enable

  # Wayland mode (native hardware only)
  secubox-kiosk-setup install --wayland
  secubox-kiosk-setup enable --wayland
  ```

---

## ✅ Terminé cette session (Session 28)

### Live USB Initramfs Fix ✅
- **Problem**: x64 live USB image boots to initramfs prompt (can't find root)
- **Root cause**: Modules for live-boot (squashfs, loop, overlay) were only in `/etc/modules-load.d/` which loads AFTER boot, not in initramfs
- **Fixes applied to `image/build-live-usb.sh`**:
  - Added critical modules to `/etc/initramfs-tools/modules` (squashfs, loop, overlay, ext4, vfat, iso9660, usb_storage, uas, sd_mod, dm_mod, virtio_blk, virtio_scsi, virtio_pci)
  - Created `/etc/initramfs-tools/conf.d/live-boot.conf` with `MODULES=most` for broad hardware support
  - Added `filesystem.size` and `filesystem.packages` files to live partition
  - Fixed `chroot` call for filesystem.packages (used awk on dpkg status instead)
  - Added debug GRUB menu entries (break=init, break=premount) for troubleshooting
  - Removed `2>/dev/null` from update-initramfs to surface any errors

### Images Built ✅
- **x64 Live USB**: `output/secubox-live-amd64-bookworm.img` (8GB, 670MB squashfs)
- **RPi 400**: `output/secubox-rpi-arm64-bookworm.img` (8GB)

---

## ✅ Terminé cette session (Session 27)

### Kiosk X11 Mode ✅
- **Switched from Cage/Wayland to X11/startx** — VirtualBox GPU compatibility
  - Cage/wlroots fails with "Basic output test failed" on VBoxSVGA
  - Created `secubox-kiosk-x11.service` using startx + chromium
  - Works reliably with VMware SVGA II / VBoxSVGA drivers
- **Files created on VM**:
  - `/etc/systemd/system/secubox-kiosk-x11.service`
  - `/home/secubox-kiosk/.xinitrc`

### Menu System Fix ✅
- **Problem**: Only 2 modules shown (hub, portal) instead of all installed
- **Root cause**: menu.d/*.json files not installed on VM
- **Fix**: Copied 85 menu JSON files to `/usr/share/secubox/menu.d/`
- **Result**: Menu API now returns all installed modules correctly

### Authentication Fix ✅
- **Created `/etc/secubox/secubox.conf`** with auth section
- **JWT login working** — admin/secubox credentials
- **All API endpoints** now properly authenticated

### secubox-netmodes Fixes ✅
- **Bug fix**: `int(float())` for /proc/uptime parsing (line 95)
- **Frontend JWT fix**: Added `getToken()` and auto-login on 401
- **Auto-Detect working**: Returns board=x64-vm, wan=enp0s3
- **Files modified**:
  - `packages/secubox-netmodes/api/main.py` — uptime bug fix
  - `packages/secubox-netmodes/www/netmodes/index.html` — JWT auth in api()

---

## ✅ Terminé session précédente (Session 26)

### Kiosk GUI VM Testing ✅
- **Fixed kiosk display** — Enabled 3D acceleration in VirtualBox
  - `VBoxManage modifyvm "VM" --accelerate3d on --vram 128`
  - Cage Wayland compositor now renders properly
- **Installed SecuBox packages on kiosk VM**
  - secubox-core, secubox-hub, secubox-portal
  - Fixed nginx port 9443 + nftables firewall rule
- **Kiosk fully functional** — Displays SecuBox Control Center

### secubox-net-detect Integration ✅
- **New API endpoints in secubox-netmodes**:
  - `GET /detect` — Run secubox-net-detect, return JSON (board, interfaces)
  - `GET /detect_cached` — Return cached detection (faster)
  - `POST /auto_apply` — Auto-configure network based on detection
  - `GET /board_info` — Get detected board from state
- **Frontend updates**:
  - Added "Auto-Detect" button in header
  - Auto-Detection card with board/WAN/LAN/SFP display
  - Preview YAML and Apply buttons
  - Pre-fills WAN/LAN selectors from detection
- **Files modified**:
  - `packages/secubox-netmodes/api/main.py` — +200 lines
  - `packages/secubox-netmodes/www/netmodes/index.html` — Auto-detect UI

---

## ✅ Terminé session précédente (Session 25)

### Kiosk Mode Fixes ✅
- **Fixed UID mismatch** — Service now uses dynamic UID detection
  - Kiosk user created with UID 1000 when possible
  - Service file updated with actual UID at runtime
  - `XDG_RUNTIME_DIR=/run/user/<actual-uid>`
- **Fixed timing issue** — cmdline handler no longer tries apt-get at sysinit.target
  - If packages pre-installed (--kiosk flag): enable immediately
  - If packages missing: creates oneshot service to install after network
- **Fixed marker file confusion**
  - `.kiosk-installed` — Marks packages installed
  - `.kiosk-enabled` — Marks kiosk mode activated (required by service)
- **Updated build-live-usb.sh**
  - `--kiosk` flag now creates user and start script during build
  - All kiosk dependencies pre-installed for immediate boot
- **Improved start-kiosk.sh**
  - Waits for nginx/hub service to be ready (30s max)
  - Uses `curl -sk` to check HTTPS endpoint
- **Updated secubox-kiosk.service**
  - `ConditionPathExists=/var/lib/secubox/.kiosk-enabled`
  - `After=nginx.service secubox-hub.service`
- **Root autologin preserved**
  - Kiosk uses tty1 for display
  - Root autologin moved to tty2 (Ctrl+Alt+F2 to access)
  - Console access always available for debugging
- **Files modified**:
  - `image/sbin/secubox-kiosk-setup` — Refactored with setup_kiosk_user(), update_service_file(), setup_root_autologin_tty2()
  - `image/sbin/secubox-cmdline-handler` — Smart package detection
  - `image/systemd/secubox-kiosk.service` — ConditionPathExists for enabled marker
  - `image/build-live-usb.sh` — Full kiosk setup when --kiosk flag used, tty2 autologin

---

## ✅ Terminé session précédente (Session 24)

### Network Auto-Detection & Preseed System ✅
- **secubox-net-detect** — Auto-detection script for WAN/LAN interfaces
  - Board detection via /proc/device-tree/model (MochaBin, ESPRESSObin)
  - x64 detection via DMI (VM vs baremetal)
  - Interface mapping: eth0=WAN, eth*/lan*=LAN based on device
  - Netplan generation for 3 modes: router, bridge, single
  - Link detection for x64 auto-discovery
- **Board configurations**:
  - `board/x64-live/config.mk` — Live USB profile settings
  - `board/x64-vm/config.mk` — VM-specific settings
  - Netplan templates for x64 auto-DHCP on common interfaces
- **secubox-cmdline-handler** — Kernel parameter parser
  - `secubox.netmode=router|bridge|single` — Network mode selection
  - `secubox.kiosk=1` — Enable GUI kiosk mode
  - `secubox.debug=1` — Enable debug mode
  - Runs early at boot (sysinit.target)
- **secubox-kiosk-setup** — GUI kiosk mode installer
  - Installs Cage Wayland compositor + Chromium
  - Fullscreen WebUI at https://localhost:9443/
  - Commands: install, enable, disable, status
  - Perfect for touchscreen/embedded displays
- **build-live-usb.sh updates**:
  - GRUB menu entries: Kiosk Mode, Bridge Mode
  - Installs all detection scripts and services
  - Systemd services for early boot configuration
- **firstboot.sh integration**:
  - Calls secubox-net-detect to configure network
  - Updates secubox.conf with detected board/interface
  - Creates .net-configured marker

### Phase 8-10 Progress ✅
- secubox-jabber (XMPP) — Deployed
- secubox-magicmirror — Deployed
- secubox-mmpm — Deployed
- secubox-redroid — Deployed
- secubox-vault — Built
- secubox-cloner — Built
- secubox-vm — Built
- secubox-wazuh — Built
- secubox-ossec — Built
- All commits pushed to master

---

## ✅ Terminé session précédente (Session 23)

### Migration Preparation Workflow ✅
- Created `.claude/REMAINING-PACKAGES.md` — 53 packages remaining inventory
- Classified by complexity (Easy/Medium/Complex/Native)
- Identified 25 packages with different naming (already ported)
- Defined Phase 8 (21 apps), Phase 9 (22 tools), Phase 10 (10 security)
- Updated TODO.md with P8/P9/P10 task items
- Created HISTORY.md for milestone tracking
- Set priority: ollama → jellyfin → vault → homeassistant

### secubox-ollama v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (485 lines)
  - Container management (Docker/Podman detection)
  - Model management (list, pull, remove)
  - Chat completion API (`/chat`)
  - Text generation API (`/generate`)
  - System resource monitoring (`/system`)
  - Container logs (`/logs`)
- **CRT-light frontend** — Full P31 phosphor theme
  - Tabs: Chat, Models, System, Logs, Settings
  - Popular model quick-pull buttons
  - Real-time chat interface
- **Deployed to VM** — Running at https://localhost:9443/ollama/

### secubox-jellyfin v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (15+ endpoints)
  - Container management (Docker/Podman)
  - Media library configuration
  - Hardware acceleration (VAAPI)
  - Backup/restore functionality
  - Setup wizard tracking
- **CRT-light frontend** — Jellyfin blue accent theme
  - Tabs: Libraries, Settings, Logs, Backup
  - Install banner when not installed
  - Library type icons (movies, tvshows, music, photos)
- **Deployed to VM** — Running at https://localhost:9443/jellyfin/

### secubox-lyrion v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (18+ endpoints)
  - Container management (Docker/Podman)
  - Player control via Squeezebox JSON-RPC
  - Library scanning, stats
  - Backup/restore functionality
- **CRT-light frontend** — Theme-aware with Lyrion orange accents
  - Tabs: Players, Library, System, Logs, Settings
  - JSON-RPC integration for library stats
- **Deployed to VM** — Running at https://localhost:9443/lyrion/

### secubox-zigbee v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (20+ endpoints)
  - Container management (Docker/Podman)
  - USB serial dongle detection (/dev/ttyUSB*, /dev/ttyACM*)
  - Device management: rename, remove, permit_join
  - MQTT integration
  - Kernel module detection (cp210x, ch341)
- **CRT-light frontend** — Theme-aware with Zigbee green accents
  - Tabs: Devices, Network, Diagnostics, Logs, Settings
  - Pairing mode toggle with animation
- **Deployed to VM** — Running at https://localhost:9443/zigbee/

### secubox-localai v1.0.0 ✅
- **FastAPI backend** — Ported from OpenWRT RPCD (15+ endpoints)
  - Container management (Docker/Podman)
  - Model gallery with popular LLMs
  - OpenAI-compatible chat/completion API proxy
  - Resource monitoring (CPU/memory)
- **CRT-light frontend** — Theme-aware with LocalAI purple accents
  - Tabs: Chat, Models, Gallery, Logs, Settings
  - Interactive chat interface
- **Deployed to VM** — Running at https://localhost:9443/localai/
- **Total modules: 59** (was 55)

### Ad Guard Theme Update ✅
- Updated frontend to be theme-aware
- Added Ad Guard blue accent color
- Dark mode support via body.dark class

---

## ✅ Terminé session précédente (Session 21)

### Live ISO Boot Console Fixes ✅
- **Issue**: Live ISO boot showed flickering console, login prompt disappearing
- **Root causes identified and fixed**:
  1. **Service restart loops** — 14 SecuBox services crashing on live boot (missing configs)
  2. **Martian packet logging** — Network errors flooding console
  3. **Getty autologin conflict** — live-config tried to login as 'user' (doesn't exist)
  4. **Systemd status messages** — [FAILED] messages overwriting login prompt

- **Fixes applied to `image/build-installer-iso.sh`**:
  - Mask 14 services incompatible with live boot (secubox-haproxy, secuboxd, lxc-net, etc.)
  - Disable martian packet logging via sysctl
  - Configure systemd ShowStatus=no for quiet boot
  - Fix getty autologin: disable live-config autologin, create 'user' fallback account
  - Set kernel printk level to suppress non-critical messages
  - Add debug boot menu entries (rescue, emergency, no-preseed)

- **Fixes applied to `image/preseed-apply.sh`**:
  - Skip service restarts on live boot entirely
  - Use background processes for installed systems

- **Output**:
  - ISO: `secubox-c3box-clone-amd64-bookworm.iso` (457MB)
  - IMG: `secubox-c3box-clone-amd64-bookworm.img` (969MB)
  - Live boot working with stable console login

- **Commit pushed**: `288b27a Fix live ISO boot console issues`

---

## ✅ Terminé session précédente (Session 20)

### x64 Installer ISO Build System ✅
- **image/build-installer-iso.sh** (886 lines) — Hybrid Live USB / Headless Installer
  - UEFI boot with GRUB (x86_64-efi)
  - Live boot mode with SquashFS + persistence partition
  - Headless auto-install to first available disk
  - Preseed system for configuration restoration
  - Boot menu: Live, Install (headless), Safe Mode, To RAM
- **image/export-c3box-clone.sh** (340 lines) — Export device configuration
  - Exports: /etc/secubox/, netplan, WireGuard, users, nginx, SSL certs
  - LXC container configs, /data partition
  - Creates preseed.tar.gz for cloning
- **image/build-c3box-clone.sh** (174 lines) — Combined export + ISO workflow
  - Single command to clone any C3Box device
  - `--skip-export` option to rebuild ISO from existing preseed
- **Commit pushed**: `141b0c0 Add x64 installer ISO and C3Box clone build system`

### C3Box Configuration Export ✅
- **Exported from VM** (localhost:2222)
- **50 SecuBox packages** captured in manifest
- **Configuration**: secubox.conf, mesh.toml, users.json, traffic-shaper.json, etc.
- **Network**: netplan + WireGuard configs
- **Services**: nginx sites, CrowdSec, nftables rules
- **LXC containers**: mailserver, roundcube, streamlit
- **Output**: `output/c3box-clone-preseed.tar.gz` (36KB)

### streamlitctl v1.0.0 ✅
- **packages/secubox-streamlit/scripts/streamlitctl** (521 lines)
- Full Streamlit LXC controller for Debian bookworm
- **Commands**: install, start, stop, restart, status, destroy, logs, shell
- **App management**: app create, app list
- **Features**:
  - Debootstrap-based minimal Debian container
  - Python 3.11 + Streamlit installation
  - Persistent apps directory at /srv/streamlit/apps
  - Memory limit 1GB per container
  - Three-fold commands: components, access (JSON output)
- **Debian packaging** updated (control, rules, changelog v1.2.0)

### VSCode Tasks ✅
- **Build C3Box Clone ISO (from VM)** — Clone localhost:2222
- **Build C3Box Clone ISO (custom host)** — Clone any device
- **Export C3Box Config Only** — Export without building ISO
- **Build Installer ISO (x64)** — Fresh install ISO
- **Build Live USB (x64)** — Live-only USB
- **Build Installer ISO with Preseed** — ISO with custom preseed
- **New inputs**: c3boxHost, c3boxPort, preseedFile

---

## ✅ Terminé session précédente (Session 19)

### Socket Directory Fix (Permanent) ✅
- **Issue**: `/run/secubox/` sockets disappearing, causing 502 errors and navbar showing only 2 categories
- **Root cause**: Directory permissions reset after service restarts
- **Solution**: Created `secubox-runtime.service` — oneshot service that runs before all secubox services
  - Creates `/run/secubox` with correct ownership (secubox:secubox)
  - Sets permissions to 775
  - Runs after local-fs.target, before hub/portal/p2p services
- **Files added**:
  - `packages/secubox-core/systemd/secubox-runtime.service`
  - Updated `packages/secubox-core/debian/rules` to install the service
  - Updated `packages/secubox-core/debian/postinst` to enable the service
- **Commit pushed**: `ba6b5da Add secubox-runtime.service to ensure /run/secubox exists`

### Master-Link Admin Navbar Integration ✅
- **Updated `/master-link/admin.html`** with standard SecuBox UI
  - Added sidebar navbar using shared `sidebar.js`
  - Changed from dark CRT to P31 Phosphor light theme
  - Removed back button (navigate via sidebar instead)
  - Consistent styling with other SecuBox modules
  - Fixed sidebar element: `<nav class="sidebar" id="sidebar">` (was wrong div)
- **Commit pushed**: `5834115 Update Master-Link Admin with navbar integration`

### VM Restart & Verification ✅
- Restarted frozen VirtualBox VM
- Applied `secubox-runtime.service` fix on VM
- Verified all **46 sockets** restored in `/run/secubox/`
- Verified all **46 services** running
- Verified navbar API: **7 categories**, **45 modules**
- Tested Master-Link: status, peers, tree, invite-local all working

### ReDroid (Android in Container) Integration ✅
- **redroid/redroid-lxc-setup.sh** — Interactive wizard for ReDroid deployment
  - Docker installation, ADB/scrcpy setup
  - Automatic architecture detection (ARM64/x86_64)
  - LXC binder device configuration
  - Multi-instance support with docker-compose
  - NDK translation for ARM apps on x86 hosts
  - Android versions: 9, 10, 11, 12, 13, 15
- **redroid/proxmox-host-config.sh** — Proxmox host configuration helper
  - Binder kernel module loading (binder_linux, ashmem_linux)
  - LXC config snippets for device passthrough
  - Instructions for MOCHAbin/ESPRESSObin ARM64 and x86_64
- **VSCode tasks for ReDroid management**:
  - Setup wizard, auto-setup Android 12
  - Start/stop/status commands
  - Screen mirroring (scrcpy), ADB shell
  - APK installation, live logs
  - Binder device diagnostics
  - Multi-instance support (up to 3 instances)
- **Commit pushed**: `5340ebc Add ReDroid (Android in Container) LXC setup scripts`

---

## ✅ Terminé session précédente (Session 18)

### Master-Link Admin Dashboard (v1.6.0) ✅
- **Admin Dashboard** — `/master-link/admin.html`
  - Dark CRT theme matching SecuBox aesthetics
  - Stats cards: role, peers, pending, active tokens
  - Tabs: Overview, Peers list, Mesh Tree, Generate Invite
  - Token generation with copy buttons (token, URL, CLI)
  - Peer approval workflow from dashboard
- **Localhost-only API endpoints**:
  - `POST /master-link/invite-local` — Generate tokens without JWT auth
  - `POST /master-link/cleanup-local` — Cleanup expired tokens
  - `is_local_request()` helper checks X-Real-IP, X-Forwarded-For headers
- **IP prioritization**: `get_lan_ip()` now prefers 192.168.255.x mesh addresses
- **Dependencies**: Added `avahi-daemon`, `avahi-utils` for mDNS discovery
- **Commit pushed**: `0ecdb98 Add Master-Link Admin Dashboard (v1.6.0)`

### Mesh Invite CLI (v1.5.0) ✅
- **sbx-mesh-invite v1.0.0** — CLI tool to generate mesh invite tokens
  - Options: `--auto-approve`, `--manual-approve`, `--ttl`, `--ip`
  - Auto-detects local LAN IP (prefers 192.168.x.x addresses)
  - Stores tokens in `/var/lib/secubox/p2p/master-link/tokens.json`
  - ASCII box formatted output for easy copy-paste
  - Works on Debian and OpenWRT (openssl, sha256sum, or fallbacks)
- **Commit pushed**: `9b6f7fd Add sbx-mesh-invite CLI tool (v1.5.0)`

### VM Socket Fix ✅
- **Issue**: All 46 secubox API sockets disappeared from `/run/secubox/`
- **Cause**: Directory permissions reset after service restarts
- **Fix**: Created `/etc/tmpfiles.d/secubox.conf` with `d /run/secubox 0775 secubox secubox -`
- **Result**: All 46 sockets now persist across restarts

### Multi-Master Support (v1.4.0) ✅
- **sbx-mesh-join v1.4.0** — Auto-detect master type
  - `detect_master_type()` — Probe endpoints to identify master type
  - Debian API support: `/api/v1/p2p/master-link/join` (port 7331)
  - OpenWRT CGI support: `/cgi-bin/masterlink/join` (port 80 or 7331)
  - Fallback: Try all methods when master type unknown
  - Save `master_type` in local config for future reference
  - Better troubleshooting hints for both master types
- **Commit pushed**: `aadbe17 sbx-mesh-join v1.4.0: Auto-detect master type`

### Simplified Invite Flow (v1.3.0) ✅
- **secubox-p2p v1.3.0** — Simplified mesh join workflow
  - `POST /master-link/invite` — Generate shareable invite with URLs + CLI commands
  - `GET /master-link/join-script?token=xxx` — Returns executable shell script
  - Copy-paste friendly ASCII box output for invites
  - One-liner join: `wget -qO- '<url>' | sh`
- **sbx-mesh-join CLI tool** — `/usr/bin/sbx-mesh-join`
  - Works on OpenWRT (wget, uci, br-lan) and Debian (curl)
  - Accepts URL or IP+token arguments
  - Auto-detects system type and configures accordingly
- **Commits pushed**:
  - `aa8493a Add simplified invite flow and OpenWRT join script (v1.3.0)`
  - `066ed94 Add OpenWRT Master-Link client implementation guide`

### OpenWRT Documentation ✅
- **docs/OPENWRT-MASTERLINK.md** — Complete implementation guide (487 lines)
  - RPCD backend script (luci.masterlink)
  - LuCI JavaScript view for join/leave UI
  - UCI config template
  - OpenWRT package Makefile
  - ACL permissions file
  - Testing commands and directory structure

### P2P Hub Light Theme ✅
- **secubox-p2p www/p2p/index.html** — Full P31 Phosphor light theme applied
  - Updated CSS root variables from dark (#0a0a0a, #33ff33) to light palette (#e8f5e9, #006622)
  - Fixed all components: buttons, forms, tables, modals, status cards, status badges
  - Updated mesh visualization canvas colors to light theme
  - Added border-radius and improved shadows for modern look
- **Commit pushed** — `91d6550 Apply P31 Phosphor light theme to P2P Hub page`

### VM Testing ✅
- **VirtualBox SecuBox-Dev** — Running and accessible
  - SSH: `ssh -p 2222 root@localhost`
  - HTTPS: https://localhost:9443
- **P2P Hub page** — Deployed and tested at /p2p/
- **Master-Link page** — Tested at /master-link/
  - All endpoints working (status, peers, tree, token validation)
  - 3 peers approved via master-link (test-peer, c3box, C3BOX/OpenWRT)
  - Mesh hierarchy: master (depth 0) → 3 children (depth 1)
- **CLI tools tested**:
  - `sbx-mesh-invite` — Generates tokens with auto-detected IP (192.168.100.1)
  - `sbx-mesh-join` — Joins mesh with multi-master support

---

## ✅ Terminé session précédente (Session 17)

### Master-Link Enrollment System ✅
- **secubox-p2p v1.2.0** — Token-based mesh node enrollment (ported from secubox-openwrt)
  - Token generation with TTL and auto-approve options
  - Join request handling with token validation
  - Peer approval workflow: approve, reject, promote to sub-master
  - Depth-based mesh hierarchy (max_depth configurable)
  - Master/sub-master/peer role management
  - Mesh tree visualization endpoint
  - Upstream join capability for peer-side enrollment
- **Master-Link join page** — `/master-link/?token=xxx`
  - P31 Phosphor light theme (consistent with other modules)
  - 3-step wizard: Review master → Enter details → Join mesh
  - Shows master fingerprint, role, depth for verification
  - Auto-approval status display
- **New API endpoints**:
  - `GET /master-link/status` — Status and peer counts (public)
  - `POST /master-link/token` — Generate join token
  - `POST /master-link/join` — Handle join request
  - `POST /master-link/approve` — Approve/reject/promote peer
  - `GET /master-link/peers` — List all join requests
  - `GET /master-link/tree` — Mesh hierarchy tree
  - `GET/POST /master-link/config` — Configuration management
  - `POST /master-link/join-with-token` — Join upstream mesh
- **nginx config** — Added `/master-link/` route
- **debian/rules** — Installs master-link www directory

### Device Intel Enhancement ✅
- **secubox-device-intel v1.2.1** — Enhanced SecuBox/OpenWRT detection
  - Specific SecuBox markers (no false positives)
  - GL.iNet custom UI detection
  - SecuBox theme extraction (crt-p31, etc.)
  - Single IP probe endpoint

### Mesh UI Fix ✅
- **secubox-mesh www/mesh/index.html** — P31 light theme (was dark CRT conflict)
- **secubox-mesh API** — Made /status, /services, /domains public endpoints

---

## ✅ Terminé cette session (Session 16)

### UI Theme & Navbar Consistency ✅
- **Theme toggle system** — Light/dark P31 phosphor themes working across all modules
  - Light theme: mint green palette (#e8f5e9, #006622)
  - Dark theme: blue-tinted palette (#0a0e14, #33ff66)
  - Toggle persists via localStorage (`sbx_theme` key)
- **Fixed 35+ pages** — Body class standardized to `crt-light`
- **Fixed inline CSS variables** — Added `updateInlineThemeVars()` for modules using `--bg`/`--fg`/`--dim`
- **Collapsed sidebar categories** — Categories collapse by default, only active category expanded
- **Fixed navbar integration issues**:
  - Portal: Changed path from `/c3box/` to `/portal/`
  - Metrics: Fixed `title` → `name` in menu JSON
  - Mesh DNS: Removed duplicate 580-mesh.json
  - WireGuard: Removed duplicate 21-wireguard.json
  - Metrics: Fixed sidebar.js path `/assets/js/` → `/shared/`
  - p2p, zkp, mesh: Added missing crt-light.css link

### Documentation & Screenshots ✅
- **45 module screenshots captured** — Using Playwright screenshot-tool.py
- **docs/UI-GUIDE.md** — CRT theme documentation with color palette and module list
- **scripts/fix-navbar.sh** — Automated navbar integration checker
- **docs/OPENWRT-DEBIAN-COMPARISON.md** — Full comparison:
  - OpenWRT: 103 luci-app modules
  - Debian: 52 packages (49 UI + 3 backend)
  - Migration status by category
  - ~1000+ API endpoints documented
  - Roadmap for remaining 68 modules

### Previous Session (15) — Module Compliance Fixes ✅
- **Maintainer standardization** — All 51 packages now use `Gerald KERMA <devel@cybermind.fr>`
  - Fixed 12 control files with wrong maintainer
  - Fixed 9 changelog files with wrong maintainer
- **JWT Authentication** — Added to secubox-mesh API (was missing)
  - All endpoints now require JWT auth except /health
  - secubox-roadmap is intentionally public (read-only migration status)

### Go Daemon Organization ✅
- **Moved Go code to `daemon/` directory** — Proper structure for mesh daemon
  - `daemon/cmd/secuboxd/` — Mesh daemon main
  - `daemon/cmd/secuboxctl/` — CLI tool
  - `daemon/c3box/` — Situational awareness dashboard
  - `daemon/internal/` — Internal packages (discovery, identity, telemetry, topology)
  - `daemon/pkg/` — Shared packages (config, hamiltonian)
  - `daemon/systemd/` — systemd service units
  - `daemon/testdata/` — Test configuration files
- **Added `daemon/Makefile`** — Build targets for all binaries
- **Added `daemon/README.md`** — Documentation for mesh daemon architecture

### Debian Packaging for Go Daemon ✅
- **packages/secubox-daemon/** — New package for mesh daemon
  - `secubox-daemon` — Contains secuboxd + secuboxctl
  - `secubox-c3box` — Situational awareness dashboard (separate package)
  - Full debian packaging (control, changelog, rules, postinst, prerm)
  - Systemd integration with socket activation

### Unix Socket Control Server ✅
- **daemon/internal/control/server.go** — Control server implementation
  - Unix socket at `/run/secuboxd/topo.sock`
  - Commands: mesh.status, mesh.peers, mesh.topology, mesh.nodes
  - Commands: node.info, node.rotate, telemetry.latest, ping
  - JSON responses with proper error handling
  - Graceful shutdown and socket cleanup
- **daemon/cmd/secuboxctl/main.go** — CLI expanded with new commands
  - `secuboxctl mesh topology` — Show mesh topology
  - `secuboxctl mesh nodes` — List mesh nodes with ZKP status
  - `secuboxctl telemetry latest` — Show telemetry metrics
- **Tested on VM** — All commands working:
  - Node info shows DID, role, ZKP expiry
  - Mesh status shows running state, uptime
  - Telemetry shows CPU/memory/disk, nftables rules, CrowdSec bans

### Go Daemon Telemetry Implementation ✅
- **pkg/hamiltonian/hamiltonian.go** — Fixed `currentTimestamp()` to use `time.Now().Unix()`
- **internal/telemetry/telemetry.go** — Implemented metrics collection:
  - `getCPUPercent()` — Reads from /proc/stat
  - `getDiskPercent()` — Uses syscall.Statfs for root filesystem
  - `getNFTablesRuleCount()` — Parses `nft list ruleset` output
  - `getCrowdSecBans()` — Queries `cscli decisions list`

---

## ✅ Terminé session précédente (Session 14)

### API Documentation Expansion ✅
- **wiki/API-Reference.md** — Comprehensive API docs for all 48 modules
  - Core modules: hub, portal, system (70+ endpoints)
  - Security modules: crowdsec, waf, mitmproxy, hardening, nac, auth (150+ endpoints)
  - Network modules: netmodes, wireguard, qos, dpi, traffic, vhost, cdn (200+ endpoints)
  - Services modules: haproxy, netdata, mediaflow (80+ endpoints)
  - Application modules: mail, dns, users, gitea, nextcloud (100+ endpoints)
  - Container modules: backup, watchdog, tor, exposure (60+ endpoints)
  - Intel modules: device-intel, vortex-dns, vortex-firewall, soc, metrics, meshname (100+ endpoints)
  - Other modules: mesh, p2p, zkp, repo, roadmap (40+ endpoints)
  - Total: ~1000+ documented API endpoints
  - Code examples for common operations (login, ban IP, add peer)
  - Error response format and rate limiting info
  - WebSocket documentation for real-time updates

---

## ✅ Terminé session précédente (Session 13)

### Multilingual Module Documentation ✅
- **wiki/MODULES-EN.md** — English module docs (48 modules, 771 lines)
- **wiki/MODULES-FR.md** — French module docs
- **wiki/MODULES-DE.md** — German module docs
- **wiki/MODULES-ZH.md** — Chinese module docs
- **wiki/_Sidebar.md** — Updated with multilingual module links
- **docs/SCREENSHOTS-VM.md** — Added missing Metrics Dashboard entry (47 screenshots)
- All screenshots captured and linked to GitHub raw URLs

---

## ✅ Terminé session précédente (Session 12)

### secubox-metrics Module ✅
- **Metrics Dashboard** — Migrated from OpenWRT luci-app-metrics-dashboard
  - FastAPI backend with caching (30s TTL)
  - System overview: uptime, load, memory, vhosts, certs, LXC count
  - Service status: HAProxy, WAF, CrowdSec
  - WAF stats: active bans, alerts (24h), blocked requests
  - Connections: TCP by port (HTTPS/HTTP/SSH)
  - P31 Phosphor CRT theme (#33ff66 green glow)
- **API endpoints**: /status, /health, /overview, /waf_stats, /connections, /all, /refresh, /certs, /vhosts
- **CI Fix**: Added build-essential to build dependencies
- **Nginx config**: Modular /etc/nginx/secubox.d/metrics.conf
- **Total modules: 47** (was 46)

### secubox-soc Module ✅
- **Security Operations Center** — New SOC dashboard module
  - World Clock: 10 timezone display (UTC, EST, PST, GMT, CET, MSK, GST, SGT, JST, AEST)
  - World Threat Map: SVG with 30 country coordinates, threat heatmap
  - Ticket System: Create, assign, track security incidents
  - Threat Intel: IOC management (IPs, domains, hashes)
  - P2P Intel: Peer-to-peer threat sharing network
  - Alerts: Real-time security alert feed
  - WebSocket: Live updates for all components
  - CRT P31 theme: Full green phosphor aesthetic
- **API endpoints**: 20+ (clock, map, tickets, intel, peers, alerts, stats, ws)
- **Total modules: 46** (was 45)

### Documentation ✅
- **docs/MODULES.md** — Comprehensive module documentation
  - 46 modules cataloged by category
  - API endpoint counts per module
  - CRT P31 theme documentation
  - Screenshot checklist for all modules
  - Module architecture diagram
  - Build and deploy instructions
- **docs/screenshots/.gitkeep** — Created screenshots directory

### CRT Theme Fixes ✅

### 4 New Modules Ported ✅
From OpenWRT planned modules to Debian:
- **secubox-device-intel** v1.0.0 — Asset discovery and fingerprinting
  - ARP table scanning, MAC vendor lookup (OUI database)
  - DHCP lease tracking, hostname detection
  - Device tagging and notes, trusted device marking
  - Network interface listing, active scan capability
- **secubox-vortex-dns** v1.0.0 — DNS firewall with RPZ and threat feeds
  - Blocklist management (hosts/domains format)
  - Custom domain rules (block/allow/redirect)
  - Unbound and dnsmasq support
  - Threat feed integration (Steven Black, OISD, URLhaus, etc.)
- **secubox-vortex-firewall** v1.0.0 — nftables threat enforcement
  - IP blocklist management (plain/CIDR/CSV formats)
  - nftables sets for IPv4/IPv6 blocking
  - Custom IP rules (drop/reject/log)
  - Threat feed integration (Spamhaus, Feodo, SSL Blacklist, etc.)
- **secubox-meshname** v1.0.0 — Mesh network domain resolution
  - Mesh node registration with custom domain
  - mDNS host discovery via Avahi
  - dnsmasq integration for local DNS
  - DNS resolver test endpoint

All modules include FastAPI backend, Catppuccin frontend, Debian packaging.
Total modules: **45** (was 41)

### VM Fixes ✅
- **Hub socket fix** — Fixed /run/secubox permissions for socket creation
- **Roadmap navbar** — Standardized to use shared sidebar.js like all other modules
- **Login credentials** — Recreated /etc/secubox/users.json with admin user
- **VM RAM** — Increased to 4GB for 47 services (was 2GB, causing timeouts)
- **vortex-firewall** — Fixed permission error creating /etc/nftables.d (try/except + postinst)

### Frontend Fixes ✅
- **Login redirect** — Fixed path `/login/` → `/portal/login.html` in 4 new modules
- **JSON error handling** — Improved API function to handle non-JSON responses gracefully
- **Sidebar CSS** — Added missing `sidebar.css` link to 4 new modules + roadmap
- **CSS conflicts** — Removed local `.sidebar` overrides to allow shared CRT P31 theme
- All 5 pages tested: device-intel, vortex-dns, vortex-firewall, meshname, roadmap

### Menu Fix ✅
- Removed duplicate WireGuard menu entry (21-wireguard.json)

### secubox-qos v1.1.0 — Per-VLAN QoS Support ✅
- **Multi-interface support** — Manage QoS on eth0, eth0.100, eth0.200, etc.
- **VLAN discovery** — Auto-detect existing VLAN interfaces
- **Per-VLAN policies** — Independent bandwidth limits per VLAN
- **802.1p PCP marking** — Map tc classes to VLAN priority (0-7)
- **VLAN creation/deletion** — Create VLAN interfaces with QoS from UI
- **VLAN-aware rules** — Traffic classification by VLAN ID
- **Per-interface statistics** — RX/TX bytes, tc class stats
- **Apply-all function** — Apply QoS to all managed interfaces at once
- **Frontend updated** — VLAN policies table, PCP settings, interface stats

New API endpoints:
- `GET /vlans` — List VLAN interfaces with policies
- `GET/POST/DELETE /vlan/{interface}` — VLAN policy management
- `POST /vlan/create` — Create new VLAN with QoS
- `POST /vlan/apply_all` — Apply QoS to all interfaces
- `GET/POST /pcp/mappings` — 802.1p priority mappings
- `GET/POST/DELETE /interfaces` — Interface management
- `GET/POST/DELETE /vlan/rules` — VLAN classification rules

### 6 New Modules Committed (Session 9) ✅
- **secubox-backup** v1.0.0 — System config and LXC container backup/restore
- **secubox-watchdog** v1.0.0 — Container, service, and endpoint monitoring
- **secubox-tor** v1.0.0 — Tor circuits and hidden services management
- **secubox-exposure** v1.0.0 — Unified exposure settings (Tor, SSL, DNS, Mesh)
- **secubox-mitmproxy** v1.0.0 — WAF with traffic inspection, alerts, and bans
- **secubox-traffic** v1.0.0 — TC/CAKE QoS traffic shaping per interface

All modules include FastAPI backend, Catppuccin frontend, Debian packaging.
Total modules: **41** (was 35)

### Menu.d Fixes ✅
- Added missing menu.d JSON files for exposure, mitmproxy, traffic
- Updated debian/rules to install menu.d files

### Metapackages Updated to v1.1.0 ✅
- **secubox-full** — Now includes all 39 modules (was 14)
- **secubox-lite** — Added portal, hardening; watchdog/backup in suggests
- **repo/README.md** — Updated package list (41 total)

---

## ✅ Previously Done (Session 8)

### secubox-mail Enhancement (v2.1.0) ✅
- **Security features dashboard** — Visual grid with toggle switches
  - DKIM, SpamAssassin, Greylisting, ClamAV controls
  - Security score indicator (0-4)
  - Real-time status for each feature
- **Mail logs viewer** — New tab with configurable line count
- **Mailbox repair** — Per-user repair action
- **DKIM record display** — DNS setup modal shows DKIM record
- **LXC path fix** — Added `-P /srv/lxc` to lxc-info/lxc-attach commands
- **Service permissions** — Run as root for LXC access, removed sandboxing

### secubox-users Enhancement (v1.1.0) ✅
- **usersctl CLI v1.1.0** — Full user management controller
  - Commands: status, list, add, delete, get, enable, disable, passwd, sync, export, import
  - Service provisioning: Nextcloud, Gitea, Email, Matrix, Jellyfin, PeerTube, Jabber
  - Three-fold commands: components, access (JSON output)
  - Consistent v1.1.0 versioning
- **Enhanced API** — Groups, validation, import/export
  - Pydantic models with validation (username 3+ chars, password 8+ chars)
  - Group endpoints with permissions
  - Import/export for bulk user management
  - Service status per user
- **Modern Frontend** — Catppuccin-styled UI
  - User/group tables with action buttons
  - Modal dialogs for create/edit
  - Toast notifications
  - Service status chips with icons
  - Import/export functionality
- **Nginx config** — Frontend + API locations

---

## ✅ Previously Done (Session 7)

### New Modules (2 in Session 7) ✅
- **secubox-repo** (v1.0.0) — APT repository management module
  - repoctl CLI for package management
  - GPG key generation and signing
  - Multi-distribution support (bookworm, trixie)
  - Web dashboard for repository status
  - FastAPI endpoints for remote management

- **secubox-hardening** (v1.0.0) — Kernel and system hardening
  - hardeningctl CLI for security management
  - Sysctl hardening (ASLR, kptr_restrict, SYN cookies, etc.)
  - Module blacklist (uncommon protocols, filesystems)
  - Security benchmark tool
  - Web dashboard with security score

### APT Repository Deployment Scripts ✅
- **export-secrets.sh** — Export GPG + SSH keys for GitHub Actions
- **local-publish.sh** — Local test server (reprepro + Python HTTP)
- **install.sh** — User installation script (`curl | bash`)
- **README updates** — Complete deployment documentation

### Nextcloud File Sync ✅
- **nextcloudctl v1.2.0** — Full Nextcloud LXC management
- **Debian bookworm LXC** — PHP 8.2, Nginx, Redis, SQLite
- **Nextcloud 30.0.4** — Latest stable release
- **Port 9080** — Avoids CrowdSec conflict (8080)
- **Redis caching** — Fixed systemd unit for LXC
- **Admin user** — ncadmin / secubox123
- **WebDAV, CalDAV, CardDAV** — All enabled
- **Bind mounts** — /srv/nextcloud/{data,config} persistent

### Gitea Git Server ✅
- **giteactl v1.4.0** — Full Gitea LXC management
- **Alpine Linux LXC** — Lightweight container via debootstrap
- **Host networking** — No br0 bridge required (lxc.net.0.type = none)
- **Two-phase install** — install-init.sh → start-gitea.sh
- **PATH/HOME fix** — Export environment for su-exec
- **WORK_PATH config** — Gitea 1.22.6 requirement
- **Admin user** — Created via `giteactl user add`
- **SSH + HTTP** — Port 2222 (SSH), 3000 (HTTP)
- **LFS support** — Enabled with proper config

### AppArmor Security Profiles ✅
- **Base profile** — secubox-base abstractions for all services
- **Hub profile** — Menu, systemd, monitoring access
- **Mail profile** — LXC containers, ACME, mail data
- **WireGuard profile** — wg tools, config, QR codes
- **CrowdSec profile** — cscli, logs, API socket
- **Generic profile** — For simple API services
- **Install script** — scripts/install-apparmor.sh

### Audit Rules ✅
- **50-secubox.rules** — Comprehensive audit rules
- **Config changes** — secubox, wireguard, mail, haproxy
- **Security events** — JWT access, privilege escalation, failed access
- **System changes** — nftables, netplan, SSH, sudo
- **Install script** — scripts/install-audit.sh

### ClamAV Antivirus ✅
- **mailserverctl v2.6.0** — av setup/enable/disable/status/update commands
- **ClamAV daemon + milter** — Installed in LXC container via apt
- **Postfix integration** — Via clamav-milter on port 8894
- **Freshclam** — Automatic virus definition updates
- **API endpoints** — /av/status, /av/setup, /av/enable, /av/disable, /av/update
- **secubox-mail v2.0.0** — Full mail security stack complete

### Postgrey Greylisting ✅
- **mailserverctl v2.5.0** — grey setup/enable/disable/status commands
- **Postgrey** — Installed in LXC container via apt
- **Whitelist** — Common mail providers (Google, Microsoft, Yahoo, etc.)
- **Postfix integration** — smtpd_recipient_restrictions with policy service
- **Auto-whitelist** — After 5 successful deliveries from same sender
- **API endpoints** — /grey/status, /grey/setup, /grey/enable, /grey/disable
- **secubox-mail v1.9.0** — Deployed and tested

### Service Fixes ✅
- **secubox-haproxy v1.1.1** — Fixed systemd namespace error when HAProxy not installed
- **RuntimeDirectory=haproxy** — Automatically creates /run/haproxy
- **All 32 services** — Now running on VM

### SpamAssassin Integration ✅
- **mailserverctl v2.4.0** — spam setup/enable/disable/status/update commands
- **SpamAssassin + spamc** — Installed in LXC container
- **Postfix content filter** — Integrates via spamfilter pipe
- **Bayes learning** — Auto-learn enabled by default
- **API endpoints** — /spam/status, /spam/setup, /spam/enable, /spam/disable

### Mail Autodiscover ✅
- **Thunderbird/Evolution** — /mail/config-v1.1.xml (Mozilla autoconfig)
- **Outlook** — /autodiscover/autodiscover.xml (Microsoft format)
- **Apple iOS/macOS** — /{domain}.mobileconfig (configuration profile)
- **Well-known** — /.well-known/autoconfig/mail/config-v1.1.xml
- **Public endpoints** — No authentication required for client access

### OpenDKIM Integration ✅
- **mailserverctl v2.3.0** — Full DKIM/OpenDKIM support
- **dkim setup** — Complete setup (keygen + install + configure + sync)
- **dkim keygen** — Generate 2048-bit RSA key pair
- **dkim status** — Show key, DNS record, service status
- **OpenDKIM** — Installed in LXC container with milter
- **Postfix integration** — smtpd_milters configured
- **DNS records** — Standard and BIND format output
- **API endpoints** — /dkim/status, /dkim/setup, /dkim/keygen, /dkim/sync

### ACME Certificate Support ✅
- **mailserverctl v2.2.0** — ACME certificate management
- **acme.sh integration** — issue, renew, install commands
- **SSL/TLS commands** — ssl status, ssl selfsigned
- **Dovecot SSL** — TLS 1.2+ configuration
- **API endpoints** — /acme/status, /acme/issue, /acme/renew

### Previous: Mail Server LXC ✅
- **mailserverctl v2.1.0** — Debian bookworm via debootstrap
- **roundcubectl v1.4.0** — Debian bookworm via debootstrap
- **Host networking** — LXC containers use `lxc.net.0.type = none`
- **Three-fold commands** — Both scripts have `components` and `access` JSON commands
- **Postfix + Dovecot** — Tested and working with authentication

### VM Service Count ✅
- **30 services running** — All SecuBox APIs active
- **Disk expanded** — VM disk resized to 16GB for Debian LXC

---

## ⚠️ Known Issues

### Debian LXC Disk Space
- **VM root partition** — Only 2.4GB, Debian debootstrap needs ~500MB per container
- **Solution** — Move /srv/lxc to /data partition (symlinked)
- **Recommendation** — Production systems need 8GB+ root partition

---

## ⬜ Next Up

### PRIORITY: Extend Existing Modules (Before Adding New)
Per user request: Focus on completing and enhancing existing modules before porting new ones from OpenWRT.

**Modules to Enhance:**
1. ~~**secubox-netmodes** — Integrate secubox-net-detect for auto-configuration~~ ✅ Done (Session 26)
2. ~~**secubox-system** — Add board detection info to system status~~ ✅ Done (Session 30)
3. ~~**secubox-core** — Integrate kiosk setup option in admin~~ ✅ Done (Session 30)
4. ~~**secubox-hub** — Add network mode selection to dashboard~~ ✅ Done (Session 30)
5. ~~**secubox-portal** — Add device-specific theming based on board~~ ✅ Done (Session 31)

**✅ All Priority Module Enhancements Complete!**

### SecuBox SOC — Phase 5: Hierarchical Mode ✅

**Phase 5 implements multi-tier deployment:**
- [x] Mode configuration (edge/regional/central) via API
- [x] Regional-to-central aggregation (upstream push)
- [x] Cross-region threat correlation
- [x] Multi-tier enrollment workflow
- [x] Global View page for central SOC
- [x] Settings page for mode configuration
- [ ] Deploy and test multi-tier setup (requires hardware)

**Packages Updated:**
- `secubox-soc-gateway_1.1.0-1_all.deb` (21KB) - Added hierarchy lib
- `secubox-soc-web_1.1.0-1_all.deb` (67KB) - Added GlobalView & Settings

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                      CENTRAL SOC                             │
│   secubox-soc-gateway (central) + secubox-soc-web (React)   │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  REGIONAL SOC   │ │  REGIONAL SOC   │ │  REGIONAL SOC   │
│  (Paris)        │ │  (London)       │ │  (New York)     │
└─────────────────┘ └─────────────────┘ └─────────────────┘
       │                   │                   │
   ┌───┴───┐           ┌───┴───┐           ┌───┴───┐
   ▼       ▼           ▼       ▼           ▼       ▼
┌─────┐ ┌─────┐     ┌─────┐ ┌─────┐     ┌─────┐ ┌─────┐
│Edge │ │Edge │     │Edge │ │Edge │     │Edge │ │Edge │
│Node │ │Node │     │Node │ │Node │     │Node │ │Node │
└─────┘ └─────┘     └─────┘ └─────┘     └─────┘ └─────┘
```

**Build & Test Live USB:**
```bash
sudo bash image/build-live-usb.sh --local-cache
# Flash and test on x64 hardware or VM
```

### Phase 8: Applications (In Progress)

**Completed:**
- [x] secubox-ollama — LLM inference ✅
- [x] secubox-jellyfin — Media server ✅
- [x] secubox-lyrion — Audio server ✅
- [x] secubox-zigbee — IoT gateway ✅
- [x] secubox-localai — Local AI inference ✅
- [x] secubox-jabber — XMPP messaging ✅
- [x] secubox-magicmirror — Smart display ✅
- [x] secubox-mmpm — MagicMirror packages ✅
- [x] secubox-redroid — Android container ✅

**Phase 9 (Built, not deployed):**
- [x] secubox-vault — Secrets management
- [x] secubox-cloner — System backup/restore
- [x] secubox-vm — Virtualization (KVM/LXC)

**Phase 10 (Built, not deployed):**
- [x] secubox-wazuh — SIEM
- [x] secubox-ossec — Host IDS

> See [REMAINING-PACKAGES.md](REMAINING-PACKAGES.md) for full Phase 8-10 inventory

---

### Mail Server ✅ COMPLETE
All optional mail security features implemented:
- DKIM signing (OpenDKIM)
- Spam filtering (SpamAssassin)
- Greylisting (Postgrey)
- Virus scanning (ClamAV)

### CI/CD Workflows ✅
- **build-packages.yml** — Dynamic matrix for all 33 packages
- **build-image.yml** — System images for 5 boards (MOCHAbin, ESPRESSObin, VM)
- **Dual architecture** — arm64 + amd64 builds
- **Auto-publish** — On tag v* → APT repo + GitHub Release
- **GPG signed** — SHA256SUMS with GPG signatures
- **build-all.sh** — Local build script for development

### APT Repository Scripts ✅
- **export-secrets.sh** — Export GPG keys and SSH deploy keys for GitHub Actions
- **local-publish.sh** — Local testing with Python HTTP server
- **install.sh** — User installation script for apt.secubox.in
- **Deployment docs** — Complete GitHub secrets configuration

### Infrastructure
1. **Configure GitHub Secrets** — Add GPG_PRIVATE_KEY, DEPLOY_SSH_KEY, DEPLOY_KNOWN_HOSTS
2. **Deploy apt.secubox.in server** — Run setup-repo-server.sh on VPS
3. **Create initial release** — Tag v1.0.0 to trigger workflows
4. **Documentation** — User guide, API docs

---

## ✅ Précédemment terminé

### Three-fold Architecture ✅
- **6 modules upgraded** — vhost, haproxy, streamlit, gitea, metablogizer, roundcube
- **All *ctl scripts have** — `components` and `access` JSON commands
- **Version bumps** — 1.1.0 for all modules with three-fold

### Mail Integration ✅
- **mail-lxc and webmail-lxc** — Integrated into secubox-mail (no standalone UI)
- **secubox-mail 1.3.0** — Full mail management with installation wizard
- **roundcubectl** — Added three-fold commands (components, access)
- **API endpoints** — /webmail/start, /webmail/stop, /webmail/install, /settings, /dkim/setup

### Mail Frontend ✅
- **Install banner** — Shows when mail not installed with wizard button
- **Settings tab** — Domain, hostname, IP, ports configuration
- **Per-component controls** — Install/Start/Stop buttons for mail server and webmail
- **DNS Setup modal** — Shows required DNS records
- **DKIM Setup** — Generate DKIM keys with one click

### Maintainer Update ✅
- **Gerald KERMA <devel@cybermind.fr>** — Propagated to 33 control + 33 changelog files

### Authentication Fix ✅
- **JWT secret mismatch fixed** — Portal and modules now use same secret
- **Fixed redirect paths** — All 12 modules now redirect to `/portal/login.html` instead of `/login/`
- **Token flow working** — Login → localStorage → API auth chain verified

### New Modules (4) ✅
- **secubox-c3box** — Services Portal page with links to all SecuBox services
- **secubox-gitea** — Gitea Git Server management (LXC, repos, users, backups)
- **secubox-nextcloud** — Nextcloud File Sync (LXC, storage, users, backups)
- **secubox-portal** — Added to navbar, links to services portal

### Module Count ✅
- **33 packages total** — 30 services + 3 new modules
- **29 services running** — All core + new modules active on VM
- **Menu shows 26 modules** — Organized in 6 categories

---

## ✅ Précédemment terminé

### WAF + HAProxy Integration ✅
- **secubox-waf** : Web Application Firewall (300+ rules, 17 categories)
  - SQLi, XSS, RCE, LFI detection
  - VoIP/SIP, XMPP, router botnet patterns
  - CrowdSec auto-ban integration
  - Rate limiting per IP
- **secubox-haproxy** : Updated with WAF MITM integration
  - `/waf/status`, `/waf/toggle`, `/waf/routes`, `/waf/sync-routes`
  - Per-vhost WAF bypass controls
  - Config generation routes traffic through waf_inspector backend

### 2-Layer Architecture Modules ✅
- **secubox-mail-lxc** : LXC container for Postfix/Dovecot
- **secubox-webmail-lxc** : LXC container for Roundcube/SOGo
- **secubox-publish** : Unified publishing dashboard (streamlit + streamforge + droplet + metablogizer)

### New Modules Ported (4) ✅
- **secubox-dns** : DNS Master / BIND zone management (zones, records, DNSSEC)
- **secubox-mail** : Email server Postfix/Dovecot (users, aliases, dkim)
- **secubox-users** : Unified identity management (7 services: nextcloud, matrix, gitea, email, jellyfin, peertube, jabber)
- **secubox-webmail** : Roundcube/SOGo management (config, cache, plugins)

### Script Fix ✅
- **scripts/new-module.sh** : Removed manual systemd installation (conflicts with dh_installsystemd)

### Dynamic Menu System ✅
- **sidebar.js** : Shared sidebar component for all modules
- **Menu API** : `/api/v1/hub/menu` returns 22 modules in 6 categories
- **menu.d/** : JSON definitions per package (installed via debian/rules)
- **CSS fixes** : Added missing variables (--cyan, --yellow, --purple) to all modules

### Module Scaffold ✅
- **.claude/skills/module.md** : Skill documentation
- **scripts/new-module.sh** : Complete package scaffold script

### All Services Running ✅
26 secubox-* services active on VM:
- secubox-hub, secubox-system
- secubox-crowdsec, secubox-wireguard, secubox-auth, secubox-nac
- secubox-netmodes, secubox-dpi, secubox-qos, secubox-vhost
- secubox-netdata, secubox-mediaflow
- secubox-haproxy, secubox-cdn, secubox-waf
- secubox-droplet, secubox-streamlit, secubox-streamforge, secubox-metablogizer
- secubox-dns, secubox-mail, secubox-users, secubox-webmail
- secubox-mail-lxc, secubox-webmail-lxc, secubox-publish

---

## ✅ Completed this session

### Build & Integration ✅
- **30 packages built** — All packages compile successfully
- **27 services running** — Full deployment on VM
- **27 nginx configs** — Modular API routing working
- **Fixed prerm scripts** — No longer remove nginx configs on upgrade
- **Fixed hub uptime** — int(float()) for /proc/uptime parsing
- **Fixed portal login** — Now stores JWT token to localStorage
- **Fixed logout** — Clears tokens and redirects properly

---

## ⬜ Next Up

1. **Deploy apt.secubox.in** — Setup reprepro server
2. **Publish packages** — Upload all 30 debs to APT repo
3. **Documentation** — User guide, API docs

---

## 🛠️ Quick Commands

```bash
# SSH to VM (key auth configured)
ssh -p 2222 root@localhost

# Create new module
./scripts/new-module.sh myapp "Description" apps "🚀" 500

# Build package
cd packages/secubox-<name> && dpkg-buildpackage -us -uc -b

# Deploy to VM
scp -P 2222 *.deb root@localhost:/tmp/ && ssh -p 2222 root@localhost "dpkg -i /tmp/*.deb"

# Check menu API (should show 22 modules)
curl -sk https://localhost:8443/api/v1/hub/menu | jq '.total_modules'
```

---

## 🗓️ Historique récent

- **2026-03-27** (Session 21):
  - Fixed live ISO boot console issues (flickering, no login prompt)
  - Masked 14 services that cause restart loops on live boot
  - Fixed getty autologin conflict with live-config
  - Disabled martian packet logging and systemd status messages
  - Added debug boot menu entries (rescue, emergency, no-preseed)
  - Live ISO now boots with stable console login
  - Commit pushed: `288b27a Fix live ISO boot console issues`

- **2026-03-26** (Session 20):
  - x64 Installer ISO build system: build-installer-iso.sh (hybrid live/installer)
  - C3Box clone scripts: export-c3box-clone.sh, build-c3box-clone.sh
  - streamlitctl v1.0.0: Streamlit LXC controller (521 lines)
  - Exported C3Box config: 50 packages, 3 LXC containers, full settings
  - VSCode tasks for ISO building added
  - Commit pushed: `141b0c0 Add x64 installer ISO and C3Box clone build system`

- **2026-03-26** (Session 19):
  - Socket directory fix: secubox-runtime.service ensures /run/secubox exists
  - ReDroid integration: Android in Container LXC setup scripts
  - VSCode tasks for ReDroid management added
  - Both commits pushed to GitHub

- **2026-03-26** (Session 18):
  - Master-Link Admin Dashboard v1.6.0
  - Localhost-only API endpoints
  - sbx-mesh-invite CLI tool v1.5.0
  - Multi-master support v1.4.0

- **2026-03-26** (Session 16):
  - UI theme toggle fixed (light/dark P31 phosphor)
  - Collapsed sidebar categories by default
  - Fixed 35+ pages with wrong body class
  - 45 module screenshots captured
  - docs/UI-GUIDE.md created
  - docs/OPENWRT-DEBIAN-COMPARISON.md created (103 vs 52 modules)
  - scripts/fix-navbar.sh created

- **2026-03-25** (Session 15):
  - Maintainer standardized to Gerald KERMA on all 51 packages
  - JWT auth added to secubox-mesh
  - Go daemon reorganized to daemon/ directory
  - Unix socket control server implemented

- **2026-03-21** (Session 2):
  - WAF module created (300+ rules, CrowdSec integration)
  - HAProxy WAF MITM integration complete
  - 2-layer architecture: mail-lxc, webmail-lxc containers
  - Unified secubox-publish module
  - All 26 services running on VM

- **2026-03-21** (Session 1):
  - Ported 4 new modules: dns, mail, users, webmail
  - Fixed new-module.sh script (removed manual systemd install)
  - Dynamic menu now shows 22 modules in 6 categories
  - All 22 services running on VM

- **2025-03-21** :
  - Dynamic menu system complete (18 modules, 6 categories)
  - Shared sidebar.js for consistent navigation
  - CSS variables fixed across all modules
  - Module scaffold skill created

- **2025-03-20** :
  - Phase 4 complete: apt.secubox.in (reprepro, GPG, CI)
  - Local cache build system added
  - Image VM x64 built successfully

## VirtualBox Kiosk Fix (2026-04-08)

**Problem**: Kiosk mode causes black screen in VirtualBox due to X11/graphics driver issues.

**Solution**: 
1. Skip kiosk service on VirtualBox (detect via `systemd-detect-virt | grep oracle`)
2. Default target set to `multi-user.target` (console) instead of `graphical.target`
3. Users access via SSH or web UI when testing in VirtualBox
4. Kiosk works normally on real hardware

**Files modified**:
- `image/systemd/secubox-kiosk.service` - Added VirtualBox skip check
- `image/build-live-usb.sh` - Changed default target to multi-user

**Testing**:
- VirtualBox: Boot to console, access via SSH (port 2222) or web UI (port 9443)
- Real hardware: Kiosk starts automatically as before

## Dashboard Real Data Fix (2026-04-14)

**Problem**: Dashboard showing placeholder values:
- Memory: -/-
- Storage: -/-
- LAN/BR-WAN: -
- Module versions: all showing "-"

**Root Causes**:
1. `loadNetwork()` had hardcoded IP addresses instead of using API data
2. No calls to `/memory` and `/disk` endpoints for actual used/total values
3. `network_summary` API didn't return IP addresses
4. Module version info wasn't included in service status data

**Solutions**:
1. Updated `network_summary` API to return actual LAN/WAN IP addresses
2. Added `loadMemory()` and `loadDisk()` functions to fetch real data
3. Updated `loadNetwork()` to use API response for IP addresses
4. Added `_get_package_version()` helper to fetch installed package versions
5. Updated modules table to display actual versions from dpkg

**Files Modified**:
- `packages/secubox-hub/api/main.py`:
  - Enhanced `network_summary` endpoint with IP address discovery
  - Added `_get_package_version()` function
  - Updated `_svc()` to include package versions
- `packages/secubox-hub/www/index.html`:
  - Fixed `loadNetwork()` to use API data instead of hardcoded IPs
  - Added `loadMemory()` and `loadDisk()` functions
  - Updated modules table to show real versions
  - Added new functions to refresh cycle

## EspressoBin Slipstream Consistency (2026-04-14)

**Problem**: EspressoBin build only checked `output/debs` while AMD64 also checked cache.

**Solution**: Updated `build-ebin-live-usb.sh` to:
- Check both `output/debs` and `~/.cache/secubox/debs`
- Prefer output/debs over cache (for newer local builds)
- Install secubox-core first as dependency
- Use `--force-overwrite` for duplicate files

**Files Modified**:
- `image/build-ebin-live-usb.sh` - Consistent slipstream with AMD64 build

## EspressoBin Build Fix - $HOME Issue (2026-04-14)

**Problem**: EspressoBin live USB build failed after step 3/7, jumping to cleanup. The slipstream step couldn't find packages.

**Root Cause**: When running with `sudo`, `$HOME` becomes `/root` instead of `/home/reepost`. The script used `${HOME}/.cache/secubox/debs` which resolved to `/root/.cache/secubox/debs` (non-existent).

**Solution**: Updated `build-ebin-live-usb.sh`:
1. Added `SUDO_USER` detection to get original user's home directory
2. Changed `ls` to `find` to avoid `set -e` failures when no files match

```bash
# Get original user's home when running with sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    USER_HOME="$HOME"
fi
CACHE_DEBS="${USER_HOME}/.cache/secubox/debs"
```

**Files Modified**:
- `image/build-ebin-live-usb.sh` - Fixed slipstream $HOME handling

## Build Status (2026-04-14 18:20)

- **AMD64 Live USB**: ✅ Complete (8GB image)
  - Location: `output/secubox-live-amd64-bookworm.img`
  - 126 packages slipstreamed

- **EspressoBin Live USB**: 🔄 Building (ARM64/QEMU emulation)
  - Build restarted with fixed script
  - Progress: Debootstrap phase

## Build Complete (2026-04-14 22:45)

### AMD64 Live USB ✅
- **Image**: `output/secubox-live-amd64-bookworm.img` (8.0 GB)
- **SHA256**: Available at `.img.sha256`
- All 126 SecuBox packages slipstreamed

### EspressoBin V7 Live USB ✅
- **Image**: `output/secubox-espressobin-v7-live-usb.img` (2.0 GB)
- **SHA256**: Available at `.img.sha256`
- All SecuBox packages slipstreamed
- Includes secubox-flash-emmc tool

### Fixes Applied:
1. Fixed `$HOME` issue in EspressoBin build when running with sudo
2. Changed `ls` to `find` to avoid `set -e` failures
3. Added error handling for dpkg installation step
4. Fixed grep in package count verification

### How to Use:

**AMD64 (x86_64):**
```bash
sudo dd if=output/secubox-live-amd64-bookworm.img of=/dev/sdX bs=4M status=progress
```

**EspressoBin V7:**
```bash
sudo dd if=output/secubox-espressobin-v7-live-usb.img of=/dev/sdX bs=4M status=progress
# Boot from USB, then run:
secubox-flash-emmc
```


---

## 2026-04-20: Remote UI Enhanced Architecture

### New Gadget Modes (secubox-otg-gadget.sh v2.0)

| Mode | Functions | Purpose |
|------|-----------|---------|
| **normal** | ECM + ACM | Network + Serial (default) |
| **flash** | Mass Storage + ACM | Boot EspressoBin from USB for recovery/flashing |
| **debug** | ECM + Mass Storage + ACM | Network + File exchange + Serial |

### Round UI as Remote Control (Not Just Clock)

The Round UI should function as a **full remote control interface**:

1. **Mode Selector**
   - Touch to switch between Normal/Flash/Debug modes
   - Visual indicator of current mode

2. **Status Panels**
   - Normal: EspressoBin metrics (CPU, MEM, DISK, etc.)
   - Flash: Boot status, flash progress, U-Boot console
   - Debug: Connection status, file transfer, serial output

3. **Interactive Controls**
   - Reboot EspressoBin
   - Start/Stop services
   - Switch network modes
   - Trigger eMMC flash

4. **U-Boot Console**
   - In Flash mode, display serial output from /dev/ttyGS0
   - Send commands to U-Boot

### Files Updated

- `remote-ui/round/secubox-otg-gadget.sh` - Added flash/debug modes + status JSON
- `image/firstboot.sh` - Added filesystem expansion for eMMC

### Next Steps

1. Update Round UI index.html with mode-aware interface
2. Add WebSocket or polling for serial console output
3. Create flash progress indicator
4. Test USB enumeration between Pi Zero and EspressoBin

### Current Issue

Pi Zero USB enumeration failing with error -110 (timeout). Possible causes:
- Cable issue (data lines)
- Power issue
- Gadget not ready fast enough


---

## 2026-04-22: HyperPixel DPI / I2C Pin Conflict (RESOLVED)

### Issue
HyperPixel 2.1 Round display not working on Pi Zero W - screen stays blank.

### Root Cause
Kernel error: `pin gpio2 already requested by i2c; cannot claim for dpi`

The DPI display driver needs GPIO pins 2/3, but `dtparam=i2c_arm=on` enables I2C on those same pins, causing a conflict.

### Solution
Remove from config.txt:
```
# DO NOT USE - conflicts with DPI:
# dtparam=i2c_arm=on
# dtparam=spi=on
```

The hyperpixel2r overlay:
- Uses **i2c10** (software I2C) for touch controller
- LCD init uses **pigpio software SPI** (bit-banging), not hardware SPI

### Files Updated
- `remote-ui/round/build-eye-remote-image.sh` - Removed i2c_arm/spi from config
- Config.txt on SD card - Disabled conflicting parameters

### Lesson Learned
When using DPI displays on Raspberry Pi, avoid enabling standard I2C/SPI that may conflict with DPI GPIO pins.

---

## 2026-04-22: Pi Zero W requires explicit DPI timings (INVESTIGATING)

### Issue
Display still blank after fixing I2C conflict. Pi Zero W not booting or not creating framebuffer.

### Root Cause (suspected)
The `hyperpixel2r` overlay may be designed for KMS mode only. Pi Zero W (BCM2835) doesn't support KMS, so the overlay alone doesn't configure DPI output.

### Solution
Add explicit DPI timing parameters to config.txt:

```
enable_dpi_lcd=1
display_default_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 59 480 0 15 60 15 0 0 0 60 0 19200000 6
framebuffer_width=480
framebuffer_height=480
```

These settings explicitly tell the VideoCore GPU how to drive the DPI display, bypassing the need for KMS driver support.

### Testing
- Awaiting confirmation that explicit DPI settings fix the display
