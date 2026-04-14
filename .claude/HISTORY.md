# HISTORY — SecuBox-DEB Migration Log
*Tracking completed milestones with dates*

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
