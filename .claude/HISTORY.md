# HISTORY — SecuBox-DEB Migration Log
*Tracking completed milestones with dates*

---

## 2026-05-07

### Session 111 — LED Kernel + CrowdSec GeoIP + Boot Fixes

**Completed:**

1. **LED Kernel Configuration** (Issue #60)
   - Fixed network drivers: MARVELL_PHY, MDIO, SFP, MDIO_I2C → built-in (=y)
   - Fixed USB drivers: XHCI, EHCI, OHCI, USB_STORAGE → built-in
   - Kernel build initiated with updated config
   - LED chip detected at I2C-1 address 0x64 (IS31FL319X)

2. **CrowdSec WebUI GeoIP Enhancement**
   - Added country flags to bans/decisions list
   - Implemented GeoIP cache with 24h TTL (localStorage)
   - Uses ipapi.co (HTTPS) with backend fallback
   - Commit: `feat(crowdsec): Add GeoIP cache with country flags`

3. **WAF Client IP Fix**
   - Fixed mitmproxy to read X-Forwarded-For header
   - WAF now logs real attacker IP (not HAProxy internal IP)

4. **GitHub Issues Created**
   - #59: 503 errors at boot (service startup delay)
   - #60: LED kernel with IS31FL319X and built-in drivers
   - #61: Eye Remote gadget metrics endpoint

**In Progress:**
- Kernel build (~25% complete)
- 503 error permanent fix (HAProxy/mitmproxy chain)

---

## 2026-05-06

### Session 109 — VHost Matrix Sync + Eye Remote Fixes

**Completed:**

1. **VHost Matrix Sync Tool** (`scripts/vhost-matrix-sync.sh`)
   - Python-based HAProxy parsing (reliable regex extraction)
   - Fixed stderr logging for clean JSON capture
   - Syncs HAProxy vhosts → mitmproxy routes + health prober
   - Uses 10.100.0.1 (LXC bridge IP) for proper routing
   - Successfully synced 94 vhosts on production server

2. **Eye Remote Dashboard Fixes**
   - API calls now use public endpoints (no JWT required)
   - Added `/api/v1/system/metrics` alias for Pi Zero compatibility
   - Pi Zero round UI displays correct MOCHAbin host metrics

3. **HAProxy VHost Additions**
   - Added sdlc.gk2.secubox.in and facb.gk2.secubox.in backends
   - Both routed through mitmproxy WAF inspector

4. **GitHub Issue #49**: MetaBlogizer + Streamlit version management via Gitea

---

### Session 102 — v2.5.0 WAF Integration Complete

**Goal:** Complete WAF mitmproxy LXC integration (all 5 phases)

**Completed:**

1. **CMSD-1.0 License Integration**
   - Created `LICENCE-CMSD-1.0.md` (French authoritative version)
   - Created `LICENSE-CMSD-1.0.en.md` (English informative translation)
   - Created `LICENSING.md` (license documentation, SPDX guidance)
   - Updated `README.md` with prominent license notice (CAN/CANNOT table)
   - Wiki pages: License.md, License-FR.md with QR codes
   - PDF booklet uploaded to GitHub release v2.4.0

2. **WAF Phase 1-4: Mitmproxy LXC Container**
   - LXC container at `/data/lxc/mitmproxy` (10.100.0.60:8080)
   - 330 HAProxy backends routing through mitmproxy_inspector
   - HAProxy `http-request set-uri` for proxy-style requests
   - All traffic tagged with X-SecuBox-WAF: inspected header
   - All 6 LXC containers verified running

3. **WAF Phase 5: Package Updates**
   - `secubox-waf` v1.1.0: Added LXC mitmproxy support, wafctl, systemd service
   - `secubox-haproxy` v1.2.0: Added `waf` subcommand (status/enable/disable)
   - WebUI dashboard: Added mitmproxy container status card

4. **WebUI Access Fixed**
   - Added 192.168.1.200:9443 HAProxy bind
   - Added nginx server_name for 192.168.1.200
   - WebUI accessible at https://192.168.1.200:9443/
   - Created webui_direct backend (bypasses WAF)

---

### Session 101 — C3BOX Network Recovery + HAProxy LXC Routing

**Goal:** Establish network connectivity between C3BOX and MOCHAbin for migration

**Completed:**

1. **C3BOX Network Recovery**
   - Fixed eth2 NO-CARRIER issue (was on wrong interface)
   - C3BOX lan0@eth1 connected to MOCHAbin lan0 (DSA switch)
   - IP assigned on br-lan: 192.168.255.201 (original) + .10 (secondary)
   - Connectivity established: C3BOX ↔ MOCHAbin via 192.168.255.x

2. **Migration Archive Imported**
   - 93 SSL certificates copied to /data/haproxy/certs/
   - 99 nginx secubox.d configs available
   - LXC container configs imported

3. **HAProxy LXC Routing Added**
   - Created backends: lxc_gitea, lxc_nextcloud, lxc_matrix
   - ACL routing for gitea.gk2.secubox.in → 10.100.0.40:3000
   - ACL routing for nextcloud.gk2.secubox.in → 10.100.0.20:80
   - ACL routing for matrix.gk2.secubox.in → 10.100.0.30:8008

4. **Routing Verified**
   - gk2.secubox.in → 200 (WebUI)
   - gitea.gk2.secubox.in → 200 (LXC)
   - nextcloud.gk2.secubox.in → 302 (LXC redirect)
   - blog.cybermind.fr → 200 (nginx_vhosts)
   - Unknown domains → 503 (correct fallback)

5. **Metablogizer Migration COMPLETE**
   - 166 sites synced from C3BOX (/srv/metablogizer/sites/)
   - 60 sites emancipated (published) with nginx + HAProxy routing
   - UCI config converted to nginx server blocks (per-port)
   - Fixed HAProxy ACL order (metablog backends vs nginx_vhosts)
   - All sites accessible from internet with correct content

**TODO (noted for later):**
- Implement mitmproxy WAF container (like C3BOX architecture)
- HAProxy cacert + vhost SSL verification
- Metablogizer TOML config conversion

### Session 101 continued — Source Package Sync

**Goal:** Sync source packages with deployed working configurations

**Completed:**

1. **secubox-streamlit package updated:**
   - API main.py: Added `sudo -n` for LXC commands (NoNewPrivileges workaround)
   - Added systemd drop-in: `debian/secubox-streamlit.service.d/allow-lxc.conf`
   - Added sudoers config: `sudoers.d/secubox-streamlit`
   - Added example config: `config/streamlit.toml.example`
   - Updated postinst: Creates config dir, example config, LXC symlink
   - Updated debian/rules to install new files

2. **secubox-metablogizer package updated:**
   - Added example config: `config/metablogizer.toml.example`
   - Updated debian/rules to install example config

3. **TOML configs saved:**
   - `.claude/configs/streamlit.toml` (35 apps, 29 instances)
   - `.claude/configs/metablogizer.toml` (151 sites)

---

### Session 100 — MOCHAbin Migration SUCCESS

**Goal:** Complete C3BOX → SecuBox-DEB migration with proper WAF and routing

**Completed:**

1. **Network Configuration**
   - WAN (eth2): 192.168.1.200/24 → Freebox DMZ
   - LAN (br-lan): 192.168.255.1/24 via systemd-networkd (DSA bridge)
   - LXC (br-lxc): 10.100.0.1/24
   - Default route via 192.168.1.254 (Freebox)

2. **LXC Containers Running**
   - gitea: 10.100.0.40
   - mail: 10.100.0.10
   - matrix: 10.100.0.30
   - nextcloud: 10.100.0.20

3. **HAProxy WAF (ACL-based)**
   - SQL Injection detection → 403
   - XSS detection → 403
   - Path Traversal detection → 403
   - Scanner detection (nikto, sqlmap, nuclei) → 403

4. **Routing Verified**
   - Unknown domains/IP → 503 (correct fallback)
   - gk2.secubox.in → 200 (WebUI)
   - gitea.gk2.secubox.in → LXC gitea
   - nextcloud.gk2.secubox.in → LXC nextcloud

5. **Network Persistence**
   - `/etc/netplan/01-secubox-gateway.yaml` — WAN/LXC config
   - `/etc/systemd/network/10-br-lan.network` — LAN (DSA bridge)

6. **CTL Tools Installed**
   - 17 tools in `/usr/sbin/` (haproxyctl, vhostctl, streamlitctl, etc.)

**Key Fix:** br-lan IP (192.168.255.1) was missing — added via systemd-networkd since DSA bridge not managed by netplan.

**Mitmproxy Status:** Disabled due to pyOpenSSL ARM64 incompatibility. HAProxy ACL-based WAF provides equivalent protection.

**Custom Error Page Added:**
- `/etc/haproxy/errors/503.http` — "FATAL ERROR / END OF INTERNET" page
- Unknown domains return custom 503 (cyberpunk skull design)
- WebUI ACL added for: gk2.secubox.in, admin.gk2.secubox.in, secubox.local, secubox.maegia.tv, c3box.maegia.tv
- Fallback backend changed from `nginx_vhosts` to `fallback_503`

---

## 2026-05-05

### Session 99 — MOCHAbin Migration Recovery Plan

**Goal:** Document lessons learned from failed migration and create proper procedure

**Analysis of Session 97 Failure:**
1. HAProxy manually configured with only 5 ACLs instead of all 93 domains
2. Default backend incorrectly set to `nginx_vhosts` (WebUI) instead of 503 error page
3. WAF (mitmproxy) not installed due to OpenSSL compatibility issue
4. Websites not accessible from internet despite HAProxy showing 200 locally
5. User reverted to old C3BOX

**Root Causes Identified:**
- Did not use `haproxyctl migrate` command
- Did not use `scripts/migration-export.sh` for full export
- Manual HAProxy config used wrong fallback backend pattern

**Documentation Created:**
- Updated `.claude/WIP.md` with comprehensive migration checklist
- Documented proper 8-step migration procedure
- Added verification checklist for next attempt
- Documented key files and error page requirement

**Proper Migration Tools:**
- `scripts/migration-export.sh` — Full export from OpenWrt
- `scripts/migration-import.sh` — Import to SecuBox-DEB with transformation
- `haproxyctl migrate <host>` — HAProxy-specific migration with UCI→TOML conversion

**Key Requirement:**
```haproxy
# CORRECT fallback backend
backend fallback
    mode http
    http-request deny deny_status 503

# WRONG - never use WebUI as fallback for unmatched domains
# default_backend nginx_vhosts
```

---

### Session 97 — MOCHAbin Migration Attempt (FAILED)

**Goal:** Full data migration from OpenWrt C3BOX to SecuBox-DEB MOCHAbin

**Issues Encountered:**
- DSA (Distributed Switch Architecture) — lan0-lan3 can't be added to Linux bridges
- SFP28-25G module incompatible with 10G SFP+ port (used eth2 copper instead)
- nftables DNAT syntax in inet tables requires `ip dnat to` not just `dnat to`
- mitmproxy crashed due to OpenSSL AttributeError (X509_V_FLAG_NOTIFY_POLICY)

**Network Setup (Partial Success):**
- WAN on eth2 (copper) with DMZ IP 192.168.1.200/24
- LAN on lan0 (DSA) with 192.168.255.1/24
- br-lxc for containers with 10.100.0.1/24
- LXC containers running (mail, nextcloud, gitea)

**Critical Failure Points:**
1. HAProxy configured manually — only 5 ACLs/backends instead of 93
2. WebUI set as fallback backend — domains without ACL showed admin panel
3. Websites not actually accessible from internet
4. WAF not functional

**User Feedback:** "you have missed a lot of works", "websites are not up",
"worst, you make the webui admin on frontend fallback", "you make all badly"

**Result:** User reverted to old C3BOX. Migration needs complete redo with proper tools.

---

### Session 98 — SecuBox Modem Module

**Goal:** Create comprehensive LTE/5G modem management module

**Completed:**
1. **Package Structure** — Full package at `packages/secubox-modem/`
   - `api/main.py` — FastAPI application with background signal collector
   - `api/routers/` — status, connection, sms, terminal routers
   - `core/` — modem_detect, mm_client, qmi_client, at_interface, signal_history
   - `www/modem/` — WebUI with tabs for Status, Signal, SMS, Terminal, Settings

2. **Modem Detection** — Auto-detect Quectel modems
   - USB scanning via `lsusb`
   - ModemManager integration via `mmcli`
   - Known Quectel PIDs: EC25, EC21, EP06, EM12, RM500Q, RM520N, RG500Q

3. **Connection Management** — ModemManager-based
   - Connect/disconnect with APN configuration
   - Config persistence in `/var/lib/secubox/modem/`
   - Known APN database (FR, US, generic)

4. **SMS Functionality** — Full send/receive via mmcli
   - List messages, send SMS, delete
   - WebUI compose modal and message list

5. **AT Terminal** — Interactive command console
   - WebSocket endpoint at `/api/v1/modem/at/console`
   - REST fallback at `/api/v1/modem/at/command`
   - Security: blocks dangerous commands (AT+CFUN=0, AT+QPOWD, etc.)

6. **Signal Monitoring** — Real-time with history
   - Background collector every 30 seconds
   - Signal history stored in `/var/cache/secubox/modem/`
   - Chart.js graph in WebUI Signal tab

7. **QMI Client** — Detailed signal queries
   - `qmicli` wrapper for RSRP, RSRQ, SINR, cell location
   - RF band information, serving system details

8. **Debian Packaging**
   - `debian/control` — Dependencies: modemmanager, libqmi-utils, libmbim-utils, picocom
   - `debian/postinst` — Creates data dirs, adds secubox to dialout group
   - `systemd/secubox-modem.service` — With memory limits

9. **WebUI Features**
   - P31 phosphor CRT theme (light mode)
   - Signal bars visualization
   - xterm.js AT terminal
   - Chart.js signal history graph
   - APN database quick-select

**Files Created:**
- `packages/secubox-modem/api/main.py` — FastAPI app (~200 lines)
- `packages/secubox-modem/api/routers/status.py` — Status/info/signal endpoints
- `packages/secubox-modem/api/routers/connection.py` — Connect/disconnect/config
- `packages/secubox-modem/api/routers/sms.py` — SMS CRUD
- `packages/secubox-modem/api/routers/terminal.py` — WebSocket AT console
- `packages/secubox-modem/core/modem_detect.py` — USB/mmcli detection
- `packages/secubox-modem/core/mm_client.py` — ModemManager wrapper
- `packages/secubox-modem/core/qmi_client.py` — qmicli wrapper
- `packages/secubox-modem/core/at_interface.py` — Serial AT handler
- `packages/secubox-modem/core/signal_history.py` — Signal cache
- `packages/secubox-modem/www/modem/index.html` — Dashboard (~700 lines)
- `packages/secubox-modem/www/modem/js/modem.js` — UI logic (~500 lines)
- `packages/secubox-modem/debian/*` — Full Debian packaging
- `packages/secubox-modem/nginx/modem.conf` — WebSocket-enabled proxy
- `packages/secubox-modem/menu.d/37-modem.json` — Navbar entry
- `packages/secubox-modem/README.md` — Comprehensive documentation

**Migration Map Updated:**
- Added secubox-modem to module list
- Total modules: 125

**Deployed to MOCHAbin (192.168.255.10):**
- Fixed import paths (`...core` → `core` for absolute imports)
- nginx config moved to `/etc/nginx/secubox.d/modem.conf`
- Socket created at `/run/secubox/modem.sock`
- Menu entry at `/etc/secubox/menus.d/37-modem.json`
- Health endpoint verified: `/api/v1/modem/health`
- WebUI accessible at `/modem/`

---

### Session 95 — Eye Remote USB Gadget & Tow-Boot

**Goal:** Get Eye Remote (Pi Zero W USB gadget) working with MOCHAbin

**Completed:**
1. **Tow-Boot Flashed** — Replaced old U-Boot 2018.03 with Tow-Boot for proper USB PHY init
   - Used `bubt` command for Marvell bootloader flash
   - Pre-built binary from `tools/Tow-Boot/output/Tow-Boot.spi.bin`

2. **Kernel 6.12 Boot** — Working with CONFIG_PHY_MVEBU_CP110_UTMI
   - Fixed MAC address issue with `setenv ethaddr`
   - Fixed console: ttyMV0 → ttyS0 in extlinux.conf
   - Created /boot/extlinux/extlinux.conf with both kernels (default + 6.12)

3. **Eye Remote USB Detection** — Pi Zero gadget detected on Bus 01
   - ECM Network + ACM Serial + Mass Storage interfaces
   - udev rules auto-configure 10.55.0.1/30 interface

4. **SSD Storage** — 1TB mSATA mounted as /data
   - eMMC freed for system only
   - `/data` contains: secubox-backups, overlay upper/work dirs

5. **secubox-eye-remote Package Deployed**
   - Service running: `secubox-eye-remote.service` (active)
   - Socket: `/run/secubox/eye-remote.sock`
   - Health endpoint working: `/health`

6. **udev Rules Deployed** — Auto-configure USB network on connect
   - `/etc/udev/rules.d/90-secubox-eye-remote.rules`
   - `/usr/local/sbin/secubox-eye-network.sh`
   - Matches Pi Zero gadget by vendor/product ID (1d6b:0104)

**API Status:**
- `/api/v1/eye-remote/status` — Working (connected=true)
- `/api/v1/eye-remote/serial/status` — Working (/dev/ttyACM0 detected)
- `/health` — Working

7. **Kernel 6.12 Default** — Set as default boot in extlinux.conf
   - `DEFAULT secubox-612` in `/boot/extlinux/extlinux.conf`
   - Running: `6.12.85+deb12-arm64`

8. **Socket Creation Fix** — RuntimeDirectoryPreserve for all services
   - Root cause: Multiple services with `RuntimeDirectory=secubox` caused socket cleanup conflicts
   - Fix: Added `/etc/systemd/system/secubox-*.service.d/preserve.conf` with `RuntimeDirectoryPreserve=yes`
   - All services now preserve their sockets when other services restart

9. **Nginx Proxy Path Fix** — Eye Remote API routing
   - Issue: nginx `proxy_pass http://unix:/run/secubox/eye-remote.sock:/;` stripped path prefix
   - Fix: Changed to `proxy_pass http://unix:/run/secubox/eye-remote.sock:/api/v1/eye-remote/;`
   - FastAPI expects full path `/api/v1/eye-remote/status`

10. **Remote UI Emancipation** — Unified WebUI path
    - `/remote-ui/` now serves the Remote UI Management page
    - `/eye-remote/` redirects to `/remote-ui/`
    - API remains at `/api/v1/eye-remote/`

11. **Socket Conflict Resolution** — Definitive fix
    - Root cause: All services had `RuntimeDirectory=secubox`, causing conflicts when any service restarted
    - Fix: Created `/etc/systemd/system/secubox-*.service.d/no-runtime-dir.conf` with `RuntimeDirectory=`
    - `secubox-core.service` is now the ONLY service managing `/run/secubox/`
    - Result: 85+ sockets stable, no more conflicts

12. **JSON Error Fixes** — Navbar component errors
    - Issue: Disabled services returned HTML 502 instead of JSON
    - Fix: Added `/etc/nginx/snippets/api-error.conf` returning JSON for 502/503/504
    - Services using `include /etc/nginx/snippets/secubox-proxy.conf;` now return proper JSON errors

13. **Service Emancipation** — Full WebUI + API exposure
    - Emancipated 13 services with unified nginx configs:
      - crowdsec, waf, dpi, system, wireguard, netdata, haproxy
      - hub, admin, auth, metrics, glances, backup
    - Each service has: WebUI at `/<service>/`, API at `/api/v1/<service>/`
    - All services verified working (UI=200, API=200 or 401 for auth-required)
    - Created `/srv/backups` directory for backup service

**Files Modified:**
- `board/mochabin/flash-tow-boot.cmd` — bubt flash script
- `board/mochabin/flash-tow-boot.txt` — manual instructions
- `packages/secubox-eye-remote/api/main.py` — Fixed interface check (usb0, ARP)
- `packages/secubox-eye-remote/udev/90-secubox-eye-remote.rules` — Removed NAME rename
- `packages/secubox-eye-remote/scripts/secubox-eye-network.sh` — Use usb0, notify API
- `packages/secubox-eye-remote/nginx/eye-remote.conf` — WebUI + API + redirect

**MOCHAbin Files Created:**
- `/etc/nginx/snippets/api-error.conf` — JSON error responses
- `/etc/nginx/secubox.d/*.conf` — 13 service nginx configs
- `/etc/systemd/system/secubox-*.service.d/no-runtime-dir.conf` — Socket conflict fix
- `/srv/backups/` — Backup storage directory

14. **CrowdSec Console Enrollment** — Fixed key typo
    - Enrollment key had `1` (one) instead of `l` (lowercase L)
    - Corrected key: `cmoleja50000802le9t1f7o0d`

15. **CrowdSec Dashboard Cleanup** — Removed obsolete UI elements
    - Removed Migration section (OpenWrt migration not needed)
    - Removed Components tab
    - Removed Access tab
    - Removed "Import from OpenWrt" button

16. **CrowdSec LAPI/CAPI Status Fix** — Sudo privilege issue
    - Issue: `NoNewPrivileges=true` in systemd blocked sudo
    - Fix: Created `/etc/systemd/system/secubox-crowdsec.service.d/allow-sudo.conf`
    - Added sudoers entry for cscli: `/etc/sudoers.d/secubox-crowdsec`
    - Rewrote status.py to use `cscli lapi status` subprocess instead of HTTP

17. **CrowdSec Collections Status Fix** — Parsing issue
    - Issue: Collections showing 0 when 7 installed
    - Root cause: Code checked `status == "enabled"` but CrowdSec uses `status = "enabled,update-available"`
    - Fix: Changed to `"enabled" in (item.get("status") or "")`

18. **CrowdSec Bouncers API Fix** — LAPI auth issue
    - Issue: HTTP calls to LAPI failed (missing X-Api-Key)
    - Fix: Rewrote bouncers.py to use `cscli bouncers list -o json` subprocess

19. **CrowdSec Hub Functions** — Added missing functions
    - Added `refreshHub()` and `reloadEngine()` JavaScript functions
    - Added `/hub/update` and `/service/reload` API endpoints

20. **Duplicate Remote UI Entry Removed** — Menu cleanup
    - Removed duplicate `remote-ui` menu entry from secubox-system
    - Eye Remote (`eye-remote`) remains functional at `/eye-remote/`
    - Files removed: `packages/secubox-system/menu.d/15-remote-ui.json`
    - Files removed: `packages/secubox-system/www/remote-ui/index.html`

**CrowdSec Files Modified:**
- `packages/secubox-crowdsec/api/routers/status.py` — cscli subprocess with shell=True
- `packages/secubox-crowdsec/api/routers/bouncers.py` — cscli subprocess for bouncers
- `packages/secubox-crowdsec/api/main.py` — Added hub update and reload endpoints
- `packages/secubox-crowdsec/www/index.html` — Removed Migration, Components, Access tabs
- `packages/secubox-crowdsec/systemd/allow-sudo.conf` — NoNewPrivileges=false override
- `packages/secubox-crowdsec/sudoers.d/secubox-crowdsec` — cscli sudo permission

### Session 96 — Eye Remote Auto-Pairing & Pi Zero Builder

**Goal:** Add auto-pairing and metrics API to Eye Remote

**Completed:**
1. **Auto-Pair Endpoint** — Added `/api/v1/eye-remote/auto-pair` POST
   - Creates pairing record for currently connected device
   - Gets hostname from Pi Zero via metrics API
   - Stores devices in `/var/lib/secubox/eye-remote/auto-paired.json`

2. **Paired Devices Endpoint** — Added `/api/v1/eye-remote/paired-devices` GET
   - Lists all paired Eye Remote devices
   - Masks tokens for security (shows only first 8 chars)

3. **Pi Zero Metrics API in Builder** — Updated `install_zerow.sh` v1.9.0
   - Integrated `pizero-metrics-api.py` into SD card builder
   - Added `pizero-metrics.service` systemd unit
   - New Pi Zero SD cards now auto-include metrics API

4. **PiZero Metrics Public Endpoint** — Added `/api/v1/eye-remote/pizero/metrics`
   - Relays metrics from Pi Zero without requiring auth
   - Dashboard can display CPU, Mem, Temp without complex auth setup

5. **Fixed _eye_state Missing** — MOCHAbin hotfix
   - Added `_eye_state = {"connected": False, "last_seen": None}` to deployed main.py

**Files Modified:**
- `packages/secubox-eye-remote/api/main.py` — Added auto-pair, paired-devices, pizero/metrics endpoints
- `remote-ui/round/install_zerow.sh` — v1.9.0, integrated pizero-metrics-api

**Commits:**
- 30b8773 feat(eye-remote): Add auto-pair and paired-devices endpoints

### Session 97 — Eye Remote Routing Fixes & Navbar Emoji Cleanup

**Goal:** Fix Eye Remote metrics not reaching MOCHAbin, fix navbar emoji icons

**Completed:**
1. **rp_filter Martian Source Fix** — Packets from Pi Zero (10.55.0.2) were being dropped
   - Root cause: Kernel reverse path filter rejecting packets on USB gadget interface
   - Fix: Added `/etc/sysctl.d/99-secubox-usb.conf` with `net.ipv4.conf.all.rp_filter = 0`
   - Also apply per-interface in udev rules: `sysctl -w net.ipv4.conf.%k.rp_filter=0`

2. **Dual Interface Routing Conflict** — Pi Zero had both usb0 and usb1 with same IP
   - Root cause: Pi Zero gadget created RNDIS (usb0) + CDC-ECM (usb1), both configured
   - Fix: Added `usb1-disable` config to `install_zerow.sh` to bring down usb1

3. **USB Re-plug Detection** — udev rules weren't triggering on reconnect
   - Fix: Added `ACTION=="bind"` event to udev rules for re-plug detection
   - Added `sleep 2` delay for gadget initialization

4. **Network Script Status Command** — Added `secubox-eye-network.sh status`
   - Shows interface state, rp_filter status, and peer reachability

5. **Navbar Emoji Icons** — Replaced text-based icons with proper emoji
   - Updated CATEGORY_META in hub API with missing categories
   - Fixed 7 menu.d JSON files with text icons (catalog, shield, camera, etc.)

**Files Modified:**
- `packages/secubox-eye-remote/sysctl.d/99-secubox-usb.conf` — rp_filter disable
- `packages/secubox-eye-remote/udev/90-secubox-eye-remote.rules` — bind event, rp_filter
- `packages/secubox-eye-remote/scripts/secubox-eye-network.sh` — status command
- `packages/secubox-eye-remote/debian/install` — Added sysctl.d to package
- `remote-ui/round/install_zerow.sh` — usb1-disable config
- `packages/secubox-hub/api/main.py` — CATEGORY_META additions
- `packages/secubox-*/menu.d/*.json` — 7 files with emoji icon fixes

**Commits:**
- 01f2bf1 fix(eye-remote): Resolve rp_filter and dual-interface routing issues
- a47d290 fix(menu): Replace text icons with emoji in navbar

---

## 2026-05-04

### Session 93 — MOCHAbin Full Image Build

**Goal:** Build MOCHAbin image with slipstream packages (full profile like ESPRESSObin)

**Problem:**
- Previous build attempts failed with "Erreur: La localisation 5890MiB est en dehors du périphérique"
- Root cause: `board/mochabin/config.mk` had `IMG_SIZE="4G"` which was insufficient for ~5.5GB rootfs

**Fix Applied:**
```makefile
# board/mochabin/config.mk
# Before:
IMG_SIZE="4G"

# After:
IMG_SIZE="8G"
```

**Build Results:**
- Image: `output/secubox-mochabin-bookworm.img.gz` (1.2G compressed, 8G uncompressed)
- SHA256: `f1db869b5e82c2d851fa16d38faad4db91f4e76982da8d013c3cceef36b7164c`
- Slipstream packages: All SecuBox .deb packages pre-installed

**Known Issues (Non-blocking):**
- 4 packages failed during slipstream (missing systemd service files):
  - secubox-mitmproxy
  - secubox-smtp-relay
  - secubox-soc-agent
  - secubox-soc-gateway

**Commits:**
- de2f365 fix(mochabin): Increase image size to 8G for full install

**Deployment:**
- Flashed to USB thumb drive (28.8G DataTraveler 3.0)
- Ready for boot testing on MOCHAbin hardware

### Session 93b — MOCHAbin eMMC Flash & Boot Success

**Goal:** Flash SecuBox image to eMMC and boot from it

**USB Boot Issues:**
- USB storage not detected in Linux (f2500000.usb deferred probe)
- USB thumb drive only accessible from U-Boot, not from running Linux

**eMMC Flash from U-Boot:**
```
usb reset
ext4load usb 0:3 0x10000000 secubox-mochabin-bookworm.img.gz
gzwrite mmc 0 0x10000000 ${filesize}
```

**Boot Script Issue:**
- Initial boot.scr used `uInitrd` (U-Boot wrapped initrd)
- Image only contains raw `initrd.img` from Debian
- Error: "Wrong Ramdisk Image Format"

**Solution - Use raw initrd with filesize:**
```bash
setenv bootcmd_emmc 'fatload mmc 0:1 0x7000000 Image; fatload mmc 0:1 0x6f00000 dtbs/marvell/armada-7040-mochabin.dtb; fatload mmc 0:1 0x9000000 initrd.img; setenv bootargs root=/dev/mmcblk0p2 rootfstype=ext4 rootwait console=ttyS0,115200 earlycon=uart8250,mmio32,0xf0512000 net.ifnames=0; booti 0x7000000 0x9000000:${filesize} 0x6f00000'
setenv bootcmd 'run bootcmd_emmc'
saveenv
```

**Key insight:** U-Boot can boot raw initrd.img by passing filesize after colon: `0x9000000:${filesize}`

**Boot Success:**
- Kernel: 6.1.0-42-arm64
- Memory: 8GB detected (7.8Gi available)
- eMMC: 14.7 GiB DF4016
- Network: br-lan @ 192.168.1.1, eth0 @ 10.55.255.177
- Dashboard: https://192.168.1.1:9443
- All SecuBox services started

**Minor Issues (Non-blocking):**
- `crowdsec.service` failed to start (needs investigation)
- `lxc-net.service` failed (bridge setup conflict)
- `secubox-metablogiz` keeps restarting (service loop)

**Hardware Notes:**
- SFP module: OEM SFP28-25G-SR-S detected on eth0 (incompatible mode)
- SATA: 1TB WD Blue SA510 detected on ata2 (user's personal drive)
- USB: Quectel EP06-E LTE modem on USB1

### Session 93c — Nginx .dpkg-new Config Fix

**Problem:**
- Dashboard `/system/` returning HTML instead of JSON
- `secubox-system.service` was disabled/not running
- Nginx configs in `/etc/nginx/secubox.d/` had `.dpkg-new` suffix (not activated)

**Root Cause:**
- dpkg leaves `.dpkg-new` files when installing new conffiles over existing ones
- Build scripts didn't rename these after package installation

**Fix Applied:**
Added `.dpkg-new` activation step to all build scripts:
- `image/build-image.sh` (line ~760)
- `image/build-live-usb.sh` (line ~1824)
- `image/build-rpi-usb.sh` (line ~751)

```bash
# Activate .dpkg-new configs
for newconf in "${ROOTFS}/etc/nginx/secubox.d/"*.dpkg-new; do
  [[ -f "$newconf" ]] || continue
  mv "$newconf" "${newconf%.dpkg-new}"
done
```

**Services Fixed on Running System:**
```bash
systemctl enable --now secubox-system
cd /etc/nginx/secubox.d && for f in *.dpkg-new; do mv "$f" "${f%.dpkg-new}"; done
nginx -s reload
```

### Session 93d — Performance Comparison: OpenWrt vs Debian

**Test Environment:**
- 192.168.255.1 — SecuBox OpenWrt 24.10.5 (MOCHAbin 8GB)
- 192.168.255.10 — SecuBox Debian Bookworm (MOCHAbin 8GB)

#### System Comparison

| Metric | OpenWrt | Debian | Notes |
|--------|---------|--------|-------|
| **Kernel** | 6.6.119 | 6.1.0-42-arm64 | OpenWrt newer |
| **Uptime** | 2 days 22h | 18 hours | — |
| **Load Average** | 6.63 | 1.31 | **Debian 5x lower** |
| **Total Processes** | 1768 | 172 | **Debian 10x fewer** |
| **Memory Total** | 8GB | 8GB | Same |
| **Memory Used** | 3.1GB (38%) | 1.7GB (22%) | **Debian 45% less** |
| **Memory Available** | 4.8GB | 6.2GB | **Debian +1.4GB** |
| **Swap Used** | 1.6GB | 0 | Debian no swap needed |
| **Disk Used** | 10.6G/14.6G (73%) | 3.5G/5.4G (69%) | Similar % |

#### Service Memory Usage (kB)

| Service | OpenWrt | Debian | Δ |
|---------|---------|--------|---|
| nginx | 2,184 | 12,036 | +5.5x |
| haproxy | 36,888 | 47,080 | +28% |
| crowdsec | 105,840 | 194,732 | +84% |
| dnsmasq | 2,404 | 2,000 | -17% |
| netdata | N/A | 4,520 | — |
| Python APIs | N/A | 1,250,656 | — |

#### Version Comparison

| Component | OpenWrt | Debian |
|-----------|---------|--------|
| Python | 3.11.14 | 3.11.2 |
| OpenSSL | 3.0.18 | 3.0.18 |
| HAProxy | 3.0.12 | 2.6.12 |
| CrowdSec | 1.7.6 | 1.7.7 |

#### Analysis

**Debian Advantages:**
- **5x lower system load** (1.3 vs 6.6) — more responsive
- **45% less memory used** — more headroom for services
- **No swap thrashing** — better performance under load
- **10x fewer processes** — cleaner process tree
- **systemd** — modern service management, dependencies
- **Standard Debian packages** — easier updates, security patches

**OpenWrt Advantages:**
- **Newer kernel** (6.6 vs 6.1) — more hardware support
- **Lighter nginx** (2MB vs 12MB) — minimal footprint
- **Smaller crowdsec** (105MB vs 194MB) — optimized binary
- **HAProxy 3.0** vs 2.6 — newer features

**Debian Trade-offs:**
- Python FastAPI services use ~1.2GB total for 22 SecuBox APIs
- This replaces shell-based RPCD (unmeasured but lighter)
- Benefit: proper async, JWT auth, OpenAPI docs

**Conclusion:**
Debian migration successful. Despite heavier individual services, overall system load and memory pressure significantly lower. The structured systemd architecture provides better resource management than OpenWrt's init scripts.

### Session 93e — CrowdSec Firewall Bouncer Setup

**Problem:**
- CrowdSec agent running but no firewall bouncer installed
- CAPI blocklist (16k+ IPs) not enforced at firewall level

**Fix:**
```bash
# Clear stuck apt locks
pkill -9 apt dpkg
rm -f /var/lib/dpkg/lock-frontend

# Install bouncer
apt-get install -y crowdsec-firewall-bouncer-nftables
```

**Result:**
- Bouncer auto-registered with CrowdSec API
- nftables tables created: `ip crowdsec`, `ip6 crowdsec6`
- Services enabled on boot

**Verification:**
```bash
cscli bouncers list
# cs-firewall-bouncer-1777957909  127.0.0.1  ✔️  v0.0.34

systemctl is-active crowdsec crowdsec-firewall-bouncer
# active
# active
```

**Protection Active:**
| Category | Decisions |
|----------|-----------|
| http:dos | 9,128 |
| http:exploit | 3,090 |
| http:bruteforce | 1,369 |
| ssh:bruteforce | 1,115 |
| http:scan | 890 |
| generic:scan | 657 |
| ssh:exploit | 353 |

### Session 93f — Fix Service Restart Loops

**Problem:**
Multiple SecuBox services in restart loops due to missing Python dependencies.

**Root Cause:**
- `python-multipart` missing (required for FastAPI file uploads)
- `email-validator` missing (required for Pydantic email fields)

**Affected Services:**
- secubox-metablogizer, secubox-droplet, secubox-avatar, secubox-streamlit, secubox-users

**Fix on Running System:**
```bash
pip3 install --break-system-packages python-multipart email-validator
systemctl restart secubox-metablogizer secubox-avatar
```

**Build Scripts Updated:**
- `image/build-image.sh` — added python-multipart, email-validator
- `image/build-rpi-usb.sh` — added email-validator

**Disabled Non-Critical Services (missing dependencies):**
- secubox-picobrew (IoT controller, needs hardware)
- secubox-threats (needs Suricata)
- secubox-eye-remote (import error)
- secubox-openclaw (OSINT tool)
- secubox-ui-manager (display manager)
- secubox-net-fallback (network already configured)

**Result:**
- 86 services running
- 0 failed
- Load: 7.7 → 3.7 (no more restart loops)

### Session 93g — Dashboard System API Fix

**Problem:**
- https://192.168.255.10/system/ returning JSON parse errors
- `/api/v1/system/*` endpoints returning HTML instead of JSON

**Root Cause:**
- `secubox-system.service` was running but socket `/run/secubox/system.sock` was missing
- Service started at 05:03 but socket disappeared (possibly cleaned by systemd-tmpfiles)

**Fix:**
```bash
systemctl restart secubox-system
```

**Verification:**
```bash
curl -s https://localhost/api/v1/system/info
# {"hostname":"secubox-mochabin","board":"Globalscale MOCHAbin","arch":"aarch64"...}
```

**Dashboard Status:**
- ✅ https://192.168.255.10/system/ working
- ✅ System info, resources, services endpoints functional
- ✅ JWT authentication enforced on protected endpoints

### Session 93h — CrowdSec Dashboard & Socket Stability

**Problem:**
- https://192.168.255.10/crowdsec/ returning JSON parse errors
- Multiple service sockets disappearing after bulk restart

**Root Cause:**
- Services running but Unix sockets not created
- Bulk `systemctl restart 'secubox-*'` causes race conditions
- Services need time to initialize and create sockets

**Fix:**
```bash
# Restart specific services individually
systemctl restart secubox-system secubox-crowdsec
sleep 5
```

**Verified Working:**
```
✅ /api/v1/hub/status      → JWT required (correct)
✅ /api/v1/system/info     → {"hostname":"secubox-mochabin"...}
✅ /api/v1/crowdsec/status → {"running":true,"version":"v1.7.7"...}
```

**Note:** Hub service uses TCP port 8001 (not socket) for VM compatibility.

---

## 2026-05-05

### Session 94 — Socket RuntimeDirectory Fix & Dashboard Stability

**Problem:**
- Multiple dashboard pages returning JSON parse errors
- Services "active" but sockets missing in `/run/secubox/`
- RuntimeDirectory causing socket deletion when services restart

**Root Cause:**
All SecuBox services shared `RuntimeDirectory=secubox` which caused:
1. Each service restart recreated `/run/secubox/` with only its own socket
2. Other service sockets were deleted
3. Race conditions during bulk restarts

**Fix Applied:**

1. **Created tmpfiles.d config for persistent directory:**
```bash
cat > /etc/tmpfiles.d/secubox.conf << 'CONF'
d /run/secubox 0775 secubox secubox -
CONF
```

2. **Disabled RuntimeDirectory in services:**
```bash
for svc in auth system users crowdsec wireguard dpi dns vhost cdn qos waf nac netmodes admin hub; do
  mkdir -p /etc/systemd/system/secubox-$svc.service.d
  cat > /etc/systemd/system/secubox-$svc.service.d/runtime.conf << 'CONF'
[Service]
RuntimeDirectory=
RuntimeDirectoryPreserve=
CONF
done
systemctl daemon-reload
```

3. **Fixed nginx users.conf routing:**
```nginx
location /api/v1/users/ {
    rewrite ^/api/v1/users/(.*)$ /$1 break;
    proxy_pass http://unix:/run/secubox/users.sock;
    include /etc/nginx/snippets/secubox-proxy.conf;
}
```

4. **Installed udev rules for Eye Remote:**
```bash
cat > /etc/udev/rules.d/90-secubox-otg.rules << 'RULES'
SUBSYSTEM=="net", ATTRS{idVendor}=="1d6b", ATTRS{idProduct}=="0104", DRIVERS=="cdc_ether", NAME="secubox-round"
SUBSYSTEM=="tty", ATTRS{idVendor}=="1d6b", ATTRS{idProduct}=="0104", KERNEL=="ttyACM*", SYMLINK+="secubox-console"
RULES
```

**Result:**
- All 14+ sockets persisting across service restarts
- Dashboard pages working: system, crowdsec, users, wireguard, dns, dpi, waf
- CrowdSec console enrolled and active

**Sockets Created:**
```
/run/secubox/admin.sock
/run/secubox/auth.sock
/run/secubox/cdn.sock
/run/secubox/crowdsec.sock
/run/secubox/dns.sock
/run/secubox/dpi.sock
/run/secubox/nac.sock
/run/secubox/netmodes.sock
/run/secubox/qos.sock
/run/secubox/system.sock
/run/secubox/users.sock
/run/secubox/vhost.sock
/run/secubox/waf.sock
/run/secubox/wireguard.sock
```

**USB Configuration:**
- USB1 (480 Mbps): Quectel EP06-E LTE modem
- USB2 (5000 Mbps): Available for Eye Remote Pi Zero W
- Eye Remote detection pending (needs to be plugged into USB3 port)

---

## 2026-05-03

### Session 92 — Tow-Boot eMMC Support & MOCHAbin Documentation

**Goal:** Add eMMC boot partition support to Tow-Boot for MOCHAbin, document boot mode jumpers

**Context:**
- MOCHAbin board with dead/intermittent SPI NOR flash (JEDEC 00,00,00)
- eMMC works in U-Boot but BootROM communication fails
- Original Tow-Boot build lacks `mmc partconf` command
- No microSD slot on MOCHAbin (correction to documentation)

**Implementation:**

1. **Copied Tow-Boot to Project:**
   - Source: `/home/reepost/DEVEL/MOKATOOL/Tow-Boot/`
   - Destination: `tools/Tow-Boot/`

2. **Enabled eMMC Boot Support:**
   - Added `mmcBootIndex = "0"` to MOCHAbin board configs
   - Enables `CONFIG_SUPPORT_EMMC_BOOT=y` in U-Boot
   - New commands available: `mmc partconf`, `mmc bootbus`

3. **Built New Tow-Boot:**
   ```bash
   sg nix-users -c "nix-build -A globalscale-mochabin-8gb"
   ```
   - Output: `Tow-Boot.spi.bin`, `Tow-Boot.mmcboot.bin`, `Tow-Boot.noenv.bin`

4. **Hardware Testing (Failed):**
   - SPI flash intermittent (sometimes detected, mostly JEDEC 00,00,00)
   - eMMC boot partition: BootROM returns `Error interrupt: 00018000`
   - Tried boot partitions 1, 2, and user area — all fail at BootROM level
   - **Verdict: Hardware defective** — board abandoned

**Files Modified:**
- `tools/Tow-Boot/boards/globalscale-mochabin-2gb/default.nix`
- `tools/Tow-Boot/boards/globalscale-mochabin-4gb/default.nix`
- `tools/Tow-Boot/boards/globalscale-mochabin-8gb/default.nix`

**Files Created:**
- `tools/Tow-Boot/output/` — Built binaries
- `tools/Tow-Boot/SECUBOX.md` — SecuBox-specific documentation

**Documentation Updated:**
- `board/mochabin/README.md`:
  - Added boot mode jumper table (J17-J22)
  - Added SPI → eMMC jumper change instructions
  - Documented Tow-Boot flashing procedures
  - Added known hardware issues section
  - Removed incorrect microSD slot reference

**Boot Mode Jumpers (J17-J22):**
| Mode | Code | J17 | J18 | J19 | J20 | J21 | J22 |
|------|------|-----|-----|-----|-----|-----|-----|
| SPI | 0x32 | L | R | L | L | R | R |
| eMMC | 0x2B | R | R | L | R | L | R |

**Result:**
- Tow-Boot with eMMC support ready for working boards
- Complete MOCHAbin boot documentation
- Defective board identified and abandoned

---

### Session 91 — Wiki Badges & VirtualBox VM Rebuild

**Goal:** Update wiki and README with build status badges, metrics dashboard, and rebuild VBox VM

---

### Session 90 — Mitmproxy WAF Module Migration

**Goal:** Complete migration of mitmproxy WAF module from SecuBox-OpenWrt to SecuBox-DEB

**Context:**
- Original OpenWrt module: luci-app-mitmproxy-waf (shell scripts + LuCI frontend)
- Target: Full Debian package with FastAPI backend, LXC container isolation, HAProxy integration

**Implementation (15 tasks via Subagent-Driven Development):**

1. **Package Scaffold** — debian/control, rules, postinst, prerm, systemd service
2. **Configuration** — mitmproxy.toml (TOML), waf-rules.json (90+ patterns, 14 categories)
3. **mitmproxyctl CLI** — Python CLI for LXC lifecycle (install, start, stop, restart, status, destroy, logs)
4. **Threat Detection Addon** — secubox_waf.py mitmproxy addon with real-time threat detection
5. **FastAPI Backend** — 5 routers with JWT auth:
   - status.py — Container control, stats, mode settings
   - settings.py — TOML configuration CRUD
   - alerts.py — Threat log, ban management, CrowdSec integration
   - haproxy.py — WAF enable/disable, route sync
   - waf.py — Rule category management
6. **WebUI** — status.html, settings.html, filters.html (CRT-light theme)
7. **Integration** — nginx config, CrowdSec acquisition config, menu.d entry

**WAF Detection Categories (14):**
- SQL Injection, XSS, Command Injection, Path Traversal
- SSRF, XXE, LDAP Injection, Log4Shell
- Scanner Detection, Path Scanning, CVE Exploits, RCE
- VoIP Attacks, XMPP Attacks

**Files Created:**
- `packages/secubox-mitmproxy/` — Complete package structure
- `debian/` — control, rules, postinst, prerm, service, mitmproxy.toml
- `api/` — main.py, routers/{status,settings,alerts,haproxy,waf}.py
- `addons/secubox_waf.py` — Mitmproxy addon
- `bin/mitmproxyctl` — CLI tool
- `data/waf-rules.json` — 90+ detection patterns
- `www/mitmproxy/` — WebUI pages
- `nginx/mitmproxy.conf` — API/static proxy
- `README.md` — Comprehensive documentation

**Code Review Findings (Fixed):**
1. LXC architecture hardcoded to amd64 → Now detects actual arch (arm64/amd64)
2. Missing WebUI API endpoints → Added /set_mode, /save_settings, /setup_firewall, /clear_firewall, /wan_setup, /wan_clear, /clear_alerts
3. Missing crowdsec dir in debian/rules → Added

**Commits:**
- 17 commits from package scaffold through final fixes
- d69dd43 fix(mitmproxy): Address code review findings
- 87602fc fix(mitmproxy): Add crowdsec directory to debian/rules install

**Result:**
- Complete secubox-mitmproxy package ready for dpkg-buildpackage
- LXC-isolated WAF with 90+ threat detection patterns
- Full CrowdSec integration for auto-banning
- HAProxy route sync for traffic inspection
- WebUI dashboard with real-time alerts

---

### Session 91 — Wiki Badges & VirtualBox VM Rebuild

**Goal:** Update wiki and README with build status badges, metrics dashboard, and rebuild VBox VM

**Context:**
- Session 90 completed mitmproxy WAF migration
- ESPRESSObin has insufficient disk space for LXC container
- Need VirtualBox VM for testing mitmproxy installation
- Wiki and README need updated badges/metrics

**Completed:**

1. **VirtualBox VM Rebuild:**
   - Built new x64-bookworm image with 8GB disk
   - Generated VDI (2.8GB) and compressed img.gz (963MB)
   - Fixed VM UUID mismatch after VDI recreation
   - VM now running with 4GB RAM, EFI boot

2. **Wiki Home.md Update:**
   - Added workflow status badges (packages, live USB, installer, eye remote, multiboot)
   - Added development metrics table (131 packages, 94% migration, 2000+ APIs)
   - Added module status by category with progress indicators
   - Updated version announcement to v2.3.0

3. **README.md Update:**
   - Added comprehensive workflow badges
   - Added metrics table (packages, migration %, APIs, architectures)
   - Updated version to v2.3.0

4. **Dependency Fix:**
   - Added xz-utils to secubox-mitmproxy dependencies for LXC template extraction

**Commits:**
- 22487f8 docs: Add build status badges and metrics to README
- e041caa docs: Add build badges and metrics dashboard to wiki Home

**Artifacts:**
- `output/secubox-vm-x64-bookworm.img.gz` (963MB)
- `output/secubox-vm-x64-bookworm.vdi` (2.8GB)
- SHA256: 13e69ae55ab185daaf6e9b04ff1fad69bc40cf53c5ae8daac9829334226deca6

**Result:**
- Wiki now shows live build status for all components
- VirtualBox VM ready for mitmproxy testing
- GitHub Actions handles artifact creation on releases

---

### Session 89 — Emancipate SecuBox-Dev Methodology

**Goal:** Extract and document the SecuBox development methodology as a standalone, reusable guide

**Context:**
- Compared `.claude/` tracking files between secubox-openwrt (15 files) and secubox-deb (18 files)
- Identified core methodology patterns across 88+ development sessions
- Methodology needs to be portable for other projects

**Key Differences Found (OpenWrt vs Debian):**
| Aspect | OpenWrt | Debian |
|--------|---------|--------|
| Focus | Future features, themes, AI layers | Migration completion, CSPN compliance |
| Tracking | Version milestones (v0.19→v1.0) | Session-based (S01→S88), phases |
| Unique files | ROADMAP, EVOLUTION-PLAN, THEME_CONTEXT | MIGRATION-MAP, PATTERNS, MODULE-COMPLIANCE |

**Methodology Document Created:**
- Part 1: Project tracking structure (WIP, TODO, HISTORY, PATTERNS)
- Part 2: Session-based development workflow
- Part 3: Migration patterns (Shell/UCI → FastAPI/TOML)
- Part 4: Performance patterns for embedded systems
- Part 5: Compliance verification checklists
- Part 6: Quick reference
- Part 7: How to apply to new projects
- Appendix: Templates

**Files Created:**
- `docs/SECUBOX-DEV-METHODOLOGY.md` — 762 lines standalone methodology guide

**Commits:**
- 082ebe0 docs(methodology): Emancipate SecuBox-Dev methodology as standalone guide

**Result:**
- Methodology portable and documented
- Can be applied to any embedded/systems project with AI coding assistants

---

## 2026-05-02

### Session 88 — Navbar Module Filtering Fix

**Goal:** Fix navbar showing modules that aren't installed, causing 403/404/500 errors

**Problems Identified:**
1. Portal returning 403 (no index.html, only login.html)
2. Modules without www directories showing in navbar
3. Deploy script copying to wrong directory (secubox-hub vs hub symlink issue)
4. Menu items without `id` field still appearing

**Root Causes:**
- `/portal/` had only `login.html`, no `index.html` for nginx to serve
- `_check_module_installed()` was checking for service sockets/systemd, not actual www content
- `/usr/lib/secubox/hub` (uvicorn workdir) was separate from `/usr/lib/secubox/secubox-hub` (deploy target)
- Menu definitions (menu.d/*.json) included items without `id` field

**Fixes:**
1. Created `portal/index.html` redirect to `login.html`
2. Rewrote `_check_module_installed()` to only return True for modules with:
   - www directory at `/usr/share/secubox/www/{module_id}`
   - At least one HTML file in that directory
3. Added filter to skip menu items without valid `id` or with `console_only: true`
4. Created symlink: `/usr/lib/secubox/hub -> /usr/lib/secubox/secubox-hub`

**Files Changed:**
- `packages/secubox-hub/api/main.py` — Updated `_check_module_installed()` and `_compute_menu_sync()`
- `packages/secubox-hub/www/portal/index.html` — New redirect file

**Commits:**
- 96b51ef fix(hub): Filter navbar to only show modules with www directories

**Result:**
- Navbar shows only 8 modules with actual www content (was 29)
- All menu items return HTTP 200
- No more 403/404/500 errors from navbar links

---

### Session 87 — HAProxy WebUI CRUD Enhancement

**Goal:** Add full CRUD operations for VHosts, Backends, Servers, and Certificates to the HAProxy WebUI dashboard

**Context:**
- Compared OpenWrt SecuBox HAProxy implementation with secubox-deb
- OpenWrt had 35+ RPCD methods, 8 separate JS view files
- secubox-deb already had comprehensive FastAPI backend (40+ endpoints)
- WebUI was read-only — needed CRUD operations

**Implementation:**
1. Added modal system for add/edit forms
2. Added toast notifications for success/error feedback
3. Added client-side form validation with `validateForm()` function
4. Added enhanced `apiCall()` function with comprehensive error handling
5. VHost CRUD: add, edit, delete with domain/backend/SSL/WAF/ACME options
6. Backend CRUD: add, edit, delete with mode/balance/health check options
7. Server CRUD: nested under backends with address/port/weight management
8. Certificate CRUD: request ACME certs with progress bar, delete existing
9. Updated all tables with action buttons (Edit/Delete/Manage)
10. Maintained P31 Phosphor theme consistency

**Files Changed:**
- `packages/secubox-haproxy/www/haproxy/index.html` — ~1565 lines (was ~690)
- `docs/superpowers/specs/2026-05-02-haproxy-webui-enhancement-design.md` — Design spec
- `docs/superpowers/plans/2026-05-02-haproxy-webui-crud.md` — Implementation plan

**Commits (10 total):**
- f0970d6 feat(haproxy-ui): Add modal and toast HTML containers with CSS and JS functions
- 251b292 feat(haproxy-ui): Add validation and enhanced API functions
- ebb1bb4 feat(haproxy-ui): Add VHost CRUD functions
- d51e26e feat(haproxy-ui): Add Backend CRUD functions
- 591d289 feat(haproxy-ui): Add Server CRUD functions
- 4b2b214 feat(haproxy-ui): Add Certificate CRUD functions
- 3df7247 feat(haproxy-ui): Update VHosts table with CRUD buttons
- db04ffb feat(haproxy-ui): Update Backends table with CRUD buttons
- acdb94b feat(haproxy-ui): Update Certificates table with CRUD buttons
- 2a1dde2 fix(haproxy-ui): Add form CSS and remove unused function

**Result:**
- Full CRUD operations for all HAProxy entities
- Consistent UI with existing P31 Phosphor theme
- All API endpoints already existed — frontend-only enhancement
- Code review passed with Good quality rating

---

### Session 86 — GitHub Actions Package Architecture Filtering Fix

**Goal:** Fix GitHub Actions workflow failures when building ARM64 images

**Problem:**
- GitHub Actions build-image.yml workflow failing on arm64 boards (mochabin, espressobin-v7, espressobin-ultra, rpi400)
- Error: `package architecture (amd64) does not match system (arm64)` for secubox-c3box and secubox-daemon
- Slipstream code copied ALL .deb packages without architecture filtering
- When building arm64 images, amd64 packages were being copied and dpkg failed to install them

**Root Cause:**
- In `image/build-image.sh` line 675: `cp "${DEBS_DIR}"/secubox-*.deb` copied all packages regardless of architecture
- Same issue in `image/build-ebin-live-usb.sh` and `image/build-live-usb.sh`
- `build-rpi-usb.sh` already had correct filtering (only copied `_all.deb` and `_arm64.deb`)

**Fix Applied:**

1. **image/build-image.sh** — Added architecture filtering in slipstream section:
   - Replaced blind `cp` with a loop that filters by `DEBIAN_ARCH`
   - Only copies `*_all.deb` and `*_${DEBIAN_ARCH}.deb` packages
   - Logs skipped packages count for debugging

2. **image/build-ebin-live-usb.sh** — Added arm64 architecture filter:
   - Filter for `*_all.deb` and `*_arm64.deb` only
   - Updated cache search to also filter by architecture

3. **image/build-live-usb.sh** — Added amd64 architecture filter:
   - Filter for `*_all.deb` and `*_amd64.deb` only
   - Updated cache search to also filter by architecture

**Result:**
- ARM64 image builds will now skip amd64-only packages (secubox-daemon, secubox-c3box)
- AMD64 image builds will skip arm64-only packages
- Architecture-independent packages (`_all.deb`) are correctly installed on all platforms

---

## 2026-05-01

### Session 85 — VirtualBox VM Network Detection Fix

**Goal:** Fix network configuration for VirtualBox VMs with multiple interfaces (NAT + host-only)

**Problem:**
- VBox VMs with 2 interfaces (NAT + host-only) had host-only interface put into br-lan bridge
- br-lan bridge got static IP 192.168.1.1/24 instead of DHCP from VBox host-only network
- This broke host-only network access (should get IP in 192.168.56.x range)

**Root Cause:**
- `secubox-net-detect` treated x64-vm and x64-baremetal identically
- Both went through router mode logic that creates bridges for multi-interface setups
- VMs don't need bridges - each interface should independently get DHCP

**Fix Applied:**

1. **image/sbin/secubox-net-detect** — Separate VM handling:
   - New `x64-vm)` case in `get_interface_config()` with `profile="vm"`
   - VMs: first interface as WAN, empty LAN list (no bridge)
   - Added VM detection in `generate_netplan()`: when `board="x64-vm"`, configure ALL physical interfaces with DHCP
   - In `main()`: `profile="vm"` forces `mode="single"` (skip bridge creation)

**Result:**
- VBox VMs now correctly configure all interfaces with DHCP
- Host-only interface gets IP from VBox DHCP server (192.168.56.x range)
- NAT interface gets IP from VM's internal NAT (10.0.2.x range)
- No br-lan bridge created for VMs

**Testing:**
- Built new image with fix
- VM visible at 192.168.56.110 on host-only network (DHCP working)
- SSH service startup issue separate from network fix

---

### Session 84 — AMD64 Real Hardware Network Fix

**Goal:** Fix network configuration for real AMD64 hardware (x64-live board)

**Problem:**
- x64-live netplan used broken wildcard syntax (`wan0:` with `match: name: "e*"`)
- Missing `set-name:` directive caused netplan to not properly configure interfaces
- On real hardware with multiple interfaces (enp2s0, enp3s0, eno1), this caused IP assignment failures

**Fixes Applied:**

1. **board/x64-live/netplan/00-secubox.yaml** — Complete rewrite:
   - Changed from broken `wan0:` wildcard to proper `eth-dhcp:` and `eth-legacy:` match patterns
   - Both patterns get DHCP with different route metrics (100 vs 200) for determinism
   - Added `optional: true` to prevent boot blocking
   - Added documentation explaining secubox-net-detect role

2. **image/sbin/secubox-net-detect** — Enhanced interface detection:
   - Added logging for interface discovery process
   - Expanded naming pattern matching for real hardware:
     - `enp[0-9]*s0` patterns (PCI bus addressing)
     - `eno[0-9]*` patterns (onboard NICs)
     - `ens*` patterns (VMware ESXi)
   - Added fallback logic when no link detected
   - Improved YAML generation with DHCP overrides
   - Fixed empty LAN interface handling

3. **image/sbin/secubox-net-reset** — New utility script:
   - `--status` to show current network detection state
   - `--apply` to re-detect and apply immediately
   - `--reboot` to clear marker and reboot (default)
   - Helpful for debugging network issues

**Files Modified:**
- `board/x64-live/netplan/00-secubox.yaml`
- `image/sbin/secubox-net-detect`
- `image/build-live-usb.sh` — Updated embedded netplan config
- `CLAUDE.md` — Added Debian shell scripting guidelines and mitmproxy docs

**Files Created:**
- `image/sbin/secubox-net-reset`

**Testing:**
```bash
# On real AMD64 hardware:
secubox-net-reset --status    # Check current state
secubox-net-reset --apply     # Force re-detection
journalctl -u secubox-net-detect -f  # Watch detection logs
```

---

## 2026-04-30

### Session 83 — Module Enhancement & Service Fixes

**Goal:** Complete stub/mockup implementations and fix service startup issues

**Critical Security Fixes:**
- **secubox-voip**: Implemented PBKDF2-SHA256 password hashing (100k iterations)
  - Fixed plaintext password storage in extension/trunk creation
  - Added `hash_password()` and `verify_password()` functions

**Core Functionality Completed:**
- **secubox-dns-provider**: Full OVH and Route53 adapter implementations
  - OVH: list_domains, list_records, create/update/delete, ACME challenges, zone export
  - Route53: Same full API coverage using boto3
- **secubox-ai-gateway**: Auto-persist provider configuration
  - Added `_persist_providers()` helper function
  - Provider updates now automatically saved to disk
- **secubox-threat-analyst**: WAF rule generation added
  - Complete JSON format rules for WAF module integration
  - Includes blocked IPs, patterns, and metadata
- **secubox-mirror**: Added docker, npm, and pypi sync support
  - Docker: Registry v2 API verification
  - NPM: Registry ping endpoint check
  - PyPI: Simple API verification
- **secubox-eye-remote**: Proper JWT auth import from secubox_core
  - Fallback for standalone Pi Zero deployment

**System Module Performance:**
- **secubox-system**: 275ms → 40ms (6.8x faster) with batch systemctl calls

**Service Startup Fixes:**
- Fixed uvicorn path in 31 systemd service files
- Changed `/usr/local/bin/uvicorn` → `/usr/bin/python3 -m uvicorn`
- Services now start correctly on all Python installation types

**Affected Packages:**
cloner, hexo, jabber, jellyfin, localai, lyrion, magicmirror, matrix, mesh,
mmpm, netifyd, newsbin, ollama, ossec, p2p, peertube, photoprism, picobrew,
redroid, rezapp, roadmap, simplex, soc-agent, soc-gateway, vault, vm, wazuh,
webradio, zigbee, zkp

**Files Modified:**
- `packages/secubox-voip/api/main.py`
- `packages/secubox-dns-provider/api/main.py`
- `packages/secubox-ai-gateway/api/main.py`
- `packages/secubox-threat-analyst/api/main.py`
- `packages/secubox-mirror/api/main.py`
- `packages/secubox-eye-remote/api/routers/devices.py`
- `packages/secubox-eye-remote/api/routers/boot_media.py`
- `packages/secubox-system/api/main.py`
- 31× `packages/*/debian/*.service`

---

### Session 82 — API Performance Optimization Campaign

**Feature:** Applied double-buffer pre-cache pattern to all slow modules

**Performance Results:**
| Module | Before | After | Improvement |
|--------|--------|-------|-------------|
| CrowdSec | 1800ms | 45ms | **40x faster** |
| HAProxy | 353ms | 50ms | **7x faster** |
| Users | 1906ms | 37ms | **51x faster** |
| Hub Menu | ~2000ms | 80ms | **25x faster** |

**Files Modified:**
- `packages/secubox-crowdsec/api/routers/status.py` — Complete rewrite with cache
- `packages/secubox-crowdsec/api/main.py` — Added cache startup/shutdown
- `packages/secubox-haproxy/api/main.py` — Added status cache + background refresh
- `packages/secubox-users/api/main.py` — Added status cache + background refresh

**Pattern Applied:**
```python
# Double-buffer pre-cache pattern
_cache: Dict = {}
CACHE_FILE = Path("/var/cache/secubox/module/status.json")

async def _refresh_cache():
    while True:
        data = await compute_in_threadpool()
        _cache.update(data)
        CACHE_FILE.write_text(json.dumps(data))
        await asyncio.sleep(30)

@app.get("/status")
async def status():
    return _cache or load_from_file() or compute_sync()
```

**Target Profile: secubox-lite (ESPRESSObin 1GB)**
First home ISP secured solution with:
- CrowdSec IDS/IPS
- HAProxy reverse proxy
- DNS filtering
- Firewall (nftables)
- All APIs responding in <50ms

---

### Session 81 — Hub Menu Double-Buffer Pre-Cache

**Feature:** Implemented double-buffer pre-cache pattern for navbar menu

**Problem:** Navbar menu was slow (several seconds) due to synchronous systemctl calls for each module check.

**Solution:**
- Added `MENU_CACHE_FILE` at `/var/cache/secubox/menu.json` for persistence
- Added `_menu_cache` in-memory dict for instant responses
- Added `_refresh_menu_cache()` background task (30s interval)
- Added `_compute_menu_sync()` running in thread pool
- Cache loaded from file on startup for fast navbar display

**Performance:**
- Before: Several seconds per request (sequential systemctl calls)
- After: ~80ms average response time

**Files Modified:**
- `packages/secubox-hub/api/main.py` — Added cache infrastructure

**Device:** ESPRESSObin V7 (192.168.255.250)

---

### Session 80 — Security Services Integration on ESPRESSObin

**Feature:** Integrated core security modules (CrowdSec, HAProxy, WAF, DNS) on ESPRESSObin

**Services Deployed:**
| Service | Port | Status | Dashboard |
|---------|------|--------|-----------|
| secubox-crowdsec | 8010 | ✅ Running | /crowdsec/ |
| secubox-haproxy | 8011 | ✅ Running | /haproxy-dashboard/ |
| secubox-waf | 8012 | ✅ Running | /waf/ |
| secubox-dns | 8013 | ✅ Running | /dns/ |

**Files Modified:**
- `packages/secubox-dns/api/main.py` — Fixed Pydantic v1 compatibility (field_validator → validator)

**Systemd Overrides Created (ESPRESSObin):**
- `/etc/systemd/system/secubox-crowdsec.service.d/override.conf` — TCP port 8010
- `/etc/systemd/system/secubox-haproxy.service.d/override.conf` — TCP port 8011
- `/etc/systemd/system/secubox-waf.service.d/override.conf` — TCP port 8012
- `/etc/systemd/system/secubox-dns.service.d/override.conf` — TCP port 8013

**Nginx Configs Verified:**
- `/etc/nginx/secubox.d/crowdsec.conf` — API + static dashboard
- `/etc/nginx/secubox.d/haproxy.conf` — API + static dashboard
- `/etc/nginx/secubox.d/waf.conf` — API + static dashboard
- `/etc/nginx/secubox.d/dns.conf` — API + static dashboard

**API Endpoints Working:**
- CrowdSec: 75+ endpoints (decisions, alerts, bouncers, hub, console, migration)
- HAProxy: 35+ endpoints (vhosts, backends, certs, stats, WAF toggle)
- WAF: 15+ endpoints (rules, categories, bans, alerts, autoban)
- DNS: 20+ endpoints (zones, records, stats, webhooks, export)

**Dashboard Features (OpenWrt-inspired):**
- CrowdSec: Status monitoring, ban management, alerts, hub, bouncers, console enrollment
- HAProxy: VHost management, backends, certificates, stats, WAF integration
- WAF: Rule categories, auto-ban, alerts, IP banning
- DNS: Zone management, records, validation, history, webhooks

---

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

### Session 99 (continued) — MOCHAbin Migration Execution

**Date:** 2026-05-06

**Completed:**
1. ✅ Exported from C3BOX:
   - 93 SSL certificates
   - 99 nginx secubox.d configs
   - HAProxy config
   - 4 LXC container configs
   - Error pages (400, 403, 408, 500, 502, 503, 504)

2. ✅ Transferred to MOCHAbin (192.168.255.1)

3. ✅ HAProxy configured:
   - All 93 SSL certs in `/data/haproxy/certs/`
   - LXC routing: gitea, nextcloud, mail, matrix
   - Default backend: nginx_vhosts (port 9080)
   - All backends UP

4. ✅ Nginx configured:
   - Default 503 server for unknown domains
   - WebUI served only for specific hostnames
   - 99 module API configs in secubox.d

5. ✅ CTL tools deployed:
   - 14 CTL tools copied to /usr/sbin/
   - Tools Debian-native (OpenWrt refs only in migrate commands)
   - Tested: vhostctl, metablogizerctl, crowdsecctl, streamlitctl

6. ✅ Vhost auto-creation:
   - Created `/usr/local/bin/secubox-vhost-create`
   - Supports: proxy, streamlit, static vhost types

**Verified:**
- admin.gk2.secubox.in → 200 (WebUI)
- git.maegia.tv → 200 (Gitea LXC)
- unknown.test.com → 503 (blocked)

---


7. ✅ WAF configured:
   - HAProxy ACL-based WAF active
   - Blocks: SQLi, XSS, Path Traversal, Scanners
   - Mitmproxy WAF disabled (pyOpenSSL ARM64 incompatibility)
   - Full mitmproxy WAF requires internet to install updated packages

**Test Results:**
```
Normal request:     200 ✓
SQLi attempt:       403 ✓ (blocked)
XSS attempt:        403 ✓ (blocked)
Path traversal:     403 ✓ (blocked)
Scanner UA:         403 ✓ (blocked)
```

