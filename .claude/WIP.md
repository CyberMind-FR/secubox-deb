# WIP — Work In Progress
*Mis à jour : 2026-03-24 (Session 12)*

---

## ✅ Terminé cette session

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
