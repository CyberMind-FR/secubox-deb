# WIP — Work In Progress
*Mis à jour : 2026-03-22 (Session 5)*

---

## ✅ Terminé cette session

### ACME Certificate Support ✅
- **mailserverctl v2.2.0** — Added ACME certificate management
- **acme.sh integration** — issue, renew, install commands
- **SSL/TLS commands** — ssl status, ssl selfsigned
- **Dovecot SSL** — TLS 1.2+ configuration via conf.d/10-ssl.conf
- **API endpoints** — /acme/status, /acme/issue, /acme/renew, /acme/install
- **Certificate sync** — Auto-sync certificates to LXC container

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

### Mail Server Production
1. **DKIM signing** — Integrate OpenDKIM with Postfix
2. **Mail autodiscover** — Thunderbird/Outlook autoconfig endpoints

### Infrastructure
1. **Deploy apt.secubox.in** — Setup reprepro server
2. **Publish packages** — Upload all 33 debs to APT repo
3. **Documentation** — User guide, API docs

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
