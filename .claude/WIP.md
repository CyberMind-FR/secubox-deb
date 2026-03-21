# WIP — Work In Progress
*Mis à jour : 2026-03-21*

---

## ✅ Terminé cette session

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
