# WIP — Work In Progress
*Mis à jour : 2025-03-21*

---

## ✅ Terminé cette session

### Dynamic Menu System ✅
- **sidebar.js** : Shared sidebar component for all modules
- **Menu API** : `/api/v1/hub/menu` returns 18 modules in 6 categories
- **menu.d/** : JSON definitions per package (installed via debian/rules)
- **CSS fixes** : Added missing variables (--cyan, --yellow, --purple) to all modules

### Module Scaffold ✅
- **.claude/skills/module.md** : Skill documentation
- **scripts/new-module.sh** : Complete package scaffold script

### All Services Running ✅
17 secubox-* services active on VM:
- secubox-hub, secubox-system
- secubox-crowdsec, secubox-wireguard, secubox-auth, secubox-nac
- secubox-netmodes, secubox-dpi, secubox-qos, secubox-vhost
- secubox-netdata, secubox-mediaflow
- secubox-haproxy, secubox-cdn
- secubox-droplet, secubox-streamlit, secubox-streamforge, secubox-metablogizer

---

## ⬜ Next Up

1. **Deploy apt.secubox.in** — Setup reprepro server
2. **Build & publish** — All packages to APT repo
3. **Integration tests** — Full workflow on clean VM
4. **Documentation** — User guide, API docs

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

# Check menu API
curl -sk https://localhost:8443/api/v1/hub/menu | jq '.categories | length'
```

---

## 🗓️ Historique récent

- **2025-03-21** :
  - Dynamic menu system complete (18 modules, 6 categories)
  - Shared sidebar.js for consistent navigation
  - CSS variables fixed across all modules
  - Module scaffold skill created
  - All 17 services running on VM

- **2025-03-20** :
  - Phase 4 complete: apt.secubox.in (reprepro, GPG, CI)
  - Local cache build system added
  - Image VM x64 built successfully
