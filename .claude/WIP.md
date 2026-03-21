# WIP — Work In Progress
*Mis à jour : 2026-03-20*

---

## ✅ Terminé cette session

### Phase 1 — Hardware ✅
- **build-image.sh** : Support arm64 + amd64 (VirtualBox)
- **create-vbox-vm.sh** : Script création VM VirtualBox automatique
- **Board configs** :
  - `mochabin` : Armada 7040 (SecuBox Pro)
  - `espressobin-v7` : Armada 3720 (SecuBox Lite)
  - `espressobin-ultra` : Armada 3720 + WiFi/LTE
  - `vm-x64` : VirtualBox/QEMU test target
  - `vm-arm64` : QEMU arm64 emulation
- **firstboot.sh** : Détection board ARM/x64, JWT, SSH, nftables

### Phase 2 — Infrastructure ✅
- secubox_core lib avec system.py
- nginx template
- rewrite-xhr.py (corrigé pour gérer les accolades imbriquées)

### Phase 3 — Modules ✅

**Tous les 14 modules sont complets (www + API + deb).**

Total : 435 appels rpc.declare réécrits | ~350+ endpoints FastAPI

### Phase 4 — APT Repo ✅
- **apt.secubox.in** — Configuration reprepro + nginx
- **GPG signing** — Script generate-gpg-key.sh
- **CI publish** — GitHub Actions workflow publish-packages.yml
- **repo-manage.sh** — Gestion add/remove/list/sync
- **setup-repo-server.sh** — Installation serveur complet
- **Metapackages** — secubox-full + secubox-lite

### Local Cache Build System ✅
- **setup-local-cache.sh** — apt-cacher-ng + repo local
- **build-all-local.sh** — Build tous les packages
- **--local-cache** flag dans build-image.sh

---

## ⬜ Next Up — Tests

1. Tester VM dans VirtualBox
2. Déployer apt.secubox.in sur serveur
3. Build et publish packages réels

---

## 🧪 Build avec cache local

```bash
# 1. Setup cache local (une fois)
sudo bash scripts/setup-local-cache.sh

# 2. Builder tous les packages SecuBox
bash scripts/build-all-local.sh bookworm amd64

# 3. Construire image avec cache local
sudo bash image/build-image.sh --board vm-x64 --local-cache --vdi

# 4. Créer VM VirtualBox
bash image/create-vbox-vm.sh output/secubox-vm-x64-bookworm.vdi
```

---

## 🗓️ Historique récent

- **2026-03-20** :
  - Phase 4 complète : apt.secubox.in (reprepro, GPG, CI)
  - Local cache build system ajouté
  - Image VM x64 construite avec succès
  - **Phases 1, 2, 3, 4 terminées à 100%**
