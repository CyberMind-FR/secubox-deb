# SecuBox-DEB — Scripts

Outils de build, déploiement et maintenance pour SecuBox-DEB.

---

## Build Scripts

| Script | Description |
|--------|-------------|
| `build-packages.sh` | Build tous les packages .deb |
| `build-all.sh` | Build complet + deploy |
| `build-all-local.sh` | Build avec cache local |
| `build-add-local.sh` | Ajouter package au repo local |

### Usage

```bash
# Build tous les packages
bash build-packages.sh

# Build un package spécifique
bash build-packages.sh --package secubox-hub

# Build avec cache local (plus rapide)
bash build-all-local.sh
```

---

## Deploy Scripts

| Script | Description |
|--------|-------------|
| `deploy.sh` | Déployer sur cible via SSH |

### Usage

```bash
# Déployer un package
bash deploy.sh secubox-hub root@192.168.1.1

# Déployer tous les packages
bash deploy.sh all root@192.168.1.1
```

---

## Package Scaffolding

| Script | Description |
|--------|-------------|
| `new-package.sh` | Créer structure package Debian |
| `new-module.sh` | Créer module avec API FastAPI |
| `port-frontend.sh` | Porter frontend depuis OpenWrt |

### Usage

```bash
# Nouveau package
bash new-package.sh secubox-mymodule

# Nouveau module avec API
bash new-module.sh mymodule

# Porter frontend LuCI
bash port-frontend.sh crowdsec-dashboard
```

---

## Local Cache Setup

| Script | Description |
|--------|-------------|
| `setup-local-cache.sh` | Configurer apt-cacher-ng |
| `local-repo-add.sh` | Ajouter .deb au repo local |

### Usage

```bash
# Setup initial
sudo bash setup-local-cache.sh

# Ajouter un package
bash local-repo-add.sh ../output/debs/secubox-core_1.0.0.deb
```

---

## VM & Testing

| Script | Description |
|--------|-------------|
| `run-qemu.sh` | Lancer image dans QEMU |
| `run-vbox.sh` | Lancer VM VirtualBox |
| `create-secubox-vm.sh` | Créer VM SecuBox |
| `qemu-screenshot.sh` | Screenshot VM QEMU |

### Usage

```bash
# Test dans QEMU
bash run-qemu.sh ../output/secubox-vm-x64.img

# Screenshot automatique
bash qemu-screenshot.sh
```

---

## Fix & Maintenance

| Script | Description |
|--------|-------------|
| `fix-navbar.sh` | Corriger navbar modules |
| `fix-emoji-fonts.sh` | Installer fonts emoji |
| `fix-namespace-errors.sh` | Fix namespace Python |
| `ui-fix-checker.sh` | Vérifier UI modules |
| `update-nginx-modular.sh` | Update config nginx |
| `retrofit-nginx-modular.sh` | Migrer config nginx |
| `update-debian-nginx.sh` | Update nginx Debian |

---

## Security Scripts

| Script | Description |
|--------|-------------|
| `install-apparmor.sh` | Installer profils AppArmor |
| `install-audit.sh` | Configurer auditd |

### Usage

```bash
sudo bash install-apparmor.sh
sudo bash install-audit.sh
```

---

## Screenshot & Documentation

| Script | Description |
|--------|-------------|
| `capture-module-screenshots.sh` | Screenshots tous modules |
| `secubox-screenshots.sh` | Screenshots automatiques |

---

## Export Scripts

| Script | Description |
|--------|-------------|
| `export-preseed.sh` | Exporter config preseed |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECUBOX_TARGET` | Cible SSH (user@host) |
| `SECUBOX_PORT` | Port SSH (défaut: 22) |

---

## See Also

- [docs/TOOLS.md](../docs/TOOLS.md) — Référence complète des outils
- [image/README.md](../image/README.md) — Scripts de build d'images

---

## Author

Gerald KERMA <devel@cybermind.fr>
