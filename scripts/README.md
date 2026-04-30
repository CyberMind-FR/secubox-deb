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

## Flash & Download

| Script | Description |
|--------|-------------|
| `flash-multiboot.sh` | Download & flash multiboot USB |

### Usage

```bash
# List available releases
bash flash-multiboot.sh --list

# Flash latest multiboot to USB
sudo bash flash-multiboot.sh /dev/sdb

# Download specific release without flashing
bash flash-multiboot.sh --release multiboot-v2.2.4-live --download

# Flash with force (no confirmation)
sudo bash flash-multiboot.sh --force /dev/sdb
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

## Performance Benchmarks

| Script | Description |
|--------|-------------|
| `bench/api-latency.py` | API endpoint latency testing (P50/P95/P99) |
| `bench/memory-baseline.sh` | Per-service memory tracking (RSS/PSS/USS) |
| `bench/startup-time.sh` | Service cold-start measurement |
| `bench/cpu-profile.sh` | Flame graph generation with py-spy |
| `bench/locustfile.py` | Locust load test scenarios |

See [bench/README.md](bench/README.md) for detailed usage.

### Quick Usage

```bash
# API latency
./bench/api-latency.py --host 192.168.255.250 --requests 50

# Memory baseline
./bench/memory-baseline.sh

# Load test
locust -f bench/locustfile.py --host https://192.168.255.250
```

---

## Migration Scripts

| Script | Description |
|--------|-------------|
| `migration-export.sh` | Export SecuBox-OpenWrt configs via SSH |
| `migration-import.sh` | Import migration archive to SecuBox-DEB |
| `migration-transform.py` | UCI → TOML/netplan/nftables converter |

### Overview

Migration Data Saver exports services and content from SecuBox-OpenWrt and restores them to SecuBox-DEB targets (VirtualBox/amd64, ESPRESSObin/ARM64).

```
┌─────────────────────────────────┐
│  SecuBox-OpenWrt (source)       │
│  ├─ /etc/config/* (UCI)         │
│  ├─ /etc/wireguard/*.conf       │
│  ├─ /etc/crowdsec/*             │
│  └─ /srv/www/* (content)        │
└──────────────┬──────────────────┘
               │ SSH + tar
               ▼
┌─────────────────────────────────┐
│  Migration Archive (.tar.gz)    │
│  ├─ manifest.json               │
│  ├─ configs/ (UCI → TOML)       │
│  ├─ secrets/ (encrypted)        │
│  └─ content/ (web/media)        │
└──────────────┬──────────────────┘
               │ transform + import
               ▼
┌─────────────────────────────────┐
│  SecuBox-DEB (target)           │
│  ├─ /etc/secubox/*.toml         │
│  ├─ /etc/netplan/*.yaml         │
│  ├─ /etc/nftables.conf          │
│  └─ /srv/www/*                  │
└─────────────────────────────────┘
```

### Usage

```bash
# 1. Setup SSH key access to OpenWrt source
ssh-copy-id -i ~/.ssh/secubox-openwrt root@192.168.255.1

# 2. Export from OpenWrt
bash scripts/migration-export.sh -h 192.168.255.1 -i ~/.ssh/secubox-openwrt -o /tmp/migration.tar.gz

# 3. Preview import on target (dry-run)
bash scripts/migration-import.sh -f /tmp/migration.tar.gz --dry-run

# 4. Apply migration
bash scripts/migration-import.sh -f /tmp/migration.tar.gz

# Export with encryption
bash scripts/migration-export.sh -h 192.168.255.1 -e -o /tmp/migration.tar.gz.enc

# Import encrypted archive
bash scripts/migration-import.sh -f /tmp/migration.tar.gz.enc --passphrase "secret"

# Export/import specific modules only
bash scripts/migration-export.sh -h 192.168.255.1 -m wireguard,crowdsec,certs -o /tmp/partial.tar.gz
bash scripts/migration-import.sh -f /tmp/partial.tar.gz -m wireguard,crowdsec
```

### Exported Modules

| Module | OpenWrt Source | Debian Destination |
|--------|----------------|-------------------|
| network | /etc/config/network (UCI) | /etc/netplan/00-secubox.yaml |
| firewall | /etc/config/firewall (UCI) | /etc/nftables.conf |
| wireguard | /etc/wireguard/*.conf | /etc/wireguard/*.conf |
| crowdsec | /etc/crowdsec/* | /etc/crowdsec/* |
| dhcp | /etc/config/dhcp (UCI) | /etc/dnsmasq.d/secubox.conf |
| haproxy | /etc/haproxy/* | /etc/haproxy/* |
| nginx | /etc/nginx/* | /etc/nginx/* |
| certs | /etc/letsencrypt/* | /etc/letsencrypt/* |
| content | /srv/www/* | /srv/www/* |
| vhosts | /etc/config/vhost (UCI) | /etc/secubox/vhosts/*.toml |
| users | /etc/secubox/auth.toml | /etc/secubox/auth.toml |
| state | /var/lib/secubox/* | /var/lib/secubox/* |

### Rollback

Pre-import snapshots are created automatically at `/var/lib/secubox/rollback/pre-migration-TIMESTAMP/`. To rollback:

```bash
# Restore from snapshot
cp -a /var/lib/secubox/rollback/pre-migration-20260429-143022/* /etc/
```

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
