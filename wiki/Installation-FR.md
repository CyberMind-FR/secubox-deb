# Guide d'Installation

[English](Installation) | [中文](Installation-ZH)

## Installation Rapide (APT)

```bash
# Ajouter le depot SecuBox
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Installer la suite complete
sudo apt install secubox-full

# Ou installation minimale
sudo apt install secubox-lite
```

## Configuration Manuelle APT

```bash
# Importer la cle GPG
curl -fsSL https://apt.secubox.in/gpg.key | gpg --dearmor -o /etc/apt/keyrings/secubox.gpg

# Ajouter le depot
echo "deb [signed-by=/etc/apt/keyrings/secubox.gpg] https://apt.secubox.in bookworm main" \
  | sudo tee /etc/apt/sources.list.d/secubox.list

# Mettre a jour et installer
sudo apt update
sudo apt install secubox-full
```

## Installation Image Systeme

### Telecharger les Images

| Carte | Image |
|-------|-------|
| MOCHAbin | `secubox-mochabin-bookworm.img.gz` |
| ESPRESSObin v7 | `secubox-espressobin-v7-bookworm.img.gz` |
| ESPRESSObin Ultra | `secubox-espressobin-ultra-bookworm.img.gz` |
| VM x64 | `secubox-vm-x64-bookworm.img.gz` |

### Flasher sur Carte SD / eMMC

```bash
# Telecharger
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-mochabin-bookworm.img.gz

# Flasher sur carte SD
gunzip -c secubox-mochabin-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

### Configuration VirtualBox

```bash
# Decompresser
gunzip secubox-vm-x64-bookworm.img.gz

# Convertir en VDI
VBoxManage convertfromraw secubox-vm-x64-bookworm.img secubox.vdi --format VDI

# Creer la VM
VBoxManage createvm --name SecuBox --ostype Debian_64 --register
VBoxManage modifyvm SecuBox --memory 2048 --cpus 2 --nic1 nat --firmware efi
VBoxManage storagectl SecuBox --name SATA --add sata
VBoxManage storageattach SecuBox --storagectl SATA --port 0 --device 0 --type hdd --medium secubox.vdi

# Demarrer
VBoxManage startvm SecuBox
```

### Configuration QEMU

```bash
gunzip secubox-vm-x64-bookworm.img.gz
qemu-system-x86_64 \
  -drive file=secubox-vm-x64-bookworm.img,format=raw \
  -enable-kvm \
  -m 2048 \
  -smp 2 \
  -bios /usr/share/ovmf/OVMF.fd
```

## Selection des Paquets

### Metapaquets

| Paquet | Description |
|--------|-------------|
| `secubox-full` | Tous les modules (recommande pour MOCHAbin/VM) |
| `secubox-lite` | Modules essentiels (pour ESPRESSObin) |

### Paquets Individuels

**Coeur :**
- `secubox-core` - Bibliotheques partagees, framework auth
- `secubox-hub` - Tableau de bord central
- `secubox-portal` - Authentification web

**Securite :**
- `secubox-crowdsec` - IDS/IPS avec CrowdSec
- `secubox-waf` - Pare-feu applicatif web
- `secubox-auth` - OAuth2, portail captif
- `secubox-nac` - Controle d'acces reseau

**Reseau :**
- `secubox-wireguard` - Tableau de bord VPN
- `secubox-haproxy` - Repartiteur de charge
- `secubox-dpi` - Inspection approfondie des paquets
- `secubox-qos` - Gestion de bande passante
- `secubox-netmodes` - Modes reseau

**Applications :**
- `secubox-mail` - Serveur email
- `secubox-dns` - Serveur DNS
- `secubox-netdata` - Supervision

## Post-Installation

### Premier Demarrage

1. Acceder a l'interface Web : `https://<IP>:8443`
2. Connexion : admin / admin
3. Changer le mot de passe immediatement
4. Configurer les parametres reseau
5. Activer les modules requis

### Renforcement Securite

```bash
# Changer les mots de passe par defaut
passwd root
passwd secubox

# Mettre a jour le systeme
apt update && apt upgrade

# Activer le pare-feu
systemctl enable --now nftables
```

## Configuration Requise

### Materiel

| Spec | Minimum | Recommande |
|------|---------|------------|
| RAM | 1 Go | 2+ Go |
| Stockage | 4 Go | 16+ Go |
| CPU | ARM64/x86_64 | 2+ coeurs |

### Logiciel

- Debian 12 (bookworm)
- systemd
- Python 3.11+

## Voir Aussi

- [[Live-USB-FR]] - Essayer sans installer
- [[Configuration-FR]] - Configuration systeme
- [[Modules-FR]] - Details des modules
