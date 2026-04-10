# Installationsanleitung

[English](Installation) | [Français](Installation-FR) | [中文](Installation-ZH)

## Schnellinstallation (APT)

```bash
# SecuBox-Repository hinzufügen
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Vollständige Suite installieren
sudo apt install secubox-full

# Oder minimale Installation
sudo apt install secubox-lite
```

## Manuelle APT-Einrichtung

```bash
# GPG-Schlüssel importieren
curl -fsSL https://apt.secubox.in/gpg.key | gpg --dearmor -o /etc/apt/keyrings/secubox.gpg

# Repository hinzufügen
echo "deb [signed-by=/etc/apt/keyrings/secubox.gpg] https://apt.secubox.in bookworm main" \
  | sudo tee /etc/apt/sources.list.d/secubox.list

# Aktualisieren und installieren
sudo apt update
sudo apt install secubox-full
```

## System-Image-Installation

### Images herunterladen

| Board | Image |
|-------|-------|
| MOCHAbin | `secubox-mochabin-bookworm.img.gz` |
| ESPRESSObin v7 | `secubox-espressobin-v7-bookworm.img.gz` |
| ESPRESSObin Ultra | `secubox-espressobin-ultra-bookworm.img.gz` |
| VM x64 | `secubox-vm-x64-bookworm.img.gz` |

### Auf SD-Karte / eMMC flashen

```bash
# Herunterladen
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-mochabin-bookworm.img.gz

# Auf SD-Karte flashen
gunzip -c secubox-mochabin-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

### VirtualBox-Einrichtung

```bash
# Dekomprimieren
gunzip secubox-vm-x64-bookworm.img.gz

# In VDI konvertieren
VBoxManage convertfromraw secubox-vm-x64-bookworm.img secubox.vdi --format VDI

# VM erstellen
VBoxManage createvm --name SecuBox --ostype Debian_64 --register
VBoxManage modifyvm SecuBox --memory 2048 --cpus 2 --nic1 nat --firmware efi
VBoxManage storagectl SecuBox --name SATA --add sata
VBoxManage storageattach SecuBox --storagectl SATA --port 0 --device 0 --type hdd --medium secubox.vdi

# Starten
VBoxManage startvm SecuBox
```

### QEMU-Einrichtung

```bash
gunzip secubox-vm-x64-bookworm.img.gz
qemu-system-x86_64 \
  -drive file=secubox-vm-x64-bookworm.img,format=raw \
  -enable-kvm \
  -m 2048 \
  -smp 2 \
  -bios /usr/share/ovmf/OVMF.fd
```

## Paketauswahl

### Metapakete

| Paket | Beschreibung |
|-------|--------------|
| `secubox-full` | Alle Module (empfohlen für MOCHAbin/VM) |
| `secubox-lite` | Kern-Module (für ESPRESSObin) |

### Einzelpakete

**Kern:**
- `secubox-core` - Gemeinsame Bibliotheken, Auth-Framework
- `secubox-hub` - Zentrales Dashboard
- `secubox-portal` - Web-Authentifizierung

**Sicherheit:**
- `secubox-crowdsec` - IDS/IPS mit CrowdSec
- `secubox-waf` - Web Application Firewall
- `secubox-auth` - OAuth2, Captive Portal
- `secubox-nac` - Network Access Control

**Netzwerk:**
- `secubox-wireguard` - VPN-Dashboard
- `secubox-haproxy` - Load Balancer
- `secubox-dpi` - Deep Packet Inspection
- `secubox-qos` - Bandbreitenmanagement
- `secubox-netmodes` - Netzwerkmodi

**Anwendungen:**
- `secubox-mail` - E-Mail-Server
- `secubox-dns` - DNS-Server
- `secubox-netdata` - Überwachung

## Nach der Installation

### Erster Start

1. Web UI aufrufen: `https://<IP>:8443`
2. Anmelden: admin / admin
3. Passwort sofort ändern
4. Netzwerkeinstellungen konfigurieren
5. Benötigte Module aktivieren

### Sicherheitshärtung

```bash
# Standardpasswörter ändern
passwd root
passwd secubox

# System aktualisieren
apt update && apt upgrade

# Firewall aktivieren
systemctl enable --now nftables
```

## Anforderungen

### Hardware

| Spezifikation | Minimum | Empfohlen |
|---------------|---------|-----------|
| RAM | 1 GB | 2+ GB |
| Speicher | 4 GB | 16+ GB |
| CPU | ARM64/x86_64 | 2+ Kerne |

### Software

- Debian 12 (bookworm)
- systemd
- Python 3.11+

## Siehe auch

- [[Live-USB]] - Ausprobieren ohne Installation
- [[Configuration]] - Systemkonfiguration
- [[MODULES-DE|Module]] - Moduldetails
