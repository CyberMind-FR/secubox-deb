# SecuBox

**CyberMind · Gondwana · Notre-Dame-du-Cruet · Savoie** | [EN](Home) | [中文](Home-ZH) | **v1.5.9**

Solution complète d'appliance de sécurité portée d'OpenWrt vers Debian bookworm. Conçue pour les cartes ARM64 GlobalScale (MOCHAbin, ESPRESSObin) et les systèmes x86_64. **125 paquets** avec plus de **2000+ points d'API**.

---

## 🔴 BOOT — Démarrage Rapide

### VirtualBox (2 Minutes) ⭐

Testez SecuBox instantanément dans VirtualBox — aucune clé USB requise :

```bash
# Télécharger l'image
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/v1.5.9/secubox-live-amd64-bookworm.img.gz
gunzip secubox-live-amd64-bookworm.img.gz

# Convertir au format VDI
VBoxManage convertfromraw secubox-live-amd64-bookworm.img secubox-live.vdi --format VDI

# Créer et démarrer la VM
curl -sLO https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh
chmod +x create-vbox-vm.sh
./create-vbox-vm.sh secubox-live.vdi
```

**Une seule commande avec téléchargement automatique :**

```bash
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh | bash -s -- --download
```

Voir [[Live-USB-VirtualBox]] pour la documentation complète.

### Live USB (Matériel) ⚡

Démarrez directement depuis USB sur du matériel physique :

```bash
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/v1.5.9/secubox-live-amd64-bookworm.img.gz
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

Voir [[Live-USB-FR]] pour le guide complet.

### Installation APT (Debian existant)

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full   # ou secubox-lite
```

Voir [[Installation-FR]] pour les instructions détaillées.

---

## 🟠 AUTH — Identifiants d'Accès

| Service | Utilisateur | Mot de passe |
|---------|-------------|--------------|
| **Interface Web** | admin | secubox |
| **SSH** | root | secubox |
| **Accès** | https://localhost:9443 | Port SSH 2222 |

---

## 🟢 ROOT — Configuration Requise

| Carte | SoC | Profil | Utilisation |
|-------|-----|--------|-------------|
| MOCHAbin | Armada 7040 | Full | Passerelle Entreprise |
| ESPRESSObin v7 | Armada 3720 | Lite | Routeur Maison/PME |
| ESPRESSObin Ultra | Armada 3720 | Lite+ | Maison avec Wi-Fi |
| Raspberry Pi 400 | BCM2711 | Full | Projets Maker |
| VM x86_64 | Tous | Full | Test/Développement |
| QEMU ARM64 | Émulé | Full | Test ARM sur x86 |

---

## 🟣 MIND — Aperçu des Fonctionnalités

| Stack | Description | Modules |
|-------|-------------|---------|
| 🟠 **AUTH** | Authentification, ZeroTrust, MFA | auth, portal, users, nac |
| 🟡 **WALL** | Pare-feu, CrowdSec, WAF, IDS/IPS | crowdsec, waf, threats, ipblock |
| 🔴 **BOOT** | Déploiement, provisioning | cloner, vault, vm, rezapp |
| 🟣 **MIND** | IA, analyse comportementale, DPI | dpi, netifyd, ai-insights, soc |
| 🟢 **ROOT** | Système, CLI, durcissement | core, hub, system, console |
| 🔵 **MESH** | Réseau, WireGuard, QoS | wireguard, haproxy, netmodes, turn |

**Total : 125 paquets**

Voir [[MODULES-FR|Modules]] pour la documentation complète des modules.

---

## 🔵 MESH — Documentation

### Pour Commencer
- [[Live-USB-VirtualBox|Démarrage rapide VirtualBox]] ⭐
- [[Live-USB-FR]] — Guide USB bootable
- [[ARM-Installation-FR]] — Cartes ARM & U-Boot ⚡
- [[QEMU-ARM64]] — Émulation ARM sur x86 🖥️

### Configuration
- [[Configuration-FR]] — Configuration système
- [[Troubleshooting-FR]] — Problèmes courants

### Référence
- [[MODULES-FR|Modules]] — Les 125 modules
- [[API-Reference-FR]] — API REST (2000+ endpoints)

---

## 🟡 WALL — Fonctionnalités de Sécurité

- **CrowdSec** — IDS/IPS communautaire
- **WAF** — 300+ règles ModSecurity
- **nftables** — Politique DROP par défaut
- **AI-Insights** — Détection ML des menaces
- **IPBlock** — Gestion automatique des blocklists
- **MAC-Guard** — Contrôle des adresses MAC

---

## Liens

- [Dépôt GitHub](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [Issues](https://github.com/CyberMind-FR/secubox-deb/issues)
- [CyberMind](https://cybermind.fr)

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie*
