# SecuBox-DEB

**Appliance de Sécurité pour Debian** | [English](Home) | [中文](Home-ZH) | **v1.5.0**

SecuBox est une solution d'appliance de sécurité complète portée d'OpenWrt vers Debian bookworm, conçue pour les cartes ARM64 GlobalScale (MOCHAbin, ESPRESSObin) et les systèmes x86_64. Maintenant avec **93 paquets** et plus de **2000+ points d'API**.

---

## Démarrage Rapide

### VirtualBox (2 Minutes) ⭐

Testez SecuBox instantanément dans VirtualBox - aucune clé USB requise :

```bash
# Télécharger l'image
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/v1.5.0/secubox-live-amd64-bookworm.img.gz
gunzip secubox-live-amd64-bookworm.img.gz

# Convertir au format VDI
VBoxManage convertfromraw secubox-live-amd64-bookworm.img secubox-live.vdi --format VDI

# Créer et démarrer la VM (utiliser notre script)
curl -sLO https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/scripts/create-secubox-vm.sh
chmod +x create-secubox-vm.sh
./create-secubox-vm.sh secubox-live.vdi
```

**Ou en une seule commande avec téléchargement automatique :**

```bash
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/scripts/create-secubox-vm.sh | bash -s -- --download
```

**Accès (attendre 30-60s pour le démarrage) :**

| Service | Accès |
|---------|-------|
| **SSH** | `ssh -p 2222 root@localhost` |
| **Interface Web** | https://localhost:9443 |
| **Mot de passe** | `secubox` |

Voir [[Live-USB-VirtualBox]] pour la documentation complète et le dépannage.

---

### Live USB (Matériel)

Démarrez directement depuis USB sur du matériel physique :

```bash
# Télécharger
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/v1.5.0/secubox-live-amd64-bookworm.img.gz

# Flasher sur clé USB (remplacer /dev/sdX)
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

Voir [[Live-USB-FR]] pour le guide complet.

---

### Installation APT (Debian existant)

```bash
# Ajouter le dépôt et installer
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full   # ou secubox-lite
```

Voir [[Installation-FR]] pour les instructions détaillées.

---

## Options du Script de Création VM

Le script `create-secubox-vm.sh` supporte :

```bash
./create-secubox-vm.sh [OPTIONS] <image.vdi|image.img>

Options:
    --download        Télécharger la dernière image automatiquement
    --name NOM        Nom de la VM (défaut: SecuBox-Live)
    --memory MB       RAM en MB (défaut: 4096)
    --cpus N          Nombre de CPUs (défaut: 2)
    --ssh-port PORT   Port SSH (défaut: 2222)
    --https-port PORT Port HTTPS (défaut: 9443)
    --headless        Démarrer sans interface graphique
    --no-start        Créer la VM sans la démarrer
```

**Exemples :**

```bash
# Télécharger et créer une VM headless
./create-secubox-vm.sh --download --headless

# Configuration personnalisée
./create-secubox-vm.sh secubox.vdi --name "SecuBox-Dev" --memory 8192 --cpus 4

# Ports différents (si les défauts sont utilisés)
./create-secubox-vm.sh secubox.vdi --ssh-port 2223 --https-port 9444
```

---

## Fonctionnalités

| Catégorie | Modules | Nombre |
|-----------|---------|--------|
| **Sécurité** | CrowdSec, WAF, NAC, Auth, Hardening, AI-Insights, IPBlock | 15 |
| **Réseau** | WireGuard, HAProxy, DPI, QoS, Modes Réseau, Interceptor | 12 |
| **SOC** | Fleet Monitoring, Corrélation d'Alertes, Threat Maps, Console TUI | 6 |
| **Supervision** | Netdata, Metrics, Threats, OpenClaw OSINT | 8 |
| **Applications** | Ollama, Jellyfin, HomeAssistant, Matrix, Jitsi, PeerTube | 21 |
| **Outils Système** | Glances, MQTT, TURN, Vault, Cloner, VM | 22 |
| **Email & DNS** | Postfix/Dovecot, Webmail, DNS Provider | 9 |

**Total : 93 paquets**

---

## Matériel Supporté

| Carte | SoC | Profil | Utilisation |
|-------|-----|--------|-------------|
| MOCHAbin | Armada 7040 | Full | Passerelle Entreprise |
| ESPRESSObin v7 | Armada 3720 | Lite | Routeur Maison/PME |
| ESPRESSObin Ultra | Armada 3720 | Lite+ | Maison avec Wi-Fi |
| Raspberry Pi 4/5 | BCM2711/2712 | Lite/Full | Projets Maker |
| VM x86_64 | Tous | Full | Test/Développement |

---

## Documentation

- [[Live-USB-VirtualBox]] - **Démarrage rapide VirtualBox** ⭐
- [[Live-USB-FR]] - Guide USB bootable
- [[Installation-FR]] - Installation complète
- [[MODULES-FR|Modules]] - Les 93 modules
- [[API-Reference-FR]] - API REST (2000+ endpoints)
- [[Troubleshooting-FR]] - Problèmes courants

---

## Identifiants par Défaut

| Service | Utilisateur | Mot de passe |
|---------|-------------|--------------|
| Interface Web | admin | secubox |
| SSH | root | secubox |

---

## Liens

- [Dépôt GitHub](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [Issues](https://github.com/CyberMind-FR/secubox-deb/issues)
- [CyberMind](https://cybermind.fr)
