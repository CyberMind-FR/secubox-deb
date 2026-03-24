# SecuBox-DEB

**Appliance de Securite pour Debian** | [English](Home) | [中文](Home-ZH)

SecuBox est une solution d'appliance de securite complete portee d'OpenWrt vers Debian bookworm, concue pour les cartes ARM64 GlobalScale (MOCHAbin, ESPRESSObin) et les systemes x86_64.

## Demarrage Rapide

### Live USB (Le plus rapide)

Demarrez directement depuis USB - aucune installation requise :

```bash
# Telecharger
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz

# Flasher sur cle USB
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

Voir [[Live-USB-FR]] pour le guide complet.

### Installation APT

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full
```

## Fonctionnalites

| Categorie | Modules |
|-----------|---------|
| **Securite** | CrowdSec IDS/IPS, WAF, NAC, Auth |
| **Reseau** | WireGuard VPN, HAProxy, DPI, QoS |
| **Supervision** | Netdata, MediaFlow, Metrics |
| **Email** | Postfix/Dovecot, Webmail |
| **Publication** | Droplet, Streamlit, MetaBlogizer |

## Materiel Supporte

| Carte | SoC | Utilisation |
|-------|-----|-------------|
| MOCHAbin | Armada 7040 | SecuBox Pro |
| ESPRESSObin v7 | Armada 3720 | SecuBox Lite |
| ESPRESSObin Ultra | Armada 3720 | SecuBox Lite+ |
| VM x86_64 | Tous | Test/Developpement |

## Documentation

- [[Live-USB-FR]] - Guide USB bootable
- [[Installation-FR]] - Installation complete
- [[Configuration-FR]] - Configuration systeme
- [[API-Reference-FR]] - Documentation API REST
- [[Troubleshooting-FR]] - Problemes courants

## Identifiants par Defaut

| Service | Utilisateur | Mot de passe |
|---------|-------------|--------------|
| Interface Web | admin | admin |
| SSH | root | secubox |

## Liens

- [Depot GitHub](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [Issues](https://github.com/CyberMind-FR/secubox-deb/issues)
