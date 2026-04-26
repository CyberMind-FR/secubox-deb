# SecuBox OS

**CyberMind · Gondwana · Notre-Dame-du-Cruet · Savoie** | [FR](Home-FR) | [中文](Home-ZH)

**SecuBox OS** — Appliance de cybersécurité complète portée depuis OpenWrt vers Debian bookworm.
Conçue pour boards ARM64 GlobalScale (MOCHAbin, ESPRESSObin) et systèmes x86_64.

**125 modules · 2000+ endpoints API · Candidat ANSSI CSPN**

---

## Qu'est-ce que SecuBox OS ?

SecuBox OS est un système d'exploitation durci orienté sécurité réseau :

| Fonction | Description |
|----------|-------------|
| **Firewall** | nftables DEFAULT DROP, règles automatiques |
| **IDS/IPS** | CrowdSec + Suricata, threat intelligence temps réel |
| **WAF** | HAProxy + mitmproxy, 300+ règles ModSecurity |
| **VPN** | WireGuard natif, mesh P2P |
| **DPI** | nDPId + netifyd, analyse trafic L7 |
| **DNS** | Unbound Vortex, blocklists automatiques |

---

## 🔴 BOOT — Démarrage rapide

### VirtualBox (Recommandé)

```bash
# One-liner avec téléchargement auto
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh | bash -s -- --download
```

Voir [[Live-USB-VirtualBox]] pour les détails.

### Live USB

```bash
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

Voir [[Live-USB]] pour le guide complet.

### Installation APT

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full
```

---

## 🟠 AUTH — Accès

| Service | Utilisateur | Mot de passe | Port |
|---------|-------------|--------------|------|
| Web UI | admin | secubox | 9443 |
| SSH | root | secubox | 2222 |

---

## 🟢 ROOT — Matériel supporté

### ARM64 (Production)

| Board | SoC | Profil | Usage |
|-------|-----|--------|-------|
| MOCHAbin | Armada 7040 | Full | Entreprise, datacenter |
| ESPRESSObin v7 | Armada 3720 | Lite | PME, agences |
| ESPRESSObin Ultra | Armada 3720 | Lite+ | PME étendu |

### x86_64 (Dev/Test)

| Plateforme | Profil | Usage |
|------------|--------|-------|
| VirtualBox | Full | Développement |
| QEMU/KVM | Full | Test/CI |
| Bare metal | Full | Production x86 |

---

## 🟣 MIND — Stack modulaire

SecuBox OS est organisé en 6 stacks fonctionnelles :

| Stack | Code couleur | Modules clés |
|-------|--------------|--------------|
| 🟠 **AUTH** | Orange | auth, portal, nac, users |
| 🟡 **WALL** | Jaune | crowdsec, waf, ipblock, threats |
| 🔴 **BOOT** | Rouge | cloner, vault, vm, backup |
| 🟣 **MIND** | Violet | dpi, ai-insights, netdata |
| 🟢 **ROOT** | Vert | core, hub, system, admin |
| 🔵 **MESH** | Bleu | wireguard, haproxy, qos, mesh |

Voir [[Modules]] pour les 125 modules.

---

## 🔵 MESH — Documentation

### Démarrage
- [[Live-USB-VirtualBox|VirtualBox]]
- [[Live-USB|USB Boot]]
- [[ARM-Installation|Boards ARM]]
- [[QEMU-ARM64|Émulation QEMU]]

### Configuration
- [[Configuration]]
- [[Configuration-Advanced]]
- [[Troubleshooting]]

### Architecture
- [[Architecture-Boot|Couches de boot]]
- [[Architecture-Modules|Design modulaire]]
- [[Architecture-Security|Modèle de sécurité]]

### Développement
- [[Developer-Guide]]
- [[Design-System|UI/UX]]
- [[API-Reference]]

---

## 🟡 WALL — Sécurité

### Firewall & IDS
- **nftables** — DEFAULT DROP, règles dynamiques
- **CrowdSec** — IDS communautaire, bouncer automatique
- **Suricata** — Signatures ET Open

### WAF & Inspection
- **HAProxy** — TLS 1.3, load balancing
- **mitmproxy** — Inspection HTTPS transparente
- **300+ règles** — OWASP ModSecurity CRS

### AI & Threat Intel
- **AI-Insights** — Détection ML anomalies
- **Threat feeds** — AbuseIPDB, Emerging Threats
- **Geo-blocking** — Blocage par pays

---

## Addons

### 👁️ Eye Remote (Addon)

Dashboard USB gadget compact pour monitoring SecuBox.

| Composant | Description |
|-----------|-------------|
| Hardware | Pi Zero W + HyperPixel 2.1 Round (480×480) |
| Connexion | USB OTG (10.55.0.0/30) ou WiFi |
| Modes | Normal, Flash, Debug, TTY, Auth |

**Documentation :** [[Eye-Remote|Eye Remote Addon]]

```bash
# Build image Pi Zero W
cd remote-ui/round
sudo ./build-eye-remote-image.sh -i raspios-lite.img.xz
```

---

## Liens

- [GitHub](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [APT Repository](https://apt.secubox.in)
- [CyberMind](https://cybermind.fr)

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie*
