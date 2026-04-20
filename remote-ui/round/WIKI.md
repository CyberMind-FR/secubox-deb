# SecuBox Eye Remote — Wiki Technique

Documentation technique complète pour le déploiement et la maintenance de l'Eye Remote sur HyperPixel 2.1 Round ou x64 live.

---

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Modes de fonctionnement](#modes-de-fonctionnement)
3. [Mockups visuels](#mockups-visuels)
4. [Prérequis matériel](#prérequis-matériel)
5. [Installation détaillée](#installation-détaillée)
6. [Architecture technique](#architecture-technique)
7. [API Backend](#api-backend)
8. [Frontend Dashboard](#frontend-dashboard)
9. [USB OTG Gadget](#usb-otg-gadget)
10. [Configuration avancée](#configuration-avancée)
11. [Sécurité](#sécurité)
12. [x64 Live Boot](#x64-live-boot)
13. [Maintenance](#maintenance)
14. [Dépannage avancé](#dépannage-avancé)

---

## Vue d'ensemble

Le **SecuBox Eye Remote** est bien plus qu'un simple dashboard — c'est une **télécommande de sécurité multifonction** qui peut surveiller, déboguer, et même contrôler une appliance SecuBox via USB OTG.

### Évolution du concept

```
Version 1.0 (Clock)          Version 2.0 (Eye Remote)
┌────────────────────┐       ┌────────────────────┐
│    Simple clock    │       │  Remote Control    │
│    Status display  │  ──►  │  5 USB modes       │
│    WiFi only       │       │  Security key      │
│                    │       │  U-Boot keyboard   │
│                    │       │  Live flash tool   │
└────────────────────┘       └────────────────────┘
```

### Cas d'usage

| Mode | Cas d'usage |
|------|-------------|
| **Normal** | Rack datacenter, NOC monitoring, status display |
| **Flash** | Recovery d'une SecuBox briquée, installation initiale |
| **Debug** | Export de logs, diagnostic terrain, support remote |
| **TTY** | Commandes U-Boot automatisées, rescue boot |
| **Auth** | 2FA hardware, SSH authentication, WebAuthn |

### Caractéristiques

| Fonctionnalité | Détail |
|----------------|--------|
| Résolution | 480×480 pixels (circulaire) ou adaptatif x64 |
| Rafraîchissement | 2 secondes (configurable) |
| Protocole | REST API + JWT |
| Consommation | < 5W (RPi Zero W + écran) |
| Mode hors-ligne | Simulation disponible |
| USB Modes | ECM, ACM, Mass Storage, HID Keyboard, FIDO |
| Plateformes | RPi Zero W, x64 Live USB, VM |

---

## Modes de fonctionnement

### Vue d'ensemble des modes

```
                    ┌─────────────────────────────────────┐
                    │        secubox-otg-gadget.sh        │
                    └──────────────────┬──────────────────┘
                                       │
        ┌──────────┬───────────┬───────┼───────┬──────────┐
        │          │           │       │       │          │
        ▼          ▼           ▼       ▼       ▼          ▼
    ┌───────┐  ┌───────┐  ┌───────┐ ┌─────┐ ┌──────┐  ┌──────┐
    │ start │  │ flash │  │ debug │ │ tty │ │ auth │  │ stop │
    └───┬───┘  └───┬───┘  └───┬───┘ └──┬──┘ └──┬───┘  └──┬───┘
        │          │          │        │       │         │
        ▼          ▼          ▼        ▼       ▼         ▼
    ECM+ACM    Mass+ACM   ECM+Mass   HID+ACM  FIDO    Cleanup
                          +ACM               +ACM
```

### Mode Normal (start)

**Fonctions USB**: ECM/RNDIS (réseau) + CDC-ACM (série)

```
Gadget Configuration:
├── functions/
│   ├── ecm.usb0          ← Ethernet CDC (10.55.0.0/30)
│   └── acm.usb0          ← Serial console (115200 baud)
└── configs/c.1/
    ├── ecm.usb0 → ../functions/ecm.usb0
    └── acm.usb0 → ../functions/acm.usb0
```

**Status file** (`/run/secubox-gadget-status.json`):
```json
{
  "mode": "normal",
  "state": "active",
  "message": "OTG network ready",
  "timestamp": "2026-04-20T14:32:07+02:00",
  "extra": {
    "ip": "10.55.0.2",
    "serial": "/dev/ttyGS0"
  }
}
```

### Mode Flash (Recovery)

**Fonctions USB**: Mass Storage (bootable) + CDC-ACM (série)

```
Mass Storage Image:
/var/lib/secubox-flash.img (256MB, FAT32 bootable)
├── EFI/BOOT/
│   └── BOOTX64.EFI       ← GRUB EFI loader
├── vmlinuz               ← Kernel
├── initrd.img            ← Initramfs avec secubox-rescue
└── secubox-rescue.squashfs
```

**Workflow**:
```
1. Pi Zero expose image as bootable USB
2. Target SecuBox boots from USB (F12/BIOS)
3. Rescue system starts
4. Flash eMMC from recovery image
5. Round UI shows progress in real-time
```

### Mode Debug

**Fonctions USB**: ECM + Mass Storage (R/W) + CDC-ACM

```
Debug Partition:
/var/lib/secubox-debug.img (512MB, ext4)
├── var/log/secubox/      ← Exported logs
├── etc/secubox/          ← Config backup
├── run/secubox/          ← Runtime state
└── EXPORT_LOG.txt        ← Export manifest
```

**Cas d'usage**:
- Extract logs without SSH access
- Backup configuration
- Forensic analysis

### Mode TTY (Virtual Keyboard)

**Fonctions USB**: HID Keyboard + CDC-ACM

```
HID Keyboard Report (8 bytes):
┌─────────┬──────────┬──────┬──────┬──────┬──────┬──────┬──────┐
│Modifier │ Reserved │ Key1 │ Key2 │ Key3 │ Key4 │ Key5 │ Key6 │
└─────────┴──────────┴──────┴──────┴──────┴──────┴──────┴──────┘
    0x00      0x00     Scan codes (USB HID Usage Tables)
```

**Commandes automatisées**:
```bash
# U-Boot rescue sequence
./secubox-hid-keyboard.sh cmd 'printenv'
./secubox-hid-keyboard.sh cmd 'setenv bootcmd run bootusb'
./secubox-hid-keyboard.sh cmd 'saveenv'
./secubox-hid-keyboard.sh cmd 'boot'
```

**Queue file** (`/run/secubox-cmd-queue`):
```json
["printenv", "setenv bootcmd run bootusb", "saveenv", "boot"]
```

### Mode Auth (Eye Remote Security Key)

**Fonctions USB**: FIDO2/U2F HID + CDC-ACM

```
FIDO2 Flow:
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Relying   │────►│  Eye Remote │────►│   Display   │
│    Party    │     │  FIDO HID   │     │  QR + Touch │
└─────────────┘     └─────────────┘     └─────────────┘
     WebAuthn          Challenge           User approval
     SSH auth          Response            via touchscreen
```

**Auth state** (`/run/secubox-auth-state.json`):
```json
{
  "status": "pending",
  "challenge": "a3f7bc91...",
  "origin": "ssh://secubox.local",
  "timestamp": "2026-04-20T14:32:07Z",
  "qr_data": "otpauth://..."
}
```

---

## Mockups visuels

### Dashboard Normal — État nominal
```
╔══════════════════════════════════════╗
║         ● SECUBOX EYE               ║
║           OTG MODE                   ║
║                                      ║
║         ╔═══════════════╗            ║
║         ║   14:32:07    ║            ║
║         ║   mer 20 avr  ║            ║
║         ║   secubox-zr  ║            ║
║         ║   up 24h12    ║            ║
║         ╚═══════════════╝            ║
║                                      ║
║   ┌─────┐  ┌─────┐  ┌─────┐         ║
║   │AUTH │  │WALL │  │BOOT │         ║
║   │ 23% │  │ 41% │  │ 28% │         ║
║   └─────┘  └─────┘  └─────┘         ║
║   ┌─────┐  ┌─────┐  ┌─────┐         ║
║   │MIND │  │ROOT │  │MESH │         ║
║   │ 0.2 │  │ 44° │  │-62db│         ║
║   └─────┘  └─────┘  └─────┘         ║
║                                      ║
║   ═══════════════════════            ║
║   AUTH─WALL─BOOT─MIND─ROOT─MESH     ║
║                                      ║
║         ● NOMINAL                   ║
║   TEMP [████████░░░░] 44°C          ║
╚══════════════════════════════════════╝
```

### Dashboard Normal — Alerte CPU
```
╔══════════════════════════════════════╗
║         ● SECUBOX EYE               ║
║           OTG MODE                   ║
║                                      ║
║         ╔═══════════════╗            ║
║         ║   14:32:07    ║            ║
║         ╚═══════════════╝            ║
║                                      ║
║   ┌─────┐  ┌─────┐  ┌─────┐         ║
║   │AUTH │  │WALL │  │BOOT │         ║
║   │⚠87%│  │ 41% │  │ 28% │  ← Alert ║
║   └─────┘  └─────┘  └─────┘         ║
║                                      ║
║   ═══════════════════════            ║
║         ▲ AUTH 87%                  ║ ← Status bar
║   TEMP [████████████░] 72°C         ║ ← Temp warning
╚══════════════════════════════════════╝
```

### Mode Flash — Progress
```
╔══════════════════════════════════════╗
║         ● FLASH MODE                ║
║                                      ║
║         ╔═══════════════╗            ║
║         ║   FLASHING    ║            ║
║         ║   eMMC...     ║            ║
║         ╚═══════════════╝            ║
║                                      ║
║   ┌────────────────────────────┐     ║
║   │ ████████████████░░░░░░░░░ │     ║
║   │           67%              │     ║
║   │   1.2 GB / 1.8 GB         │     ║
║   │   ETA: 2m 34s             │     ║
║   └────────────────────────────┘     ║
║                                      ║
║   💾 secubox-2.0.0-armada.img       ║
║                                      ║
║         [CANCEL]                    ║
╚══════════════════════════════════════╝
```

### Mode TTY — Command Queue
```
╔══════════════════════════════════════╗
║         ● TTY MODE                  ║
║       Virtual HID Keyboard           ║
║                                      ║
║   ┌────────────────────────────┐     ║
║   │ Queue (3 commands):        │     ║
║   │ ✓ printenv                 │     ║
║   │ ► setenv bootcmd run usb   │ ←   ║
║   │   saveenv                  │     ║
║   │   boot                     │     ║
║   └────────────────────────────┘     ║
║                                      ║
║   ⌨️  Typing: setenv bootcm...      ║
║      [██████████░░░░] 67%           ║
║                                      ║
║   Serial output:                     ║
║   ┌────────────────────────────┐     ║
║   │ => printenv                │     ║
║   │ bootcmd=run bootmmc        │     ║
║   │ =>                         │     ║
║   └────────────────────────────┘     ║
║                                      ║
║   [PAUSE]  [SKIP]  [+CMD]           ║
╚══════════════════════════════════════╝
```

### Mode Auth — QR Challenge
```
╔══════════════════════════════════════╗
║         ● EYE REMOTE                ║
║       FIDO2 Security Key             ║
║                                      ║
║   ┌────────────────────────────┐     ║
║   │                            │     ║
║   │    ▄▄▄▄▄ ▄ ▄ ▄ ▄▄▄▄▄      │     ║
║   │    █ ▄▄▄ █ ▀▄  █ ▄▄▄ █    │     ║
║   │    █ ███ █▀▀▄▄ █ ███ █    │     ║
║   │    █▄▄▄▄█ ▄ █ ▄█▄▄▄▄█    │     ║
║   │    ▄▄▄ ▄▄▄▄▄ ▄▄▄▄▄▄▄▄    │     ║
║   │    ▀▀▀▀▄██▀▀▀▄ ▄▀█ ▀▀    │     ║
║   │    ▄▄▄▄▄▄▄ ▀▄█▀▄ █▀▄█    │     ║
║   │                            │     ║
║   └────────────────────────────┘     ║
║                                      ║
║   🔐 SSH: root@secubox.local        ║
║      Challenge: a3f7bc91...         ║
║                                      ║
║    ┌────────────┐ ┌────────────┐    ║
║    │  APPROVE   │ │    DENY    │    ║
║    │    ✓       │ │     ✗      │    ║
║    └────────────┘ └────────────┘    ║
╚══════════════════════════════════════╝
```

### Mode Debug — Export Logs
```
╔══════════════════════════════════════╗
║         ● DEBUG MODE                ║
║                                      ║
║   Target: secubox-esbin              ║
║   IP: 10.55.0.1                      ║
║                                      ║
║   ┌────────────────────────────┐     ║
║   │ Exported files:            │     ║
║   │ 📁 /var/log/secubox/       │     ║
║   │    ├── crowdsec.log   2.1M │     ║
║   │    ├── suricata.log   4.3M │     ║
║   │    └── audit.log      892K │     ║
║   │ 📁 /etc/secubox/           │     ║
║   │    └── (14 files)     128K │     ║
║   └────────────────────────────┘     ║
║                                      ║
║   Storage: [██████░░░░] 58% used    ║
║   Total exported: 7.4 MB            ║
║                                      ║
║   [EXPORT MORE]  [EJECT]  [STOP]    ║
╚══════════════════════════════════════╝
```

---

## Prérequis matériel

### Bill of Materials (BOM)

| Composant | Référence exacte | Prix indicatif | Notes |
|-----------|------------------|----------------|-------|
| RPi Zero W | Raspberry Pi Zero W v1.1 | ~15€ | WiFi + BT intégré |
| RPi Zero 2 W | Raspberry Pi Zero 2 W | ~20€ | Alternative plus puissante |
| HyperPixel 2.1 Round | Pimoroni PIM578 | ~50€ | Tactile capacitif |
| Carte microSD | SanDisk Industrial 8Go+ | ~10€ | Class 10, endurance |
| Alimentation | 5V 2.5A micro-USB | ~10€ | Officielle RPi recommandée |
| Câble | Micro-USB vers USB-A | — | Pour l'alimentation |

### Compatibilité

| Modèle | Supporté | Notes |
|--------|----------|-------|
| RPi Zero W | ✅ | Recommandé (testé) |
| RPi Zero 2 W | ✅ | Plus rapide, compatible |
| RPi Zero (sans W) | ❌ | Pas de WiFi intégré |
| RPi 3/4/5 | ⚠️ | Fonctionne mais surdimensionné |

---

## Installation détaillée

### Étape 1 : Préparation de l'environnement

```bash
# Cloner le dépôt SecuBox-Deb
git clone https://github.com/CyberMind-FR/secubox-deb.git
cd secubox-deb/remote-ui/round

# Vérifier les outils requis
which dd xzcat partprobe
```

### Étape 2 : Télécharger l'image Raspberry Pi OS

```bash
# Raspberry Pi OS Lite (32-bit, Bookworm) — recommandé
wget https://downloads.raspberrypi.com/raspios_lite_armhf/images/raspios_lite_armhf-2024-03-15/2024-03-15-raspios-bookworm-armhf-lite.img.xz

# SHA256 verification
echo "abc123... *2024-03-15-raspios-bookworm-armhf-lite.img.xz" | sha256sum -c
```

### Étape 3 : Identifier le périphérique SD

```bash
# Avant insertion
lsblk

# Insérer la carte SD, puis
lsblk
# Nouveau périphérique = votre carte SD (ex: /dev/sdb)

# ATTENTION: Vérifier avec dmesg
dmesg | tail -20 | grep -E "sd|mmc"
```

### Étape 4 : Exécuter l'installation

```bash
sudo ./install_zerow.sh \
    --device /dev/sdb \
    --image 2024-03-15-raspios-bookworm-armhf-lite.img.xz \
    --ssid "MonReseauWiFi" \
    --psk "MotDePasseSecurise123" \
    --hostname "secubox-round" \
    --pubkey ~/.ssh/id_ed25519.pub
```

### Étape 5 : Premier démarrage

1. Éjecter proprement : `sudo eject /dev/sdb`
2. Retirer la carte SD
3. Monter l'écran HyperPixel sur le GPIO du RPi Zero W
4. Insérer la carte SD
5. Brancher l'alimentation
6. Attendre 5-10 minutes (firstrun)

Le système va :
- Configurer le réseau WiFi
- Mettre à jour les paquets
- Installer les drivers HyperPixel
- Configurer le kiosk Chromium
- Redémarrer automatiquement

### Étape 6 : Vérifier la connexion

```bash
# Attendre que le RPi soit visible sur le réseau
ping secubox-round.local

# Connexion SSH
ssh secubox@secubox-round.local
# Mot de passe par défaut: secubox2026
```

### Étape 7 : Déployer le dashboard

```bash
./deploy.sh \
    --host secubox-round.local \
    --api-url http://192.168.1.1:8000 \
    --api-pass "VotreMotDePasseAPISecuBox"
```

---

## Architecture technique

### Diagramme de flux

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SecuBox Appliance                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ secubox-system (FastAPI)                                     │   │
│  │ └── /api/v1/system/metrics                                   │   │
│  │     └── core/metrics.py (lecture /proc, sans psutil)        │   │
│  └─────────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                          WiFi / Ethernet
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                      RPi Zero W + HyperPixel                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ nginx:8080                                                   │   │
│  │ ├── location /api/* → proxy_pass http://secubox:8000        │   │
│  │ └── location /* → /var/www/secubox-round/index.html         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Chromium (kiosk mode)                                        │   │
│  │ └── http://localhost:8080                                    │   │
│  │     └── fetch('/api/v1/system/metrics') chaque 5s           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ HyperPixel 2.1 Round (480×480)                              │   │
│  │ └── Framebuffer /dev/fb0                                     │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Stack logicielle RPi

| Couche | Composant | Version |
|--------|-----------|---------|
| OS | Raspberry Pi OS Lite | Bookworm (12) |
| Display Manager | LightDM | 1.26 |
| Window Manager | Openbox | 3.6 |
| Browser | Chromium | 120+ |
| Web Server | nginx | 1.22 |
| Driver écran | hyperpixel2r | latest |

---

## API Backend

### Collecte des métriques (sans psutil)

Le module `core/metrics.py` collecte les métriques directement depuis `/proc` pour éviter la dépendance psutil (trop lourde pour armhf) :

```python
# CPU: Delta /proc/stat sur 200ms
async def cpu_percent(sample_ms=200):
    t1 = read_proc_stat()
    await asyncio.sleep(sample_ms / 1000)
    t2 = read_proc_stat()
    return calculate_delta(t1, t2)

# Memory: /proc/meminfo
async def mem_percent():
    with open('/proc/meminfo') as f:
        data = parse_meminfo(f.read())
    return (data['MemTotal'] - data['MemAvailable']) / data['MemTotal'] * 100

# Disk: os.statvfs
async def disk_percent(path='/'):
    st = os.statvfs(path)
    return (1 - st.f_bavail / st.f_blocks) * 100

# Temperature: /sys/class/thermal
async def cpu_temp():
    with open('/sys/class/thermal/thermal_zone0/temp') as f:
        return int(f.read()) / 1000

# WiFi: /proc/net/wireless
async def wifi_rssi():
    with open('/proc/net/wireless') as f:
        # Parse signal level from wlan0 line
```

### Endpoints

#### `GET /api/v1/system/metrics`

Réponse complète des métriques :

```json
{
  "cpu_percent": 45.2,
  "mem_percent": 67.8,
  "disk_percent": 34.5,
  "wifi_rssi": -52,
  "load_avg_1": 0.42,
  "cpu_temp": 48.3,
  "uptime_seconds": 86420,
  "hostname": "secubox-01",
  "secubox_version": "1.7.0",
  "modules_active": 5
}
```

#### `GET /api/v1/system/metrics/modules`

État des 6 modules :

```json
{
  "modules": {
    "AUTH": "active",
    "WALL": "active",
    "BOOT": "active",
    "MIND": "inactive",
    "ROOT": "active",
    "MESH": "active"
  },
  "active_count": 5
}
```

#### `GET /api/v1/system/metrics/alerts`

Alertes basées sur les seuils :

```json
{
  "global_level": "warn",
  "alerts": [
    {
      "metric": "cpu",
      "level": "warn",
      "value": 78.5,
      "threshold": 70,
      "message": "CPU élevé: 78.5%"
    }
  ],
  "alerts_count": 1,
  "timestamp": 1713196800
}
```

---

## Frontend Dashboard

### Structure SVG

Le dashboard utilise des `<circle>` SVG pour les anneaux :

```html
<svg viewBox="0 0 480 480">
  <!-- MESH - Anneau extérieur -->
  <circle class="ring" id="ring-mesh" cx="240" cy="240" r="220"
          stroke-width="35" stroke="#104A88" fill="none"/>

  <!-- ROOT -->
  <circle class="ring" id="ring-root" cx="240" cy="240" r="185"
          stroke-width="35" stroke="#0A5840" fill="none"/>

  <!-- MIND -->
  <circle class="ring" id="ring-mind" cx="240" cy="240" r="150"
          stroke-width="35" stroke="#3D35A0" fill="none"/>

  <!-- BOOT -->
  <circle class="ring" id="ring-boot" cx="240" cy="240" r="115"
          stroke-width="35" stroke="#803018" fill="none"/>

  <!-- WALL -->
  <circle class="ring" id="ring-wall" cx="240" cy="240" r="80"
          stroke-width="35" stroke="#9A6010" fill="none"/>

  <!-- AUTH - Plus proche du centre -->
  <circle class="ring" id="ring-auth" cx="240" cy="240" r="45"
          stroke-width="25" stroke="#C04E24" fill="none"/>

  <!-- Centre: CPU % -->
  <text id="cpu-text" x="240" y="250" text-anchor="middle"
        font-size="48" fill="#fff">78%</text>
</svg>
```

### Logique de couleur (alertes)

```javascript
function updateRingColor(ring, status) {
  const colors = {
    active: ring.dataset.color,    // Couleur normale du module
    inactive: '#333',              // Gris foncé
    error: '#e63946'               // Rouge
  };
  ring.style.stroke = colors[status] || colors.inactive;
}

function updateCpuColor(percent) {
  const cpu = document.getElementById('cpu-text');
  if (percent < 70) cpu.style.fill = '#00ff41';       // Vert
  else if (percent < 85) cpu.style.fill = '#ffc107';  // Orange
  else cpu.style.fill = '#e63946';                    // Rouge
}
```

---

## Configuration avancée

### Seuils d'alerte personnalisés

Éditer `/etc/secubox/secubox.conf` sur l'appliance SecuBox :

```toml
[remote_ui.thresholds.cpu]
warn = 60    # Alerter plus tôt
crit = 75

[remote_ui.thresholds.temp]
warn = 55    # Pour environnement chaud
crit = 65
```

### Intervalle de rafraîchissement

Dans `index.html` ou via `deploy.sh` :

```javascript
// CFG.REFRESH_INTERVAL = 5000;  // 5 secondes (défaut)
CFG.REFRESH_INTERVAL = 2000;     // 2 secondes (plus réactif)
CFG.REFRESH_INTERVAL = 10000;    // 10 secondes (économie réseau)
```

### USB OTG (Ethernet gadget)

Pour connecter le RPi directement à l'appliance SecuBox via USB :

```bash
sudo ./install_zerow.sh -d /dev/sdb -i image.img \
    --no-wifi \
    --usb-otg
```

Cela configure le Zero W en mode "Ethernet gadget" — il apparaîtra comme interface réseau USB sur la SecuBox.

---

## Sécurité

### Authentification

Le dashboard utilise JWT pour s'authentifier auprès de l'API :

1. Au démarrage, `POST /api/v1/auth/login` avec les credentials configurés
2. Le token JWT est stocké en mémoire (pas de localStorage)
3. Refresh automatique avant expiration
4. Scope limité : `metrics:read` (lecture seule)

### Isolation réseau

Recommandations :
- Placer le RPi sur un VLAN dédié (monitoring)
- Limiter les règles firewall : RPi → SecuBox:8000 uniquement
- Désactiver SSH après configuration si non nécessaire

### Secrets

- Le mot de passe WiFi est stocké dans `/boot/wpa_supplicant.conf` (effacé après firstrun)
- Le mot de passe API est patché dans `index.html` (non idéal, mais dashboard est isolé)
- Pour production : utiliser un token JWT pré-généré avec scope limité

---

## USB OTG Gadget

### Configuration ConfigFS

```bash
# Gadget creation sequence
GADGET=/sys/kernel/config/usb_gadget/secubox

mkdir -p $GADGET
cd $GADGET

# Device descriptor
echo 0x1d6b > idVendor    # Linux Foundation
echo 0x0104 > idProduct   # Multifunction Composite Gadget
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

# Strings
mkdir -p strings/0x409
echo "CyberMind"        > strings/0x409/manufacturer
echo "SecuBox Eye"      > strings/0x409/product
echo "$(cat /proc/cpuinfo | grep Serial | cut -d: -f2 | tr -d ' ')" \
                        > strings/0x409/serialnumber

# Configuration
mkdir -p configs/c.1/strings/0x409
echo "SecuBox OTG"      > configs/c.1/strings/0x409/configuration
echo 250                > configs/c.1/MaxPower
```

### ECM Function (Ethernet)
```bash
mkdir -p functions/ecm.usb0
# MAC addresses
HOST_MAC="de:ad:be:ef:$(echo $SERIAL | cut -c1-4)"
DEV_MAC="de:ad:be:ef:$(echo $SERIAL | cut -c5-8)"
echo $HOST_MAC > functions/ecm.usb0/host_addr
echo $DEV_MAC  > functions/ecm.usb0/dev_addr
ln -s functions/ecm.usb0 configs/c.1/
```

### ACM Function (Serial)
```bash
mkdir -p functions/acm.usb0
ln -s functions/acm.usb0 configs/c.1/
# Creates /dev/ttyGS0 on gadget side
# Creates /dev/ttyACM0 on host side
```

### Mass Storage Function
```bash
mkdir -p functions/mass_storage.usb0
echo 1 > functions/mass_storage.usb0/stall
echo 0 > functions/mass_storage.usb0/lun.0/cdrom
echo 0 > functions/mass_storage.usb0/lun.0/ro
echo 0 > functions/mass_storage.usb0/lun.0/nofua
echo "/var/lib/secubox-debug.img" > functions/mass_storage.usb0/lun.0/file
ln -s functions/mass_storage.usb0 configs/c.1/
```

### HID Keyboard Function
```bash
mkdir -p functions/hid.usb0
echo 1   > functions/hid.usb0/protocol    # Keyboard
echo 1   > functions/hid.usb0/subclass    # Boot interface
echo 8   > functions/hid.usb0/report_length
# HID Report Descriptor (boot keyboard)
echo -ne '\x05\x01\x09\x06\xa1\x01\x05\x07...' \
         > functions/hid.usb0/report_desc
ln -s functions/hid.usb0 configs/c.1/
# Creates /dev/hidg0
```

### Activation
```bash
# Find available UDC
UDC=$(ls /sys/class/udc | head -1)
echo $UDC > $GADGET/UDC
```

---

## x64 Live Boot

### Supported Platforms

| Platform | Display | Touch | Notes |
|----------|---------|-------|-------|
| Standard PC | VGA/HDMI | Optional | Full resolution |
| VM (QEMU) | virtio-vga | No | Testing only |
| Intel NUC | HDMI/DP | USB | Industrial kiosk |
| Mini PC | HDMI | USB HID | Cost-effective |

### Building x64 Live Image

```bash
# Build with Eye Remote profile
./image/build-live-usb.sh \
    --profile x64-live \
    --eye-remote \
    --output /tmp/secubox-eye-live.iso

# Contents
secubox-eye-live.iso
├── EFI/BOOT/
│   └── BOOTX64.EFI
├── boot/
│   ├── vmlinuz
│   └── initrd.img
├── live/
│   └── filesystem.squashfs
└── secubox/
    └── eye-remote/
        ├── index.html
        └── config/
```

### Boot Parameters

```
GRUB_CMDLINE:
  quiet splash
  secubox.mode=eye-remote
  secubox.api=http://192.168.1.1:8000
  secubox.display=auto
```

### Kiosk Configuration (x64)

```bash
# /etc/secubox/eye-remote.conf
[display]
resolution = "auto"       # or "1920x1080", "1280x720"
fullscreen = true
touch_enabled = true
rotation = 0              # 0, 90, 180, 270

[api]
base_url = "http://secubox.local:8000"
fallback_url = "http://192.168.1.1:8000"
simulate = false

[kiosk]
browser = "chromium"      # or "firefox"
hide_cursor = true
disable_context_menu = true
```

### Use Cases

1. **Initial SecuBox Setup**
   - Boot x64 live USB on target hardware
   - Eye Remote guides through setup wizard
   - Configure network, passwords, modules

2. **Staging Environment**
   - Test SecuBox configurations
   - Validate API responses
   - Train operators on interface

3. **Field Deployment**
   - Portable diagnostic tool
   - Works on any x64 laptop
   - No permanent installation needed

4. **Touchscreen Kiosk**
   - Industrial HMI displays
   - NOC wall displays
   - Public demo stations

---

## Maintenance

### Mise à jour du dashboard

```bash
# Depuis la machine de développement
cd secubox-deb/remote-ui/round
git pull
./deploy.sh -h secubox-round.local
```

### Mise à jour système RPi

```bash
ssh secubox@secubox-round.local
sudo apt update && sudo apt upgrade -y
sudo reboot
```

### Logs utiles

```bash
# Logs kiosk
journalctl -u secubox-remote-ui -f

# Logs nginx
tail -f /var/log/nginx/access.log /var/log/nginx/error.log

# Logs firstrun (si problème initial)
cat /var/log/secubox-firstrun.log
```

### Backup de configuration

```bash
ssh secubox@secubox-round.local "tar czf - /etc/nginx /var/www/secubox-round" > round-backup.tar.gz
```

---

## Dépannage avancé

### Problème : Écran blanc ou figé

```bash
# 1. Vérifier X11
ssh secubox@secubox-round.local
DISPLAY=:0 xrandr
# Doit afficher la résolution 480x480

# 2. Redémarrer le stack graphique
sudo systemctl restart lightdm

# 3. Vérifier Chromium
ps aux | grep chromium
# Si absent, redémarrer le service
sudo systemctl restart secubox-remote-ui
```

### Problème : "Network Error" dans le dashboard

```bash
# 1. Test connectivité
curl -v http://192.168.1.1:8000/api/v1/system/health

# 2. Vérifier proxy nginx
cat /etc/nginx/sites-enabled/secubox-round | grep proxy_pass

# 3. Corriger et recharger
sudo sed -i 's|proxy_pass .*;|proxy_pass http://192.168.1.1:8000;|' \
    /etc/nginx/sites-enabled/secubox-round
sudo nginx -t && sudo systemctl reload nginx
```

### Problème : Driver HyperPixel non chargé

```bash
# Vérifier le dtoverlay
cat /boot/config.txt | grep hyperpixel
# Doit afficher: dtoverlay=hyperpixel2r

# Vérifier les modules kernel
lsmod | grep -E "spi|i2c"

# Réinstaller le driver
cd /tmp && git clone https://github.com/pimoroni/hyperpixel2r.git
cd hyperpixel2r && sudo ./install.sh
sudo reboot
```

### Problème : Performances faibles

```bash
# Vérifier la température (throttling si > 80°C)
vcgencmd measure_temp

# Vérifier la fréquence CPU
vcgencmd measure_clock arm

# Augmenter le swap si nécessaire (Zero W = 512MB RAM)
sudo dphys-swapfile swapoff
sudo sed -i 's/CONF_SWAPSIZE=.*/CONF_SWAPSIZE=256/' /etc/dphys-swapfile
sudo dphys-swapfile setup
sudo dphys-swapfile swapon
```

---

## Annexes

### A. Palette de couleurs complète

| Module | Hex | RGB | HSL |
|--------|-----|-----|-----|
| AUTH | `#C04E24` | rgb(192, 78, 36) | hsl(16, 68%, 45%) |
| WALL | `#9A6010` | rgb(154, 96, 16) | hsl(35, 81%, 33%) |
| BOOT | `#803018` | rgb(128, 48, 24) | hsl(14, 68%, 30%) |
| MIND | `#3D35A0` | rgb(61, 53, 160) | hsl(244, 50%, 42%) |
| ROOT | `#0A5840` | rgb(10, 88, 64) | hsl(162, 80%, 19%) |
| MESH | `#104A88` | rgb(16, 74, 136) | hsl(211, 79%, 30%) |

### B. Commandes utiles

```bash
# Capture d'écran du dashboard
ssh secubox@secubox-round.local "DISPLAY=:0 scrot /tmp/screen.png"
scp secubox@secubox-round.local:/tmp/screen.png .

# Mode simulation rapide
./deploy.sh -h secubox-round.local --sim

# Désactiver le dashboard (maintenance)
ssh secubox@secubox-round.local "sudo systemctl stop secubox-remote-ui"

# Réactiver
ssh secubox@secubox-round.local "sudo systemctl start secubox-remote-ui"
```

---

## Annexe: Commandes rapides

```bash
# === Mode Switching ===
sudo secubox-otg-gadget.sh start      # Normal mode
sudo secubox-otg-gadget.sh tty        # TTY keyboard mode
sudo secubox-otg-gadget.sh auth       # Eye Remote security key
sudo secubox-otg-gadget.sh flash      # Recovery/flash mode
sudo secubox-otg-gadget.sh debug      # Debug export mode
sudo secubox-otg-gadget.sh stop       # Disable gadget
secubox-otg-gadget.sh status          # Show current state

# === TTY Keyboard ===
./secubox-hid-keyboard.sh cmd 'printenv'
./secubox-hid-keyboard.sh type 'hello world'
./secubox-hid-keyboard.sh enter
./secubox-hid-keyboard.sh ctrl-c
./secubox-hid-keyboard.sh queue /run/secubox-cmd-queue

# === Serial Console (from host) ===
screen /dev/ttyACM0 115200
minicom -D /dev/ttyACM0 -b 115200

# === Network Debug ===
ip addr show usb0                     # Gadget side
ip addr show secubox-round            # Host side
ping 10.55.0.1                        # From gadget to host
ping 10.55.0.2                        # From host to gadget

# === Screenshot ===
ssh pi@secubox-round "DISPLAY=:0 scrot /tmp/eye.png"
scp pi@secubox-round:/tmp/eye.png .

# === x64 Live Boot ===
./image/build-live-usb.sh --profile x64-live --eye-remote
qemu-system-x86_64 -m 2G -cdrom secubox-eye-live.iso
```

---

*Documentation mise à jour : 2026-04-20*
*Version : 2.0.0 — Eye Remote Edition*
*Auteur : Gérald Kerma — CyberMind*
