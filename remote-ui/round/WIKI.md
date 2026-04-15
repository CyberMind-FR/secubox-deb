# SecuBox Remote UI — Wiki Technique

Documentation technique complète pour le déploiement et la maintenance du dashboard HyperPixel 2.1 Round.

---

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Prérequis matériel](#prérequis-matériel)
3. [Installation détaillée](#installation-détaillée)
4. [Architecture technique](#architecture-technique)
5. [API Backend](#api-backend)
6. [Frontend Dashboard](#frontend-dashboard)
7. [Configuration avancée](#configuration-avancée)
8. [Sécurité](#sécurité)
9. [Maintenance](#maintenance)
10. [Dépannage avancé](#dépannage-avancé)

---

## Vue d'ensemble

Le **SecuBox Remote UI — Round Edition** est un dashboard physique déporté qui affiche en temps réel l'état d'une appliance SecuBox. Il utilise un écran circulaire HyperPixel 2.1 Round (480×480 pixels) monté sur un Raspberry Pi Zero W.

### Cas d'usage

- **Rack datacenter** : Affichage d'état visible sans connexion à l'interface web
- **NOC** : Surveillance visuelle instantanée des modules de sécurité
- **Showroom** : Démonstration des capacités SecuBox
- **Home lab** : Monitoring élégant pour installation personnelle

### Caractéristiques

| Fonctionnalité | Détail |
|----------------|--------|
| Résolution | 480×480 pixels (circulaire) |
| Rafraîchissement | 5 secondes (configurable) |
| Protocole | REST API + JWT |
| Consommation | < 5W (RPi Zero W + écran) |
| Mode hors-ligne | Simulation disponible |

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

*Documentation mise à jour : 2026-04-15*
*Version : 1.0.0*
*Auteur : Gérald Kerma — CyberMind*
