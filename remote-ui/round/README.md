# SecuBox Remote UI — Round Edition

Dashboard kiosk pour **HyperPixel 2.1 Round Touch** (480×480 px) sur **Raspberry Pi Zero W**.

Affichage temps réel des métriques SecuBox via 6 anneaux concentriques représentant les modules système.

---

## Aperçu

```
          ┌─────────────────────┐
          │       MESH          │  ← Anneau extérieur (bleu marine)
          │   ┌───────────┐     │
          │   │   ROOT    │     │  ← Vert foncé
          │   │ ┌───────┐ │     │
          │   │ │ MIND  │ │     │  ← Violet
          │   │ │┌─────┐│ │     │
          │   │ ││BOOT ││ │     │  ← Marron
          │   │ ││┌───┐││ │     │
          │   │ │││WAL│││ │     │  ← Bronze
          │   │ ││├───┤││ │     │
          │   │ │││CPU│││ │     │  ← Centre: % CPU
          │   │ │││78%│││ │     │
          │   │ ││└───┘││ │     │
          │   │ │└─────┘│ │     │
          │   │ └───────┘ │     │
          │   └───────────┘     │
          └─────────────────────┘
              HyperPixel 2.1
                480×480
```

---

## Matériel requis

| Composant | Référence | Notes |
|-----------|-----------|-------|
| Raspberry Pi Zero W | RPi Zero W / Zero 2 W | WiFi intégré requis |
| HyperPixel 2.1 Round | Pimoroni | Écran tactile circulaire 480×480 |
| Carte microSD | 8 Go minimum | Class 10 recommandée |
| Alimentation | 5V 2.5A | Via micro-USB |

---

## Installation rapide

### 1. Flasher la carte SD

```bash
# Télécharger Raspberry Pi OS Lite (32-bit armhf - REQUIS pour Zero W)
wget https://downloads.raspberrypi.com/raspios_lite_armhf/images/raspios_lite_armhf-2024-11-19/2024-11-19-raspios-bookworm-armhf-lite.img.xz

# Flasher et configurer (avec USB OTG pour accès direct)
sudo ./install_zerow.sh \
    -d /dev/mmcblk0 \
    -i 2024-11-19-raspios-bookworm-armhf-lite.img.xz \
    -s "MonWiFi" \
    -p "MotDePasseWiFi" \
    -k ~/.ssh/id_rsa.pub \
    -r  # Active USB OTG (recommandé)
```

> **Important:** Utilisez l'image **32-bit armhf**, pas arm64. Le Zero W est ARMv6.

### 2. Premier démarrage

1. Éjecter la carte SD : `sudo eject /dev/mmcblk0`
2. Insérer dans le RPi Zero W avec l'écran HyperPixel monté
3. **Connecter le câble USB sur le port DATA (celui du milieu)**, pas PWR
4. Attendre ~90 secondes pour le boot initial

### 3. Connexion SSH (via USB OTG)

```bash
# Sur le host, configurer l'interface USB
sudo ip addr add 10.55.0.1/30 dev enxXXXXXXXXXXXX  # Remplacer par le nom réel
sudo ip link set enxXXXXXXXXXXXX up

# Connecter au Zero W (credentials par défaut: pi:raspberry)
ssh pi@10.55.0.2
```

### 4. Premier boot (si WiFi configuré)

- Attendre ~10 min (installation des drivers, redémarrage automatique)
- L'écran HyperPixel s'allume après le redémarrage

### 3. Déployer le dashboard

```bash
# Depuis le dépôt SecuBox-Deb
./deploy.sh -h secubox-round.local \
    --api-url http://192.168.1.1:8000 \
    --api-pass "VotreMotDePasse"
```

---

## Scripts

### `install_zerow.sh`

Prépare et flashe une microSD pour RPi Zero W avec HyperPixel 2.1 Round.

```
Usage: install_zerow.sh [OPTIONS]

Options requises:
  -d, --device DEVICE     Périphérique SD (ex: /dev/sdb, /dev/mmcblk1)
  -i, --image IMAGE       Image Raspberry Pi OS (.img ou .img.xz)
  -s, --ssid SSID         Nom du réseau WiFi
  -p, --psk PSK           Mot de passe WiFi

Options facultatives:
  -h, --hostname NAME     Hostname (défaut: secubox-round)
  -u, --user USER         Utilisateur (défaut: secubox)
  -k, --pubkey FILE       Clé SSH publique à installer
  --no-wifi               Ne pas configurer le WiFi
  -r, --usb-otg           Activer USB OTG (mode gadget Ethernet)
  --help                  Afficher cette aide
```

**Sécurité intégrée :**
- Refuse `/dev/sda`, `/dev/nvme0n1`, `/dev/mmcblk0` (disques système)
- Demande confirmation avant l'effacement

### `deploy.sh`

Déploie/met à jour le dashboard sur un RPi Zero W configuré.

```
Usage: deploy.sh [OPTIONS]

Options requises:
  -h, --host HOST         Adresse IP ou hostname du RPi Zero W

Options facultatives:
  -u, --user USER         Utilisateur SSH (défaut: secubox)
  -p, --port PORT         Port SSH (défaut: 22)
  --api-url URL           URL de l'API SecuBox
  --api-pass PASS         Mot de passe API
  --sim                   Activer le mode simulation
  --no-sim                Désactiver le mode simulation
```

---

## Architecture

```
SecuBox (Armada/x86)              RPi Zero W + HyperPixel
┌─────────────────────┐          ┌─────────────────────┐
│  secubox-system     │          │  nginx:8080         │
│  FastAPI:8000       │◄────────►│  ├── /api/* → proxy │
│  └── /api/v1/system │   WiFi   │  └── /* → dashboard │
│      /metrics       │          │                     │
│      /metrics/alerts│          │  Chromium kiosk     │
│      /metrics/modules          │  └── http://localhost:8080
└─────────────────────┘          └─────────────────────┘
```

### Endpoints API utilisés

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/system/metrics` | Métriques système complètes |
| `GET /api/v1/system/metrics/health` | Health check rapide |
| `GET /api/v1/system/metrics/modules` | État des 6 modules |
| `GET /api/v1/system/metrics/alerts` | Alertes actives |
| `POST /api/v1/auth/login` | Authentification JWT |

### Modules affichés

| Code | Service | Couleur | Description |
|------|---------|---------|-------------|
| AUTH | secubox-auth | `#C04E24` | Authentification / SSO |
| WALL | secubox-crowdsec | `#9A6010` | WAF / IDS |
| BOOT | secubox-hub | `#803018` | Dashboard principal |
| MIND | secubox-ai-insights | `#3D35A0` | IA / Insights |
| ROOT | secubox-system | `#0A5840` | Système |
| MESH | secubox-p2p | `#104A88` | Réseau mesh |

---

## Configuration

### `secubox.conf` — Section `[remote_ui]`

```toml
[remote_ui]
enabled       = true
api_base      = "/api/v1/system"
refresh_ms    = 5000
simulate      = false

[remote_ui.thresholds.cpu]
warn = 70
crit = 85

[remote_ui.thresholds.mem]
warn = 75
crit = 90

[remote_ui.thresholds.disk]
warn = 80
crit = 95

[remote_ui.thresholds.temp]
warn = 65
crit = 75

[remote_ui.thresholds.wifi]
warn = -70
crit = -80
```

### Mode simulation

Pour tester le dashboard sans connexion à l'API SecuBox :

```bash
./deploy.sh -h secubox-round.local --sim
```

---

## systemd Service

Le kiosk est géré par `secubox-remote-ui.service` :

```ini
[Service]
Type=simple
User=secubox
Environment=DISPLAY=:0
ExecStart=/usr/bin/chromium-browser --kiosk ...
Restart=always
RestartSec=10
MemoryMax=256M
CPUQuota=80%
```

---

## Dépannage

### L'écran reste noir

1. **Vérifier que le KMS overlay est actif** (vc4-kms-v3d + vc4-kms-dpi-hyperpixel2r) :
   ```bash
   ssh pi@10.55.0.2
   grep -E "vc4|hyperpixel|display_auto" /boot/firmware/config.txt
   # Doit afficher:
   # dtoverlay=vc4-kms-v3d
   # dtoverlay=vc4-kms-dpi-hyperpixel2r
   # display_auto_detect=0
   ```

2. Vérifier le DRM/KMS :
   ```bash
   ls -la /dev/dri/
   # Doit afficher: card0, renderD128
   dmesg | grep -iE "drm|vc4|dpi"
   # Doit montrer: "bound 20208000.dpi" et "vc4drmfb frame buffer"
   ```

3. Vérifier le framebuffer :
   ```bash
   ls -la /dev/fb*
   # Doit afficher: /dev/fb0
   fbset -fb /dev/fb0
   # Doit montrer: geometry 480 480
   ```

4. Si non-KMS (fallback), vérifier l'init :
   ```bash
   systemctl status hyperpixel2r-init
   # Doit être "inactive (dead)" avec status=0/SUCCESS
   ```

### SSH via USB OTG ne fonctionne pas

1. Vérifier l'interface USB côté host :
   ```bash
   ip link | grep enx
   # Doit montrer une interface enxXXXXXX UP
   ```

2. Configurer l'IP sur le host :
   ```bash
   sudo ip addr add 10.55.0.1/30 dev enxXXXXXXXX
   sudo ip link set enxXXXXXXXX up
   ```

3. Si l'interface n'apparaît pas, vérifier le câble (doit être DATA, pas PWR)

### Chromium ne se lance pas

```bash
# Vérifier le service
systemctl status secubox-remote-ui

# Logs détaillés
journalctl -u secubox-remote-ui -f
```

### Dashboard affiche "Erreur connexion API"

1. Vérifier la connectivité réseau :
   ```bash
   ping 192.168.1.1  # IP de la SecuBox
   ```

2. Vérifier l'URL API dans nginx :
   ```bash
   cat /etc/nginx/sites-enabled/secubox-round | grep proxy_pass
   ```

3. Redéployer avec la bonne URL :
   ```bash
   ./deploy.sh -h secubox-round.local --api-url http://192.168.1.1:8000
   ```

### Rafraîchir le dashboard manuellement

```bash
ssh secubox@secubox-round.local
systemctl restart secubox-remote-ui
```

---

## Ressources

- [HyperPixel 2.1 Round — Pimoroni](https://shop.pimoroni.com/products/hyperpixel-2-1-round)
- [Driver GitHub](https://github.com/pimoroni/hyperpixel2r)
- [SecuBox Documentation](https://docs.secubox.in)

---

## Licence

Proprietary — CyberMind / ANSSI CSPN candidate

Author: Gérald Kerma <gandalf@gk2.net>
