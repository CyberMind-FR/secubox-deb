# SecuBox Eye Remote — Round Edition

**Remote control dashboard** for **HyperPixel 2.1 Round Touch** (480×480 px) on **Raspberry Pi Zero W** or **x64/amd64 live systems**.

More than a simple status display — the Eye Remote transforms into a **powerful debugging and security tool** with multiple USB gadget modes.

---

## Overview

```
          ┌─────────────────────┐
          │   ● SECUBOX EYE     │  ← Mode indicator (OTG/WiFi/SIM)
          │   ┌───────────────┐ │
          │  ┌┤  ╔═══════════╗├┐│
          │  │└──╢  14:32:07 ╟┘││  ← Time/Status center
          │  │   ╢ NOMINAL   ╟ ││
          │  │┌──╢ secubox-zr╟─┐│
          │  ││  ╚═══════════╝ ││
          │  ││ [AUTH]  [WALL] ││  ← Module pods (6)
          │  │└─────────────────┘│
          │  └──[TTY]  [AUTH]───┘│  ← Mode selector (touch)
          │        480×480       │
          └─────────────────────┘
              HyperPixel 2.1
           or x64 touchscreen
```

### Key Features

| Feature | Description |
|---------|-------------|
| **5 USB Modes** | Normal, Flash, Debug, TTY, Auth |
| **Eye Remote** | Security key with QR auth display |
| **U-Boot Access** | Virtual keyboard for bootloader |
| **Live Flash** | Bootable USB recovery mode |
| **x64 Support** | Live boot on any touchscreen |

---

## Matériel requis

| Composant | Référence | Notes |
|-----------|-----------|-------|
| Raspberry Pi Zero W | RPi Zero W / Zero 2 W | WiFi intégré requis |
| HyperPixel 2.1 Round | Pimoroni | Écran tactile circulaire 480×480 |
| Carte microSD | 8 Go minimum | Class 10 recommandée |
| Alimentation | 5V 2.5A | Via micro-USB |
| Câble USB | Data-capable | Must be DATA port, not PWR |

---

## USB Gadget Modes

The Eye Remote supports **5 operational modes** via USB OTG composite gadget:

```
┌────────────┬────────────┬──────────────────────────────────────────┐
│ Command    │ Mode       │ Functions                                │
├────────────┼────────────┼──────────────────────────────────────────┤
│ start      │ Normal     │ Network (ECM) + Serial                   │
│ flash      │ Recovery   │ Bootable USB + Serial (U-Boot access)    │
│ debug      │ Debug      │ Network + Storage + Serial               │
│ tty        │ Keyboard   │ Virtual keyboard + Serial (automation)   │
│ auth       │ Eye Remote │ FIDO/U2F HID + QR display (security key) │
└────────────┴────────────┴──────────────────────────────────────────┘
```

### Mode: Normal (default)
```
┌────────────────────────────────────┐
│         ● SECUBOX EYE             │
│           OTG MODE                 │
│                                    │
│         ╔═══════════╗              │
│         ║  14:32:07 ║              │
│         ║ NOMINAL   ║              │
│         ║ up 24h12  ║              │
│         ╚═══════════╝              │
│                                    │
│   [AUTH]  [WALL]  [BOOT]          │
│   [MIND]  [ROOT]  [MESH]          │
│                                    │
│   ═══════════════════════          │ ← 6 status rings
│     CPU 23% │ MEM 41%              │
└────────────────────────────────────┘
```
- **ECM/RNDIS** network: `10.55.0.0/30`
- **CDC-ACM** serial: `/dev/ttyGS0` @ 115200

### Mode: Flash (Recovery)
```
┌────────────────────────────────────┐
│         ● FLASH MODE              │
│      ████████████████ 100%         │ ← Progress bar
│                                    │
│         ╔═══════════╗              │
│         ║  READY    ║              │
│         ║ Boot from ║              │
│         ║   USB     ║              │
│         ╚═══════════╝              │
│                                    │
│   💾 secubox-flash.img             │
│      256MB bootable                │
│                                    │
│   [REBOOT TARGET]  [CANCEL]        │
└────────────────────────────────────┘
```
- **Mass Storage**: Bootable recovery image
- **Serial**: U-Boot console access
- Use case: Flash/recover bricked SecuBox

### Mode: Debug
```
┌────────────────────────────────────┐
│         ● DEBUG MODE              │
│                                    │
│    ┌──────────────────────────┐    │
│    │ Network: 10.55.0.2       │    │
│    │ Serial:  /dev/ttyACM0    │    │
│    │ Storage: secubox-debug   │    │
│    └──────────────────────────┘    │
│                                    │
│    📁 /var/log/secubox/            │
│    📁 /etc/secubox/                │
│    📁 /run/secubox/                │
│                                    │
│   [VIEW LOGS]  [EXPORT]  [STOP]    │
└────────────────────────────────────┘
```
- **ECM** network + **Mass Storage** (R/W debug partition)
- Use case: Extract logs, inspect config

### Mode: TTY (Virtual Keyboard)
```
┌────────────────────────────────────┐
│         ● TTY MODE                │
│       Virtual HID Keyboard         │
│                                    │
│    ┌──────────────────────────┐    │
│    │ > printenv               │    │ ← Command queue
│    │ > setenv bootcmd run usb │    │
│    │ > boot                   │    │
│    └──────────────────────────┘    │
│                                    │
│    ⌨️  Sending keystroke...        │
│       [████████░░░░] 67%           │
│                                    │
│   [PAUSE]  [CLEAR]  [+CMD]         │
└────────────────────────────────────┘
```
- **HID Keyboard**: USB scan codes → target U-Boot
- **Serial**: Capture output
- Use case: Automated U-Boot commands, rescue boot

### Mode: Auth (Eye Remote Security Key)
```
┌────────────────────────────────────┐
│         ● EYE REMOTE              │
│       FIDO2/U2F Security Key       │
│                                    │
│         ┌─────────────┐            │
│         │ ▄▄▄ ▀▀▀ ▄▄▄│            │
│         │ █▀█ ▄▄▄ █▀█│            │ ← QR Code
│         │ ▀▀▀ █▀█ ▀▀▀│            │
│         │ ▄▄▄ ▀▀▀ ▄▄▄│            │
│         └─────────────┘            │
│                                    │
│    🔐 Touch to authenticate        │
│       Challenge: a3f7...           │
│                                    │
│   [APPROVE]     [DENY]             │
└────────────────────────────────────┘
```
- **FIDO2/U2F HID**: Hardware security key
- **QR Display**: One-time challenge codes
- Use case: SSH auth, WebAuthn, 2FA

---

## x64/amd64 Live Boot Support

The Eye Remote dashboard also runs on **standard x64 systems** for:

- **Live USB boot** environments
- **SecuBox staging** and initial setup
- **Touchscreen kiosks** (any resolution, scales to fit)
- **VM testing** during development

```bash
# Build live USB with Eye Remote
./image/build-live-usb.sh --profile x64-live --eye-remote

# Run in VM for testing
qemu-system-x86_64 -m 2G -cdrom secubox-live.iso \
    -device virtio-vga -display gtk
```

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

### `secubox-otg-gadget.sh`

USB OTG composite gadget controller for all modes.

```bash
# Start normal mode (ECM + Serial)
sudo ./secubox-otg-gadget.sh start

# Switch to TTY mode (HID keyboard)
sudo ./secubox-otg-gadget.sh tty

# Switch to Auth mode (Eye Remote)
sudo ./secubox-otg-gadget.sh auth

# Flash mode (bootable recovery)
sudo ./secubox-otg-gadget.sh flash

# Debug mode (network + storage)
sudo ./secubox-otg-gadget.sh debug

# Check status
./secubox-otg-gadget.sh status
```

### `secubox-hid-keyboard.sh`

Virtual keyboard for TTY mode automation.

```bash
# Send a command (type + Enter)
./secubox-hid-keyboard.sh cmd 'printenv'

# Type without Enter
./secubox-hid-keyboard.sh type 'setenv bootcmd run bootusb'

# Send special keys
./secubox-hid-keyboard.sh enter
./secubox-hid-keyboard.sh ctrl-c

# Process command queue file
./secubox-hid-keyboard.sh queue /run/secubox-cmd-queue

# Interactive mode (stdin)
echo -e "printenv\nboot" | ./secubox-hid-keyboard.sh interactive
```

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

### Eye Remote as USB Gadget

```
┌─────────────────────────────────────────────────────────────────────┐
│                     SecuBox Target (Armada/x86)                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ USB Host Port                                                │    │
│  │   ├── ECM/RNDIS Network ────────► 10.55.0.1 (usb0)          │    │
│  │   ├── CDC-ACM Serial ───────────► /dev/ttyACM0              │    │
│  │   ├── Mass Storage ─────────────► /dev/sda (debug/flash)    │    │
│  │   └── HID Keyboard ─────────────► Virtual input device      │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              ▲ USB OTG                               │
└──────────────────────────────┼──────────────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │   USB Data Cable    │
                    │   (NOT power-only)  │
                    └──────────┬──────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────┐
│                              ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ configfs USB Gadget (libcomposite)                          │    │
│  │   ├── ECM function ──────► usb0 (10.55.0.2)                 │    │
│  │   ├── ACM function ──────► /dev/ttyGS0 (console)            │    │
│  │   ├── Mass Storage ──────► /var/lib/secubox-*.img           │    │
│  │   └── HID function ──────► /dev/hidg0 (keyboard)            │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│                    RPi Zero W + HyperPixel 2.1 Round                 │
│                         "SecuBox Eye Remote"                         │
└─────────────────────────────────────────────────────────────────────┘
```

### Communication Flow

```
SecuBox (Armada/x86)              RPi Zero W + HyperPixel
┌─────────────────────┐          ┌─────────────────────┐
│  secubox-system     │          │  nginx:8080         │
│  FastAPI:8000       │◄────────►│  ├── /api/* → proxy │
│  └── /api/v1/system │ USB OTG  │  └── /* → dashboard │
│      /metrics       │ 10.55.0  │                     │
│      /metrics/alerts│◄─WiFi───►│  Chromium kiosk     │
│      /metrics/modules│ backup  │  └── localhost:8080 │
│                     │          │                     │
│  U-Boot console     │◄────────►│  HID Keyboard       │
│  /dev/ttyACM0       │ Serial   │  secubox-hid-kbd.sh │
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

## systemd Services

### Framebuffer Dashboard (v1.11.0+)

For Pi Zero W (ARMv6, no NEON), the dashboard runs via framebuffer:

```ini
# /etc/systemd/system/secubox-fb-dashboard.service
[Unit]
Description=SecuBox Eye Remote Framebuffer Dashboard
After=hyperpixel2r-init.service
Wants=hyperpixel2r-init.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/local/bin/fb_dashboard.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Dependencies:**
- `pigpiod.service` — GPIO daemon for LCD init
- `hyperpixel2r-init.service` — ST7701S LCD controller init

### Chromium Kiosk (ARM64/x64 only)

For systems with NEON support (Pi Zero 2 W, x64):

```ini
# /etc/systemd/system/secubox-remote-ui.service
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

## FAQ / Troubleshooting

### Why doesn't Chromium work on Pi Zero W?

**Error:** `The hardware on this system lacks support for NEON SIMD extensions`

**Cause:** Pi Zero W uses an ARMv6 CPU which lacks NEON SIMD instructions. Chromium on Debian Bookworm requires NEON.

**Solution:** Use the framebuffer dashboard (`fb_dashboard.py`) which renders directly to `/dev/fb0` using Python PIL. This is enabled by default in v1.11.0+.

### Display stays black (no content)

1. **Check overlay name** — Must be `hyperpixel2r` (not `hyperpixel4`):
   ```bash
   grep dtoverlay /boot/firmware/config.txt
   # Should show: dtoverlay=hyperpixel2r
   ```

2. **Check pigpiod is running** — Required for LCD initialization:
   ```bash
   systemctl status pigpiod
   # Should be: active (running)
   ```

3. **Check hyperpixel2r-init** — LCD controller initialization:
   ```bash
   systemctl status hyperpixel2r-init
   # Should be: inactive (dead) with Result: success
   ```

4. **Check framebuffer dashboard** — Rendering service:
   ```bash
   systemctl status secubox-fb-dashboard
   # Should be: active (running)
   ```

### Service dependency order

The services must start in this order:
```
pigpiod → hyperpixel2r-init → secubox-fb-dashboard
```

If the display doesn't work after reboot, check that all three services succeeded:
```bash
systemctl status pigpiod hyperpixel2r-init secubox-fb-dashboard --no-pager
```

### "GPIO not allocated" error

**Cause:** Using RPi.GPIO (which depends on lgpio) when DPI overlay is active. The kernel claims GPIO pins for DPI output.

**Solution:** Use pigpio instead of RPi.GPIO. The init script in v1.10.0+ uses pigpio which works correctly via the pigpiod daemon.

### Display shows colored stripes but no dashboard

**Cause:** Framebuffer is initialized but no application is rendering to it.

**Solution:** Ensure the dashboard service is enabled:
```bash
sudo systemctl enable --now secubox-fb-dashboard
```

### How to test framebuffer manually

```bash
# Draw random noise to confirm framebuffer works
cat /dev/urandom > /dev/fb0

# Run dashboard manually
python3 /usr/local/bin/fb_dashboard.py
```

### Which config.txt settings are required?

Minimum required for HyperPixel 2.1 Round (v1.11.0):
```
dtoverlay=hyperpixel2r
enable_dpi_lcd=1
display_default_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 55 480 0 15 60 15 0 0 0 60 0 19200000 6
framebuffer_width=480
framebuffer_height=480
dtparam=i2c_arm=on
dtparam=spi=on
dtoverlay=dwc2
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
