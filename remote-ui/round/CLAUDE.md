# CLAUDE.md — SecuBox Remote UI · Round Edition
# CyberMind-FR/secubox-deb · remote-ui/round/
# Version : 2.0 · Avril 2026

> Ce fichier est lu automatiquement par Claude Code à chaque session.
> Il contient le contexte complet, les conventions, les mockups ASCII
> et les règles de génération pour le module Remote UI Round.

---

## 1. IDENTITÉ DU MODULE

```
Module   : remote-ui/round
Fonction : Dashboard kiosk temps réel sur HyperPixel 2.1 Round Touch (480×480)
Matériel : RPi Zero W (ARMv6 armhf) connecté à SecuBox-Deb via OTG ou WiFi
Fichier  : remote-ui/round/index.html  (autonome, zero CDN, ~124 KB)
Transport: USB OTG composé (RNDIS/CDC-ECM prioritaire) + WiFi WPA2 (fallback)
Auth     : JWT HS256, scope metrics:read, renouvellement automatique 30s avant exp
Brand    : SecuBox · CyberMind (jamais "CyberMind Produits SASU")
```

---

## 2. STACK TECHNIQUE

### Backend (SecuBox-Deb, déjà implémenté)

```
secubox/
  api/v1/routers/system.py      GET /api/v1/system/metrics
                                 GET /api/v1/system/modules
                                 GET /api/v1/system/alerts
                                 POST /api/v1/remote-ui/connected
                                 GET /api/v1/remote-ui/status
  core/metrics.py               Collecte async sans psutil (stdlib pure)
  core/alerts.py                AlertsEngine, seuils depuis secubox.conf
  core/remote_ui.py             RemoteUIManager (état transport OTG/WiFi)
  models/system.py              Pydantic v2 : SystemMetricsResponse etc.
```

### Réponse JSON attendue — GET /api/v1/system/metrics

```json
{
  "cpu_percent":     23.5,
  "mem_percent":     41.2,
  "disk_percent":    28.7,
  "wifi_rssi":       -62,
  "load_avg_1":      0.18,
  "cpu_temp":        44.2,
  "uptime_seconds":  86400,
  "hostname":        "secubox-zero",
  "secubox_version": "2.0.0",
  "modules_active":  ["AUTH","WALL","BOOT","MIND","ROOT","MESH"]
}
```

### Frontend (remote-ui/round/index.html)

```
HTML5 + Canvas API + CSS3
Zéro framework, zéro CDN, zéro dépendance externe
Icônes PNG officiels SecuBox embarqués en base64 (assets/icons/)
Mode simulation intégré (CFG.SIMULATE=true) si API absente
```

---

## 3. TABLE MODULES → MÉTRIQUES → ANNEAUX

```
┌────────┬──────────┬─────────┬──────────┬───────────────────────────┐
│ Module │ Couleur  │Métrique │ Anneau r │ Icône PNG officiel        │
├────────┼──────────┼─────────┼──────────┼───────────────────────────┤
│ AUTH   │ #C04E24  │ CPU %   │ r = 214  │ assets/icons/auth-22.png  │
│ WALL   │ #9A6010  │ MEM %   │ r = 201  │ assets/icons/wall-22.png  │
│ BOOT   │ #803018  │ DISK %  │ r = 188  │ assets/icons/boot-22.png  │
│ MIND   │ #3D35A0  │ LOAD ×  │ r = 175  │ assets/icons/mind-22.png  │
│ ROOT   │ #0A5840  │ TEMP °C │ r = 162  │ assets/icons/root-22.png  │
│ MESH   │ #104A88  │ WiFi dBm│ r = 149  │ assets/icons/mesh-22.png  │
└────────┴──────────┴─────────┴──────────┴───────────────────────────┘

Sémantique : AUTH surveille le CPU (charge auth = CPU-intensif)
             WALL surveille la MEM (filtrage réseau = RAM-intensif)
             BOOT surveille le DISK (intégrité boot = état stockage)
             MIND surveille le LOAD (supervision = charge générale)
             ROOT surveille la TEMP (accès root = chauffe système)
             MESH surveille le WiFi (réseau maillé = qualité lien)
```

---

## 4. MOCKUP ASCII — DASHBOARD 480×480

```
╔══════════════════════════════════════╗
║         ● SECUBOX ROUND             ║  ← badge transport (OTG/WiFi/SIM)
║                                      ║
║         ┌────────────────┐           ║
║     [ROOT]              [WALL]       ║  ← pods gauche/droite haut
║    TEMP°C  ●━━━━━━━━━●  MEM%        ║
║           ┌──────────┐               ║
║           │ 14:32:07 │               ║  ← horloge centrale
║           │mer 15 avr│               ║
║  [MIND]   │secubox-zr│  [BOOT]       ║
║  LOAD×    │ up 24h00 │  DISK%       ║
║           └──────────┘               ║
║     [AUTH]             [MESH]        ║  ← pods bas (AUTH haut centre)
║     CPU%               WiFidBm      ║
║                                      ║
║      ═══════════════════════         ║  ← 6 anneaux concentriques
║    AUTH WALL BOOT MIND ROOT MESH     ║    (Canvas, dessinés derrière)
║                                      ║
║         ● NOMINAL                   ║  ← barre statut
║    TEMP [████░░░░░░░░] 44°C         ║  ← barre température
╚══════════════════════════════════════╝
```

---

## 5. MOCKUP ASCII — TRANSPORT MANAGER

```
Démarrage
    │
    ▼
┌──────────────────────────────────────┐
│  TM.probe()                          │
│  1. fetch http://10.55.0.1:8000/     │
│     /api/v1/health  timeout=2s       │
│     OK → active="OTG" ──────────┐   │
│     KO → otgFails++             │   │
│  2. fetch http://secubox.local:8000/ │
│     timeout=3s                  │   │
│     OK → active="WiFi" ─────────┤   │
│     KO → active="SIM"           │   │
└──────────────────────────────────┘   │
         ▼                             │
    active = OTG / WiFi / SIM ◄────────┘

En cours d'exécution (toutes les 30s) :
  Si OTG KO 3× consécutifs → basculer WiFi
  Si OTG redevient OK → rebascule OTG silencieusement

Badge transport :
  "● OTG"   couleur ROOT #0A5840
  "● WiFi"  couleur MESH #104A88
  "○ SIM"   couleur gris  #3a3a3a
```

---

## 6. ARBORESCENCE COMPLÈTE — LIVRABLES DE CETTE SESSION

### Fichiers produits et livrés (prêts à committer)

```
CyberMind-FR/secubox-deb/
│
├── remote-ui/
│   └── round/
│       │
│       ├── index.html                        [124 KB] ★ PRINCIPAL
│       │   ├── <style>
│       │   │   └── fond #080808, monospace, 480×480 circle clip
│       │   ├── <body> #screen
│       │   │   ├── #ring-canvas (Canvas 480×480)
│       │   │   │   └── 6 arcs progressifs AUTH/WALL/BOOT/MIND/ROOT/MESH
│       │   │   ├── #center
│       │   │   │   ├── #time          HH:MM:SS 1Hz
│       │   │   │   ├── #date          jj mmm aaaa FR
│       │   │   │   ├── #hostname      depuis API ou fallback
│       │   │   │   └── #uptime        up XXhXX
│       │   │   ├── #transport         ● OTG | ● WiFi | ○ SIM
│       │   │   ├── .pod#pod-AUTH      img 22px + val + unit + name
│       │   │   ├── .pod#pod-WALL      (5 autres idem)
│       │   │   ├── .pod#pod-BOOT
│       │   │   ├── .pod#pod-MIND
│       │   │   ├── .pod#pod-ROOT
│       │   │   ├── .pod#pod-MESH
│       │   │   ├── #status            ● NOMINAL | ▲ MODULE val
│       │   │   ├── #temp-row          barre TEMP ROOT couleur dynamique
│       │   │   └── #auth-overlay      splash JWT boot → hidden
│       │   └── <script>
│       │       ├── ICONS{}            data URIs PNG base64
│       │       │   └── AUTH/WALL/BOOT/MIND/ROOT/MESH × {22,48,96}
│       │       ├── CFG{}
│       │       │   ├── API_OTG_BASE   'http://10.55.0.1:8000'
│       │       │   ├── API_WIFI_BASE  'http://secubox.local:8000'
│       │       │   ├── ENDPOINT_METRICS/LOGIN/MODULES/ALERTS
│       │       │   ├── LOGIN_USER/PASS (patcher via deploy.sh)
│       │       │   ├── REFRESH_INTERVAL        2000 ms
│       │       │   ├── JWT_RENEW_BEFORE_MS     30000
│       │       │   ├── OTG_FAILOVER_THRESHOLD  3
│       │       │   ├── PROBE_INTERVAL          30000 ms
│       │       │   └── SIMULATE                true (défaut)
│       │       ├── TM{}  TransportManager
│       │       │   ├── .active        'OTG'|'WiFi'|'SIM'
│       │       │   ├── .probe()       test OTG → WiFi → SIM
│       │       │   ├── .login()       POST /auth/token JWT
│       │       │   ├── .ensureJwt()   renouvellement auto
│       │       │   └── .fetchMetrics() GET /system/metrics
│       │       ├── SIM{}              dérive réaliste cpu/mem/disk/net/load/temp
│       │       ├── RINGS[]            6 entrées {color,r,w,fn}
│       │       ├── drawRings(s)       Canvas clearRect + 6 arcs + dot tête
│       │       ├── updateDOM(s)       6 pods + temp + uptime + status + badge
│       │       ├── updateClock()      setInterval 1000ms
│       │       ├── podTap(mod)        opacity flash 180ms
│       │       └── init()             probe → login → tick → setInterval
│       │
│       ├── assets/
│       │   ├── icons/                          ★ 24 PNG OFFICIELS
│       │   │   ├── auth-22.png   [1.2 KB]  cible hexagonale #C04E24
│       │   │   ├── auth-48.png   [3.6 KB]
│       │   │   ├── auth-96.png   [9.3 KB]
│       │   │   ├── auth-128.png  [15 KB]
│       │   │   ├── wall-22.png   [1.2 KB]  mur de briques #9A6010
│       │   │   ├── wall-48.png   [3.6 KB]
│       │   │   ├── wall-96.png   [9.8 KB]
│       │   │   ├── wall-128.png  [17 KB]
│       │   │   ├── boot-22.png   [1.2 KB]  fusée #803018
│       │   │   ├── boot-48.png   [3.6 KB]
│       │   │   ├── boot-96.png   [11 KB]
│       │   │   ├── boot-128.png  [17 KB]
│       │   │   ├── mind-22.png   [920 B]   robot IA #3D35A0
│       │   │   ├── mind-48.png   [2.5 KB]
│       │   │   ├── mind-96.png   [6.5 KB]
│       │   │   ├── mind-128.png  [10 KB]
│       │   │   ├── root-22.png   [708 B]   terminal $>_ #0A5840
│       │   │   ├── root-48.png   [2.0 KB]
│       │   │   ├── root-96.png   [5.4 KB]
│       │   │   ├── root-128.png  [8.4 KB]
│       │   │   ├── mesh-22.png   [1.2 KB]  engrenage réseau #104A88
│       │   │   ├── mesh-48.png   [3.6 KB]
│       │   │   ├── mesh-96.png   [9.8 KB]
│       │   │   └── mesh-128.png  [16 KB]
│       │   │   SOURCE : extraits de SecuBox_Charte_Light_3_.html
│       │   │   TRAITEMENT : JPEG 110px → PNG RGBA, fond noir supprimé
│       │   │   (threshold R/G/B < 28 → alpha=0, near-black antialiasing)
│       │   │
│       │   ├── svg/                    ← sources vectorielles (à créer)
│       │   │   ├── auth.svg
│       │   │   ├── wall.svg
│       │   │   ├── boot.svg
│       │   │   ├── mind.svg
│       │   │   ├── root.svg
│       │   │   └── mesh.svg
│       │   └── generate_icons.sh       ← cairosvg batch 22/48/96/128
│       │
│       ├── install_zerow.sh            [207 lignes] ★
│       │   ├── OPTIONS : -d -i -s -p -h -u -k -r --kiosk --no-wifi
│       │   ├── Sécurité : refuse /dev/sda /dev/nvme0n1 /dev/mmcblk0
│       │   ├── Flash .img et .img.xz (xzcat pipe)
│       │   ├── Détection partitions (mmcblk/sdX)
│       │   ├── Boot/root mount avec trap cleanup
│       │   ├── SSH, WiFi WPA2 country=FR, hostname, clé SSH pub
│       │   ├── dtoverlay=hyperpixel2r + i2c_arm + spi → config.txt
│       │   ├── rc.local firstrun → installe pimoroni/hyperpixel2r
│       │   │   (attend réseau 60s, flag /etc/.hyperpixel_installed)
│       │   └── --kiosk : kiosk.service systemd Chromium :8080
│       │
│       ├── deploy.sh                   [scripts SSH]
│       │   ├── OPTIONS : -h -u -p --api-url --api-pass --sim/--no-sim
│       │   ├── Copie index.html → /var/www/secubox-round/
│       │   ├── Patch CFG.SIMULATE, API_OTG_BASE, LOGIN_PASS
│       │   ├── nginx reload
│       │   └── curl test HTTP 200
│       │
│       ├── secubox-otg-gadget.sh       ← configfs libcomposite
│       │   ├── start : crée gadget ECM + ACM via /sys/kernel/config
│       │   ├── stop  : détruit le gadget proprement
│       │   ├── status: affiche état UDC + fonctions actives
│       │   └── MAC ECM déterministe depuis /proc/cpuinfo Serial
│       │
│       ├── secubox-otg-host-up.sh      ← udev hook SecuBox host
│       │   ├── ip addr add 10.55.0.1/30 dev secubox-round
│       │   ├── ip link set secubox-round up
│       │   └── POST /api/v1/remote-ui/connected (token interne)
│       │
│       └── secubox-remote-ui.service   ← systemd kiosk Zero W
│           └── nginx + Chromium kiosk après graphical.target
│
├── secubox/
│   ├── api/
│   │   └── v1/
│   │       └── routers/
│   │           └── system.py           ← router FastAPI
│   │               ├── GET  /api/v1/system/metrics
│   │               ├── GET  /api/v1/system/modules
│   │               ├── GET  /api/v1/system/alerts
│   │               ├── POST /api/v1/remote-ui/connected
│   │               └── GET  /api/v1/remote-ui/status
│   │
│   ├── core/
│   │   ├── metrics.py                  ← collecte async /proc stdlib
│   │   │   ├── cpu_percent   delta /proc/stat 200ms
│   │   │   ├── mem_percent   /proc/meminfo MemAvailable/MemTotal
│   │   │   ├── disk_percent  os.statvfs('/')
│   │   │   ├── wifi_rssi     /proc/net/wireless → iwconfig fallback
│   │   │   ├── cpu_temp      /sys/class/thermal/tz0/temp ÷ 1000
│   │   │   ├── load_avg_1    os.getloadavg()[0]
│   │   │   ├── uptime_secs   /proc/uptime champ 1
│   │   │   └── Cache TTL 1s (asyncio)
│   │   │
│   │   ├── alerts.py                   ← AlertsEngine
│   │   │   ├── Seuils depuis secubox.conf [remote_ui]
│   │   │   └── Niveaux : nominal | warn | crit
│   │   │
│   │   └── remote_ui.py                ← RemoteUIManager
│   │       ├── État transport OTG/WiFi/absent
│   │       ├── Détecte interface secubox-round (udev/polling)
│   │       └── transport_info() pour logs SecuBox
│   │
│   └── models/
│       └── system.py                   ← Pydantic v2
│           ├── SystemMetricsResponse
│           ├── ModulesStatusResponse
│           ├── AlertItem
│           ├── AlertsResponse
│           └── RemoteUIStatusResponse
│
├── etc/
│   └── udev/
│       └── rules.d/
│           └── 90-secubox-otg.rules    ← détecte Zero W, → secubox-round
│
└── CLAUDE.md                           ← ce fichier [~350 lignes]
```

### Fichiers système Zero W (générés par install_zerow.sh)

```
/boot/firmware/
├── config.txt          += dtoverlay=dwc2, hyperpixel2r, i2c_arm, spi
└── wpa_supplicant.conf    country=FR, réseau WPA2

/etc/
├── hostname
├── hosts               (hostname patché)
├── modules             += dwc2, libcomposite
├── modprobe.d/
│   └── secubox-otg.conf   options dwc2 dr_mode=peripheral
├── network/interfaces.d/
│   └── usb0               10.55.0.2/30 static
├── systemd/system/
│   ├── secubox-otg-gadget.service
│   ├── secubox-serial-console.service  ttyGS0 115200
│   └── kiosk.service    (si --kiosk)
└── rc.local             firstrun pimoroni/hyperpixel2r

/usr/local/sbin/
└── secubox-otg-gadget.sh

/var/www/secubox-round/
└── index.html

/etc/nginx/sites-available/
└── secubox-round        port 8080, proxy /api/ → :8000

/home/pi/.ssh/
└── authorized_keys      (si -k PUBKEY)
```

### Résumé des tailles

```
index.html (v2, icônes embarquées)   124 KB
install_zerow.sh                     207 lignes
deploy.sh                             ~80 lignes
secubox_round_dashboard.html (v1)    ~90 KB
CLAUDE.md                            ~350 lignes
PNG icons × 24                       ~164 KB total
  22px × 6  :   ~6 KB
  48px × 6  :  ~20 KB
  96px × 6  :  ~52 KB
  128px × 6 :  ~86 KB
```

---

## 7. BLOC CFG — PARAMÈTRES CONFIGURABLES

```javascript
// Dans index.html <script>, en tête, modifiable par deploy.sh
const CFG = {
  // Transport OTG (prioritaire)
  API_OTG_BASE:  'http://10.55.0.1:8000',

  // Transport WiFi (fallback)
  API_WIFI_BASE: 'http://secubox.local:8000',

  // Endpoints API
  ENDPOINT_METRICS: '/api/v1/system/metrics',
  ENDPOINT_LOGIN:   '/api/v1/auth/token',
  ENDPOINT_MODULES: '/api/v1/system/modules',
  ENDPOINT_ALERTS:  '/api/v1/system/alerts',

  // Credentials dashboard (scope metrics:read)
  LOGIN_USER: 'dashboard',
  LOGIN_PASS: 'secubox-round',       // ← patcher via deploy.sh --api-pass

  // Timing
  REFRESH_INTERVAL:       2000,      // ms polling métriques
  JWT_RENEW_BEFORE_MS:   30000,      // renouveler 30s avant expiry
  OTG_FAILOVER_THRESHOLD:    3,      // timeouts OTG avant bascule WiFi
  PROBE_INTERVAL:        30000,      // ms re-probe transport

  // Mode dégradé : true = simulation si API absente
  SIMULATE: true,
};
```

---

## 8. SEUILS D'ALERTE (depuis secubox.conf [remote_ui])

```toml
[remote_ui]
enabled          = true
transport_mode   = "auto"          # "otg" | "wifi" | "auto"
otg_network      = "10.55.0.0/30"
otg_host_ip      = "10.55.0.1"
otg_peer_ip      = "10.55.0.2"
wifi_host        = ""              # IP SecuBox si WiFi seul
refresh_interval_ms        = 2000
otg_probe_interval_s       = 30
otg_failover_threshold     = 3
serial_console_enabled     = true
serial_baud                = 115200

# Seuils alertes
cpu_warn  = 70   ; cpu_crit  = 85    # → AUTH rouge
mem_warn  = 75   ; mem_crit  = 90    # → WALL rouge
disk_warn = 80   ; disk_crit = 95    # → BOOT rouge
temp_warn = 65   ; temp_crit = 75    # → ROOT rouge

# CORS origines autorisées
allowed_origins = [
  "http://10.55.0.2:8080",
  "http://localhost:8080"
]
```

---

## 9. OTG COMPOSÉ — CONFIGURATION SYSTÈME

### RPi Zero W (gadget USB)

```
/boot/firmware/config.txt
  dtoverlay=dwc2          ← mode peripheral
  dtoverlay=hyperpixel2r  ← écran SPI/I2C
  dtparam=i2c_arm=on
  dtparam=spi=on

/etc/modules
  dwc2
  libcomposite

/etc/modprobe.d/secubox-otg.conf
  options dwc2 dr_mode=peripheral

/etc/network/interfaces.d/usb0
  allow-hotplug usb0
  iface usb0 inet static
    address 10.55.0.2/30
    gateway 10.55.0.1

Fonction ECM  : usb0  → réseau 10.55.0.0/30
Fonction ACM  : ttyGS0 → console série 115200 baud
MAC ECM       : dérivée déterministe du serial RPi
```

### SecuBox-Deb (hôte USB)

```
/etc/udev/rules.d/90-secubox-otg.rules
  → détecte le Zero W, renomme en "secubox-round"
  → appelle secubox-otg-host-up.sh

secubox-otg-host-up.sh
  ip addr add 10.55.0.1/30 dev secubox-round
  ip link set secubox-round up
  POST /api/v1/remote-ui/connected (token interne)
```

---

## 10. CONVENTIONS DE CODE

### Python (backend)

```python
# Async natif uniquement
async def get_metrics() -> SystemMetricsResponse: ...

# Zéro psutil — stdlib pure
# cpu_percent  : delta /proc/stat 200ms
# mem_percent  : /proc/meminfo MemAvailable/MemTotal
# disk_percent : os.statvfs('/')
# wifi_rssi    : /proc/net/wireless, fallback iwconfig
# cpu_temp     : /sys/class/thermal/thermal_zone0/temp ÷ 1000
# uptime       : /proc/uptime premier champ
# load_avg_1   : os.getloadavg()[0]

# Cache TTL 1s sur les métriques (asyncio, pas de threading)
# Logging : from secubox.core.logger import logger
# Docstrings en français
# PARAMETERS double-buffer 4R sur tout état mutable
```

### JavaScript (frontend)

```javascript
// Jamais de framework, jamais de CDN
// Toutes les icônes embarquées en base64 dans ICONS{}
// TransportManager : OTG prioritaire, WiFi fallback, SIM dégradé
// Un token JWT par transport (OTG et WiFi indépendants)
// Math.round() systématique avant affichage de tout nombre
// Fallback onerror sur chaque <img> PNG → SVG inline
```

### Shell

```bash
set -euo pipefail      # systématique
shellcheck clean       # aucun warning
Docstrings fr          # commentaires en français
```

---

## 11. ORDRE DE GÉNÉRATION RECOMMANDÉ

Quand Claude Code travaille sur ce module, l'ordre optimal est :

```
1.  secubox/models/system.py              Pydantic schemas
2.  secubox/core/metrics.py               Collecte async /proc
3.  secubox/core/alerts.py                AlertsEngine seuils TOML
4.  secubox/core/remote_ui.py             RemoteUIManager transport
5.  secubox/api/v1/routers/system.py      Router FastAPI + CORS
6.  secubox/api/v1/__init__.py            Patch include_router
7.  remote-ui/round/assets/svg/*.svg      6 SVG sources icônes
8.  remote-ui/round/assets/generate_icons.sh  cairosvg batch
9.  remote-ui/round/index.html            Dashboard complet
10. remote-ui/round/secubox-otg-gadget.sh configfs libcomposite
11. remote-ui/round/secubox-otg-host-up.sh udev hook host
12. remote-ui/round/install_zerow.sh      Flash + config Zero W
13. remote-ui/round/deploy.sh             Déploiement SSH
14. remote-ui/round/secubox-remote-ui.service systemd
15. Documentation secubox.conf [remote_ui]
```

---

## 12. TESTS MINIMAUX REQUIS

```python
# secubox/tests/test_remote_ui.py
async def test_metrics_endpoint_returns_200(): ...
async def test_metrics_requires_jwt(): ...
async def test_metrics_schema_valid(): ...
async def test_alerts_nominal_state(): ...
async def test_alerts_cpu_critical(): ...
async def test_transport_otg_registered(): ...
async def test_cors_allowed_origin(): ...
async def test_cors_blocked_origin(): ...
```

```bash
# Smoke test terrain Zero W
curl -s http://10.55.0.1:8000/api/v1/health | jq .status
curl -s http://10.55.0.2:8080/ | grep -c "SECUBOX"
i2cdetect -y 10          # touch HyperPixel
vcgencmd measure_temp    # capteur temp RPi
cat /proc/net/wireless   # WiFi RSSI
```

---

## 13. RÈGLES ABSOLUES (NE JAMAIS VIOLER)

```
✗ Jamais psutil comme dépendance
✗ Jamais de CDN externe dans index.html
✗ Jamais "CyberMind Produits SASU" dans aucun output
✗ Jamais de secret hardcodé — tout dans secubox.conf
✗ Jamais fond non-noir (#080808) pour le dashboard kiosk
✗ Jamais de couleur hors palette module SecuBox pour les pods
✗ Jamais dr_mode=otg pour le Zero W (risque host mode)
✗ Jamais brancher sur le port PWR micro-B pour l'OTG

✓ Toujours Math.round() avant affichage numérique
✓ Toujours fallback SVG inline si PNG absent (onerror)
✓ Toujours timeout sur chaque fetch (AbortSignal.timeout)
✓ Toujours PARAMETERS double-buffer 4R sur états mutables
✓ Toujours docstrings/commentaires en français
✓ Toujours générer les tests avant de passer au module suivant
```

---

## 14. COMMANDES FRÉQUENTES

```bash
# Déployer le dashboard sur le Zero W
./remote-ui/round/deploy.sh -h rpi-zero-round.local -u pi --no-sim

# Passer en mode API réelle
./deploy.sh --api-url http://10.55.0.1:8000 --api-pass MON_MDP

# Vérifier le gadget OTG
ssh pi@rpi-zero-round.local "systemctl status secubox-otg-gadget"
ssh pi@rpi-zero-round.local "ip addr show usb0"
ssh pi@rpi-zero-round.local "cat /proc/net/wireless"

# Console série de rescue (depuis SecuBox host)
screen /dev/secubox-console 115200
# ou : minicom -D /dev/ttyACM0 -b 115200

# Tests backend
cd secubox-deb
pytest secubox/tests/test_remote_ui.py -v

# Générer les icônes PNG depuis les SVG
cd remote-ui/round/assets
bash generate_icons.sh

# Vérifier CORS
curl -H "Origin: http://10.55.0.2:8080" \
     -H "Authorization: Bearer $JWT" \
     http://10.55.0.1:8000/api/v1/system/metrics
```

---

## 14.1 BOOT MEDIA API — ENDPOINTS COMPLÉMENTAIRES

Portage depuis SecuBox-Eye / eye-remote module (v2.1.0+).

### Boot Media Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/eye-remote/boot-media/state` | État du boot-media (active/shadow) |
| POST | `/api/v1/eye-remote/boot-media/upload` | Uploader fichier image vers shadow |
| POST | `/api/v1/eye-remote/boot-media/swap` | Basculer active ↔ shadow atomiquement |
| POST | `/api/v1/eye-remote/boot-media/rollback` | Rollback snapshot 4R |
| GET | `/api/v1/eye-remote/boot-media/tftp/status` | État serveur TFTP réseau |

### Modèles Pydantic (Boot Media)

```python
class BootMediaState(BaseModel):
    active_partition: str       # "/dev/mmcblk0p1" ou symlink
    active_size: int            # taille octets
    active_hash: str            # SHA256
    shadow_partition: str
    shadow_size: int
    shadow_hash: str
    rollback_count: int         # R1..R4 disponibles
    last_swap_timestamp: datetime
    tftp_enabled: bool

class BootMediaSwapRequest(BaseModel):
    validate_hash: Optional[str] = None  # SHA256 attendu active post-swap
    rollback_target: Optional[int] = None # R1|R2|R3|R4

class TftpStatus(BaseModel):
    enabled: bool
    port: int
    serving_root: str
    clients_connected: int
```

### Systemd Services (Eye-Remote)

| Service | File | Description |
|---------|------|-------------|
| `secubox-eye-gadget.service` | `/etc/systemd/system/` | USB composé ECM+ACM+mass_storage |
| `secubox-eye-serial.service` | `/etc/systemd/system/` | Console série via xterm.js |
| `secubox-eye-websocket.service` | `/etc/systemd/system/` | WebSocket API (port /run/secubox/eye.sock) |

### Directives PARAMETERS (Boot Media Double-Buffer)

Boot-media stocke ses états dans le double-buffer PARAMETERS :

```
/var/cache/secubox/boot-media/
├── active/
│   ├── KERNEL
│   ├── INITRD
│   ├── DTB
│   ├── metadata.json
│   └── integrity.sha256
├── shadow/           ← édition
│   ├── (idem structure)
│   └── pending_swap.flag
└── rollback/
    ├── R1/
    ├── R2/
    ├── R3/
    └── R4/
```

Swap atomique :
```
1. Valider SHA256(shadow/KERNEL) == metadata.validate_hash
2. fsync() tous les fichiers shadow/
3. Atomic rename : shadow → active (via mv -T)
4. Archiver ancien active → R1, shift R1→R2, R2→R3, R3→R4
5. Retirer pending_swap.flag
```

---

## 15. RÉFÉRENCES

```
Repo principal    : github.com/CyberMind-FR/secubox-deb
Branch            : feature/remote-ui-round
APT repo          : apt.secubox.in
Dashboard live    : live.maegia.tv
Docs              : docs.secubox.in
Certification     : ANSSI CSPN 2027

Hardware cible dashboard : RPi Zero W ARMv6 armhf 512MB
Écran                    : Pimoroni HyperPixel 2.1 Round Touch 480×480
Driver écran             : github.com/pimoroni/hyperpixel2r
Connexion                : USB OTG composé (ECM + ACM) + WiFi WPA2 fallback
Réseau OTG               : 10.55.0.0/30 (SecuBox=.1, Zero W=.2)
Console rescue           : /dev/ttyACM0 (host) / /dev/ttyGS0 (gadget)
```

---

*CyberMind · SecuBox-Deb · remote-ui/round · 2026*
*Fichier généré automatiquement — ne pas éditer manuellement*
*Mettre à jour via : claude-code "update CLAUDE.md remote-ui-round"*
