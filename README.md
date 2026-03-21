# SecuBox-DEB
## Migration OpenWrt → Debian · GlobalScale Technologies
**CyberMind · Gandalf · Mars 2026**

Port complet de [SecuBox OpenWrt](https://github.com/gkerma/secubox-openwrt) vers **Debian bookworm arm64** pour les boards **MOCHAbin** (Armada 7040) et **ESPRESSObin v7/Ultra** (Armada 3720).

---

## 🏗️ Architecture

```
OpenWrt / LuCI                   →    Debian bookworm arm64
─────────────────────────────────────────────────────────
RPCD shell backend               →    FastAPI + Uvicorn (Unix socket)
UCI config /etc/config/          →    TOML /etc/secubox/secubox.conf
luci-app-*/htdocs/ (JS/CSS/HTML) →    Conservé + XHR réécrits
OpenWrt packages (.ipk)          →    Paquets Debian (.deb)
opkg                             →    apt + repo secubox.gondwana.systems
```

**Boards supportés :**

| Board | SoC | RAM | Réseau | Profil |
|-------|-----|-----|--------|--------|
| MOCHAbin | Armada 7040 Quad-core 1.8GHz | 4 GB | 2× SFP+ 10GbE + 4× GbE | SecuBox Pro |
| ESPRESSObin v7 | Armada 3720 Dual 1.2GHz | 1–2 GB | WAN + 2× LAN DSA | SecuBox Lite |
| ESPRESSObin Ultra | Armada 3720 Dual 1.2GHz | 2 GB | WAN PoE + 4× LAN + Wi-Fi | SecuBox Lite+ |

---

## 📦 Paquets Debian (14 modules)

| Paquet | Source OpenWrt | Description |
|--------|---------------|-------------|
| `secubox-core` | *(base)* | Lib Python partagée, nginx, firstboot |
| `secubox-hub` | `luci-app-secubox` | Dashboard central |
| `secubox-crowdsec` | `luci-app-crowdsec-dashboard` | IDS/IPS CrowdSec |
| `secubox-netdata` | `luci-app-netdata-dashboard` | Monitoring temps réel |
| `secubox-wireguard` | `luci-app-wireguard-dashboard` | VPN WireGuard |
| `secubox-dpi` | `luci-app-netifyd-dashboard` | DPI dual-stream |
| `secubox-netmodes` | `luci-app-network-modes` | Modes réseau |
| `secubox-nac` | `luci-app-client-guardian` | NAC + portail captif |
| `secubox-auth` | `luci-app-auth-guardian` | OAuth2 + vouchers |
| `secubox-qos` | `luci-app-bandwidth-manager` | QoS / HTB |
| `secubox-mediaflow` | `luci-app-media-flow` | Détection streaming |
| `secubox-cdn` | `luci-app-cdn-cache` | Cache CDN local |
| `secubox-vhost` | `luci-app-vhost-manager` | Virtual hosts nginx |
| `secubox-system` | `luci-app-system-hub` | Contrôle système |

---

## 🚀 Démarrage rapide (développement)

```bash
git clone https://github.com/gkerma/secubox-deb
cd secubox-deb
bash setup-dev.sh
source .venv/bin/activate && source .env

# Porter le frontend d'un module depuis le repo source
bash scripts/port-frontend.sh crowdsec-dashboard

# Lancer l'API en dev
cd packages/secubox-crowdsec
uvicorn api.main:app --reload --host 127.0.0.1 --port 8001

# Tester
curl http://127.0.0.1:8001/health
curl -X POST http://127.0.0.1:8001/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"secubox"}'
```

---

## 💿 Build image board

```bash
# MOCHAbin (nécessite root + debootstrap)
sudo bash image/build-image.sh --board mochabin --out output/

# Flasher
zcat output/secubox-mochabin-bookworm.img.gz | \
  dd of=/dev/mmcblk0 bs=4M status=progress
```

---

## 📦 Build paquets .deb

```bash
# Un module
cd packages/secubox-crowdsec
dpkg-buildpackage --host-arch arm64 -us -uc -b

# Tous (via CI)
git tag v1.0.0 && git push --tags
# → GitHub Actions build + publish APT repo
```

---

## 🔧 VSCode Tasks (`Ctrl+Shift+B`)

| Task | Description |
|------|-------------|
| 📥 Port frontend — module unique | Copier htdocs + réécrire XHR |
| 🚀 Run API — module en dev | Uvicorn local avec hot-reload |
| 📦 Build .deb — module unique | Cross-compile arm64 |
| 🚢 Déployer — TOUT sur le board | SSH rsync + restart services |
| 💿 Build image — MOCHAbin | debootstrap + GPT + .img.gz |
| ⚡ Workflow complet — un module | Port + build en séquence |

---

## 🗺️ Suivi de migration

Voir `.claude/MIGRATION-MAP.md` pour l'état de chaque module.

Démarrer une session de travail avec Claude Code :
```bash
claude  # dans le répertoire du projet — lit CLAUDE.md automatiquement
```

---

## 📄 Licence

Apache-2.0 © 2026 CyberMind · Gandalf / gkerma
