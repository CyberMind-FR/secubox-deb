# CLAUDE.md — SecuBox-DEB
## Migration OpenWrt → Debian · GlobalScale Marvell Armada
### Instructions pour Claude Code dans VSCode

---

## 🧭 Session Startup — Lire d'abord

**À chaque session, lire dans cet ordre :**

1. `.claude/WIP.md`         → ce qui est en cours, le prochain à faire
2. `.claude/TODO.md`        → backlog priorisé par phase
3. `.claude/MIGRATION-MAP.md` → état de chaque module (✅ / 🔄 / ⬜)
4. `.claude/PATTERNS.md`    → patterns RPCD→FastAPI avec exemples réels

**Quand l'utilisateur dit "continue" / "suivant" / "next" :**
Consulter `WIP.md` → prendre le premier item "⬜ Next Up" → l'implémenter → mettre à jour les fichiers `.claude/`.

---

## 🏗️ Ce qu'est ce projet

**SecuBox-DEB** est le portage Debian bookworm arm64 de SecuBox OpenWrt.

**Source** : `https://github.com/gkerma/secubox-openwrt`
Chaque `package/secubox/luci-app-<module>/` devient un paquet Debian `secubox-<module>`.

**Principe de migration :**
- Frontend `htdocs/` (HTML/JS/CSS) → **conservé à l'identique** dans `www/`
- Backend `root/usr/libexec/rpcd/luci.<module>` (shell) → **porté** en `api/main.py` (FastAPI)
- Config `root/etc/config/` (UCI) → `debian/` + `/etc/secubox/<module>.toml`
- Makefile OpenWrt → `debian/control` + `debian/rules` + `debian/postinst`
- Menu/ACL JSON → conservés, plus middleware JWT FastAPI

**Stack cible :**
- Debian bookworm arm64
- Kernel 6.6 LTS mainline (DTS Marvell upstream)
- FastAPI + Uvicorn sur Unix socket par module
- Nginx reverse proxy : statics htdocs + `/api/v1/<module>/*`
- nftables, netplan, WireGuard kernel natif
- CrowdSec dpkg officiel, HAProxy TLS 1.3
- APT repo signé GPG : `apt.secubox.in`

---

## 📁 Structure du repo

```
secubox-deb/
├── .claude/                    ← Suivi de projet (lire en premier)
│   ├── TODO.md
│   ├── WIP.md
│   ├── MIGRATION-MAP.md
│   └── PATTERNS.md
├── .github/workflows/          ← CI GitHub Actions cross-arm64
│   ├── build-image.yml
│   └── build-packages.yml
├── .vscode/                    ← Tasks VSCode
│   └── tasks.json
├── board/                      ← Config par board GlobalScale
│   ├── mochabin/               ← Armada 7040, cible Pro
│   │   ├── config.mk
│   │   └── netplan/00-secubox.yaml
│   ├── espressobin-v7/         ← Armada 3720, cible Lite
│   └── espressobin-ultra/      ← Armada 3720 Ultra
├── image/                      ← Scripts de construction d'image
│   ├── build-image.sh          ← debootstrap → .img flashable
│   ├── firstboot.sh            ← SSH keys, JWT, hostname
│   └── partition-layout.sh     ← GPT : ESP + rootfs + data
├── common/                     ← Code partagé
│   ├── secubox_core/           ← Lib Python : JWT, config, logging
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── config.py
│   │   └── logger.py
│   ├── nginx/secubox.conf      ← Template nginx reverse proxy
│   └── systemd/                ← Units systemd génériques
├── packages/                   ← 14 paquets Debian
│   ├── secubox-core/           ← Bibliothèque partagée Python
│   ├── secubox-hub/            ← luci-app-secubox → dashboard central
│   ├── secubox-crowdsec/       ← luci-app-crowdsec-dashboard
│   ├── secubox-netdata/        ← luci-app-netdata-dashboard
│   ├── secubox-wireguard/      ← luci-app-wireguard-dashboard
│   ├── secubox-dpi/            ← luci-app-netifyd-dashboard + dpi-dual
│   ├── secubox-netmodes/       ← luci-app-network-modes
│   ├── secubox-nac/            ← luci-app-client-guardian
│   ├── secubox-auth/           ← luci-app-auth-guardian
│   ├── secubox-qos/            ← luci-app-bandwidth-manager
│   ├── secubox-mediaflow/      ← luci-app-media-flow
│   ├── secubox-cdn/            ← luci-app-cdn-cache
│   ├── secubox-vhost/          ← luci-app-vhost-manager
│   └── secubox-system/         ← luci-app-system-hub
├── scripts/                    ← Outils dev/déploiement
│   ├── new-package.sh          ← Scaffold un nouveau paquet
│   ├── deploy.sh               ← Déployer sur board via SSH
│   ├── port-frontend.sh        ← Copier htdocs depuis secubox-openwrt
│   └── rewrite-xhr.py          ← Réécrire /cgi-bin/luci → /api/v1
├── docs/
│   └── PORTING-GUIDE.md        ← Guide complet de portage module par module
├── secubox.conf.example        ← /etc/secubox/secubox.conf (TOML)
├── setup-dev.sh                ← Installation environnement dev
└── README.md
```

---

## 🔑 Règles impératives

### Réseau / Sécurité
- **JAMAIS** de waf_bypass ni de port ouvert inutile
- nftables DEFAULT DROP — ouvrir explicitement seulement ce qui est nécessaire
- HAProxy en frontal TLS 1.3 pour toute exposition externe
- AppArmor profile enforce pour chaque service

### Pattern FastAPI (RPCD → API)
- Chaque méthode RPCD `luci.<module>/<method>` → `GET /api/v1/<module>/<method>`
- Les méthodes d'action (set_*, apply, ban...) → `POST /api/v1/<module>/<method>`
- Authentification JWT **obligatoire** sur tous les endpoints via `Depends(auth.require_jwt)`
- Socket Unix `/run/secubox/<module>.sock` — jamais de port TCP direct

### Packaging Debian
- Versioning : `1.0.0-1~bookworm1`
- `debian/postinst` : `systemctl enable --now secubox-<module>`
- `debian/prerm` : `systemctl stop secubox-<module>`
- Toujours `debian/compat` = 13, `Standards-Version: 4.6.2`

### Frontend (htdocs conservé)
- **Ne pas modifier** le JS/CSS/HTML des vues LuCI
- Le script `scripts/rewrite-xhr.py` remplace les appels ubus par des appels REST
- URL pattern : `rpc.declare({object: 'luci.X', method: 'Y'})` → `fetch('/api/v1/X/Y')`

### Mise à jour des fichiers de suivi
Après chaque module complété :
- Cocher `✅` dans `.claude/MIGRATION-MAP.md`
- Mettre à jour `.claude/WIP.md` (déplacer vers "Fait", pointer le suivant)
- Appender à `.claude/HISTORY.md` avec la date

---

## 🛠️ Commandes usuelles

```bash
# Build un paquet .deb localement (cross arm64)
cd packages/secubox-crowdsec
dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b

# Déployer sur le MOCHAbin
bash scripts/deploy.sh secubox-crowdsec root@192.168.1.1

# Construire l'image complète
bash image/build-image.sh --board mochabin --out /tmp/secubox-deb.img

# Porter le frontend d'un module depuis le repo source
bash scripts/port-frontend.sh crowdsec-dashboard

# Réécrire les appels XHR d'un module
python3 scripts/rewrite-xhr.py packages/secubox-crowdsec/www/

# Lancer l'API d'un module en dev local
cd packages/secubox-crowdsec && uvicorn api.main:app --reload --uds /tmp/crowdsec.sock
```

---

## 🎯 Priorité de migration

| Ordre | Module | Complexité | Raison |
|-------|--------|------------|--------|
| 1 | secubox-core | — | Dépendance de tous |
| 2 | secubox-hub | Facile | Référence de pattern |
| 3 | secubox-crowdsec | Facile | API REST déjà dispo |
| 4 | secubox-netdata | Facile | Proxy simple |
| 5 | secubox-wireguard | Facile | wg CLI natif |
| 6 | secubox-vhost | Facile | Templates nginx |
| 7 | secubox-dpi | Moyen | Socket netifyd |
| 8 | secubox-mediaflow | Facile | Consomme secubox-dpi |
| 9 | secubox-qos | Moyen | pyroute2 tc HTB |
| 10 | secubox-system | Moyen | pystemd DBus |
| 11 | secubox-netmodes | Complexe | netplan + bridge |
| 12 | secubox-nac | Complexe | nft sets + dnsmasq |
| 13 | secubox-auth | Moyen | authlib OAuth2 |
| 14 | secubox-cdn | Moyen | squid/nginx cache |

---

## 📡 Auteur

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr · https://secubox.in
