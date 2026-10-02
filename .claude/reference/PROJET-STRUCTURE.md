<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

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
- HAProxy TLS 1.3
- APT repo signé GPG : `apt.secubox.in`

---

## 📁 Structure du repo

```
secubox-deb/
├── .claude/                    ← Suivi de projet (lire en premier)
│   ├── WIP.md                  ← Travail en cours
│   ├── TODO.md                 ← Backlog priorisé
│   ├── HISTORY.md              ← Historique changements
│   ├── MIGRATION-MAP.md        ← État migration modules
│   ├── PATTERNS.md             ← Patterns code
│   ├── MODULE-COMPLIANCE.md    ← Règles conformité
│   ├── QUICKSHEET-REFERENCE.md ← Quick ref commandes
│   ├── DESIGN-CHARTER.md       ← Charte UI/UX
│   └── NOTES.md                ← Notes session
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
│   ├── secubox-wireguard/      ← luci-app-wireguard-dashboard
│   ├── secubox-dpi/            ← dashboard DPI (nDPId) + dpi-dual
│   ├── secubox-netmodes/       ← luci-app-network-modes
│   ├── secubox-nac/            ← luci-app-client-guardian
│   ├── secubox-auth/           ← luci-app-auth-guardian
│   ├── secubox-qos/            ← luci-app-bandwidth-manager
│   ├── secubox-mediaflow/      ← luci-app-media-flow
│   ├── secubox-cdn/            ← luci-app-cdn-cache
│   ├── secubox-vhost/          ← luci-app-vhost-manager
│   └── secubox-system/         ← luci-app-system-hub
├── scripts/                    ← Outils dev/déploiement (voir scripts/README.md)
│   ├── README.md               ← Documentation scripts
│   ├── build-packages.sh       ← Build tous les .deb
│   ├── deploy.sh               ← Déployer sur board via SSH
│   ├── new-package.sh          ← Scaffold un nouveau paquet
│   └── port-frontend.sh        ← Copier htdocs depuis secubox-openwrt
├── remote-ui/                  ← Interfaces UI déportées (voir remote-ui/README.md)
│   ├── README.md               ← Documentation remote-ui
│   └── round/                  ← Eye Remote Dashboard Pi Zero W
├── docs/
│   ├── TOOLS.md                ← Référence outils build/génération
│   └── PORTING-GUIDE.md        ← Guide portage module par module
├── secubox.conf.example        ← /etc/secubox/secubox.conf (TOML)
├── setup-dev.sh                ← Installation environnement dev
└── README.md
```

---

## 🎯 Priorité de migration

| Ordre | Module | Complexité | Raison |
|-------|--------|------------|--------|
| 1 | secubox-core | — | Dépendance de tous |
| 2 | secubox-hub | Facile | Référence de pattern |
| 5 | secubox-wireguard | Facile | wg CLI natif |
| 6 | secubox-vhost | Facile | Templates nginx |
| 7 | secubox-dpi | Moyen | Socket nDPId |
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
