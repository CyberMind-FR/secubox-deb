# MIGRATION MAP — SecuBox OpenWrt → Debian
*Mis à jour : 2026-03-24*

Légende : ✅ Terminé · 🔄 En cours · ⬜ À faire · ⏸ Bloqué

---

## Infrastructure

| Composant | Statut | Notes |
|-----------|--------|-------|
| Repo structure | ✅ | Structure créée |
| CLAUDE.md | ✅ | Instructions Claude Code |
| secubox_core lib | ✅ | auth, config, logger, system |
| nginx template | ✅ | Reverse proxy complet |
| rewrite-xhr.py | ✅ | Gère accolades imbriquées |
| CI build-image | ✅ | Scaffold créé |
| CI build-packages | ✅ | Scaffold créé |
| build-image.sh | ✅ | arm64 + amd64 (VirtualBox) |
| create-vbox-vm.sh | ✅ | Création VM automatique |
| firstboot.sh | ✅ | JWT + SSH + hostname + nftables |
| APT repo | ✅ | apt.secubox.in (reprepro + GPG + CI) |
| Local cache | ✅ | apt-cacher-ng + repo local |

---

## Boards supportés

| Board | SoC | Arch | Profil | Statut |
|-------|-----|------|--------|--------|
| **mochabin** | Armada 7040 | arm64 | secubox-full | ✅ |
| **espressobin-v7** | Armada 3720 | arm64 | secubox-lite | ✅ |
| **espressobin-ultra** | Armada 3720 | arm64 | secubox-lite | ✅ |
| **vm-x64** | x86_64-generic | amd64 | secubox-full | ✅ |

---

## Paquets Debian — 33 modules

| Module | www/ | API | deb/ | Endpoints | Statut |
|--------|------|-----|------|-----------|--------|
| **secubox-core** | — | — | ✅ | — | ✅ |
| **secubox-hub** | ✅ (71) | ✅ | ✅ | 40+ endpoints | ✅ |
| **secubox-portal** | ✅ | ✅ | ✅ | login, auth | ✅ |
| **secubox-crowdsec** | ✅ (54) | ✅ | ✅ | 54 endpoints | ✅ |
| **secubox-netdata** | ✅ (16) | ✅ | ✅ | 16 endpoints | ✅ |
| **secubox-wireguard** | ✅ (28) | ✅ | ✅ | 28+ endpoints | ✅ |
| **secubox-vhost** | ✅ | ✅ | ✅ | vhosts, ssl, certs | ✅ |
| **secubox-mediaflow** | ✅ (20) | ✅ | ✅ | streams, alerts... | ✅ |
| **secubox-dpi** | ✅ | ✅ | ✅ | 40+ endpoints netifyd | ✅ |
| **secubox-qos** | ✅ (80) | ✅ | ✅ | 80+ endpoints HTB + VLAN v1.1.0 | ✅ |
| **secubox-auth** | ✅ (11) | ✅ | ✅ | 20+ endpoints | ✅ |
| **secubox-cdn** | ✅ (36) | ✅ | ✅ | 25+ endpoints | ✅ |
| **secubox-system** | ✅ (42) | ✅ | ✅ | 35+ endpoints | ✅ |
| **secubox-netmodes** | ✅ (34) | ✅ | ✅ | 25+ endpoints + templates | ✅ |
| **secubox-nac** | ✅ (32) | ✅ | ✅ | 25+ endpoints | ✅ |
| **secubox-haproxy** | ✅ | ✅ | ✅ | stats, backends, acls | ✅ |
| **secubox-droplet** | ✅ | ✅ | ✅ | upload, publish | ✅ |
| **secubox-streamlit** | ✅ | ✅ | ✅ | apps, deploy | ✅ |
| **secubox-streamforge** | ✅ | ✅ | ✅ | apps, templates | ✅ |
| **secubox-metablogizer** | ✅ | ✅ | ✅ | sites, tor, publish | ✅ |
| **secubox-dns** | ✅ | ✅ | ✅ | zones, records, BIND | ✅ |
| **secubox-mail** | ✅ | ✅ | ✅ | Postfix/Dovecot + webmail | ✅ |
| **secubox-users** | ✅ | ✅ | ✅ | unified identity v1.1.0 | ✅ |
| **secubox-webmail** | ✅ | ✅ | ✅ | Roundcube/SOGo | ✅ |
| **secubox-mail-lxc** | — | ✅ | ✅ | LXC backend (no UI) | ✅ |
| **secubox-webmail-lxc** | — | ✅ | ✅ | LXC backend (no UI) | ✅ |
| **secubox-publish** | ✅ | ✅ | ✅ | Unified publishing | ✅ |
| **secubox-waf** | ✅ | ✅ | ✅ | 300+ rules, CrowdSec | ✅ |
| **secubox-gitea** | ✅ | ✅ | ✅ | Git server LXC | ✅ |
| **secubox-nextcloud** | ✅ | ✅ | ✅ | File sync LXC | ✅ |
| **secubox-c3box** | ✅ | ✅ | ✅ | Services portal | ✅ |
| **secubox-backup** | ✅ | ✅ | ✅ | config, container backup | ✅ |
| **secubox-watchdog** | ✅ | ✅ | ✅ | containers, services, endpoints | ✅ |
| **secubox-tor** | ✅ | ✅ | ✅ | circuits, hidden services | ✅ |
| **secubox-exposure** | ✅ | ✅ | ✅ | Tor, SSL, DNS, Mesh | ✅ |
| **secubox-mitmproxy** | ✅ | ✅ | ✅ | WAF, alerts, bans | ✅ |
| **secubox-traffic** | ✅ | ✅ | ✅ | TC/CAKE QoS | ✅ |
| **secubox-device-intel** | ✅ | ✅ | ✅ | asset discovery, fingerprinting | ✅ |
| **secubox-vortex-dns** | ✅ | ✅ | ✅ | DNS firewall, RPZ, threat feeds | ✅ |
| **secubox-vortex-firewall** | ✅ | ✅ | ✅ | nftables threat enforcement | ✅ |
| **secubox-meshname** | ✅ | ✅ | ✅ | mesh DNS, mDNS, Avahi | ✅ |
| **secubox-soc** | ✅ | ✅ | ✅ | SOC dashboard, clock, map, tickets | ✅ |
| **secubox-roadmap** | ✅ | ✅ | ✅ | migration roadmap tracker | ✅ |
| **secubox-metrics** | ✅ | ✅ | ✅ | real-time metrics dashboard | ✅ |
| **secubox-mesh** | ✅ | ✅ | ✅ | Yggdrasil mesh network | ✅ |
| **secubox-p2p** | ✅ | ✅ | ✅ | P2P networking | ✅ |
| **secubox-zkp** | ✅ | ✅ | ✅ | ZKP Hamiltonian proofs | ✅ |
| **secubox-hardening** | ✅ | ✅ | ✅ | sysctl + module blacklist | ✅ |
| **secubox-repo** | ✅ | ✅ | ✅ | APT repository management | ✅ |

**Total : 52 modules | ~1000+ endpoints API**

*Note: mail-lxc and webmail-lxc are backend components integrated into secubox-mail*

---

## Phases du projet

### Phase 1 — Hardware ✅
- [x] build-image.sh (debootstrap arm64 + amd64)
- [x] Board configs (mochabin, espressobin-v7, espressobin-ultra, vm-x64)
- [x] create-vbox-vm.sh (VirtualBox)
- [x] firstboot.sh (détection board améliorée)
- [x] Templates netplan par board
- [ ] Kernel 6.6 LTS cross-compile (optionnel — peut utiliser stock Debian)

### Phase 2 — Infrastructure ✅
- [x] secubox_core Python lib
- [x] nginx reverse proxy template
- [x] rewrite-xhr.py script
- [x] CI scaffolds

### Phase 3 — Modules ✅
- [x] Tous les frontends portés (13/13)
- [x] Tous les APIs implémentés (14/14)
- [x] Packaging debian complet (14/14)
- [x] Templates netplan pour netmodes
- [x] Frontend secubox-dpi créé

### Phase 4 — APT Repo ✅
- [x] apt.secubox.in (reprepro config)
- [x] GPG signing (generate-gpg-key.sh)
- [x] CI publish workflow (publish-packages.yml)
- [x] repo-manage.sh (add/remove/list/sync)
- [x] setup-repo-server.sh (nginx + Let's Encrypt)
- [x] Metapackages (secubox-full, secubox-lite)
- [x] Local cache build (apt-cacher-ng + repo local)

---

## Commandes de build

```bash
# Build image ARM (MOCHAbin)
sudo bash image/build-image.sh --board mochabin

# Build image x64 pour VirtualBox
sudo bash image/build-image.sh --board vm-x64 --vdi

# Build image x64 avec cache local (plus rapide)
sudo bash image/build-image.sh --board vm-x64 --local-cache --vdi

# Créer VM VirtualBox
bash image/create-vbox-vm.sh output/secubox-vm-x64-bookworm.vdi

# Build un paquet .deb
cd packages/secubox-crowdsec && dpkg-buildpackage -us -uc -b

# Build et ajouter au repo local
bash scripts/build-add-local.sh secubox-crowdsec bookworm
```

---

## Prochaines étapes

1. ~~Phase 1 : build-image.sh + board configs~~ ✅ Fait
2. ~~Phase 2 : Infrastructure~~ ✅ Fait
3. ~~Phase 3 : Modules~~ ✅ Fait
4. ~~Phase 4 : APT repo (apt.secubox.in)~~ ✅ Fait
5. Tests d'intégration sur VM et hardware réel

---

## Build avec cache local

```bash
# Setup cache local (une fois)
sudo bash scripts/setup-local-cache.sh

# Builder tous les packages SecuBox
bash scripts/build-all-local.sh bookworm amd64

# Construire image avec cache local
sudo bash image/build-image.sh --board vm-x64 --local-cache
```
