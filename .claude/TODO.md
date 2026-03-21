# TODO — SecuBox-DEB Backlog
*Mis à jour : 2026-03-20*

---

## 🔥 PHASE 1 — Bootstrap HW + OS (S01–S03)

- [ ] **P1-01** Valider boot Debian bookworm arm64 sur MOCHAbin physique
  - Flasher image Armbian bookworm MOCHAbin comme base
  - Vérifier : réseau mvneta/mvpp2, eMMC, DTS armada-7040-mochabin
- [ ] **P1-02** Compiler kernel 6.6 LTS arm64 avec config SecuBox
  - CONFIG : mvneta, mvpp2, DSA 88E6341, wireguard, nft, cls_flower, act_mirred, KASLR
  - Tester DTS upstream armada-7040-mochabin.dts et armada-3720-espressobin-v7.dts
- [ ] **P1-03** Écrire `image/build-image.sh` (debootstrap → GPT → .img.gz)
  - Partitions : ESP 256MB FAT32 + rootfs ext4 3GB + data ext4 reste
  - Packages minimalistes : systemd, netplan, nftables, openssh-server, python3
- [ ] **P1-04** Écrire `image/firstboot.sh`
  - Génération JWT secret (openssl rand -hex 32)
  - Injection clé SSH depuis `/boot/authorized_keys`
  - Configuration hostname depuis `/boot/hostname`
- [ ] **P1-05** netplan templates par board
  - `board/mochabin/netplan/00-secubox.yaml` : WAN=eth0, LAN=eth1..eth4, SFP+=eth5,eth6
  - `board/espressobin-v7/netplan/00-secubox.yaml` : WAN=eth0, LAN=lan0,lan1 (DSA)
- [ ] **P1-06** CI GitHub Actions Phase 1
  - `build-image.yml` : matrix [mochabin, espressobin-v7, espressobin-ultra]
  - Cross-compile via qemu-user-static + binfmt arm64

---

## ✅ PHASE 2 — API Gateway + secubox-core + secubox-hub (S04–S07) — TERMINÉ

- [x] **P2-01** Implémenter `common/secubox_core/` (lib Python partagée)
  - `auth.py` : JWT HS256, require_jwt dependency, login endpoint
  - `config.py` : charger /etc/secubox/secubox.conf (TOML), get_board_info()
  - `logger.py` : logging structuré JSON vers journald
  - `system.py` : board_info(), uptime(), service_status(), disk_usage()
- [x] **P2-02** Écrire `common/nginx/secubox.conf`
  - Serve `/usr/share/secubox/www/` pour les statics
  - Proxy `/api/v1/<module>/` → `unix:/run/secubox/<module>.sock`
  - TLS autosigné firstboot + Let's Encrypt optionnel
- [x] **P2-03** Paquet `secubox-core` complet
  - `debian/control`, `debian/rules`, `debian/postinst`
  - Installe secubox_core dans `/usr/lib/python3/dist-packages/`
  - Crée `/etc/secubox/`, `/run/secubox/`, `/var/lib/secubox/`
- [x] **P2-04** Paquet `secubox-hub` (référence de pattern)
  - Porter `luci-app-secubox` : dashboard central, module launcher
  - `api/main.py` : endpoints status, modules, alerts, monitoring, settings
  - `debian/` complet + unit systemd `secubox-hub.service`
- [x] **P2-05** Script `scripts/rewrite-xhr.py`
  - Remplace `rpc.declare({object:'luci.X',method:'Y'})` → `fetch('/api/v1/X/Y')`
  - Mode dry-run + mode patch in-place

---

## 🌐 PHASE 3 — Modules (S07–S12)

### Groupe A — Faciles (proxy ou CLI)
- [x] **P3-01** `secubox-crowdsec` ✅
  - API complète : 54 endpoints (status, decisions, alerts, bouncers, hub, wizard, acquisition, etc.)
  - Frontend porté et XHR réécrit
  - Packaging debian complet
- [ ] **P3-02** `secubox-netdata`
  - Méthodes : status, charts, data, alarms, info
  - Backend : proxy FastAPI → Netdata REST v2 (http://localhost:19999)
- [ ] **P3-03** `secubox-wireguard`
  - Méthodes : status, peers, interfaces, generate_keys, create_interface, add_peer, remove_peer, config, generate_qr, traffic, interface_control, bandwidth_rates, ping_peer
  - Backend : subprocess wg/wg-quick + ip commands (WireGuard kernel natif)
- [ ] **P3-04** `secubox-vhost`
  - Méthodes : list_vhosts, add_vhost, remove_vhost, ssl_status, get_certificates, get_logs
  - Backend : générer configs nginx depuis templates Jinja2 + certbot/acme.py
- [ ] **P3-05** `secubox-mediaflow`
  - Méthodes : status, services, clients, history, alerts
  - Backend : consomme socket netifyd (dépend secubox-dpi)

### Groupe B — Moyens
- [ ] **P3-06** `secubox-dpi`
  - Méthodes : status, applications, devices, flows, risks, talkers, settings
  - Backend : netifyd JSON socket /run/netifyd.sock + tc mirred setup (ifb0)
  - Setup DPI dual-stream : `tc qdisc add dev eth0 ingress` + `tc filter mirred` + ifb0
- [ ] **P3-07** `secubox-qos`
  - Méthodes : status, classes, rules, schedules, clients, usage, quotas, apply_qos
  - Backend : pyroute2 (tc HTB classes, nftables marks, quota tracking)
  - Remplace : `tc qdisc`, `tc class`, `tc filter` shell → pyroute2 Python
- [ ] **P3-08** `secubox-auth`
  - Méthodes : status, sessions, vouchers, oauth_providers, splash_config, bypass_rules
  - Backend : authlib OAuth2 (Google/GitHub) + SQLite sessions/vouchers
- [ ] **P3-09** `secubox-cdn`
  - Méthodes : status, policies, cache_stats, purge, preload, settings
  - Backend : squid-openssl (dpkg) config generation ou nginx proxy_cache
- [ ] **P3-10** `secubox-system`
  - Méthodes : status, health_score, services_list, service_control, logs, backup, diagnostics
  - Backend : pystemd (DBus systemd) + journald + psutil

### Groupe C — Complexes
- [ ] **P3-11** `secubox-netmodes`
  - Méthodes : status, get_current_mode, set_mode, apply_mode, rollback, get_interfaces
  - Modes : router, sniffer-inline, sniffer-passive, access-point, relay/extender
  - Backend : netplan YAML templates + ip link/bridge + systemd-networkd
  - Un template YAML par mode dans `/etc/secubox/netmodes/`
- [ ] **P3-12** `secubox-nac`
  - Méthodes : status, clients, zones, portal_config, parental_rules, alerts, logs
  - Backend : dnsmasq lease parser + nftables sets (per-zone) + captive portal nginx
  - Zones nft : `set lan_allowed { type ether_addr; }` etc.

---

## 📦 PHASE 4 — APT Repo + Packaging (S13–S14)

- [ ] **P4-01** Setup APT repo signé GPG
  - reprepro sur `apt.secubox.gondwana.systems`
  - Script `scripts/publish-apt.sh` : signer + uploader via rsync/SSH
- [ ] **P4-02** Métapaquets
  - `secubox-full` : Depends: tous les modules
  - `secubox-lite` : Depends: core,hub,crowdsec,wireguard,netdata (ESPRESSObin ≤2GB)
- [ ] **P4-03** Script `secubox-update` installé dans `/usr/bin/`
  - apt update + apt upgrade secubox-* + systemctl restart secubox-* + health check

---

## 🔒 PHASE 5 — CSPN Hardening (S15–S18)

- [ ] **P5-01** AppArmor profiles pour chaque service
- [ ] **P5-02** Kernel config hardening (KASLR, FORTIFY, STACKPROTECTOR_STRONG, SLAB_FREELIST_RANDOM)
- [ ] **P5-03** Rootfs read-only : overlayfs + A/B partition eMMC
- [ ] **P5-04** Secrets : firstboot génère dans /run/secubox/keys (tmpfs), pas hardcodés
- [ ] **P5-05** auditd + journald forwarding + logrotate GPG
- [ ] **P5-06** nftables DEFAULT DROP policy + règles minimales
- [ ] **P5-07** Cible de sécurité ANSSI (rédiger draft CC EAL2)

---

## 🚀 PHASE 6 — CI/CD Image Factory (S19–S21)

- [ ] **P6-01** `build-packages.yml` : dpkg-buildpackage cross arm64 + reprepro
- [ ] **P6-02** `build-image.yml` : matrix 3 boards + SHA256SUMS signés
- [ ] **P6-03** Release pipeline : tag v* → GitHub Release + APT repo update

---

## ✅ COMPLÉTÉ

*(rien encore — début de projet)*
