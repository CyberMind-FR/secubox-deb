# TODO — SecuBox-DEB Backlog
*Mis à jour : 2026-03-22*

---

## ✅ PHASE 1 — Bootstrap HW + OS (S01–S03) — TERMINÉ

- [x] **P1-01** Images Debian bookworm arm64 + amd64
- [x] **P1-02** build-image.sh (debootstrap multi-arch)
- [x] **P1-03** firstboot.sh (JWT, SSH, hostname, nftables)
- [x] **P1-04** netplan templates par board
- [x] **P1-05** create-vbox-vm.sh (VirtualBox VM)
- [ ] **P1-06** Kernel 6.6 LTS cross-compile (optionnel)

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

## ✅ PHASE 3 — Modules (S07–S12) — TERMINÉ (33 modules)

All 33 modules ported and running:
- [x] **P3-01** `secubox-crowdsec` — 54 endpoints
- [x] **P3-02** `secubox-netdata` — 16 endpoints
- [x] **P3-03** `secubox-wireguard` — 28+ endpoints
- [x] **P3-04** `secubox-vhost` — vhosts, SSL, certs
- [x] **P3-05** `secubox-mediaflow` — streams, alerts
- [x] **P3-06** `secubox-dpi` — 40+ endpoints netifyd
- [x] **P3-07** `secubox-qos` — 60+ endpoints HTB
- [x] **P3-08** `secubox-auth` — 20+ endpoints
- [x] **P3-09** `secubox-cdn` — 25+ endpoints
- [x] **P3-10** `secubox-system` — 35+ endpoints
- [x] **P3-11** `secubox-netmodes` — 25+ endpoints + templates
- [x] **P3-12** `secubox-nac` — 25+ endpoints
- [x] **P3-13** `secubox-haproxy` — stats, backends, WAF
- [x] **P3-14** `secubox-droplet` — upload, publish
- [x] **P3-15** `secubox-streamlit` — apps, deploy
- [x] **P3-16** `secubox-streamforge` — apps, templates
- [x] **P3-17** `secubox-metablogizer` — sites, tor
- [x] **P3-18** `secubox-dns` — zones, BIND
- [x] **P3-19** `secubox-mail` — Postfix/Dovecot + DKIM + SpamAssassin + Postgrey + ClamAV
- [x] **P3-20** `secubox-users` — unified identity
- [x] **P3-21** `secubox-webmail` — Roundcube
- [x] **P3-22** `secubox-waf` — 300+ rules, CrowdSec
- [x] **P3-23** `secubox-gitea` — Git server LXC
- [x] **P3-24** `secubox-nextcloud` — File sync LXC
- [x] **P3-25** `secubox-c3box` — Services portal
- [x] **P3-26** `secubox-publish` — Unified publishing

---

## ✅ PHASE 4 — APT Repo + Packaging (S13–S14) — TERMINÉ

- [x] **P4-01** APT repo signé GPG (apt.secubox.in)
- [x] **P4-02** reprepro config + publish workflow
- [x] **P4-03** Métapaquets (secubox-full, secubox-lite)
- [x] **P4-04** Local cache build system (apt-cacher-ng)
- [x] **P4-05** Deployment scripts (export-secrets.sh, local-publish.sh, install.sh)

---

## ✅ PHASE 5 — CSPN Hardening (S15–S18) — TERMINÉ

- [x] **P5-01** AppArmor profiles pour chaque service
  - Base profile: /etc/apparmor.d/local/secubox-base
  - Hub, Mail, WireGuard, CrowdSec specific profiles
  - Generic profile for simple services
  - Install script: scripts/install-apparmor.sh
- [x] **P5-02** Kernel config hardening — secubox-hardening module
  - Sysctl hardening (ASLR, kptr_restrict, dmesg_restrict)
  - Network hardening (SYN cookies, rp_filter, no redirects)
  - Module blacklist (uncommon protocols, filesystems)
  - hardeningctl CLI + FastAPI + web dashboard
- [ ] **P5-03** Rootfs read-only : overlayfs + A/B partition eMMC
- [x] **P5-04** Secrets : firstboot génère dans /run/secubox/keys (tmpfs)
  - JWT secret generated at firstboot
  - Stored in /run/secubox/ (tmpfs)
- [x] **P5-05** auditd rules for SecuBox services
  - Config changes, JWT access, firewall rules
  - Authentication, privilege escalation
  - Install script: scripts/install-audit.sh
- [x] **P5-06** nftables DEFAULT DROP policy + règles minimales
  - inet secubox_filter with DROP policy
  - Only SSH, HTTP/HTTPS, WireGuard open
- [ ] **P5-07** Cible de sécurité ANSSI (rédiger draft CC EAL2)

---

## ✅ PHASE 6 — CI/CD Image Factory (S19–S21)

- [x] **P6-01** `build-packages.yml` : dpkg-buildpackage cross arm64 + reprepro
  - Dynamic matrix from packages directory
  - Dual architecture (arm64 + amd64)
  - Auto-publish on tag v*
  - build-all.sh for local development
- [x] **P6-02** `build-image.yml` : matrix 5 boards + SHA256SUMS signés
  - MOCHAbin, ESPRESSObin v7, ESPRESSObin Ultra, vm-x64, vm-arm64
  - Compressed with gzip and xz
  - GPG signed checksums
- [x] **P6-03** Release pipeline : tag v* → GitHub Release + APT repo update
  - Auto-publish packages to apt.secubox.in
  - Auto-create GitHub Release with images
  - Installation instructions in release notes

---

## ✅ COMPLÉTÉ

- Phase 1: Hardware bootstrap — Images arm64 + amd64, VirtualBox VM
- Phase 2: Infrastructure — secubox_core, nginx proxy, rewrite-xhr.py
- Phase 3: Modules — All 35 modules ported (~750+ API endpoints)
- Phase 4: APT Repo — reprepro, GPG, metapackages, local cache
- Phase 5: CSPN Hardening — AppArmor, sysctl, auditd, nftables (mostly complete)
- Phase 6: CI/CD — build-packages.yml, build-image.yml, release.yml

**Current status:**
- 35 packages total (33 original + secubox-repo + secubox-hardening)
- Mail server: DKIM + SpamAssassin + Postgrey + ClamAV
- WAF: 300+ rules with CrowdSec integration
- Hardening: Kernel sysctl + module blacklist
