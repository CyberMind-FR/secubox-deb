# TODO — SecuBox-DEB Backlog
*Mis à jour : 2026-04-21*

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

## ✅ PHASE 7 — Documentation (S22–S24) — TERMINÉ

- [x] **P7-01** Comprehensive API Reference (EN, FR, ZH)
  - 48 modules documented with ~1000+ endpoints
  - Organized by category (Core, Security, Network, Services, Apps, Intel)
  - Code examples for common operations
  - WebSocket documentation
  - Error handling and rate limiting
- [x] **P7-02** Multilingual module documentation
  - wiki/MODULES-EN.md, MODULES-FR.md, MODULES-DE.md, MODULES-ZH.md
  - 48 modules with screenshots and descriptions
- [x] **P7-03** Installation guides (EN, FR, ZH)
- [x] **P7-04** Live USB guide with persistence

---

## ✅ COMPLÉTÉ

- Phase 1: Hardware bootstrap — Images arm64 + amd64, VirtualBox VM
- Phase 2: Infrastructure — secubox_core, nginx proxy, rewrite-xhr.py
- Phase 3: Modules — All 48 modules ported (~1000+ API endpoints)
- Phase 4: APT Repo — reprepro, GPG, metapackages, local cache
- Phase 5: CSPN Hardening — AppArmor, sysctl, auditd, nftables (mostly complete)
- Phase 6: CI/CD — build-packages.yml, build-image.yml, release.yml
- Phase 7: Documentation — API Reference (EN/FR/ZH), Module docs, Installation guides

**Current status:**
- 52 packages total (48 modules + metapackages)
- Mail server: DKIM + SpamAssassin + Postgrey + ClamAV
- WAF: 300+ rules with CrowdSec integration
- Hardening: Kernel sysctl + module blacklist
- Documentation: Comprehensive API docs in 3 languages

---

## ✅ PHASE 8 — Applications (21 modules) — COMPLETE

High-value user-facing services:

- [x] **P8-01** `secubox-ollama` — LLM inference, Ollama API proxy ✅
- [x] **P8-02** `secubox-jellyfin` — Media server LXC ✅
- [x] **P8-03** `secubox-homeassistant` — IoT hub LXC ✅
- [x] **P8-04** `secubox-zigbee` — Zigbee2MQTT gateway ✅
- [x] **P8-05** `secubox-photoprism` — Photo management ✅
- [x] **P8-06** `secubox-matrix` — Synapse chat server LXC ✅
- [x] **P8-07** `secubox-jitsi` — Video conferencing LXC ✅
- [x] **P8-08** `secubox-gotosocial` — Fediverse server ✅
- [x] **P8-09** `secubox-peertube` — Video platform LXC ✅
- [x] **P8-10** `secubox-hexo` — Static blog generator ✅
- [x] **P8-11** `secubox-magicmirror` — Smart display ✅
- [x] **P8-12** `secubox-lyrion` — Music server ✅
- [x] **P8-13** `secubox-webradio` — Internet radio ✅
- [x] **P8-14** `secubox-voip` — VoIP/PBX LXC ✅
- [x] **P8-15** `secubox-jabber` — XMPP server ✅
- [x] **P8-16** `secubox-simplex` — Secure messaging ✅
- [x] **P8-17** `secubox-torrent` — BitTorrent client ✅
- [x] **P8-18** `secubox-newsbin` — Usenet client ✅
- [x] **P8-19** `secubox-domoticz` — Home automation ✅
- [x] **P8-20** `secubox-localai` — Alternative LLM backend ✅
- [x] **P8-21** `secubox-mmpm` — MagicMirror package manager ✅

---

## ✅ PHASE 9 — System Tools (22 modules) — COMPLETE

Infrastructure utilities:

- [x] **P9-01** `secubox-vault` — Config backup/restore ✅
- [x] **P9-02** `secubox-cloner` — System imaging ✅
- [x] **P9-03** `secubox-vm` — QEMU/KVM virtualization ✅
- [x] **P9-04** `secubox-glances` — System monitor ✅
- [x] **P9-05** `secubox-rtty` — Remote terminal ✅
- [x] **P9-06** `secubox-nettweak` — Network tuning ✅
- [x] **P9-07** `secubox-routes` — Routing table view ✅
- [x] **P9-08** `secubox-ksm` — Kernel same-page merging ✅
- [x] **P9-09** `secubox-reporter` — System reports ✅
- [x] **P9-10** `secubox-metabolizer` — Log processor ✅
- [x] **P9-11** `secubox-metacatalog` — Service catalog ✅
- [x] **P9-12** `secubox-saas-relay` — SaaS proxy ✅
- [x] **P9-13** `secubox-rezapp` — App deployment ✅
- [x] **P9-14** `secubox-turn` — TURN/STUN server ✅
- [x] **P9-15** `secubox-smtp-relay` — Mail relay ✅
- [x] **P9-16** `secubox-mqtt` — MQTT broker ✅
- [x] **P9-17** `secubox-cyberfeed` — Threat feed aggregator ✅
- [x] **P9-18** `secubox-avatar` — Identity management ✅
- [x] **P9-19** `secubox-admin` — Admin dashboard ✅
- [x] **P9-20** `secubox-mirror` — Mirror/CDN ✅
- [x] **P9-21** `secubox-netdiag` — Network diagnostics ✅
- [x] **P9-22** `secubox-picobrew` — Homebrew controller ✅

---

## ✅ PHASE 10 — Security Extensions (10 modules) — COMPLETE

Advanced security features:

- [x] **P10-01** `secubox-wazuh` — SIEM integration ✅
- [x] **P10-02** `secubox-ai-insights` — ML threat detection ✅
- [x] **P10-03** `secubox-ipblock` — IP blocklist manager ✅
- [x] **P10-04** `secubox-interceptor` — Traffic interception ✅
- [x] **P10-05** `secubox-cookies` — Cookie analysis ✅
- [x] **P10-06** `secubox-mac-guard` — MAC address control ✅
- [x] **P10-07** `secubox-dns-provider` — DNS API (OVH, Gandi) ✅
- [x] **P10-08** `secubox-threats` — Threat dashboard ✅
- [x] **P10-09** `secubox-openclaw` — OSINT tool ✅
- [x] **P10-10** `secubox-netifyd` — DPI daemon ✅

---

## 🔄 PHASE 11 — Live USB Enhancements (v1.7.0)

### Remote UI / HyperPixel 2.1 Round
- [x] **P11-R01** USB OTG composite gadget (ECM + ACM)
- [x] **P11-R02** TransportManager with OTG/WiFi failover
- [x] **P11-R03** install_zerow.sh with safe device check
- [x] **P11-R04** Fix vc4-kms-v3d conflict with HyperPixel
- [x] **P11-R05** Bookworm userconf file for pi:raspberry
- [x] **P11-R06** usb0-up.sh bypass NetworkManager
- [x] **P11-R07** Test HyperPixel display on real hardware ✅ v1.10.0
  - Fixed: dtoverlay=hyperpixel2r (not hyperpixel4)
  - Fixed: hyperpixel2r-init uses pigpio instead of RPi.GPIO (lgpio issues on Bookworm)
  - Fixed: Service dependencies (requires pigpiod)
- [x] **P11-R08** Display verified working after reboot ✅
- [x] **P11-R09** Framebuffer dashboard for Pi Zero W ✅ v1.11.0
  - Pi Zero W (ARMv6) lacks NEON SIMD required by Chromium
  - Created Python PIL-based framebuffer dashboard (fb_dashboard.py)
  - Renders directly to /dev/fb0 without X11
  - 6 circular module rings with animated metrics
  - Auto-starts via secubox-fb-dashboard.service

### Kiosk Mode
- [ ] **P11-01** Display SecuBox version in kiosk mode header/footer
- [ ] **P11-02** Show current authentication mode (ZKP/standard) in kiosk UI
- [ ] **P11-03** Add boot mode indicator (kiosk/console/bridge) on splash

### Authentication Feedback
- [ ] **P11-04** Visual feedback for auth mode in portal login page
- [ ] **P11-05** Auth mode toggle in system settings
- [ ] **P11-06** ZKP status indicator in dashboard

### Boot Experience
- [ ] **P11-07** Plymouth theme with version number
- [ ] **P11-08** GRUB menu version display
- [ ] **P11-09** Boot mode selection with descriptions

---

> **Reference**: See [REMAINING-PACKAGES.md](REMAINING-PACKAGES.md) for detailed inventory with complexity classification
