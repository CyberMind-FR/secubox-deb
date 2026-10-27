<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox

<p align="center">
  <img src="docs/assets/secubox-eyemote-banner.svg" alt="SecuBox — Network Security Appliance" width="800">
</p>

<p align="center"><b>Your network security appliance — plug it in, own your data, sleep at night.</b></p>

<p align="center">
  <a href="https://github.com/CyberMind-FR/secubox-deb/releases"><img src="https://img.shields.io/github/v/release/CyberMind-FR/secubox-deb?label=Release&logo=github" alt="Release"></a>
  <a href="https://github.com/CyberMind-FR/secubox-deb/actions/workflows/build-packages.yml"><img src="https://github.com/CyberMind-FR/secubox-deb/actions/workflows/build-packages.yml/badge.svg" alt="Packages"></a>
  <a href="https://github.com/CyberMind-FR/secubox-deb/actions/workflows/build-all-live-usb.yml"><img src="https://github.com/CyberMind-FR/secubox-deb/actions/workflows/build-all-live-usb.yml/badge.svg" alt="Live USB"></a>
  <a href="LICENCE-CMSD-1.0.md"><img src="https://img.shields.io/badge/License-CMSD--1.0-gold.svg" alt="License CMSD-1.0"></a>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-profiles">Profiles</a> ·
  <a href="#-quick-demo">Quick Demo</a> ·
  <a href="#-quick-deploy">Quick Deploy</a> ·
  <a href="https://github.com/CyberMind-FR/secubox-deb/wiki">Docs</a> ·
  <a href="https://github.com/CyberMind-FR/secubox-deb/wiki/Roadmap">Roadmap</a> ·
  <a href="#-contributing">Contributing</a>
</p>

---

<p align="center">
  <img src="docs/assets/poster/secubox-affiche-bilingue.jpg" alt="SecuBox — Reprenez le contrôle de votre réseau. Your network. Your rules." width="900">
</p>
<p align="center"><sub>Affiche illustrative · Illustrative poster. Les fonctions et l'interface représentées ne sont pas toutes au même niveau de maturité : voir « <a href="#-where-we-are">Où en est-on ? / Where we are</a> ».</sub></p>

**FR 🇫🇷** SecuBox est un projet de sécurité réseau et d'hébergement souverain, construit sur Debian 13 Trixie. Son ambition : rendre les outils de sécurité et d'autonomie numérique accessibles aux particuliers, aux associations et aux petites organisations. Le projet dispose déjà de briques fonctionnelles et d'un prototype opérationnel ; certains composants sont utilisables, d'autres continuent d'évoluer. **Tester · Contribuer · Échanger · Partager.**

**EN 🇬🇧** SecuBox is a network security and sovereign hosting project built on Debian 13 Trixie. Its ambition is to make digital security and autonomy more accessible to individuals, associations and small organizations. A working prototype and functional components already exist; some are usable, others remain under active development. **Test · Contribute · Discuss · Share.**

SecuBox turns a small ARM board — or any x86 PC — into a complete, self-hosted
security appliance: firewall, VPN, intrusion detection, WAF, DNS filtering and a
suite of sovereign services, all behind one web dashboard. It runs on **Debian 13 (Trixie)**, the base
of SecuBox from alpha 9 ([#1294](https://github.com/CyberMind-FR/secubox-deb/issues/1294)).
Packages are built as `~trixie1` and published in the `trixie` suite of
`apt.secubox.in`.

## Why SecuBox

- **Your hardware, your rules.** Everything runs on the box you own. No cloud
  account, no telemetry, no third-party cookie ever leaves the appliance.
- **Whole stack, one install.** About 110 packages (plus 57 meta-packages for profiles, services and functions)
  covering security, networking, applications and operations — instead of a weekend of glue work.
- **Sized to the machine.** Three profiles, from a 2 GB board to a full home
  server, each installing only what that machine can carry.
- **Runs on what you already have.** Raspberry Pi, ESPRESSObin, MOCHAbin,
  a repurposed laptop, or a VM on your desktop.
- **Auditable by design.** Source-disclosed licence, modular `ctl` grammar,
  every module documented.

## Key features

| | |
|---|---|
| 🛡️ **Firewall & WAF** | nftables with a default-drop policy, and `sbxwaf` in front of every web service — pattern detected → kernel drop, no third-party service in the path |
| 🔐 **VPN** | WireGuard with QR-code enrolment for phones |
| 🧹 **Ad blocking** | `ad-guard` removes ads and trackers at the DNS level for TVs, streamers and other devices, per device |
| 👨‍👩‍👧 **Web filtering** | `webfilter` classifies DNS queries (adult, gambling, phishing/malware) and can block them per device and per profile. It starts in observe-only mode: nothing is blocked until you choose |
| 🚨 **Intrusion detection** | HTTP, SSH, SMTP and IMAP watched together — `sbxwaf` + `sbx-authwatch` feed one ban set |
| 📊 **Web dashboard** | One interface for the whole box, from any browser |
| ☁️ **Sovereign services** | Nextcloud, mail, Gitea, Jellyfin, PeerTube, radio, blog publishing… each in its own LXC container |
| 🔄 **Automatic updates** | Security patches applied on their own |
| 🎭 **Decoy & watermark** | Unrouted hosts and bait paths get a plausible, inert page — watermarked, so a fake credential replayed later is recognised as ours. Learning only: no bans follow |
| 🧬 **Actor intelligence** | Scanners correlated across addresses and countries; a walking subdomain dictionary is regrouped into one campaign instead of dozens of fragments |

> A visual tour of the dashboard lives in the
> [wiki gallery](https://github.com/CyberMind-FR/secubox-deb/wiki/MODULES-EN).

---

## 🧭 Where we are

*State on 2026-10-19. SecuBox is neither certified nor ready for every use: CSPN (ANSSI) certification is a goal, not an achievement.*

| Level | Components | Note |
|---|---|---|
| **Usable** (running on an infrastructure box) | Admin web UI, default-drop nftables firewall, `sbxwaf` WAF behind HAProxy TLS 1.3, DNS and ad filtering, WireGuard and peer-to-peer mesh, LXC services (mail, files, chat, code hosting, media) | Tested on MOCHAbin and x86. Updates are still frequent. |
| **Being tested** | DPI classification (nDPId), self-provisioning of boards (Auto-Load), the `minimal` profile for 1 GB boards (ESPRESSObin) | DPI is memory-hungry and its output is not proof of an attack. On 1 GB the WAF and HAProxy saturate the board, so `minimal` leaves them out. |
| **Design only** | Zone-based firewall (per port and per device), automatic peering of freshly prepared boards | Not coded or not deployed yet. |

## ⚡ Quick Start

**Fastest path — a VM on your own machine, no hardware needed.**

```bash
git clone https://github.com/CyberMind-FR/secubox-deb.git
cd secubox-deb
./image/create-vbox-vm.sh --download      # downloads the latest amd64 image, creates & boots the VM
```

Then open **https://localhost:9443** and log in with `admin` / `secubox`.

> Change that password before the box ever sees a network it does not own.

Prefer QEMU on an ARM host? Use
[`create-qemu-arm64-vm.sh`](https://github.com/CyberMind-FR/secubox-deb/releases/latest)
from the release assets.

## 🧩 Profiles

A **profile** decides which modules are installed; a **tier** decides what the
machine can carry. Pick the profile that matches your hardware and your needs.

| | **lite** | **isp** | **full** |
|---|---|---|---|
| For | Protection only, 2 GB RAM | A protected layer with simple, limited hosting, 4 GB and up | The whole current fleet, like the reference box, 8 GB and up |
| Includes | Firewall, WAF (`sbxwaf`), DPI, MITM engine (`sbxmitm`), ad-guard, webfilter, threat detection, anti-rootkit, access control, WireGuard | lite + routing, QoS, certificates, Tor, mesh, supervision, simple site hosting (`metablogizer`, `publish`) | isp + every module of the reference box: Nextcloud, Gitea, Jellyfin, PeerTube, mail, radio, Zigbee, AI, voice… |
| Typical machine | ESPRESSObin | Raspberry Pi 400, MOCHAbin, x86 PC | MOCHAbin, x86 PC |

<p align="center"><img src="docs/assets/secubox-profils-infographie.jpg" alt="SecuBox: choose your protection level — lite, isp, full" width="800"></p>

A fourth profile, **minimal**, is sized for a 1 GB board (ESPRESSObin): DPI, DNS guard, ad-guard, access control (NAC), Freebox, IPv6 guard, web filter, WireGuard
and the admin WebUI only. No WAF (it stays on the infrastructure), no Hall, no hosted service. Measured on a real ESPRESSObin: the 951 MB leave little room, which is why the WAF
and HAProxy were tried and removed. Step-by-step install: [docs/INSTALL-ESPRESSOBIN.md](docs/INSTALL-ESPRESSOBIN.md); field notes: [docs/FAQ-ESPRESSOBIN-1GO.md](docs/FAQ-ESPRESSOBIN-1GO.md).

Side-by-side table, glossary and a popularisation prompt:
[docs/PROFILS-COMPARATIF.md](docs/PROFILS-COMPARATIF.md).

**Validating a fleet.** The *Profile comparison* page (`/profiles/comparatif.html#parc`) has a second tab, *Fleet
validation*, that shows what really runs on every box of the WireGuard mesh: one row per SecuBox package, one column
per box, and four levels per cell — expected by that box's profile, package and version, services (systemd units and
modules served by the aggregator), and memory/CPU actually used. Each box records its own state every 5 minutes and
signs it with its Ed25519 key; the page only displays what the boxes signed, flags version mismatches and errors, and
names any box whose record cannot be read. Read-only. Guide (French):
[wiki — Valider un parc](https://github.com/CyberMind-FR/secubox-deb/wiki/Valider-un-parc).

## 📘 Official AMD64 Installation

Install and reproduce the GK2 development box on an AMD64 PC, VirtualBox,
KVM or QEMU: [Official AMD64 GK2 Clone installation guide](docs/INSTALL-AMD64-GK2.md).

## 🎬 Quick Demo

**Boot it from a USB stick on any x86_64 PC — nothing is written to the disk.**

Download the live image from the
[latest release](https://github.com/CyberMind-FR/secubox-deb/releases/latest),
then write it to a USB stick:

```bash
zcat secubox-live-amd64-trixie.img.gz | sudo dd of=/dev/sdX bs=4M status=progress   # /dev/sdX = your USB device
```

Boot from the stick, then reach the dashboard at `https://<device-ip>/`.
Full walkthrough and troubleshooting: [Live USB](https://github.com/CyberMind-FR/secubox-deb/wiki/Live-USB).

## 🚀 Quick Deploy

**For 24/7 operation on dedicated hardware.** Image names follow
`secubox-<profile>-<board>-<suite>` — check the release assets for what a given
release actually ships.

| Target | Best for | Image (release asset) | Suite |
|---|---|---|---|
| VirtualBox / QEMU | Lab & demo | `secubox-full-vm-x64-trixie.img.gz` (also `isp`) | Debian 13 |
| Raspberry Pi 4 / 400 | Desktop appliance, kiosk | `secubox-full-rpi-arm64-trixie.img.gz` (also `lite`, `isp`) | Debian 13 |
| Any x86_64 PC | Repurposed hardware | `secubox-live-amd64-trixie.img.gz` (live) | Debian 13 |
| Any x86_64 PC | Permanent install — **headless auto-install** to the first disk | `secubox-installer-amd64-trixie.iso.gz` or `.img.gz` | Debian 13 |
| MOCHAbin | Enterprise | `secubox-lite-mochabin-trixie.img.gz`, `secubox-isp-mochabin-trixie.img.gz`, or the live stick `secubox-mochabin-live-usb.img.gz` | Debian 13 |
| ESPRESSObin v7 | Small gateway (1 GB: use the `minimal` profile) | `secubox-lite-espressobin-v7-trixie.img.xz` (1.7 GB compressed) | Debian 13 |

Large images are split into `.part00`, `.part01`… in the release: join them before use
(`cat secubox-full-vm-x64-trixie.img.gz.part* > secubox-full-vm-x64-trixie.img.gz`) and check the result
against the matching `.assembled.sha256`.

The profile genuinely selects which modules are installed. An ESPRESSObin
image is written to a microSD card (or a USB stick); `secubox-install-emmc` then copies the
running system to the eMMC and refuses clearly if it does not fit (4 GB eMMC:
lite yes, isp maybe not).

Flashing, U-Boot and first-boot steps:
[Installation](https://github.com/CyberMind-FR/secubox-deb/wiki/Installation) ·
[ARM / U-Boot](https://github.com/CyberMind-FR/secubox-deb/wiki/ARM-Installation) ·
[Supported hardware](https://github.com/CyberMind-FR/secubox-deb/wiki/Hardware)

### 🧪 Current release: `v3.0.0-alpha.19`

Published 2026-10-27. This is a **pre-release line**: run it on a test box, not on the link your
household depends on. Since alpha 18, the main changes are:

- **MOCHAbin as a real router.** Durable router mode (bridge `br-lan` under systemd-networkd, LAN DHCP, the box's
  DNS with filtering and ad-guard, NAT, firewall), applied without ever restarting the mvpp2 WAN, with an automatic
  rollback when not confirmed within 3 minutes (#3189). A « Réseau » panel maps WAN, mesh, tunnels, containers,
  switch and clients (#3190); a port can be isolated into its own network (#3201); trusted routed LAN (#3206).
- **WireGuard mesh.** New boxes join automatically under their own name, a node without WAN is relayed, and a
  wildcard DNS record is created at the registrar for each new node.
- **Hall « master view »** (Hall v2) is the default.
- **Services.** Video conferencing (La Suite Meet), an App-Store-like shop, mail (external IMAP fetch, local relay,
  webmail), SMB shares (ksmbd), podcaster portal and RSS, backups on `/data`, OVH DNS management.
- **Debian stock kernel 6.12.113** on MOCHAbin (WAN and switch handled by the initrd), TFTP netboot and eMMC flash
  from the live system.

Images: `lite` (ESPRESSObin v7, MOCHAbin, RPi 400), `isp` (MOCHAbin, RPi 400, VM x64), `full` (RPi 400, VM x64),
x64 live, the installer, and `minimal` (ESPRESSObin v7, RPi 400, rebuilt from master after the tag, #3223); the
MOCHAbin live USB is missing this time, its build now exceeds GitHub's 6-hour job limit (#3225).
Guided path: first section of the [wiki home](https://github.com/CyberMind-FR/secubox-deb/wiki).

### Verifying downloads

Every release ships `SHA256SUMS`. Always check before flashing:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

---

## 📚 Documentation

| | |
|---|---|
| [Wiki home](https://github.com/CyberMind-FR/secubox-deb/wiki) | Portal — every guide starts here |
| [Configuration](https://github.com/CyberMind-FR/secubox-deb/wiki/Configuration) | First-boot settings, network modes |
| [Modules](https://github.com/CyberMind-FR/secubox-deb/wiki/MODULES-EN) | Every module, one by one |
| [API reference](https://github.com/CyberMind-FR/secubox-deb/wiki/API-Reference) | 2000+ endpoints |
| [Architecture](https://github.com/CyberMind-FR/secubox-deb/wiki/Modules-Architecture) | The 6-layer model |
| [Troubleshooting](https://github.com/CyberMind-FR/secubox-deb/wiki/Troubleshooting) | When it does not boot |
| [ESPRESSObin install](docs/INSTALL-ESPRESSOBIN.md) | Nine steps from a bare board to a box attached to the infrastructure |
| [Project overview](docs/PROJECT-OVERVIEW.md) | Long form: flagship programmes, release history, CTL grammar |
| [Cryptographic policy](docs/POLITIQUE-CRYPTO.md) | Which algorithms, why, and the two protocol-imposed exceptions — the reference document for CSPN evaluation |
| [Aurora design reference](.claude/AURORA-REFERENCE.md) | The shared style of the admin web panels: tokens, structure, data-honesty rules, iframe height protocol, tests. [Gallery of every page](docs/aurora/README.md) (demo captures, regenerated by `scripts/snapshots-aurora.py`) |

## 🤝 Contributing

Issues and pull requests are welcome at
[CyberMind-FR/secubox-deb](https://github.com/CyberMind-FR/secubox-deb/issues).
Read [Module guidelines](docs/MODULE-GUIDELINES.md) first — module layout and
the `ctl` grammar are conventions, not suggestions.
Hardware test reports go to
[Board feedback](https://github.com/CyberMind-FR/secubox-deb/wiki/Board-Feedback).

## 📄 License

**CyberMind Source-Disclosed License (CMSD-1.0)** — the source is published and
auditable; redistribution and commercial use are restricted. Full terms in
[LICENCE-CMSD-1.0.md](LICENCE-CMSD-1.0.md).

---

<p align="center"><sub>SecuBox — CyberMind · Your services. Your hardware. Your rules.</sub></p>
