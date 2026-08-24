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
  <a href="#-quick-demo">Quick Demo</a> ·
  <a href="#-quick-deploy">Quick Deploy</a> ·
  <a href="https://github.com/CyberMind-FR/secubox-deb/wiki">Docs</a> ·
  <a href="https://github.com/CyberMind-FR/secubox-deb/wiki/Roadmap">Roadmap</a> ·
  <a href="#-contributing">Contributing</a>
</p>

---

SecuBox turns a small ARM board — or any x86 PC — into a complete, self-hosted
security appliance running on Debian bookworm: firewall, VPN, intrusion
detection, WAF, and a suite of sovereign services, all behind one web dashboard.

## Why SecuBox

- **Your hardware, your rules.** Everything runs on the box you own. No cloud
  account, no telemetry, no third-party cookie ever leaves the appliance.
- **Whole stack, one install.** 124 packages covering security, networking,
  applications and operations — instead of a weekend of glue work.
- **Runs on what you already have.** Raspberry Pi, ESPRESSObin, MOCHAbin,
  a repurposed laptop, or a VM on your desktop.
- **Auditable by design.** Source-disclosed licence, modular `ctl` grammar,
  every module documented.

## Key features

| | |
|---|---|
| 🛡️ **Firewall & WAF** | nftables + active enforcement — pattern detected → CrowdSec → kernel drop in ~12s |
| 🔐 **VPN** | WireGuard with QR-code enrolment for phones |
| 🚨 **Intrusion detection** | CrowdSec IDS/IPS with automatic blocking |
| 📊 **Web dashboard** | One interface for the whole box, from any browser |
| ☁️ **Sovereign services** | Nextcloud, mail, Gitea, Jellyfin, PeerTube, radio, forum… |
| 🔄 **Automatic updates** | Security patches applied on their own |

> A visual tour of the dashboard lives in the
> [wiki gallery](https://github.com/CyberMind-FR/secubox-deb/wiki/UI-COMPARISON).

---

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

## 🎬 Quick Demo

**Boot it from a USB stick on any x86_64 PC — nothing is written to the disk.**

```bash
# The bootable live image currently ships with the Alpha 3 pre-release
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/v3.0.0-alpha.1/secubox-live-amd64-bookworm.img.gz
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress   # /dev/sdX = your USB device
```

Boot from the stick, then reach the dashboard at `https://<device-ip>/`.
Full walkthrough and troubleshooting: [Live USB](https://github.com/CyberMind-FR/secubox-deb/wiki/Live-USB).

> On the stable line (`v2.41.0`) the published image is the **installer**
> (`secubox-installer-amd64-bookworm.iso.gz`), which writes to disk rather than
> running live.

## 🚀 Quick Deploy

**For 24/7 operation on dedicated hardware.**

| Target | Best for | Published image |
|---|---|---|
| Any x86_64 PC | Repurposed hardware | `secubox-live-amd64-bookworm.img.gz` (live) |
| Any x86_64 PC | Permanent install | `secubox-installer-amd64-bookworm.iso.gz` |
| MOCHAbin | Enterprise | `secubox-mochabin-live-usb.img.gz` |
| VirtualBox / QEMU | Lab & demo | `secubox-full-vm-x64-bookworm.img.gz` |

> ESPRESSObin and Raspberry Pi are supported targets, but their images are not
> in the current release assets — build them from source
> ([Building](https://github.com/CyberMind-FR/secubox-deb/wiki/Building)) or
> check the [releases page](https://github.com/CyberMind-FR/secubox-deb/releases)
> for a later build.

Flashing, U-Boot and first-boot steps:
[Installation](https://github.com/CyberMind-FR/secubox-deb/wiki/Installation) ·
[ARM / U-Boot](https://github.com/CyberMind-FR/secubox-deb/wiki/ARM-Installation) ·
[Supported hardware](https://github.com/CyberMind-FR/secubox-deb/wiki/Hardware)

### 🧪 Testing Alpha 3

`v3.0.0-alpha.1` is the current pre-release — 124 packages, disk images and
Live USB builds for every supported board. It is a **pre-release**: run it on a
test box, not on the link your household depends on.
Guided path: [**Démarrage rapide Alpha3**](https://github.com/CyberMind-FR/secubox-deb/wiki) —
VM in one command, or real arm64 hardware — first section of the wiki home.

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
| [Modules](https://github.com/CyberMind-FR/secubox-deb/wiki/MODULES-EN) | The 124 packages, one by one |
| [API reference](https://github.com/CyberMind-FR/secubox-deb/wiki/API-Reference) | 2000+ endpoints |
| [Architecture](https://github.com/CyberMind-FR/secubox-deb/wiki/Modules-Architecture) | The 6-layer model |
| [Troubleshooting](https://github.com/CyberMind-FR/secubox-deb/wiki/Troubleshooting) | When it does not boot |
| [Project overview](docs/PROJECT-OVERVIEW.md) | Long form: flagship programmes, release history, CTL grammar |

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
