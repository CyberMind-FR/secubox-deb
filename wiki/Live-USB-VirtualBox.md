<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔴 Live image → VirtualBox — Quick Start

Test SecuBox (Alpha3, `v3.0.0-alpha`) on VirtualBox in minutes. The helper
`image/create-vbox-vm.sh` downloads the live amd64 image from the GitHub
releases, converts it, and creates + starts the VM — one command.

## Prerequisites

- **VirtualBox 7.0+**
- `gh` (GitHub CLI) *or* `curl`/`wget` — for `--download`
- ~8 GB free disk, 4 GB RAM

## Quick start (recommended — one command)

```bash
git clone https://github.com/CyberMind-FR/secubox-deb.git
cd secubox-deb

# Downloads the latest release's secubox-live-amd64 image, builds + starts the VM:
bash image/create-vbox-vm.sh --download

# …or pin a specific pre-release:
bash image/create-vbox-vm.sh --download v3.0.0-alpha.1
```

That's it. The script converts the image to VDI, creates an EFI VM named
`SecuBox-Live` (4 GB RAM, 4 vCPU), wires NAT port-forwarding, and boots it.

Useful flags (see `--help`): `--headless`, `-m/--memory MB`, `-c/--cpus N`,
`-s/--ssh PORT`, `-w/--https PORT`, `-n/--name NAME`, `--no-start`,
`-f/--force` (recreate an existing VM).

### Already have an image?

```bash
# Pass an explicit .img / .img.gz / .vdi (skips the download):
bash image/create-vbox-vm.sh output/secubox-live-amd64-bookworm.img
# With no argument it picks the newest secubox-live-amd64-*.img* in output/.
```

Build one yourself instead of downloading: `sudo bash image/build-image.sh
--board vm-x64 --local-cache` (see **[[Build-System]]**).

## Access

Wait ~30–60 s for first boot (firstboot generates the JWT, sets up SSH), then:

| Access | Default | Notes |
|--------|---------|-------|
| **SSH** | `ssh -p 2222 root@localhost` | host 2222 → guest 22 |
| **Portal (HTTPS)** | `https://localhost:9443` | host 9443 → guest 443 |
| **HTTP** | `http://localhost:8080` | host 8080 → guest 80 |

Portal master accounts: **gk2** (host) / **admin** (management). The live image
also ships a default root password for SSH — see the release notes for the
current value.

## Manual VirtualBox commands (fallback)

If you prefer to drive `VBoxManage` yourself:

```bash
# 1) Get + extract the image
gh release download v3.0.0-alpha.1 -p 'secubox-live-amd64-bookworm.img.gz'
gunzip secubox-live-amd64-bookworm.img.gz

# 2) Convert to VDI
VBoxManage convertfromraw secubox-live-amd64-bookworm.img secubox-live.vdi --format VDI

# 3) Create + configure (EFI, NAT port-forwards)
VM="SecuBox-Live"
VBoxManage createvm --name "$VM" --ostype Debian_64 --register
VBoxManage modifyvm "$VM" \
    --memory 4096 --cpus 4 --vram 128 \
    --graphicscontroller vmsvga --firmware efi --boot1 disk --nic1 nat \
    --natpf1 "SSH,tcp,,2222,,22" \
    --natpf1 "HTTPS,tcp,,9443,,443" \
    --natpf1 "HTTP,tcp,,8080,,80"
VBoxManage storagectl "$VM" --name SATA --add sata --controller IntelAhci
VBoxManage storageattach "$VM" --storagectl SATA --port 0 --device 0 \
    --type hdd --medium "$(realpath secubox-live.vdi)"

# 4) Start (drop --type gui for headless, or use --type headless)
VBoxManage startvm "$VM" --type gui
```

## Troubleshooting

**VM won't boot / black screen** — try legacy BIOS instead of EFI:

```bash
VBoxManage modifyvm "SecuBox-Live" --firmware bios
```

**Port already in use** — pick other host ports at creation time:

```bash
bash image/create-vbox-vm.sh --download --ssh 2223 --https 9444
```

**Graphics glitches** — switch controller / disable 3D:

```bash
VBoxManage modifyvm "SecuBox-Live" --graphicscontroller vboxsvga --accelerate3d off
```

**Check services once booted:**

```bash
ssh -p 2222 root@localhost
systemctl status 'secubox-*' --no-pager | head
```

## Cleanup

```bash
VBoxManage controlvm "SecuBox-Live" poweroff 2>/dev/null || true
VBoxManage unregistervm "SecuBox-Live" --delete
rm -f secubox-live.vdi secubox-live-amd64-bookworm.img
```

## See also

- **[[Home]]** — landing + quick start (all targets)
- **[[Installation]]** — full install guide (APT, Live USB, ARM)
- **[[QEMU-ARM64]]** — emulated arm64 VM (dev)
- **[[Build-System]]** — build images from source
- **[[Hardware-Matrix]]** — BYOH compatibility by board/SoC
