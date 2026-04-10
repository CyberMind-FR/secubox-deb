# SecuBox-DEB Image Scripts

This directory contains all scripts for building bootable SecuBox images and managing deployments.

---

## Quick Reference

| Script | Purpose | Target |
|--------|---------|--------|
| `build-image.sh` | Build raw disk image | ARM64 boards / x64 VM |
| `build-live-usb.sh` | Build live USB image | x64 (amd64) |
| `build-installer-iso.sh` | Build hybrid ISO installer | x64 (amd64) |
| `build-rpi-usb.sh` | Build Raspberry Pi image | Raspberry Pi 400 |
| `build-c3box-clone.sh` | Clone existing C3Box device | x64 (amd64) |
| `export-c3box-clone.sh` | Export device configuration | Any SecuBox device |
| `create-vbox-vm.sh` | Create VirtualBox VM | x64 (amd64) |
| `firstboot.sh` | First boot initialization | All platforms |
| `preseed-apply.sh` | Apply preseed configuration | All platforms |

---

## Main Build Scripts

### build-image.sh

Build a flashable disk image for ARM64 boards or x64 VMs using debootstrap.

**Usage:**
```bash
sudo bash image/build-image.sh [OPTIONS]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--board BOARD` | Target board | `mochabin` |
| `--suite SUITE` | Debian suite | `bookworm` |
| `--out DIR` | Output directory | `./output` |
| `--size SIZE` | Image size | `4G` |
| `--vdi` | Also create VDI (VirtualBox) | - |
| `--local-cache` | Use local APT cache | - |
| `--slipstream` | Include local .deb packages | - |
| `--keep-rootfs` | Keep rootfs after build | - |

**Supported Boards:**
- `mochabin` - Marvell Armada 7040 (arm64) - SecuBox Pro
- `espressobin-v7` - Marvell Armada 3720 (arm64) - SecuBox Lite
- `espressobin-ultra` - Marvell Armada 3720 (arm64) - SecuBox Lite+
- `vm-x64` - VirtualBox/QEMU (amd64) - Test/Dev
- `vm-arm64` - QEMU virt (arm64) - Test/Dev ARM64

**Examples:**
```bash
# Build for MochaBin
sudo bash image/build-image.sh --board mochabin

# Build x64 VM with VDI conversion
sudo bash image/build-image.sh --board vm-x64 --vdi

# Build with local packages
sudo bash image/build-image.sh --board vm-x64 --slipstream --local-cache
```

**Output:**
- `output/secubox-<board>-<suite>.img.gz` - Compressed disk image
- `output/secubox-<board>-<suite>.vdi` - VirtualBox disk (if `--vdi`)
- `output/secubox-<board>-<suite>.qcow2` - QEMU disk (if vm-arm64)

---

### build-live-usb.sh

Build a bootable live USB image for x64 systems with UEFI + Legacy BIOS hybrid boot.

**Usage:**
```bash
sudo bash image/build-live-usb.sh [OPTIONS]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--suite SUITE` | Debian suite | `bookworm` |
| `--out DIR` | Output directory | `./output` |
| `--size SIZE` | Image size | `8G` |
| `--local-cache` | Use local APT cache | - |
| `--no-kiosk` | Disable GUI kiosk mode | Kiosk enabled |
| `--no-persistence` | No persistent storage partition | Persistence enabled |
| `--no-compress` | Skip gzip compression | - |
| `--preseed FILE` | Include preseed config archive | - |

**Features:**
- UEFI + Legacy BIOS boot support
- All SecuBox packages pre-installed
- Root autologin on console
- Network auto-detection at boot
- GUI kiosk mode (Chromium fullscreen)
- VT100/DEC PDP-style cyber boot splash
- Plymouth graphical boot theme
- Persistent storage partition

**Boot Options (GRUB Menu):**
- SecuBox Live - Standard boot
- SecuBox Live (Kiosk GUI) - GUI kiosk mode
- SecuBox Live (Bridge Mode) - Network bridge mode
- SecuBox Live (Safe Mode) - No GPU acceleration
- SecuBox Live (To RAM) - Load entire system to RAM
- SecuBox Live (Auto-Check HW) - Hardware check on boot
- SecuBox Live (Emergency Shell) - Systemd emergency target
- SecuBox Live (Debug) - Verbose boot with breakpoints

**Example:**
```bash
# Build live USB with kiosk mode
sudo bash image/build-live-usb.sh --local-cache

# Flash to USB drive
zcat output/secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

**Output:**
- `output/secubox-live-amd64-<suite>.img.gz` - Compressed bootable image

---

### build-installer-iso.sh

Build a hybrid ISO that can boot live or perform headless installation.

**Usage:**
```bash
sudo bash image/build-installer-iso.sh [OPTIONS]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--suite SUITE` | Debian suite | `bookworm` |
| `--out DIR` | Output directory | `./output` |
| `--name NAME` | ISO name prefix | `secubox-installer` |
| `--local-cache` | Use local APT cache | - |
| `--slipstream` | Include local .deb packages | Enabled |
| `--no-slipstream` | Don't include local packages | - |
| `--live-only` | Only live mode, no installer | - |
| `--preseed FILE` | Include preseed config | - |

**Boot Options:**
- **SecuBox Live** - Boot live system, test before installing
- **SecuBox Install (Headless)** - Auto-install to first disk
- **SecuBox Install (Expert)** - Interactive installation

**Headless Installation:**
The installer automatically:
1. Detects the first available disk (NVMe > SATA > VirtIO)
2. Creates GPT partitions (ESP + root + data)
3. Copies live system to disk
4. Installs GRUB bootloader
5. Reboots into installed system

**Example:**
```bash
# Build installer ISO
sudo bash image/build-installer-iso.sh --local-cache --slipstream

# Write to USB
sudo dd if=output/secubox-installer-amd64-bookworm.img of=/dev/sdX bs=4M status=progress

# Burn to CD/DVD
xorriso -as cdrecord -v dev=/dev/sr0 output/secubox-installer-amd64-bookworm.iso
```

**Output:**
- `output/secubox-installer-amd64-<suite>.iso` - Hybrid bootable ISO
- `output/secubox-installer-amd64-<suite>.img` - Raw USB image

---

### build-rpi-usb.sh

Build a bootable USB/SD image for Raspberry Pi 400.

**Usage:**
```bash
sudo bash image/build-rpi-usb.sh [OPTIONS]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--suite SUITE` | Debian suite | `bookworm` |
| `--out DIR` | Output directory | `./output` |
| `--size SIZE` | Image size | `8G` |
| `--local-cache` | Use local APT cache | - |
| `--kiosk` | Include GUI kiosk packages | - |
| `--no-compress` | Skip compression | - |

**Features:**
- Native Pi bootloader (no GRUB)
- ARM64 Debian with cross-compilation via QEMU
- Serial console enabled (for debugging)
- HDMI console with autologin
- VT100/DEC PDP-style boot splash
- Plymouth graphical boot theme

**Example:**
```bash
# Build Raspberry Pi image
sudo bash image/build-rpi-usb.sh --local-cache

# Flash to SD card or USB
zcat output/secubox-rpi-arm64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

**Output:**
- `output/secubox-rpi-arm64-<suite>.img.gz` - Compressed bootable image

---

## Cloning Scripts

### build-c3box-clone.sh

Build a complete clone image from an existing C3Box device.

**Usage:**
```bash
sudo bash image/build-c3box-clone.sh [OPTIONS]
```

**Connection Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--host HOST` | C3Box host | `localhost` / `$C3BOX_HOST` |
| `--port PORT` | SSH port | `2222` / `$C3BOX_PORT` |
| `--user USER` | SSH user | `root` / `$C3BOX_USER` |
| `--key FILE` | SSH private key | - |

**Build Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--out DIR` | Output directory | `./output` |
| `--suite SUITE` | Debian suite | `bookworm` |
| `--local-cache` | Use local APT cache | - |
| `--slipstream` | Include local .deb packages | Enabled |
| `--skip-export` | Use existing preseed | - |

**What Gets Cloned:**
- System configuration (`/etc/secubox/`)
- User accounts and SSH keys
- Network configuration (netplan, WireGuard)
- Service configurations (nginx, HAProxy, CrowdSec)
- SSL certificates (Let's Encrypt, custom)
- LXC container configs (optional)
- Data partition contents (optional)

**Example:**
```bash
# Clone from VM on port 2222
sudo bash image/build-c3box-clone.sh --host localhost --port 2222

# Clone from remote device
sudo bash image/build-c3box-clone.sh --host 192.168.1.100 --port 22

# Rebuild ISO from existing export
sudo bash image/build-c3box-clone.sh --skip-export
```

**Output:**
- `output/secubox-c3box-clone-amd64-<suite>.iso` - Bootable clone ISO
- `output/secubox-c3box-clone-amd64-<suite>.img` - USB image
- `output/c3box-clone-preseed.tar.gz` - Configuration archive

---

### export-c3box-clone.sh

Export configuration from a running C3Box device for cloning.

**Usage:**
```bash
sudo bash image/export-c3box-clone.sh [OPTIONS]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--host HOST` | C3Box host | `localhost` / `$C3BOX_HOST` |
| `--port PORT` | SSH port | `2222` / `$C3BOX_PORT` |
| `--user USER` | SSH user | `root` / `$C3BOX_USER` |
| `--key FILE` | SSH private key | - |
| `--out DIR` | Output directory | `./output` |
| `--name NAME` | Export name | `c3box-clone` |
| `--no-lxc` | Don't export LXC containers | - |
| `--no-data` | Don't export /data partition | - |

**Example:**
```bash
# Export from VM
bash image/export-c3box-clone.sh --host localhost --port 2222

# Use with build-installer-iso.sh
sudo bash image/build-installer-iso.sh --preseed output/c3box-clone-preseed.tar.gz
```

**Output:**
- `output/<name>-preseed.tar.gz` - Configuration archive
- `output/<name>-manifest.txt` - List of exported items

---

## VM Management

### create-vbox-vm.sh

Create a VirtualBox VM configured for SecuBox.

**Usage:**
```bash
bash image/create-vbox-vm.sh [OPTIONS] [IMAGE.vdi]
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--name NAME` | VM name | `SecuBox-Dev` |
| `--ram MB` | RAM in MB | `2048` |
| `--cpus N` | CPU count | `2` |

**Network Configuration:**
- Adapter 1: NAT (WAN - internet access)
- Adapter 2: Host-Only (LAN - 192.168.100.x)

**Example:**
```bash
# Create VM with existing VDI
bash image/create-vbox-vm.sh output/secubox-vm-x64-bookworm.vdi

# Create VM with custom settings
bash image/create-vbox-vm.sh --name MySecuBox --ram 4096 --cpus 4

# Start the VM
VBoxManage startvm SecuBox-Dev --type gui
```

---

## Boot & Initialization Scripts

### firstboot.sh

One-shot initialization script executed on first boot.

**Location:** Installed as `/usr/bin/secubox-firstboot`

**What It Does:**
1. Creates `secubox` system user
2. Sets up directories (`/etc/secubox/`, `/run/secubox/`, `/var/lib/secubox/`)
3. Configures hostname from `/boot/hostname` (if present)
4. Injects SSH keys from `/boot/authorized_keys`
5. Generates JWT secret for API authentication
6. Sets admin password (from `/boot/admin_password` or random)
7. Creates `/etc/secubox/secubox.conf` with detected board info
8. Generates self-signed TLS certificate
9. Enables nginx with SecuBox configuration
10. Runs network auto-detection
11. Configures nftables firewall (DEFAULT DROP)

**Systemd Service:**
```ini
[Unit]
Description=SecuBox First Boot Initialization
ConditionPathExists=!/var/lib/secubox/.firstboot_done
```

---

### preseed-apply.sh

Apply preseed configuration from a clone archive.

**Location:** Installed as `/usr/lib/secubox/preseed-apply.sh`

**What It Applies:**
1. SecuBox configuration (`/etc/secubox/`)
2. Network configuration (netplan, WireGuard)
3. User accounts and SSH keys
4. Service configurations (nginx, HAProxy, CrowdSec)
5. SSL certificates
6. Package list verification
7. Service restarts (skipped on live boot)

**Systemd Service:**
```ini
[Unit]
Description=SecuBox Preseed Configuration
ConditionPathExists=/usr/share/secubox/preseed.tar.gz
```

---

## Helper Scripts (sbin/)

### secubox-net-detect

Automatic network interface detection and configuration.

**Location:** `/usr/sbin/secubox-net-detect`

**Usage:**
```bash
secubox-net-detect {detect|apply|test} [mode]
```

**Commands:**
| Command | Description |
|---------|-------------|
| `detect` | Detect interfaces, output JSON |
| `apply MODE` | Generate and apply netplan |
| `test` | Test WAN connectivity |

**Network Modes:**
- `router` - WAN (DHCP) + LAN bridge (192.168.1.1/24)
- `bridge` - All interfaces bridged, DHCP
- `single` - WAN only, no bridge

**Board Detection:**
- Reads `/proc/device-tree/model` for ARM boards
- Reads `/sys/class/dmi/id/product_name` for x64
- Auto-detects VirtualBox, QEMU, VMware, KVM

**Interface Mapping:**
| Board | WAN | LAN |
|-------|-----|-----|
| mochabin | eth0 | eth1-eth4 + SFP eth5-eth6 |
| espressobin-v7 | eth0 | lan0, lan1 |
| espressobin-ultra | eth0 | lan0-lan3 |
| x64-vm | First with link | Others |

---

### secubox-cmdline-handler

Kernel command line parameter handler.

**Location:** `/usr/sbin/secubox-cmdline-handler`

**Usage:**
```bash
secubox-cmdline-handler {parse|apply}
```

**Supported Parameters:**
| Parameter | Values | Description |
|-----------|--------|-------------|
| `secubox.netmode=` | router/bridge/single | Network mode |
| `secubox.kiosk=` | 0/1 | Enable GUI kiosk |
| `secubox.debug=` | 0/1 | Enable debug mode |
| `secubox.hwcheck=` | 0/1 | Run hardware check |

**Example Boot Command:**
```
linux /live/vmlinuz boot=live secubox.netmode=bridge secubox.kiosk=1
```

---

### secubox-kiosk-setup

GUI kiosk mode configuration tool.

**Location:** `/usr/sbin/secubox-kiosk-setup`

**Usage:**
```bash
secubox-kiosk-setup {install|enable|disable|console|no-console|status} [--x11|--wayland]
```

**Commands:**
| Command | Description |
|---------|-------------|
| `install` | Install GUI packages |
| `enable` | Enable kiosk autostart |
| `disable` | Disable kiosk (console) |
| `console` | Enable console TUI mode |
| `no-console` | Disable console TUI |
| `status` | Show current mode |

**Display Modes:**
- **X11** (default) - Better VM compatibility, uses `startx`
- **Wayland** - Native performance, uses Cage compositor

**Features:**
- Fullscreen Chromium displaying SecuBox WebUI
- Cursor hidden after 3 seconds
- Screen blanking disabled
- Console access on TTY2 (Ctrl+Alt+F2)
- Connects to `https://localhost/` (works without network)

**Example:**
```bash
# Install and enable kiosk
secubox-kiosk-setup install --x11
secubox-kiosk-setup enable

# Check status
secubox-kiosk-setup status

# Switch to console TUI
secubox-kiosk-setup console
```

---

## Systemd Services (systemd/)

| Service | Description |
|---------|-------------|
| `secubox-net-detect.service` | Network auto-detection |
| `secubox-cmdline.service` | Kernel cmdline handler |
| `secubox-kiosk.service` | GUI kiosk mode (TTY7) |
| `secubox-kiosk-wayland.service` | Wayland kiosk variant |
| `secubox-firstboot.service` | First boot initialization |
| `secubox-preseed.service` | Preseed application |

---

## Default Credentials

| Access | Username | Password |
|--------|----------|----------|
| SSH / Console | root | secubox |
| SSH / Console | secubox | secubox |
| Web UI | admin | admin (or generated) |

**Note:** On first boot, if no `/boot/admin_password` file is present, a random password is generated and saved to `/boot/admin_password_generated.txt`.

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `C3BOX_HOST` | Clone target host | localhost |
| `C3BOX_PORT` | Clone target SSH port | 2222 |
| `C3BOX_USER` | Clone target SSH user | root |

---

## Local Cache Setup

For faster builds, set up local APT cache:

```bash
# Setup apt-cacher-ng and local repo
sudo bash scripts/setup-local-cache.sh

# Build with local cache
sudo bash image/build-live-usb.sh --local-cache
```

Cache endpoints:
- APT Cache: `http://127.0.0.1:3142`
- SecuBox Repo: `http://127.0.0.1:8080`

---

## Troubleshooting

### Boot Issues

1. **Black screen on boot:**
   - Use Safe Mode from GRUB menu
   - Add `nomodeset` to kernel parameters

2. **No network after boot:**
   - Check `journalctl -u secubox-net-detect`
   - Run `/usr/sbin/secubox-net-detect detect` manually

3. **Kiosk not starting:**
   - Check `systemctl status secubox-kiosk`
   - Verify `/var/lib/secubox/.kiosk-enabled` exists
   - Access console via TTY2 (Ctrl+Alt+F2)

### Build Issues

1. **Debootstrap fails:**
   - Check network connectivity
   - Try `--local-cache` with apt-cacher-ng

2. **Cross-compilation issues (ARM on x64):**
   - Install: `apt install qemu-user-static binfmt-support`
   - Enable: `update-binfmts --enable qemu-aarch64`

3. **VirtualBox import fails:**
   - Use raw `.img` instead of `.vdi`
   - Convert manually: `qemu-img convert -f raw -O vdi image.img image.vdi`

---

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
