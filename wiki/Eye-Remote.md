# Eye Remote — Pi Zero USB Gadget

> **SecuBox Eye Remote** transforms a Raspberry Pi Zero W into a portable USB boot media controller for ARM64 SecuBox devices (ESPRESSObin, MOCHAbin).

---

## Overview

The Eye Remote presents a multiboot storage image to the host device via USB gadget mass_storage, enabling network-less deployment and recovery.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Eye Remote Architecture                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────────┐        USB OTG         ┌─────────────────┐   │
│   │  Pi Zero W   │ ◄─────────────────────►│  ESPRESSObin    │   │
│   │              │   mass_storage +       │  or MOCHAbin    │   │
│   │  Eye Remote  │   ECM network          │                 │   │
│   └──────────────┘                        └─────────────────┘   │
│         │                                        │              │
│         │ µSD Card                               │              │
│         ▼                                        ▼              │
│   ┌──────────────┐                        ┌─────────────────┐   │
│   │ storage.img  │ ────presented as───►   │ /dev/sda        │   │
│   │ 16GB image   │    USB mass storage    │ Bootable disk   │   │
│   └──────────────┘                        └─────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **USB Mass Storage** | Pi Zero presents `storage.img` as USB disk to host |
| **USB ECM Network** | Ethernet over USB for remote management |
| **Serial Console** | USB ACM serial for debug access |
| **Dual Boot Menu** | Interactive menu: Live RAM Boot or Flash to eMMC |
| **Web Dashboard** | xterm.js serial console + status UI |

---

## Hardware Requirements

| Component | Specification |
|-----------|---------------|
| Pi Zero W | Any revision (W for WiFi management) |
| µSD Card | 32GB+ Class 10 / A1 recommended |
| USB Cable | USB-A to Micro-USB OTG |
| Target | ESPRESSObin, MOCHAbin, or compatible ARM64 |

---

## Quick Start

### 1. Flash the Eye Remote Image

```bash
# Download the Eye Remote image
wget https://github.com/CyberMind-FR/secubox-deb/releases/download/eye-remote-v2.2.4/secubox-eye-remote.img.xz

# Flash to µSD card
xzcat secubox-eye-remote.img.xz | sudo dd of=/dev/sdX bs=4M status=progress conv=fsync
sync
```

### 2. Connect Pi Zero to Target

1. Insert µSD card into Pi Zero
2. Connect Pi Zero USB port to target's USB port
3. Power on target device

### 3. Boot Menu

The target device will see a USB mass storage device and boot from it. The U-Boot boot.scr presents:

```
============================================
          BOOT MENU
============================================

  [1] Live RAM Boot (default)
  [2] Flash SecuBox to eMMC

Auto-boot in 5 seconds...
```

---

## Partition Layout

| Partition | Label | Size | Purpose |
|-----------|-------|------|---------|
| 1 | SECUBOX-EFI | 512MB | Boot files (kernel, DTB, GRUB, U-Boot) |
| 2 | secubox-arm64 | ~4GB | ARM64 rootfs (RAM-loaded) |
| 3 | secubox-amd64 | ~4GB | AMD64 rootfs (for x86 targets) |
| 4 | secubox-data | ~7GB | Shared persistent data |

---

## USB Gadget Configuration

The Pi Zero configures multiple USB gadget functions:

```bash
# /boot/config.txt
dtoverlay=dwc2

# cmdline.txt (after rootwait)
modules-load=dwc2,g_multi
```

### Gadget Functions

| Function | Device | Purpose |
|----------|--------|---------|
| `mass_storage` | Host sees USB disk | Boot media |
| `ecm` | usb0 network | Remote access |
| `acm` | ttyGS0 serial | Debug console |

---

## Building the Image

### From Repository

```bash
cd secubox-deb

# Build the Eye Remote image
sudo bash image/eye-remote/build-eye-remote.sh \
    --output output/secubox-eye-remote.img \
    --storage-size 16G

# Or with multiboot integration
sudo bash image/multiboot/build-multiboot.sh \
    --output output/secubox-multiboot.img \
    --size 16G
```

### GitHub Actions

The image is automatically built via CI:
- Workflow: `.github/workflows/build-eye-remote.yml`
- Trigger: Push to `eye-remote-v*` tags

---

## Remote Management

### WiFi Configuration

Edit `/boot/wpa_supplicant.conf` on the µSD card before first boot:

```
country=FR
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="YourWiFi"
    psk="YourPassword"
}
```

### SSH Access

```bash
# Via WiFi (if configured)
ssh secubox@<pi-zero-ip>

# Via USB ECM network
ssh secubox@10.55.0.1
```

### Web Dashboard

Access at `http://10.55.0.1:8080`:
- Serial console via xterm.js
- Boot media status
- Storage swap controls

### HyperPixel Round Display (v2.1.1+)

The Eye Remote supports the Pimoroni HyperPixel 2.1 Round (480×480) for a dedicated dashboard:

```
┌────────────────────────────────┐
│     🔴 🟠 🟡 🟢 🔵 🟣          │  ← Rainbow icon ring
│         ╭─────╮                │
│      ╭──│TIME │──╮             │  ← Center clock
│     ╭───│DATE │───╮            │
│    ╭────│HOST │────╮           │  ← Concentric metric rings
│   ╭─────│ UP  │─────╮          │    (red→purple outer→inner)
│   ╰─────╰─────╯─────╯          │
│         RADAR ⟳                │  ← Rotating radar sweep
└────────────────────────────────┘
```

**Features:**
- 6 module icons in rainbow order (BOOT, AUTH, WALL, ROOT, MESH, MIND)
- Radar sweep syncs with targeted module glow
- Metric arcs aligned with corresponding icon colors
- Concentric rings: red (outer) → purple (inner)

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/eye-remote/status` | System status |
| GET | `/api/v1/eye-remote/boot-media/state` | Boot media state |
| POST | `/api/v1/eye-remote/boot-media/upload` | Upload to shadow |
| POST | `/api/v1/eye-remote/boot-media/swap` | Swap active/shadow |
| POST | `/api/v1/eye-remote/boot-media/rollback` | Rollback swap |

---

## Troubleshooting

### Pi Zero Not Booting

1. Check µSD card is properly seated
2. Verify `config.txt` contains `dtoverlay=dwc2`
3. Check power LED (solid red = powered)
4. Check activity LED (flashing green = reading SD)

### Target Not Seeing USB Storage

1. Ensure USB cable supports data (not charge-only)
2. Check Pi Zero is fully booted (activity LED stops flashing)
3. On target, run `lsusb` to check USB detection
4. Check `dmesg` for mass_storage errors

### Boot Menu Not Appearing

1. Target U-Boot must support `usb start`
2. Check boot order in U-Boot: `printenv boot_targets`
3. Manually try: `usb start; fatload usb 0:1 $kernel_addr_r Image`

---

## See Also

- [[Multiboot|Multi-Boot Live OS]] — Full multiboot documentation
- [[ARM-Installation]] — ARM64 installation guide
- [[ESPRESSObin]] — ESPRESSObin specific setup
- [[Live-USB]] — Standard Live USB guide

---

## Support

- **Issues**: https://github.com/CyberMind-FR/secubox-deb/issues
- **Wiki**: https://github.com/CyberMind-FR/secubox-deb/wiki
