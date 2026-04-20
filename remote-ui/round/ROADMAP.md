# SecuBox Eye Remote — Roadmap & Tutorial

## Version 1.8.0 Release Notes

**Release Date:** 2026-04-20
**Codename:** Eye Remote

### What's New

The Round UI has been transformed from a simple status display into a **full remote control device** for SecuBox appliances.

### New Features

| Feature | Description |
|---------|-------------|
| **5 USB Modes** | Normal, Flash, Debug, TTY, Auth |
| **HID Keyboard** | Virtual keyboard for U-Boot automation |
| **FIDO2 Security Key** | Hardware authentication via Eye Remote |
| **x64 Live Boot** | Run Eye Remote on any x64 touchscreen |
| **Infographic Prompts** | Ready-to-use Claude.ai prompts |

---

## Roadmap

### v1.8.x — Eye Remote Foundation (Current)

- [x] Multi-mode USB gadget (secubox-otg-gadget.sh)
- [x] HID keyboard emulation (secubox-hid-keyboard.sh)
- [x] TTY mode for U-Boot automation
- [x] Auth mode skeleton (FIDO2 HID)
- [x] Documentation (README, WIKI, mockups)
- [x] x64 live boot profile

### v1.9.0 — Eye Remote Interactive UI (Q2 2026)

- [ ] Mode-aware index.html (switch UI based on mode)
- [ ] Touch mode selector in dashboard
- [ ] Real-time serial output display (TTY mode)
- [ ] Progress bar for flash operations
- [ ] QR code generation for Auth mode
- [ ] Command queue editor (TTY mode)

### v2.0.0 — Eye Remote Security (Q3 2026)

- [ ] Full FIDO2 implementation
- [ ] WebAuthn integration
- [ ] SSH pubkey authentication via Eye Remote
- [ ] Challenge-response flow with QR backup
- [ ] Secure element integration (optional)

### v2.1.0 — Eye Remote Mesh (Q4 2026)

- [ ] Eye Remote as MirrorNet node
- [ ] P2P status replication
- [ ] Multi-SecuBox monitoring from single Eye
- [ ] Remote mode switching via mesh

---

## Tutorial: Building Your Eye Remote

### Bill of Materials

| Component | Price | Link |
|-----------|-------|------|
| Raspberry Pi Zero W | ~15€ | raspberrypi.com |
| HyperPixel 2.1 Round | ~50€ | pimoroni.com |
| microSD 16GB | ~10€ | Any Class 10 |
| USB data cable | ~5€ | Must support data |
| **Total** | **~80€** | |

### Step 1: Flash the SD Card

```bash
cd secubox-deb/remote-ui/round

# Download Raspberry Pi OS Lite (32-bit armhf)
wget https://downloads.raspberrypi.com/raspios_lite_armhf/images/\
raspios_lite_armhf-2024-11-19/2024-11-19-raspios-bookworm-armhf-lite.img.xz

# Flash with USB OTG enabled
sudo ./install_zerow.sh \
    -d /dev/sdX \
    -i 2024-11-19-raspios-bookworm-armhf-lite.img.xz \
    -s "YourWiFi" \
    -p "YourPassword" \
    -k ~/.ssh/id_rsa.pub \
    -r  # Enable USB OTG
```

### Step 2: Assemble Hardware

```
        ┌──────────────────────────┐
        │     HyperPixel Round     │
        │     ┌────────────┐       │
        │     │            │       │
        │     │   Display  │       │
        │     │            │       │
        │     └────────────┘       │
        │                          │
        │     [GPIO Header]        │
        └──────────┬───────────────┘
                   │
        ┌──────────┴───────────────┐
        │    Raspberry Pi Zero W   │
        │                          │
        │  [PWR]  [DATA]  [HDMI]   │
        │    ○      ●       ○      │
        │          ↑               │
        │    Connect USB here      │
        └──────────────────────────┘
```

**Important:** Connect USB cable to the DATA port (middle), not PWR!

### Step 3: First Boot

1. Insert SD card into Pi Zero
2. Connect USB data cable to SecuBox
3. Wait 90 seconds for boot
4. Eye Remote will appear as `secubox-round` network interface

### Step 4: Deploy Dashboard

```bash
# From your dev machine
./deploy.sh \
    -h secubox-round.local \
    --api-url http://10.55.0.1:8000 \
    --api-pass "YourAPIPassword"
```

### Step 5: Switch Modes

```bash
# SSH to Eye Remote
ssh pi@10.55.0.2

# Switch to TTY mode for U-Boot access
sudo secubox-otg-gadget.sh tty

# Send commands
./secubox-hid-keyboard.sh cmd 'printenv'
./secubox-hid-keyboard.sh cmd 'boot'

# Switch back to normal
sudo secubox-otg-gadget.sh start
```

---

## Use Cases

### 1. Recover a Bricked SecuBox

```bash
# On Eye Remote
sudo secubox-otg-gadget.sh flash

# Boot SecuBox from USB (F12/BIOS)
# Flash mode presents bootable recovery image
# Flash eMMC from recovery environment
```

### 2. Debug U-Boot Issues

```bash
# Enable TTY mode
sudo secubox-otg-gadget.sh tty

# Send automated boot sequence
./secubox-hid-keyboard.sh queue << 'EOF'
["printenv", "setenv bootcmd run bootusb", "saveenv", "boot"]
EOF
./secubox-hid-keyboard.sh queue /run/secubox-cmd-queue
```

### 3. Export Logs for Support

```bash
# Enable debug mode
sudo secubox-otg-gadget.sh debug

# Logs appear on host as USB mass storage
# Mount and copy /var/log/secubox/*
```

### 4. Hardware 2FA Authentication

```bash
# Enable auth mode
sudo secubox-otg-gadget.sh auth

# Eye Remote becomes FIDO2 security key
# QR code displayed for backup
# Touch to approve authentication requests
```

---

## x64 Live Boot

For testing or portable use without dedicated hardware:

```bash
# Build live USB with Eye Remote
./image/build-live-usb.sh \
    --profile x64-live \
    --eye-remote \
    --output /tmp/secubox-eye.iso

# Boot on any x64 PC or VM
qemu-system-x86_64 -m 2G -cdrom /tmp/secubox-eye.iso
```

---

## Creating Infographics

See `INFOGRAPHIC-PROMPT.md` for ready-to-use Claude.ai prompts:

1. Open claude.ai
2. Copy a prompt from the file
3. Ask Claude to generate the image
4. Use in your documentation or marketing

---

## Contributing

### Areas Needing Help

- [ ] FIDO2 library integration (Python fido2)
- [ ] QR code generation (qrcode library)
- [ ] Touchscreen mode selector UI
- [ ] Serial terminal display component
- [ ] x64 installer wizard

### Testing Hardware Needed

- Various USB-C to Micro-USB cables (OTG compatibility)
- Different SecuBox boards (MOCHAbin, EspressoBin)
- x64 touchscreen displays

---

## Links

- **GitHub:** github.com/CyberMind-FR/secubox-deb
- **Docs:** docs.secubox.in
- **Demo:** live.maegia.tv
- **Support:** gandalf@gk2.net

---

*SecuBox Eye Remote — More than a dashboard*
*CyberMind — https://cybermind.fr*
*Author: Gérald Kerma*
