# SecuBox Eye Remote — Infographic Generation Prompts
## For Claude.ai / Image Generation

---

## 1. Hero Infographic — Eye Remote Overview

**Prompt for Claude.ai:**

```
Create a professional cyberpunk-style infographic for "SecuBox Eye Remote" - a circular touchscreen remote control device for cybersecurity appliances.

Layout: 16:9 landscape, dark background (#080808)

Main visual: A circular touchscreen (480x480px) showing 6 concentric colored rings around a central clock display. The rings represent security modules:
- AUTH (orange-red #C04E24) - outermost
- WALL (bronze #9A6010)
- BOOT (dark red #803018)
- MIND (purple #3D35A0)
- ROOT (dark green #0A5840)
- MESH (navy blue #104A88) - innermost

Center shows: "14:32:07" in white monospace font, "NOMINAL" status below

Left side panel: "5 USB MODES"
- Normal: Network monitoring icon
- Flash: USB drive icon with lightning
- Debug: Bug icon with magnifying glass
- TTY: Keyboard icon
- Auth: Key/lock icon

Right side panel: "FEATURES"
- USB OTG Composite Gadget
- HID Keyboard Emulation
- FIDO2 Security Key
- Live Boot Support (x64)
- Real-time Metrics

Bottom: "CyberMind" logo, "SecuBox Eye Remote" title, "docs.secubox.in" URL

Style: Cyberpunk, neon accents on dark, circuit board patterns in background, professional but futuristic
Colors: Use the module colors as accent colors throughout
```

---

## 2. Mode Comparison Infographic

**Prompt for Claude.ai:**

```
Create a 5-panel comparison infographic showing the 5 USB modes of SecuBox Eye Remote.

Each panel (vertical column):

Panel 1 - NORMAL MODE
- Icon: Network waves
- Color accent: Green (#00ff41)
- Text: "Status Dashboard"
- Bullets: Real-time metrics, 6 module status, Alert notifications
- USB functions: ECM Network + Serial

Panel 2 - FLASH MODE
- Icon: USB drive + download arrow
- Color accent: Orange (#ffc107)
- Text: "Recovery Boot"
- Bullets: Bootable USB image, eMMC flashing, U-Boot access
- USB functions: Mass Storage + Serial

Panel 3 - DEBUG MODE
- Icon: Bug + folder
- Color accent: Cyan (#00d4ff)
- Text: "Log Export"
- Bullets: Extract logs, Config backup, Forensic analysis
- USB functions: Network + Storage + Serial

Panel 4 - TTY MODE
- Icon: Keyboard
- Color accent: Purple (#6e40c9)
- Text: "Virtual Keyboard"
- Bullets: U-Boot commands, Automated scripts, Rescue boot
- USB functions: HID Keyboard + Serial

Panel 5 - AUTH MODE
- Icon: Shield with key
- Color accent: Red (#e63946)
- Text: "Security Key"
- Bullets: FIDO2/WebAuthn, SSH authentication, QR challenges
- USB functions: FIDO HID + Serial

Background: Dark (#0a0a0f), circuit pattern
Style: Clean, modern, cybersecurity theme
Bottom banner: "SecuBox Eye Remote - More than a dashboard"
```

---

## 3. Quick Start Howto Infographic

**Prompt for Claude.ai:**

```
Create a step-by-step "Quick Start" infographic for SecuBox Eye Remote setup.

Layout: Vertical flow, 5 numbered steps with icons

Step 1: FLASH
- Icon: SD card
- Text: "Flash microSD with install_zerow.sh"
- Code snippet: "./install_zerow.sh -d /dev/sdb -i raspios.img -s WiFi -p pass"

Step 2: CONNECT
- Icon: USB cable
- Text: "Connect to DATA port (not PWR)"
- Warning: "Use data-capable USB cable!"
- Diagram: Pi Zero with arrow pointing to middle port

Step 3: BOOT
- Icon: Power button
- Text: "Wait 90 seconds for first boot"
- Progress: "Installing drivers..."

Step 4: CONFIGURE
- Icon: Gear/settings
- Text: "Deploy dashboard with API credentials"
- Code: "./deploy.sh -h secubox-round.local --api-url http://10.55.0.1:8000"

Step 5: ENJOY
- Icon: Checkmark in circle
- Text: "Eye Remote is ready!"
- Show circular dashboard mockup

Color scheme: Dark background, green accent for success steps, orange for warnings
Bottom: "Full documentation: github.com/CyberMind-FR/secubox-deb"
```

---

## 4. Architecture Diagram

**Prompt for Claude.ai:**

```
Create a technical architecture diagram for SecuBox Eye Remote USB OTG connection.

Two main boxes connected by USB cable:

LEFT BOX - "SecuBox Target"
- Label: "Armada/x86 Appliance"
- Show USB Host port
- Internal components:
  - FastAPI (port 8000)
  - /api/v1/system/metrics
  - U-Boot console
  - /dev/ttyACM0

CENTER - USB OTG Cable
- Arrow showing bidirectional data
- Functions listed:
  - ECM Network (10.55.0.0/30)
  - CDC-ACM Serial
  - Mass Storage
  - HID Keyboard

RIGHT BOX - "Eye Remote"
- Label: "RPi Zero W + HyperPixel"
- Show circular display
- Internal components:
  - configfs gadget
  - nginx:8080
  - Chromium kiosk
  - /dev/hidg0

Data flow arrows:
- Metrics API ←→ Dashboard
- Serial Console ←→ Debug
- HID Keyboard → U-Boot
- Mass Storage ↔ Flash/Debug

Style: Technical diagram, clean lines, dark theme
Colors: Use module colors for different data flows
```

---

## 5. x64 Live Boot Infographic

**Prompt for Claude.ai:**

```
Create an infographic showing SecuBox Eye Remote running on multiple platforms.

Title: "One Dashboard, Multiple Platforms"

Three platform cards:

Card 1 - RPi Zero W
- Image: Small green board with round display
- Specs: ARMv6, 512MB RAM, HyperPixel 2.1
- Use case: "Permanent installation, USB OTG control"

Card 2 - x64 Live USB
- Image: USB drive with SecuBox logo
- Specs: Any x64 PC, 2GB RAM min
- Use case: "Portable diagnostics, staging, demos"

Card 3 - Touchscreen Kiosk
- Image: Industrial panel PC
- Specs: Intel NUC, 7" touchscreen
- Use case: "NOC display, field deployment"

Bottom section: "Build Commands"
- RPi: "./install_zerow.sh -d /dev/sdb ..."
- x64: "./build-live-usb.sh --profile x64-live --eye-remote"
- VM: "qemu-system-x86_64 -m 2G -cdrom secubox-eye.iso"

Style: Modern, clean, dark background with colored accents
```

---

## 6. Security Key (Auth Mode) Infographic

**Prompt for Claude.ai:**

```
Create an infographic explaining the Eye Remote as a FIDO2 security key.

Title: "Eye Remote Security Key"

Main visual: Circular display showing QR code with "Touch to Authenticate" message

Flow diagram (left to right):
1. Service requests auth (SSH, WebAuthn)
2. Eye Remote receives challenge
3. Display shows QR + details
4. User touches APPROVE/DENY
5. Signed response sent back

Features list:
- FIDO2/U2F compliant
- WebAuthn support
- SSH public key auth
- QR code backup
- Touch approval required
- No batteries to replace

Comparison table:
| Feature | YubiKey | Eye Remote |
| Display | No | Yes (480x480) |
| QR Backup | No | Yes |
| USB Modes | 1 | 5 |
| Status | LED | Full dashboard |
| Price | $50+ | ~$80 (DIY) |

Style: Security-focused, lock/key imagery, dark with gold (#c9a84c) accents
```

---

## 7. Social Media Banner

**Prompt for Claude.ai:**

```
Create a Twitter/X banner (1500x500) for SecuBox Eye Remote announcement.

Left third: Circular display showing dashboard with colored rings

Center:
- "SecuBox Eye Remote"
- "The dashboard that controls back"
- 5 mode icons in a row

Right third:
- "CyberMind" logo
- "Open Source Security"
- GitHub icon with "CyberMind-FR/secubox-deb"

Style: Cyberpunk gradient background (dark to purple), neon glow effects
Font: Modern sans-serif, bold headlines
Colors: Dark base, module colors as accents
```

---

## Usage Instructions

1. Copy the desired prompt
2. Open Claude.ai (claude.ai)
3. Ask Claude to "Create an image" or use the image generation feature
4. Paste the prompt
5. Download the generated image
6. Use in documentation, social media, or presentations

---

## Notes

- Adjust dimensions as needed for your platform
- Colors reference the official SecuBox module palette
- All prompts assume dark theme for consistency
- Add "CyberMind" branding where appropriate
- Avoid any references to "CyberMind Produits SASU"

---

*Generated for SecuBox Eye Remote documentation*
*CyberMind — https://cybermind.fr*
*Author: Gérald Kerma <gandalf@gk2.net>*
