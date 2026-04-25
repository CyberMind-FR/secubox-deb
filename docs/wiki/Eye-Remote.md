# 👁️ Eye Remote

**SecuBox Eye Remote** — Compact USB gadget display for SecuBox monitoring and boot device.

**Hardware:** Raspberry Pi Zero W + HyperPixel 2.1 Round (480×480)

---

## Quick Links

| Page | Description |
|------|-------------|
| [[Eye-Remote-Hardware]] | Hardware setup, GPIO, display config |
| [[Eye-Remote-Implementation]] | Software architecture, agent, renderer |
| [[Eye-Remote-Bootstrap]] | Boot device, A/B slots, mass storage |
| [[Eye-Remote-Gateway]] | Gateway emulator for testing |
| [[eye-remote-icons]] | Icon reference with images |

---

## Features

### Display Dashboard
- 480×480 round framebuffer display
- Radial menu system with 6 slices
- Real-time SecuBox metrics
- Touch navigation

### USB Connection
- CDC-ECM network (10.55.0.2 ↔ 10.55.0.1)
- CDC-ACM serial console
- Mass storage for boot images

### Boot Device
- A/B slot boot media
- Atomic swap for safe updates
- 4-level rollback (R1-R4)
- TFTP netboot server

---

## Connection Diagram

```
┌─────────────────┐     USB OTG      ┌─────────────────┐
│   Eye Remote    │◄────────────────►│    SecuBox      │
│  Pi Zero W      │   10.55.0.0/30   │   Appliance     │
│  HyperPixel 2.1 │                  │                 │
└─────────────────┘                  └─────────────────┘
       │                                     │
       │ Display                             │ LAN
       ▼                                     ▼
  ┌─────────┐                          ┌─────────┐
  │ 480×480 │                          │ Network │
  │ Round   │                          │ Clients │
  └─────────┘                          └─────────┘
```

---

## Radial Menu

The display shows a radial menu with 6 colored slices:

| Slice | Color | Function |
|-------|-------|----------|
| 0 | #C04E24 | DEVICES |
| 1 | #9A6010 | SECUBOX |
| 2 | #803018 | LOCAL |
| 3 | #3D35A0 | NETWORK |
| 4 | #0A5840 | SECURITY |
| 5 | #104A88 | EXIT |

See [[eye-remote-icons]] for complete icon reference.

---

## Build & Deploy

```bash
# Build Eye Remote image
cd remote-ui/round
sudo ./build-eye-remote-image.sh -i raspios-lite.img.xz

# Flash to SD card
sudo dd if=eye-remote.img of=/dev/sdX bs=4M status=progress

# Test with gateway emulator
cd tools/secubox-eye-gateway
./secubox-eye-gateway --profile stressed
```

---

## Translations

- [[Eye-Remote-Bootstrap-FR|Français]]
- [[Eye-Remote-Bootstrap-ZH|中文]]

---

*← Back to [[Home|SecuBox Wiki]]*
