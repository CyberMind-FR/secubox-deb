# Eye Remote Hardware & Interfaces

## Supported Hardware

### Display Module

| Component | Model | Specifications |
|-----------|-------|----------------|
| **Display** | Pimoroni HyperPixel 2.1 Round | 480×480 IPS, capacitive touch |
| **Controller** | ST7701S | DPI interface, SPI init required |
| **Interface** | 40-pin GPIO | Full GPIO header required |
| **Touch** | I2C | Address 0x15 on I2C-10 |

### Computing Units

| Board | SoC | Status | Notes |
|-------|-----|--------|-------|
| **Raspberry Pi Zero W** | BCM2835 (ARMv6) | ✅ Recommended | 512MB RAM, WiFi, BT |
| **Raspberry Pi Zero 2 W** | BCM2710 (ARMv8) | ⚠️ Untested | 512MB RAM, quad-core |
| **Raspberry Pi Zero WH** | BCM2835 | ✅ Works | Pre-soldered headers |

> **Note:** Pi Zero W is recommended for power efficiency. Pi 3/4/5 not supported due to form factor.

---

## Hardware Connections

### GPIO Pinout (HyperPixel 2.1 Round)

```
┌─────────────────────────────────────────────────────────────┐
│                    40-pin GPIO Header                       │
├──────┬──────┬───────────────────────────────────────────────┤
│ Pin  │ GPIO │ Function                                      │
├──────┼──────┼───────────────────────────────────────────────┤
│  1   │ 3V3  │ Power                                         │
│  2   │ 5V   │ Power (display backlight)                     │
│  3   │ 2    │ I2C1 SDA (touch controller)                   │
│  5   │ 3    │ I2C1 SCL (touch controller)                   │
│  6   │ GND  │ Ground                                        │
│ 10   │ 15   │ SPI CE1 (LCD chip select)                     │
│ 11   │ 17   │ LCD CLK (SPI clock)                           │
│ 13   │ 27   │ LCD MOSI (SPI data)                           │
│ 15   │ 22   │ LCD DC (data/command select)                  │
│ 19   │ 10   │ SPI MOSI (alt function)                       │
│ 21   │ 9    │ SPI MISO (alt function)                       │
│ 23   │ 11   │ SPI CLK (alt function)                        │
│ 35   │ 19   │ Backlight PWM                                 │
│ 36   │ 16   │ LCD Reset                                     │
│ 37   │ 26   │ Touch interrupt                               │
│ 38   │ 20   │ DPI DE                                        │
│ 40   │ 21   │ DPI CLK                                       │
│ 4-40 │ ...  │ DPI data (RGB666)                             │
└──────┴──────┴───────────────────────────────────────────────┘
```

### USB OTG Connection

```
                    Pi Zero W
        ┌───────────────────────────────┐
        │   PWR      DATA      HDMI     │
        │   (○)      (●)       (○)      │
        │            ↑                  │
        │    USB OTG data port          │
        │    Connect here!              │
        └───────────────────────────────┘
                     │
                     │ Micro-USB cable
                     │
        ┌────────────▼────────────────┐
        │        SecuBox Host         │
        │   USB-A port (any)          │
        └─────────────────────────────┘

⚠️ WARNING: Do NOT use the PWR port for OTG!
   The DATA port (middle) must be used.
```

---

## Network Interfaces

### USB OTG Network (Primary)

| Parameter | Value |
|-----------|-------|
| Interface | `usb0` (Eye) / `secubox-round` (Host) |
| Eye IP | 10.55.0.2/30 |
| Host IP | 10.55.0.1/30 |
| Gateway | 10.55.0.1 |
| Protocol | CDC-ECM (Ethernet over USB) |

### USB Serial Console (Rescue)

| Parameter | Value |
|-----------|-------|
| Device (Host) | `/dev/ttyACM0` |
| Device (Eye) | `/dev/ttyGS0` |
| Baud Rate | 115200 |
| Protocol | CDC-ACM (Serial over USB) |

```bash
# Connect from SecuBox host
screen /dev/ttyACM0 115200
# or
minicom -D /dev/ttyACM0 -b 115200
```

### WiFi (Fallback)

| Parameter | Value |
|-----------|-------|
| Interface | `wlan0` |
| Mode | Client (WPA2-PSK) |
| Hostname | `secubox-round.local` |
| mDNS | Avahi (enabled) |

---

## Display Configuration

### Legacy DPI Mode (Required for Pi Zero W)

The HyperPixel 2.1 Round uses a DPI (parallel) interface that requires specific timing configuration. **KMS (Kernel Mode Setting) does not work on Pi Zero W**.

#### /boot/config.txt

```ini
# HyperPixel 2.1 Round - Legacy DPI
dtoverlay=hyperpixel2r
enable_dpi_lcd=1
display_default_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 55 480 0 15 60 15 0 0 0 60 0 19200000 6
framebuffer_width=480
framebuffer_height=480
display_rotate=0

# I2C for touch
dtparam=i2c_arm=on
dtparam=spi=on
```

### ST7701S LCD Initialization

The LCD controller requires SPI commands at boot to initialize. This is handled by `hyperpixel2r-init` service.

```
Boot sequence:
1. pigpiod.service starts (GPIO daemon)
2. hyperpixel2r-init.service runs (SPI init)
3. framebuffer becomes available
4. lightdm.service starts (X11)
5. Chromium kiosk launches
```

### DPI Timing Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| H pixels | 480 | Horizontal resolution |
| H front porch | 10 | H blank before sync |
| H sync | 16 | H sync pulse width |
| H back porch | 55 | H blank after sync |
| V pixels | 480 | Vertical resolution |
| V front porch | 15 | V blank before sync |
| V sync | 60 | V sync pulse width |
| V back porch | 15 | V blank after sync |
| V sync polarity | 0 | Active low |
| H sync polarity | 0 | Active low |
| DE polarity | 0 | Active high |
| Pixel clock | 19200000 | 19.2 MHz |
| Clock edge | 6 | Sample on rising edge |

---

## USB Gadget Modes

The Eye Remote supports multiple USB gadget configurations:

### Mode: `start` (Default)

```
┌─────────────────────────────┐
│      USB Composite          │
├─────────────────────────────┤
│  ECM (Ethernet)  usb0       │
│  ACM (Serial)    ttyGS0     │
└─────────────────────────────┘
```

### Mode: `tty` (HID Keyboard)

```
┌─────────────────────────────┐
│      USB HID                │
├─────────────────────────────┤
│  HID Keyboard   hidg0       │
│  Can type on host           │
└─────────────────────────────┘
```

### Mode: `debug` (Network + Storage)

```
┌─────────────────────────────┐
│      USB Composite          │
├─────────────────────────────┤
│  ECM (Ethernet)  usb0       │
│  ACM (Serial)    ttyGS0     │
│  Mass Storage    debug.img  │
└─────────────────────────────┘
```

### Mode: `flash` (Bootable USB)

```
┌─────────────────────────────┐
│      USB Mass Storage       │
├─────────────────────────────┤
│  Boot image only            │
│  Host sees USB drive        │
└─────────────────────────────┘
```

### Mode: `auth` (FIDO2)

```
┌─────────────────────────────┐
│      USB FIDO2              │
├─────────────────────────────┤
│  FIDO2/U2F Security Key     │
│  WebAuthn compatible        │
└─────────────────────────────┘
```

---

## Power Requirements

| State | Current | Notes |
|-------|---------|-------|
| Boot | ~400mA | Peak during initialization |
| Idle | ~150mA | Display on, no activity |
| Active | ~250mA | WiFi + display + CPU |
| Sleep | ~100mA | Display dimmed |

**Power source:** USB 5V from host (via DATA port)

> **Note:** Ensure host USB port provides at least 500mA. Use powered hub if needed.

---

## Troubleshooting

### Display Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Black screen | KMS enabled | Use legacy DPI mode |
| White screen | ST7701S not initialized | Check pigpiod + hyperpixel2r-init |
| Flickering | Wrong DPI timings | Verify config.txt settings |
| No touch | I2C not enabled | Check `dtparam=i2c_arm=on` |

### Network Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| No usb0 | Gadget not loaded | Check `secubox-otg-gadget.service` |
| No IP | usb0-up failed | Check `/var/log/usb0-up.log` |
| Host no interface | udev rule missing | Check `/etc/udev/rules.d/90-secubox-otg.rules` |

### USB Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Not recognized | Wrong port | Use DATA port (middle) |
| Disconnects | Power insufficient | Use powered hub |
| No serial | ACM not loaded | Check `libcomposite` module |

---

## Hardware Revisions

### HyperPixel 2.1 Round

| Version | Changes | Compatibility |
|---------|---------|---------------|
| v1.0 | Original release | ✅ Works |
| v2.0 | Improved touch | ✅ Works |
| v2.1 | Current production | ✅ Recommended |

### Eye Remote Board Compatibility

| Version | Pi Zero W | Pi Zero 2 W | Notes |
|---------|-----------|-------------|-------|
| v1.x | ✅ | ⚠️ Untested | KMS mode (broken) |
| v2.0 | ✅ | ⚠️ Untested | Legacy DPI mode |

---

*CyberMind · SecuBox Eye Remote Hardware Guide · April 2026*
