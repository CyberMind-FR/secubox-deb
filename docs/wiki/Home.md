# SecuBox-DEB Wiki

Welcome to the SecuBox-DEB documentation wiki.

## Eye Remote

The Eye Remote is a compact USB gadget display for monitoring SecuBox metrics.

| Page | Description |
|------|-------------|
| [Eye Remote Implementation](Eye-Remote-Implementation.md) | Architecture, API, and implementation guide |
| [Eye Remote Hardware](Eye-Remote-Hardware.md) | Hardware setup, GPIO pinout, display configuration |
| [Eye Remote Gateway](Eye-Remote-Gateway.md) | Gateway emulator for development and testing |

### Quick Start

1. **Hardware**: Raspberry Pi Zero W + HyperPixel 2.1 Round (480×480)
2. **Connection**: USB OTG (10.55.0.0/30) or WiFi
3. **Dashboard**: Python framebuffer rendering (no browser needed)

### Build Image

```bash
# Lightweight framebuffer mode (recommended)
cd remote-ui/round
sudo ./build-eye-remote-image.sh -i raspios-lite.img.xz --framebuffer

# With WiFi pre-configured
sudo ./build-eye-remote-image.sh -i raspios-lite.img.xz -s "SSID" -p "password"
```

### Test with Emulator

```bash
# Start gateway emulator
cd tools/secubox-eye-gateway
pip install -e .
secubox-eye-gateway --profile stressed --port 8765

# Test on desktop (requires pygame)
cd remote-ui/round
python3 test-dashboard-amd64.py --api http://localhost:8765
```

---

## Other Documentation

- [CLAUDE.md](../../CLAUDE.md) — Project conventions and migration guide
- [Porting Guide](../PORTING-GUIDE.md) — OpenWrt to Debian migration

---

*CyberMind · SecuBox-DEB · April 2026*
