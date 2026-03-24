# SecuBox-DEB

**Security Appliance for Debian** | [Francais](Home-FR) | [中文](Home-ZH)

SecuBox is a complete security appliance solution ported from OpenWrt to Debian bookworm, designed for GlobalScale ARM64 boards (MOCHAbin, ESPRESSObin) and x86_64 systems.

## Quick Start

### Live USB (Fastest)

Boot directly from USB - no installation required:

```bash
# Download
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz

# Flash to USB drive
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

See [[Live-USB]] for complete guide.

### APT Installation

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full
```

## Features

| Category | Modules |
|----------|---------|
| **Security** | CrowdSec IDS/IPS, WAF, NAC, Auth |
| **Networking** | WireGuard VPN, HAProxy, DPI, QoS |
| **Monitoring** | Netdata, MediaFlow, Metrics |
| **Email** | Postfix/Dovecot, Webmail |
| **Publishing** | Droplet, Streamlit, MetaBlogizer |

## Supported Hardware

| Board | SoC | Use Case |
|-------|-----|----------|
| MOCHAbin | Armada 7040 | SecuBox Pro |
| ESPRESSObin v7 | Armada 3720 | SecuBox Lite |
| ESPRESSObin Ultra | Armada 3720 | SecuBox Lite+ |
| VM x86_64 | Any | Testing/Development |

## Documentation

- [[Live-USB]] - Bootable USB guide
- [[Installation]] - Full installation
- [[Configuration]] - System configuration
- [[API-Reference]] - REST API documentation
- [[Troubleshooting]] - Common issues

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Web UI | admin | admin |
| SSH | root | secubox |

## Links

- [GitHub Repository](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [Issues](https://github.com/CyberMind-FR/secubox-deb/issues)
