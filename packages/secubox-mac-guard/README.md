# SecuBox MAC Guard

MAC address control and network access module for SecuBox-DEB.

**Category:** Security

## Features

- MAC address whitelist/blacklist management
- Device discovery via ARP table and DHCP leases
- OUI vendor lookup using ieee-data
- Device naming and tagging
- Alert on unknown devices
- nftables MAC filtering integration
- Real-time device monitoring
- P31 Phosphor light theme with cyan (#06b6d4) accent

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mac-guard
```

## Configuration

Configuration file: `/etc/secubox/mac-guard.toml`

```toml
[mac-guard]
mode = "whitelist"          # whitelist, blacklist, or disabled
alert_on_unknown = true     # Alert when unknown devices are detected
auto_block_unknown = false  # Automatically block unknown devices
scan_interval = 60          # Network scan interval in seconds
```

## API Endpoints

### Health & Status
- `GET /api/v1/mac-guard/health` - Health check
- `GET /api/v1/mac-guard/status` - Module status

### Configuration
- `GET /api/v1/mac-guard/config` - Get configuration
- `POST /api/v1/mac-guard/config` - Update configuration

### Devices
- `GET /api/v1/mac-guard/devices` - All discovered devices
- `GET /api/v1/mac-guard/device/{mac}` - Device details
- `POST /api/v1/mac-guard/device/{mac}/tag` - Tag device with name/tags

### Whitelist
- `GET /api/v1/mac-guard/whitelist` - Get whitelist
- `POST /api/v1/mac-guard/whitelist` - Add to whitelist
- `DELETE /api/v1/mac-guard/whitelist/{mac}` - Remove from whitelist

### Blacklist
- `GET /api/v1/mac-guard/blacklist` - Get blacklist
- `POST /api/v1/mac-guard/blacklist` - Add to blacklist
- `DELETE /api/v1/mac-guard/blacklist/{mac}` - Remove from blacklist

### Other
- `GET /api/v1/mac-guard/unknown` - Unknown devices
- `POST /api/v1/mac-guard/scan` - Trigger network scan
- `GET /api/v1/mac-guard/vendors` - OUI vendor lookup
- `GET /api/v1/mac-guard/alerts` - MAC alerts
- `GET /api/v1/mac-guard/stats` - Statistics
- `POST /api/v1/mac-guard/sync` - Sync nftables sets

## nftables Integration

MAC Guard creates and manages nftables sets for MAC filtering:

```bash
# Table: inet secubox_mac_guard
# Sets: mac_whitelist, mac_blacklist

# View current sets
nft list set inet secubox_mac_guard mac_whitelist
nft list set inet secubox_mac_guard mac_blacklist
```

## Dependencies

- `secubox-core` - Core SecuBox library
- `nftables` - Firewall backend
- `nginx` - Reverse proxy
- `ieee-data` - OUI vendor database

### Optional
- `nmap` - Network scanning
- `arp-scan` - Enhanced ARP scanning

## Data Files

- `/var/lib/secubox/mac-guard/devices.json` - Discovered devices
- `/var/lib/secubox/mac-guard/whitelist.json` - Whitelist entries
- `/var/lib/secubox/mac-guard/blacklist.json` - Blacklist entries
- `/var/lib/secubox/mac-guard/alerts.json` - Alert history

## Service Management

```bash
# Check status
systemctl status secubox-mac-guard

# View logs
journalctl -u secubox-mac-guard -f

# Restart service
systemctl restart secubox-mac-guard
```

## License

MIT License - CyberMind 2024-2026
