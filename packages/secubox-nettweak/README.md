# secubox-nettweak

SecuBox Network Tuning Module - sysctl and TCP/IP stack optimization.

## Overview

This module provides a web UI and API for managing kernel network parameters
via sysctl. It allows administrators to apply predefined tuning profiles or
customize individual settings for optimal network performance.

## Features

- **Tuning Profiles**: Pre-configured settings for different use cases
  - Default: Standard Linux defaults
  - Performance: High throughput for bulk transfers
  - Low-Latency: Optimized for real-time applications
  - Security: Maximum security, defense in depth
  - Router: Optimized for packet forwarding

- **TCP Settings**: Manage TCP stack parameters
  - Buffer sizes (rmem, wmem)
  - Window scaling, timestamps, SACK
  - Fast Open, congestion control
  - Keepalive settings

- **Network Settings**: Manage network stack parameters
  - IP forwarding
  - Reverse path filtering
  - ICMP settings
  - Socket buffer defaults

- **Persistence**: Settings are saved to `/etc/sysctl.d/90-secubox-nettweak.conf`

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /status | Current tuning status and summary |
| GET | /profiles | List available tuning profiles |
| GET | /profile/{id} | Get detailed profile settings |
| GET | /settings | Get all managed sysctl settings |
| GET | /tcp | Get TCP stack settings |
| GET | /net | Get network stack settings |
| POST | /apply | Apply a profile or custom settings |
| POST | /set/{key} | Set a single sysctl value |
| POST | /reload | Reload sysctl configuration |
| POST | /reset | Reset to system defaults |

## Installation

```bash
apt install secubox-nettweak
```

## Configuration

Settings are managed through the web UI or API. Custom settings are persisted
to `/etc/sysctl.d/90-secubox-nettweak.conf`.

## Security Notes

- The service runs as root to modify kernel parameters
- JWT authentication is required for all write operations
- Changes are logged to the audit log

## Files

- `/usr/lib/secubox/nettweak/` - API code
- `/usr/share/secubox/www/nettweak/` - Web UI
- `/etc/sysctl.d/90-secubox-nettweak.conf` - Persistent settings
- `/run/secubox/nettweak.sock` - Unix socket

## Dependencies

- secubox-core
- python3-fastapi
- procps (for sysctl command)

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
