# SecuBox IPBlock

IP blocklist management module for SecuBox-DEB.

## Features

- **Multiple Blocklist Sources**: Spamhaus DROP/EDROP, Emerging Threats, Feodo Tracker, SSL Blacklist, TOR Exit Nodes, FireHOL, Blocklist.de
- **Custom Rules**: Manual IP blocking with optional expiration
- **Whitelist Management**: Exempt specific IPs from blocking
- **nftables Integration**: Uses nftables sets for efficient blocking
- **Auto-Update**: Scheduled blocklist updates
- **Statistics**: Track blocked packets and history
- **Import/Export**: Bulk IP list management

## API Endpoints

All endpoints require JWT authentication except health checks.

### Health & Status
- `GET /health` - Health check
- `GET /status` - Module status and nftables availability

### Configuration
- `GET /config` - Get current configuration
- `POST /config` - Update configuration

### Blocklist Sources
- `GET /lists` - List active blocklist sources
- `GET /lists/available` - List available blocklist sources
- `POST /list/add` - Add a blocklist source
- `DELETE /list/{id}` - Remove a blocklist source
- `POST /list/{id}/update` - Update a specific blocklist
- `POST /lists/update-all` - Update all enabled blocklists

### Blocked IPs
- `GET /blocked` - Get manually blocked IPs
- `POST /block` - Block an IP address
- `DELETE /block/{ip}` - Unblock an IP address

### Whitelist
- `GET /whitelist` - Get whitelisted IPs
- `POST /whitelist` - Add IP to whitelist
- `DELETE /whitelist/{ip}` - Remove IP from whitelist

### Statistics & History
- `GET /stats` - Get block statistics
- `GET /history` - Get block history

### Import/Export
- `POST /import` - Import IP list
- `GET /export` - Export blocked IPs

### Apply Rules
- `POST /apply` - Apply all rules to nftables

## Configuration

Configuration is stored in `/var/lib/secubox/ipblock/state.json`:

```json
{
  "config": {
    "auto_update_enabled": true,
    "update_interval": 86400,
    "log_blocked": true,
    "block_action": "drop"
  }
}
```

## nftables Table

The module creates an `inet ipblock` table with:
- `blocked_v4` / `blocked_v6` sets for blocked IPs
- `whitelist_v4` / `whitelist_v6` sets for whitelisted IPs
- Input and output chains with priority -5

## File Locations

- API: `/usr/lib/secubox/ipblock/`
- Web UI: `/usr/share/secubox/www/ipblock/`
- State: `/var/lib/secubox/ipblock/state.json`
- Lists: `/var/lib/secubox/ipblock/lists/`
- History: `/var/lib/secubox/ipblock/history.json`
- nftables: `/etc/nftables.d/ipblock.nft`

## Systemd Service

```bash
systemctl status secubox-ipblock
systemctl restart secubox-ipblock
journalctl -u secubox-ipblock -f
```

## Building

```bash
cd packages/secubox-ipblock
dpkg-buildpackage -us -uc -b
```

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
