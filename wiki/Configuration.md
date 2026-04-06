# SecuBox Configuration

[English](Configuration) | [Français](Configuration-FR) | [中文](Configuration-ZH)

## Configuration Files

SecuBox uses TOML configuration files located in `/etc/secubox/`.

### Main Configuration

```
/etc/secubox/
├── secubox.toml          # Main configuration
├── modules/              # Per-module configs
│   ├── crowdsec.toml
│   ├── wireguard.toml
│   ├── dpi.toml
│   └── ...
├── tls/                  # TLS certificates
│   ├── cert.pem
│   └── key.pem
└── secrets/              # Sensitive data (chmod 600)
    └── jwt.key
```

### secubox.toml

```toml
[general]
hostname = "secubox"
timezone = "Europe/Paris"
locale = "en_US.UTF-8"

[network]
wan_interface = "eth0"
lan_interfaces = ["lan0", "lan1"]
bridge_name = "br-lan"
lan_ip = "192.168.1.1"
lan_netmask = "255.255.255.0"
dhcp_enabled = true
dhcp_range_start = "192.168.1.100"
dhcp_range_end = "192.168.1.200"

[security]
firewall_enabled = true
default_policy = "drop"
crowdsec_enabled = true
waf_enabled = true

[services]
nginx_enabled = true
haproxy_enabled = true
ssh_enabled = true
ssh_port = 22
```

## Module Configuration

Each module has its own configuration file in `/etc/secubox/modules/`.

### Example: CrowdSec

```toml
# /etc/secubox/modules/crowdsec.toml
[crowdsec]
enabled = true
api_url = "http://127.0.0.1:8080"
log_level = "info"

[bouncers]
firewall = true
nginx = true

[scenarios]
ssh_bruteforce = true
http_bad_user_agent = true
```

### Example: WireGuard

```toml
# /etc/secubox/modules/wireguard.toml
[wireguard]
enabled = true
interface = "wg0"
listen_port = 51820
private_key_file = "/etc/secubox/secrets/wg_private.key"

[peers]
# Peers are managed via API
```

## Environment Variables

Some settings can be overridden via environment variables:

```bash
SECUBOX_DEBUG=1              # Enable debug mode
SECUBOX_LOG_LEVEL=debug      # Set log level
SECUBOX_CONFIG=/path/to/cfg  # Custom config path
```

## Applying Changes

After modifying configuration:

```bash
# Validate configuration
secubox-config validate

# Apply changes
secubox-config apply

# Or restart specific module
systemctl restart secubox-<module>
```

## Double-Buffer System (CSPN)

For security-critical changes, SecuBox uses a double-buffer system:

```
/etc/secubox/
├── active/     # Current live config (read-only)
├── shadow/     # Pending changes (editable)
└── rollback/   # 4 previous versions (R1-R4)
```

### Workflow

1. Edit in `shadow/`
2. Validate: `secubox-config validate --shadow`
3. Swap: `secubox-config swap`
4. Rollback if needed: `secubox-config rollback R1`

## See Also

- [[Installation]] — Initial setup
- [[API-Reference]] — REST API documentation
- [[Modules]] — Available modules
- [[Troubleshooting]] — Common issues
