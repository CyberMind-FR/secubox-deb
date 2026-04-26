# Configuration Advanced

Advanced configuration options for SecuBox OS.

---

## Configuration Files

| File | Description |
|------|-------------|
| `/etc/secubox/secubox.conf` | Main TOML configuration |
| `/etc/secubox/modules.d/` | Per-module configs |
| `/etc/netplan/*.yaml` | Network configuration |
| `/etc/nftables.conf` | Firewall rules |

---

## TOML Configuration

### Main Config

```toml
# /etc/secubox/secubox.conf

[system]
hostname = "secubox"
timezone = "Europe/Paris"
locale = "fr_FR.UTF-8"

[api]
listen = "/run/secubox/api.sock"
jwt_secret_file = "/etc/secubox/secrets/jwt.key"
jwt_expiry = 3600

[logging]
level = "info"
audit_log = "/var/log/secubox/audit.log"
```

### Module Config Example

```toml
# /etc/secubox/modules.d/crowdsec.toml

[crowdsec]
enabled = true
api_url = "http://127.0.0.1:8080"
bouncer_key_file = "/etc/secubox/secrets/crowdsec-bouncer.key"

[crowdsec.thresholds]
ban_duration = "4h"
captcha_duration = "1h"
```

---

## Network Modes

### Router Mode (Default)

```yaml
# /etc/netplan/00-secubox.yaml
network:
  version: 2
  ethernets:
    wan0:
      dhcp4: true
  bridges:
    br-lan:
      interfaces: [lan0, lan1]
      addresses: [192.168.1.1/24]
      dhcp4: false
```

### Bridge Mode

```yaml
network:
  version: 2
  bridges:
    br0:
      interfaces: [wan0, lan0, lan1]
      dhcp4: true
```

---

## Firewall Rules

### Add Custom Rule

```bash
# Allow specific port
nft add rule inet filter input tcp dport 8080 accept

# Block IP
nft add rule inet filter input ip saddr 1.2.3.4 drop

# Save rules
nft list ruleset > /etc/nftables.conf
```

### Default Policy

SecuBox uses **DEFAULT DROP** policy:
- All incoming blocked except established
- All outgoing allowed
- Explicit rules for services

---

## API Authentication

### Generate New JWT Secret

```bash
openssl rand -base64 32 > /etc/secubox/secrets/jwt.key
chmod 600 /etc/secubox/secrets/jwt.key
systemctl restart secubox-api
```

### API Token

```bash
# Get token
curl -X POST https://localhost:9443/api/v1/auth/login \
    -d '{"username":"admin","password":"secubox"}' \
    -H "Content-Type: application/json"

# Use token
curl -H "Authorization: Bearer <token>" \
    https://localhost:9443/api/v1/system/status
```

---

## Double-Buffer Configuration

SecuBox uses PARAMETERS double-buffer for safe config changes:

```
/etc/secubox/
├── active/      ← Live config (read-only)
├── shadow/      ← Edit here
└── rollback/    ← R1-R4 snapshots
```

### Swap Config

```bash
secubox-config validate   # Validate shadow
secubox-config swap       # Atomic swap
secubox-config rollback   # Revert to R1
```

---

## See Also

- [[Configuration]] — Basic configuration
- [[Troubleshooting]] — Common issues
- [[Architecture-Security]] — Security model

---

*← Back to [[Home|SecuBox OS]]*
