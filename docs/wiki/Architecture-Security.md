# Architecture — Security Model

SecuBox OS security architecture for ANSSI CSPN certification.

---

## Security Principles

| Principle | Implementation |
|-----------|----------------|
| **Defense in Depth** | Multiple security layers |
| **Default Deny** | nftables DROP policy |
| **Least Privilege** | Per-module user/group |
| **Audit Trail** | Immutable logging |
| **Secure by Default** | Hardened out of the box |

---

## Security Layers

```
┌─────────────────────────────────────────────────┐
│ L1: Network Perimeter                           │
│     nftables, CrowdSec, Geo-blocking            │
├─────────────────────────────────────────────────┤
│ L2: Application Security                        │
│     HAProxy TLS 1.3, WAF, mitmproxy             │
├─────────────────────────────────────────────────┤
│ L3: Authentication                              │
│     JWT, ZKP (optional), OAuth2                 │
├─────────────────────────────────────────────────┤
│ L4: System Hardening                            │
│     AppArmor, seccomp, namespaces               │
├─────────────────────────────────────────────────┤
│ L5: Audit & Compliance                          │
│     Immutable logs, CSPN audit trail            │
└─────────────────────────────────────────────────┘
```

---

## Firewall (nftables)

### Default Policy

```nft
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        # Explicit service rules only
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

### Rule Management

```bash
# View rules
nft list ruleset

# Add rule (via module API)
POST /api/v1/firewall/rules
{
    "action": "accept",
    "protocol": "tcp",
    "dport": 443,
    "source": "any"
}
```

---

## IDS/IPS Stack

### CrowdSec

- Community threat intelligence
- Automatic bouncer (ban/captcha)
- Local decision engine

### Suricata (optional)

- ET Open rules
- Protocol anomaly detection
- TLS fingerprinting

---

## WAF Configuration

### HAProxy + mitmproxy

```
Internet → HAProxy (TLS 1.3) → mitmproxy → Backend
              │                    │
              └──────────────────────→ Logs
```

**Rules:**
- OWASP ModSecurity CRS
- Custom SecuBox rules
- No WAF bypass allowed

---

## Authentication

### JWT Tokens

```
Header: { "alg": "HS256", "typ": "JWT" }
Payload: { "sub": "admin", "scope": ["admin"], "exp": ... }
Signature: HMAC-SHA256(secret, header.payload)
```

### Token Flow

1. `POST /api/v1/auth/login` → JWT
2. Include `Authorization: Bearer <token>` in requests
3. Token expires after 1 hour (configurable)

---

## Privilege Separation

Each module runs under dedicated user:

```
secubox-crowdsec  → crowdsec:crowdsec
secubox-waf       → mitmproxy:mitmproxy
secubox-dns       → unbound:unbound
secubox-hub       → secubox:secubox
```

### AppArmor Profiles

```
/etc/apparmor.d/secubox-<module>
```

All profiles in **enforce** mode.

---

## Audit Logging

### Immutable Log

```
/var/log/secubox/audit.log
```

- Append-only (chattr +a)
- RFC 3339 timestamps
- All security decisions logged
- Rotation without truncate

### Log Format

```json
{
    "timestamp": "2026-04-26T20:45:00Z",
    "module": "crowdsec",
    "action": "ban",
    "target": "1.2.3.4",
    "reason": "brute-force",
    "duration": "4h"
}
```

---

## CSPN Requirements

| Requirement | Implementation |
|-------------|----------------|
| Privilege separation | Per-module users |
| Encryption | TLS 1.3 minimum |
| Authentication | JWT + optional ZKP |
| Audit trail | Immutable logs |
| Rollback | 4R double-buffer |
| Surface minimization | Unused services disabled |

---

## See Also

- [[Architecture-Boot]] — Boot security
- [[Architecture-Modules]] — Module isolation
- [[Configuration-Advanced]] — Security config

---

*← Back to [[Home|SecuBox OS]]*
