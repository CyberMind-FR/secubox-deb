# Developer Guide

Getting started with SecuBox-DEB development.

---

## Tech Stack

### Base System
- **OS**: Debian 12 (Bookworm) ARM64
- **Kernel**: 6.x with netfilter, tc, eBPF modules
- **Transport**: Tailscale (WireGuard-based mesh)
- **Containers**: Docker / Podman

### Security Stack
- **Firewall**: nftables (not iptables)
- **IDS/IPS**: Suricata + CrowdSec
- **WAF**: HAProxy + mitmproxy
- **DNS**: Unbound (Vortex DNS) + blocklists
- **DPI**: nDPId + netifyd (dual-stream via tc mirred)
- **Auth**: SecuBox-ZKP (Hamiltonian NP / GK-HAM-2025)
- **P2P Mesh**: MirrorNet (did:plc + WireGuard + Chain of Hamiltonians)

### Application Stack
- **Backend**: Python 3.11+ (FastAPI / Flask), Bash, C
- **Frontend**: HTML/CSS/JS vanilla or React
- **Config**: YAML + TOML, double-buffer / 4R versioning
- **Pipeline**: 5-stage production pipeline (collect → process → analyze → report → alert)

---

## Code Conventions

### Python

```python
"""
SecuBox-Deb :: <ModuleName>
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/module", tags=["module"])

class MetricsResponse(BaseModel):
    cpu_percent: float
    mem_percent: float
```

### Bash

```bash
#!/usr/bin/env bash
# SecuBox-Deb :: <script_name>
# CyberMind — Gérald Kerma
set -euo pipefail
readonly MODULE="<name>"
readonly VERSION="<semver>"
```

### nftables

```nft
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        log prefix "[SECUBOX-MODULE] " level info
    }
}
```

---

## Double-Buffer / 4R Pattern

All configuration uses the PARAMETERS module with 4R versioning:

```
/etc/secubox/<module>/
├── active/    → live config (read-only in prod)
├── shadow/    → editable, validation before swap
├── rollback/  → 4 timestamped snapshots (R1..R4)
└── pending/   → awaiting ZKP validation
```

### Operations

```bash
# Swap double-buffer (atomic)
secubox-params swap --module <name> --validate-zkp

# Rollback to R1
secubox-params rollback --module <name> --target R1

# Check config status
secubox-params status --module <name>
```

---

## FastAPI Module Structure

```
packages/secubox-<module>/
├── api/
│   ├── __init__.py
│   ├── main.py          ← FastAPI app with router
│   └── routers/
│       └── metrics.py   ← Endpoint implementations
├── core/
│   ├── config.py        ← TOML configuration
│   └── service.py       ← Business logic
├── models/
│   └── schemas.py       ← Pydantic models
├── www/
│   ├── index.html       ← Web UI (from OpenWrt port)
│   └── static/
├── debian/
│   ├── control
│   ├── rules
│   ├── postinst
│   └── prerm
└── README.md
```

---

## Common Commands

```bash
# Build .deb package (cross-compile for ARM64)
cd packages/secubox-<module>
dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b

# Deploy to device via SSH
bash scripts/deploy.sh secubox-<module> root@192.168.1.1

# Run API in development mode
uvicorn api.main:app --reload --uds /tmp/<module>.sock

# Run tests
pytest tests/ -v

# Check system status
systemctl status secubox-* --no-pager

# View live logs
journalctl -u secubox-* -f --output json | jq '.MESSAGE'
```

---

## ANSSI CSPN Compliance

1. **Privilege separation** by layer (L1/L2/L3)
2. **Encryption**: TLS 1.3 minimum
3. **Authentication**: ZKP Hamiltonian (GK-HAM-2025) — no plaintext secrets
4. **Logs**: Immutable, RFC 3339 timestamped, secure rotation
5. **Rollback**: Every config change → 4R snapshot mandatory
6. **Attack surface**: Minimal — disable unused services
7. **Tests**: Coverage ≥ 80%, regression tests on every PR

---

## What NOT to Do

- Use `iptables` (replaced by nftables)
- Use `uci` / LuCI (that's SecuBox-OpenWrt — abandoned)
- Write secrets in plaintext in code
- Use ACCEPT default firewall policies
- Suggest Python libraries with known vulnerabilities
- Ignore double-buffer schema for configs
- Mention "CrowdSec Ambassador" or "CyberMind Produits SASU"

---

## References

- [ANSSI CSPN](https://www.ssi.gouv.fr/entreprise/certification_cspn/)
- [nDPId](https://github.com/utoni/nDPId)
- [CrowdSec Docs](https://docs.crowdsec.net)
- [Suricata Docs](https://docs.suricata.io)
- [nftables Wiki](https://wiki.nftables.org)

---

*See also: [[Developer-Patterns]], [[Architecture-Boot]], [[Design-System]]*
