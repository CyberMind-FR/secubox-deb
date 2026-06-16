# SecuBox Security Posture

**DEFCON-Level Security Health & CSPN/TPN Media Compliance Monitoring**

## Overview

The `secubox-security-posture` module provides comprehensive security health monitoring, compliance checking, and performance analysis for SecuBox, aligned with **ANSSI CSPN** and **TPN Media** certification requirements.

### Key Features

1. **DEFCON-Level Security Scoring**
   - Military-standard DEFCON levels (1-5)
   - Real-time security score (0-100)
   - Per-category scoring (network, threat, access, data, resilience)
   - Visual indicators (colors, emojis)

2. **CSPN Compliance**
   - Automated checks for ANSSI CSPN test matrix
   - Traceability to CSPN requirements
   - Compliance reporting for auditors
   - Certificate readiness assessment

3. **TPN Media Compliance**
   - Media industry-specific requirements
   - Content protection and anti-piracy
   - DRM integration verification
   - Partner trust validation

4. **Performance Monitoring**
   - System resource monitoring (CPU, memory, disk, network)
   - Service performance metrics (WAF, CrowdSec, mitmproxy, etc.)
   - Bottleneck detection and analysis
   - Optimization recommendations

5. **Combined Dashboard**
   - Unified security posture overview
   - Integrated DEFCON + CSPN + TPN + Performance
   - Actionable recommendations

## DEFCON Levels

| DEFCON | Level | Color | Description | Score Range |
|--------|-------|-------|-------------|-------------|
| DEFCON 5 | Normal | 🟢 Green | All systems operational | 90-100% |
| DEFCON 4 | Increased Chatter | 🟡 Yellow | Minor issues detected | 70-89% |
| DEFCON 3 | Heightened | 🟠 Orange | Active threats being mitigated | 50-69% |
| DEFCON 2 | Severe | 🔴 Red | Major incident in progress | 30-49% |
| DEFCON 1 | Maximum | 🔴 Flashing | Critical breach detected | 0-29% |

## API Endpoints

All endpoints are available at `/api/v1/security-posture/` via unix socket.

### DEFCON Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/defcon` | Full DEFCON info with all indicators |
| GET | `/defcon/summary` | Lightweight DEFCON summary |
| GET | `/defcon/indicators` | All DEFCON indicators with values |
| GET | `/defcon/category/{category}` | Indicators for specific category |

### CSPN Compliance Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/cspn` | Full CSPN compliance report |
| GET | `/cspn/summary` | CSPN compliance summary |
| GET | `/cspn/requirements` | All CSPN requirements |
| GET | `/cspn/requirements/{req_id}` | Specific CSPN requirement |
| GET | `/cspn/certificate/readiness` | CSPN certificate readiness |

### TPN Media Compliance Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/tpn` | Full TPN Media compliance report |
| GET | `/tpn/summary` | TPN compliance summary |
| GET | `/tpn/requirements` | All TPN requirements |
| GET | `/tpn/requirements/{req_id}` | Specific TPN requirement |
| GET | `/tpn/certificate/readiness` | TPN certificate readiness |

### Performance Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/performance` | All performance metrics |
| GET | `/performance/summary` | Performance summary |
| GET | `/performance/bottlenecks` | Detected bottlenecks |
| GET | `/performance/recommendations` | Optimization recommendations |
| GET | `/performance/history` | Performance history (default 24h) |
| GET | `/performance/history?hours={n}` | Performance history for N hours |

### Combined Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/overview` | Combined security posture overview |
| GET | `/health` | Service health check |
| POST | `/checks/run` | Run all compliance checks (background) |

## Example Usage

### Check DEFCON Level

```bash
curl --unix-socket /run/secubox/security-posture.sock \
  http://localhost/api/v1/security-posture/defcon | jq .
```

Response:
```json
{
  "level": "defcon_3",
  "level_name": "Defcon 3",
  "score": 74.5,
  "score_int": 74,
  "color": "#f97316",
  "emoji": "🟠",
  "blink": false,
  "description": "🟠 HEIGHTENED • Active threats being detected and mitigated • Security Score: 74.5/100 • Active monitoring required",
  "recommendations": [
    "🟠 Review active threat alerts in Threat Analyst",
    "🟠 Verify WAF rules are up to date",
    ...
  ],
  "category_scores": {
    "network": 85.0,
    "threat": 70.0,
    "access": 90.0,
    "data": 80.0,
    "resilience": 95.0
  },
  "cspn_compliance": {
    "status": "compliant",
    "score": 74.5,
    "threshold": 70,
    "warnings": [],
    ...
  },
  "tpn_compliance": {
    "status": "non_compliant",
    "score": 74.5,
    "threshold": 85,
    ...
  }
}
```

### Check CSPN Compliance

```bash
curl --unix-socket /run/secubox/security-posture.sock \
  http://localhost/api/v1/security-posture/cspn/summary | jq .
```

Response:
```json
{
  "timestamp": "2026-06-16T14:30:00Z",
  "summary": {
    "total_requirements": 24,
    "total_weight": 120,
    "passed": 108,
    "failed": 0,
    "warnings": 6,
    "skipped": 6,
    "pass_percentage": 90.0,
    "fail_percentage": 0.0,
    "warning_percentage": 5.0,
    "compliance_score": 90.0,
    "is_compliant": true
  }
}
```

### Check Performance

```bash
curl --unix-socket /run/secubox/security-posture.sock \
  http://localhost/api/v1/security-posture/performance/summary | jq .
```

Response:
```json
{
  "timestamp": "2026-06-16T14:30:00Z",
  "score": 82.5,
  "status": "good",
  "color": "#86efac",
  "emoji": "🟢",
  "category_scores": {
    "cpu": 90.0,
    "memory": 75.0,
    "disk": 85.0,
    "network": 95.0,
    "io": 80.0,
    "service": 80.0
  },
  "bottlenecks": 1,
  "critical_bottlenecks": 0
}
```

### Get Combined Overview

```bash
curl --unix-socket /run/secubox/security-posture.sock \
  http://localhost/api/v1/security-posture/overview | jq .
```

Response:
```json
{
  "timestamp": "2026-06-16T14:30:00Z",
  "combined_score": 85.3,
  "overall_status": "good",
  "overall_color": "#86efac",
  "overall_emoji": "🟢",
  "defcon": {
    "level": "defcon_3",
    "level_name": "Defcon 3",
    "score": 74.5,
    "color": "#f97316",
    ...
  },
  "cspn": {
    "compliant": true,
    "score": 90.0
  },
  "tpn_media": {
    "compliant": false,
    "score": 75.0
  },
  "performance": {
    "score": 82.5,
    "status": "good",
    "bottlenecks": 1
  },
  "recommendations": [
    {"source": "defcon", "severity": "medium", "text": "..."},
    {"source": "tpn", "severity": "high", "text": "TPN Media compliance score 75.0%..."}
  ]
}
```

## Architecture

### Module Structure

```
packages/secubox-security-posture/
├── api/
│   ├── __init__.py          # Package init
│   ├── main.py              # FastAPI endpoints
│   ├── defcon.py            # DEFCON calculator
│   ├── cspn_compliance.py   # CSPN compliance checker
│   ├── tpn_compliance.py    # TPN Media compliance checker
│   └── performance.py        # Performance monitor
├── debian/
│   ├── changelog
│   ├── control
│   ├── rules
│   ├── source/
│   │   └── format
│   ├── secubox-security-posture.service
│   └── secubox-security-posture.sock
└── README.md
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    SecuBox Security Posture                    │
├─────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  DEFCON     │    │  CSPN       │    │  TPN Media   │      │
│  │  Engine     │    │  Checker    │    │  Checker    │      │
│  │             │    │             │    │             │      │
│  │• 12 metrics │    │• 24 reqs    │    │• 20 reqs    │      │
│  │• Score 0-100│    │• Auto check │    │• Auto check │      │
│  │• DEFCON 1-5 │    │• CSPN align │    │• Media spec │      │
│  └─────────────┘    └─────────────┘    └─────────────┘      │
│          │                  │                   │             │
│          └──────────────────┼───────────────────┘             │
│                             │                                 │
│                    ┌────────▼────────┐                         │
│                    │   Performance    │                         │
│                    │    Monitor       │                         │
│                    │                 │                         │
│                    │• 15 metrics      │                         │
│                    │• Bottleneck det. │                         │
│                    │• Recommendations │                         │
│                    └────────┬────────┘                         │
│                             │                                 │
│                    ┌────────▼────────┐                         │
│                    │   FastAPI       │                         │
│                    │    Endpoints     │                         │
│                    │                 │                         │
│                    │• /defcon        │                         │
│                    │• /cspn          │                         │
│                    │• /tpn           │                         │
│                    │• /performance    │                         │
│                    │• /overview       │                         │
│                    └─────────────────┘                         │
│                                                                 │
└─────────────────────────────────────────────────────────────┘
             │          │          │           │
             ▼          ▼          ▼           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Data Sources                               │
├─────────────────────────────────────────────────────────────┤
│  • WAF (mitmproxy)    • CrowdSec    • Health Doctor        │
│  • nftables          • System        • HAProxy              │
│  • Nginx             • psutil       • Threat Analyst       │
└─────────────────────────────────────────────────────────────┘
```

## Integration

### With SecuBox Aggregator

To integrate with the SecuBox aggregator, add `security-posture` to the modules list in `/etc/secubox/aggregator.toml`:

```toml
[modules]
modules = [
    "hub",
    "threat-analyst",
    "health-doctor",
    "security-posture",
    # ... other modules
]
```

### With nginx

The module provides a unix socket at `/run/secubox/security-posture.sock`. To expose via nginx:

```nginx
location /api/v1/security-posture/ {
    proxy_pass http://unix:/run/secubox/security-posture.sock:
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    
    # For WebSocket support
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

## Installation

### Build Package

```bash
cd packages/secubox-security-posture
dpkg-buildpackage -us -uc -b
```

### Install Package

```bash
sudo apt install ../secubox-security-posture_1.0.0-1_all.deb
```

### Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable secubox-security-posture.service
sudo systemctl start secubox-security-posture.service
sudo systemctl status secubox-security-posture.service
```

### Enable Socket

```bash
sudo systemctl enable secubox-security-posture.sock
sudo systemctl start secubox-security-posture.sock
```

## Development

### Run Standalone (Testing)

```bash
cd packages/secubox-security-posture
python3 -m uvicorn api.main:app --reload --port 8082
```

Then access at `http://localhost:8082/api/v1/security-posture/`

### Run Tests

```bash
cd packages/secubox-security-posture
python3 -m pytest tests/ -v
```

## DEFCON Indicator Weights

| Category | Weight | Description |
|----------|--------|-------------|
| Network | 30% | WAF, Firewall, nftables |
| Threat | 25% | CrowdSec, DPI, detection |
| Access | 20% | Auth, privilege, ACL |
| Data | 15% | Encryption, integrity |
| Resilience | 10% | Uptime, backups |

## Performance Metric Weights

| Category | Weight | Description |
|----------|--------|-------------|
| CPU | 25% | CPU usage metrics |
| Memory | 25% | Memory usage metrics |
| Disk | 15% | Disk usage metrics |
| Network | 10% | Network bandwidth |
| I/O | 10% | Disk I/O |
| Service | 15% | Service latency/throughput |

## CSPN Compliance Thresholds

| Requirement Type | Threshold |
|------------------|-----------|
| Overall Score | ≥ 70% |
| Network Category | ≥ 80% |
| Threat Category | ≥ 70% |
| Access Category | ≥ 80% |
| Data Category | ≥ 80% |
| Resilience Category | ≥ 70% |

## TPN Media Compliance Thresholds

| Requirement Type | Threshold |
|------------------|-----------|
| Overall Score | ≥ 85% |
| All Categories | ≥ 80% (varies by category) |
| CSPN Compliance | Must pass |

## Security Considerations

- All endpoints are accessible via **unix socket only** (no HTTP exposure)
- Socket permissions: `0660 root:secubox`
- No authentication required (security via socket permissions)
- Service runs as `secubox` user (non-root)
- AppArmor profile should be configured for additional protection

## License

This module is part of SecuBox and is licensed under the **CyberMind Source-Disclosed License v1.0 (CMSD-1.0)**.

See [LICENCE-CMSD-1.0.md](../../../LICENCE-CMSD-1.0.md) for details.

## References

- [ANSSI CSPN Certification](https://www.ssi.gouv.fr/en/certification/cspn/)
- [TPN Media Security Requirements](https://www.trustedpartnernetwork.com/)
- [DEFCON Levels (Wikipedia)](https://en.wikipedia.org/wiki/DEFCON)

---

**Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>**
