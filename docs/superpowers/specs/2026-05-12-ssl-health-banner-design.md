<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SSL Certificate Health in Health Banner — Design Spec

> **Reference:** CM-SSL-BANNER-2026-05-12
> **Status:** Approved
> **Author:** Gerald Kerma / Claude

---

## Goal

Display SSL certificate expiration status for the current domain in the SecuBox Health Banner, providing at-a-glance visibility into certificate health for all proxied websites.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser (proxied website)                                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Health Banner (injected by mitmproxy)                    │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  🏥 87%  ████████░░                                 │  │  │
│  │  │  🔒 45j                    ← NEW: SSL status        │  │  │
│  │  │  ┌───┬───┬───┬───┬───┐                             │  │  │
│  │  │  │WAF│CS │HAP│NGX│SYS│                             │  │  │
│  │  │  └───┴───┴───┴───┴───┘                             │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
         │
         │ GET /api/v1/metrics/health/summary
         │ Host: example.gk2.secubox.in
         ▼
┌─────────────────────────────────────────────────────────────────┐
│  SecuBox Hub API                                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  get_ssl_status(domain)                                   │  │
│  │  - Read /etc/letsencrypt/live/{domain}/cert.pem          │  │
│  │  - Parse with cryptography.x509                           │  │
│  │  - Calculate days_remaining                               │  │
│  │  - Return status: ok | warn | error | expired | unknown   │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Scope

### In Scope
- SSL certificate status for the **current domain** (from `Host` header)
- Minimal display: icon + days remaining
- Aggressive thresholds for Let's Encrypt 90-day certs
- Integration with existing Health Banner double-buffer cache

### Out of Scope
- Multi-domain monitoring dashboard
- Email/webhook alerts on expiration
- Certificate renewal automation (handled by certbot)
- Full certificate details (issuer, SAN list, chain)

---

## Backend Changes

### File: `packages/secubox-hub/api/main.py`

#### New Function: `get_ssl_status(domain: str)`

```python
from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_ssl_status(domain: str) -> dict:
    """
    Get SSL certificate status for a domain.

    Returns:
        {
            "domain": "example.gk2.secubox.in",
            "days_remaining": 45,
            "status": "ok",  # ok | warn | error | expired | unknown | none
            "expiry": "2026-06-26T12:00:00Z"
        }
    """
    # Certificate search paths (in order of priority)
    cert_paths = [
        Path(f"/etc/letsencrypt/live/{domain}/cert.pem"),
        Path(f"/etc/letsencrypt/live/{domain.split('.', 1)[-1]}/cert.pem"),  # wildcard
        Path(f"/etc/haproxy/certs/{domain}.pem"),
        Path(f"/etc/nginx/ssl/{domain}.crt"),
    ]

    cert_path = None
    for p in cert_paths:
        if p.exists():
            cert_path = p
            break

    if not cert_path:
        return {
            "domain": domain,
            "days_remaining": None,
            "status": "unknown",
            "expiry": None
        }

    try:
        cert_data = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        now = datetime.now(timezone.utc)
        expiry = cert.not_valid_after_utc
        days_remaining = (expiry - now).days

        # Thresholds: >7j ok, 3-7j warn, <3j error, ≤0 expired
        if days_remaining <= 0:
            status = "expired"
        elif days_remaining < 3:
            status = "error"
        elif days_remaining <= 7:
            status = "warn"
        else:
            status = "ok"

        return {
            "domain": domain,
            "days_remaining": days_remaining,
            "status": status,
            "expiry": expiry.isoformat()
        }
    except Exception as e:
        return {
            "domain": domain,
            "days_remaining": None,
            "status": "unknown",
            "expiry": None,
            "error": str(e)
        }
```

#### Modify: Health Summary Endpoint

Add SSL status to the existing `/api/v1/metrics/health/summary` response:

```python
@app.get("/api/v1/metrics/health/summary")
async def health_summary(request: Request):
    # ... existing code ...

    # Extract domain from Host header
    host = request.headers.get("host", "").split(":")[0]
    ssl_status = get_ssl_status(host) if host else None

    return {
        "score": score,
        "modules": modules,
        "stats": stats,
        "alerts": alerts,
        "ssl": ssl_status  # NEW
    }
```

---

## Frontend Changes

### File: `packages/secubox-hub/www/shared/health-banner.js`

#### CSS Addition (in style block)

```css
/* SSL Certificate Status */
.ssl-status {
    display: flex;
    align-items: center;
    gap: 4px;
    font-size: 12px;
    font-weight: 500;
    padding: 2px 8px;
    border-radius: 4px;
    margin: 4px 0;
}

.ssl-ok {
    color: #00ff41;
    background: rgba(0, 255, 65, 0.1);
}

.ssl-warn {
    color: #ffc107;
    background: rgba(255, 193, 7, 0.1);
}

.ssl-error {
    color: #e63946;
    background: rgba(230, 57, 70, 0.1);
}

.ssl-expired {
    color: #e63946;
    background: rgba(230, 57, 70, 0.2);
    animation: blink 1s infinite;
}

.ssl-unknown {
    color: #6b6b7a;
    background: rgba(107, 107, 122, 0.1);
}

@keyframes blink {
    50% { opacity: 0.5; }
}
```

#### JavaScript Addition (in renderBanner function)

```javascript
// SSL Certificate Status (after score, before modules)
function renderSslStatus(ssl) {
    if (!ssl) return '';

    const statusMap = {
        ok: { emoji: '🔒', label: 'Cert OK' },
        warn: { emoji: '🔐', label: 'Cert expiring soon' },
        error: { emoji: '🔓', label: 'Cert critical' },
        expired: { emoji: '🔓', label: 'Cert EXPIRED' },
        unknown: { emoji: '❓', label: 'Cert unknown' },
        none: { emoji: '🔓', label: 'No HTTPS' }
    };

    const info = statusMap[ssl.status] || statusMap.unknown;
    const days = ssl.days_remaining;
    const daysText = days !== null ? `${days}j` : '--';
    const displayText = ssl.status === 'expired' ? 'EXPIRÉ' :
                        ssl.status === 'none' ? 'HTTP' : daysText;

    return `
        <div class="ssl-status ssl-${ssl.status}" title="${info.label} - ${ssl.domain}">
            ${info.emoji} ${displayText}
        </div>
    `;
}

// In renderBanner(), after score section:
const sslHtml = renderSslStatus(data.ssl);
// Insert sslHtml after scoreHtml, before modulesHtml
```

---

## Error Handling

| Scenario | Backend Response | Frontend Display |
|----------|------------------|------------------|
| Cert found, valid | `status: "ok"`, `days_remaining: 45` | 🔒 45j (green) |
| Cert expiring 3-7 days | `status: "warn"`, `days_remaining: 5` | 🔐 5j (yellow) |
| Cert expiring <3 days | `status: "error"`, `days_remaining: 2` | 🔓 2j (red) |
| Cert expired | `status: "expired"`, `days_remaining: -3` | 🔓 EXPIRÉ (red blink) |
| Cert file not found | `status: "unknown"` | ❓ -- (gray) |
| No Host header | `ssl: null` | (no SSL line shown) |
| HTTP-only domain | `status: "none"` | 🔓 HTTP (gray) |
| Parse error | `status: "unknown"`, `error: "..."` | ❓ -- (gray) |

---

## Caching

SSL status is included in the existing Health Banner cache:
- **Refresh interval:** 30 seconds (existing `REFRESH_INTERVAL`)
- **localStorage TTL:** 5 minutes (existing `CACHE_KEY` with 300000ms TTL)
- **Double-buffer:** Uses existing `HealthCache.write()` → `swap()` pattern

No additional network requests required.

---

## File Permissions

The `secubox-hub` service user needs read access to certificate files:

```bash
# Already handled by secubox-core postinst
usermod -aG ssl-cert secubox-hub
chmod 640 /etc/letsencrypt/live/*/cert.pem
chown root:ssl-cert /etc/letsencrypt/live/*/cert.pem
```

---

## Testing

### Unit Tests: `tests/test_ssl_status.py`

```python
def test_ssl_status_ok():
    """Cert with 45 days remaining → status ok"""

def test_ssl_status_warn():
    """Cert with 5 days remaining → status warn"""

def test_ssl_status_error():
    """Cert with 2 days remaining → status error"""

def test_ssl_status_expired():
    """Cert with -3 days remaining → status expired"""

def test_ssl_status_not_found():
    """Missing cert file → status unknown"""

def test_ssl_status_wildcard():
    """Wildcard cert matches subdomain"""
```

### Integration Test

1. Deploy to MOCHAbin
2. Visit `https://admin.gk2.secubox.in/`
3. Open Health Banner sidebar
4. Verify SSL status line shows: 🔒 XXj (green)

---

## Thresholds

| Days Remaining | Status | Color | Icon |
|----------------|--------|-------|------|
| > 7 | `ok` | Green (#00ff41) | 🔒 |
| 3 - 7 | `warn` | Yellow (#ffc107) | 🔐 |
| 1 - 2 | `error` | Red (#e63946) | 🔓 |
| ≤ 0 | `expired` | Red (blinking) | 🔓 |

These aggressive thresholds assume Let's Encrypt 90-day certificates with certbot auto-renewal at 30 days. Anything under 7 days indicates renewal failure.

---

## Dependencies

- `cryptography` — Already in `common/secubox_core/requirements.txt`
- No new packages required

---

## Version

Increment Health Banner version:
```javascript
const VERSION = '1.2.0';  // was 1.1.0
```

Changelog:
- **1.2.0** — Add SSL certificate health status display
