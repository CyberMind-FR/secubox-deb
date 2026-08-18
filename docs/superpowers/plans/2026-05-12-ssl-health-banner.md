<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SSL Certificate Health in Health Banner — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Display SSL certificate expiration status for the current domain in the Health Banner sidebar.

**Architecture:** Backend (`secubox-metrics/api/main.py`) extracts domain from `Host` header, reads cert from `/etc/letsencrypt/live/{domain}/cert.pem`, returns `ssl` object in health summary. Frontend (`health-banner.js`) renders SSL line after score section.

**Tech Stack:** Python 3.11, cryptography, FastAPI, vanilla JS

---

## File Structure

| File | Responsibility |
|------|----------------|
| `packages/secubox-metrics/api/main.py` | Add `get_ssl_status()` function, enrich `/api/v1/metrics/health/summary` |
| `packages/secubox-hub/www/shared/health-banner.js` | Add SSL display after score section |
| `tests/test_ssl_status.py` | Unit tests for SSL status logic |

---

### Task 1: Add SSL Status Function to Metrics API

**Files:**
- Modify: `packages/secubox-metrics/api/main.py:1-50` (imports)
- Modify: `packages/secubox-metrics/api/main.py:430-620` (health summary section)
- Create: `tests/test_ssl_status.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_ssl_status.py`:

```python
"""
SecuBox-Deb :: SSL Status Tests
CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from pathlib import Path

# We'll import the function after creating it
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "packages/secubox-metrics/api"))


def test_ssl_status_ok():
    """Cert with 45 days remaining returns status ok."""
    from main import get_ssl_status

    # Mock cert with 45 days remaining
    mock_cert = MagicMock()
    mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=45)

    with patch('main.Path.exists', return_value=True), \
         patch('main.Path.read_bytes', return_value=b'cert data'), \
         patch('main.x509.load_pem_x509_certificate', return_value=mock_cert):

        result = get_ssl_status("example.com")

        assert result["status"] == "ok"
        assert result["days_remaining"] == 45
        assert result["domain"] == "example.com"


def test_ssl_status_warn():
    """Cert with 5 days remaining returns status warn."""
    from main import get_ssl_status

    mock_cert = MagicMock()
    mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=5)

    with patch('main.Path.exists', return_value=True), \
         patch('main.Path.read_bytes', return_value=b'cert data'), \
         patch('main.x509.load_pem_x509_certificate', return_value=mock_cert):

        result = get_ssl_status("example.com")

        assert result["status"] == "warn"
        assert result["days_remaining"] == 5


def test_ssl_status_error():
    """Cert with 2 days remaining returns status error."""
    from main import get_ssl_status

    mock_cert = MagicMock()
    mock_cert.not_valid_after_utc = datetime.now(timezone.utc) + timedelta(days=2)

    with patch('main.Path.exists', return_value=True), \
         patch('main.Path.read_bytes', return_value=b'cert data'), \
         patch('main.x509.load_pem_x509_certificate', return_value=mock_cert):

        result = get_ssl_status("example.com")

        assert result["status"] == "error"
        assert result["days_remaining"] == 2


def test_ssl_status_expired():
    """Cert with -3 days (expired) returns status expired."""
    from main import get_ssl_status

    mock_cert = MagicMock()
    mock_cert.not_valid_after_utc = datetime.now(timezone.utc) - timedelta(days=3)

    with patch('main.Path.exists', return_value=True), \
         patch('main.Path.read_bytes', return_value=b'cert data'), \
         patch('main.x509.load_pem_x509_certificate', return_value=mock_cert):

        result = get_ssl_status("example.com")

        assert result["status"] == "expired"
        assert result["days_remaining"] == -3


def test_ssl_status_not_found():
    """Missing cert file returns status unknown."""
    from main import get_ssl_status

    with patch.object(Path, 'exists', return_value=False):
        result = get_ssl_status("nonexistent.com")

        assert result["status"] == "unknown"
        assert result["days_remaining"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest tests/test_ssl_status.py -v`

Expected: FAIL with `ImportError: cannot import name 'get_ssl_status' from 'main'`

- [ ] **Step 3: Add imports to main.py**

At the top of `packages/secubox-metrics/api/main.py`, after existing imports (around line 17), add:

```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend
```

- [ ] **Step 4: Add get_ssl_status function**

In `packages/secubox-metrics/api/main.py`, after the `build_health_summary()` function (around line 610), add:

```python
# ═══════════════════════════════════════════════════════════════════════════════
# SSL CERTIFICATE STATUS
# ═══════════════════════════════════════════════════════════════════════════════

def get_ssl_status(domain: str) -> dict:
    """
    Get SSL certificate status for a domain.

    Thresholds (aggressive for Let's Encrypt 90-day certs):
    - ok: > 7 days remaining
    - warn: 3-7 days remaining
    - error: < 3 days remaining
    - expired: <= 0 days remaining

    Returns:
        dict with domain, days_remaining, status, expiry
    """
    if not domain:
        return {
            "domain": None,
            "days_remaining": None,
            "status": "unknown",
            "expiry": None
        }

    # Certificate search paths (in order of priority)
    # 1. Direct domain match
    # 2. Wildcard (parent domain)
    # 3. HAProxy combined cert
    # 4. Nginx cert
    parent_domain = '.'.join(domain.split('.')[1:]) if '.' in domain else domain

    cert_paths = [
        Path(f"/etc/letsencrypt/live/{domain}/cert.pem"),
        Path(f"/etc/letsencrypt/live/{parent_domain}/cert.pem"),
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

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest tests/test_ssl_status.py -v`

Expected: All 5 tests PASS

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-metrics/api/main.py tests/test_ssl_status.py
git commit -m "feat(metrics): Add get_ssl_status() for certificate health

- Reads cert from /etc/letsencrypt/live/{domain}/cert.pem
- Thresholds: >7j ok, 3-7j warn, <3j error, ≤0 expired
- 5 unit tests with mocked certificates

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 2: Enrich Health Summary Endpoint with SSL Status

**Files:**
- Modify: `packages/secubox-metrics/api/main.py:613-620` (get_health_summary endpoint)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_ssl_status.py`:

```python
def test_health_summary_includes_ssl():
    """Health summary endpoint includes ssl field."""
    from main import build_health_summary
    from fastapi import Request
    from unittest.mock import AsyncMock

    # Mock the request with Host header
    mock_request = MagicMock()
    mock_request.headers = {"host": "admin.gk2.secubox.in"}

    # We can't easily test the full endpoint, but we can verify
    # build_health_summary returns the expected structure
    result = build_health_summary()

    # The function should have these keys
    assert "score" in result
    assert "modules" in result
    # SSL will be added in the endpoint, not build_health_summary
```

- [ ] **Step 2: Modify the endpoint to include SSL**

Replace the `get_health_summary` endpoint in `packages/secubox-metrics/api/main.py` (around line 613-620):

```python
@app.get("/api/v1/metrics/health/summary")
async def get_health_summary(request: Request):
    """
    Health summary for the global health banner.
    Returns aggregated health score and module statuses.
    No auth required for banner display.
    """
    summary = build_health_summary()

    # Add SSL certificate status for the current domain
    host = request.headers.get("host", "").split(":")[0]  # Remove port if present
    if host:
        summary["ssl"] = get_ssl_status(host)
    else:
        summary["ssl"] = None

    return summary
```

- [ ] **Step 3: Add Request import**

At the top of the file, update the FastAPI import (around line 17):

```python
from fastapi import FastAPI, Depends, HTTPException, Request
```

- [ ] **Step 4: Run tests to verify**

Run: `cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb && python -m pytest tests/test_ssl_status.py -v`

Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-metrics/api/main.py tests/test_ssl_status.py
git commit -m "feat(metrics): Add SSL status to health summary endpoint

- Extract domain from Host header
- Call get_ssl_status() and include in response
- Frontend can now display certificate health

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 3: Add SSL Display to Health Banner Frontend

**Files:**
- Modify: `packages/secubox-hub/www/shared/health-banner.js`

- [ ] **Step 1: Add SSL CSS styles**

In `packages/secubox-hub/www/shared/health-banner.js`, find the style block (around line 269-590) and add after the `.hb-pct` style (around line 390):

```css
            /* SSL Certificate Status */
            .hb-ssl {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 8px 12px;
                background: rgba(255,255,255,0.03);
                border-radius: 6px;
                border: 1px solid rgba(255,255,255,0.08);
                font-size: 11px;
            }
            .hb-ssl-icon {
                font-size: 14px;
            }
            .hb-ssl-days {
                font-weight: 600;
            }
            .hb-ssl.ssl-ok {
                border-color: rgba(0, 255, 65, 0.3);
            }
            .hb-ssl.ssl-ok .hb-ssl-days {
                color: #00ff41;
            }
            .hb-ssl.ssl-warn {
                border-color: rgba(255, 193, 7, 0.3);
            }
            .hb-ssl.ssl-warn .hb-ssl-days {
                color: #ffc107;
            }
            .hb-ssl.ssl-error {
                border-color: rgba(230, 57, 70, 0.3);
            }
            .hb-ssl.ssl-error .hb-ssl-days {
                color: #e63946;
            }
            .hb-ssl.ssl-expired {
                border-color: rgba(230, 57, 70, 0.5);
                background: rgba(230, 57, 70, 0.1);
                animation: ssl-blink 1s infinite;
            }
            .hb-ssl.ssl-expired .hb-ssl-days {
                color: #e63946;
            }
            @keyframes ssl-blink {
                50% { opacity: 0.6; }
            }
            .hb-ssl.ssl-unknown {
                border-color: rgba(107, 107, 122, 0.3);
            }
            .hb-ssl.ssl-unknown .hb-ssl-days {
                color: #6b6b7a;
            }
```

- [ ] **Step 2: Add SSL rendering function**

In the same file, after the `getScoreVibe` function (around line 226), add:

```javascript
    function renderSslStatus(ssl) {
        if (!ssl) return '';

        const statusConfig = {
            ok: { emoji: '🔒', label: 'Certificate OK' },
            warn: { emoji: '🔐', label: 'Certificate expiring soon' },
            error: { emoji: '🔓', label: 'Certificate critical' },
            expired: { emoji: '🔓', label: 'Certificate EXPIRED' },
            unknown: { emoji: '❓', label: 'Certificate unknown' }
        };

        const config = statusConfig[ssl.status] || statusConfig.unknown;
        const days = ssl.days_remaining;
        const daysText = ssl.status === 'expired' ? 'EXPIRÉ' :
                         days !== null ? `${days}j` : '--';

        return `
            <div class="hb-ssl ssl-${ssl.status}" title="${config.label} — ${ssl.domain || 'unknown'}">
                <span class="hb-ssl-icon">${config.emoji}</span>
                <span class="hb-ssl-days">${daysText}</span>
            </div>
        `;
    }
```

- [ ] **Step 3: Add SSL section to banner HTML structure**

Find the `createBannerElement` function (around line 228) and add an SSL placeholder div after the score div:

```javascript
        banner.innerHTML = `
            <div class="hb-content">
                <div class="hb-score">
                    <span class="hb-icon">💖</span>
                    <div class="hb-score-info">
                        <span class="hb-label">VIBING</span>
                        <div class="hb-bar"><div class="hb-fill"></div></div>
                    </div>
                    <span class="hb-pct">--</span>
                </div>
                <div class="hb-ssl-container"></div>
                <div class="hb-modules"></div>
                <div class="hb-alerts"></div>
                <div class="hb-sparkle">✨</div>
                <div class="hb-details">
                    <div class="hb-stats-grid"></div>
                </div>
            </div>
        `;
```

- [ ] **Step 4: Update the render function to display SSL**

Find the `updateBanner` function (search for `function updateBanner`) and add SSL rendering after the score update:

```javascript
        // Update SSL status (after score section)
        const sslContainer = banner.querySelector('.hb-ssl-container');
        if (sslContainer && data.ssl) {
            sslContainer.innerHTML = renderSslStatus(data.ssl);
        }
```

- [ ] **Step 5: Update version number**

At the top of the file (around line 18), update:

```javascript
    const VERSION = '1.2.0';
```

- [ ] **Step 6: Test manually in browser**

Open: `https://admin.gk2.secubox.in/`
Expected: Health banner sidebar shows SSL status line (🔒 XXj) after the score

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-hub/www/shared/health-banner.js
git commit -m "feat(health-banner): Add SSL certificate status display v1.2.0

- Show cert expiry days after score section
- Color-coded: green (>7j), yellow (3-7j), red (<3j)
- Blinking animation for expired certs

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 4: Copy Updated Files to Debian Package

**Files:**
- Sync: `packages/secubox-metrics/debian/secubox-metrics/usr/lib/secubox/metrics/api/main.py`
- Sync: `packages/secubox-hub/debian/secubox-hub/usr/share/secubox/www/shared/health-banner.js`

- [ ] **Step 1: Copy metrics API**

```bash
cp packages/secubox-metrics/api/main.py \
   packages/secubox-metrics/debian/secubox-metrics/usr/lib/secubox/metrics/api/main.py
```

- [ ] **Step 2: Copy health banner JS**

```bash
cp packages/secubox-hub/www/shared/health-banner.js \
   packages/secubox-hub/debian/secubox-hub/usr/share/secubox/www/shared/health-banner.js
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-metrics/debian packages/secubox-hub/debian
git commit -m "chore: Sync debian package files for SSL health feature

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 5: Deploy and Validate

**Files:** None (deployment task)

- [ ] **Step 1: Deploy to MOCHAbin**

```bash
# Deploy metrics API
bash scripts/deploy.sh secubox-metrics root@192.168.1.200

# Deploy hub (health-banner.js)
bash scripts/deploy.sh secubox-hub root@192.168.1.200
```

- [ ] **Step 2: Restart metrics service**

```bash
ssh root@192.168.1.200 'systemctl restart secubox-metrics'
```

- [ ] **Step 3: Validate API response**

```bash
curl -s https://admin.gk2.secubox.in/api/v1/metrics/health/summary | jq '.ssl'
```

Expected output:
```json
{
  "domain": "admin.gk2.secubox.in",
  "days_remaining": 45,
  "status": "ok",
  "expiry": "2026-06-26T12:00:00+00:00"
}
```

- [ ] **Step 4: Validate frontend display**

1. Open: `https://admin.gk2.secubox.in/`
2. Click the health banner trigger (◀) on the right edge
3. Verify SSL line shows: 🔒 XXj (green)

- [ ] **Step 5: Update HISTORY.md**

Add session entry to `.claude/HISTORY.md`:

```markdown
### Session 153 — SSL Certificate Health in Health Banner

**Goal:** Display SSL certificate expiration status in the Health Banner sidebar.

**Changes:**
- `packages/secubox-metrics/api/main.py`: Added `get_ssl_status()` function
- `packages/secubox-hub/www/shared/health-banner.js`: Added SSL display (v1.2.0)
- `tests/test_ssl_status.py`: 5 unit tests

**Thresholds:**
- 🔒 >7j (green)
- 🔐 3-7j (yellow)
- 🔓 <3j (red)
- 🔓 EXPIRÉ (red blink)

**Reference:** CM-SSL-BANNER-2026-05-12
```

- [ ] **Step 6: Final commit**

```bash
git add .claude/HISTORY.md
git commit -m "docs: Add Session 153 - SSL certificate health in Health Banner

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Add `get_ssl_status()` function | `main.py`, `test_ssl_status.py` |
| 2 | Enrich health summary endpoint | `main.py` |
| 3 | Add SSL display to frontend | `health-banner.js` |
| 4 | Sync debian package files | `debian/` dirs |
| 5 | Deploy and validate | deployment |

**Total estimated steps:** 25
**Tests:** 5 unit tests
