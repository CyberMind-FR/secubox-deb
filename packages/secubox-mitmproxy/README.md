# 🔍 MITM Proxy

Traffic inspection and WAF proxy with auto-ban

**Category:** Security

## Screenshot

![MITM Proxy](../../docs/screenshots/vm/mitmproxy.png)

## Features

- Traffic inspection
- Request logging
- Auto-ban
- SSL interception

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mitmproxy
```

## Configuration

Configuration file: `/etc/secubox/mitmproxy.toml`

## API Endpoints

- `GET /api/v1/mitmproxy/status` - Module status
- `GET /api/v1/mitmproxy/health` - Health check

## Addons

### `secubox_waf.py`

Inspects every HTTP response in transit, applies the SecuBox WAF ruleset
and injects the health-banner + cookie-inventory bootstrap script before
`</body>` on text/html responses. Domain allow/exclude lists configurable
via `[cdn]`.

### `cookie_audit.py` (issue #156)

Companion to the WAF addon. Captures every `Set-Cookie` header observed in
transit and appends a structured JSONL record to
`/var/log/secubox/cookie-audit/server.jsonl`. Cookie values are
sha256-hashed at the addon — the raw value never leaves the process.

Register both addons together:

```
mitmdump -s /usr/share/secubox/addons/secubox_waf.py \
         -s /usr/share/secubox/addons/cookie_audit.py
```

The companion browser script `shared/cookie-inventory.js` (loaded via the
WAF banner injection) snapshots `document.cookie` and posts to
`/api/v1/cookie-audit/ingest`. The secubox-metrics
`CookieAuditAggregator` reconciles both streams and flags RGPD/ePrivacy
violations (JS-set, non-strictly-necessary cookies).

Enable via `[cookie_audit] enabled = true` in `/etc/secubox/secubox.conf`.

## License

MIT License - CyberMind © 2024-2026
