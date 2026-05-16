# 📈 System Metrics

Real-time system metrics dashboard

**Category:** Dashboard

## Screenshot

![System Metrics](../../docs/screenshots/vm/metrics.png)

## Features

- CPU/Memory
- Network stats
- Disk I/O
- Historical data

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-metrics
```

## Configuration

Configuration file: `/etc/secubox/metrics.toml`

## API Endpoints

- `GET /api/v1/metrics/status` - Module status
- `GET /api/v1/metrics/health` - Health check

## Endpoints — live panel (issue #92)

Three public endpoints feed the health-banner live panel. All are
unauthenticated, CORS-open, and `Cache-Control: public, max-age=300`.

| Method | Path                              | Schema (high-level)                                  |
|--------|-----------------------------------|------------------------------------------------------|
| GET    | `/api/v1/metrics/visitor-origin`  | `{enabled, window_minutes, entries:[{asn,org,count}]}`|
| GET    | `/api/v1/metrics/live-hosts`      | `{enabled, window_minutes, entries:[{host,count}]}`   |
| GET    | `/api/v1/metrics/cert-status`     | `{enabled, summary, next_renewal, warnings}`          |

Config blocks live in `/etc/secubox/secubox.conf`:

```toml
[visitor_origin]
enabled = true
min_count = 5

[live_hosts]
enabled = true

[cert_status]
enabled = true
warn_days = 30

[cookie_audit]
enabled = true
```

## Cookie Audit (RGPD / ePrivacy, issue #156)

Reconciles two cookie streams to detect RGPD violations on
operator-owned vhosts:

| Method | Path                                  | Description                                          |
|--------|---------------------------------------|------------------------------------------------------|
| POST   | `/api/v1/cookie-audit/ingest`         | Browser snapshot ingest (credentials: omit, hashed)  |
| GET    | `/api/v1/cookie-audit/report?host=…`  | Per-vhost reconciled report                          |
| GET    | `/api/v1/cookie-audit/summary`        | Global rollup (counts + violations)                  |

Each cookie's verdict carries a `source` flag — `http` (only server
`Set-Cookie`), `js` (only `document.cookie`, set by client-side script), or
`both`. A `js`-source cookie that is not `strictly_necessary` flips
`rgpd_violation = true` (LCEN art. 82 / ePrivacy). The default classifier
covers GA/Matomo/Hotjar/Facebook/Microsoft Clarity patterns; extend via
`[cookie_audit.classifier]` in `secubox.conf`. Cookie values are
sha256-hashed end-to-end — the API never receives raw values.

Disabled by default. Requires the companion mitmproxy `cookie_audit` addon
(see `packages/secubox-mitmproxy/README.md`) and the browser-side
`shared/cookie-inventory.js` (loaded automatically via the WAF banner
injection).

MaxMind GeoLite2-ASN refresh: install `geoipupdate` (available in Debian
bookworm's `contrib` repository; `secubox-metrics` lists it as a
`Recommends`, not `Depends`, so `apt install secubox-metrics` succeeds
without `contrib` enabled). Drop a license file at
`/etc/secubox/secrets/maxmind.conf` (mode 0600, owner `secubox`).
The `secubox-geoipupdate.timer` runs weekly; if either the binary or the
key is absent, the unit is a silent no-op and the VisitorOrigin banner
section stays hidden.

## License

MIT License - CyberMind © 2024-2026
