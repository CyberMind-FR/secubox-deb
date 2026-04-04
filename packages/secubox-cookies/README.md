# SecuBox Cookies

Cookie tracking, analysis, and privacy compliance monitoring module for SecuBox-DEB.

## Features

- **Cookie Tracking**: Monitor and track cookies across domains
- **Third-Party Detection**: Identify third-party cookies automatically
- **Tracker Identification**: Match cookies against known tracking patterns
- **Policy Enforcement**: Create and enforce cookie policies
- **GDPR Compliance**: Check compliance with privacy regulations
- **Domain Filtering**: Filter and analyze cookies by domain
- **Statistics Dashboard**: View comprehensive cookie statistics
- **Violation Alerts**: Get alerts for policy violations

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Service status with statistics

### Configuration
- `GET /config` - Get current configuration
- `POST /config` - Update configuration

### Cookie Tracking
- `GET /cookies` - List all tracked cookies (with filters)
- `GET /cookie/{domain}` - Get cookies for a specific domain
- `GET /thirdparty` - List third-party cookies only

### Tracker Management
- `GET /trackers` - List known tracker patterns
- `POST /tracker/add` - Add new tracker pattern
- `DELETE /tracker/{id}` - Remove tracker pattern

### Policy Management
- `GET /policies` - List cookie policies
- `POST /policy` - Create new policy
- `DELETE /policy/{id}` - Delete policy

### Violations & Stats
- `GET /violations` - List policy violations
- `GET /stats` - Get cookie statistics
- `GET /logs` - Get analysis logs

### Scanning
- `POST /scan` - Scan URL for cookies

## Configuration

Configuration file: `/etc/secubox/cookies.json`

```json
{
  "enabled": true,
  "scan_interval": 300,
  "retention_days": 30,
  "block_trackers": true,
  "alert_on_suspicious": true,
  "gdpr_mode": true,
  "third_party_detection": true,
  "tracker_detection": true,
  "known_trackers": [
    {"pattern": ".*google-analytics\\.com.*", "name": "Google Analytics", "category": "analytics"}
  ],
  "policies": [
    {
      "id": "default-gdpr",
      "name": "GDPR Default",
      "enabled": true,
      "block_third_party": false,
      "block_trackers": true,
      "require_consent": true,
      "max_cookie_age_days": 365
    }
  ]
}
```

## Tracker Categories

- `analytics` - Analytics and measurement (Google Analytics, Mixpanel)
- `advertising` - Advertising and retargeting (DoubleClick, Criteo)
- `marketing` - Marketing automation (HubSpot, Intercom)
- `social` - Social media tracking
- `unknown` - Unclassified trackers

## Data Storage

- Configuration: `/etc/secubox/cookies.json`
- Cookie database: `/var/lib/secubox/cookies/cookies.json`
- Violations: `/var/lib/secubox/cookies/violations.json`
- Cache: `/var/cache/secubox/cookies/`
- Logs: `/var/log/secubox/cookies.log`

## Integration

Works with SecuBox MITMProxy for traffic-based cookie analysis. When mitmproxy intercepts HTTP traffic, cookies can be extracted and analyzed automatically.

## Service Management

```bash
# Start service
systemctl start secubox-cookies

# Stop service
systemctl stop secubox-cookies

# View logs
journalctl -u secubox-cookies -f
```

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
