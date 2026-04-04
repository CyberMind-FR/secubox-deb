# SecuBox Threats

Unified Security Threats Dashboard for SecuBox-DEB.

## Features

- **Unified Threat Dashboard**: Centralized view of all security threats
- **Aggregated Alerts**: Collects alerts from CrowdSec, Suricata, and WAF
- **IOC Management**: Track Indicators of Compromise (IPs, domains, hashes, URLs)
- **Threat Intelligence Feeds**: Subscribe to STIX/MISP/CSV feeds
- **Risk Scoring**: Real-time risk assessment based on active threats
- **Incident Tracking**: Create and manage security incidents
- **Timeline View**: Visual timeline of security events
- **Report Generation**: Summary, detailed, and executive reports

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Module status with counts

### Configuration
- `GET /config` - Get configuration
- `POST /config` - Update configuration

### Threats
- `GET /threats` - List active threats
- `GET /threat/{id}` - Get threat details
- `POST /threats` - Create new threat
- `POST /threat/{id}/acknowledge` - Acknowledge threat
- `POST /threat/{id}/resolve` - Resolve threat

### Alerts
- `GET /alerts` - Aggregated alerts from all sources
- `GET /alerts/sources` - List alert sources and status

### IOCs
- `GET /iocs` - List IOCs with search
- `POST /ioc` - Add IOC
- `DELETE /ioc/{id}` - Remove IOC

### Threat Feeds
- `GET /feeds` - List subscribed feeds
- `POST /feed/subscribe` - Subscribe to feed
- `DELETE /feed/{id}` - Unsubscribe

### Timeline & Scores
- `GET /timeline` - Threat timeline (24h default)
- `GET /scores` - Risk scores

### Incidents
- `GET /incidents` - List incidents
- `POST /incident` - Create incident
- `PUT /incident/{id}` - Update incident

### Reports
- `GET /reports` - List generated reports
- `POST /report/generate` - Generate new report
- `GET /report/{id}` - Get report details

## Data Sources

The module aggregates alerts from:

1. **CrowdSec**: Uses `cscli alerts list` command
2. **Suricata IDS**: Parses `/var/log/suricata/eve.json`
3. **WAF**: Reads `/var/log/secubox/waf.json`

## Configuration

Configuration file: `/etc/secubox/threats.toml`

```toml
auto_acknowledge_low = false
alert_retention_days = 30
threat_retention_days = 90
feed_refresh_enabled = true

[risk_score_weights]
severity_critical = 10.0
severity_high = 7.0
severity_medium = 4.0
severity_low = 1.0
```

## Data Storage

Data is stored in `/var/lib/secubox/threats/`:

- `threats.json` - Active threats
- `alerts.json` - Aggregated alerts
- `iocs.json` - IOC database
- `feeds.json` - Feed subscriptions
- `incidents.json` - Incident records
- `reports.json` - Generated reports
- `scores.json` - Cached risk scores

## Frontend

The dashboard is available at `/threats/` and features:

- P31 Phosphor light theme with red accent (#dc2626)
- Risk score gauge visualization
- Tabbed interface: Dashboard, Threats, Alerts, IOCs, Feeds, Incidents, Reports
- Real-time threat timeline
- Alert aggregation by source
- IOC search functionality
- Report generation

## Dependencies

- `secubox-core` - Core library
- `python3-tomli` - TOML configuration parsing

Recommended:
- `secubox-crowdsec` - CrowdSec integration
- `suricata` - Network IDS

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
