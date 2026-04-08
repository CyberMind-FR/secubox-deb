# SecuBox Reporter

System reporting module that generates PDF and HTML reports for SecuBox. Supports multiple report types with scheduled generation capabilities.

## Features

- PDF and HTML report generation
- Multiple report types: Daily, Weekly, Security, Network
- Background report generation with status tracking
- Report scheduling with cron expressions
- System statistics collection (CPU, memory, disk, network)
- SecuBox services status monitoring
- Report index persistence across restarts
- Automatic stats cache refresh (60s interval)
- Download completed reports with proper MIME types
- Report deletion with file cleanup

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check (public) |
| GET | /status | Module status and report counts |
| GET | /reports | List generated reports (paginated) |
| POST | /reports/generate | Generate a new report |
| GET | /reports/{id} | Get report details |
| GET | /reports/{id}/download | Download report file |
| DELETE | /reports/{id} | Delete a report |
| GET | /templates | List available report templates |
| GET | /schedule | Get report generation schedule |
| POST | /schedule | Update report schedule |
| GET | /stats | Get current system stats |

## Report Types

| Type | Description | Default Sections |
|------|-------------|------------------|
| daily | Daily system health summary | system_health, services_status, alerts_summary, network_stats |
| weekly | Weekly analysis with trends | system_health, services_status, alerts_summary, network_stats, security_events, bandwidth_usage, top_clients |
| security | Security events and incidents | security_events, crowdsec_decisions, blocked_ips, auth_failures, waf_alerts, vulnerability_scan |
| network | Network traffic analysis | interface_stats, bandwidth_usage, top_protocols, top_clients, dns_queries, connection_summary |

## Configuration

**Schedule file:** `/etc/secubox/reporter-schedule.json`

Example schedule configuration:
```json
{
  "enabled": true,
  "schedules": [
    {
      "id": "daily",
      "cron": "0 6 * * *",
      "report_type": "daily",
      "format": "pdf",
      "enabled": true,
      "description": "Daily report at 6:00 AM"
    },
    {
      "id": "weekly",
      "cron": "0 7 * * 1",
      "report_type": "weekly",
      "format": "pdf",
      "enabled": true,
      "description": "Weekly report on Monday at 7:00 AM"
    }
  ]
}
```

### Generate Report Request (POST /reports/generate)

```json
{
  "report_type": "daily",
  "format": "pdf",
  "start_date": "2024-01-01",
  "end_date": "2024-01-31",
  "sections": ["system_health", "services_status"],
  "title": "Custom Report Title"
}
```

### Update Schedule (POST /schedule)

```json
{
  "cron": "0 8 * * *",
  "report_type": "daily",
  "format": "pdf",
  "enabled": true
}
```

## Dependencies

- secubox-core (>= 1.0)
- python3-weasyprint | wkhtmltopdf (for PDF generation)
- psutil (Python system monitoring)

**Recommended:** python3-weasyprint for better PDF quality.

## Files

- `/var/lib/secubox/reports/` - Generated reports directory
- `/var/lib/secubox/reports/index.json` - Reports index/metadata
- `/var/cache/secubox/reporter/stats.json` - Cached system stats
- `/etc/secubox/reporter-schedule.json` - Scheduling configuration
- `/usr/share/secubox/reporter/templates/` - Report templates
- `/run/secubox/reporter.sock` - Unix socket for API

## Report Status Workflow

1. **pending** - Report queued for generation
2. **generating** - Report being created
3. **completed** - Report ready for download
4. **failed** - Generation failed (check error field)

## Usage Examples

### Generate a security report

```bash
curl -X POST -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" \
     -d '{"report_type": "security", "format": "pdf"}' \
     http://localhost/api/v1/reporter/reports/generate
```

### List recent reports

```bash
curl -H "Authorization: Bearer $JWT" \
     "http://localhost/api/v1/reporter/reports?limit=10"
```

### Download a report

```bash
curl -H "Authorization: Bearer $JWT" \
     -o report.pdf \
     http://localhost/api/v1/reporter/reports/abc123/download
```

### Schedule daily reports

```bash
curl -X POST -H "Authorization: Bearer $JWT" \
     -H "Content-Type: application/json" \
     -d '{"cron": "0 6 * * *", "report_type": "daily", "format": "pdf", "enabled": true}' \
     http://localhost/api/v1/reporter/schedule
```

### Get current system stats

```bash
curl -H "Authorization: Bearer $JWT" \
     http://localhost/api/v1/reporter/stats
```

## Report Styling

Reports use a P31 phosphor-inspired color palette:

- Primary green: #00dd44 (peak)
- Accent amber: #ffb347 (decay)
- Background: Light tube colors (#e8f5e9)
- Monospace font: Courier Prime

Reports are optimized for both screen viewing and printing.

## Security Notes

- All API endpoints (except /health) require JWT authentication
- Reports are stored with unique UUIDs
- File paths are validated before serving
- Background task isolation prevents blocking

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind — https://cybermind.fr
