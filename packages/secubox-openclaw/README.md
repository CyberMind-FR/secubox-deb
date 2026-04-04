# SecuBox OpenClaw - OSINT Intelligence Module

Open Source Intelligence (OSINT) tool for reconnaissance and information gathering.

## Features

- **Domain Reconnaissance**: DNS enumeration, WHOIS lookup, subdomain discovery
- **IP Intelligence**: Reverse DNS, ASN lookup, port scanning, reputation check
- **Email Analysis**: Email validation, MX records, SPF/DMARC verification
- **Certificate Transparency**: SSL certificate discovery via crt.sh
- **External Integrations**: Shodan, Censys, VirusTotal, SecurityTrails

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Status with statistics

### Configuration
- `GET /config` - Get configuration (masked)
- `POST /config` - Update configuration

### Scanning
- `POST /scan/domain` - Start domain scan
- `POST /scan/ip` - Start IP scan
- `POST /scan/email` - Start email scan
- `GET /scans` - List scan history
- `GET /scan/{id}` - Get scan results
- `DELETE /scan/{id}` - Delete scan

### Quick Lookups
- `GET /subdomains/{domain}` - Subdomain enumeration
- `GET /dns/{domain}` - DNS records
- `GET /whois/{target}` - WHOIS lookup
- `GET /certs/{domain}` - Certificate transparency
- `GET /ports/{ip}` - Port scan (Shodan or direct)
- `GET /reputation/{target}` - Reputation check

### Export
- `GET /exports` - Available export formats
- `POST /export` - Export scan results

### Integrations
- `GET /integrations` - API integration status

## Configuration

Configuration is stored in `/var/lib/secubox/openclaw/config.json`:

```json
{
  "shodan_api_key": "",
  "censys_api_id": "",
  "censys_api_secret": "",
  "virustotal_api_key": "",
  "securitytrails_api_key": "",
  "max_concurrent_scans": 3,
  "scan_timeout": 300,
  "cache_ttl": 3600
}
```

## Dependencies

- `dnsutils` - DNS lookup tools (dig)
- `whois` - WHOIS lookup
- `curl` - HTTP client
- `nmap` (recommended) - Network scanning

## Usage

Access the web interface at: `https://<secubox-host>/openclaw/`

Or use the API directly:
```bash
# Start a domain scan
curl -X POST "https://<host>/api/v1/openclaw/scan/domain?target=example.com" \
  -H "Authorization: Bearer $TOKEN"

# Quick DNS lookup
curl "https://<host>/api/v1/openclaw/dns/example.com" \
  -H "Authorization: Bearer $TOKEN"
```

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
