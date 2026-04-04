# SecuBox DNS Provider

Multi-provider DNS API management module for SecuBox-DEB.

## Features

- **Multi-Provider Support**: OVH, Gandi, Cloudflare, AWS Route53
- **Domain Management**: List and manage domains across providers
- **DNS Record CRUD**: Create, read, update, delete DNS records
- **ACME DNS-01**: Automated certificate challenge support
- **Dynamic DNS**: Update A/AAAA records with current IP
- **Zone Import/Export**: BIND format zone file support
- **Audit Logging**: Comprehensive activity tracking (CSPN compliant)

## API Endpoints

### Health & Status
- `GET /health` - Health check
- `GET /status` - Service status

### Configuration
- `GET /config` - Get configuration
- `POST /config` - Update configuration

### Provider Management
- `GET /providers` - List configured providers
- `POST /provider` - Add provider credentials
- `PUT /provider/{id}` - Update provider
- `DELETE /provider/{id}` - Remove provider

### Domain Management
- `GET /domains` - List domains from all providers
- `GET /domain/{name}/records` - List records for domain
- `POST /domain/{name}/record` - Create record
- `PUT /domain/{name}/record/{id}` - Update record
- `DELETE /domain/{name}/record/{id}` - Delete record

### ACME DNS-01
- `POST /acme/challenge` - Create ACME challenge TXT record
- `DELETE /acme/challenge` - Cleanup challenge record

### Dynamic DNS
- `POST /ddns/update` - Update Dynamic DNS record

### Zone Import/Export
- `GET /zones/export/{domain}` - Export zone (BIND or JSON format)
- `POST /zones/import` - Import zone from BIND format

### Audit
- `GET /logs` - Get audit logs
- `GET /summary` - Get comprehensive summary

## Supported Providers

### Cloudflare
```json
{
  "provider": "cloudflare",
  "name": "My Cloudflare",
  "credentials": {
    "api_token": "your-api-token"
  }
}
```

### Gandi
```json
{
  "provider": "gandi",
  "name": "My Gandi",
  "credentials": {
    "api_key": "your-api-key"
  }
}
```

### OVH
```json
{
  "provider": "ovh",
  "name": "My OVH",
  "credentials": {
    "application_key": "your-app-key",
    "application_secret": "your-app-secret",
    "consumer_key": "your-consumer-key",
    "endpoint": "ovh-eu"
  }
}
```

### AWS Route53
```json
{
  "provider": "route53",
  "name": "My AWS",
  "credentials": {
    "access_key_id": "your-access-key",
    "secret_access_key": "your-secret-key",
    "region": "us-east-1"
  }
}
```

## Files

- `/usr/lib/secubox/dns-provider/api/` - FastAPI application
- `/usr/share/secubox/www/dns-provider/` - Web interface
- `/var/lib/secubox/dns-provider/` - Data storage
- `/run/secubox/dns-provider.sock` - Unix socket

## Dependencies

- secubox-core (>= 1.0.0)
- python3-httpx

## Security

- JWT authentication required for all endpoints
- Credentials stored encrypted at rest
- Audit log is append-only (CSPN requirement)
- Provider API tokens masked in responses

## License

Proprietary - CyberMind / ANSSI CSPN candidate

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr
