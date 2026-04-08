# SecuBox SMTP Relay

SMTP relay module for forwarding emails through a smarthost using Postfix. Enables outbound email delivery through external SMTP providers with SASL authentication and TLS encryption.

## Features

- Postfix MTA management (start/stop/restart)
- Smarthost configuration with SASL authentication
- TLS encryption support
- Mail queue monitoring and management
- Delivery statistics (sent, failed, deferred, bounced)
- Test email functionality
- Real-time mail logs
- Queue flush and message deletion
- TOML and Postfix configuration synchronization

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check (public) |
| GET | /status | Relay status (running, queue size, sent/failed counts) |
| GET | /queue | List mail queue entries |
| POST | /queue/flush | Flush mail queue (attempt immediate delivery) |
| DELETE | /queue/{queue_id} | Delete specific message from queue |
| GET | /stats | Delivery statistics (sent, failed, deferred, bounced) |
| POST | /start | Start Postfix service |
| POST | /stop | Stop Postfix service |
| POST | /restart | Restart Postfix service |
| GET | /config | Get relay configuration (password masked) |
| POST | /config | Update relay configuration |
| GET | /logs | Get mail logs (up to 500 lines) |
| POST | /test | Send a test email through the relay |

## Configuration

**Config file:** `/etc/secubox/smtp-relay.toml`

**Example configuration:**
```toml
[relay]
smarthost = "smtp.example.com"
port = 587
username = "user@example.com"
password = "your-password"
tls = true
from_domain = "secubox.local"
```

**Postfix files managed:**
- `/etc/postfix/main.cf` - Main Postfix configuration
- `/etc/postfix/sasl_passwd` - SASL credentials (chmod 600)

## Dependencies

- postfix
- libsasl2-modules
- ca-certificates
- python3-fastapi
- python3-pydantic
- secubox-core

## Files

- `/etc/secubox/smtp-relay.toml` - Module configuration
- `/etc/postfix/main.cf` - Postfix main configuration
- `/etc/postfix/sasl_passwd` - SASL password file (hashed)
- `/var/log/mail.log` - Mail delivery logs
- `/run/secubox/smtp-relay.sock` - Unix socket for FastAPI

## Common Smarthosts

| Provider | Smarthost | Port |
|----------|-----------|------|
| Gmail | smtp.gmail.com | 587 |
| Office 365 | smtp.office365.com | 587 |
| SendGrid | smtp.sendgrid.net | 587 |
| Mailgun | smtp.mailgun.org | 587 |
| Amazon SES | email-smtp.region.amazonaws.com | 587 |

## Usage Examples

**Send test email via API:**
```bash
curl -X POST http://localhost/api/v1/smtp-relay/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "recipient@example.com",
    "subject": "Test Email",
    "body": "This is a test from SecuBox SMTP Relay."
  }'
```

**Flush mail queue:**
```bash
curl -X POST http://localhost/api/v1/smtp-relay/queue/flush \
  -H "Authorization: Bearer $TOKEN"
```

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind — https://cybermind.fr
