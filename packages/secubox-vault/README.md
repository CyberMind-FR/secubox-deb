# SecuBox Vault

Secure secrets management module for SecuBox. Provides encrypted storage for sensitive data with Fernet (AES-128-CBC) encryption and optional HashiCorp Vault integration.

## Features

- Encrypted local secrets store using Fernet (AES-128-CBC)
- HashiCorp Vault integration detection and status
- Secret tagging and search capabilities
- Automatic secret rotation with cryptographic randomness
- Complete audit logging for all secret operations
- Import/export functionality for backup and migration
- Random secret generation (urlsafe, hex, bytes formats)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check |
| GET | /status | Vault status and statistics |
| GET | /secrets | List all secret keys (values hidden) |
| GET | /secrets/{key} | Retrieve a specific secret |
| POST | /secrets | Create a new secret |
| PUT | /secrets/{key} | Update an existing secret |
| DELETE | /secrets/{key} | Delete a secret |
| POST | /secrets/{key}/rotate | Rotate secret with new random value |
| GET | /secrets/search/{query} | Search secrets by key or description |
| GET | /secrets/tag/{tag} | Filter secrets by tag |
| GET | /audit | View audit log entries |
| POST | /generate | Generate random secret values |
| POST | /export | Export secrets (with or without values) |
| POST | /import | Import secrets from export data |

## Configuration

**Vault Directory:** `/var/lib/secubox/vault`

**Environment Variables:**
- `VAULT_ADDR` - HashiCorp Vault address (default: `http://127.0.0.1:8200`)

**Data Models:**

```python
# Secret creation
{
    "key": "api_key",
    "value": "secret_value",
    "description": "API key for external service",
    "tags": ["api", "production"]
}

# Secret update
{
    "value": "new_secret_value",
    "description": "Updated description"  # optional
}
```

## Dependencies

- python3
- python3-fastapi
- python3-pydantic
- python3-cryptography
- secubox-core
- vault (optional, for HashiCorp Vault integration)

## Files

- `/var/lib/secubox/vault/secrets.enc` - Encrypted secrets store
- `/var/lib/secubox/vault/.key` - Encryption key (mode 600)
- `/var/lib/secubox/vault/audit.log` - Audit log of all secret operations
- `/etc/secubox/vault.toml` - Module configuration

## Security

- Encryption key automatically generated on first use
- All files stored with restrictive permissions (600)
- Every read, create, update, delete, and rotate operation is logged
- Secret rotation includes hash of previous value for audit trail
- Export with values requires explicit flag

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
