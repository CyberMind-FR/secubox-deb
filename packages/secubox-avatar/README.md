# SecuBox Avatar - Identity Manager

Identity and avatar management module for SecuBox services.

## Features

- Unified identity management across SecuBox services
- Avatar upload with image processing (JPG, PNG, GIF, WebP)
- Service sync to Gitea, Nextcloud, Mail, Matrix, LDAP
- P31 Phosphor light theme frontend
- JWT authentication on all endpoints

## API Endpoints

### Public

- `GET /health` - Health check

### Protected (JWT required)

- `GET /identities` - List all identities
- `GET /identity/{id}` - Get specific identity
- `POST /identity` - Create new identity
- `PUT /identity/{id}` - Update identity
- `DELETE /identity/{id}` - Remove identity
- `POST /avatar/upload` - Upload avatar image
- `GET /avatar/{id}` - Get avatar image (public)
- `DELETE /avatar/{id}` - Delete avatar
- `GET /services` - List connected services
- `POST /sync` - Sync identity to connected services
- `GET /summary` - Dashboard widget summary

## Configuration

Configuration file: `/etc/secubox/avatar.toml`

```toml
[avatar]
max_image_size = 5242880  # 5MB

[services.gitea]
enabled = true
url = "https://git.example.com"
api_key = "secret"

[services.nextcloud]
enabled = true
url = "https://cloud.example.com"

[services.mail]
enabled = false

[services.matrix]
enabled = false

[services.ldap]
enabled = false
```

## Data Storage

- Identities: `/var/lib/secubox/avatar/identities.json`
- Avatar images: `/var/lib/secubox/avatar/images/`

## Dependencies

- secubox-core (>= 1.0)
- python3-fastapi
- python3-pil (Pillow for image processing)

## Build

```bash
cd packages/secubox-avatar
dpkg-buildpackage -us -uc -b
```

## License

Proprietary - CyberMind ANSSI CSPN candidate
