<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# metactl — ISP Home Publish CLI

Command-line interface for SecuBox ISP Home Publish operations.

## Installation

```bash
sudo apt install secubox-publish
```

Installs to `/usr/sbin/metactl`.

## Usage

```bash
metactl <command> [options]
```

## Commands

### upload

Upload and publish a ZIP/TAR.GZ archive:

```bash
metactl upload mysite.zip mysite --auto-publish
metactl upload ~/blog.tar.gz blog --domain=blog.gk2.secubox.in
```

Options:
- `--domain=<domain>` — Custom domain (default: `<name>.gk2.secubox.in`)
- `--auto-publish` — Publish immediately (default)
- `--no-auto-publish` — Upload only, don't publish

### list

List all published bundles and sites:

```bash
metactl list
```

### publish / unpublish

Publish or unpublish an existing site:

```bash
metactl publish mysite
metactl unpublish mysite
```

### download

Download a published bundle as ZIP:

```bash
metactl download mysite backup.zip
```

### qrcode

Generate QR code for site URL (outputs PNG to stdout):

```bash
metactl qrcode mysite > qrcode.png
```

### health

Check site health (HTTP, HTTPS, WAF status):

```bash
metactl health mysite.gk2.secubox.in
```

### status

Show publishing platform status:

```bash
metactl status
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECUBOX_API_BASE` | `http://127.0.0.1/api/v1/publish` | Publish API base URL |
| `SECUBOX_METABLOGIZER_API` | `http://127.0.0.1/api/v1/metablogizer` | MetaBlogizer API URL |
| `SECUBOX_TOKEN_FILE` | `/etc/secubox/secrets/jwt-token` | JWT token file path |
| `SECUBOX_TOKEN` | — | JWT token (overrides file) |

## Examples

### Quick publish static site

```bash
# Create ZIP of your site
zip -r mysite.zip public/

# Upload and publish
metactl upload mysite.zip mysite

# Check health
metactl health mysite.gk2.secubox.in

# Generate QR for sharing
metactl qrcode mysite > mysite-qr.png
```

### Backup and restore

```bash
# Download backup
metactl download mysite ~/backups/mysite-$(date +%Y%m%d).zip

# Restore on another server
metactl upload ~/backups/mysite-20260510.zip mysite-restored
```

### Batch operations

```bash
# List all sites
metactl list | grep -v Draft

# Health check all
for site in $(metactl list | awk '{print $1}'); do
    echo "=== $site ==="
    metactl health "$site.gk2.secubox.in"
done
```

## Web Interface

The web wizard is available at `/publish/` and provides:

1. **Drag & drop** upload
2. **Auto-detection** of content type
3. **Progress tracking**
4. **Infrastructure status** (VHost, SSL, WAF)
5. **One-click setup** for all services
6. **QR code** generation
7. **CLI commands** for this guide

## License

MIT License - CyberMind © 2024-2026
