# SecuBox Cloner

System backup and restore module for SecuBox. Creates compressed tar archives of SecuBox configuration and data directories with scheduling support via systemd timers.

## Features

- Full system configuration backup to compressed tar.gz archives
- Configurable backup paths with exclude patterns
- Metadata storage for backup descriptions and contents
- Automatic backup scheduling via systemd timers
- Retention-based cleanup of old backups
- Dry-run restore for preview before extraction
- Disk usage monitoring for backup storage

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /health | Health check |
| GET | /status | Cloner status, disk usage, and schedule |
| GET | /backups | List all backups with metadata |
| GET | /backups/{backup_id} | Get backup details and contents listing |
| POST | /backups | Create a new backup |
| DELETE | /backups/{backup_id} | Delete a backup |
| POST | /backups/{backup_id}/restore | Restore from backup (supports dry_run) |
| GET | /config | Get cloner configuration |
| PUT | /config | Update cloner configuration |
| PUT | /schedule | Configure automated backup schedule |
| POST | /cleanup | Remove old backups (retention policy) |
| GET | /paths | List default backup paths with sizes |

## Configuration

**Configuration File:** `/etc/secubox/cloner.json`

**Default Backup Paths:**
- `/etc/secubox`
- `/var/lib/secubox`
- `/etc/nginx/secubox.d`
- `/usr/share/secubox`

**Default Exclusions:**
- `/var/lib/secubox/backups`
- `*.sock`
- `*.pid`
- `__pycache__`
- `*.pyc`

**Data Models:**

```python
# Backup configuration
{
    "name": "pre-upgrade-backup",
    "paths": ["/etc/secubox", "/var/lib/secubox"],
    "exclude": ["*.sock", "*.pid"],
    "compress": true,
    "description": "Backup before system upgrade"
}

# Restore configuration
{
    "backup_id": "backup-20240408-120000.tar.gz",
    "target_path": "/",
    "dry_run": false
}

# Schedule configuration
{
    "enabled": true,
    "interval": "daily",  # daily, weekly, monthly
    "retention": 7,        # keep last N backups
    "time": "03:00"
}
```

## Dependencies

- python3
- python3-fastapi
- python3-pydantic
- secubox-core
- systemd (for scheduled backups)

## Files

- `/var/lib/secubox/backups/` - Backup storage directory
- `/var/lib/secubox/cloner/state.json` - Cloner state file
- `/etc/secubox/cloner.json` - Module configuration
- `/etc/systemd/system/secubox-cloner-backup.timer` - Systemd timer for scheduled backups
- `*.meta.json` - Metadata files for each backup

## Usage Examples

**Create a backup:**
```bash
curl -X POST http://localhost/api/v1/cloner/backups \
  -H "Content-Type: application/json" \
  -d '{"name": "manual-backup", "description": "Pre-upgrade backup"}'
```

**Preview restore (dry run):**
```bash
curl -X POST http://localhost/api/v1/cloner/backups/backup-20240408.tar.gz/restore \
  -H "Content-Type: application/json" \
  -d '{"backup_id": "backup-20240408.tar.gz", "dry_run": true}'
```

**Enable daily backups:**
```bash
curl -X PUT http://localhost/api/v1/cloner/schedule \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "interval": "daily", "retention": 7, "time": "03:00"}'
```

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind - https://cybermind.fr
