# MODULE-COMPLIANCE.md — SecuBox-DEB Module Compliance Requirements

*Formal design rules for all SecuBox-DEB modules*

---

## Overview

Every SecuBox-DEB module MUST comply with the following requirements before being marked as complete. These rules ensure consistent quality, testability, and documentation across all packages.

---

## Compliance Checklist

### 1. README.md (Required)

Each module MUST have a `packages/secubox-<module>/README.md` containing:

- [ ] Module name and description
- [ ] Feature list
- [ ] API endpoint documentation (all routes)
- [ ] Configuration file location and format
- [ ] Dependencies (Debian packages, Python modules)
- [ ] Port/socket information
- [ ] Installation instructions
- [ ] Usage examples

**Template location**: `.claude/TEMPLATES/README-template.md`

### 2. Wiki Documentation (Required)

Each module MUST have wiki documentation in:

- [ ] `wiki/MODULES-EN.md` — English module entry
- [ ] `wiki/MODULES-FR.md` — French module entry

Wiki entry MUST include:
- Screenshot (if applicable)
- Brief description
- Key features (bullet points)
- Related modules

### 3. VirtualBox Testing (Required)

Each module MUST be tested in VirtualBox before release:

- [ ] Service starts successfully (`systemctl status secubox-<module>`)
- [ ] API health endpoint responds (`/api/v1/<module>/health`)
- [ ] Web UI loads correctly (if applicable)
- [ ] Sidebar navigation works
- [ ] No critical errors in logs (`journalctl -u secubox-<module>`)

**Test VM**: SecuBox-Test (VirtualBox)
**Access**: SSH port 2223, HTTPS port 8444

### 4. VirtualBox Snapshots (Required)

After successful testing, create a VirtualBox snapshot:

```bash
VBoxManage snapshot "SecuBox-Test" take "<Phase>-<Module>-$(date +%Y%m%d)" \
  --description "SecuBox-DEB <Module> test - <summary>"
```

Snapshot naming convention:
- `Phase9-Complete-20260408` — Phase completion
- `Module-<name>-<date>` — Individual module test

---

## Module Structure Requirements

### Directory Structure

```
packages/secubox-<module>/
├── api/
│   ├── __init__.py
│   └── main.py              # FastAPI app
├── www/
│   └── <module>/
│       └── index.html       # Web UI with sidebar
├── debian/
│   ├── control              # Package metadata
│   ├── rules                # Build rules
│   ├── postinst             # Post-install script
│   ├── prerm                # Pre-remove script
│   └── secubox-<module>.service  # systemd unit
├── menu.d/
│   └── <order>-<module>.json    # Sidebar menu entry
└── README.md                # Module documentation
```

### Web UI Requirements (Pattern 12)

All module frontends MUST include:

```html
<head>
    <link rel="stylesheet" href="/shared/crt-light.css">
    <link rel="stylesheet" href="/shared/sidebar-light.css">
</head>
<body class="crt-light">
    <nav class="sidebar" id="sidebar"></nav>
    <main class="main-content">
        <!-- Module content -->
    </main>
    <script src="/shared/sidebar.js"></script>
</body>
```

### Menu Integration

Module MUST provide `menu.d/<order>-<module>.json`:

```json
{
  "id": "module-name",
  "name": "Display Name",
  "icon": "🔧",
  "path": "/module/",
  "category": "apps",
  "order": 800,
  "description": "Short description"
}
```

---

## API Requirements

### Mandatory Endpoints

Every module API MUST implement:

- `GET /health` — Returns `{"status": "ok", "module": "<name>"}`
- `GET /status` — Returns module-specific status

### Authentication

All endpoints (except /health) MUST use JWT authentication:

```python
from secubox_core.auth import require_jwt

@router.get("/status")
async def status(user=Depends(require_jwt)):
    ...
```

### Socket Path

API MUST listen on Unix socket: `/run/secubox/<module>.sock`

---

## Debian Package Requirements

### debian/control

```
Source: secubox-<module>
Section: net
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://cybermind.fr/secubox
Rules-Requires-Root: no

Package: secubox-<module>
Architecture: all
Depends: ${misc:Depends}, secubox-core (>= 1.0), <dependencies>
Description: SecuBox <Module> — <short description>
 <Long description spanning multiple lines.>
 .
 Port Debian bookworm de luci-app-<module> (SecuBox OpenWrt / CyberMind.fr).
```

### debian/postinst

```bash
#!/bin/bash
set -e
case "$1" in
  configure)
    systemctl daemon-reload
    systemctl enable secubox-<module>.service
    systemctl start  secubox-<module>.service || true
    systemctl reload nginx 2>/dev/null || true
    ;;
esac
#DEBHELPER#
```

---

## Compliance Verification

### Automated Checks

```bash
# Check README exists
test -f packages/secubox-<module>/README.md

# Check API health
curl -sk https://localhost:8444/api/v1/<module>/health

# Check web UI
curl -sk https://localhost:8444/<module>/ | grep -q 'sidebar'

# Check service status
systemctl is-active secubox-<module>
```

### Manual Verification

1. Browse to `https://<vm-ip>/<module>/`
2. Verify sidebar loads with all menu entries
3. Test primary module functionality
4. Check browser console for JS errors

---

## Phase Completion Criteria

A phase is considered complete when:

1. All modules in the phase have README.md
2. All modules are documented in wiki (EN + FR)
3. All modules tested in VirtualBox
4. VirtualBox snapshot created for the phase
5. `.claude/TODO.md` updated with completion status

---

## Current Compliance Status

| Phase | Modules | READMEs | Wiki | VBox Test | Snapshot |
|-------|---------|---------|------|-----------|----------|
| Phase 1 | 6 | ✅ | ✅ | ✅ | ✅ |
| Phase 2 | 5 | ✅ | ✅ | ✅ | ✅ |
| Phase 3 | 33 | ✅ | ✅ | ✅ | ✅ |
| Phase 4 | 5 | ✅ | ✅ | ✅ | ✅ |
| Phase 5 | 7 | ✅ | ✅ | ✅ | ✅ |
| Phase 6 | 3 | ✅ | ✅ | ✅ | ✅ |
| Phase 7 | — | ✅ | ✅ | ✅ | ✅ |
| Phase 8 | 21 | ✅ | ⬜ | ✅ | ✅ |
| Phase 9 | 22 | ✅ | ⬜ | ✅ | ✅ |
| Phase 10 | 10 | ✅ | ⬜ | ✅ | ✅ |

---

*Last updated: 2026-04-08*
