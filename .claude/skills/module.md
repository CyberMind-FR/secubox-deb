# Skill: /module - SecuBox Module Design & Scaffold

Create a new SecuBox module package with API, frontend, and Debian packaging.

## Usage

```
/module <module-name> [description]
```

## What This Skill Does

1. **Creates package structure** in `packages/secubox-<name>/`:
   - `api/main.py` - FastAPI app with status endpoint
   - `api/routers/` - Action endpoints (JWT protected)
   - `www/<name>/index.html` - Frontend with sidebar
   - `debian/` - Control, rules, service file
   - `menu.d/` - Menu definition JSON

2. **Follows SecuBox patterns**:
   - Unix socket: `/run/secubox/<name>.sock`
   - API prefix: `/api/v1/<name>/`
   - JWT auth via `secubox_core.auth`
   - Consistent CSS variables and sidebar

## Template Structure

```
packages/secubox-<name>/
├── api/
│   ├── __init__.py
│   └── main.py
├── www/
│   └── <name>/
│       └── index.html
├── menu.d/
│   └── XX-<name>.json
└── debian/
    ├── control
    ├── rules
    ├── changelog
    ├── compat
    ├── postinst
    ├── prerm
    └── secubox-<name>.service
```

## Steps to Execute

1. Parse module name from args
2. Check if package already exists
3. Create directory structure
4. Generate api/main.py from template
5. Generate www/<name>/index.html from template
6. Generate debian/ files from template
7. Generate menu.d/<order>-<name>.json
8. Add nginx location to common/nginx/secubox.conf
9. Update .claude/MIGRATION-MAP.md

## API Template (api/main.py)

```python
"""SecuBox <Name> API"""
from fastapi import FastAPI, Depends
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox <Name>")
config = get_config("<name>")

@app.get("/status")
async def status():
    return {"module": "<name>", "status": "ok"}

@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    return {"config": dict(config)}
```

## Frontend Template (index.html)

Standard SecuBox dashboard with:
- CSS variables: --bg-dark, --cyan, --green, --red, --yellow, --purple
- Sidebar element: `<nav class="sidebar" id="sidebar"></nav>`
- Sidebar script: `<script src="/shared/sidebar.js"></script>`
- API calls using fetch to `/api/v1/<name>/`

## Menu Definition (menu.d/XX-name.json)

```json
{
  "id": "<name>",
  "name": "<Name>",
  "category": "apps",
  "icon": "📦",
  "path": "/<name>/",
  "order": 500,
  "description": "<description>"
}
```

Categories: dashboard, security, network, monitoring, publishing, apps
