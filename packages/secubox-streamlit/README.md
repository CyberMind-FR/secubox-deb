# 🎨 Streamlit

Streamlit app platform

**Category:** Apps

## Screenshot

![Streamlit](../../docs/screenshots/vm/streamlit.png)

## Features

- App hosting
- Deployment
- Management
- Logs

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-streamlit
```

## Configuration

Configuration file: `/etc/secubox/streamlit.toml`

## API Endpoints

- `GET /api/v1/streamlit/status` - Module status
- `GET /api/v1/streamlit/health` - Health check
- `GET /api/v1/streamlit/apps` - Per-app list, enriched with `current_tag` and `deployed_at` (read from `<app>/.deploy.json` or fallback `git describe --tags --exact-match`)

## Version pinning via Gitea

The 28 directory-form Streamlit apps under `/srv/streamlit/apps/` are
mirrored in Gitea as `gandalf/streamlit-<appname>`, each with a `v1.0.0`
tag on the initial state.

Deploy a specific version:

```bash
sudo streamlitctl deploy <app> --from-gitea --tag v1.0.0
```

Rollback to the most recent backup:

```bash
sudo streamlitctl rollback <app>
```

After a deploy, `/srv/streamlit/apps/<app>/.deploy.json` records the
current tag and deployment timestamp. The FastAPI surfaces them via
`current_tag` and `deployed_at` on `/api/v1/streamlit/apps`.

To re-run the ingest (or pick up newly added apps):

```bash
bash scripts/streamlit-ingest.sh                  # all apps
bash scripts/streamlit-ingest.sh --dry-run        # preview
bash scripts/streamlit-ingest.sh --app <name>     # single app
bash scripts/streamlit-ingest.sh --halt-on-fail   # stop on first failure
```

The deploy/rollback path does **not** auto-restart the LXC — `streamlitctl
start`/`stop` operate on the whole container, which would kill all other
running apps. Streamlit auto-reloads on file changes in the watched app
directory.

## License

MIT License - CyberMind © 2024-2026
