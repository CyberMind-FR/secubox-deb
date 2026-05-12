# 📝 Metablogizer

Static site publisher with Tor

**Category:** Publishing

## Screenshot

![Metablogizer](../../docs/screenshots/vm/metablogizer.png)

## Features

- Static sites
- Tor publishing
- Templates
- Markdown

## Gitea ingest

The 166 sites under `/srv/metablogizer/sites/*` are tracked in Gitea at
`https://gitea.gk2.secubox.in/gandalf/?tab=repositories&q=metablog`
as `gandalf/metablog-<sitename>` repositories, each with a `v1.0.0` tag
on the initial state.

Initial ingest is driven by three scripts in `scripts/`:

```bash
bash scripts/metablog-ingest-gitea-config.sh   # one-time: enables push-create
bash scripts/lib/gitea-ssh-preflight.sh --check  # verify SSH path
bash scripts/metablog-ingest.sh                # full run
```

Flags on `metablog-ingest.sh`: `--dry-run`, `--limit N`, `--site <name>`, `--halt-on-fail`.

Idempotent — re-running picks up new sites and skips ones already in sync.
Per-site outcome lands in `output/ingest-report.json`. Important: the SSH
URL uses `gitea@` (NOT `git@`) because Gitea's built-in SSH server validates
the username against the OS user it runs as.

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-metablogizer
```

## Configuration

Configuration file: `/etc/secubox/metablogizer.toml`

## API Endpoints

- `GET /api/v1/metablogizer/status` - Module status
- `GET /api/v1/metablogizer/health` - Health check

## License

MIT License - CyberMind © 2024-2026
