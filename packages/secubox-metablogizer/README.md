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

## Version metadata (site.json)

Every site under `/srv/metablogizer/sites/` carries a `site.json` describing it.
The formal schema lives at `packages/secubox-metablogizer/schema/site.json.schema.json`.

Required fields: `name`, `domain`, `published`.
Optional: `version`, `title`, `description`, `category`, `streamlit_app`,
`tags`, `last_updated`.

If `version` and/or `last_updated` are absent, the API derives them from the
local git state (`git describe --tags --exact-match` and
`git log -1 --format=%cI`).

The `/api/v1/metablogizer/sites` endpoint returns the enriched form;
consumers (e.g. the upcoming sub-D dashboard) see one consistent shape.

### Backfill

To create or merge `site.json` files in bulk:

```bash
bash scripts/metablog-site-backfill.sh --dry-run        # preview
bash scripts/metablog-site-backfill.sh                  # create missing
bash scripts/metablog-site-backfill.sh --force          # merge missing fields
bash scripts/metablog-site-backfill.sh --site <name>    # one site only
```

Per-run JSON report at `output/metablog-backfill-report.json`. The backfill
auto-detects `streamlit_app` by probing the Gitea repo
`gandalf/streamlit-<name>.git` (sub-F).

## Version dashboard

The Hub exposes a per-site dashboard at:

- **List**: `https://admin.gk2.secubox.in/metablogizer/`
  - 8 columns: Name · Domain · Version · Streamlit · Updated · Status · Size · Actions
  - Inline filter (matches `name` and `domain`)
  - Sortable headers (Name, Domain, Version, Updated)
  - Auto-refresh every 60s; paused when the tab is hidden

- **Per-site drill-in**: `https://admin.gk2.secubox.in/metablogizer/site.html?name=<sitename>`
  - All `site.json` fields
  - Three quick links: 🌐 live site, 🦊 Gitea repo, 🎨 Streamlit app (if any)
  - Tag history is not shown inline; click the Gitea link and use its
    **Releases** tab (auth required, handled by your Gitea session)

Data comes from `/api/v1/metablogizer/sites` and
`/api/v1/metablogizer/site/<name>` (sub-C, PR #102). The dashboard is
pure vanilla JS — no framework, no router.

## Deploy webhook

A push to the default branch of any `metablog-*` repo on Gitea
triggers an automatic deploy of the live site.

- **Endpoint**: `POST https://admin.gk2.secubox.in/api/v1/metablogizer/webhook`
- **Auth**: HMAC-SHA256 in `X-Gitea-Signature` header, shared secret in
  `/etc/secubox/metablogizer-webhook.secret` (chmod 600, owner `secubox`)
- **Action**: `git fetch + git reset --hard origin/<default>` under a
  per-site `asyncio.Lock`; invalidates the dashboard cache; reloads nginx
  only if `site.json:domain` changed.

### Provisioning the secret (one-shot on the MOCHAbin)

```bash
sudo install -o secubox -g secubox -m 600 /dev/stdin \
  /etc/secubox/metablogizer-webhook.secret <<< "$(openssl rand -hex 32)"
sudo systemctl restart secubox-metablogizer
```

### Registering the webhook on every Gitea repo

```bash
scripts/metablog-webhook-install.sh \
  --gitea-token <admin-or-repo-token> \
  --secret-file /etc/secubox/metablogizer-webhook.secret
```

The installer is idempotent — re-run after adding new sites.

### Observability

- `journalctl -u secubox-metablogizer | grep '^deploy '`
- `GET /api/v1/metablogizer/deploys` (JWT-gated) returns the last 50 deploys

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
