<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# billets — micro-blog gateway inter-médias sociaux

Self-hosted micro-blog + social-media gateway. Author-published short posts; a
public read feed with comments, emoji reactions and republish share-intents. It
**ingests** links/embeds from social networks (SSRF-guarded oEmbed, sanitized)
and lets each billet be **re-shared** back to them.

Built as a SecuBox module (`secubox-billets`): FastAPI + **aiosqlite (WAL)** +
Jinja2, served on a Unix socket behind nginx.

## Architecture

```
api/
  asgi.py        runtime entrypoint (uvicorn api.asgi:app) — lifespan opens the DB
  main.py        app factory + public feed / permalink / feeds / oEmbed
  db.py          aiosqlite WAL + numbered .sql migrations
  models.py      Pydantic v2 (strict, size-limited, https-only URLs)
  repo.py        billet/comment/reaction/author queries (keyset pagination)
  ids.py         ULID (time-sortable)
  routes/        admin.py (auth + CRUD + moderation), public.py (react/comment)
  services/      render, sanitize, ssrf, oembed, linkcard, eventlog, revisions,
                 antispam, security, feeds
  templates/  static/  migrations/
  manage.py      CLI: create-author / set-password / seed
```

**Invariants.** Every security-relevant action (publish/edit/delete, comment
moderation, login) appends to an **append-only BLAKE2b hash-chained** `event_log`
(`services/eventlog`, `verify_chain`). Every billet's content **and style** are
versioned in a **Gitea repo** (`services/revisions`, one front-matter `.md` per
billet, full `git log --follow` history).

## Install

### Debian package
```
dpkg -i secubox-billets_*.deb
# postinst creates the secubox user, /var/lib/secubox/billets, the signing
# secret, the venv (pip install requirements.txt), and the nginx vhost.
cd /usr/lib/secubox/billets
sudo -u secubox venv/bin/python -m api.manage create-author admin
```
Set the public origin so feeds/oEmbed emit absolute URLs — add to the unit:
`Environment=BILLETS_SITE_URL=https://billets.example.com`.

### Standalone
`sudo deploy/install.sh` (idempotent). In SecuBox, billets is fronted by
HAProxy (TLS 1.3) → sbxwaf → nginx → the socket.

## Configuration (environment)

| Var | Default | Purpose |
|-----|---------|---------|
| `BILLETS_DB` | `/var/lib/secubox/billets/billets.db` | SQLite WAL file |
| `BILLETS_REVISIONS_DIR` | `/var/lib/secubox/billets/revisions` | Gitea revision repo |
| `BILLETS_SECRET_FILE` | `/etc/secubox/secrets/billets` | signing secret (0600 secubox) |
| `BILLETS_SECRET` | — | secret override (takes precedence) |
| `BILLETS_SITE_URL` | derived from request | absolute origin for feeds/oEmbed |

To push revisions to Gitea, add an `origin` remote in the revisions repo as the
`secubox` user (else commits stay local — still a full history).

## Backup / restore

SQLite is the single source of truth. Take a consistent snapshot:
```
sudo -u secubox sqlite3 /var/lib/secubox/billets/billets.db ".backup '/var/backups/billets-$(date +%F).db'"
```
Restore: stop the service, copy the backup over `billets.db` (and the `-wal`/`-shm`
are rebuilt), start again. The Gitea revision repo and `/etc/secubox/secrets/billets`
should be backed up alongside.

## Tests

```
PYTHONPATH=. python -m pytest -q     # from packages/secubox-billets
```
Covers data layer, feed/pagination, admin auth/CRUD, **SSRF + XSS** (the critical
step), comments/anti-spam, reactions, feeds/oEmbed. `pip-audit` runs in CI.

## Design decisions (documented per the brief)

- **aiosqlite (async), not sync sqlite3.** As a SecuBox module, billets shares
  the aggregator's event loop path; a blocking DB call would stall the box. All
  DB access is awaited off-loop.
- **`api/` layout + Unix socket**, following SecuBox module conventions (rather
  than the standalone `app/` layout).
- **Own author auth** (argon2id + optional TOTP) kept per spec; SecuBox-auth SSO
  is a possible v2.
- **htmx replaced by a tiny vanilla shim** (`static/billets.js`, CSP
  `script-src 'self'`). The reaction endpoint returns an htmx-compatible fragment,
  so dropping in a vendored `htmx.min.js` at deploy works unchanged — this avoids
  an un-fetchable CDN dependency while keeping graceful no-JS degradation.
- **Emails hashed** (BLAKE2b), not encrypted — never displayed, only used to
  detect a returning approved commenter (spec allows "chiffré au repos ou hashé").
- **oEmbed discovery is same-origin only** (Mastodon/PeerTube self-hosted); an
  unknown host with no same-origin oEmbed link falls back to a local OpenGraph card.
