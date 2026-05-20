# secubox-yacy

[YaCy](https://yacy.net) peer-to-peer sovereign search engine for SecuBox.
JVM + YaCy hosted in a Debian LXC at `10.100.0.80` on the SecuBox `br-lxc`
bridge.

Follows [`docs/MODULE-GUIDELINES.md`](../../docs/MODULE-GUIDELINES.md);
opens the **SEARCH** layer of the SecuBox CTL grammar.

## Quickstart

```bash
apt install secubox-yacy
yacyctl install     # provisions LXC at 10.100.0.80, installs JVM + YaCy
yacyctl status
```

Open `https://<your-secubox>/yacy/` and use the YaCy admin UI for search,
peer config, and crawl scheduling.

## CTL — `yacyctl`

Three-fold introspection (always available):

```text
yacyctl components       # LXC + daemon + host-API states
yacyctl status           # overall green/yellow/red
yacyctl access list      # public URL(s) + auth method
```

Module-specific nouns (full implementation in v1.1.0 follow-up):

```text
yacyctl peer       list|add <url>|remove <hash>|status <hash>
yacyctl index      status|build <urls.txt>|clear|optimize
yacyctl query      test <terms>|count <terms>
yacyctl blacklist  list|add <pattern>|remove <pattern>
yacyctl crawler    list|start <profile>|stop <id>|schedule <profile> <cron>

yacyctl install      # idempotent LXC + JVM + YaCy bootstrap
yacyctl reload       # restart host FastAPI + yacy daemon
```

## Configuration

`/etc/secubox/yacy.toml` (seeded from `yacy.toml.example` at install). Key
fields: `lxc.{name,ip,bridge,path}`, `yacy.{http_port,heap_max,release_url}`,
`peer.mode` (`standalone` / `freeworld` / `intranet`), `exposure.public_hostname`.

## Files

```text
/etc/secubox/yacy.toml                # operator config
/etc/secubox/secrets/yacy-admin       # admin password (generated at install)
/etc/nginx/secubox.d/yacy.conf
/var/lib/secubox/yacy/                # host state
/usr/lib/secubox/yacy/api/            # host FastAPI
/usr/share/secubox/lib/yacy/          # install-lxc.sh + provisioning
/usr/share/secubox/www/yacy/          # SecuBox-themed web UI wrapper
/usr/share/secubox/menu.d/60-yacy.json
/data/lxc/yacy/                       # the LXC rootfs (created by yacyctl install)
```

## API

FastAPI on `/run/secubox/yacy.sock`, exposed by nginx at `/api/v1/yacy/`.
Mandatory endpoints: `/status`, `/components`, `/access`, `/healthz`,
`/version`. Module-specific endpoints (one per CTL noun-verb pair) shell
out to `yacyctl --json`.

## Troubleshooting

- `yacyctl status` shows `daemon: stopped` → `lxc-attach -n yacy -- systemctl status yacy`.
- nginx 502 on `/yacy/` → check LXC IP `10.100.0.80` reachable, or re-run `yacyctl install`.
- YaCy admin password rotation → write a new value to `/etc/secubox/secrets/yacy-admin` and update via the YaCy admin UI (or future `yacyctl admin passwd`).
