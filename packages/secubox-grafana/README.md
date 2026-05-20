# secubox-grafana

Grafana OSS dashboards for SecuBox security metrics, hosted in a Debian LXC
on the SecuBox `br-lxc` bridge.

Follows [`docs/MODULE-GUIDELINES.md`](../../docs/MODULE-GUIDELINES.md).

## Quickstart

```bash
apt install secubox-grafana
grafanactl install        # provisions the LXC at 10.100.0.70, installs grafana, seeds dashboards
grafanactl status         # green/yellow/red overall + last event
grafanactl dashboard list # confirms the 6 pre-provisioned dashboards
```

Then open `https://<your-secubox>/grafana/` in a browser.

## CTL — `grafanactl`

Matches the SecuBox CTL grammar (`docs/grammar.md`), **OPS MONITORING** layer.

Three-fold introspection (always available):

```text
grafanactl components       # LXC + daemon + host-API states
grafanactl status           # overall green/yellow/red + last event
grafanactl access list      # public URL(s) + auth method
```

Module-specific nouns:

```text
grafanactl dashboard list                  # provisioned + user dashboards
grafanactl dashboard add <file.json>       # POST to /api/dashboards/db
grafanactl dashboard remove <uid>
grafanactl dashboard export <uid>          # writes JSON to stdout

grafanactl datasource list
grafanactl datasource add <toml-fragment>
grafanactl datasource remove <name>
grafanactl datasource test <name>          # round-trip to Grafana

grafanactl alert list
grafanactl alert mute <id>
grafanactl alert unmute <id>

grafanactl user list
grafanactl user add <name> <role>          # Admin|Editor|Viewer
grafanactl user remove <name>
grafanactl user passwd <name>

grafanactl api-key list
grafanactl api-key create <name> <role>
grafanactl api-key revoke <id>

grafanactl install                         # idempotent LXC provisioning
grafanactl reload                          # restart host FastAPI + grafana inside LXC
```

`--json` on any verb returns machine-readable output.

## Pre-provisioned dashboards

- `nftables` — drops/accepts per chain/rule, geo overlay (from secubox-metrics)
- `crowdsec` — alerts per scenario, decisions over time
- `suricata` — alerts by severity, top src IPs
- `cookie-audit` — RGPD/ePrivacy violations from the ledger
- `mitmproxy-waf` — Set-Cookie inspections + block decisions
- `secubox-services` — secubox-* systemd unit health (vital + non-vital)

User-added dashboards go alongside the provisioned ones in Grafana's
folder layout. Re-running `grafanactl install` is idempotent and never
overwrites user dashboards (only the provisioned bundle is refreshed).

## API

FastAPI on `/run/secubox/grafana.sock`, exposed by nginx at
`/api/v1/grafana/`. Mandatory endpoints per the SecuBox API conventions:

| Endpoint | Purpose |
|---|---|
| `GET /status` | same JSON as `grafanactl status --json` |
| `GET /components` | same JSON as `grafanactl components --json` |
| `GET /access` | same JSON as `grafanactl access --json` |
| `GET /healthz` | `{"ok": true}` |
| `GET /version` | `{"version": ..., "build": ...}` |

Plus one endpoint per CTL noun-verb pair (e.g. `GET /dashboards`,
`POST /dashboards`, etc.). All non-trivial endpoints require JWT via
`Depends(auth.require_jwt)`.

## Files

```text
/etc/secubox/grafana.toml                # operator config
/etc/secubox/grafana.toml.example        # package defaults (re-installed on upgrade)
/etc/secubox/secrets/grafana-admin       # admin password (generated at install)
/etc/secubox/secrets/grafana-api-key     # API key for grafanactl (generated at install)
/etc/nginx/secubox.d/grafana.conf        # nginx snippet (auto-included by secubox vhost)
/var/lib/secubox/grafana/                # state, sentinel files
/usr/lib/secubox/grafana/api/            # FastAPI host control plane
/usr/share/secubox/lib/grafana/          # install-lxc.sh + provisioning bundle
/usr/share/secubox/www/grafana/          # SecuBox-themed web UI wrapper
/usr/share/secubox/menu.d/50-grafana.json
/data/lxc/grafana/                       # the LXC rootfs (created by `grafanactl install`)
```

## Troubleshooting

- `grafanactl status` shows `daemon: stopped` → run `lxc-attach -n grafana -- systemctl status grafana-server` inside the LXC.
- nginx 502 on `/grafana/` → check LXC is up: `lxc-info -n grafana`; if down, `grafanactl install` re-runs idempotently.
- `dashboard add` returns 401 → API key expired/missing: regenerate with `grafanactl api-key create grafanactl-internal Admin --replace`.
