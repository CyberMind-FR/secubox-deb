# secubox-proxypac

SecuBox WPAD/PAC auto-config: zero-config client-side routing to mesh
services (mesh tor-exit SOCKS, toolbox MITM, gateway, or `DIRECT`).

## What it does

`secubox-proxypac` generates `/var/lib/secubox/proxypac/proxy.pac`, a
standard [PAC](https://en.wikipedia.org/wiki/Proxy_auto-config) (Proxy
Auto-Config) file, and serves it via [WPAD](https://en.wikipedia.org/wiki/Web_Proxy_Autodiscovery_Protocol)
so LAN/mesh clients pick up the right proxy for each host automatically —
no manual browser proxy configuration.

The PAC content is composed from two sources, in this precedence order:

1. **Operator overrides** — `/etc/secubox/proxypac/rules.d/*.rules` (see
   below), highest precedence.
2. **Active mesh services** — the p2p `/services` catalog (via the p2p
   Unix socket), for any `ServiceOffer` carrying an optional `pac`
   descriptor (see "annuaire `pac` field" below).
3. **Toolbox default** — a catch-all directive (e.g. route everything
   else through the local MITM/toolbox), if configured.
4. **`DIRECT`** — the unconditional fallback if nothing else matched.

The first host-glob match wins (rules are evaluated top-to-bottom in the
composed order above). Every generated PAC ends with a terminal
`return "DIRECT";`, and every non-`DIRECT` directive is itself
fail-open (`...; DIRECT`) — see "Fail-safe / atomic-swap invariant"
below.

## rules.d format

Operator policy lives in `/etc/secubox/proxypac/rules.d/*.rules`. Files
are parsed in **sorted filename order** (hence the numeric prefixes,
e.g. `00-onion.rules`, `50-webui.rules`), and each non-comment,
non-blank line is:

```
<host-glob> <proxy_type> [address]
```

- `host-glob` — a PAC `shExpMatch` host pattern, e.g. `*.onion`,
  `*.example.com`.
- `proxy_type` — one of `socks5`, `http`, `gateway`, `direct`.
- `address` — `host:port` (or bare host for `http`/`gateway`); omitted
  for `direct`.
- Lines starting with `#` and blank lines are ignored (comments).

Example (`conf/rules.d/00-onion.rules`, shipped as a seed):

```
# secubox-proxypac seed: route .onion via a mesh tor-exit when one is active.
*.onion socks5 10.10.0.1:9050
```

The WebUI (`POST /override`, `DELETE /override/{host}`) persists
operator-added rules to `/etc/secubox/proxypac/rules.d/50-webui.rules`
— a file the API owns exclusively; hand-edit any other numbered file
for static seeds instead.

**Precedence recap**: `override` (rules.d, including `50-webui.rules`)
> `service:<id>` (active catalog entry) > `toolbox` (catch-all) >
implicit `DIRECT`. Within overrides, the **last** definition of a host wins,
so a later file (e.g. the WebUI's `50-webui.rules`) overrides an earlier seed
(e.g. `00-onion.rules`) for the same host glob — explicit operator policy beats
shipped defaults. The `override` source as a whole still wins over anything with
the same host from `services`/`toolbox`.

**Dependency note**: the `/proxy.pac` nginx `allow`/`deny` gate matches on
`$remote_addr`; behind HAProxy that is `127.0.0.1` unless the `real_ip` rewrite
(`set_real_ip_from` / `real_ip_header X-Forwarded-For`) shipped by **secubox-hub**
is loaded — hence `Depends: secubox-hub`.

## Annuaire `pac` field

A `ServiceOffer` in the p2p annuaire may carry an **optional**
`pac` descriptor:

```json
{
  "pac": {
    "match": ["*.onion"],
    "proxy": "socks5"
  }
}
```

- `match` — non-empty list of host globs this service should be routed
  for.
- `proxy` — one of `socks5`, `http`, `gateway`, `direct`.

This field is byte-stable and backward-compatible: a `ServiceOffer`
without `pac` serializes to identical `canonical_bytes` as before the
field existed (it's excluded from canonical JSON when absent), so
existing signed offers and mesh sync are unaffected. Services declaring
`pac` are cross-referenced by their `endpoint` host — for `socks5`
the port defaults to the service's `macro.params.socks_port` (falling
back to `9050`) unless overridden; for `http`/`gateway` the endpoint
host is used as-is.

Only `enabled` catalog entries with a `pac` descriptor contribute
routing rules; anything else is ignored by the generator.

## WPAD delivery

Two artifacts are served, both **LAN/mesh-gated only — never public**:

- `/proxy.pac` — served by the main SecuBox vhost
  (`nginx/proxypac.conf`), `allow 127.0.0.1; allow 192.168.0.0/16; allow
  10.10.0.0/24; deny all;`, `Content-Type:
  application/x-ns-proxy-autoconfig`, short cache (`max-age=300`).
- `wpad.dat` — served on a dedicated `wpad.<domain>` vhost
  (`nginx/wpad-vhost.conf`), same LAN/mesh `allow`/`deny` gate, aliasing
  the identical `proxy.pac` file so both discovery paths always agree.

Zero-config discovery is completed via **DHCP option 252**
(`conf/dnsmasq-wpad.conf`):

```
dhcp-option=252,"http://wpad.gk2.secubox.in/wpad.dat"
```

Browsers/OSes that support WPAD auto-detect this DHCP option (or the
`wpad.<domain>` DNS convention) and fetch `wpad.dat` without any client
configuration.

## Fail-safe / atomic-swap invariant

Generation (`proxypac.generator.run_once` / `generate` /
`write_atomic`) never leaves `proxy.pac` broken or empty:

1. `generate()` composes overrides + service rules + toolbox default
   into PAC JavaScript source.
2. `write_atomic()` validates the rendered text contains
   `function FindProxyForURL` and a terminal `return "DIRECT";`,
   writes it to `proxy.pac.shadow`, then atomically renames
   (`os.replace`) the shadow over the live `proxy.pac`.
3. If **anything** fails during composition, validation, or the
   p2p socket read (which fails open to an empty service list rather
   than raising), the exception is caught, logged, and the
   **last-good `proxy.pac` is left untouched** — clients never see a
   half-written or invalid PAC file.
4. Every non-`DIRECT` directive the generator ever emits
   (`SOCKS5 ...; DIRECT`, `PROXY ...; DIRECT`) ends in `; DIRECT`, so a
   dead proxy fails open to direct connection rather than blocking
   traffic.

This mirrors the double-buffer/4R discipline used elsewhere in
SecuBox (shadow write → validate → atomic swap; no rollback history is
kept here since the previous file is never touched on failure).

## Regeneration triggers

- `secubox-proxypac-gen.path` — watches
  `/etc/secubox/proxypac/rules.d` and fires `secubox-proxypac-gen.service`
  (which runs `/usr/sbin/proxypac-gen`, a thin CLI wrapping
  `generator.run_once()`) on any change.
- `secubox-proxypac-gen.timer` — periodic fallback regen (`OnBootSec=2min`,
  `OnUnitActiveSec=5min`) to pick up p2p catalog changes even without a
  rules.d edit.
- The WebUI API also calls `run_once()` synchronously after every
  `POST /override` / `DELETE /override/{host}` mutation, so operator
  changes take effect immediately without waiting for the timer.

## API (mounted at `/api/v1/proxypac/`)

| Method | Path | Description |
|--------|------|--------------|
| GET | `/rules` | List the composed rules.d overrides |
| POST | `/override` | Add/replace an override `{host, proxy, address}` |
| DELETE | `/override/{host}` | Remove an override |
| GET | `/candidates` | List auto-learn candidate hosts |
| POST | `/candidate/{host}/accept` | Promote a candidate to an override |
| POST | `/candidate/{host}/reject` | Dismiss a candidate |
| GET | `/health` | Health check |

All routes except `/health` require JWT (`Depends(require_jwt)`).
Override add/remove and candidate accept/reject append an entry to the
CSPN audit trail (`/var/log/secubox/audit.log`).

## Deploy notes

- **Aggregator wiring**: add `proxypac` to the `aggregator.toml` module
  list so `/api/v1/proxypac/` is served in-process by the shared
  aggregator (like sibling modules). `secubox-proxypac.service` ships
  as a thin standalone fallback (own `proxypac.sock`) for when the
  aggregator isn't wired yet or a dedicated socket is preferred.
- **nginx**: enable `nginx/proxypac.conf` (the `/proxy.pac` +
  `/api/v1/proxypac/` location block) and `nginx/wpad-vhost.conf` (the
  dedicated `wpad.<domain>` vhost) into `sites-enabled`, then
  `nginx -t && systemctl reload nginx` (done automatically by
  `debian/postinst`, which also assumes the vhost/site drop is
  performed at deploy — the packaged files live under `nginx/` and are
  not auto-symlinked by the `.deb`).
- **dnsmasq**: deploy `conf/dnsmasq-wpad.conf` to the access point's
  dnsmasq config directory (e.g.
  `/etc/dnsmasq.d/dnsmasq-wpad.conf`) and restart `dnsmasq` so DHCP
  option 252 is advertised.
- **Regen units**: `debian/postinst` runs an initial `proxypac-gen`
  (fail-safe — ignored if it errors before the p2p socket exists) and
  enables `secubox-proxypac-gen.path` + `secubox-proxypac-gen.timer`.
- Package runs as `secubox:secubox` (created in `postinst` if absent);
  state under `/var/lib/secubox/proxypac/`, rules under
  `/etc/secubox/proxypac/rules.d/`, audit log under
  `/var/log/secubox/audit.log`.

## Out of scope

- **Mesh gateway with generative URLs for off-mesh clients** — a
  separate follow-on sub-project (tracked apart from this package);
  this package only routes clients that are already on the LAN/mesh.
- **Auto-learn detector** that populates `candidates.json` — deferred;
  this package ships the accept/reject/read half of that loop
  (`GET /candidates`, `POST /candidate/{host}/accept|reject`), but the
  detector that discovers and writes candidates is fed by a later,
  separate effort (#743).
