# secubox-lyrion

[Lyrion Music Server](https://lyrion.org) (formerly Logitech Media Server /
Squeezebox Server) for SecuBox, hosted in a Debian bookworm LXC at
`10.100.0.100` on the SecuBox `br-lxc` bridge.

Follows [`docs/MODULE-GUIDELINES.md`](../../docs/MODULE-GUIDELINES.md); opens
the **HOSTING** layer of the SecuBox CTL grammar (sister to streamlitctl,
metablogizerctl, etc.).

## Quickstart

```bash
apt install secubox-lyrion
lyrionctl install       # provisions LXC at 10.100.0.100, installs Lyrion 9.0.4
lyrionctl status        # green when LXC + daemon + host-api all up
```

Web admin at `http://10.100.0.100:9000/` (direct) or
`https://<host>/lyrion/` (through the canonical hub vhost).

## CTL — `lyrionctl`

Three-fold + lifecycle (v1.0.0 ships install + reload; rest is v1.1.0):

```text
lyrionctl components | status | access [--json]
lyrionctl install | reload | repair (1.1.0) | wizard (1.1.0) | uninstall (1.1.0)

lyrionctl player    list | play <id> | pause <id> | next <id> | prev <id> | volume <id> <0-100>
lyrionctl library   scan | refresh | status | wipe
lyrionctl playlist  list | add <name> | remove <name> | tracks <name>
lyrionctl plugin    list | install <name> | uninstall <name>
```

## Music library

The `[library]` section of `/etc/secubox/lyrion.toml` points to the host's
music directory (default `/data/music`). On `lyrionctl install`, that path
is bind-mounted read-only into the LXC at the same path. LMS scans +
indexes from there; no writes to source files.

## Ports

| Port | Proto | Use |
|---|---|---|
| 9000 | tcp | Web UI + JSON-RPC API (proxied via nginx `/lyrion/`) |
| 9090 | tcp | CLI (telnet/netcat) |
| 3483 | tcp+udp | slimproto (Squeezebox players discover/connect) |

3483 is **NOT exposed publicly** — players are expected on the LAN. Add an
nftables DNAT only if you have a remote Squeezebox.

## Files

```text
/etc/secubox/lyrion.toml                  # operator config
/etc/nginx/secubox.d/lyrion.conf          # /api/v1/lyrion/ + /lyrion/ iframe
/etc/nginx/secubox-routes.d/lyrion.conf   # idem (canonical hub vhost)
/usr/lib/secubox/lyrion/api/              # host FastAPI
/usr/share/secubox/lib/lyrion/install-lxc.sh
/usr/share/secubox/www/lyrion/            # SecuBox-themed iframe wrapper
/usr/share/secubox/menu.d/80-lyrion.json
/data/lxc/lyrion/                         # LXC rootfs (created by lyrionctl install)
/data/music/                              # operator music library (bind-mounted)
```
