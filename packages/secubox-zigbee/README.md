# secubox-zigbee

[zigbee2mqtt](https://www.zigbee2mqtt.io) for SecuBox, hosted in a Debian
bookworm LXC at `10.100.0.111` on the SecuBox `br-lxc` bridge. Coordinator
radio is mounted into the LXC via the host's `/dev/secubox-zgb` symlink.

Follows [`docs/MODULE-GUIDELINES.md`](../../docs/MODULE-GUIDELINES.md);
opens the **MESH** layer of the SecuBox CTL grammar (sister to mqttctl,
homeassistantctl, etc.).

## URLs (dual-vhost split, per MODULE-GUIDELINES §4 REQUIRED)

| URL | Role |
| --- | --- |
| `https://admin.gk2.secubox.in/zigbee/` | **SecuBox admin** — components / status / access / backups / restore. Static page calling `/api/v1/zigbee/*`. |
| `https://zigbee.gk2.secubox.in/` | **Real zigbee2mqtt frontend** at vhost root, Authelia-gated. The admin page's `Open Zigbee Manager →` button points here (URL read from `/api/v1/zigbee/access` — do NOT hardcode). |
| `http://10.100.0.111:8080/` | Inside the LXC, behind nginx — usually only useful for debugging from gk2 itself. |

## Quickstart

```bash
apt install secubox-zigbee
# The package's install-lxc.sh provisions the LXC at 10.100.0.111,
# installs zigbee2mqtt, mounts the radio, and starts the daemon.
systemctl status secubox-zigbee   # green when host FastAPI + LXC + z2m + bridge all up
```

## API — `/api/v1/zigbee/` (Unix socket `/run/secubox/zigbee.sock`)

```text
GET  /healthz                  liveness
GET  /components               three-fold: lxc, device, daemon, bridge
GET  /status                   overall green | yellow | red
GET  /access                   urls — public (Authelia), lan (direct), lan-mqtt
GET  /backups                  list available z2m state snapshots
POST /backup                   trigger a fresh snapshot (synchronous)
POST /restore {id}             roll back to a snapshot (stops z2m, archives current,
                               copies snapshot files, restarts z2m)
```

The backup/restore surface (#373 → v2.6.0) lets the operator recover from
a z2m database wipe — the failure mode behind the 2026-05-23 incident
where a MQTT outage during reboot left z2m looping against EHOSTUNREACH
and overwriting `database.db` with a 560 B coordinator-only file.

## Ports

| Port | Proto | Use |
| --- | --- | --- |
| 8080 | tcp | z2m frontend (proxied by nginx — admin via dedicated vhost) |
| 1883 | tcp | MQTT broker reachable at `mqtt://10.100.0.110:1883` (separate `secubox-mqtt` LXC) |

## Files

```text
/etc/secubox/zigbee.toml                       # operator config (env vars: SECUBOX_LXC_IP, …)
/etc/nginx/secubox.d/zigbee.conf               # /api/v1/zigbee/ + static /zigbee/ admin alias
/etc/nginx/secubox-routes.d/zigbee.conf        # idem (canonical hub vhost include)
/etc/nginx/sites-available/zigbee.conf         # dedicated zigbee.gk2.secubox.in vhost
/usr/lib/secubox/zigbee/api/                   # host FastAPI
/usr/share/secubox/www/zigbee/                 # SecuBox admin webui (static)
/usr/share/secubox/menu.d/80-zigbee.json       # menu entry (mesh category)
/usr/sbin/zigbee-backup, zigbee-restore        # host scripts (sudo NOPASSWD per package sudoers.d)
/data/backup/zigbee/<UTC-timestamp>/           # hourly snapshots
/data/lxc/zigbee/                              # LXC rootfs
```
