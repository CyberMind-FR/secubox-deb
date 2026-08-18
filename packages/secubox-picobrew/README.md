<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🍺 PicoBrew

LXC appliance host for PicoBrew devices — **phase 1**

**Category:** IoT

## What this module does

PicoBrew appliances (Pico S/C/Pro, Z Series, Zymatic) only ever talk to
`picobrew.com`. The manufacturer's cloud for that domain has been shut down
since 2020, which bricks the device. This module gives it a second life by:

- Provisioning a Debian LXC container (`picobrew`, `10.100.0.150/24` on
  `br-lxc`) that runs the upstream [`picobrew_pico`](https://github.com/chiefwigms/picobrew_pico)
  server the device expects.
- Rewriting `picobrew.com` locally (Unbound drop-in) to that LXC's address,
  so the device's factory DNS lookup resolves to a server that's actually
  alive.
- Terminating TLS in front of the server (the Z series requires HTTPS;
  `picobrew_pico` itself only serves plain HTTP on `:80`).
- Exposing a small admin panel (state + start/stop) served by a FastAPI
  backend that never acts privileged itself.

**Out of scope for phase 1:** temperature sensors, fermentation profiles,
recipes, alerts, Tilt/iSpindel support. The existing sensor-controller code
is preserved untouched in `lib/stillwatch/legacy_controller.py` for a later
phase — it is not shipped or wired up yet.

## `picobrewctl` — the single privileged surface

The panel never runs privileged actions directly: it always goes through
`sudo -n /usr/sbin/picobrewctl <subcommand>` (see
`debian/secubox-picobrew.sudoers`), the one audited root surface for this
module.

```text
picobrewctl install          # debootstrap + clone picobrew_pico + venv + systemd unit + TLS
picobrewctl start            # lxc-start
picobrewctl stop             # lxc-stop
picobrewctl status [--json]  # installed / running / ip / pinned_sha / session_active
picobrewctl update <sha>     # explicit upgrade to a pinned commit (refused during an active brew)
picobrewctl logs             # journalctl -u picobrew inside the LXC
```

Upstream is cloned at install time and then **pinned** to the resulting SHA:
no implicit update ever happens on its own — a change mid-brew on a machine
that's heating wort would be unacceptable. Upgrades only happen via an
explicit `picobrewctl update <sha>`, and are refused while a brew session is
active (`$STATE_DIR/session.active`, overridable for tests via
`PICOBREW_SESSION_FILE`).

## LXC

- Container name: `picobrew`, path `/data/lxc/picobrew`
- Bridge: `br-lxc`, address `10.100.0.150/24`, gateway `10.100.0.1`
- `lxc.start.auto = 1`: the appliance comes back after a board reboot
  without any human action

## DNS drop-in

`conf/unbound-picobrew.conf` redirects only `picobrew.com` to the LXC
(`10.100.0.150`) and is active by default — the manufacturer cloud for that
domain is dead, so there is nothing left to break by doing so.

## Configuration

Configuration file: `/etc/secubox/picobrew.toml`

## API Endpoints

- `GET /api/v1/picobrew/status` — aggregated container state (relays `picobrewctl status --json`)
- `POST /api/v1/picobrew/start` — delegates to `picobrewctl start`
- `POST /api/v1/picobrew/stop` — delegates to `picobrewctl stop`
- `GET /api/v1/picobrew/health` — health check

## Manual verification recipe (on the board)

Provisioning is not unit-testable; after deployment:

```bash
sudo picobrewctl install          # debootstrap + clone + venv + service
sudo picobrewctl status --json    # installed:true, running:true, pinned_sha set
dig +short picobrew.com @127.0.0.1   # must answer 10.100.0.150
curl -s -o /dev/null -w '%{http_code}\n' http://10.100.0.150/   # expected: 200
```

Then power on the real PicoBrew device and confirm it registers in the logs:
`sudo picobrewctl logs`.

**Network path note:** the device sits on the LAN, the LXC on `br-lxc`
(`10.100.0.0/24`) behind a default-DROP nftables policy. LAN → `br-lxc`
forwarding must be verified before the first real-device test — that test
is also the first test of this forwarding path, not just of the PicoBrew
server itself.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
