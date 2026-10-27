<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Core

Core package for SecuBox-Deb platform. Provides shared libraries, utilities, and base services.

## Components

### Python Library (`secubox_core`)

Shared Python modules for all SecuBox services:

- `auth.py` - JWT authentication helpers
- `config.py` - TOML configuration loader
- `logger.py` - Unified logging
- `system.py` - System utilities
- `kiosk.py` - Kiosk mode helpers

### Services

| Service | Description |
|---------|-------------|
| `secubox-core.service` | Core initialization |
| `secubox-runtime.service` | Runtime directory setup |
| `secubox-led-heartbeat.service` | LED heartbeat indicator |
| `secubox-dns-listes.service` (+ `.path`, `.timer`) | DNS block lists compiled into one tagged Unbound file (#3205) |

### CLI Tools

- `/usr/bin/secubox` - Main SecuBox CLI
- `/usr/bin/secubox-firstboot` - First boot initialization
- `/usr/sbin/secubox-led-heartbeat` - LED heartbeat daemon
- `/usr/sbin/secubox-dns-listes` - `appliquer` (default), `etat`, `compiler FICHIER` (#3205)

## Listes DNS compilées (`secubox-dns-listes`, 1.8.0, #3205)

webfilter, adblock and adult no longer write into `/etc/unbound/unbound.conf.d`: each **deposits** its render
(`93-secubox-webfilter.conf`, `95-secubox-adblock.conf`, `96-secubox-adult.conf`) in
`/var/lib/secubox-dns-listes/sources` (`secubox_unbound.depot.deposer_source` / `retirer_source`). The root oneshot
`secubox-dns-listes.service` (AppArmor `/usr/sbin/secubox-dns-listes`, only `CAP_DAC_OVERRIDE` for `audit.log`, `MemoryMax=50%`) then:

1. adopts an old file still present in `unbound.conf.d` (older generator, previous install) as its source;
2. compiles the sources with `secubox_unbound.listes`: one client class per address block that carries a policy
   (`access-control`, `access-control-view`, override target, plus Unbound's built-in `127.0.0.0/8` and `::1`), each
   domain once, `define-tag`/`local-zone-tag` groups, `access-control-tag-action … always_transparent` for exceptions;
   decisions identical to the separate files (bench on gk1 with gk2's real configuration: Unbound 743 → 387 MB,
   145 530 questions, 27 classes);
3. writes `92-secubox-listes.conf` and removes 93/95/96 in **one** transaction (`poser_vues`: one
   `unbound-checkconf`, one reload, full byte-for-byte rollback); the reload only counts once
   `unbound-control status` answers again (#2969).

The tree `/var/lib/secubox-dns-listes` (sources, state, 0600 lock) is root-owned and **outside** `/var/lib/secubox`
(owned by the shared `secubox` account, which could rename and replace a sub-directory); every deposit checks the
directory and its parent (no symlink, owner, not group/world-writable). New ACL elements in the 92 reuse the action and
kept view of the element that covered the class: the compiled file never opens access the old files did not.

Triggers: `secubox-dns-listes.path` (sources **and** `unbound.conf.d`: a new TV view or network changes the classes),
daily timer. The state `/var/lib/secubox-dns-listes/etat.json` (0644) holds `etat` (`applique`, `inchange`,
`en-cours` — left by a killed pass, the next one verifies and reloads —, `erreur`, `sans-unbound`), `stats`,
`adoptes`, `passes`, `t`, `t_echec` and the `signature` of the inputs actually compiled: a pass whose inputs (sources,
what the compiler reads from the context, compiler code, written files) are unchanged does not recompile, a failure on
the same inputs is retried after one hour, a source deposited during a compilation is picked up (up to three passes).

`/etc/secubox/dns-listes.toml`: `mode = "compile"` (default) or `mode = "direct"` (rollback: sources copied unchanged
under their old names, no compilation).

## LED Heartbeat

Visual system status indicator using IS31FL3199 RGB LEDs on MOCHAbin.

### Configuration

Environment variables in systemd service:

```ini
Environment=LED_COLOR=green   # red, green, or blue
Environment=LED_NUM=1         # LED number (1-3)
```

### Pattern

Double-pulse heartbeat pattern:
- ON 150ms → OFF 150ms → ON 150ms → OFF 700ms (repeat)

### Manual Control

```bash
# Start/stop
systemctl start secubox-led-heartbeat
systemctl stop secubox-led-heartbeat

# Test LED manually
echo 255 > /sys/class/leds/green:led1/brightness
echo 0 > /sys/class/leds/green:led1/brightness
```

## Installation

```bash
apt install secubox-core
```

## Dependencies

- python3
- python3-toml
- i2c-tools (for LED control)

## Files

```
/usr/lib/python3/dist-packages/secubox_core/
/usr/bin/secubox
/usr/bin/secubox-firstboot
/usr/sbin/secubox-led-heartbeat
/usr/sbin/secubox-dns-listes
/usr/lib/python3/dist-packages/secubox_unbound/{__init__,listes,depot}.py
/etc/apparmor.d/secubox-dns-listes
/var/lib/secubox-dns-listes/{sources/,etat.json}
/usr/lib/systemd/system/secubox-*.service
/usr/share/secubox-core/nginx/
/etc/nginx/secubox.d/
```

## License

Proprietary - CyberMind / ANSSI CSPN candidate
