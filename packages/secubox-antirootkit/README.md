<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-antirootkit

Host-based intrusion detection module for SecuBox-Deb — anti-escape
containment + exec-surveillance scanner + integrity wrap + alert-only
manual quarantine.

## What it does — v1 scope

### LIVE

- **Anti-escape (A2):** any process not resolvable to a dpkg-backed
  executable is moved into `sbx-untrusted.slice`, a top-level cgroup whose
  egress is dropped by the `secubox_antiescape` nft table except for
  `lan_safe` destinations (RFC1918 + loopback). Jailing is performed by the
  root-only `secubox-antirootkitctl jail <pid>` helper via a scoped,
  exact-path sudoers rule (`sudoers/secubox-antirootkit`) — the daemon
  itself never runs as root.
- **Exec scanner (A):** targeted auditd watches
  (`conf/99-sbx-procwatch.rules`, key `sbx_exec`) on the common unbacked-exec
  surface — `/usr/local/bin`, `/usr/local/sbin`, `/tmp`, `/dev/shm`, `/opt`,
  `/usr/lib/jvm`, `/home` — feed `api/execwatch.py`, which decides
  allow-vs-jail using the dpkg-backing resolver (`api/dpkg_backing.py`) plus
  a TOML allowlist (`api/allowlist.py`, `/etc/secubox/antirootkit.toml`) and
  appends every decision to an append-only SQLite forensic log
  (`api/execlog.py`). The daemon (`api/daemon.py`) tracks a real polling
  cursor so each audit record is processed exactly once, even when two
  successive `ausearch` windows overlap. The watch list is deliberately
  targeted, not global, to keep audit volume low on a box running ~200
  services.
- **Alert-only quarantine-prep (C):** whenever the daemon jails a process it
  also appends an alert (`api/alerts.build_alert`) to the shared SQLite-backed
  store (`api/alertstore.py`, `/var/lib/secubox/antirootkit/alerts.db`) —
  the daemon (`sbx-antirootkitd.service`) and the API
  (`secubox-antirootkit.service`) are separate processes, so this store
  cannot be a plain in-memory list; `GET /alerts` returns it,
  most-recent-first.
  `POST /quarantine-prep` NEVER executes chmod/cp/nft/systemctl itself — it
  only returns an operator-reviewable plan (`api/quarantine.py`) that a
  human runs by hand. The web panel is served at `/antirootkit/`.

### SCAFFOLDED — v1.1 follow-up (not yet running automatically)

- **Integrity wrap (B):** `api/integrity.py` wraps `debsums`/`rkhunter` and
  the module Recommends `aide`, `rkhunter` and `chkrootkit` alongside a hard
  `debsums` dependency, but **no `.timer` schedules a scan yet** in this
  release. Do not assume integrity scanning runs automatically until that
  timer ships.

## Runtime topology

- `secubox-antirootkit.service` — FastAPI dashboard (status/execlog/alerts/
  quarantine-prep) on its own `/run/secubox/antirootkit.sock`, no aggregator
  dependency, runs as the confined `secubox-antirootkit` system user.
- `sbx-antirootkitd.service` — the exec-watcher daemon (`api/daemon.py`),
  tails `ausearch -k sbx_exec` and jails unknown execs via sudo into the
  ctl. `NoNewPrivileges=no` (needed for the scoped sudo call).
- `sbx-untrusted.slice` — top-level (cgroup-root) slice; must stay
  unnested so `socket cgroupv2 level 1 "sbx-untrusted.slice"` in the nft
  rule keeps matching.

## Prerequisite (out-of-package, apt/boot)

`auditd` must actually be running (`systemctl enable --now auditd`) and the
kernel must support cgroup v2 unified hierarchy for the anti-escape jail to
take effect; this package installs the config/rules but does not itself
change the box's cgroup boot mode.
