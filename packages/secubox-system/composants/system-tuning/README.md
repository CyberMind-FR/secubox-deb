<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-system-tuning

SecuBox System Tuning — swap + zram + memory/CPU caps for LXC.

Per-board memory tuning for SecuBox: configures a swap file in /data (boards typically ship with 0 swap and exhaust real memory under LXC load), and applies per-LXC-container cgroup MemoryHigh soft caps to throttle (not OOM-kill) runaway containers.

Captures the by-hand fix applied on gk2 on 2026-05-27 (#391) so other boards inherit it automatically. Idempotent: re-running the tuning script after editing the TOML config only diffs the deltas.

Configuration lives at /etc/secubox/tuning/{config.toml, lxc-memory-high.toml}. Apply with secubox-tuning-apply or wait for the next package upgrade.

Distinct from secubox-hardening (kernel sysctl + AppArmor + module blacklist for *security*) — this package is *performance* tuning: swap and cgroup soft limits.

Paquet Debian : version `1.2.5-1~bookworm1`, architecture `all`.

## Contenu

- `etc/` : fichiers du module
- `sbin/` : exécutables
- `tests/` : tests

## Tests

2 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-system-tuning`.
