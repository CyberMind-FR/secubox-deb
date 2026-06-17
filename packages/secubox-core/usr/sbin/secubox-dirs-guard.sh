#!/bin/sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# SecuBox-Deb :: shared-dir traversal guard
# Keep the shared SecuBox parent dirs traversable (0755) so EVERY secubox-* user
# can reach its own subtree. Counters the recurring `install -d -m 0750 …/secubox`
# clobber in various module postinsts that breaks kbin/toolbox (#626/#630).
# chmod-only (owner-agnostic); runs every minute via secubox-dirs-guard.timer.
for d in /var/lib/secubox /var/log/secubox /var/cache/secubox /etc/secubox /usr/share/secubox; do
    [ -d "$d" ] || continue
    [ "$(stat -c %a "$d" 2>/dev/null)" = "755" ] || chmod 0755 "$d" 2>/dev/null || true
done
exit 0
