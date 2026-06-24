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

# /run/secubox is the world-writable socket dir and MUST stay 1777 root:root so
# a service running as ANY user can create its own socket. 90+ services declare
# `RuntimeDirectory=secubox`, which makes systemd re-chown the parent to
# secubox:secubox 0755 on every (re)start — locking out non-secubox socket
# creators (e.g. blacklist-attrib: "Permission denied") (#421/#494). Re-assert
# the canonical perms here so that flapping self-heals each minute.
if [ -d /run/secubox ]; then
    [ "$(stat -c '%a %U %G' /run/secubox 2>/dev/null)" = "1777 root root" ] || {
        chown root:root /run/secubox 2>/dev/null || true
        chmod 1777 /run/secubox 2>/dev/null || true
    }
fi
exit 0
