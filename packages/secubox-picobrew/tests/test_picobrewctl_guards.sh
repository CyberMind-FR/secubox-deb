#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# SecuBox-Deb :: test_picobrewctl_guards — validation des entrées critiques.

CTL="$(dirname "$0")/../sbin/picobrewctl"
fail=0
ok() { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && echo "PASS accept $1 '$2'" || { echo "FAIL should-accept $1 '$2'"; fail=1; }; }
no() { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && { echo "FAIL should-reject $1 '$2'"; fail=1; } || echo "PASS reject $1 '$2'"; }

# A pinned SHA is exactly 40 lowercase hex chars — anything else could be a
# crafted ref that makes `git checkout` fetch attacker-chosen code.
ok sha "0123456789abcdef0123456789abcdef01234567"
no sha "HEAD"
no sha "main"
no sha "0123456789abcdef0123456789abcdef0123456"      # 39 — trop court
no sha "0123456789ABCDEF0123456789ABCDEF01234567"     # majuscules
no sha "v1.0; rm -rf /"

# Unknown subcommand must not silently succeed.
"$CTL" definitely-not-a-command >/dev/null 2>&1 && { echo "FAIL unknown cmd accepted"; fail=1; } || echo "PASS reject unknown cmd"
exit $fail
