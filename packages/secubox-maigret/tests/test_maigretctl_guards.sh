#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# Exercises maigretctl's injection guards via the hidden __guard entrypoint.
set -u
CTL="$(dirname "$0")/../sbin/maigretctl"
fail=0
ok()  { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && echo "PASS accept $1 '$2'" || { echo "FAIL should-accept $1 '$2'"; fail=1; }; }
no()  { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && { echo "FAIL should-reject $1 '$2'"; fail=1; } || echo "PASS reject $1 '$2'"; }

# --- username: alphanumeric first char, then [A-Za-z0-9._-], max 64 ---
ok username "johndoe";       ok username "John.Doe_99"; ok username "a-b_c.d"; ok username "0user"
no username "-johndoe";      no username "--flag";        # leading '-' = flag-injection
no username 'a;rm -rf /';    no username 'a b';           # metacharacters / spaces
no username "$(printf 'a\nb')"                            # newline
no username '../../etc/passwd'                            # path traversal
no username 'a/b';           no username 'a@b'            # slash / at not allowed
no username '';              no username '.hidden'        # empty / non-alnum first
no username "$(printf 'a%.0s' {1..65})"                   # 65 chars > 64 limit
ok username "$(printf 'a%.0s' {1..64})"                   # exactly 64 chars OK

# --- id: 8 lowercase hex ---
ok id "a1b2c3d4";            no id "XYZ";  no id "a1b2c3d4e5"; no id "A1B2C3D4"; no id ""
exit $fail
