#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
# #3829 : _entier ne rend qu'un entier, et _jobs_in_flight ne lance qu'un lxc-attach.
set -u
CTL="$(dirname "$0")/../sbin/peertubectl"
fail=0

# _entier : extrait les chiffres, vide -> 0, multi-ligne/avertissement -> chiffres seuls.
check_entier() {
    local got; got=$(bash -c ". <(sed -n '/^_entier()/p' '$CTL'); _entier \"\$1\"" _ "$1")
    [ "$got" = "$2" ] || { echo "FAIL _entier('$1') = '$got' attendu '$2'"; fail=1; }
}
check_entier "" "0"
check_entier "5" "5"
check_entier $'\n' "0"
check_entier "WARNING\n12" "12"
check_entier "3 " "3"

# Un seul lxc-attach dans _jobs_in_flight (sinon re-dépassement de délai sous charge).
nb=$(grep -c "lxc-attach" <(sed -n '/^_jobs_in_flight()/,/^}/p' "$CTL"))
[ "$nb" -eq 1 ] || { echo "FAIL _jobs_in_flight lance $nb lxc-attach (attendu 1)"; fail=1; }

# Plus aucun $(( )) sur une valeur non coercée dans cmd_backlog.
grep -q 'counters=$(_entier' "$CTL" || { echo "FAIL counters non coercé"; fail=1; }

[ "$fail" -eq 0 ] && echo "OK test_backlog_entier_3829" || exit 1
