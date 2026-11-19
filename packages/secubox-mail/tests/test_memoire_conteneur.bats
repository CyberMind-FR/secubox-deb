#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

setup() {
    LIB="$BATS_TEST_DIRNAME/../lib/mail/memoire.sh"
    CFG="$BATS_TEST_TMPDIR/config"
    cat > "$CFG" <<'C'
lxc.uts.name = mail
# Phase 6.P (#496) : memory budget
# Phase 6.P (#496) : memory budget
lxc.cgroup2.cpu.weight = 300
# Phase 6.P (#496) : memory budget
lxc.cgroup2.memory.max = 512M
lxc.cgroup2.memory.swap.max = 0
lxc.cgroup2.memory.high = 500M
lxc.cgroup2.memory.max = 1G
lxc.start.auto = 1
C
}

@test "remplace tous les réglages mémoire par un seul bloc, garde le reste" {
    run bash -c ". '$LIB'; mail_memoire_config '$CFG'"
    [ "$status" -eq 10 ]
    [ "$(grep -c '^lxc.cgroup2.memory.max = 1G$' "$CFG")" -eq 1 ]
    [ "$(grep -c '^lxc.cgroup2.memory.high = 900M$' "$CFG")" -eq 1 ]
    [ "$(grep -c '^lxc.cgroup2.memory.swap.max = 0$' "$CFG")" -eq 1 ]
    [ "$(grep -c 'memory.max' "$CFG")" -eq 1 ]
    ! grep -q '512M\|500M\|#496' "$CFG"
    grep -q '^lxc.cgroup2.cpu.weight = 300$' "$CFG"
    grep -q '^lxc.start.auto = 1$' "$CFG"
}

@test "idempotent : un second passage ne change rien" {
    bash -c ". '$LIB'; mail_memoire_config '$CFG'" || true
    cp "$CFG" "$CFG.avant"
    run bash -c ". '$LIB'; mail_memoire_config '$CFG'"
    [ "$status" -eq 0 ]
    cmp -s "$CFG" "$CFG.avant"
}

@test "applique les limites au cgroup vivant, sans redémarrage" {
    mkdir -p "$BATS_TEST_TMPDIR/cg/lxc.payload.mail"
    run bash -c "MAIL_CGROUP_RACINE='$BATS_TEST_TMPDIR/cg'; . '$LIB'; mail_memoire_vive mail"
    [ "$status" -eq 0 ]
    [ "$(cat "$BATS_TEST_TMPDIR/cg/lxc.payload.mail/memory.max")" = "1G" ]
    [ "$(cat "$BATS_TEST_TMPDIR/cg/lxc.payload.mail/memory.high")" = "900M" ]
}

@test "conteneur absent : rien à faire" {
    run bash -c "MAIL_CGROUP_RACINE='$BATS_TEST_TMPDIR/vide'; . '$LIB'; mail_memoire_vive mail; mail_memoire_config /nexiste/pas"
    [ "$status" -eq 0 ]
}
