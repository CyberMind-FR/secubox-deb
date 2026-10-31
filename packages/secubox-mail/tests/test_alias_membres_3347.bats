#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
# #3347 — membres d'un alias : ajout, retrait, validation, dernier membre gardé.

setup() {
    export DATA_PATH="$BATS_TEST_TMPDIR"
    export CONFIG_PATH="$BATS_TEST_TMPDIR/config"
    export SECUBOX_AUDIT_LOG="$BATS_TEST_TMPDIR/audit.log"
    mkdir -p "$CONFIG_PATH"
    printf 'contact@secubox.in gk2@secubox.in\nroot@secubox.in gk2@secubox.in\n' > "$CONFIG_PATH/virtual"
    # shellcheck source=/dev/null
    source "${BATS_TEST_DIRNAME}/../lib/mail/users.sh"
    CONFIG_PATH="$BATS_TEST_TMPDIR/config"
    alias_recompile() { echo recompile >> "$BATS_TEST_TMPDIR/recompile"; }
}

@test "membre-add ajoute une cible et recompile" {
    run alias_membre_add contact@secubox.in cedre83@secubox.in
    [ "$status" -eq 0 ]
    grep -qx 'contact@secubox.in gk2@secubox.in, cedre83@secubox.in' "$CONFIG_PATH/virtual"
    grep -qx 'root@secubox.in gk2@secubox.in' "$CONFIG_PATH/virtual"
    [ -f "$BATS_TEST_TMPDIR/recompile" ]
    grep -q '"alias_membre_ajoute"' "$SECUBOX_AUDIT_LOG"
}

@test "membre-add refuse un doublon" {
    run alias_membre_add contact@secubox.in gk2@secubox.in
    [ "$status" -ne 0 ]
    grep -qx 'contact@secubox.in gk2@secubox.in' "$CONFIG_PATH/virtual"
}

@test "membre-add refuse une adresse invalide ou une injection" {
    for c in 'pas-une-adresse' 'a@b.c, evil@x.y' 'a@b.c
d@e.f' 'a b@c.d' '-x@y.z' ''; do
        run alias_membre_add contact@secubox.in "$c"
        [ "$status" -ne 0 ]
    done
    [ "$(wc -l < "$CONFIG_PATH/virtual")" -eq 2 ]
}

@test "membre-add refuse un alias inconnu" {
    run alias_membre_add inconnu@secubox.in cedre83@secubox.in
    [ "$status" -ne 0 ]
}

@test "membre-del retire une cible" {
    alias_membre_add contact@secubox.in cedre83@secubox.in
    run alias_membre_del contact@secubox.in gk2@secubox.in
    [ "$status" -eq 0 ]
    grep -qx 'contact@secubox.in cedre83@secubox.in' "$CONFIG_PATH/virtual"
    grep -q '"alias_membre_retire"' "$SECUBOX_AUDIT_LOG"
}

@test "membre-del refuse de retirer le dernier membre" {
    run alias_membre_del contact@secubox.in gk2@secubox.in
    [ "$status" -ne 0 ]
    grep -qx 'contact@secubox.in gk2@secubox.in' "$CONFIG_PATH/virtual"
}

@test "membre-del refuse un membre absent" {
    run alias_membre_del contact@secubox.in personne@secubox.in
    [ "$status" -ne 0 ]
}
