#!/usr/bin/env bats
# packages/secubox-system/tests/test_leasewatch.bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0

setup() {
    export TMP=$(mktemp -d)
    export RES="$TMP/reservations.conf"
    export SECUBOX_EYE_RESERVATIONS_FILE="$RES"
    export SECUBOX_EYE_SKIP_RELOAD=1   # don't call systemctl in tests
    export SECUBOX_EYE_SKIP_API=1      # don't curl the API in tests
    touch "$RES"
    SCRIPT="$BATS_TEST_DIRNAME/../usr/lib/secubox/eye-remote-leasewatch.sh"
}

teardown() {
    rm -rf "$TMP"
}

@test "add: appends reservation for new MAC" {
    run "$SCRIPT" add 02:fb:00:00:11:03 10.55.0.11 eye-rpiz
    [ "$status" -eq 0 ]
    grep -q "^dhcp-host=02:fb:00:00:11:03,10.55.0.11,eye-rpiz" "$RES"
}

@test "add: is idempotent for the same MAC" {
    "$SCRIPT" add 02:fb:00:00:11:03 10.55.0.11 eye-rpiz
    "$SCRIPT" add 02:fb:00:00:11:03 10.55.0.11 eye-rpiz
    [ "$(grep -c '^dhcp-host=' "$RES")" -eq 1 ]
}

@test "old: does not append anything" {
    "$SCRIPT" old 02:fb:00:00:11:03 10.55.0.11 eye-rpiz
    [ ! -s "$RES" ]
}

@test "missing hostname: fills from MAC suffix" {
    "$SCRIPT" add 02:fb:00:00:11:03 10.55.0.11
    grep -q "eye-fb00001103" "$RES"
}
