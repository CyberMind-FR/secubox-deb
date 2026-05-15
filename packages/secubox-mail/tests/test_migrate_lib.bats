#!/usr/bin/env bats
load helpers

setup() { load_libs; make_fake_lxc_env; }

@test "migrate.sh sources cleanly" {
    [ "$(type -t detect_legacy_lxc)" = "function" ]
    [ "$(type -t guard_data_path)" = "function" ]
    [ "$(type -t detect_legacy_toml_keys)" = "function" ]
}

@test "detect_legacy_lxc finds mailserver+roundcube paths" {
    mkdir -p "$LXC_BASE/mailserver/rootfs" "$LXC_BASE/roundcube/rootfs"
    run detect_legacy_lxc
    [ "$status" -eq 0 ]
    [[ "$output" == *"mailserver"* ]]
    [[ "$output" == *"roundcube"* ]]
}

@test "detect_legacy_lxc returns 1 when only 'mail' exists" {
    mkdir -p "$LXC_BASE/mail/rootfs"
    run detect_legacy_lxc
    [ "$status" -eq 1 ]
}

@test "guard_data_path refuses non-empty vmail (data preservation invariant I13)" {
    mkdir -p "$DATA_PATH/vmail/secubox.in/gk2"
    touch "$DATA_PATH/vmail/secubox.in/gk2/keep-me"
    run guard_data_path
    [ "$status" -ne 0 ]
    [[ "$output" == *"refusing"* ]] || [[ "$output" == *"already has data"* ]]
}

@test "guard_data_path accepts empty vmail dir" {
    mkdir -p "$DATA_PATH/vmail"
    run guard_data_path
    [ "$status" -eq 0 ]
}

@test "guard_data_path accepts missing vmail dir" {
    run guard_data_path
    [ "$status" -eq 0 ]
}

@test "detect_legacy_toml_keys finds each legacy key" {
    local toml="$BATS_TEST_TMPDIR/mail.toml"
    cat > "$toml" <<TOML
[mail]
mail_container = "mailserver"
webmail_container = "roundcube"
mail_ip = "192.168.255.30"
webmail_ip = "192.168.255.31"
webmail_port = 8027
TOML
    run detect_legacy_toml_keys "$toml"
    [ "$status" -eq 0 ]
    [[ "$output" == *"mail_container"* ]]
    [[ "$output" == *"webmail_container"* ]]
    [[ "$output" == *"mail_ip"* ]]
    [[ "$output" == *"webmail_ip"* ]]
    [[ "$output" == *"webmail_port"* ]]
}

@test "detect_legacy_toml_keys returns 1 when toml is already migrated" {
    local toml="$BATS_TEST_TMPDIR/mail.toml"
    cat > "$toml" <<TOML
[mail]
container = "mail"
lxc_ip = "10.100.0.10"
TOML
    run detect_legacy_toml_keys "$toml"
    [ "$status" -eq 1 ]
}
