#!/usr/bin/env bats
load helpers

setup() { load_libs; make_fake_lxc_env; }

@test "lxc.sh sources cleanly" {
    [ "$(type -t lxc_exists)" = "function" ]
    [ "$(type -t lxc_running)" = "function" ]
    [ "$(type -t lxc_create_config)" = "function" ]
    [ "$(type -t lxc_start_safely)" = "function" ]
    [ "$(type -t lxc_attach_run)" = "function" ]
}

@test "lxc_exists returns 1 for missing container" {
    run lxc_exists "ghost-mail"
    [ "$status" -eq 1 ]
}

@test "lxc_exists returns 0 when rootfs exists" {
    mkdir -p "$LXC_BASE/mail/rootfs"
    run lxc_exists "mail"
    [ "$status" -eq 0 ]
}

@test "lxc_create_config writes a config with veth + 10.100.0.10 + br-lxc + unprivileged" {
    lxc_create_config "mail" "10.100.0.10" "br-lxc" "10.100.0.1"
    [ -f "$LXC_BASE/mail/config" ]
    grep -q "lxc.uts.name = mail"                       "$LXC_BASE/mail/config"
    grep -q "lxc.rootfs.path = dir:$LXC_BASE/mail/rootfs" "$LXC_BASE/mail/config"
    grep -q "lxc.net.0.type = veth"                     "$LXC_BASE/mail/config"
    grep -q "lxc.net.0.link = br-lxc"                   "$LXC_BASE/mail/config"
    grep -q "lxc.net.0.ipv4.address = 10.100.0.10/24"   "$LXC_BASE/mail/config"
    grep -q "lxc.net.0.ipv4.gateway = 10.100.0.1"       "$LXC_BASE/mail/config"
    grep -q "lxc.idmap = u 0 100000 65536"              "$LXC_BASE/mail/config"
    grep -qE "vmail[[:space:]]+var/vmail[[:space:]]+none[[:space:]]+bind" "$LXC_BASE/mail/config"
}

@test "lxc_create_config accepts plain IP (no /CIDR) and defaults to /24" {
    lxc_create_config "mail" "10.100.0.10"
    grep -q "lxc.net.0.ipv4.address = 10.100.0.10/24" "$LXC_BASE/mail/config"
}
