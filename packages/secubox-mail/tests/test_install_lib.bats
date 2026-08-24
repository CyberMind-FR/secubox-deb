#!/usr/bin/env bats
load helpers

setup() { load_libs; make_fake_lxc_env; }

@test "install.sh sources cleanly" {
    [ "$(type -t bootstrap_debian)" = "function" ]
    [ "$(type -t install_mail_packages)" = "function" ]
    [ "$(type -t install_webmail_packages)" = "function" ]
    [ "$(type -t configure_postfix)" = "function" ]
    [ "$(type -t configure_dovecot)" = "function" ]
    [ "$(type -t configure_roundcube)" = "function" ]
}

@test "bootstrap_debian refuses to run if debootstrap missing" {
    local fake_path="$BATS_TEST_TMPDIR/path"
    mkdir -p "$fake_path"
    PATH="$fake_path" run bootstrap_debian "$LXC_BASE/mail"
    [ "$status" -ne 0 ]
    [[ "$output" == *"debootstrap"* ]]
}

@test "la liste de paquets inclut Sieve + ManageSieve" {
    local install_sh="${BATS_TEST_DIRNAME}/../lib/mail/install.sh"
    grep -q 'dovecot-sieve' "$install_sh"
    grep -q 'dovecot-managesieved' "$install_sh"
}
