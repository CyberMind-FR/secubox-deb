#!/usr/bin/env bats
# SecuBox-Deb :: mail :: mailctl ssl renew (ref #1169 task 10)
load helpers

setup() {
    export DATA_PATH="$BATS_TEST_TMPDIR/data"
    mkdir -p "$DATA_PATH/ssl"
    source_mailctl_functions
}

@test "ssl renew garde une copie horodatée de l'ancien cert" {
    : > "$DATA_PATH/ssl/fullchain.pem"
    acme_renew() { echo "renew"; }; export -f acme_renew   # mock du renouvellement
    reload_mail_tls() { :; }; export -f reload_mail_tls
    run cmd_ssl renew
    [ "$status" -eq 0 ]
    ls "$DATA_PATH/ssl/"fullchain.pem.* >/dev/null 2>&1
}

@test "ssl renew échoue proprement et garde l'ancien cert si acme_renew échoue" {
    echo "old-cert" > "$DATA_PATH/ssl/fullchain.pem"
    acme_renew() { return 1; }; export -f acme_renew
    reload_mail_tls() { echo "should-not-reload"; }; export -f reload_mail_tls
    run cmd_ssl renew
    [ "$status" -ne 0 ]
    [ "$(cat "$DATA_PATH/ssl/fullchain.pem")" = "old-cert" ]
}

@test "ssl renew appelle reload_mail_tls après un renouvellement réussi" {
    : > "$DATA_PATH/ssl/fullchain.pem"
    acme_renew() { return 0; }; export -f acme_renew
    reload_mail_tls() { echo "RELOADED" > "$BATS_TEST_TMPDIR/reload.marker"; }; export -f reload_mail_tls
    run cmd_ssl renew
    [ "$status" -eq 0 ]
    [ -f "$BATS_TEST_TMPDIR/reload.marker" ]
}
