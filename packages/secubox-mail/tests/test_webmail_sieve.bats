#!/usr/bin/env bats
# #1181 : WEBMAIL_CONTAINER vient du TOML (LXC roundcube séparé) + geste webmail-sieve.
load helpers
setup() {
  export CONFIG_FILE="$BATS_TEST_TMPDIR/mail.toml"
  printf 'container = "mail"\nwebmail_container = "roundcube"\nlxc_ip = "10.100.0.10"\n' > "$CONFIG_FILE"
}
@test "WEBMAIL_CONTAINER lu depuis le TOML (roundcube, pas mail)" {
  source_mailctl_functions
  [ "$WEBMAIL_CONTAINER" = "roundcube" ]
}
@test "défaut = conteneur mail si webmail_container absent" {
  printf 'container = "mail"\nlxc_ip = "10.100.0.10"\n' > "$CONFIG_FILE"
  source_mailctl_functions
  [ "$WEBMAIL_CONTAINER" = "mail" ]
}
@test "dispatch webmail-sieve + geste présents" {
  grep -q "webmail-sieve) cmd_webmail_sieve" "${BATS_TEST_DIRNAME}/../sbin/mailctl"
  grep -q "cmd_webmail_sieve()" "${BATS_TEST_DIRNAME}/../sbin/mailctl"
  grep -q "'managesieve'" "${BATS_TEST_DIRNAME}/../sbin/mailctl"
}
