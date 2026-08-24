#!/usr/bin/env bats
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"; export CONTAINER="mail"
  export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  export TEMPLATES_DIR="$BATS_TEST_TMPDIR/templates"
  mkdir -p "$TEMPLATES_DIR/rspamd/local.d"
  echo 'antivirus { clamav { type = "clamav"; servers = "/var/run/clamav/clamd.ctl"; } }' \
    > "$TEMPLATES_DIR/rspamd/local.d/antivirus.conf"
  source_mailctl_functions
}

@test "antivirus off est un no-op sans installation" {
  lxc_attach() { echo "APPEL: $*" >> "$BATS_TEST_TMPDIR/calls"; }
  export -f lxc_attach
  run cmd_antivirus off
  [ "$status" -eq 0 ]
  ! grep -q 'apt.*clamav' "$BATS_TEST_TMPDIR/calls" 2>/dev/null
}

@test "antivirus off retire le module rspamd et redémarre rspamd" {
  lxc_attach() { echo "APPEL: $*" >> "$BATS_TEST_TMPDIR/calls"; }
  export -f lxc_attach
  run cmd_antivirus off
  [ "$status" -eq 0 ]
  grep -q 'rm -f /etc/rspamd/local.d/antivirus.conf' "$BATS_TEST_TMPDIR/calls"
  grep -q 'systemctl restart rspamd' "$BATS_TEST_TMPDIR/calls"
}

@test "antivirus on installe clamav, dépose le module rspamd et redémarre les deux services" {
  lxc_attach() { echo "APPEL: $*" >> "$BATS_TEST_TMPDIR/calls"; }
  export -f lxc_attach
  run cmd_antivirus on
  [ "$status" -eq 0 ]
  grep -q 'apt-get install -y clamav-daemon clamav-freshclam' "$BATS_TEST_TMPDIR/calls"
  grep -q 'tee /etc/rspamd/local.d/antivirus.conf' "$BATS_TEST_TMPDIR/calls"
  grep -q 'systemctl restart clamav-daemon rspamd' "$BATS_TEST_TMPDIR/calls"
}

@test "antivirus on ne casse pas si le gabarit source est absent" {
  rm -f "$TEMPLATES_DIR/rspamd/local.d/antivirus.conf"
  lxc_attach() { echo "APPEL: $*" >> "$BATS_TEST_TMPDIR/calls"; }
  export -f lxc_attach
  run cmd_antivirus on
  [ "$status" -eq 0 ]
  ! grep -q 'tee /etc/rspamd/local.d/antivirus.conf' "$BATS_TEST_TMPDIR/calls" 2>/dev/null
}

@test "antivirus status rapporte l'état clamav-daemon" {
  lxc_attach() { echo "active"; }
  export -f lxc_attach
  run cmd_antivirus status
  [ "$status" -eq 0 ]
  [[ "$output" == *"active"* ]]
}

@test "antivirus status rapporte inactive quand clamav-daemon est absent" {
  lxc_attach() { return 1; }
  export -f lxc_attach
  run cmd_antivirus status
  [[ "$output" == *"inactive"* ]]
}

@test "antivirus avec sous-commande inconnue échoue avec usage" {
  run cmd_antivirus bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage"* ]]
}
