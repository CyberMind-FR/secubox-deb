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

# clamavctl simulé : le paquet secubox-clamav (LXC dédié, #1912) n'est pas installé en test.
faux_clamavctl() {
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  printf '#!/bin/sh\necho "LXC STOPPED — clamd endormi"\n' > "$BATS_TEST_TMPDIR/bin/clamavctl"
  chmod +x "$BATS_TEST_TMPDIR/bin/clamavctl"
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

@test "antivirus on dépose le module rspamd vers le LXC clamav et n'installe RIEN dans le conteneur mail" {
  faux_clamavctl
  LXC_PATH="$BATS_TEST_TMPDIR/lxc"      # source_mailctl_functions l'a remis à sa valeur par défaut
  mkdir -p "$LXC_PATH/mail/rootfs/etc/rspamd/local.d"
  echo 'local_addrs = "127.0.0.0/8";' > "$LXC_PATH/mail/rootfs/etc/rspamd/local.d/options.inc"
  lxc_attach() { echo "APPEL: $*" >> "$BATS_TEST_TMPDIR/calls"; }
  export -f lxc_attach
  run cmd_antivirus on
  [ "$status" -eq 0 ]
  grep -q 'tee /etc/rspamd/local.d/antivirus.conf' "$BATS_TEST_TMPDIR/calls"
  # task_timeout posé CÔTÉ HÔTE (options.inc est à l'uid 0 de l'hôte : le conteneur ne peut pas l'écrire)
  grep -q '^task_timeout = 150s;' "$LXC_PATH/mail/rootfs/etc/rspamd/local.d/options.inc"
  [ "$(grep -c '^task_timeout' "$LXC_PATH/mail/rootfs/etc/rspamd/local.d/options.inc")" = "1" ]
  grep -q 'systemctl restart rspamd' "$BATS_TEST_TMPDIR/calls"
  ! grep -q 'apt-get' "$BATS_TEST_TMPDIR/calls"
  ! grep -q 'clamav-daemon' "$BATS_TEST_TMPDIR/calls"
}

@test "antivirus on sans le paquet secubox-clamav échoue proprement, sans rien déposer" {
  lxc_attach() { echo "APPEL: $*" >> "$BATS_TEST_TMPDIR/calls"; }
  export -f lxc_attach
  PATH="/usr/bin:/bin" run cmd_antivirus on
  [ "$status" -ne 0 ]
  [[ "$output" == *"secubox-clamav"* ]]
  ! grep -q 'tee' "$BATS_TEST_TMPDIR/calls" 2>/dev/null
}

@test "antivirus on échoue proprement si le gabarit source est absent" {
  faux_clamavctl
  rm -f "$TEMPLATES_DIR/rspamd/local.d/antivirus.conf"
  lxc_attach() { echo "APPEL: $*" >> "$BATS_TEST_TMPDIR/calls"; }
  export -f lxc_attach
  run cmd_antivirus on
  [ "$status" -ne 0 ]
  ! grep -q 'tee /etc/rspamd/local.d/antivirus.conf' "$BATS_TEST_TMPDIR/calls" 2>/dev/null
}

@test "antivirus status rapporte l'état du LXC clamav et du module rspamd" {
  faux_clamavctl
  lxc_attach() { echo "module Rspamd : déposé"; }
  export -f lxc_attach
  run cmd_antivirus status
  [ "$status" -eq 0 ]
  [[ "$output" == *"clamd endormi"* ]]
  [[ "$output" == *"module Rspamd"* ]]
}

@test "le gabarit livré pointe sur le mandataire de l'hôte, pas sur un clamd local" {
  g="$(cd "$BATS_TEST_DIRNAME/.." && pwd)/templates/rspamd/local.d/antivirus.conf"
  grep -q 'servers = "10.100.0.1:3310"' "$g"
  ! grep -q 'clamd.ctl' "$g"
  grep -q 'timeout = 120' "$g"
}

@test "le gabarit n'enveloppe PAS sa configuration dans antivirus { } (section déjà ouverte par Rspamd)" {
  g="$(cd "$BATS_TEST_DIRNAME/.." && pwd)/templates/rspamd/local.d/antivirus.conf"
  # Une ligne de code (hors commentaire) qui ouvre `antivirus {` = section imbriquée = module mort.
  ! grep -Ev '^[[:space:]]*#' "$g" | grep -Eq '^[[:space:]]*antivirus[[:space:]]*\{'
  grep -Ev '^[[:space:]]*#' "$g" | grep -Eq '^clamav[[:space:]]*\{'
}

@test "antivirus avec sous-commande inconnue échoue avec usage" {
  run cmd_antivirus bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage"* ]]
}
