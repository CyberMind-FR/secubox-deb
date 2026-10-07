#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Webmail : Apache ne démarre pas dans le LXC roundcube sans surcharge du bac à sable (226/NAMESPACE, gk2, 2026-10-05) → 502.
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"; export CONTAINER="mail"; export WEBMAIL_CONTAINER="roundcube"; export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  source_mailctl_functions
  CALLS="$BATS_TEST_TMPDIR/calls"; : > "$CALLS"
  lxc_attach() { echo "ATTACH $*" >> "$CALLS"; case "$*" in *"cat >"*) cat >> "$CALLS" ;; esac; }
  lxc_running() { return 0; }
  export -f lxc_attach lxc_running
}

@test "mailctl webmail pose la surcharge sur apache2 et les nettoyages, puis démarre apache2" {
  run cmd_webmail
  [ "$status" -eq 0 ]
  for s in apache2 phpsessionclean roundcube-gc roundcube-cleandb; do grep -q "/etc/systemd/system/$s.service.d/" "$CALLS"; done
  grep -q 'enable --now apache2' "$CALLS"
}

@test "conteneur webmail arrêté : refus sans rien écrire" {
  lxc_running() { return 1; }
  run cmd_webmail
  [ "$status" -ne 0 ]
  ! grep -q 'service.d' "$CALLS"
}

@test "la sous-commande webmail est dans le dispatcher" {
  grep -q '^    webmail)' "$BATS_TEST_DIRNAME/../sbin/mailctl"
}
