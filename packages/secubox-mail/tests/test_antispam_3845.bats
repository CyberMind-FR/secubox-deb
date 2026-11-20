#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# #3845 : rspamd désactivable. « off » retire les milters AVANT d'arrêter rspamd ; « on » démarre rspamd AVANT de
# poser les milters ; chaque geste est audité ; la veille (#3842) ne relance pas un rspamd désactivé.
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"; export CONTAINER="mail"; export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  export SECUBOX_AUDIT_LOG="$BATS_TEST_TMPDIR/audit.log"
  source_mailctl_functions
  CALLS="$BATS_TEST_TMPDIR/calls"; : > "$CALLS"; export CALLS
  lxc_attach() { shift; echo "ATTACH $*" >> "$CALLS"; case "$*" in
      "systemctl is-enabled --quiet rspamd") [ -f "$BATS_TEST_TMPDIR/rspamd-on" ] ;;
      "systemctl is-failed --quiet rspamd") return 0 ;;
      "systemctl is-failed --quiet "*) return 1 ;;
      *) return 0 ;; esac; }
  lxc_running() { return 0; }
  logger() { :; }
  export -f lxc_attach lxc_running logger
}

@test "off : milters vidés et Postfix rechargé AVANT l'arrêt de rspamd, geste audité" {
  run cmd_antispam off
  [ "$status" -eq 0 ]
  n_milter=$(grep -n 'postconf -e smtpd_milters= non_smtpd_milters=' "$CALLS" | cut -d: -f1)
  n_stop=$(grep -n 'disable --now rspamd' "$CALLS" | cut -d: -f1)
  [ -n "$n_milter" ] && [ -n "$n_stop" ] && [ "$n_milter" -lt "$n_stop" ]
  grep -q 'postfix reload' "$CALLS"
  grep -q '"action":"antispam_desactive"' "$SECUBOX_AUDIT_LOG"
}

@test "on : rspamd démarré AVANT les milters, geste audité" {
  run cmd_antispam on
  [ "$status" -eq 0 ]
  n_start=$(grep -n 'enable --now rspamd' "$CALLS" | cut -d: -f1)
  n_milter=$(grep -n 'smtpd_milters=inet:127.0.0.1:11332' "$CALLS" | cut -d: -f1)
  [ -n "$n_start" ] && [ -n "$n_milter" ] && [ "$n_start" -lt "$n_milter" ]
  grep -q '"action":"antispam_active"' "$SECUBOX_AUDIT_LOG"
}

@test "conteneur arrêté : aucun geste" {
  lxc_running() { return 1; }; export -f lxc_running
  run cmd_antispam off
  [ "$status" -ne 0 ]
  ! grep -q ATTACH "$CALLS"
}

@test "la veille ne relance pas un rspamd désactivé, mais relance un rspamd activé" {
  run cmd_veille
  ! grep -q 'systemctl start rspamd' "$CALLS"
  : > "$CALLS"; touch "$BATS_TEST_TMPDIR/rspamd-on"
  run cmd_veille
  grep -q 'systemctl start rspamd' "$CALLS"
}

@test "geste inconnu refusé ; sous-commande dans le dispatcher" {
  run cmd_antispam 'x; rm -rf /'
  [ "$status" -ne 0 ]
  grep -q '^    antispam)' "$BATS_TEST_DIRNAME/../sbin/mailctl"
}
