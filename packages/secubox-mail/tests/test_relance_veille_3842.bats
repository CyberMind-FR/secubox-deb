#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# #3842 : sur gk2 le 19/11, l'OOM du conteneur mail a tué le maître de Postfix ; postfix@- est resté en échec 31 h,
# sans relance ni alerte. Postfix et Dovecot repartent seuls ; rspamd et clamav-daemon sont tués en premier ;
# une veille côté hôte relance un service en échec et sort en erreur s'il ne repart pas.
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"; export CONTAINER="mail"; export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  source_mailctl_functions
  CALLS="$BATS_TEST_TMPDIR/calls"; : > "$CALLS"
  ECHECS="$BATS_TEST_TMPDIR/echecs"; : > "$ECHECS"        # services en échec, un par ligne
  TENACES="$BATS_TEST_TMPDIR/tenaces"; : > "$TENACES"     # services qui ne repartent pas
  export CALLS ECHECS TENACES
  lxc_attach() {
    shift
    local ligne="$*" dernier="${*: -1}"
    echo "ATTACH $ligne" >> "$CALLS"
    case "$*" in
      *"cat >"*) cat >> "$CALLS" ;;
      "systemctl is-failed --quiet "*) grep -qx "$dernier" "$ECHECS" ;;
      "systemctl is-active --quiet "*) ! grep -qx "$dernier" "$TENACES" ;;
      *"systemctl start "*) sed -i "/^${ligne##* }\$/d" "$ECHECS" ;;
      *) return 0 ;;
    esac
  }
  lxc_running() { return 0; }
  logger() { echo "LOGGER $*" >> "$CALLS"; }
  export -f lxc_attach lxc_running logger
}

@test "Postfix (gabarit) et Dovecot reçoivent la relance automatique" {
  run cmd_services_relance
  [ "$status" -eq 0 ]
  grep -q '/etc/systemd/system/postfix@.service.d/20-secubox-relance.conf' "$CALLS"
  grep -q '/etc/systemd/system/dovecot.service.d/20-secubox-relance.conf' "$CALLS"
  grep -q '^Restart=on-failure$' "$CALLS"
  grep -q '^StartLimitBurst=5$' "$CALLS"
  grep -q 'daemon-reload' "$CALLS"
}

@test "rspamd et clamav-daemon sont désignés premiers tués, jamais un ajustement négatif" {
  run cmd_services_relance
  [ "$status" -eq 0 ]
  grep -q '/etc/systemd/system/rspamd.service.d/20-secubox-oom.conf' "$CALLS"
  grep -q '/etc/systemd/system/clamav-daemon.service.d/20-secubox-oom.conf' "$CALLS"
  grep -q '^OOMScoreAdjust=500$' "$CALLS"
  ! grep -q '^OOMScoreAdjust=-' "$CALLS"
}

@test "un nom de service ou de surcharge douteux est refusé sans rien écrire" {
  run _lxc_surcharge 'postfix; rm -rf /' 20-secubox-relance mail < /dev/null
  [ "$status" -ne 0 ]
  run _lxc_surcharge postfix@ '../x' mail < /dev/null
  [ "$status" -ne 0 ]
  ! grep -q 'service.d' "$CALLS"
}

@test "mailctl services pose la relance AVANT de relancer clamav-daemon" {
  run cmd_services
  [ "$status" -eq 0 ]
  n_oom=$(grep -n 'clamav-daemon.service.d/20-secubox-oom.conf' "$CALLS" | head -1 | cut -d: -f1)
  n_restart=$(grep -n 'restart clamav-daemon' "$CALLS" | head -1 | cut -d: -f1)
  [ -n "$n_oom" ] && [ -n "$n_restart" ] && [ "$n_oom" -lt "$n_restart" ]
}

@test "veille : tout en service, rien n'est relancé" {
  run cmd_veille
  [ "$status" -eq 0 ]
  ! grep -q 'systemctl start' "$CALLS"
}

@test "veille : Postfix en échec est relancé et journalisé, la veille réussit" {
  echo 'postfix@-' > "$ECHECS"
  run cmd_veille
  [ "$status" -eq 0 ]
  grep -q 'reset-failed postfix@-; systemctl start postfix@-' "$CALLS"
  grep -q 'LOGGER .*postfix@- en echec' "$CALLS"
}

@test "veille : un service qui ne repart pas fait échouer la veille" {
  echo 'dovecot' > "$ECHECS"; echo 'dovecot' > "$TENACES"
  run cmd_veille
  [ "$status" -ne 0 ]
  grep -q 'LOGGER .*toujours en echec apres relance : dovecot' "$CALLS"
}

@test "veille : conteneur arrêté, rien à faire et pas d'erreur" {
  lxc_running() { return 1; }; export -f lxc_running
  run cmd_veille
  [ "$status" -eq 0 ]
  ! grep -q 'ATTACH' "$CALLS"
}

@test "les sous-commandes et la minuterie sont livrées" {
  grep -q '^    veille)' "$BATS_TEST_DIRNAME/../sbin/mailctl"
  grep -q 'secubox-mail-veille.timer' "$BATS_TEST_DIRNAME/../debian/rules"
  grep -q 'enable --now secubox-mail-veille.timer' "$BATS_TEST_DIRNAME/../debian/postinst"
  grep -q 'ExecStart=/usr/sbin/mailctl veille' "$BATS_TEST_DIRNAME/../debian/secubox-mail-veille.service"
}

@test "veille : conteneur injoignable (attache en échec), la veille échoue au lieu de se taire" {
  lxc_attach() { echo "ATTACH $*" >> "$CALLS"; return 1; }; export -f lxc_attach
  run cmd_veille
  [ "$status" -ne 0 ]
  grep -q 'LOGGER .*injoignable' "$CALLS"
}

@test "mailctl services continue (sans bac à sable, #3667) même si la relance échoue" {
  cmd_services_relance() { return 1; }; export -f cmd_services_relance
  run cmd_services
  [ "$status" -eq 0 ]
  grep -q 'dovecot.service.d/10-lxc-sans-sandbox.conf' "$CALLS"
}

@test "l'unité de veille est bornée dans le temps et porte le socle compatible lxc-attach" {
  u="$BATS_TEST_DIRNAME/../debian/secubox-mail-veille.service"
  for d in TimeoutStartSec=2min UMask=0027 PrivateTmp=true ProtectHome=true ProtectKernelLogs=true \
           ProtectKernelModules=true RestrictRealtime=true SystemCallArchitectures=native; do
    grep -qx "$d" "$u"
  done
  grep -q 'secubox-mail-veille.service' "$BATS_TEST_DIRNAME/../../../.claude/RULES-CODE.md"
}

@test "le postinst borne mailctl services et dit quand les surcharges ne sont pas posées" {
  grep -q 'timeout 300 /usr/sbin/mailctl services' "$BATS_TEST_DIRNAME/../debian/postinst"
  grep -q 'surcharges du conteneur non posées' "$BATS_TEST_DIRNAME/../debian/postinst"
}
