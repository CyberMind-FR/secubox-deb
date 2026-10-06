#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Redis du conteneur mail : sans surcharge, son bac à sable systemd (ProtectSystem, PrivateDevices, PrivateTmp…) ne se monte pas
# dans un LXC sans privilèges (226/NAMESPACE, constaté sur gk2 le 2026-10-05). rspamd attendait alors 65 s par message
# (règle REPLIES) : les envois du rapport WAF expiraient.
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"; export CONTAINER="mail"; export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  source_mailctl_functions
  CALLS="$BATS_TEST_TMPDIR/calls"; : > "$CALLS"
  lxc_attach() { echo "ATTACH $*" >> "$CALLS"; case "$*" in *"cat >"*) cat >> "$CALLS" ;; esac; }
  lxc_running() { return 0; }
  export -f lxc_attach lxc_running
  mkdir -p "$BATS_TEST_TMPDIR/bin"; printf '#!/bin/sh\necho "DECALER $*" >> "%s"\n' "$CALLS" > "$BATS_TEST_TMPDIR/bin/secubox-lxc-decaler"
  chmod +x "$BATS_TEST_TMPDIR/bin/secubox-lxc-decaler"; export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

@test "la surcharge désactive le bac à sable du service" {
  run lxc_service_sans_sandbox redis-server mail
  [ "$status" -eq 0 ]
  grep -q '/etc/systemd/system/redis-server.service.d/' "$CALLS"
  for p in PrivateDevices=false PrivateTmp=false ProtectSystem=false ProtectHome=false PrivateUsers=false; do grep -q "$p" "$CALLS"; done
  grep -q 'daemon-reload' "$CALLS"
}

@test "un nom de service douteux est refusé sans rien écrire" {
  run lxc_service_sans_sandbox 'redis; rm -rf /' mail
  [ "$status" -ne 0 ]
  ! grep -q 'service.d' "$CALLS"
}

@test "mailctl redis pose la surcharge, démarre redis puis relance rspamd" {
  run cmd_redis
  [ "$status" -eq 0 ]
  grep -q 'DECALER' "$CALLS"
  grep -q 'redis-server.service.d' "$CALLS"
  grep -q 'enable --now redis-server' "$CALLS"
  grep -q 'restart rspamd' "$CALLS"
}

@test "l'apprentissage antispam pose aussi la surcharge avant d'activer redis" {
  run grep -n 'lxc_service_sans_sandbox redis-server' "$BATS_TEST_DIRNAME/../sbin/mailctl"
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | wc -l)" -ge 2 ]          # une fois dans cmd_redis, une fois dans cmd_antispam_apprentissage
}

@test "la sous-commande redis est dans le dispatcher" {
  grep -q '^    redis)' "$BATS_TEST_DIRNAME/../sbin/mailctl"
}

@test "mailctl redis répare aussi systemd-resolved du conteneur quand il existe et ne tourne pas" {
  lxc_attach() { echo "ATTACH $*" >> "$CALLS"; case "$*" in *"cat >"*) cat >> "$CALLS" ;; esac
    case "$*" in *"is-active systemd-resolved"*) return 3 ;; *"cat systemd-resolved"*|*"list-unit-files systemd-resolved"*) return 0 ;; esac; return 0; }
  export -f lxc_attach
  run cmd_redis
  [ "$status" -eq 0 ]
  grep -q 'systemd-resolved.service.d' "$CALLS"
  grep -q 'restart systemd-resolved' "$CALLS"
}

@test "mailctl redis ne touche pas à systemd-resolved s'il tourne déjà" {
  lxc_attach() { echo "ATTACH $*" >> "$CALLS"; case "$*" in *"cat >"*) cat >> "$CALLS" ;; esac; return 0; }
  export -f lxc_attach
  run cmd_redis
  [ "$status" -eq 0 ]
  ! grep -q 'systemd-resolved.service.d' "$CALLS"
}
