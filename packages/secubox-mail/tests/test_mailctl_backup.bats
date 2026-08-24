#!/usr/bin/env bats
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"
  export CONTAINER="mail"
  mkdir -p "$DATA_PATH/vmail" "$DATA_PATH/config" "$DATA_PATH/backups"
  echo "hello" > "$DATA_PATH/vmail/probe.txt"
  # charge uniquement les fonctions de mailctl sans exécuter le dispatch
  source_mailctl_functions
}

@test "backup crée une archive horodatée contenant vmail" {
  run cmd_backup
  [ "$status" -eq 0 ]
  local tb
  tb="$(ls "$DATA_PATH"/backups/mail-*.tar.gz)"
  [ -f "$tb" ]
  tar tzf "$tb" | grep -q "vmail/probe.txt"
}
