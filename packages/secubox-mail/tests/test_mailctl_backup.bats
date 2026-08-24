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
  tb="$(ls "$DATA_PATH"/backups/mail_*.tar.gz)"
  [ -f "$tb" ]
  tar tzf "$tb" | grep -q "vmail/probe.txt"
}

@test "restore réussie restaure vmail et redémarre dovecot" {
  local tb
  # cmd_backup n'écrit que le chemin sur stdout (le log de succès va sur
  # stderr) : une simple substitution de commande suffit à le récupérer.
  tb="$(cmd_backup)"
  [ -n "$tb" ]
  [ -f "$tb" ]

  # Simule la perte des données que le restore doit réparer.
  rm -f "$DATA_PATH/vmail/probe.txt"

  # Pas de vrai conteneur LXC en test : on simule un redémarrage Dovecot
  # réussi pour isoler le test du geste d'extraction.
  lxc_attach() { return 0; }

  run cmd_restore "$tb"
  [ "$status" -eq 0 ]
  [ -f "$DATA_PATH/vmail/probe.txt" ]
  [ "$(cat "$DATA_PATH/vmail/probe.txt")" = "hello" ]
}

@test "restore échoue proprement si l'archive est absente" {
  run cmd_restore "$DATA_PATH/backups/does-not-exist.tar.gz"
  [ "$status" -ne 0 ]
  [[ "$output" == *"archive introuvable"* ]]
}
