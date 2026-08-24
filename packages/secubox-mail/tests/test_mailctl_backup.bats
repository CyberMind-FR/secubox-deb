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

@test "restore restaure aussi dovecot.conf dans le rootfs (rollback #1169)" {
  export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  local rootfs="$LXC_PATH/$CONTAINER/rootfs"
  mkdir -p "$rootfs/etc/dovecot"
  echo "protocols = imap pop3 lmtp sieve" > "$rootfs/etc/dovecot/dovecot.conf"

  local tb
  tb="$(cmd_backup)"
  [ -n "$tb" ]
  tar tzf "$tb" | grep -q "etc/dovecot/dovecot.conf"

  # Simule une régénération cassée que le restore doit annuler.
  echo "conf cassée" > "$rootfs/etc/dovecot/dovecot.conf"

  lxc_attach() { return 0; }
  run cmd_restore "$tb"
  [ "$status" -eq 0 ]
  [ "$(cat "$rootfs/etc/dovecot/dovecot.conf")" = "protocols = imap pop3 lmtp sieve" ]
}

@test "restore ne échoue pas si l'archive ne contient pas dovecot.conf" {
  export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  local rootfs="$LXC_PATH/$CONTAINER/rootfs"
  mkdir -p "$rootfs/etc/dovecot"
  # Archive volontairement sans dovecot.conf, comme une ancienne sauvegarde.
  local tb="$DATA_PATH/backups/mail_old.tar.gz"
  tar czf "$tb" -C "$DATA_PATH" vmail config

  lxc_attach() { return 0; }
  run cmd_restore "$tb"
  [ "$status" -eq 0 ]
}
