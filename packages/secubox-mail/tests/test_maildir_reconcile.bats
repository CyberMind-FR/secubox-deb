#!/usr/bin/env bats
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"; export CONTAINER="mail"
  export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  mkdir -p "$DATA_PATH/backups" "$DATA_PATH/vmail" "$DATA_PATH/config"
  source_mailctl_functions
}

@test "reconcile est un no-op quand déjà en maildir" {
  lxc_attach() { echo "maildir:/var/vmail/%d/%n"; }   # doveconf -h mail_location
  export -f lxc_attach
  run cmd_maildir_reconcile
  [ "$status" -eq 0 ]
  [[ "$output" == *"déjà conforme"* ]]
}

@test "reconcile régénère quand mbox détecté" {
  # première invocation = doveconf (mbox), suivantes = restart/create (ok)
  lxc_attach() { case "$*" in *doveconf*) echo "mbox:~/mail" ;; *) return 0 ;; esac; }
  export -f lxc_attach
  configure_dovecot() { echo "regen appelé" >> "$BATS_TEST_TMPDIR/trace"; }
  export -f configure_dovecot
  run cmd_maildir_reconcile
  [ "$status" -eq 0 ]
  grep -q "regen appelé" "$BATS_TEST_TMPDIR/trace"
}

@test "reconcile crée les Maildir des comptes existants et remonte une erreur de redémarrage" {
  lxc_attach() {
    case "$*" in
      *doveconf*) echo "mbox:~/mail" ;;
      *"systemctl restart dovecot"*) return 1 ;;
      *) return 0 ;;
    esac
  }
  export -f lxc_attach
  configure_dovecot() { :; }
  export -f configure_dovecot
  run cmd_maildir_reconcile
  [ "$status" -ne 0 ]
}

@test "reconcile annule la bascule si le backup préalable échoue" {
  lxc_attach() { case "$*" in *doveconf*) echo "mbox:~/mail" ;; *) return 0 ;; esac; }
  export -f lxc_attach
  cmd_backup() { return 1; }
  export -f cmd_backup
  configure_dovecot() { echo "regen appelé" >> "$BATS_TEST_TMPDIR/trace"; }
  export -f configure_dovecot
  run cmd_maildir_reconcile
  [ "$status" -ne 0 ]
  [ ! -f "$BATS_TEST_TMPDIR/trace" ]
}

@test "reconcile n'abandonne pas si la création d'un Maildir échoue" {
  lxc_attach() {
    case "$*" in
      *doveconf*) echo "mbox:~/mail" ;;
      *"cat /etc/mail-config/users"*) printf 'alice@example.com:hash\nbob@example.com:hash\n' ;;
      *"doveadm mailbox create"*) return 1 ;;
      *) return 0 ;;
    esac
  }
  export -f lxc_attach
  configure_dovecot() { :; }
  export -f configure_dovecot
  run cmd_maildir_reconcile
  [ "$status" -eq 0 ]
  [[ "$output" == *"bascule Maildir effectuée"* ]]
}
