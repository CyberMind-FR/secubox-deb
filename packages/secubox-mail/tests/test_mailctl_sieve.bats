#!/usr/bin/env bats
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"; export CONTAINER="mail"
  export LXC_PATH="$BATS_TEST_TMPDIR/lxc"
  mkdir -p "$DATA_PATH/backups" "$DATA_PATH/vmail" "$DATA_PATH/config"
  source_mailctl_functions
}

@test "sieve status rapporte l'écoute 4190" {
  lxc_attach() { case "$*" in *4190*) echo "LISTEN 0 100 *:4190" ;; *) return 0 ;; esac; }
  export -f lxc_attach
  run cmd_sieve status
  [ "$status" -eq 0 ]
  [[ "$output" == *"4190"* ]]
}

@test "sieve status avertit quand 4190 est absent" {
  lxc_attach() { return 0; }
  export -f lxc_attach
  run cmd_sieve status
  [ "$status" -eq 0 ]
  [[ "$output" == *"absent"* ]]
}

@test "sieve enable réconcilie, régénère la conf et redémarre dovecot" {
  lxc_attach() {
    case "$*" in
      *doveconf*) echo "maildir:/var/vmail/%d/%n" ;;
      *"ss -tlnp"*) echo "LISTEN 0 100 *:4190" ;;
      *) return 0 ;;
    esac
  }
  export -f lxc_attach
  configure_dovecot() { echo "regen appelé" >> "$BATS_TEST_TMPDIR/trace"; }
  export -f configure_dovecot
  run cmd_sieve enable
  [ "$status" -eq 0 ]
  grep -q "regen appelé" "$BATS_TEST_TMPDIR/trace"
  [[ "$output" == *"4190"* ]]
}

@test "sieve enable remonte une erreur si le redémarrage dovecot échoue" {
  lxc_attach() {
    case "$*" in
      *doveconf*) echo "maildir:/var/vmail/%d/%n" ;;
      *"systemctl restart dovecot"*) return 1 ;;
      *) return 0 ;;
    esac
  }
  export -f lxc_attach
  configure_dovecot() { :; }
  export -f configure_dovecot
  run cmd_sieve enable
  [ "$status" -ne 0 ]
}

@test "sieve avec sous-commande inconnue échoue avec usage" {
  run cmd_sieve bogus
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage"* ]]
}
