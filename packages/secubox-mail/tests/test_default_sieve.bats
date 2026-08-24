#!/usr/bin/env bats
# SecuBox-Deb :: mail :: sieve par défaut (spam Rspamd → Junk) — Task 6.
load helpers
setup() {
  load_libs
  make_fake_lxc_env
  export SIEVE_CONFIG_DIR="${BATS_TEST_DIRNAME}/../config/sieve"
}

@test "default.sieve compile sans erreur" {
  command -v sievec >/dev/null || skip "sievec absent de l'hôte de test"
  run sievec "${BATS_TEST_DIRNAME}/../config/sieve/default.sieve" "$BATS_TEST_TMPDIR/out.svbin"
  [ "$status" -eq 0 ]
}

@test "default.sieve range le spam dans Junk" {
  grep -q 'fileinto :create "Junk"' "${BATS_TEST_DIRNAME}/../config/sieve/default.sieve"
}

@test "install_default_sieve dépose default.sieve dans le rootfs" {
  install_default_sieve mail
  local target="$LXC_BASE/mail/rootfs/var/vmail/sieve/default.sieve"
  [ -f "$target" ]
  grep -q 'fileinto :create "Junk"' "$target"
}

@test "configure_dovecot appelle install_default_sieve (idempotent)" {
  configure_dovecot mail
  local target="$LXC_BASE/mail/rootfs/var/vmail/sieve/default.sieve"
  [ -f "$target" ]
  # ré-exécution idempotente : pas d'erreur, contenu inchangé
  configure_dovecot mail
  [ -f "$target" ]
  grep -q 'fileinto :create "Junk"' "$target"
}
