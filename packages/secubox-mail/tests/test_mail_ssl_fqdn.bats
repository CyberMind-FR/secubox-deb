#!/usr/bin/env bats
# SecuBox-Deb :: mail :: mail_ssl_fqdn() — dérivation du FQDN ACME réel
# (#1169 revue finale, defaut bloquant 3). `$HOSTNAME.$DOMAIN` ne correspond
# jamais au certificat déployé sur la board.
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"
  mkdir -p "$DATA_PATH/ssl"
  source_mailctl_functions
  # CONFIG_FILE est réassigné sans condition en tête de mailctl (pas de
  # pattern ${CONFIG_FILE:-...}) : l'exporter AVANT source_mailctl_functions
  # n'aurait aucun effet. config_get() le relit dynamiquement à chaque appel,
  # donc le réaffecter ICI (après le source) suffit.
  export CONFIG_FILE="$BATS_TEST_TMPDIR/mail.toml"
}

@test "mail_ssl_fqdn lit le CN du certificat déjà déployé en priorité" {
  command -v openssl >/dev/null || skip "openssl absent de l'hôte de test"
  openssl req -x509 -newkey rsa:2048 -keyout "$DATA_PATH/ssl/privkey.pem" \
    -out "$DATA_PATH/ssl/fullchain.pem" -days 1 -nodes \
    -subj "/CN=mail.secubox.in" >/dev/null 2>&1

  # Même avec une clé TOML différente, le CN du cert existant l'emporte.
  echo 'mail_fqdn = "should-not-win.example"' > "$CONFIG_FILE"

  run mail_ssl_fqdn
  [ "$status" -eq 0 ]
  [ "$output" = "mail.secubox.in" ]
}

@test "mail_ssl_fqdn retombe sur la clé TOML mail_fqdn si aucun cert" {
  rm -rf "$DATA_PATH/ssl"
  echo 'mail_fqdn = "mail.secubox.in"' > "$CONFIG_FILE"

  run mail_ssl_fqdn
  [ "$status" -eq 0 ]
  [ "$output" = "mail.secubox.in" ]
}

@test "mail_ssl_fqdn retombe sur mail.\$DOMAIN en dernier recours" {
  rm -rf "$DATA_PATH/ssl"
  : > "$CONFIG_FILE"
  DOMAIN="example.org"

  run mail_ssl_fqdn
  [ "$status" -eq 0 ]
  [ "$output" = "mail.example.org" ]
}
