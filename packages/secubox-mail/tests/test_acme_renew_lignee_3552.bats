#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# SecuBox-Deb :: mail :: acme_renew() suit la lignée acme.sh même si certbot est installé (#3552)
load helpers

setup() {
  export DATA_PATH="$BATS_TEST_TMPDIR/data"
  export ACME_HOME="$BATS_TEST_TMPDIR/acme"
  L="$ACME_HOME/mail.example.test_ecc"
  mkdir -p "$DATA_PATH/ssl" "$L"
  echo neuf > "$L/fullchain.cer"
  echo cle > "$L/mail.example.test.key"
  echo ancien > "$DATA_PATH/ssl/fullchain.pem"
  source_mailctl_functions
  certbot() { echo "certbot appele" >&2; return 1; }
}

acme_factice() {
  printf '#!/bin/sh\necho "$@" > "%s/args"\nexit %s\n' "$BATS_TEST_TMPDIR" "$1" > "$ACME_HOME/acme.sh"
  chmod +x "$ACME_HOME/acme.sh"
}

@test "lignee acme.sh pas encore a renouveler : le certificat courant est deploye" {
  acme_factice 2
  run acme_renew mail.example.test
  [ "$status" -eq 0 ]
  [ "$(cat "$DATA_PATH/ssl/fullchain.pem")" = neuf ]
  [ "$(cat "$DATA_PATH/ssl/privkey.pem")" = cle ]
  grep -q -- '--ecc' "$BATS_TEST_TMPDIR/args"
  ! grep -q -- '--force' "$BATS_TEST_TMPDIR/args"
}

@test "echec reel d'acme.sh : l'ancien certificat reste" {
  acme_factice 1
  run acme_renew mail.example.test
  [ "$status" -eq 1 ]
  [ "$(cat "$DATA_PATH/ssl/fullchain.pem")" = ancien ]
}
