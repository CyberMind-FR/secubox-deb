#!/usr/bin/env bats
# Task 11 (#1169) — empaquetage de la dérive board-only : autoconfig XML
# (RFC 6186 / Thunderbird) + enregistrements SRV Unbound split-horizon.
# Contenu figé depuis le board (voir board-ref/ dans le plan SDD).

@test "config-v1.1.xml annonce imap 993 + submission 587" {
  local f="${BATS_TEST_DIRNAME}/../www/autoconfig/config-v1.1.xml"
  [ -f "$f" ]
  grep -q '<incomingServer type="imap">' "$f"
  grep -q '993' "$f"
  grep -q '587' "$f"
}

@test "nginx sert /mail/config-v1.1.xml (URL réellement servie par le board, tidy 4)" {
  local f="${BATS_TEST_DIRNAME}/../nginx/autoconfig.conf"
  [ -f "$f" ]
  grep -q 'location = /mail/config-v1.1.xml' "$f"
  grep -q 'alias /usr/share/secubox/www/autoconfig/config-v1.1.xml' "$f"
  # Le chemin RFC 6186 .well-known doit rester présent, inchangé.
  grep -q 'location = /.well-known/autoconfig/mail/config-v1.1.xml' "$f"
}

@test "SRV Unbound déclare _imaps._tcp et _submission._tcp" {
  local f="${BATS_TEST_DIRNAME}/../config/unbound/97-mail-srv.conf"
  [ -f "$f" ]
  grep -q '_imaps._tcp' "$f"
  grep -q '_submission._tcp' "$f"
}

@test "SRV Unbound ne touche pas le split-horizon existant (fichier dédié)" {
  local f="${BATS_TEST_DIRNAME}/../config/unbound/97-mail-srv.conf"
  # Ce fichier doit être autonome : pas de référence au fichier split-horizon
  # partagé, pour rester safe à poser en drop-in additif.
  ! grep -q '97-secubox-split-horizon' "$f"
}
