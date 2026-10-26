#!/usr/bin/env bats
# Autocrypt sortant (#1852) : la synchronisation ne pousse que du PUBLIC, valide, et ne recharge rspamd que si la config passe.
load helpers

setup() {
  export CONTAINER="mail" TEMPLATES_DIR="$BATS_TEST_TMPDIR/templates" CALLS="$BATS_TEST_TMPDIR/calls"
  mkdir -p "$TEMPLATES_DIR/rspamd" "$BATS_TEST_TMPDIR/bin"
  echo "-- regle" > "$TEMPLATES_DIR/rspamd/autocrypt.lua"
  : > "$CALLS"
  source_mailctl_functions
  lxc_exists() { return 0; }
  lxc_running() { return 0; }
  error() { echo "ERREUR: $*" >&2; }
  lxc_attach() { echo "ATTACH: $*" >> "$CALLS"; timeout 1 cat > /dev/null 2>&1 || true; }
  printf '#!/bin/sh\n[ "$1" = autocrypt ] && printf "%%s" "$SBX_TABLE"\n' > "$BATS_TEST_TMPDIR/bin/sbx-openpgp"
  chmod +x "$BATS_TEST_TMPDIR/bin/sbx-openpgp"
  export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

@test "autocrypt-sync pousse la table et la regle puis recharge rspamd" {
  export SBX_TABLE='{"alice@secubox.in":"QUJD"}'
  run cmd_autocrypt_sync
  [ "$status" -eq 0 ]
  [[ "$output" == *"1 adresse(s)"* ]]
  grep -q '/etc/rspamd/autocrypt.lua' "$CALLS"
  grep -q 'autocrypt.json' "$CALLS"
  grep -q 'rspamadm configtest' "$CALLS"
  grep -q 'systemctl reload rspamd' "$CALLS"
}

@test "autocrypt-sync refuse une table invalide et ne pousse rien" {
  export SBX_TABLE='pas du json'
  run cmd_autocrypt_sync
  [ "$status" -ne 0 ]
  ! grep -q 'autocrypt' "$CALLS"
}

@test "autocrypt-sync sans sbx-openpgp ne fait rien" {
  rm "$BATS_TEST_TMPDIR/bin/sbx-openpgp"
  PATH="/usr/bin:/bin" run cmd_autocrypt_sync
  [ "$status" -ne 0 ]
}

@test "la regle rspamd ne s'applique qu'a un envoi authentifie au nom de la meme adresse et ne remplace rien" {
  f="${BATS_TEST_DIRNAME}/../templates/rspamd/autocrypt.lua"
  grep -q "task:get_user()" "$f"
  grep -q "task:has_header('Autocrypt')" "$f"
  grep -q "adresse ~= boite" "$f"
  ! grep -qi "secret\|private" <(grep -v '^--' "$f")
}

# #3185 : gk1 a secubox-mail sans conteneur provisionné — les minuteries échouaient à chaque passage.
@test "autocrypt-sync sans conteneur provisionne s'abstient sans erreur" {
  export SBX_TABLE='{"alice@secubox.in":"QUJD"}'
  lxc_exists() { return 1; }
  lxc_running() { return 1; }
  run cmd_autocrypt_sync
  [ "$status" -eq 0 ]
  [[ "$output" == *"non provisionn"* ]]
  ! grep -q 'ATTACH' "$CALLS"
}

@test "autocrypt-sync avec un conteneur provisionne mais arrete reste une panne" {
  export SBX_TABLE='{"alice@secubox.in":"QUJD"}'
  lxc_exists() { return 0; }
  lxc_running() { return 1; }
  run cmd_autocrypt_sync
  [ "$status" -ne 0 ]
}

@test "imap-sync run sans conteneur provisionne s'abstient sans erreur" {
  lxc_exists() { return 1; }
  lxc_running() { return 1; }
  export IMAP_SYNC_DIR="$BATS_TEST_TMPDIR/imap" IMAP_SYNC_ETAT="$BATS_TEST_TMPDIR/imap-etat"
  run cmd_imap_sync run
  [ "$status" -eq 0 ]
  [[ "$output" == *"non provisionn"* ]]
}
