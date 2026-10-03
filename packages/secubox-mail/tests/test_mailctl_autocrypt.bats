#!/usr/bin/env bats
# Autocrypt sortant (#1852) : la synchronisation ne pousse que du PUBLIC, valide, et ne recharge rspamd que si la config passe.
load helpers

setup() {
  export CONTAINER="mail" TEMPLATES_DIR="$BATS_TEST_TMPDIR/templates" CALLS="$BATS_TEST_TMPDIR/calls"
  mkdir -p "$TEMPLATES_DIR/rspamd" "$BATS_TEST_TMPDIR/bin"
  echo "-- regle" > "$TEMPLATES_DIR/rspamd/autocrypt.lua"
  : > "$CALLS"
  source_mailctl_functions
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
