#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Un rootfs décalé À MOITIÉ (racine à 100000, mais des milliers d'entrées restées en uid bas) : constaté sur gk3, 12 975 entrées
# (rspamd, redis, apache2, roundcube). Le garde ne regardait que la racine : redis écrivait en « nobody », rspamd et
# mail-autocrypt échouaient. Le décalage se décide désormais sur le NOMBRE d'entrées restantes.
load helpers

setup() {
  load_libs
  export LXC_BASE="$BATS_TEST_TMPDIR/lxc"; mkdir -p "$LXC_BASE/mail/rootfs/etc" "$LXC_BASE/mail/rootfs/usr"
  export STUB_BIN="$BATS_TEST_TMPDIR/bin"; mkdir -p "$STUB_BIN"; export CALLS="$BATS_TEST_TMPDIR/calls"; : > "$CALLS"
  cat > "$STUB_BIN/secubox-lxc-decaler" <<'STUB'
#!/bin/sh
echo "decaler $*" >> "$CALLS"
case "$*" in
  *--etat*) echo "secubox-lxc-decaler: $1 : ${STUB_N:-0} entrée(s) à décaler (+100000)" ;;
esac
STUB
  chmod +x "$STUB_BIN/secubox-lxc-decaler"; export PATH="$STUB_BIN:$PATH"
}

@test "des entrées restantes déclenchent le décalage, même si la racine est déjà décalée" {
  STUB_N=12975 run lxc_decaler mail
  [ "$status" -eq 0 ]
  grep -q "decaler $LXC_BASE/mail/rootfs --etat" "$CALLS"
  grep -qx "decaler $LXC_BASE/mail/rootfs" "$CALLS"
  [[ "$output" == *"12975"* ]]
}

@test "rien à décaler : l'outil n'est appelé qu'en lecture" {
  STUB_N=0 run lxc_decaler mail
  [ "$status" -eq 0 ]
  ! grep -qx "decaler $LXC_BASE/mail/rootfs" "$CALLS"
}

@test "un conteneur sans rootfs est ignoré" {
  run lxc_decaler absent
  [ "$status" -eq 0 ]
  [ ! -s "$CALLS" ]
}

@test "mailctl redis décale aussi les retardataires avant de démarrer redis" {
  corps="$(awk '/^cmd_redis\(\) \{/,/^\}/' "$BATS_TEST_DIRNAME/../sbin/mailctl")"
  [[ "$corps" == *"secubox-lxc-decaler"* ]]
  # le décalage précède le démarrage
  av="${corps%%enable --now redis-server*}"; [[ "$av" == *"secubox-lxc-decaler"* ]]
}
