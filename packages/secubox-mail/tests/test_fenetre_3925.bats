#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# #3925 : sur la box de production le conteneur mail reste arrêté ; une fenêtre planifiée l'éveille autour des
# rapports (05:07, 05:34, lundi 07:20) puis le remet en veille. Rien d'autre que le conteneur éveillé par la fenêtre
# n'est jamais arrêté par elle.
load helpers

ecrire_toml() {  # $1 = actif ; $2.. = lignes supplémentaires de [fenetre]
  local actif="$1"; shift
  { echo "container = \"mail\""; echo "[fenetre]"; echo "actif = $actif"; printf '%s\n' "$@"; } > "$CONFIG_FILE"
}

setup() {
  export CONFIG_FILE="$BATS_TEST_TMPDIR/mail.toml"
  export DATA_PATH="$BATS_TEST_TMPDIR/data"
  ecrire_toml true
  source_mailctl_functions
  export LXC_PATH="$BATS_TEST_TMPDIR/lxc"; mkdir -p "$LXC_PATH/mail/rootfs"
  : > "$LXC_PATH/mail/config"
  export AUDIT="$BATS_TEST_TMPDIR/audit.log" SECUBOX_AUDIT_LOG="$BATS_TEST_TMPDIR/audit.log"
  export FENETRE_LOCK="$BATS_TEST_TMPDIR/f.lock" FENETRE_MARQUEUR="$BATS_TEST_TMPDIR/f.active"
  export FENETRE_MEMINFO="$BATS_TEST_TMPDIR/meminfo" FENETRE_LOADAVG="$BATS_TEST_TMPDIR/loadavg"
  echo "MemAvailable:    2048000 kB" > "$FENETRE_MEMINFO"; echo "0.50 0.40 0.30 1/200 999" > "$FENETRE_LOADAVG"
  export FENETRE_PAS=0.2 FENETRE_DUREE_S=1 FENETRE_PAS_SMTP=0.1 FENETRE_PAS_ATTENTE=0.2 FENETRE_ATTENTE_MAX=0.5
  export FENETRE_PAS_VIDANGE=0.1 FENETRE_VIDANGE_MAX=0.3 FENETRE_SMTP_MAX=0.5
  ETAT="$BATS_TEST_TMPDIR/etat"; CALLS="$BATS_TEST_TMPDIR/calls"; FILE="$BATS_TEST_TMPDIR/file"
  : > "$CALLS"; : > "$FILE"; echo arrete > "$ETAT"
  export ETAT CALLS FILE
  lxc_running() { [[ "$(cat "$ETAT")" == marche ]]; }
  cmd_start() { echo START >> "$CALLS"; echo marche > "$ETAT"; }
  cmd_stop() { echo STOP >> "$CALLS"; echo arrete > "$ETAT"; }
  lxc_attach() { shift; case "$*" in "postqueue -p") cat "$FILE" ;; esac; }
  _fen_smtp_repond() { return 0; }
  logger() { echo "LOGGER $*" >> "$CALLS"; }
  export -f lxc_running cmd_start cmd_stop lxc_attach _fen_smtp_repond logger
}

@test "inactive par défaut : message et sortie 0, rien démarré" {
  ecrire_toml false
  run cmd_fenetre
  [ "$status" -eq 0 ]
  [[ "$output" == *"inactive"* ]]
  ! grep -q START "$CALLS"
  [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "sans section [fenetre] : inerte" {
  echo 'container = "mail"' > "$CONFIG_FILE"
  run cmd_fenetre
  [ "$status" -eq 0 ]
  ! grep -q START "$CALLS"
}

@test "conteneur absent : sortie 0" {
  lxc_exists() { return 1; }; export -f lxc_exists
  run cmd_fenetre
  [ "$status" -eq 0 ]
  [[ "$output" == *"absent"* ]]
  ! grep -q START "$CALLS"
}

@test "conteneur déjà en marche : on n'y touche pas (ni démarrage, ni arrêt, ni marqueur)" {
  echo marche > "$ETAT"
  run cmd_fenetre
  [ "$status" -eq 0 ]
  [[ "$output" == *"pas a nous"* ]]
  [ ! -s "$CALLS" ]
  [ ! -e "$FENETRE_MARQUEUR" ]
  [ "$(cat "$ETAT")" = marche ]
}

@test "lxc.start.auto = 1 : géré ailleurs, on n'y touche pas" {
  echo 'lxc.start.auto = 1' > "$LXC_PATH/mail/config"
  run cmd_fenetre
  [ "$status" -eq 0 ]
  [[ "$output" == *"lxc.start.auto"* ]]
  ! grep -q START "$CALLS"
}

@test "lxc.start.auto = 0 : la fenêtre s'ouvre" {
  echo 'lxc.start.auto = 0' > "$LXC_PATH/mail/config"
  run cmd_fenetre
  [ "$status" -eq 0 ]
  grep -q START "$CALLS"
}

@test "pression mémoire : refus après les essais, mail.warning, sortie 1, rien démarré" {
  echo "MemAvailable:    300000 kB" > "$FENETRE_MEMINFO"
  run cmd_fenetre
  [ "$status" -eq 1 ]
  ! grep -q START "$CALLS"
  grep -q 'LOGGER .*mail.warning.*abandonnee' "$CALLS"
  [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "pression de charge : refus, sortie 1" {
  echo "55.00 40.00 30.00 1/200 999" > "$FENETRE_LOADAVG"
  run cmd_fenetre
  [ "$status" -eq 1 ]
  ! grep -q START "$CALLS"
}

@test "cycle complet : démarrage, tenue, remise en veille, marqueur retiré, audit" {
  run cmd_fenetre --motif "rapports du matin"
  [ "$status" -eq 0 ]
  [ "$(grep -c START "$CALLS")" -eq 1 ]
  [ "$(grep -c STOP "$CALLS")" -eq 1 ]
  [ "$(cat "$ETAT")" = arrete ]
  [ ! -e "$FENETRE_MARQUEUR" ]
  grep -q 'LOGGER .*ouverture de fenetre (rapports du matin)' "$CALLS"
  grep -q '"action":"fenetre_ouverte"' "$AUDIT"
  grep -q '"action":"fenetre_fermee"' "$AUDIT"
}

@test "marqueur : époque de début, motif, fin ; état affiché par status" {
  cmd_stop() { cat "$FENETRE_MARQUEUR" > "$BATS_TEST_TMPDIR/marq"; echo STOP >> "$CALLS"; echo arrete > "$ETAT"; }
  export -f cmd_stop
  run cmd_fenetre --motif "essai"
  [ "$status" -eq 0 ]
  [[ "$(sed -n 1p "$BATS_TEST_TMPDIR/marq")" =~ ^[0-9]+$ ]]
  [ "$(sed -n 2p "$BATS_TEST_TMPDIR/marq")" = essai ]
  [[ "$(sed -n 3p "$BATS_TEST_TMPDIR/marq")" =~ ^[0-9]+$ ]]
  printf '%s\n%s\n%s\n' 1 essai 2000000000 > "$FENETRE_MARQUEUR"
  run cmd_status
  [[ "$output" == *"ouverte"* ]]
  rm -f "$FENETRE_MARQUEUR"
  run cmd_status
  [[ "$output" == *"planifiée"* ]]
  ecrire_toml false
  run cmd_status
  [[ "$output" == *"inactive"* ]]
}

@test "port 25 muet : le conteneur est arrêté, sortie 1" {
  _fen_smtp_repond() { return 1; }; export -f _fen_smtp_repond
  run cmd_fenetre
  [ "$status" -eq 1 ]
  grep -q START "$CALLS"
  grep -q STOP "$CALLS"
  [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "démarrage en échec : remise en veille, sortie 1" {
  cmd_start() { echo START >> "$CALLS"; return 1; }; export -f cmd_start
  run cmd_fenetre
  [ "$status" -eq 1 ]
  grep -q STOP "$CALLS"
  [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "arrêt anticipé : mémoire sous le seuil sur 4 contrôles de suite" {
  export FENETRE_DUREE_S=30
  _fen_mem_mo() { if [[ -e "$FENETRE_MARQUEUR" && "$(cat "$ETAT")" == marche ]]; then echo 100; else echo 2000; fi; }
  export -f _fen_mem_mo
  run cmd_fenetre
  [ "$status" -eq 0 ]
  grep -q 'LOGGER .*mail.warning.*arret anticipe' "$CALLS"
  grep -q STOP "$CALLS"
  grep -q '"action":"fenetre_arret_memoire"' "$AUDIT"
}

@test "mémoire basse non consécutive : pas d'arrêt anticipé" {
  export FENETRE_DUREE_S=2
  n=0; echo 0 > "$BATS_TEST_TMPDIR/n"
  _fen_mem_mo() {
    [[ "$(cat "$ETAT")" == marche ]] || { echo 2000; return; }
    local n; n=$(cat "$BATS_TEST_TMPDIR/n"); echo $((n+1)) > "$BATS_TEST_TMPDIR/n"
    if (( n % 2 )); then echo 100; else echo 2000; fi
  }
  export -f _fen_mem_mo
  run cmd_fenetre
  [ "$status" -eq 0 ]
  ! grep -q 'arret anticipe' "$CALLS"
}

@test "reprise par le propriétaire : marqueur retiré, le conteneur reste en marche" {
  export FENETRE_DUREE_S=30
  _fen_sleep() { rm -f "$FENETRE_MARQUEUR"; }; export -f _fen_sleep
  run cmd_fenetre
  [ "$status" -eq 0 ]
  ! grep -q STOP "$CALLS"
  [ "$(cat "$ETAT")" = marche ]
  grep -q 'LOGGER .*proprietaire reprend' "$CALLS"
}

@test "mailctl start et restart humains retirent le marqueur ; cmd_start lui-même non" {
  grep -qE '^\s+start\)\s+shift; fenetre_cede; cmd_start' "$BATS_TEST_DIRNAME/../sbin/mailctl"
  grep -qE '^\s+restart\)\s+shift; fenetre_cede; cmd_restart' "$BATS_TEST_DIRNAME/../sbin/mailctl"
  echo x > "$FENETRE_MARQUEUR"
  run fenetre_cede
  [ ! -e "$FENETRE_MARQUEUR" ]
  ! sed -n '/^cmd_start() {/,/^}/p' "$BATS_TEST_DIRNAME/../sbin/mailctl" | grep -q 'FENETRE_MARQUEUR\|fenetre_cede'
}

@test "vidange : on attend la file active (bornée), pas le différé" {
  printf -- '-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\nABC123*     1234 Mon Nov 24 05:07:00  a@b\n' > "$FILE"
  export FENETRE_VIDANGE_MAX=0.4
  run cmd_fenetre
  [ "$status" -eq 0 ]
  grep -q 'LOGGER .*file Postfix encore active (1)' "$CALLS"
  grep -q STOP "$CALLS"
  printf -- 'DEF456     1234 Mon Nov 24 05:07:00  a@b\n' > "$FILE"
  : > "$CALLS"
  run cmd_fenetre
  ! grep -q 'encore active' "$CALLS"
}

@test "TERM : le conteneur est remis en veille et le marqueur retiré" {
  export FENETRE_DUREE_S=60 FENETRE_PAS=5
  ( cmd_fenetre ) &
  pid=$!
  for _ in $(seq 1 50); do [ -e "$FENETRE_MARQUEUR" ] && grep -q START "$CALLS" && break; sleep 0.1; done
  [ -e "$FENETRE_MARQUEUR" ]
  kill -TERM "$pid"
  wait "$pid" || true
  grep -q STOP "$CALLS"
  [ "$(cat "$ETAT")" = arrete ]
  [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "verrou : une seconde instance ne fait rien" {
  ( exec 8>"$FENETRE_LOCK"; flock 8; sleep 3 ) &
  tenu=$!
  sleep 0.3
  run cmd_fenetre
  kill "$tenu" 2>/dev/null || true; wait "$tenu" 2>/dev/null || true
  [ "$status" -eq 0 ]
  [[ "$output" == *"deja en cours"* ]]
  [ ! -s "$CALLS" ]
}

@test "bornes : durée hors limites ramenée à 10..240, valeur absurde au défaut" {
  [ "$(_fen_entier 5 90 10 240)" = 10 ]
  [ "$(_fen_entier 999 90 10 240)" = 240 ]
  [ "$(_fen_entier abc 90 10 240)" = 90 ]
  [ "$(_fen_entier 60 90 10 240)" = 60 ]
}

@test "unités et minuterie livrées, calendrier attendu" {
  d="$BATS_TEST_DIRNAME/../debian"
  grep -qx 'OnCalendar=\*-\*-\* 04:50' "$d/secubox-mail-fenetre.timer"
  grep -qx 'OnCalendar=Mon \*-\*-\* 07:05' "$d/secubox-mail-fenetre.timer"
  grep -qx 'OnCalendar=\*-\*-\* 18:00' "$d/secubox-mail-fenetre.timer"
  grep -qx 'Persistent=false' "$d/secubox-mail-fenetre.timer"
  for k in Type=exec Restart=no KillMode=mixed TimeoutStopSec=3min UMask=0027 PrivateTmp=true; do
    grep -qx "$k" "$d/secubox-mail-fenetre.service"
  done
  grep -q 'ExecStart=/usr/sbin/mailctl fenetre' "$d/secubox-mail-fenetre.service"
  grep -q 'secubox-mail-fenetre.timer' "$d/rules"
  grep -q 'secubox-mail-fenetre.service' "$d/rules"
  grep -q 'enable --now secubox-mail-fenetre.timer' "$d/postinst"
  grep -q 'disable --now secubox-mail-fenetre.timer' "$d/prerm"
  grep -q 'stop secubox-mail-fenetre.service' "$d/prerm"
  grep -q '^    fenetre)' "$BATS_TEST_DIRNAME/../sbin/mailctl"
}

@test "mail.toml livré : [fenetre] actif = false ; le merge l'ajoute sans réécrire l'existant" {
  grep -q '^\[fenetre\]' "$BATS_TEST_DIRNAME/../config/mail.toml"
  [ "$(awk '/^\[fenetre\]/{f=1;next} /^\[/{f=0} f&&/^actif/{print $3}' "$BATS_TEST_DIRNAME/../config/mail.toml")" = false ]
  source "${BATS_TEST_DIRNAME}/../lib/mail/toml.sh"
  printf 'domain = "gk2.secubox.in"\n[fenetre]\nactif = true\nduree_min = 120\n' > "$BATS_TEST_TMPDIR/m.toml"
  merge_mail_toml "$BATS_TEST_TMPDIR/m.toml"
  grep -q '^actif = true' "$BATS_TEST_TMPDIR/m.toml"
  [ "$(grep -c '^\[fenetre\]' "$BATS_TEST_TMPDIR/m.toml")" -eq 1 ]
  printf 'domain = "x"\n' > "$BATS_TEST_TMPDIR/n.toml"
  merge_mail_toml "$BATS_TEST_TMPDIR/n.toml"
  [ "$(awk '/^\[fenetre\]/{f=1;next} /^\[/{f=0} f&&/^actif/{print $3}' "$BATS_TEST_TMPDIR/n.toml")" = false ]
}

@test "aucun secret affiché ni journalisé" {
  run cmd_fenetre
  ! echo "$output" | grep -qiE 'passw|secret|token'
  ! grep -qiE 'passw|secret|token' "$CALLS" "$AUDIT"
}
