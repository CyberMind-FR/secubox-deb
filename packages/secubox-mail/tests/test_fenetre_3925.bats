#!/usr/bin/env bats
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# #3925 : sur la box de production le conteneur mail reste arrêté ; une fenêtre planifiée l'éveille autour des
# rapports (05:07, 05:34, lundi 07:20) puis le remet en veille. RÈGLE : jamais d'arrêt d'une instance qui n'est pas la
# nôtre (démarrée à la main, par un autre outil, ou au boot). Le conteneur est simulé par des fichiers d'état.
load helpers

ecrire_toml() {  # $1 = actif ; $2.. = lignes supplémentaires de [fenetre]
  local actif="$1"; shift
  { echo "container = \"mail\""; echo "[fenetre]"; echo "actif = $actif"; printf '%s\n' "$@"; } > "$CONFIG_FILE"
}
nb() { grep -c "^$1\$" "$CALLS" || true; }

setup() {
  export CONFIG_FILE="$BATS_TEST_TMPDIR/mail.toml"
  export DATA_PATH="$BATS_TEST_TMPDIR/data"
  ecrire_toml true
  source_mailctl_functions
  export LXC_PATH="$BATS_TEST_TMPDIR/lxc"; mkdir -p "$LXC_PATH/mail/rootfs"
  : > "$LXC_PATH/mail/config"
  export AUDIT="$BATS_TEST_TMPDIR/audit.log" SECUBOX_AUDIT_LOG="$BATS_TEST_TMPDIR/audit.log"
  export FENETRE_CEDE="$BATS_TEST_TMPDIR/f.cede" FENETRE_LOCK="$BATS_TEST_TMPDIR/f.lock" FENETRE_MARQUEUR="$BATS_TEST_TMPDIR/f.active"
  export FENETRE_MEMINFO="$BATS_TEST_TMPDIR/meminfo" FENETRE_LOADAVG="$BATS_TEST_TMPDIR/loadavg"
  echo "MemAvailable:    2048000 kB" > "$FENETRE_MEMINFO"; echo "0.50 0.40 0.30 1/200 999" > "$FENETRE_LOADAVG"
  export FENETRE_PAS=0.2 FENETRE_DUREE_S=1 FENETRE_PAS_SMTP=0.1 FENETRE_PAS_ATTENTE=0.2 FENETRE_ATTENTE_MAX=0.5
  export FENETRE_PAS_VIDANGE=0.1 FENETRE_VIDANGE_MAX=0.3 FENETRE_SMTP_MAX=0.5 FENETRE_PAS_IDENT=0.05
  ETAT="$BATS_TEST_TMPDIR/etat"; IDENT="$BATS_TEST_TMPDIR/ident"; CALLS="$BATS_TEST_TMPDIR/calls"
  FILE="$BATS_TEST_TMPDIR/file"; NEC="$BATS_TEST_TMPDIR/nec"; NARRETS="$BATS_TEST_TMPDIR/narrets"; NS="$BATS_TEST_TMPDIR/ns"
  : > "$CALLS"; : > "$FILE"; : > "$IDENT"; echo STOPPED > "$ETAT"; echo 1 > "$NEC"; echo 0 > "$NARRETS"; echo 0 > "$NS"
  export ETAT IDENT CALLS FILE NEC NARRETS NS
  lxc_running() { [[ "$(cat "$ETAT")" == RUNNING ]]; }
  _fen_etat() { cat "$ETAT"; }
  _fen_identite() { local i; i="$(cat "$IDENT")"; [[ -n "$i" ]] && echo "$i"; }
  _fen_ticks() { echo 1000; }
  _fen_lxc_start() { [[ "$(cat "$ETAT")" == RUNNING ]] && return 1; echo START >> "$CALLS"; echo RUNNING > "$ETAT"; echo "100:5000" > "$IDENT"; }
  _sim_arret() {   # l'arrêt n'aboutit qu'au NEC-ième geste (1 = propre, 2 = deuxième essai, 3 = lxc-stop -k, 99 = jamais)
    echo "$1" >> "$CALLS"
    local n; n=$(( $(cat "$NARRETS") + 1 )); echo "$n" > "$NARRETS"
    if (( n >= $(cat "$NEC") )); then echo STOPPED > "$ETAT"; : > "$IDENT"; fi
  }
  _fen_lxc_stop() { _sim_arret STOP; }
  _fen_lxc_kill() { _sim_arret KILL; }
  _fen_attach() { case "$*" in "postqueue -p") cat "$FILE" ;; esac; }
  _fen_smtp_repond() { return 0; }
  logger() { echo "LOGGER $*" >> "$CALLS"; }
  export -f lxc_running _fen_etat _fen_identite _fen_ticks _fen_lxc_start _sim_arret _fen_lxc_stop _fen_lxc_kill _fen_attach _fen_smtp_repond logger
}

# ---------------------------------------------------------------- inertie et refus

@test "inactive par défaut : message et sortie 0, rien démarré" {
  ecrire_toml false
  run cmd_fenetre
  [ "$status" -eq 0 ]; [[ "$output" == *"inactive"* ]]
  [ "$(nb START)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "sans section [fenetre] : inerte" {
  echo 'container = "mail"' > "$CONFIG_FILE"
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb START)" -eq 0 ]
}

@test "conteneur absent : sortie 0" {
  lxc_exists() { return 1; }; export -f lxc_exists
  run cmd_fenetre
  [ "$status" -eq 0 ]; [[ "$output" == *"absent"* ]]; [ "$(nb START)" -eq 0 ]
}

@test "conteneur déjà en marche : on n'y touche pas (ni démarrage, ni arrêt, ni marqueur)" {
  echo RUNNING > "$ETAT"; echo 77:123 > "$IDENT"
  run cmd_fenetre
  [ "$status" -eq 0 ]; [[ "$output" == *"pas a nous"* ]]
  [ "$(nb START)" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
  [ "$(cat "$ETAT")" = RUNNING ]
}

@test "lxc.start.auto = 1 : géré ailleurs, on n'y touche pas" {
  echo 'lxc.start.auto = 1' > "$LXC_PATH/mail/config"
  run cmd_fenetre
  [ "$status" -eq 0 ]; [[ "$output" == *"lxc.start.auto"* ]]; [ "$(nb START)" -eq 0 ]
}

@test "lxc.start.auto = 0 : la fenêtre s'ouvre" {
  echo 'lxc.start.auto = 0' > "$LXC_PATH/mail/config"
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb START)" -eq 1 ]
}

@test "lxc-info en échec : abandon sans démarrer (jamais pris pour STOPPED)" {
  _fen_etat() { echo ERREUR; }; export -f _fen_etat
  run cmd_fenetre
  [ "$status" -eq 1 ]; [ "$(nb START)" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]
}

@test "état en transition (STARTING) : rien, sans erreur" {
  echo STARTING > "$ETAT"
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb START)" -eq 0 ]
}

@test "_fen_etat : état EXACT, STOPPED sans rien d'autre, échec = ERREUR" {
  source_mailctl_functions; unset -f lxc_running
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  printf '#!/bin/sh\ncat "%s"\n' "$BATS_TEST_TMPDIR/sortie" > "$BATS_TEST_TMPDIR/bin/lxc-info"
  chmod +x "$BATS_TEST_TMPDIR/bin/lxc-info"
  PATH="$BATS_TEST_TMPDIR/bin:$PATH"
  echo STOPPED > "$BATS_TEST_TMPDIR/sortie"; [ "$(_fen_etat)" = STOPPED ]
  echo RUNNING > "$BATS_TEST_TMPDIR/sortie"; [ "$(_fen_etat)" = RUNNING ]
  : > "$BATS_TEST_TMPDIR/sortie"; [ "$(_fen_etat)" = ERREUR ]
  printf '#!/bin/sh\nexit 1\n' > "$BATS_TEST_TMPDIR/bin/lxc-info"
  [ "$(_fen_etat)" = ERREUR ]
}

@test "pression mémoire (< 1400 Mo) : refus après les essais, mail.warning, sortie 1" {
  echo "MemAvailable:    800000 kB" > "$FENETRE_MEMINFO"
  run cmd_fenetre
  [ "$status" -eq 1 ]; [ "$(nb START)" -eq 0 ]
  grep -q 'LOGGER .*mail.warning.*abandonnee' "$CALLS"; [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "pression de charge (> 25) : refus, sortie 1" {
  echo "30.00 40.00 30.00 1/200 999" > "$FENETRE_LOADAVG"
  run cmd_fenetre
  [ "$status" -eq 1 ]; [ "$(nb START)" -eq 0 ]
}

@test "mesure illisible = refus" {
  : > "$FENETRE_MEMINFO"
  run cmd_fenetre
  [ "$status" -eq 1 ]; [ "$(nb START)" -eq 0 ]
  echo "MemAvailable:    2048000 kB" > "$FENETRE_MEMINFO"; : > "$FENETRE_LOADAVG"
  run cmd_fenetre
  [ "$status" -eq 1 ]; [ "$(nb START)" -eq 0 ]
}

@test "démarrage humain pendant l'attente de pression : on n'y touche pas, pas de marqueur, pas d'arrêt" {
  echo "MemAvailable:    800000 kB" > "$FENETRE_MEMINFO"
  export FENETRE_ATTENTE_MAX=5
  _fen_sleep() { echo "MemAvailable:    2048000 kB" > "$FENETRE_MEMINFO"; echo RUNNING > "$ETAT"; echo 55:99 > "$IDENT"; }
  export -f _fen_sleep
  run cmd_fenetre
  [ "$status" -eq 0 ]
  [ "$(nb START)" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
  [ "$(cat "$ETAT")" = RUNNING ]
}

# ---------------------------------------------------------------- cycle nominal

@test "cycle complet : démarrage, tenue, remise en veille vérifiée, marqueur retiré, audit" {
  run cmd_fenetre --motif "rapports du matin"
  [ "$status" -eq 0 ]
  [ "$(nb START)" -eq 1 ]; [ "$(nb STOP)" -eq 1 ]
  [ "$(cat "$ETAT")" = STOPPED ]; [ ! -e "$FENETRE_MARQUEUR" ]
  grep -q 'LOGGER .*ouverture de fenetre (rapports du matin)' "$CALLS"
  grep -q '"action":"fenetre_ouverte"' "$AUDIT"; grep -q '"action":"fenetre_fermee"' "$AUDIT"
}

@test "marqueur : début, motif, fin, ticks, phase, identité ; status l'affiche" {
  _fen_lxc_stop() { cp "$FENETRE_MARQUEUR" "$BATS_TEST_TMPDIR/marq"; _sim_arret STOP; }
  export -f _fen_lxc_stop
  run cmd_fenetre --motif "essai"
  [ "$status" -eq 0 ]
  grep -qE '^debut=[0-9]+$' "$BATS_TEST_TMPDIR/marq"; grep -q '^motif=essai$' "$BATS_TEST_TMPDIR/marq"
  grep -qE '^fin=[0-9]+$' "$BATS_TEST_TMPDIR/marq"; grep -q '^ticks=1000$' "$BATS_TEST_TMPDIR/marq"
  grep -q '^phase=fermeture$' "$BATS_TEST_TMPDIR/marq"; grep -q '^identite=100:5000$' "$BATS_TEST_TMPDIR/marq"
  printf 'debut=1\nmotif=essai\nfin=2000000000\nticks=1\nphase=ouverte\nidentite=1:1\n' > "$FENETRE_MARQUEUR"
  run cmd_status
  [[ "$output" == *"ouverte"* ]]
  rm -f "$FENETRE_MARQUEUR"
  run cmd_status; [[ "$output" == *"planifiée"* ]]
  ecrire_toml false
  run cmd_status; [[ "$output" == *"inactive"* ]]
}

@test "port 25 muet : le conteneur (le nôtre) est arrêté, sortie 1" {
  _fen_smtp_repond() { return 1; }; export -f _fen_smtp_repond
  run cmd_fenetre
  [ "$status" -eq 1 ]; [ "$(nb START)" -eq 1 ]; [ "$(nb STOP)" -eq 1 ]; [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "démarrage en échec : fermeture sans toucher à un conteneur qui n'est pas le nôtre, sortie 1" {
  _fen_lxc_start() { echo START >> "$CALLS"; return 1; }; export -f _fen_lxc_start
  run cmd_fenetre
  [ "$status" -eq 1 ]; [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
}

# ---------------------------------------------------------------- garde mémoire (toutes phases)

@test "mémoire sous le seuil critique (120 Mo) : arrêt immédiat, vidange sautée" {
  export FENETRE_DUREE_S=30
  printf -- 'ABC123*  1  Mon Nov 24  a@b\n' > "$FILE"
  _fen_mem_mo() { if [[ "$(cat "$ETAT")" == RUNNING ]]; then echo 100; else echo 2000; fi; }
  export -f _fen_mem_mo
  run cmd_fenetre
  [ "$status" -eq 0 ]
  grep -q 'LOGGER .*mail.warning.*seuil critique' "$CALLS"
  [ "$(nb STOP)" -eq 1 ]; ! grep -q 'file Postfix' "$CALLS"
  grep -q '"action":"fenetre_arret_memoire"' "$AUDIT"
}

@test "mémoire sous 350 Mo sur 4 contrôles de suite : arrêt anticipé, sans vidange" {
  export FENETRE_DUREE_S=30
  printf -- 'ABC123*  1  Mon Nov 24  a@b\n' > "$FILE"
  _fen_mem_mo() { if [[ "$(cat "$ETAT")" == RUNNING ]]; then echo 300; else echo 2000; fi; }
  export -f _fen_mem_mo
  run cmd_fenetre
  [ "$status" -eq 0 ]
  grep -q 'LOGGER .*mail.warning.*arret anticipe' "$CALLS"; [ "$(nb STOP)" -eq 1 ]; ! grep -q 'file Postfix' "$CALLS"
}

@test "la garde mémoire agit aussi pendant l'attente du port 25" {
  export FENETRE_DUREE_S=30 FENETRE_SMTP_MAX=60
  _fen_smtp_repond() { return 1; }
  _fen_mem_mo() { if [[ "$(cat "$ETAT")" == RUNNING ]]; then echo 100; else echo 2000; fi; }
  export -f _fen_smtp_repond _fen_mem_mo
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 1 ]
  grep -q 'seuil critique' "$CALLS"
}

@test "mémoire basse non consécutive : pas d'arrêt anticipé" {
  export FENETRE_DUREE_S=2
  echo 0 > "$BATS_TEST_TMPDIR/n"
  _fen_mem_mo() {
    [[ "$(cat "$ETAT")" == RUNNING ]] || { echo 2000; return; }
    local n; n=$(cat "$BATS_TEST_TMPDIR/n"); echo $((n+1)) > "$BATS_TEST_TMPDIR/n"
    if (( n % 2 )); then echo 300; else echo 2000; fi
  }
  export -f _fen_mem_mo
  run cmd_fenetre
  [ "$status" -eq 0 ]; ! grep -q 'arret anticipe' "$CALLS"
}

@test "mesure mémoire illisible en cours de fenêtre : compte comme basse (4 de suite = arrêt)" {
  export FENETRE_DUREE_S=30
  _fen_mem_mo() { if [[ "$(cat "$ETAT")" == RUNNING ]]; then echo ""; else echo 2000; fi; }
  export -f _fen_mem_mo
  run cmd_fenetre
  [ "$status" -eq 0 ]; grep -q 'illisible' "$CALLS"; [ "$(nb STOP)" -eq 1 ]
}

# ---------------------------------------------------------------- propriété : jamais arrêter ce qui n'est pas à nous

@test "reprise par le propriétaire : marqueur retiré, le conteneur reste en marche" {
  export FENETRE_DUREE_S=30
  _fen_sleep() { rm -f "$FENETRE_MARQUEUR"; }; export -f _fen_sleep
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ "$(cat "$ETAT")" = RUNNING ]
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

@test "arrêt puis redémarrage par un autre outil pendant la fenêtre : autre instance, on n'arrête rien" {
  export FENETRE_DUREE_S=30
  echo 0 > "$NS"
  _fen_sleep() { local n; n=$(( $(cat "$NS") + 1 )); echo "$n" > "$NS"; (( n == 2 )) && echo "200:9000" > "$IDENT"; command sleep 0.02; }
  export -f _fen_sleep
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ "$(cat "$ETAT")" = RUNNING ]; [ ! -e "$FENETRE_MARQUEUR" ]
  grep -q 'autre instance' "$CALLS"
}

@test "arrêt par un autre outil : perte de propriété après DEUX STOPPED consécutifs, aucun arrêt" {
  export FENETRE_DUREE_S=30
  echo 0 > "$NS"
  _fen_sleep() { local n; n=$(( $(cat "$NS") + 1 )); echo "$n" > "$NS"; (( n == 1 )) && { echo STOPPED > "$ETAT"; : > "$IDENT"; }; command sleep 0.02; }
  export -f _fen_sleep
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
  grep -q 'arrete par un autre outil' "$CALLS"
}

@test "un seul STOPPED puis RUNNING (même instance) : la fenêtre continue et ferme normalement" {
  export FENETRE_DUREE_S=2
  echo 0 > "$NS"
  _fen_sleep() {
    local n; n=$(( $(cat "$NS") + 1 )); echo "$n" > "$NS"
    case "$n" in 1) echo STOPPED > "$ETAT" ;; 2) echo RUNNING > "$ETAT" ;; esac
    command sleep 0.05
  }
  export -f _fen_sleep
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 1 ]; ! grep -q 'arrete par un autre' "$CALLS"
}

@test "lxc-info en échec pendant la fenêtre : on ne cède jamais" {
  export FENETRE_DUREE_S=1
  _fen_etat() { if [[ -e "$FENETRE_MARQUEUR" ]] && grep -q '^phase=ouverte' "$FENETRE_MARQUEUR"; then echo ERREUR; else cat "$ETAT"; fi; }
  export -f _fen_etat
  run cmd_fenetre
  [ "$status" -eq 1 ] || [ "$status" -eq 0 ]
  ! grep -q 'arrete par un autre' "$CALLS"; ! grep -q 'laisse tel quel' "$CALLS"
  # fermeture : état indéterminable, marqueur conservé, rien d'arrêté
  [ -e "$FENETRE_MARQUEUR" ]; [ "$(nb STOP)" -eq 0 ]
}

@test "lxc.start.auto passé à 1 pendant la fenêtre : on cède, on n'arrête pas" {
  export FENETRE_DUREE_S=30
  _fen_sleep() { echo 'lxc.start.auto = 1' > "$LXC_PATH/mail/config"; }; export -f _fen_sleep
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "conteneur démarré par un autre juste avant nous (instant de démarrage antérieur) : jamais arrêté" {
  _fen_ticks() { echo 9000; }; export -f _fen_ticks   # notre appel est « daté » après le démarrage de l'instance (5000)
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ "$(cat "$ETAT")" = RUNNING ]; [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "reprise humaine pendant l'ouverture (marqueur retiré pendant le démarrage) : jamais recréé, jamais arrêté" {
  _fen_lxc_start() { echo START >> "$CALLS"; echo RUNNING > "$ETAT"; echo 100:5000 > "$IDENT"; rm -f "$FENETRE_MARQUEUR"; }
  export -f _fen_lxc_start
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]; [ "$(cat "$ETAT")" = RUNNING ]
  grep -q 'proprietaire reprend la main' "$CALLS"
}

@test "marqueur retiré juste avant le démarrage : on ne démarre pas" {
  _fen_etat() { rm -f "$FENETRE_MARQUEUR"; cat "$ETAT"; }; export -f _fen_etat
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb START)" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]
}

@test "démarré par un tiers avant notre lxc-start (déjà en marche) : on cède, on n'arrête rien" {
  _fen_lxc_start() { echo 55:1 > "$IDENT"; echo RUNNING > "$ETAT"; return 1; }; export -f _fen_lxc_start
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]; [ "$(cat "$ETAT")" = RUNNING ]
  grep -q 'deja en marche (demarre par un autre)' "$CALLS"
}

@test "identité illisible à la fermeture : marqueur conservé, mail.warning, sortie 1, rien d'arrêté" {
  echo RUNNING > "$ETAT"; : > "$IDENT"
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverte\nidentite=100:5000\n' > "$FENETRE_MARQUEUR"
  run cmd_fenetre_fermer
  [ "$status" -eq 1 ]; [ "$(nb STOP)" -eq 0 ]; [ -e "$FENETRE_MARQUEUR" ]
  grep -q 'LOGGER .*mail.warning.*illisible' "$CALLS"
  echo 100:5000 > "$IDENT"
  run cmd_fenetre_fermer
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 1 ]; [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "marqueur retiré juste avant l'arrêt : le conteneur est laissé en marche" {
  echo RUNNING > "$ETAT"; echo 100:5000 > "$IDENT"
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverte\nidentite=100:5000\n' > "$FENETRE_MARQUEUR"
  _fen_identite() { cat "$IDENT"; rm -f "$FENETRE_MARQUEUR"; }; export -f _fen_identite
  run cmd_fenetre_fermer
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ "$(cat "$ETAT")" = RUNNING ]
}

@test "après adoption d'un marqueur périmé, les signaux ne restent pas ignorés" {
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverte\nidentite=100:5000\n' > "$FENETRE_MARQUEUR"
  echo RUNNING > "$ETAT"; echo 100:5000 > "$IDENT"
  echo "MemAvailable:    800000 kB" > "$FENETRE_MEMINFO"
  t() { cmd_fenetre; local rc=$?; echo "TRAPS:[$(trap -p TERM INT HUP)]"; return $rc; }
  run t
  [[ "$output" == *"TRAPS:[]"* ]]
}

@test "phase « ouverture » jusqu'à la réponse du port 25 (la veille reste muette), puis « ouverte »" {
  _fen_smtp_repond() { grep -q '^phase=ouverture$' "$FENETRE_MARQUEUR" && echo ok >> "$BATS_TEST_TMPDIR/ph"; return 0; }
  _fen_lxc_stop() { grep '^phase=' "$FENETRE_MARQUEUR" >> "$BATS_TEST_TMPDIR/ph"; _sim_arret STOP; }
  export -f _fen_smtp_repond _fen_lxc_stop
  run cmd_fenetre
  [ "$status" -eq 0 ]
  grep -q '^ok$' "$BATS_TEST_TMPDIR/ph"
}

@test "conteneur mort pendant l'attente du port 25 : échec (mail.err, sortie 1), rien d'arrêté" {
  export FENETRE_SMTP_MAX=60
  _fen_smtp_repond() { return 1; }
  _fen_sleep() { echo STOPPED > "$ETAT"; : > "$IDENT"; command sleep 0.02; }
  export -f _fen_smtp_repond _fen_sleep
  run cmd_fenetre
  [ "$status" -eq 1 ]; [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
  grep -q 'LOGGER .*mail.err.*attente du port 25' "$CALLS"
}

@test "cession : mailctl start humain journalise mail.warning et laisse une trace ; la fenêtre suivante la signale" {
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverte\nidentite=100:5000\n' > "$FENETRE_MARQUEUR"
  run fenetre_cede
  [ ! -e "$FENETRE_MARQUEUR" ]; [ -s "$FENETRE_CEDE" ]
  grep -q 'LOGGER .*mail.warning.*propriete cedee.*restera en marche' "$CALLS"
  echo RUNNING > "$ETAT"; echo 77:1 > "$IDENT"
  run cmd_fenetre
  grep -q 'LOGGER .*mail.warning.*laisse en marche depuis la cession' "$CALLS"
  echo STOPPED > "$ETAT"
  run cmd_fenetre
  [ ! -e "$FENETRE_CEDE" ]
}

# ---------------------------------------------------------------- arrêt vérifié, fermeture, marqueur périmé

@test "arrêt : deuxième essai si le premier n'aboutit pas" {
  echo 2 > "$NEC"
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 2 ]; [ "$(nb KILL)" -eq 0 ]; [ "$(cat "$ETAT")" = STOPPED ]
}

@test "arrêt : lxc-stop -k en dernier recours" {
  echo 3 > "$NEC"
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb KILL)" -eq 1 ]; [ "$(cat "$ETAT")" = STOPPED ]
}

@test "arrêt impossible : marqueur conservé, mail.err, sortie 1, pas d'audit « fermee »" {
  echo 99 > "$NEC"
  run cmd_fenetre
  [ "$status" -eq 1 ]; [ -e "$FENETRE_MARQUEUR" ]
  grep -q 'LOGGER .*mail.err.*toujours en marche' "$CALLS"
  ! grep -q 'fenetre_fermee' "$AUDIT"
}

@test "marqueur périmé (instance reconnue) : adopté et fermé avant la fenêtre suivante" {
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverte\nidentite=100:5000\n' > "$FENETRE_MARQUEUR"
  echo RUNNING > "$ETAT"; echo 100:5000 > "$IDENT"
  run cmd_fenetre
  [ "$status" -eq 0 ]
  [ "$(nb STOP)" -ge 1 ]; [ "$(nb START)" -eq 1 ]; [ ! -e "$FENETRE_MARQUEUR" ]
  grep -q 'fenetre precedente' "$CALLS"
}

@test "marqueur périmé d'une autre instance : retiré, conteneur intact" {
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverte\nidentite=100:5000\n' > "$FENETRE_MARQUEUR"
  echo RUNNING > "$ETAT"; echo 300:7777 > "$IDENT"
  run cmd_fenetre
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]; [ "$(nb START)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
  [ "$(cat "$ETAT")" = RUNNING ]
}

@test "fenetre-fermer : sans marqueur ne fait rien ; avec marqueur et identité égale arrête ; idempotent" {
  echo RUNNING > "$ETAT"; echo 100:5000 > "$IDENT"
  run cmd_fenetre_fermer
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 0 ]
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverte\nidentite=100:5000\n' > "$FENETRE_MARQUEUR"
  run cmd_fenetre_fermer
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 1 ]; [ ! -e "$FENETRE_MARQUEUR" ]
  run cmd_fenetre_fermer
  [ "$status" -eq 0 ]; [ "$(nb STOP)" -eq 1 ]
}

@test "fenetre-fermer : identité différente ou lxc.start.auto = 1 : rien n'est arrêté" {
  echo RUNNING > "$ETAT"; echo 999:1 > "$IDENT"
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverte\nidentite=100:5000\n' > "$FENETRE_MARQUEUR"
  run cmd_fenetre_fermer
  [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
  echo 100:5000 > "$IDENT"; echo 'lxc.start.auto = 1' > "$LXC_PATH/mail/config"
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverte\nidentite=100:5000\n' > "$FENETRE_MARQUEUR"
  run cmd_fenetre_fermer
  [ "$(nb STOP)" -eq 0 ]; [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "fenetre-fermer : sans identité au marqueur, seule une instance démarrée après l'ouverture est arrêtée" {
  echo RUNNING > "$ETAT"; echo 100:500 > "$IDENT"    # instant 500 < ticks 1000 : antérieure
  printf 'debut=1\nmotif=x\nfin=2\nticks=1000\nphase=ouverture\nidentite=\n' > "$FENETRE_MARQUEUR"
  run cmd_fenetre_fermer
  [ "$(nb STOP)" -eq 0 ]
  echo 100:2000 > "$IDENT"
  printf 'debut=1\nmotif=x\nfin=2\nticks=1000\nphase=ouverture\nidentite=\n' > "$FENETRE_MARQUEUR"
  run cmd_fenetre_fermer
  [ "$(nb STOP)" -eq 1 ]
}

@test "veille : suspendue pendant l'ouverture ou la fermeture, active ensuite" {
  lxc_attach() { echo "ATTACH $*" >> "$CALLS"; return 0; }; export -f lxc_attach
  echo RUNNING > "$ETAT"
  printf 'debut=1\nmotif=x\nfin=2\nticks=1\nphase=ouverture\nidentite=\n' > "$FENETRE_MARQUEUR"
  run cmd_veille
  [ "$status" -eq 0 ]; [[ "$output" == *"veille suspendue"* ]]; ! grep -q ATTACH "$CALLS"
  sed -i 's/^phase=.*/phase=ouverte/' "$FENETRE_MARQUEUR"
  run cmd_veille
  grep -q ATTACH "$CALLS"
}

# ---------------------------------------------------------------- vidange, signaux, verrou

@test "vidange : on attend la file active (bornée), pas le différé" {
  printf -- '-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------\nABC123*     1234 Mon Nov 24 05:07:00  a@b\n' > "$FILE"
  export FENETRE_VIDANGE_MAX=0.4
  run cmd_fenetre
  [ "$status" -eq 0 ]
  grep -q 'LOGGER .*file Postfix encore active (1)' "$CALLS"; [ "$(nb STOP)" -eq 1 ]
  printf -- 'DEF456     1234 Mon Nov 24 05:07:00  a@b\n' > "$FILE"
  : > "$CALLS"
  run cmd_fenetre
  ! grep -q 'encore active' "$CALLS"
}

@test "TERM : le conteneur est remis en veille et le marqueur retiré" {
  export FENETRE_DUREE_S=60 FENETRE_PAS=5
  ( cmd_fenetre ) &
  pid=$!
  for _ in $(seq 1 50); do [ -e "$FENETRE_MARQUEUR" ] && grep -q '^phase=ouverte' "$FENETRE_MARQUEUR" && break; sleep 0.1; done
  grep -q '^phase=ouverte' "$FENETRE_MARQUEUR"
  kill -TERM "$pid"
  wait "$pid" || true
  [ "$(nb STOP)" -eq 1 ]; [ "$(cat "$ETAT")" = STOPPED ]; [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "HUP est traité comme TERM" {
  export FENETRE_DUREE_S=60 FENETRE_PAS=5
  ( cmd_fenetre ) &
  pid=$!
  for _ in $(seq 1 50); do [ -e "$FENETRE_MARQUEUR" ] && grep -q '^phase=ouverte' "$FENETRE_MARQUEUR" && break; sleep 0.1; done
  kill -HUP "$pid"
  wait "$pid" || true
  [ "$(nb STOP)" -eq 1 ]; [ ! -e "$FENETRE_MARQUEUR" ]
}

@test "verrou : une seconde instance ne fait rien" {
  ( exec 8>"$FENETRE_LOCK"; flock 8; sleep 3 ) &
  tenu=$!
  sleep 0.3
  run cmd_fenetre
  kill "$tenu" 2>/dev/null || true; wait "$tenu" 2>/dev/null || true
  [ "$status" -eq 0 ]; [[ "$output" == *"deja en cours"* ]]; [ ! -s "$CALLS" ]
}

@test "descripteur du verrou fermé pour les fils (9>&-), bornes de temps sur lxc" {
  m="$BATS_TEST_DIRNAME/../sbin/mailctl"
  grep -q 'timeout 90 lxc-start .*9>&-' "$m"
  grep -q 'sleep "\$1" 9>&- &' "$m"
  grep -q 'timeout 20 lxc-attach .*9>&-' "$m"
  grep -q 'timeout "\$2" lxc-stop .*9>&-' "$m"
  grep -q 'timeout 20 lxc-info .*9>&-' "$m"
  grep -q "trap '' TERM INT HUP" "$m"
}

# ---------------------------------------------------------------- entrées bornées

@test "entiers : décimaux (pas d'octal), 9 chiffres au plus, bornés" {
  [ "$(_fen_entier 5 90 10 240)" = 10 ]
  [ "$(_fen_entier 999 90 10 240)" = 240 ]
  [ "$(_fen_entier abc 90 10 240)" = 90 ]
  [ "$(_fen_entier 08 90 1 240)" = 8 ]
  [ "$(_fen_entier 09 90 1 240)" = 9 ]
  [ "$(_fen_entier 1234567890 90 10 240)" = 90 ]
  [ "$(_fen_entier -5 90 10 240)" = 90 ]
}

@test "--motif : imprimable sans antislash, 80 caractères, affiché tel quel" {
  run cmd_fenetre --motif $'rapport\\n%s\x01\ndu matin'
  [ "$status" -eq 0 ]
  m="$(grep -o 'ouverture de fenetre ([^)]*)' "$CALLS")"
  [[ "$m" == *'rapportns%sdu matin'* ]] || [[ "$m" == *'rapportn%sdu matin'* ]] || [[ "$m" == *'rapport'* ]]
  ! grep -q '\\' <<< "$m"
  run cmd_fenetre --motif "$(printf 'x%.0s' $(seq 1 200))"
  [ "$status" -eq 0 ]
  [ "$(grep -o 'ouverture de fenetre (x*)' "$CALLS" | tail -1 | tr -cd 'x' | wc -c)" -eq 80 ]
}

# ---------------------------------------------------------------- livraison

@test "unité : socle des unités qui démarrent un LXC, sans ProtectKernelLogs/RestrictRealtime/SystemCallArchitectures" {
  u="$BATS_TEST_DIRNAME/../debian/secubox-mail-fenetre.service"
  for k in Type=exec Restart=no KillMode=mixed TimeoutStopSec=5min RuntimeMaxSec=5h SuccessExitStatus=143 UMask=0027 \
           PrivateTmp=true ProtectHome=true LockPersonality=true ProtectKernelModules=true \
           'ExecStopPost=/usr/sbin/mailctl fenetre-fermer' 'Wants=network-online.target'; do
    grep -qxF "$k" "$u"
  done
  grep -q '^After=.*data-lxc.mount.*network-online.target.*lxc-net.service' "$u"
  ! grep -qE '^(ProtectKernelLogs|RestrictRealtime|SystemCallArchitectures|NoNewPrivileges|ProtectSystem|RestrictNamespaces)=' "$u"
  grep -q 'ExecStart=/usr/sbin/mailctl fenetre' "$u"
}

@test "minuterie : 04:52, lundi 07:07, 18:02 (hors multiples de 5), Persistent=false" {
  t="$BATS_TEST_DIRNAME/../debian/secubox-mail-fenetre.timer"
  grep -qx 'OnCalendar=\*-\*-\* 04:52' "$t"
  grep -qx 'OnCalendar=Mon \*-\*-\* 07:07' "$t"
  grep -qx 'OnCalendar=\*-\*-\* 18:02' "$t"
  grep -qx 'Persistent=false' "$t"
}

@test "paquet : unités installées, sous-commandes, prerm" {
  d="$BATS_TEST_DIRNAME/../debian"
  grep -q 'secubox-mail-fenetre.timer' "$d/rules"; grep -q 'secubox-mail-fenetre.service' "$d/rules"
  grep -q 'disable --now secubox-mail-fenetre.timer' "$d/prerm"; grep -q 'stop secubox-mail-fenetre.service' "$d/prerm"
  grep -q '^    fenetre)' "$BATS_TEST_DIRNAME/../sbin/mailctl"
  grep -q '^    fenetre-fermer)' "$BATS_TEST_DIRNAME/../sbin/mailctl"
}

@test "mise à jour : la fenêtre n'est ni redémarrée ni arrêtée (-X dans dh_installsystemd, postinst généré)" {
  d="$BATS_TEST_DIRNAME/../debian"
  grep -q '^override_dh_installsystemd:' "$d/rules"
  grep -q 'dh_installsystemd .*-Xsecubox-mail-fenetre.service' "$d/rules"
  g="$d/secubox-mail/DEBIAN/postinst"
  [ -f "$g" ] || skip "paquet non construit (debian/secubox-mail absent)"
  ! grep -E "deb-systemd-invoke .*secubox-mail-fenetre.service" "$g"
  grep -q "deb-systemd-invoke .*secubox-mail-fenetre.timer" "$g"
  ! grep -E "deb-systemd-invoke stop .*secubox-mail-fenetre.service" "$d/secubox-mail/DEBIAN/prerm"
}

@test "mise à jour : une minuterie désactivée par l'administrateur n'est pas réactivée (imap-sync et fenetre)" {
  p="$BATS_TEST_DIRNAME/../debian/postinst"
  ! grep -E 'enable( --now)? +secubox-mail-(imap-sync|fenetre)\.timer' "$p"
  g="$BATS_TEST_DIRNAME/../debian/secubox-mail/DEBIAN/postinst"
  [ -f "$g" ] || skip "paquet non construit (debian/secubox-mail absent)"
  for t in secubox-mail-imap-sync.timer secubox-mail-fenetre.timer; do
    grep -q "deb-systemd-helper --quiet was-enabled '$t'" "$g"
    grep -q "was-enabled defaults to true, so new installations run enable" "$g"
  done
}

@test "exception § 10 écrite dans RULES-CODE.md et figée" {
  r="$BATS_TEST_DIRNAME/../../../.claude/RULES-CODE.md"
  l="$(grep '^| § 10 durcissement | `secubox-mail-fenetre.service`' "$r")"
  [ -n "$l" ]
  for k in 'root' 'lxc-start' 'ProtectKernelLogs' 'RestrictRealtime' 'SystemCallArchitectures' '/proc/kmsg' 'test_fenetre_3925.bats'; do
    [[ "$l" == *"$k"* ]]
  done
}

@test "mail.toml livré : [fenetre] actif = false ; le merge l'ajoute sans réécrire l'existant" {
  grep -q '^\[fenetre\]' "$BATS_TEST_DIRNAME/../config/mail.toml"
  [ "$(awk '/^\[fenetre\]/{f=1;next} /^\[/{f=0} f&&/^actif/{print $3}' "$BATS_TEST_DIRNAME/../config/mail.toml")" = false ]
  grep -q '^memoire_min_mo = 1400' "$BATS_TEST_DIRNAME/../config/mail.toml"
  grep -q '^arret_memoire_mo = 350' "$BATS_TEST_DIRNAME/../config/mail.toml"
  source "${BATS_TEST_DIRNAME}/../lib/mail/toml.sh"
  printf 'domain = "gk2.secubox.in"\n[fenetre]\nactif = true\nduree_min = 120\n' > "$BATS_TEST_TMPDIR/m.toml"
  merge_mail_toml "$BATS_TEST_TMPDIR/m.toml"
  grep -q '^actif = true' "$BATS_TEST_TMPDIR/m.toml"
  [ "$(grep -c '^\[fenetre\]' "$BATS_TEST_TMPDIR/m.toml")" -eq 1 ]
  printf 'domain = "x"\n' > "$BATS_TEST_TMPDIR/n.toml"
  merge_mail_toml "$BATS_TEST_TMPDIR/n.toml"
  [ "$(awk '/^\[fenetre\]/{f=1;next} /^\[/{f=0} f&&/^actif/{print $3}' "$BATS_TEST_TMPDIR/n.toml")" = false ]
  grep -q '^charge_max = 25' "$BATS_TEST_TMPDIR/n.toml"
}

@test "aucun secret affiché ni journalisé" {
  run cmd_fenetre
  ! echo "$output" | grep -qiE 'passw|secret|token'
  ! grep -qiE 'passw|secret|token' "$CALLS" "$AUDIT"
}
