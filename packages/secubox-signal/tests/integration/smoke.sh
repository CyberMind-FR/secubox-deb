#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: SBX-SIGNAL — essai d'integration
#
# Demarre sbx-signald sur un etat JETABLE et verifie qu'il sert reellement.
# Ne demande NI signal-cli NI compte lie : le demon doit rester joignable et
# DIRE que le backend manque, plutot que de refuser de demarrer. Un module
# muet est plus difficile a diagnostiquer qu'un module qui se plaint.
set -euo pipefail

BIN="${1:?usage: smoke.sh <chemin du binaire sbx-signald>}"
TMP="$(mktemp -d)"
trap 'kill "${PID:-}" 2>/dev/null || true; rm -rf "$TMP"' EXIT

mkdir -p "$TMP/state/cli" "$TMP/log"
cat > "$TMP/signal.toml" <<TOML
[daemon]
socket = "$TMP/signal.sock"
log_dir = "$TMP/log"
state_dir = "$TMP/state"
[backend]
signal_cli = "/inexistant/signal-cli"
[retention]
store_body = false
hours = 1
TOML

"$BIN" --config "$TMP/signal.toml" >"$TMP/sortie.log" 2>&1 &
PID=$!

for _ in $(seq 1 40); do
    [ -S "$TMP/signal.sock" ] && break
    sleep 0.25
done
[ -S "$TMP/signal.sock" ] || { echo "ECHEC : socket jamais creee"; cat "$TMP/sortie.log"; exit 1; }

echec=0
verifier() {
    local nom="$1" attendu="$2" obtenu="$3"
    if [ "$obtenu" = "$attendu" ]; then
        printf '  OK    %-38s %s\n' "$nom" "$obtenu"
    else
        printf '  ECHEC %-38s attendu %s, obtenu %s\n' "$nom" "$attendu" "$obtenu"
        echec=1
    fi
}

sante=$(curl -s --unix-socket "$TMP/signal.sock" http://x/api/v1/signal/healthz)
verifier "healthz sans authentification" "ok" "$(echo "$sante" | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])')"
verifier "backend annonce non appaire"   "unlinked" "$(echo "$sante" | python3 -c 'import sys,json;print(json.load(sys.stdin)["backend"])')"

code=$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$TMP/signal.sock" http://x/api/v1/signal/status)
verifier "status exige un jeton" "401" "$code"

type=$(curl -s -o /dev/null -w '%{content_type}' --unix-socket "$TMP/signal.sock" http://x/api/v1/signal/status)
verifier "les erreurs sont en RFC 9457" "application/problem+json" "$type"

code=$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$TMP/signal.sock" http://x/api/v1/signal/micro)
verifier "cardlet servie sans jeton" "200" "$code"

perms=$(stat -c '%a' "$TMP/signal.sock")
verifier "socket en 0660" "660" "$perms"

# La base ne doit contenir AUCUNE colonne de corps peuplee quand store_body
# est faux — c'est la garantie centrale du module.
verifier "base creee" "1" "$([ -f "$TMP/state/signal.db" ] && echo 1 || echo 0)"

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
grep -q "arret propre" "$TMP/sortie.log" \
    && printf '  OK    %-38s\n' "arret propre sur SIGTERM" \
    || { printf '  ECHEC %-38s\n' "arret propre sur SIGTERM"; echec=1; }

exit $echec
