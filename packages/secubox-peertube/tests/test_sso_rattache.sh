#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# sso-rattache : un compte ordinaire par défaut ; un administrateur seulement
# sur demande explicite (--administrateur), avec une ligne d'audit (#3008).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# lxc-attach factice : journalise la requête SQL, répond « 1 » au contrôle du
# greffon et renvoie le nom pour l'UPDATE … RETURNING.
mkdir -p "$tmp/bin"
cat > "$tmp/bin/lxc-attach" <<'EOF'
#!/usr/bin/env bash
sql="${@: -1}"
printf '%s\n' "$sql" >> "$STUB_SQL"
case "$sql" in *"FROM plugin"*) echo 1 ;; *RETURNING*) echo gk2 ;; esac
EOF
chmod +x "$tmp/bin/lxc-attach"
export PATH="$tmp/bin:$PATH" STUB_SQL="$tmp/sql" SECUBOX_AUDIT_LOG="$tmp/audit.log"
export SECUBOX_PEERTUBE_CONFIG="$tmp/absent.toml"

# 1. Par défaut : seul un compte ordinaire (role = 2).
: > "$STUB_SQL"
bash "$here/sbin/peertubectl" sso-rattache gk2 >/dev/null
grep -q 'UPDATE "user"' "$STUB_SQL" || { echo "pas d'UPDATE"; exit 1; }
grep 'UPDATE "user"' "$STUB_SQL" | grep -q 'role = 2' || { echo "sans --administrateur, la garde role = 2 manque"; exit 1; }
echo "PASS sso-rattache : compte ordinaire seulement par défaut"

# 2. --administrateur : la garde de rôle tombe, et l'audit le dit.
: > "$STUB_SQL"; : > "$SECUBOX_AUDIT_LOG"
bash "$here/sbin/peertubectl" sso-rattache gk2 --administrateur >/dev/null
grep 'UPDATE "user"' "$STUB_SQL" | grep -q 'role = 2' && { echo "--administrateur garde encore role = 2"; exit 1; }
grep 'UPDATE "user"' "$STUB_SQL" | grep -q "username = 'gk2'" || { echo "nom absent de l'UPDATE"; exit 1; }
grep -q '"action": *"sso-rattache"' "$SECUBOX_AUDIT_LOG" || { echo "pas de ligne d'audit"; exit 1; }
grep -q '"administrateur": *true' "$SECUBOX_AUDIT_LOG" || { echo "l'audit ne marque pas l'administrateur"; exit 1; }
grep -q '"compte": *"gk2"' "$SECUBOX_AUDIT_LOG" || { echo "l'audit ne nomme pas le compte"; exit 1; }
echo "PASS sso-rattache --administrateur : rattache et audité"

# 3. Un drapeau inconnu est refusé.
bash "$here/sbin/peertubectl" sso-rattache gk2 --root >/dev/null 2>&1 && { echo "drapeau inconnu accepté"; exit 1; }
echo "PASS sso-rattache : drapeau inconnu refusé"
