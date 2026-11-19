#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
# #3831 : gitea coupé par le profil ou non réveillable => rien à faire (code 0), pas d'échec.
set -u
CTL="$(cd "$(dirname "$0")/.." && pwd)/sbin/secubox-gitea-reveil"
bin="$(mktemp -d)"; fail=0
cat > "$bin/log" <<'L'
#!/bin/sh
exit 0
L
# profilectl qui dit « coupé » (rc 0) => le script doit sortir 0 sans réveiller.
cat > "$bin/secubox-profilectl" <<'P'
#!/bin/sh
[ "$1" = coupe ] && exit 0
exit 1
P
cat > "$bin/secubox-wakectl" <<'W'
#!/bin/sh
echo "NE DOIT PAS ETRE APPELE" >&2
exit 1
W
chmod +x "$bin"/*
# Le script appelle secubox-profilectl sans chemin absolu (PATH) ; wakectl en /usr/sbin.
grep -q 'secubox-profilectl coupe secubox-gitea.service' "$CTL" || { echo FAIL garde coupe absente; fail=1; }
grep -q 'rien à faire : gitea non réveillable' "$CTL" || { echo FAIL repli non fatal absent; fail=1; }
grep -q 'exit 1' <(sed -n '/wakectl wake gitea/,/fi/p' "$CTL") && { echo FAIL wake encore fatal; fail=1; }
rm -rf "$bin"
[ "$fail" -eq 0 ] && echo "OK test_reveil_rien_a_faire_3831" || exit 1
