#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
# SecuBox-Deb :: image — source apt SecuBox SIGNÉE posée dans toute image (#1503)
#
# CE QUI SE PASSAIT. Une box installée depuis l'image alpha.6 n'avait AUCUNE
# source apt.secubox.in : `apt-get install secubox-full` -> « Unable to locate
# package ». Les constructeurs posaient une source seulement pour s'installer
# eux-mêmes — dépôt local 127.0.0.1 en CI, ou `trusted=yes` — ou pas du tout
# quand les paquets venaient du slipstream. Une box bêta ne pouvait donc
# recevoir aucun correctif.
#
# CE QUE FAIT CE SCRIPT, en DERNIER dans chaque construction : il remplace
# toute source SecuBox temporaire par la source publique, vérifiée par la clé
# versionnée dans image/keys/ — jamais téléchargée à la construction (on ne
# fait pas confiance au réseau pour la clé qui protège le réseau).
#
# La clé attendue est 219BA872…, celle de reprepro sur gk2. Une autre
# empreinte arrête la construction : ne JAMAIS générer de nouvelle clé.
set -euo pipefail

ROOTFS="${1:?usage: $0 <rootfs> [suite]}"
SUITE="${2:-bookworm}"
[ -d "$ROOTFS" ] || { echo "[apt] rootfs introuvable : $ROOTFS" >&2; exit 1; }

readonly DEPOT="https://apt.secubox.in"
readonly EMPREINTE="219BA872E3933EAAC3486A1344E50F0178E8BC7E"
readonly CLE_SRC="$(cd "$(dirname "$0")" && pwd)/keys/secubox-archive-keyring.gpg"
readonly CLE_DST="/usr/share/keyrings/secubox-archive-keyring.gpg"

[ -s "$CLE_SRC" ] || { echo "[apt] clé absente : $CLE_SRC" >&2; exit 1; }
vue=$(gpg --show-keys --with-colons "$CLE_SRC" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
if [ "$vue" != "$EMPREINTE" ]; then
    echo "[apt] empreinte inattendue : ${vue:-illisible} (attendu $EMPREINTE)" >&2
    exit 1
fi

install -D -m 0644 "$CLE_SRC" "${ROOTFS}${CLE_DST}"
# Les sources temporaires (locale, trusted=yes, ancien trousseau) disparaissent :
# une seule ligne SecuBox, signée.
rm -f "${ROOTFS}/etc/apt/sources.list.d/secubox.list" \
      "${ROOTFS}/etc/apt/sources.list.d/secubox-local.list"
cat > "${ROOTFS}/etc/apt/sources.list.d/secubox.list" <<EOF
# SecuBox — dépôt signé (clé ${EMPREINTE:0:8}…, #1503).
deb [signed-by=${CLE_DST}] ${DEPOT} ${SUITE} main
EOF
echo "[apt] source ${DEPOT} ${SUITE} posée (signed-by ${EMPREINTE:0:8}…)"
