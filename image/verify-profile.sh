#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: verify-profile.sh ROOTFS PROFILE
#
# Une image ne sort que si son PROFIL est réellement installé (#1361).
#
# CE QUI EST ARRIVÉ. L'image « full » alpha.5 — publiée comme telle — ne
# contenait que `secubox-core` : `apt-get install secubox-full` avait échoué
# (`secubox-ndpid-engine … not installable`), et la construction s'était
# contentée d'un `warn` avant de continuer. Au premier démarrage : firstboot en
# échec (python3-argon2 absent), pas de MirrorNet, et un kiosque qui affichait
# « Welcome to nginx! » puis un 403 — il n'y avait aucune interface à montrer.
#
# Lit l'état dpkg du rootfs DE L'EXTÉRIEUR (`--admindir`) : pas besoin de
# chroot, et testable avec un faux fichier d'état.
#
# Sortie 0 : le méta-paquet et chacune de ses dépendances sont installés.
# Sortie 1 : la liste de ce qui manque, sur la sortie d'erreur.
set -euo pipefail

ROOTFS="${1:?usage: verify-profile.sh ROOTFS PROFILE}"
PROFILE="${2:?usage: verify-profile.sh ROOTFS PROFILE}"
ADMIN="${ROOTFS%/}/var/lib/dpkg"

etat() {
    dpkg-query --admindir="$ADMIN" -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | tr -d ' ' || true
}

manques=()

# 1. Le méta-paquet lui-même.
if [[ "$(etat "$PROFILE")" != "ii" ]]; then
    echo "PROFIL NON INSTALLÉ : ${PROFILE} (état « $(etat "$PROFILE" || echo absent) »)" >&2
    echo "  L'image annoncerait « ${PROFILE#secubox-} » sans en contenir les modules." >&2
    exit 1
fi

# 2. Chacune de ses dépendances. Un groupe `a | b` est satisfait par l'une ou
#    l'autre ; la contrainte de version est vérifiée par dpkg lui-même à
#    l'installation, on ne vérifie ici que la PRÉSENCE.
deps=$(dpkg-query --admindir="$ADMIN" -W -f='${Depends}' "$PROFILE")
IFS=',' read -ra groupes <<< "$deps"
for g in "${groupes[@]}"; do
    ok=0
    IFS='|' read -ra alts <<< "$g"
    for a in "${alts[@]}"; do
        nom=$(echo "$a" | sed -E 's/\(.*\)//; s/:any//; s/^[[:space:]]+|[[:space:]]+$//g')
        [[ -z "$nom" ]] && { ok=1; break; }
        [[ "$(etat "$nom")" == "ii" ]] && { ok=1; break; }
    done
    (( ok )) || manques+=("$(echo "$g" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')")
done

# 3. Tout paquet SecuBox à moitié installé (`--force-depends` les laisse
#    dépaquetés mais non configurés, ce qui ne se voit qu'au démarrage).
while read -r st nom; do
    [[ "$st" == "ii" ]] || manques+=("$nom (état $st)")
done < <(dpkg-query --admindir="$ADMIN" -W -f='${db:Status-Abbrev} ${Package}\n' 'secubox-*' 2>/dev/null \
         | awk 'NF==2 && $1 !~ /^un$/' | tr -s ' ')

if (( ${#manques[@]} )); then
    echo "PROFIL INCOMPLET : ${PROFILE} — ${#manques[@]} manque(s) :" >&2
    printf '  - %s\n' "${manques[@]}" >&2
    exit 1
fi
echo "profil ${PROFILE} complet"
