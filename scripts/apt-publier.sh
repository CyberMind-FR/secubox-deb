#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: apt-publier — un .deb construit est publié dans apt.secubox.in (#1522)
#
# POURQUOI. Les box se mettent à jour seules (secubox-majauto) depuis le dépôt
# signé de gk2 ; un paquet déployé à la main mais oublié dans le dépôt ne
# leur parvient jamais, et un paquet PLUS VIEUX que celui du dépôt ferait
# régresser tout le parc. Ce script fait la publication en une commande,
# avec les leçons déjà payées :
#   - refus de publier une version inférieure ou égale (sauf --force) ;
#   - sauvegarde db/dists/conf avant ;
#   - `reprepro export` EXPLICITE : includedeb qui échoue sur un paquet met
#     la base à jour mais ne ré-exporte pas (InRelease resterait ancien) ;
#   - la clé est celle de reprepro sur gk2 (219BA872…) : jamais une autre.
#
# Usage : scripts/apt-publier.sh [--force] paquet_1.2.3-1~bookworm1_all.deb [...]
set -euo pipefail
readonly HOTE="${APT_HOTE:-root@192.168.1.200}"
readonly BASE=/srv/apt
readonly SUITE=bookworm

force=0
[[ "${1:-}" == "--force" ]] && { force=1; shift; }
(( $# )) || { echo "usage : $0 [--force] fichier.deb..." >&2; exit 2; }

a_publier=()
# Un paquet écarté parce qu'une version PLUS HAUTE est déjà publiée signale
# presque toujours une divergence (#1583 : podcaster/tor 1.2.0 d'une branche
# jamais fusionnée) : on publie le reste, mais la sortie est en ÉCHEC.
refuses=()
for deb in "$@"; do
    [[ -f "$deb" ]] || { echo "introuvable : $deb" >&2; exit 2; }
    p=$(dpkg-deb -f "$deb" Package); v=$(dpkg-deb -f "$deb" Version); a=$(dpkg-deb -f "$deb" Architecture)
    # Un APERÇU (~aurora…) ne part jamais au parc : majauto l'installerait la
    # nuit sur toutes les box (#1611).
    if [[ "$v" == *"~aurora"* ]]; then
        echo "REFUSÉ : $p $v est un aperçu, jamais publié" >&2; refuses+=("$p $v (aperçu)"); continue
    fi
    arch=$([[ "$a" == all ]] && echo amd64 || echo "$a")
    dep=$(ssh "$HOTE" "reprepro -b $BASE -A $arch list $SUITE $p 2>/dev/null | awk '{print \$3}'" 2>/dev/null | head -1)
    if [[ -n "$dep" ]] && ! dpkg --compare-versions "$v" gt "$dep"; then
        if (( force )); then
            echo "⚠ $p $v ≤ dépôt $dep : publié quand même (--force)"
        else
            echo "✗ $p $v n'est pas plus récent que le dépôt ($dep) — ignoré (--force pour passer outre)" >&2
            refuses+=("$p $v ≤ $dep")
            continue
        fi
    fi
    echo "→ $p ${dep:-absent} → $v [$a]"
    a_publier+=("$deb")
done
fin() {
    (( ${#refuses[@]} )) || exit 0
    echo "ÉCHEC : ${#refuses[@]} paquet(s) NON publiés — une version plus haute occupe le dépôt :" >&2
    printf '   %s\n' "${refuses[@]}" >&2
    exit 1
}
(( ${#a_publier[@]} )) || { echo "rien à publier"; fin; }

# LA CLÉ DU DÉPÔT PEUT ÊTRE AU COFFRE (#1367 P2). Protégée, elle ne signe que
# pendant une session ouverte par le Coffre : on en ouvre une de 10 min si le
# Coffre est ouvert ; scellé, on s'arrête AVANT de toucher au dépôt. Clé encore
# en clair (P0 non fait) : rien ne change.
etat_depot=$(ssh "$HOTE" 'command -v coffrectl >/dev/null 2>&1 && coffrectl depot etat --porcelaine 2>/dev/null' || true)
if [[ "$etat_depot" == *"protegee=1"* && "$etat_depot" != *"en_cache=1"* ]]; then
    ssh "$HOTE" "coffrectl depot session --minutes 10" >/dev/null \
        || { echo "ÉCHEC : la clé du dépôt est au Coffre, qui est scellé — l'ouvrir (coffrectl ouvrir, ou la page Coffre) puis relancer" >&2; exit 1; }
    echo "session de signature ouverte (10 min) par le Coffre"
fi

lot="/data/apt-import/publier-$(date +%Y%m%d-%H%M%S)"
ssh "$HOTE" "mkdir -p $lot"
scp -q "${a_publier[@]}" "$HOTE:$lot/"
ssh "$HOTE" "set -e
  sauve=/var/backups/apt-avant-\$(basename $lot); mkdir -p \$sauve
  cp -a $BASE/db $BASE/dists $BASE/conf \$sauve/
  cd $lot
  reprepro -b $BASE -C main includedeb $SUITE *.deb 2>&1 | grep -iE 'error|erreur|warn' || true
  reprepro -b $BASE export $SUITE >/dev/null
  gpg --verify $BASE/dists/$SUITE/InRelease 2>&1 | grep -q '219BA872E3933EAAC3486A1344E50F0178E8BC7E' \
    || { echo 'SIGNATURE INATTENDUE — vérifier la clé de reprepro' >&2; exit 1; }
  echo \"dépôt ré-exporté et signé (219BA872…), sauvegarde \$sauve\""
for deb in "${a_publier[@]}"; do
    p=$(dpkg-deb -f "$deb" Package); a=$(dpkg-deb -f "$deb" Architecture)
    ssh "$HOTE" "reprepro -b $BASE list $SUITE $p" | sed 's/^/   /'
done
fin
