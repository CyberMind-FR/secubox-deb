# shellcheck shell=bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: live-env.sh (#3233) — charge et VALIDE board/<carte>/live.env pour build-live-netboot.sh,
# build-live-leger.sh et build-cle-finale.sh (root). Le fichier est lu comme des DONNÉES (lignes LIVE_X=valeur,
# guillemets retirés), jamais exécuté : un `source` lancerait toute commande glissée dans une valeur. Les valeurs
# partent dans boot.cmd (où « ; » sépare des commandes U-Boot), les bootargs, `find -name` et un chemin systemd :
# chacune est contrôlée par motif.

charge_live_env() { # CARTE RACINE_DU_PAQUET → variables LIVE_* ; code ≠ 0 et motif sur stderr si refus
    local carte="$1" ici="$2" f a ligne cle val
    case "$carte" in *[!a-z0-9-]*|"") echo "carte invalide : $carte" >&2; return 1 ;; esac
    f="$ici/board/$carte/live.env"
    [ -s "$f" ] || { echo "carte sans live réseau : $f absent" >&2; return 1; }
    while IFS= read -r ligne || [ -n "$ligne" ]; do
        case "$ligne" in ''|'#'*) continue ;; esac
        [[ "$ligne" =~ ^(LIVE_[A-Z_]{1,24})=(.*)$ ]] || { echo "ligne inattendue dans $f" >&2; return 1; }
        cle="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
        if [[ "$val" =~ ^\"(.*)\"$ ]] || [[ "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
        printf -v "$cle" '%s' "$val"
    done < "$f"
    [[ "${LIVE_NOM:-}" =~ ^[a-z0-9-]{1,32}$ ]] || { echo "LIVE_NOM invalide" >&2; return 1; }
    [[ "${LIVE_TITRE:-}" =~ ^[A-Za-z0-9\ .-]{1,32}$ ]] || { echo "LIVE_TITRE invalide" >&2; return 1; }
    [[ "${LIVE_DTB:-}" =~ ^[a-z0-9.-]{1,64}\.dtb$ ]] || { echo "LIVE_DTB invalide" >&2; return 1; }
    [[ "${LIVE_PILOTE:-}" =~ ^[a-z0-9_]{1,32}$ ]] || { echo "LIVE_PILOTE invalide" >&2; return 1; }
    [[ "${LIVE_CONSOLE:-}" =~ ^tty[A-Za-z0-9]{1,8},[0-9]{4,7}$ ]] || { echo "LIVE_CONSOLE invalide" >&2; return 1; }
    [[ "${LIVE_ETHACT:-}" =~ ^[a-z0-9@_-]{1,32}$ ]] || { echo "LIVE_ETHACT invalide" >&2; return 1; }
    for a in "${LIVE_KERNEL_ADDR:-}" "${LIVE_FDT_ADDR:-}" "${LIVE_RAMDISK_ADDR:-}"; do
        [[ "$a" =~ ^(0x[0-9a-fA-F]{6,8}|\$\{[a-z_]{1,24}\})$ ]] || { echo "adresse de chargement invalide : $a" >&2; return 1; }
    done
    [[ "${LIVE_BOOTARGS-x}" =~ ^[A-Za-z0-9_.,=@:/\ -]{0,160}$ ]] || { echo "LIVE_BOOTARGS invalide" >&2; return 1; }
}

# Préparation de l'environnement U-Boot (#3271) : secubox-uboot-env.scr de la carte (board/<carte>/ du paquet installé, ou
# board/<carte>/ à la racine du dépôt), refusé s'il n'est plus celui que produit scripts/uboot-env.py.
uboot_env_scr_de() { # CARTE RACINE_DU_PAQUET → chemin du .scr sur stdout ; code ≠ 0 et motif sur stderr si refus
    local carte="$1" ici="$2" d
    for d in "$ici/board/$carte" "$ici/../../board/$carte"; do
        if [ ! -f "$d/secubox-uboot-env.scr" ] || [ ! -f "$d/secubox-uboot-env.cmd" ]; then continue; fi
        if ! python3 "$ici/scripts/uboot-env.py" cmd "$carte" | cmp -s - "$d/secubox-uboot-env.cmd"; then
            echo "$d/secubox-uboot-env.cmd en retard sur scripts/uboot-env.py : régénérer (uboot-env.py generer)" >&2
            return 1
        fi
        echo "$d/secubox-uboot-env.scr"
        return 0
    done
    echo "secubox-uboot-env.scr introuvable pour la carte $carte" >&2
    return 1
}
