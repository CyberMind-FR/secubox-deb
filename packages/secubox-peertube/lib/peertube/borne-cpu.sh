#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: secubox-peertube :: borne-cpu.sh
#
# Plafonne le CPU du conteneur PeerTube (#1010).
#
# POURQUOI AU NIVEAU DU CONTENEUR ET PAS DANS PEERTUBE. La configuration
# applicative porte deja `transcoding.threads: 1` et `transcoding.concurrency:
# 1` — et deux ffmpeg tournaient quand meme, dont un a 140 % d'un coeur.
# D'autres sections (studio video, direct) ont leurs propres reglages et
# echappent a ces deux-la. Le cgroup, lui, ne laisse rien passer : il borne
# tout ce qui tourne dans le conteneur, y compris ce qu'une version future
# ajouterait.
#
# POURQUOI PAS UNE BORNE SUR L'UNITE SYSTEMD. PeerTube sert le web et transcode
# dans le meme `peertube.service` : un plafond sur l'unite etranglerait aussi
# la consultation. Le cgroup du conteneur a le meme defaut, mais la
# consultation coute peu — c'est le transcodage qui remplit le plafond. Une
# separation reelle demanderait de sortir le transcodage du service, ce que
# PeerTube ne propose pas.
#
# LA DUREE N'EST PAS UN CRITERE. Le transcodage est du travail de fond : il
# peut prendre trois fois plus longtemps sans que personne ne s'en apercoive.
# Une board injoignable, si.
set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-peertube}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"

# LA VALEUR N'EST DEFINIE QU'ICI. Le gabarit d'installation appelle ce script
# au lieu d'ecrire la ligne lui-meme : deux ecritures de la meme borne
# finissent toujours par diverger, et c'est alors la reinstallation qui
# ramenerait silencieusement l'ancienne valeur.
#
# 100000 / 100000 = un coeur sur les quatre de la board. C'est ce que recoivent
# deja gitea et mail ; nextcloud et matrix en ont deux. Un transcodeur de fond
# ne merite pas plus qu'un service consulte.
readonly BORNE_CPU="${SECUBOX_PEERTUBE_CPU_MAX:-100000 100000}"

log() { printf '[peertube-borne-cpu] %s\n' "$*"; }

# pose_dans_config inscrit la borne dans la configuration du conteneur, pour
# qu'elle survive a un redemarrage.
#
# REMPLACE, N'APPEND JAMAIS. Une seconde ligne `lxc.cgroup2.cpu.max` laisse la
# configuration ambigue et rend la valeur effective dependante de l'ordre de
# lecture — le meme piege que le second bloc `lxc.net.0` qui laisse un
# conteneur sans adresse.
pose_dans_config() {
    local cfg="$LXC_PATH/$LXC_NAME/config"
    [ -f "$cfg" ] || { log "pas de conteneur installe, rien a borner"; return 0; }

    if grep -q '^lxc\.cgroup2\.cpu\.max' "$cfg"; then
        local actuelle
        actuelle=$(sed -n 's/^lxc\.cgroup2\.cpu\.max[[:space:]]*=[[:space:]]*//p' "$cfg" | head -1)
        [ "$actuelle" = "$BORNE_CPU" ] && { log "borne deja posee ($BORNE_CPU)"; return 0; }
        # Ecriture par fichier temporaire puis renommage : une configuration LXC
        # tronquee par une interruption laisse le conteneur non demarrable.
        sed "s|^lxc\.cgroup2\.cpu\.max[[:space:]]*=.*|lxc.cgroup2.cpu.max = $BORNE_CPU|" \
            "$cfg" > "$cfg.nouveau"
        mv "$cfg.nouveau" "$cfg"
        log "borne corrigee : $actuelle -> $BORNE_CPU"
        return 0
    fi

    printf '\n# Plafond CPU du transcodage (#1010) — pose par borne-cpu.sh.\n' >> "$cfg"
    printf 'lxc.cgroup2.cpu.max = %s\n' "$BORNE_CPU" >> "$cfg"
    log "borne ajoutee : $BORNE_CPU"
}

# pose_a_chaud applique la borne au conteneur DEJA EN MARCHE.
#
# Indispensable : la configuration n'est relue qu'au demarrage, et redemarrer
# PeerTube pour poser un plafond couperait la consultation — precisement ce
# qu'on cherche a proteger. Le cgroup v2 accepte l'ecriture a chaud.
pose_a_chaud() {
    local cg="/sys/fs/cgroup/lxc.payload.$LXC_NAME/cpu.max"
    [ -w "$cg" ] || { log "conteneur a l'arret, borne active au prochain demarrage"; return 0; }
    printf '%s\n' "$BORNE_CPU" > "$cg" 2>/dev/null \
        && log "borne appliquee a chaud" \
        || log "borne a chaud refusee (sera active au prochain demarrage)"
}

pose_dans_config
pose_a_chaud
