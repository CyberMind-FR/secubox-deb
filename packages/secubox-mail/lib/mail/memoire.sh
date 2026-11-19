# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# Mémoire du conteneur mail : un seul bloc, REMPLACÉ, jamais ajouté.
# gk2 19/11 : la config portait 512M sans swap (budget #496, lignes répétées à la main) alors que le paquet
# prévoit 1G ; doveadm (rapatriement IMAP, ~350 Mo) étouffait rspamd/postfix/dovecot (116 OOM) et toute la box.

MAIL_MEMOIRE_MAX="${MAIL_MEMOIRE_MAX:-1G}"
MAIL_MEMOIRE_HAUTE="${MAIL_MEMOIRE_HAUTE:-900M}"

# mail_memoire_config <fichier config LXC> : retire toute ligne lxc.cgroup2.memory.* et les commentaires du
# budget #496, puis pose le bloc. Idempotent. Rend 0 si rien n'a changé, 10 si le fichier a été réécrit.
mail_memoire_config() {
    local cfg="$1" tmp
    [ -f "$cfg" ] || return 0
    tmp="$(mktemp "${cfg}.XXXXXX")" || return 1
    grep -vE '^[[:space:]]*lxc\.cgroup2\.memory\.|^# Phase 6\.P \(#496\) : memory budget$|^# Mémoire du conteneur \(secubox-mail\)' "$cfg" > "$tmp" || true
    {
        echo "# Mémoire du conteneur (secubox-mail) — bloc unique, réécrit par le paquet"
        echo "lxc.cgroup2.memory.max = $MAIL_MEMOIRE_MAX"
        echo "lxc.cgroup2.memory.high = $MAIL_MEMOIRE_HAUTE"
        echo "lxc.cgroup2.memory.swap.max = 0"
    } >> "$tmp"
    if cmp -s "$tmp" "$cfg"; then rm -f "$tmp"; return 0; fi
    chmod --reference="$cfg" "$tmp" 2>/dev/null || true
    chown --reference="$cfg" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$cfg"
    return 10
}

# mail_memoire_vive <nom> : applique les mêmes limites au conteneur en marche (cgroup v2), sans redémarrage.
mail_memoire_vive() {
    local cg="${MAIL_CGROUP_RACINE:-/sys/fs/cgroup}/lxc.payload.$1"
    [ -d "$cg" ] || return 0
    echo "$MAIL_MEMOIRE_MAX" > "$cg/memory.max" 2>/dev/null || return 1
    echo "$MAIL_MEMOIRE_HAUTE" > "$cg/memory.high" 2>/dev/null || return 1
}
