# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# Mémoire du conteneur mail : un seul bloc, REMPLACÉ, jamais ajouté.
# gk2 19/11 : la config portait 512M sans swap (budget #496, lignes répétées à la main) alors que le paquet
# prévoit 1G ; doveadm (rapatriement IMAP, ~350 Mo) étouffait rspamd/postfix/dovecot (116 OOM) et toute la box.

MAIL_MEMOIRE_MAX="${MAIL_MEMOIRE_MAX:-1G}"
# PLUS DE FREIN (#3941) : high 900M sous max 1G avec l'échange interdit ne laissait au noyau que les pages de fichiers à
# évincer (relectures sans fin, jamais tué, toute la box en pression). Le plafond RAM reste 1G, c'est lui que la fenêtre
# de relance (#3925, memoire_min_mo = 1400, arret_memoire_mo, seuil critique) prend en compte : ses gardes ne changent
# pas. L'échange est borné à 256M (zram d'abord), bien moins que la moitié du plafond : en zram, au pire ~130 Mo de RAM,
# dans la marge de 400 Mo que la fenêtre garde au-dessus de 1G.
MAIL_MEMOIRE_ECHANGE="${MAIL_MEMOIRE_ECHANGE:-256M}"

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
        echo "lxc.cgroup2.memory.swap.max = $MAIL_MEMOIRE_ECHANGE"
    } >> "$tmp"
    if cmp -s "$tmp" "$cfg"; then rm -f "$tmp"; return 0; fi
    [ -e "$cfg.avant-3941" ] || cp -p "$cfg" "$cfg.avant-3941" 2>/dev/null || true
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
    # Échange ouvert AVANT le retrait du frein ; absent d'un noyau sans échange : sans effet.
    if [ -e "$cg/memory.swap.max" ]; then echo "$MAIL_MEMOIRE_ECHANGE" > "$cg/memory.swap.max" 2>/dev/null || return 1; fi
    echo max > "$cg/memory.high" 2>/dev/null || return 1
}
