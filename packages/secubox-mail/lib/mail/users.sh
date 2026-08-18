#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox Mail - User Management Library

DATA_PATH="${DATA_PATH:-/srv/mail}"
CONFIG_PATH="$DATA_PATH/config"
CONTAINER="${MAIL_CONTAINER:-mailserver}"
LXC_PATH="/data/lxc/$CONTAINER"

# ============================================================================
# User Management
# ============================================================================

user_add() {
    local email="$1"
    local password="$2"

    if [ -z "$email" ] || [ -z "$password" ]; then
        echo "Usage: user_add <email@domain> <password>"
        return 1
    fi

    local user=$(echo "$email" | cut -d@ -f1)
    local domain=$(echo "$email" | cut -d@ -f2)

    # Validate email format
    if ! echo "$email" | grep -qE '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; then
        echo "Invalid email format: $email"
        return 1
    fi

    mkdir -p "$CONFIG_PATH"

    # Check if user exists
    if grep -q "^${email}:" "$CONFIG_PATH/users" 2>/dev/null; then
        echo "User already exists: $email"
        return 1
    fi

    # Add to vmailbox
    echo "$email ${domain}/${user}/" >> "$CONFIG_PATH/vmailbox"

    # Generate password hash
    local pass_hash
    if lxc-info -n "$CONTAINER" 2>/dev/null | grep -q "RUNNING"; then
        pass_hash=$(lxc-attach -n "$CONTAINER" -- doveadm pw -s SHA512-CRYPT -p "$password" 2>/dev/null)
    else
        # Fallback to local doveadm or openssl
        if command -v doveadm >/dev/null 2>&1; then
            pass_hash=$(doveadm pw -s SHA512-CRYPT -p "$password" 2>/dev/null)
        else
            pass_hash=$(openssl passwd -6 "$password" 2>/dev/null)
        fi
    fi

    # Add to users file
    echo "${email}:${pass_hash}:5000:5000::/var/mail/${domain}/${user}::" >> "$CONFIG_PATH/users"

    # Create maildir
    local maildir="$DATA_PATH/mail/${domain}/${user}/Maildir"
    mkdir -p "$maildir"/{cur,new,tmp}
    chown -R 5000:5000 "$DATA_PATH/mail/${domain}"

    # Copy to container if exists
    if [ -d "$LXC_PATH/rootfs" ]; then
        cp "$CONFIG_PATH/vmailbox" "$LXC_PATH/rootfs/etc/postfix/vmailbox"
        cp "$CONFIG_PATH/users" "$LXC_PATH/rootfs/etc/dovecot/users"
        chmod 644 "$LXC_PATH/rootfs/etc/dovecot/users"

        # Rebuild postmap if container running
        if lxc-info -n "$CONTAINER" 2>/dev/null | grep -q "RUNNING"; then
            lxc-attach -n "$CONTAINER" -- postmap lmdb:/etc/postfix/vmailbox 2>/dev/null
        fi
    fi

    echo "User added: $email"
}

user_del() {
    local email="$1"

    if [ -z "$email" ]; then
        echo "Usage: user_del <email@domain>"
        return 1
    fi

    # Remove from vmailbox
    if [ -f "$CONFIG_PATH/vmailbox" ]; then
        sed -i "/^${email} /d" "$CONFIG_PATH/vmailbox"
    fi

    # Remove from users
    if [ -f "$CONFIG_PATH/users" ]; then
        sed -i "/^${email}:/d" "$CONFIG_PATH/users"
    fi

    # Copy to container
    if [ -d "$LXC_PATH/rootfs" ]; then
        cp "$CONFIG_PATH/vmailbox" "$LXC_PATH/rootfs/etc/postfix/vmailbox" 2>/dev/null
        cp "$CONFIG_PATH/users" "$LXC_PATH/rootfs/etc/dovecot/users" 2>/dev/null

        if lxc-info -n "$CONTAINER" 2>/dev/null | grep -q "RUNNING"; then
            lxc-attach -n "$CONTAINER" -- postmap lmdb:/etc/postfix/vmailbox 2>/dev/null
        fi
    fi

    echo "User deleted: $email"
    echo "Note: Mailbox data preserved in $DATA_PATH/mail/"
}

user_passwd() {
    local email="$1"
    local password="$2"

    if [ -z "$email" ] || [ -z "$password" ]; then
        echo "Usage: user_passwd <email@domain> <new_password>"
        return 1
    fi

    # Check if user exists
    if ! grep -q "^${email}:" "$CONFIG_PATH/users" 2>/dev/null; then
        echo "User not found: $email"
        return 1
    fi

    # Generate new password hash
    local pass_hash
    if lxc-info -n "$CONTAINER" 2>/dev/null | grep -q "RUNNING"; then
        pass_hash=$(lxc-attach -n "$CONTAINER" -- doveadm pw -s SHA512-CRYPT -p "$password" 2>/dev/null)
    else
        if command -v doveadm >/dev/null 2>&1; then
            pass_hash=$(doveadm pw -s SHA512-CRYPT -p "$password" 2>/dev/null)
        else
            pass_hash=$(openssl passwd -6 "$password" 2>/dev/null)
        fi
    fi

    # Update password in users file
    local user=$(echo "$email" | cut -d@ -f1)
    local domain=$(echo "$email" | cut -d@ -f2)
    local new_line="${email}:${pass_hash}:5000:5000::/var/mail/${domain}/${user}::"

    sed -i "s|^${email}:.*|${new_line}|" "$CONFIG_PATH/users"

    # Copy to container
    if [ -d "$LXC_PATH/rootfs" ]; then
        cp "$CONFIG_PATH/users" "$LXC_PATH/rootfs/etc/dovecot/users"
        chmod 644 "$LXC_PATH/rootfs/etc/dovecot/users"
    fi

    echo "Password changed for: $email"
}

user_list() {
    echo "Mail Users:"
    echo "==========="

    if [ ! -f "$CONFIG_PATH/users" ] || [ ! -s "$CONFIG_PATH/users" ]; then
        echo "  No users configured"
        return 0
    fi

    while IFS=: read -r email _ _ _ _ home _; do
        local domain=$(echo "$email" | cut -d@ -f2)
        local user=$(echo "$email" | cut -d@ -f1)
        local maildir="$DATA_PATH/mail/${domain}/${user}"

        local size="0"
        if [ -d "$maildir" ]; then
            size=$(du -sh "$maildir" 2>/dev/null | cut -f1)
        fi

        local count="0"
        if [ -d "$maildir/Maildir" ]; then
            count=$(find "$maildir/Maildir" -type f 2>/dev/null | wc -l)
        fi

        echo "  $email  ($size, $count messages)"
    done < "$CONFIG_PATH/users"
}

# ============================================================================
# Alias Management
# ============================================================================

alias_add() {
    local alias="$1"
    local target="$2"

    if [ -z "$alias" ] || [ -z "$target" ]; then
        echo "Usage: alias_add <alias@domain> <target@domain>"
        return 1
    fi

    mkdir -p "$CONFIG_PATH"

    # Check if alias exists
    if grep -q "^${alias} " "$CONFIG_PATH/virtual" 2>/dev/null; then
        echo "Alias already exists: $alias"
        return 1
    fi

    echo "$alias $target" >> "$CONFIG_PATH/virtual"

    # ON COMPILE LA CARTE QUE POSTFIX LIT, PAS UNE COPIE (#1025).
    #
    # $CONFIG_PATH est monte dans le conteneur sur /etc/mail-config : c'est LE
    # MEME FICHIER, pas une copie a synchroniser. L'ancienne version recopiait
    # vers /etc/postfix/virtual et lancait `postmap` sur cette copie — le .lmdb
    # etait donc construit sur un chemin que main.cf ne lit pas, tandis que
    # celui qu'il lit n'etait jamais recompile.
    #
    # Le defaut etait MUET : postfix ne se plaint pas d'une carte absente, il
    # constate qu'aucun alias ne correspond et passe a la regle suivante.
    # Ajouter un alias « reussissait », `alias list` le montrait, et il ne
    # redirigeait rien. Deux redirections posees en fevrier 2026 —
    # root@ et postmaster@ — n'ont jamais porte.
    alias_recompile "$alias"

    echo "Alias added: $alias -> $target"
}

# alias_recompile branche la carte, la compile, et recharge postfix (#1025).
#
# LES TROIS VONT ENSEMBLE. Compiler sans brancher laisse un .lmdb que personne
# ne lit ; brancher sans recharger laisse postfix sur son ancienne vue. Les
# separer, c'est reproduire le defaut a une piece pres.
alias_recompile() {
    local nouvel_alias="${1:-}"
    lxc-info -n "$CONTAINER" 2>/dev/null | grep -q "RUNNING" || {
        echo "Container not running — alias map will compile at next start"
        return 0
    }

    # `virtual_alias_domains` est ENUMERE, jamais derive de la carte.
    #
    # Le defaut `$virtual_alias_maps` ferait de secubox.in a la fois un domaine
    # de boites et un domaine d'alias : postfix refuse ce recouvrement, et la
    # remise cesserait POUR TOUT LE DOMAINE. Un correctif d'alias qui casse le
    # courrier est pire que l'absence d'alias.
    local domaines
    domaines=$(awk '{print $1}' "$CONFIG_PATH/virtual" 2>/dev/null \
        | awk -F@ 'NF==2 {print $2}' | sort -u)
    local mail_dom
    mail_dom=$(lxc-attach -n "$CONTAINER" -- postconf -h virtual_mailbox_domains 2>/dev/null)
    local alias_dom=""
    for d in $domaines; do
        case " $mail_dom " in *" $d "*) continue ;; esac
        alias_dom="${alias_dom:+$alias_dom, }$d"
    done

    # LE TYPE DE CARTE EST DEMANDE A POSTFIX, PAS SUPPOSE.
    #
    # Le modele du paquet ecrivait `lmdb:` — que le postfix 3.7 de Debian
    # bookworm NE SUPPORTE PAS ici : `postconf -m` ne l'annonce pas, et toute
    # recherche echoue sur « unsupported dictionary type ». Une directive
    # refusee ne se voit qu'a la remise du premier courrier, quand il est trop
    # tard pour faire le lien. On lit donc ce que cette installation sait lire.
    # L'ORDRE DE PREFERENCE EST LE NOTRE, PAS CELUI DE `postconf -m`.
    #
    # Une premiere version filtrait la sortie de postconf avec `grep -m1` : elle
    # rendait donc le premier type dans l'ordre ALPHABETIQUE, soit `btree`,
    # quand on voulait `lmdb`. Le resultat marchait — et n'etait pas celui
    # qu'on avait ecrit, ce qui est la definition d'un piege a retardement. On
    # interroge donc type par type, dans NOTRE ordre.
    local type_carte="" supportes
    supportes=$(lxc-attach -n "$CONTAINER" -- postconf -m 2>/dev/null)
    for t in lmdb hash btree; do
        if printf '%s\n' "$supportes" | grep -qx "$t"; then
            type_carte="$t"
            break
        fi
    done
    if [ -z "$type_carte" ]; then
        echo "postfix n'annonce ni lmdb, ni hash, ni btree — carte non compilee" >&2
        return 1
    fi

    lxc-attach -n "$CONTAINER" -- postconf -e \
        "virtual_alias_maps = ${type_carte}:/etc/mail-config/virtual" >/dev/null 2>&1
    lxc-attach -n "$CONTAINER" -- postconf -e \
        "virtual_alias_domains = $alias_dom" >/dev/null 2>&1
    lxc-attach -n "$CONTAINER" -- postmap "${type_carte}:/etc/mail-config/virtual" 2>/dev/null

    # LA CONFIGURATION EST VERIFIEE AVANT D'ETRE APPLIQUEE. Un `postconf -e`
    # fautif ne se voit qu'au prochain demarrage — c'est-a-dire, en pratique,
    # au prochain incident.
    if ! lxc-attach -n "$CONTAINER" -- postfix check 2>&1 | grep -q .; then
        lxc-attach -n "$CONTAINER" -- postfix reload >/dev/null 2>&1 || true
    else
        echo "postfix check a signale un probleme — rechargement NON effectue" >&2
        lxc-attach -n "$CONTAINER" -- postfix check 2>&1 | head -5 >&2
        return 1
    fi
    [ -n "$nouvel_alias" ] && return 0
    return 0
}

alias_del() {
    local alias="$1"

    if [ -z "$alias" ]; then
        echo "Usage: alias_del <alias@domain>"
        return 1
    fi

    if [ -f "$CONFIG_PATH/virtual" ]; then
        sed -i "/^${alias} /d" "$CONFIG_PATH/virtual"
    fi

    # Meme recompilation qu'a l'ajout (#1025) : un alias retire d'un fichier
    # dont la carte n'est pas refaite continue de rediriger. Une suppression
    # qui ne supprime pas est plus dangereuse qu'un ajout qui n'ajoute pas.
    alias_recompile

    echo "Alias deleted: $alias"
}

alias_list() {
    echo "Email Aliases:"
    echo "=============="

    if [ ! -f "$CONFIG_PATH/virtual" ] || [ ! -s "$CONFIG_PATH/virtual" ]; then
        echo "  No aliases configured"
        return 0
    fi

    while read -r alias target; do
        [ -n "$alias" ] && echo "  $alias -> $target"
    done < "$CONFIG_PATH/virtual"
}
