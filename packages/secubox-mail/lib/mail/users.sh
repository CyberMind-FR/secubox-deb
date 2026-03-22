#!/bin/bash
# SecuBox Mail - User Management Library

DATA_PATH="${DATA_PATH:-/srv/mail}"
CONFIG_PATH="$DATA_PATH/config"
CONTAINER="${MAIL_CONTAINER:-mailserver}"
LXC_PATH="/srv/lxc/$CONTAINER"

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

    # Copy to container
    if [ -d "$LXC_PATH/rootfs" ]; then
        cp "$CONFIG_PATH/virtual" "$LXC_PATH/rootfs/etc/postfix/virtual"

        if lxc-info -n "$CONTAINER" 2>/dev/null | grep -q "RUNNING"; then
            lxc-attach -n "$CONTAINER" -- postmap lmdb:/etc/postfix/virtual 2>/dev/null
        fi
    fi

    echo "Alias added: $alias -> $target"
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

    # Copy to container
    if [ -d "$LXC_PATH/rootfs" ]; then
        cp "$CONFIG_PATH/virtual" "$LXC_PATH/rootfs/etc/postfix/virtual" 2>/dev/null

        if lxc-info -n "$CONTAINER" 2>/dev/null | grep -q "RUNNING"; then
            lxc-attach -n "$CONTAINER" -- postmap lmdb:/etc/postfix/virtual 2>/dev/null
        fi
    fi

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
