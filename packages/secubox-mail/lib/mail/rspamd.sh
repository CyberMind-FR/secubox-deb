#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: mail :: Phase 2 Rspamd helpers (install + configure + dkim).
# Sourced library — do not execute directly.

# Re-entry guard — Phase 1 lesson. If a parent process re-sources this lib in
# a tight loop (e.g. through a deprecated shim that exec's back to mailctl)
# we will see SECUBOX_RSPAMD_SH_LOADED set and abort to break the recursion.
if [ "${_SECUBOX_RSPAMD_SH_LOADED:-0}" = "1" ]; then
    echo "rspamd.sh re-loaded — possible recursion, aborting" >&2
    return 1 2>/dev/null || exit 1
fi
export _SECUBOX_RSPAMD_SH_LOADED=1

# ─── install_rspamd ───────────────────────────────────────────────────────────
# Install Rspamd inside the named LXC. Idempotent — reruns are safe.
# Caller must ensure the LXC is RUNNING (we apt inside it).
install_rspamd() {
    local container="$1"
    [ -n "$container" ] || { echo "install_rspamd: container required" >&2; return 1; }
    if ! lxc-info -n "$container" 2>/dev/null | grep -q "State:.*RUNNING"; then
        echo "install_rspamd: LXC '$container' is not running" >&2
        return 1
    fi

    echo "[rspamd] installing inside LXC $container..."
    lxc-attach -n "$container" -- bash -c '
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        if dpkg -l rspamd 2>/dev/null | grep -q "^ii"; then
            echo "[rspamd] already installed"
            exit 0
        fi
        apt-get update -qq
        apt-get install -y --no-install-recommends rspamd redis-server
        # Redis is here as the future bayes/ratelimit backend; Phase 2 uses
        # sqlite defaults but having Redis installed means a Phase 8 switch
        # is config-only, not apt.
        systemctl disable redis-server.service 2>/dev/null || true
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    '
    echo "[rspamd] package installed in $container"
}

# ─── configure_rspamd_milter ──────────────────────────────────────────────────
# Copy 8 of the 9 local.d templates into the LXC (worker-controller.inc is
# handled separately because it bind-mounts secrets.inc). Set up data dirs +
# bind-mount entries.
configure_rspamd_milter() {
    local container="$1"
    [ -n "$container" ] || { echo "configure_rspamd_milter: container required" >&2; return 1; }
    local templates="${TEMPLATES_DIR:-/usr/lib/secubox/mail/templates}/rspamd"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"
    local data="${DATA_PATH:-/data/volumes/mail}"
    local local_d="$rootfs/etc/rspamd/local.d"

    install -d -m 0755 "$local_d"
    for f in options.inc worker-proxy.inc worker-normal.inc \
             dkim_signing.conf arc.conf dmarc.conf \
             greylist.conf ratelimit.conf; do
        install -m 0644 "$templates/local.d/$f" "$local_d/$f"
    done

    # Persistent data dirs on host — owner 100110:100110 = _rspamd inside unprivileged LXC.
    install -d -m 0750 "$data/rspamd/dkim" "$data/rspamd/bayes" \
                       "$data/rspamd/history" "$data/rspamd/settings"
    chown -R 100110:100110 "$data/rspamd" 2>/dev/null || true

    # Add bind-mount entries to the LXC config (idempotent).
    local lxc_conf="${LXC_BASE:-/var/lib/lxc}/$container/config"
    if [ -f "$lxc_conf" ] && ! grep -q "/etc/rspamd-keys" "$lxc_conf"; then
        cat >> "$lxc_conf" <<EOF
lxc.mount.entry = $data/rspamd/dkim    etc/rspamd-keys              none bind,create=dir 0 0
lxc.mount.entry = $data/rspamd/bayes   var/lib/rspamd/bayes         none bind,create=dir 0 0
lxc.mount.entry = $data/rspamd/history var/lib/rspamd/history       none bind,create=dir 0 0
lxc.mount.entry = $data/rspamd/settings var/lib/rspamd/settings     none bind,create=dir 0 0
EOF
    fi
    echo "[rspamd] milter config rendered in $container"
}

# ─── configure_rspamd_controller ──────────────────────────────────────────────
# Provision the controller password on the host + render secrets.inc inside the
# LXC. Phase 2 uses plaintext password protected by filesystem ACL; Phase 8 may
# switch to a hashed password (rspamadm pw -e).
configure_rspamd_controller() {
    local container="$1"
    [ -n "$container" ] || { echo "configure_rspamd_controller: container required" >&2; return 1; }
    local templates="${TEMPLATES_DIR:-/usr/lib/secubox/mail/templates}/rspamd"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"
    local local_d="$rootfs/etc/rspamd/local.d"
    local secret_host="/etc/secubox/secrets/rspamd-controller.pw"

    install -d -m 0700 /etc/secubox/secrets
    if [ ! -s "$secret_host" ]; then
        openssl rand -base64 24 > "$secret_host"
        chmod 0600 "$secret_host"
    fi
    install -m 0644 "$templates/local.d/worker-controller.inc" "$local_d/worker-controller.inc"

    local pw
    pw=$(tr -d '\n' < "$secret_host")
    cat > "$local_d/secrets.inc" <<EOF_INC
password = "$pw";
enable_password = "$pw";
EOF_INC
    chmod 0600 "$local_d/secrets.inc"
    chown 100110:100110 "$local_d/secrets.inc" 2>/dev/null || true
    echo "[rspamd] controller secret provisioned"
}

# ─── configure_rspamd_postfix_milter ──────────────────────────────────────────
# Append the smtpd_milters block to Postfix main.cf. Idempotent — looks for
# the unique sentinel comment before appending.
configure_rspamd_postfix_milter() {
    local container="$1"
    local main_cf="${DATA_PATH:-/data/volumes/mail}/config/main.cf"
    local templates="${TEMPLATES_DIR:-/usr/lib/secubox/mail/templates}/rspamd"
    if grep -q "Phase 2 Rspamd milter" "$main_cf" 2>/dev/null; then
        echo "[rspamd] Postfix milter snippet already present in $main_cf"
        return 0
    fi
    cat "$templates/postfix-milter-snippet.cf" >> "$main_cf"
    echo "[rspamd] appended Postfix milter snippet to $main_cf"
}

# ─── configure_rspamd_dkim / rspamd_keygen / rspamd_dns_records ───────────────
configure_rspamd_dkim() {
    local container="$1"
    local domain="${2:-secubox.in}"
    local selector="${3:-default}"
    local data="${DATA_PATH:-/data/volumes/mail}"

    install -d -m 0750 "$data/rspamd/dkim/$domain"
    chown -R 100110:100110 "$data/rspamd/dkim" 2>/dev/null || true

    if [ ! -f "$data/rspamd/dkim/$domain/$selector.key" ]; then
        rspamd_keygen "$domain" "$selector"
    fi
}

rspamd_keygen() {
    local domain="$1"
    local selector="${2:-default}"
    local data="${DATA_PATH:-/data/volumes/mail}"
    local outdir="$data/rspamd/dkim/$domain"
    install -d -m 0750 "$outdir"
    local keyfile="$outdir/$selector.key"
    local txtfile="$outdir/$selector.txt"

    if ! command -v rspamadm >/dev/null 2>&1; then
        echo "rspamd_keygen: rspamadm not on PATH (run install_rspamd first or run inside LXC)" >&2
        return 1
    fi

    rspamadm dkim_keygen -d "$domain" -s "$selector" -b 2048 -k "$keyfile" > "$txtfile"
    chmod 0600 "$keyfile"
    chown 100110:100110 "$keyfile" "$txtfile" 2>/dev/null || true
    echo "[rspamd] DKIM keypair generated: $keyfile (+ DNS TXT in $txtfile)"
}

rspamd_dns_records() {
    local domain="$1"
    local selector="${2:-default}"
    local data="${DATA_PATH:-/data/volumes/mail}"
    local txtfile="$data/rspamd/dkim/$domain/$selector.txt"
    [ -f "$txtfile" ] || { echo "no DNS record for $domain/$selector" >&2; return 1; }
    cat "$txtfile"
}

# ─── rspamd_purge_legacy ──────────────────────────────────────────────────────
# Per spec D9: refuse to purge SA/OpenDKIM unless Rspamd is healthy.
rspamd_purge_legacy() {
    local container="$1"
    [ -n "$container" ] || { echo "rspamd_purge_legacy: container required" >&2; return 1; }

    if ! lxc-attach -n "$container" -- rspamc -h 127.0.0.1:11334 stat >/dev/null 2>&1; then
        echo "rspamd_purge_legacy: refusing — Rspamd not healthy on $container:11334" >&2
        return 1
    fi

    echo "[rspamd] Rspamd healthy; purging SA + OpenDKIM from $container..."
    lxc-attach -n "$container" -- bash -c '
        systemctl stop opendkim spamassassin spamd 2>/dev/null || true
        systemctl disable opendkim spamassassin spamd 2>/dev/null || true
        export DEBIAN_FRONTEND=noninteractive
        apt-get purge -y opendkim opendkim-tools spamassassin spamc spamd 2>&1 | tail -3
    '
    echo "[rspamd] legacy purge complete"
}
