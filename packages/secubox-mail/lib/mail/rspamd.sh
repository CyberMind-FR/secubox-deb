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
# Render 8 of the 9 local.d templates inside the live LXC via `lxc-attach`
# (worker-controller.inc is handled separately because it bind-mounts
# secrets.inc). Set up host-side data dirs + bind-mount entries.
#
# Phase 2 lesson (commit 637b2221): writing through the host-side rootfs path
# `${LXC_BASE}/${container}/rootfs/etc/rspamd/local.d/` is brittle — on this
# board the runtime rootfs lives at `/data/lxc/mail/rootfs/` per `lxc.rootfs.
# path`, while `/var/lib/lxc/mail/rootfs/` is a stale shell that the running
# LXC does not see. Streaming each file through `lxc-attach -- tee` avoids
# guessing the rootfs path and lets the kernel resolve idmap on writes.
configure_rspamd_milter() {
    local container="$1"
    [ -n "$container" ] || { echo "configure_rspamd_milter: container required" >&2; return 1; }
    local templates="${TEMPLATES_DIR:-/usr/lib/secubox/mail/templates}/rspamd"
    local data="${DATA_PATH:-/data/volumes/mail}"

    if ! lxc-info -n "$container" 2>/dev/null | grep -q "State:.*RUNNING"; then
        echo "configure_rspamd_milter: LXC '$container' is not running" >&2
        return 1
    fi

    lxc-attach -n "$container" -- install -d -m 0755 /etc/rspamd/local.d
    for f in options.inc worker-proxy.inc worker-normal.inc \
             dkim_signing.conf arc.conf dmarc.conf \
             greylist.conf ratelimit.conf; do
        [ -f "$templates/local.d/$f" ] || {
            echo "configure_rspamd_milter: template $templates/local.d/$f missing" >&2
            return 1
        }
        lxc-attach -n "$container" -- tee "/etc/rspamd/local.d/$f" >/dev/null < "$templates/local.d/$f"
        lxc-attach -n "$container" -- chmod 0644 "/etc/rspamd/local.d/$f"
    done

    # Persistent data dirs on host — chown via lxc-attach so the kernel maps
    # _rspamd uid (varies per image: 107 in Debian 12 default; 110 in some
    # rspamd-only minimal builds) to the right outside-LXC subuid.
    install -d -m 0750 "$data/rspamd/dkim" "$data/rspamd/bayes" \
                       "$data/rspamd/history" "$data/rspamd/settings"

    # Add bind-mount entries to the LXC config (idempotent). Note: requires
    # a `lxc-stop && lxc-start` cycle of the container to activate — these
    # entries are not pickup-on-the-fly. Caller (mailctl) is expected to do
    # the restart before generating DKIM keys.
    local lxc_conf="${LXC_BASE:-/var/lib/lxc}/$container/config"
    if [ -f "$lxc_conf" ] && ! grep -q "/etc/rspamd-keys" "$lxc_conf"; then
        cat >> "$lxc_conf" <<EOF

# Phase 2 Rspamd bind mounts (added by configure_rspamd_milter)
lxc.mount.entry = $data/rspamd/dkim    etc/rspamd-keys              none bind,create=dir 0 0
lxc.mount.entry = $data/rspamd/bayes   var/lib/rspamd/bayes         none bind,create=dir 0 0
lxc.mount.entry = $data/rspamd/history var/lib/rspamd/history       none bind,create=dir 0 0
lxc.mount.entry = $data/rspamd/settings var/lib/rspamd/settings     none bind,create=dir 0 0
EOF
        echo "[rspamd] bind-mount entries appended to $lxc_conf — restart $container to activate"
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
    local secret_host="/etc/secubox/secrets/rspamd-controller.pw"

    if ! lxc-info -n "$container" 2>/dev/null | grep -q "State:.*RUNNING"; then
        echo "configure_rspamd_controller: LXC '$container' is not running" >&2
        return 1
    fi

    install -d -m 0700 /etc/secubox/secrets
    if [ ! -s "$secret_host" ]; then
        openssl rand -base64 24 > "$secret_host"
        chmod 0600 "$secret_host"
    fi

    [ -f "$templates/local.d/worker-controller.inc" ] || {
        echo "configure_rspamd_controller: template worker-controller.inc missing" >&2
        return 1
    }
    lxc-attach -n "$container" -- tee /etc/rspamd/local.d/worker-controller.inc >/dev/null \
        < "$templates/local.d/worker-controller.inc"
    lxc-attach -n "$container" -- chmod 0644 /etc/rspamd/local.d/worker-controller.inc

    local pw
    pw=$(tr -d '\n' < "$secret_host")
    lxc-attach -n "$container" -- tee /etc/rspamd/local.d/secrets.inc >/dev/null <<EOF_INC
password = "$pw";
enable_password = "$pw";
EOF_INC
    # Resolve _rspamd uid/gid via the LXC itself — the host's 100110 ≠ _rspamd
    # on all Debian images (107 on the Phase 2 deploy image). Run chown from
    # inside the container so the kernel applies idmap automatically.
    lxc-attach -n "$container" -- chown _rspamd:_rspamd /etc/rspamd/local.d/secrets.inc 2>/dev/null || true
    lxc-attach -n "$container" -- chmod 0640 /etc/rspamd/local.d/secrets.inc 2>/dev/null || true
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

    [ -n "$container" ] || { echo "configure_rspamd_dkim: container required" >&2; return 1; }
    install -d -m 0750 "$data/rspamd/dkim/$domain"

    if [ ! -f "$data/rspamd/dkim/$domain/$selector.key" ]; then
        rspamd_keygen "$container" "$domain" "$selector"
    fi
}

# Generate a 2048-bit DKIM keypair via `rspamadm dkim_keygen` *inside* the
# named LXC — rspamadm is shipped by the rspamd package and is only on PATH
# inside the container. Phase 2 lesson (commit 637b2221): the previous host-
# side variant errored out with "rspamadm not on PATH".
rspamd_keygen() {
    local container="$1"
    local domain="$2"
    local selector="${3:-default}"
    local data="${DATA_PATH:-/data/volumes/mail}"

    [ -n "$container" ] || { echo "rspamd_keygen: container required" >&2; return 1; }
    [ -n "$domain" ]    || { echo "rspamd_keygen: domain required" >&2; return 1; }
    if ! lxc-info -n "$container" 2>/dev/null | grep -q "State:.*RUNNING"; then
        echo "rspamd_keygen: LXC '$container' is not running" >&2
        return 1
    fi

    # Output dir inside the LXC — relies on the `/etc/rspamd-keys` bind mount
    # added by configure_rspamd_milter. If that mount isn't active, fall back
    # to writing into /var/lib/rspamd which is always present in the LXC.
    local outdir="/etc/rspamd-keys/$domain"
    if ! lxc-attach -n "$container" -- test -d /etc/rspamd-keys 2>/dev/null; then
        outdir="/var/lib/rspamd/dkim/$domain"
        echo "[rspamd] /etc/rspamd-keys bind mount not active — falling back to $outdir" >&2
    fi

    lxc-attach -n "$container" -- install -d -m 0750 "$outdir"
    lxc-attach -n "$container" -- chown _rspamd:_rspamd "$outdir" 2>/dev/null || true

    # rspamadm writes the key to -k <path> and prints the DNS TXT to stdout.
    # Capture the TXT alongside the key.
    lxc-attach -n "$container" -- bash -c "
        set -euo pipefail
        rspamadm dkim_keygen -d '$domain' -s '$selector' -b 2048 \
            -k '$outdir/$selector.key' > '$outdir/$selector.txt'
        chown _rspamd:_rspamd '$outdir/$selector.key' '$outdir/$selector.txt'
        chmod 0600 '$outdir/$selector.key'
        chmod 0644 '$outdir/$selector.txt'
    "

    # Mirror the public TXT to the host-side data dir so external tooling
    # (e.g. DNS-publishing scripts on the orchestrator) can read it without
    # entering the LXC.
    local host_dir="$data/rspamd/dkim/$domain"
    install -d -m 0750 "$host_dir"
    if [ "$outdir" = "/etc/rspamd-keys/$domain" ]; then
        # Bind-mount path — already visible at $host_dir on the host.
        :
    else
        # Fallback path inside the LXC rootfs; copy out via lxc-attach.
        lxc-attach -n "$container" -- cat "$outdir/$selector.txt" > "$host_dir/$selector.txt"
    fi
    echo "[rspamd] DKIM keypair generated: $outdir/$selector.key (DNS TXT in $host_dir/$selector.txt)"
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
