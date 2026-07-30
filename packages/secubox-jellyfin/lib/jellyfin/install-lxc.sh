#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-jellyfin :: install-lxc.sh
#
# Idempotent LXC bootstrap for the Jellyfin media server. Safe to re-run.
# Mirrors packages/secubox-lyrion/lib/lyrion/install-lxc.sh:
#   1. lxc-create -t download (unprivileged-compatible, idmap 0->100000)
#   2. ensure_masquerade() 10.100.0.0/24
#   3. ensure_resolv() via lxc-attach
#   4. official Jellyfin apt repo + `apt-get install jellyfin` INSIDE the LXC
# The .deb work (arch-specific) happens in the container; the host package is
# arch: all. Follows docs/MODULE-GUIDELINES.md §3.

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-jellyfin}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.170}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly JELLYFIN_PORT="${SECUBOX_JELLYFIN_PORT:-8096}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/etc/secubox/jellyfin}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly APIKEY_FILE="${SECUBOX_JELLYFIN_APIKEY:-$SECRETS_DIR/jellyfin-apikey}"
readonly LIBRARIES_JSON="${SECUBOX_JELLYFIN_LIBRARIES:-$STATE_DIR/libraries.json}"
readonly APIKEY_OWNER="${SECUBOX_JELLYFIN_USER:-secubox-jellyfin}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"

log()  { printf '[jellyfin-install] %s\n' "$*"; }
fail() { printf '[jellyfin-install] ERROR: %s\n' "$*" >&2; exit 1; }

require_cmds() {
    for c in lxc-create lxc-info lxc-start lxc-attach openssl nft; do
        command -v "$c" >/dev/null 2>&1 || fail "$c not installed"
    done
}

ensure_dirs() {
    install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 -o root -g root "$STATE_DIR"
    install -d -m 0700 -o root -g root "$SECRETS_DIR"
}

ensure_bridge() {
    if ! ip link show "$LXC_BRIDGE" >/dev/null 2>&1; then
        log "Creating bridge $LXC_BRIDGE @ ${LXC_GW}/24 ..."
        ip link add name "$LXC_BRIDGE" type bridge
        ip addr add "${LXC_GW}/24" dev "$LXC_BRIDGE"
        ip link set "$LXC_BRIDGE" up
    fi
}

ensure_masquerade() {
    if ! nft list table ip lxc 2>/dev/null | grep -q 'saddr 10.100.0.0/24'; then
        log "Adding nftables MASQUERADE for 10.100.0.0/24 ..."
        nft 'add table ip lxc' 2>/dev/null || true
        nft 'add chain ip lxc postrouting { type nat hook postrouting priority srcnat ; policy accept ; }' 2>/dev/null || true
        nft 'add rule ip lxc postrouting ip saddr 10.100.0.0/24 ip daddr != 10.100.0.0/24 counter masquerade' 2>/dev/null || true
    fi
}

lxc_state() {
    lxc-info -n "$LXC_NAME" -P "$LXC_PATH" 2>/dev/null \
        | awk -F: '/^State:/ { gsub(/ /,"",$2); print tolower($2) }' || true
}

create_lxc() {
    if [ -d "$LXC_PATH/$LXC_NAME/rootfs" ]; then
        log "LXC '$LXC_NAME' already exists — skipping debootstrap"
        return
    fi
    log "Creating unprivileged LXC '$LXC_NAME' (debian $DEBIAN_SUITE) ..."
    lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" \
        -- --dist debian --release "$DEBIAN_SUITE" \
           --arch "$(dpkg --print-architecture)"
}

# Base config — overwritten idempotently each run; partner RO binds are
# re-applied AFTER this from libraries.json (reapply_binds).
write_lxc_config() {
    log "Pinning network: $LXC_IP/24 on $LXC_BRIDGE (idmap 0->100000)"
    cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
# SecuBox-managed — see secubox-jellyfin / install-lxc.sh
lxc.uts.name = $LXC_NAME
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
lxc.net.0.name = eth0
lxc.rootfs.path = dir:$LXC_PATH/$LXC_NAME/rootfs
lxc.include = /usr/share/lxc/config/common.conf
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536
lxc.apparmor.profile = generated
lxc.start.auto = 1
lxc.start.delay = 5
EOF
}

# Re-apply any partner RO binds recorded in libraries.json (idempotent). Must
# run BEFORE start_lxc so the mounts exist when the container comes up.
reapply_binds() {
    [ -f "$LIBRARIES_JSON" ] || return 0
    command -v jq >/dev/null 2>&1 || { log "jq absent — skipping bind re-apply"; return 0; }
    local cfg="$LXC_PATH/$LXC_NAME/config" name host
    while IFS=$'\t' read -r name host; do
        [ -n "$name" ] && [ -n "$host" ] || continue
        grep -qF " media/$name none bind" "$cfg" && continue
        printf 'lxc.mount.entry = %s media/%s none bind,ro,create=dir 0 0\n' "$host" "$name" >> "$cfg"
        log "re-applied RO bind: $host -> media/$name"
    done < <(jq -r '(.libraries // [])[] | [.name, (.host_path // "")] | @tsv' "$LIBRARIES_JSON" 2>/dev/null || true)
}

start_lxc() {
    [ "$(lxc_state)" = "running" ] && { log "Already running"; return; }
    log "Starting LXC '$LXC_NAME' ..."
    lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
}

wait_for_network() {
    log "Waiting for LXC network ..."
    for _ in $(seq 1 30); do
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- ping -c1 -W1 "$LXC_GW" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "LXC '$LXC_NAME' did not reach $LXC_GW within 30s"
}

ensure_resolv() {
    log "Seeding /etc/resolv.conf in LXC ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c '
        rm -f /etc/resolv.conf
        printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf
    '
}

# ── Jellyfin install inside LXC (official apt repo) ────────────────────────────
# Jellyfin ships an official apt repo at https://repo.jellyfin.org/debian with
# arm64 packages. The `jellyfin` metapackage pulls jellyfin-server +
# jellyfin-web + ffmpeg and installs jellyfin.service (listens on :8096).
install_jellyfin_in_lxc() {
    log "Installing Jellyfin server in '$LXC_NAME' ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- bash -e <<'INNER'
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        apt-get install -y --no-install-recommends ca-certificates gnupg curl

        install -d -m 0755 /etc/apt/keyrings
        if [ ! -s /etc/apt/keyrings/jellyfin.gpg ]; then
            curl -fsSL https://repo.jellyfin.org/debian/jellyfin_team.gpg.key \
                | gpg --dearmor -o /etc/apt/keyrings/jellyfin.gpg
        fi

        ARCH="$(dpkg --print-architecture)"
        CODENAME="$(. /etc/os-release; echo "${VERSION_CODENAME:-bookworm}")"
        cat > /etc/apt/sources.list.d/jellyfin.sources <<SRC
Types: deb
URIs: https://repo.jellyfin.org/debian
Suites: ${CODENAME}
Components: main
Architectures: ${ARCH}
Signed-By: /etc/apt/keyrings/jellyfin.gpg
SRC

        if ! dpkg -l jellyfin-server 2>/dev/null | grep -q '^ii'; then
            apt-get update -q
            apt-get install -y jellyfin
        else
            echo "jellyfin-server already installed — skipping apt install"
        fi

        systemctl daemon-reload
        systemctl enable jellyfin 2>/dev/null || systemctl enable jellyfin.service 2>/dev/null || true
INNER
}

# Mint an API key placeholder if absent. NOTE: Jellyfin API keys are normally
# registered post-setup via the admin UI; this stores a stable secret (0600,
# owned by the module user) that the wiring flow presents as X-Emby-Token. If
# Jellyfin's first-run wizard has not registered it yet, virtual-folder calls
# degrade gracefully (jellyfinctl warns; binds/state still recorded).
mint_apikey() {
    if [ ! -s "$APIKEY_FILE" ]; then
        log "Minting Jellyfin API key -> $APIKEY_FILE"
        openssl rand -hex 16 > "$APIKEY_FILE"
    fi
    chown "$APIKEY_OWNER":"$APIKEY_OWNER" "$APIKEY_FILE" 2>/dev/null \
        || chown root:root "$APIKEY_FILE" 2>/dev/null || true
    chmod 0600 "$APIKEY_FILE"
}

start_jellyfin_service() {
    log "Starting jellyfin.service ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl restart jellyfin 2>/dev/null \
        || lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl restart jellyfin.service 2>/dev/null || true
}

mark_provisioned() {
    install -d -m 0755 -o root -g root "$STATE_DIR"
    date -Iseconds > "$SENTINEL"
}

main() {
    require_cmds
    ensure_dirs
    ensure_bridge
    ensure_masquerade
    create_lxc
    write_lxc_config
    reapply_binds
    start_lxc
    wait_for_network
    ensure_resolv
    install_jellyfin_in_lxc
    mint_apikey
    start_jellyfin_service
    mark_provisioned
    log "OK — LXC '$LXC_NAME' at $LXC_IP, Jellyfin provisioned + running."
    log "  · Web UI (LXC)  : http://$LXC_IP:$JELLYFIN_PORT/"
    log "  · API key       : $APIKEY_FILE (0600 $APIKEY_OWNER)"
    log "  · Libraries     : $LIBRARIES_JSON"
    log "  · Wire partners : jellyfinctl partner wire --all"
}

main "$@"
