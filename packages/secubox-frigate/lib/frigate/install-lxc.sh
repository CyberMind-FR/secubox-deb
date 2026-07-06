#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-frigate :: install-lxc.sh
# CyberMind — https://cybermind.fr
#
# Idempotent native-LXC bootstrap for the Frigate NVR module. Safe to re-run.
# Follows docs/MODULE-GUIDELINES.md §3 (mirror of photoprism / peertube).
#
# Frigate runs as a podman container INSIDE a dedicated Debian LXC, with
# `--network=host` (an unprivileged LXC can't bring up a podman CNI bridge).
# Podman is never driven by the .deb/postinst — only the LXC's own systemd
# (via the frigate.service unit dropped in by this script) starts/stops it.
# Config lives on the host at /etc/secubox/frigate (bind-mounted to /config)
# and recordings/clips/exports/db under /data/frigate (bind-mounted to
# /media/frigate).

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-frigate}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.140}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly DATA_DIR="${SECUBOX_DATA_DIR:-/data/frigate}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/frigate}"
readonly CONFIG_DIR="${SECUBOX_FRIGATE_CONFIG:-/etc/secubox/frigate}"
readonly IMAGE="${SECUBOX_FRIGATE_IMAGE:-ghcr.io/blakeblackshear/frigate:0.14.1}"
readonly HTTP_PORT="${SECUBOX_FRIGATE_PORT:-5000}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
readonly LXC_ROOT_UID="${SECUBOX_LXC_ROOT_UID:-100000}"

# Directory this script lives in — used to locate the sibling frigate.container
# unit regardless of whether we're running from the source tree
# (packages/secubox-frigate/lib/frigate/) or the installed path
# (/usr/share/secubox/lib/frigate/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

log()  { printf '[frigate-install] %s\n' "$*"; }
fail() { printf '[frigate-install] ERROR: %s\n' "$*" >&2; exit 1; }
la() { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

# ── Preflight ────────────────────────────────────────────────────────────────
require_cmds() {
    for c in lxc-create lxc-info lxc-start lxc-attach openssl; do
        command -v "$c" >/dev/null 2>&1 || fail "$c not installed"
    done
}

ensure_dirs() {
    install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 "$STATE_DIR" 2>/dev/null || true
    install -d -m 0755 "$CONFIG_DIR"
    install -d -m 0750 "$DATA_DIR/db" "$DATA_DIR/recordings" "$DATA_DIR/clips" "$DATA_DIR/exports"
    chown -R "$LXC_ROOT_UID:$LXC_ROOT_UID" "$DATA_DIR"
    chown "$LXC_ROOT_UID:$LXC_ROOT_UID" "$CONFIG_DIR"
}

install_config() {
    if [ ! -f "$CONFIG_DIR/config.yml" ]; then
        log "Seeding $CONFIG_DIR/config.yml from example"
        install -m 0640 /usr/share/secubox/frigate/frigate.config.yml.example "$CONFIG_DIR/config.yml"
        chown "$LXC_ROOT_UID:$LXC_ROOT_UID" "$CONFIG_DIR/config.yml"
    fi
}

ensure_bridge() {
    if ! ip link show "$LXC_BRIDGE" >/dev/null 2>&1; then
        log "Creating bridge $LXC_BRIDGE @ ${LXC_GW}/24 ..."
        ip link add name "$LXC_BRIDGE" type bridge
        ip addr add "${LXC_GW}/24" dev "$LXC_BRIDGE"
        ip link set "$LXC_BRIDGE" up
        cat > /etc/systemd/network/10-secubox-lxc-bridge.netdev <<EOF
[NetDev]
Name=$LXC_BRIDGE
Kind=bridge
EOF
        cat > /etc/systemd/network/10-secubox-lxc-bridge.network <<EOF
[Match]
Name=$LXC_BRIDGE

[Network]
Address=${LXC_GW}/24
ConfigureWithoutCarrier=yes
IPMasquerade=ipv4
EOF
        systemctl reload systemd-networkd 2>/dev/null || true
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

# ── LXC lifecycle ────────────────────────────────────────────────────────────
lxc_state() {
    lxc-info -n "$LXC_NAME" -P "$LXC_PATH" 2>/dev/null \
        | awk -F: '/^State:/ { gsub(/ /,"",$2); print tolower($2) }'
}

create_lxc() {
    if [ -d "$LXC_PATH/$LXC_NAME/rootfs" ]; then
        log "LXC '$LXC_NAME' already exists — skipping debootstrap"
        return
    fi
    log "Creating LXC '$LXC_NAME' (debian $DEBIAN_SUITE) ..."
    lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" -- \
        --dist debian --release "$DEBIAN_SUITE" --arch "$(dpkg --print-architecture)"
}

write_lxc_config() {
    log "Pinning LXC network: $LXC_IP/24 on $LXC_BRIDGE; bind mounts"
    cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
# SecuBox-managed — see secubox-frigate / install-lxc.sh
lxc.include = /usr/share/lxc/config/debian.common.conf
lxc.arch = linux64

lxc.idmap = u 0 $LXC_ROOT_UID 65536
lxc.idmap = g 0 $LXC_ROOT_UID 65536

lxc.rootfs.path = dir:$LXC_PATH/$LXC_NAME/rootfs
lxc.uts.name = $LXC_NAME

lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
lxc.net.0.name = eth0

# Config (host /etc/secubox/frigate) + media (host /data/frigate) bind mounts.
lxc.mount.entry = $CONFIG_DIR config none bind,create=dir 0 0
lxc.mount.entry = $DATA_DIR media/frigate none bind,create=dir 0 0

lxc.cgroup2.memory.high = 1500M
lxc.cgroup2.memory.max = 2G

lxc.start.auto = 1
lxc.start.delay = 5
EOF
}

ensure_resolv() {
    log "Seeding /etc/resolv.conf in LXC ..."
    la sh -c 'rm -f /etc/resolv.conf; printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf'
}

start_lxc() {
    [ "$(lxc_state)" = "running" ] && { log "LXC already running"; return; }
    log "Starting LXC '$LXC_NAME' ..."
    lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
}

wait_for_network() {
    log "Waiting for LXC network ..."
    for _ in $(seq 1 30); do
        la ping -c1 -W1 "$LXC_GW" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "LXC did not reach $LXC_GW within 30s"
}

# ── Frigate (podman) install inside LXC ──────────────────────────────────────
install_frigate_in_lxc() {
    log "Dropping frigate.service unit into '$LXC_NAME' rootfs ..."
    install -D -m 0644 "$SCRIPT_DIR/frigate.container" \
        "$LXC_PATH/$LXC_NAME/rootfs/etc/systemd/system/frigate.service"

    log "Installing podman + Frigate in '$LXC_NAME' ..."
    la env \
        DEBIAN_FRONTEND=noninteractive LC_ALL=C LANG=C \
        IMAGE="$IMAGE" \
        bash -e <<'INNER'
set -euo pipefail
echo '[1/3] podman'
apt-get update -q
apt-get install -y -q --no-install-recommends podman ca-certificates curl
command -v podman >/dev/null 2>&1 || { echo 'podman not installed' >&2; exit 1; }

echo '[2/3] pull image'
podman pull "$IMAGE"

echo '[3/3] enable frigate.service'
systemctl daemon-reload
systemctl enable --now frigate.service
echo '=== Frigate install complete ==='
INNER
}

verify() {
    log "Verifying Frigate on $LXC_IP:$HTTP_PORT ..."
    for _ in $(seq 1 30); do
        curl -fsS -o /dev/null --max-time 3 "http://$LXC_IP:$HTTP_PORT/" && { log "OK — responding."; return 0; }
        sleep 2
    done
    log "WARN: not responding yet (first boot can take a while; check 'journalctl' inside the LXC)."
}

mark_provisioned() { date -Iseconds > "$SENTINEL"; }

main() {
    require_cmds
    ensure_dirs
    install_config
    ensure_bridge
    ensure_masquerade
    create_lxc
    write_lxc_config
    start_lxc
    wait_for_network
    ensure_resolv
    install_frigate_in_lxc
    verify
    mark_provisioned
    log "Done — LXC '$LXC_NAME' at $LXC_IP, Frigate running."
    log "Config: $CONFIG_DIR/config.yml  Media: $DATA_DIR"
}

main "$@"
