#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-photoprism :: install-lxc.sh
# CyberMind — https://cybermind.fr
#
# Idempotent native-LXC bootstrap for the PhotoPrism module. Safe to re-run.
# Follows docs/MODULE-GUIDELINES.md §3 (mirror of grafana / secubox-peertube).
#
# PhotoPrism runs as a podman container inside a dedicated Debian LXC, with
# `--network=host` (an unprivileged LXC can't bring up a podman CNI bridge on
# the Marvell arm64 boards). Photos live on the host at /data/shared/photos,
# which Nextcloud also mounts (see secubox-nextcloud "PhotoLibrary" external
# storage) — phone → Nextcloud → /data/shared/photos → PhotoPrism originals.

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-photoprism}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.130}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly DATA_DIR="${SECUBOX_DATA_DIR:-/data/photoprism}"
readonly SHARED_PHOTOS="${SECUBOX_SHARED_PHOTOS:-/data/shared/photos}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/photoprism}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
readonly PUBLIC_HOSTNAME="${SECUBOX_PHOTOPRISM_HOSTNAME:-photoprism.gk2.secubox.in}"
readonly IMAGE="${SECUBOX_PHOTOPRISM_IMAGE:-docker.io/photoprism/photoprism:latest}"
readonly HTTP_PORT="${SECUBOX_PHOTOPRISM_PORT:-2342}"
# PhotoPrism's built-in auto-index only fires for its own UI uploads; the
# index timer below catches Nextcloud-synced files. AUTO_INDEX is the delay
# (s) before re-indexing after a UI change; -1 disables.
readonly AUTO_INDEX="${SECUBOX_PHOTOPRISM_AUTO_INDEX:-300}"
readonly LXC_ROOT_UID="${SECUBOX_LXC_ROOT_UID:-100000}"

log()  { printf '[photoprism-install] %s\n' "$*"; }
fail() { printf '[photoprism-install] ERROR: %s\n' "$*" >&2; exit 1; }
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
    install -d -m 0700 -o root -g root "$SECRETS_DIR"
    install -d -m 0750 "$DATA_DIR/storage" "$DATA_DIR/import"
    # Shared photo library — Nextcloud (www-data) writes, PhotoPrism reads.
    # 0777 so both LXCs' service UIDs can use it (both map root→100000, but
    # NC writes as www-data 100033). Acceptable on a single-appliance box.
    install -d -m 0777 "$SHARED_PHOTOS"
    chown -R "$LXC_ROOT_UID:$LXC_ROOT_UID" "$DATA_DIR"
    chown "$LXC_ROOT_UID:$LXC_ROOT_UID" "$SHARED_PHOTOS"
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
# SecuBox-managed — see secubox-photoprism / install-lxc.sh
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

# Shared photo library (Nextcloud writes here) + PhotoPrism-private dirs.
lxc.mount.entry = $SHARED_PHOTOS var/lib/photoprism/originals none bind,create=dir 0 0
lxc.mount.entry = $DATA_DIR/storage var/lib/photoprism/storage none bind,create=dir 0 0
lxc.mount.entry = $DATA_DIR/import var/lib/photoprism/import none bind,create=dir 0 0

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

# ── PhotoPrism (podman) install inside LXC ───────────────────────────────────
install_photoprism_in_lxc() {
    local admin_pw
    admin_pw="$(cat "$SECRETS_DIR/photoprism-admin" 2>/dev/null || true)"
    if [ -z "$admin_pw" ]; then
        admin_pw="$(openssl rand -hex 16)"
        echo "$admin_pw" > "$SECRETS_DIR/photoprism-admin"
        chmod 600 "$SECRETS_DIR/photoprism-admin"
    fi

    log "Installing podman + PhotoPrism in '$LXC_NAME' ..."
    la env \
        ADMIN_PW="$admin_pw" SITE_URL="https://$PUBLIC_HOSTNAME/" \
        IMAGE="$IMAGE" HTTP_PORT="$HTTP_PORT" AUTO_INDEX="$AUTO_INDEX" \
        DEBIAN_FRONTEND=noninteractive LC_ALL=C LANG=C \
        bash -e <<'INNER'
set -euo pipefail
echo '[1/4] podman'
apt-get update -q
apt-get install -y -q --no-install-recommends podman ca-certificates curl

echo '[2/4] pull image'
podman pull "$IMAGE"

echo '[3/4] photoprism.service'
cat > /etc/systemd/system/photoprism.service <<UNIT
[Unit]
Description=PhotoPrism (podman)
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/podman rm -f photoprism
ExecStart=/usr/bin/podman run --rm --name photoprism \\
  --network=host \\
  -v /var/lib/photoprism/originals:/photoprism/originals \\
  -v /var/lib/photoprism/storage:/photoprism/storage \\
  -v /var/lib/photoprism/import:/photoprism/import \\
  -e PHOTOPRISM_ADMIN_USER=admin \\
  -e PHOTOPRISM_ADMIN_PASSWORD=${ADMIN_PW} \\
  -e PHOTOPRISM_DATABASE_DRIVER=sqlite \\
  -e PHOTOPRISM_HTTP_HOST=0.0.0.0 \\
  -e PHOTOPRISM_HTTP_PORT=${HTTP_PORT} \\
  -e PHOTOPRISM_AUTO_INDEX=${AUTO_INDEX} \\
  -e PHOTOPRISM_SITE_URL="${SITE_URL}" \\
  ${IMAGE}
ExecStop=/usr/bin/podman stop photoprism
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

echo '[4/4] index timer (catches Nextcloud-synced files)'
cat > /etc/systemd/system/photoprism-index.service <<'UNIT'
[Unit]
Description=PhotoPrism incremental index (picks up Nextcloud-synced photos)
After=photoprism.service
Requires=photoprism.service

[Service]
Type=oneshot
ExecStart=/usr/bin/podman exec photoprism photoprism index
UNIT
cat > /etc/systemd/system/photoprism-index.timer <<'UNIT'
[Unit]
Description=Run PhotoPrism index every 15 min

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now photoprism.service
systemctl enable --now photoprism-index.timer
echo '=== PhotoPrism install complete ==='
INNER
}

verify() {
    log "Verifying PhotoPrism on $LXC_IP:$HTTP_PORT ..."
    for _ in $(seq 1 30); do
        curl -fsS -o /dev/null --max-time 3 "http://$LXC_IP:$HTTP_PORT/" && { log "OK — responding."; return 0; }
        sleep 2
    done
    log "WARN: not responding yet (first boot can take a while; check 'photoprismctl logs')."
}

mark_provisioned() { date -Iseconds > "$SENTINEL"; }

main() {
    require_cmds
    ensure_dirs
    ensure_bridge
    ensure_masquerade
    create_lxc
    write_lxc_config
    start_lxc
    wait_for_network
    ensure_resolv
    install_photoprism_in_lxc
    verify
    mark_provisioned
    log "Done — LXC '$LXC_NAME' at $LXC_IP, PhotoPrism running."
    log "Admin: admin / $(cat "$SECRETS_DIR/photoprism-admin")  (rotate via UI)."
    log "Public (wire HAProxy SNI + nginx vhost): https://$PUBLIC_HOSTNAME/"
    log "Nextcloud side: enable the 'PhotoLibrary' external-storage mount → $SHARED_PHOTOS (secubox-nextcloud)."
}

main "$@"
