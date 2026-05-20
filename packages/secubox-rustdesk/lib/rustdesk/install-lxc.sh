#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-rustdesk :: install-lxc.sh
#
# Idempotent LXC bootstrap for the RustDesk module. Two daemons inside
# the LXC: hbbs (signal) and hbbr (relay). On the host: HAProxy stream
# config (TCP) + nftables DNAT (UDP) for public exposure.
#
# Follows docs/MODULE-GUIDELINES.md §3. UDP DNAT is the rustdesk-specific
# delta from the grafana/yacy pattern (mitmproxy cannot inspect raw UDP).

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-rustdesk}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.90}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly RUSTDESK_RELEASE_URL="${SECUBOX_RUSTDESK_URL:-https://github.com/rustdesk/rustdesk-server/releases/download/1.1.11/rustdesk-server-linux-amd64.zip}"
readonly RUSTDESK_INSTALL_DIR="${SECUBOX_RUSTDESK_DIR:-/opt/rustdesk}"
readonly PROVISION_DIR="${SECUBOX_PROVISION_DIR:-/usr/share/secubox/lib/rustdesk/provision}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/rustdesk}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
readonly NFT_TABLE="${SECUBOX_NFT_TABLE:-inet secubox}"

log()  { printf '[rustdesk-install] %s\n' "$*"; }
fail() { printf '[rustdesk-install] ERROR: %s\n' "$*" >&2; exit 1; }

require_cmds() {
    for c in lxc-create lxc-info lxc-start lxc-attach openssl nft; do
        command -v "$c" >/dev/null 2>&1 || fail "$c not installed"
    done
}

ensure_dirs() {
    install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 -o secubox -g secubox "$STATE_DIR"
    install -d -m 0700 -o root -g root "$SECRETS_DIR"
}

ensure_bridge() {
    ip link show "$LXC_BRIDGE" >/dev/null 2>&1 && return 0
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
}

lxc_state() {
    lxc-info -n "$LXC_NAME" -P "$LXC_PATH" 2>/dev/null \
        | awk -F: '/^State:/ { gsub(/ /,"",$2); print tolower($2) }'
}

create_lxc() {
    [ -d "$LXC_PATH/$LXC_NAME/rootfs" ] && { log "LXC '$LXC_NAME' exists — skipping debootstrap"; return; }
    log "Creating LXC '$LXC_NAME' (debian $DEBIAN_SUITE) ..."
    lxc-create -n "$LXC_NAME" -t debian -P "$LXC_PATH" -- -r "$DEBIAN_SUITE"
}

write_lxc_config() {
    log "Pinning network: $LXC_IP/24 on $LXC_BRIDGE"
    cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
# SecuBox-managed — see secubox-rustdesk / install-lxc.sh
lxc.uts.name = $LXC_NAME
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
lxc.net.0.name = eth0
lxc.rootfs.path = dir:$LXC_PATH/$LXC_NAME/rootfs
lxc.include = /usr/share/lxc/config/common.conf
lxc.apparmor.profile = generated
lxc.start.auto = 1
lxc.start.delay = 5
EOF
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

# ── RustDesk install inside LXC (hbbs + hbbr) ────────────────────────────────
install_rustdesk_in_lxc() {
    log "Installing RustDesk hbbs + hbbr in '$LXC_NAME' ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- env \
        RUSTDESK_RELEASE_URL="$RUSTDESK_RELEASE_URL" \
        RUSTDESK_INSTALL_DIR="$RUSTDESK_INSTALL_DIR" \
        bash -e <<'INNER'
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        apt-get install -y --no-install-recommends \
            wget ca-certificates unzip

        if [ ! -x "${RUSTDESK_INSTALL_DIR}/hbbs" ]; then
            mkdir -p "${RUSTDESK_INSTALL_DIR}"
            cd /tmp
            wget -q "${RUSTDESK_RELEASE_URL}" -O rustdesk-server.zip
            unzip -q rustdesk-server.zip -d "${RUSTDESK_INSTALL_DIR}"
            rm -f rustdesk-server.zip
            # The release zip places hbbs/hbbr under "amd64/" — flatten to install_dir/
            if [ -d "${RUSTDESK_INSTALL_DIR}/amd64" ]; then
                mv "${RUSTDESK_INSTALL_DIR}/amd64/"* "${RUSTDESK_INSTALL_DIR}/"
                rmdir "${RUSTDESK_INSTALL_DIR}/amd64"
            fi
            chmod +x "${RUSTDESK_INSTALL_DIR}/hbbs" "${RUSTDESK_INSTALL_DIR}/hbbr"
        fi

        # Dedicated user + data dir
        if ! id -u rustdesk >/dev/null 2>&1; then
            useradd -r -s /bin/false -d /var/lib/rustdesk -m rustdesk
        fi
        chown -R rustdesk:rustdesk "${RUSTDESK_INSTALL_DIR}" /var/lib/rustdesk

        # hbbs unit (signal)
        cat > /etc/systemd/system/rustdesk-hbbs.service <<UNIT
[Unit]
Description=RustDesk signal server (hbbs)
After=network.target

[Service]
Type=simple
User=rustdesk
WorkingDirectory=/var/lib/rustdesk
ExecStart=${RUSTDESK_INSTALL_DIR}/hbbs
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

        # hbbr unit (relay) — start after hbbs is up
        cat > /etc/systemd/system/rustdesk-hbbr.service <<UNIT
[Unit]
Description=RustDesk relay server (hbbr)
After=network.target rustdesk-hbbs.service

[Service]
Type=simple
User=rustdesk
WorkingDirectory=/var/lib/rustdesk
ExecStart=${RUSTDESK_INSTALL_DIR}/hbbr
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

        systemctl daemon-reload
        systemctl enable rustdesk-hbbs rustdesk-hbbr
        systemctl restart rustdesk-hbbs rustdesk-hbbr
INNER
}

# ── Host: nftables DNAT for the UDP signal port ──────────────────────────────
# mitmproxy cannot inspect raw UDP — forward 21116/udp directly to the LXC.
# TCP ports go through HAProxy stream-mode (see haproxy/rustdesk-stream.cfg
# shipped in the .deb under /etc/haproxy/secubox-streams/).
setup_nftables_udp_dnat() {
    log "Adding nftables DNAT for 21116/udp -> $LXC_IP:21116 ..."
    nft -f - <<EOF
table inet secubox {
    chain prerouting_rustdesk {
        type nat hook prerouting priority dstnat; policy accept;
        udp dport 21116 dnat ip to $LXC_IP:21116 comment "secubox-rustdesk hbbs signal"
    }
}
EOF
}

# ── Pre-shared key generation ────────────────────────────────────────────────
generate_psk() {
    local key_file="$SECRETS_DIR/rustdesk-key"
    [ -f "$key_file" ] && return 0
    log "Generating ed25519 pre-shared key ..."
    openssl rand -base64 32 > "$key_file"
    chmod 600 "$key_file"
}

mark_provisioned() {
    install -d -m 0755 -o secubox -g secubox "$STATE_DIR"
    date -Iseconds > "$SENTINEL"
}

main() {
    require_cmds
    ensure_dirs
    ensure_bridge
    create_lxc
    write_lxc_config
    start_lxc
    wait_for_network
    install_rustdesk_in_lxc
    generate_psk
    setup_nftables_udp_dnat
    mark_provisioned
    log "OK — LXC '$LXC_NAME' at $LXC_IP, hbbs+hbbr running."
    log "Web admin: https://<host>/rustdesk/"
    log "Client cfg — relay: <your-public-ip>:21117  key: $(cat "$SECRETS_DIR/rustdesk-key")"
}

main "$@"
