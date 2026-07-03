#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-yacy :: install-lxc.sh
#
# Idempotent LXC bootstrap for the YaCy module.
# Follows docs/MODULE-GUIDELINES.md §3.

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-yacy}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.80}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly YACY_RELEASE_URL="${SECUBOX_YACY_RELEASE_URL:-https://release.yacy.net/yacy_v1.941_202603291103_f0464e7fb.tar.gz}"
readonly YACY_INSTALL_DIR="${SECUBOX_YACY_INSTALL_DIR:-/opt/yacy}"
readonly YACY_HEAP_MAX="${SECUBOX_YACY_HEAP_MAX:-1024}"
readonly PROVISION_DIR="${SECUBOX_PROVISION_DIR:-/usr/share/secubox/lib/yacy/provision}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/yacy}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"

log()  { printf '[yacy-install] %s\n' "$*"; }
fail() { printf '[yacy-install] ERROR: %s\n' "$*" >&2; exit 1; }

require_cmds() {
    for c in lxc-create lxc-info lxc-start lxc-attach openssl; do
        command -v "$c" >/dev/null 2>&1 || fail "$c not installed"
    done
}

ensure_dirs() {
    install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 -o secubox -g secubox "$STATE_DIR"
    install -d -m 0700 -o root -g root "$SECRETS_DIR"
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

ensure_resolv() {
    # /etc/resolv.conf in the download template is a symlink to a nonexistent
    # target before systemd-resolved is up. Unlink first, then write a plain
    # file via lxc-attach (unprivileged LXC: rootfs owned by mapped uid 100000).
    log "Seeding /etc/resolv.conf in LXC ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c '
        rm -f /etc/resolv.conf
        printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf
    '
}

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
    lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" -- --dist debian --release "$DEBIAN_SUITE" --arch "$(dpkg --print-architecture)"
}

write_lxc_config() {
    log "Pinning network: $LXC_IP/24 on $LXC_BRIDGE, gw $LXC_GW"
    cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
# SecuBox-managed — see secubox-yacy / install-lxc.sh
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

install_yacy_in_lxc() {
    log "Installing JVM and YaCy in '$LXC_NAME' ..."
    # Pass the parametric URL/dir via `env` to the in-LXC shell — the heredoc
    # stays unquoted-friendly because INNER is single-quoted.
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- env \
        YACY_RELEASE_URL="$YACY_RELEASE_URL" \
        YACY_INSTALL_DIR="$YACY_INSTALL_DIR" \
        YACY_HEAP_MAX="$YACY_HEAP_MAX" \
        bash -e <<'INNER'
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        apt-get install -y --no-install-recommends \
            default-jre-headless wget ca-certificates tar

        if [ ! -x "${YACY_INSTALL_DIR}/startYACY.sh" ]; then
            mkdir -p "${YACY_INSTALL_DIR}"
            cd /tmp
            wget -q "${YACY_RELEASE_URL}" -O yacy.tar.gz
            tar xzf yacy.tar.gz -C "${YACY_INSTALL_DIR}" --strip-components=1
            rm -f yacy.tar.gz
        fi

        # JVM heap from env
        if [ -f "${YACY_INSTALL_DIR}/defaults/yacy.init" ]; then
            sed -i "s/^javastart_Xmx=.*/javastart_Xmx=Xmx${YACY_HEAP_MAX}m/" \
                "${YACY_INSTALL_DIR}/defaults/yacy.init" || true
        fi

        # Dedicated user
        if ! id -u yacy >/dev/null 2>&1; then
            useradd -r -s /bin/false -d "${YACY_INSTALL_DIR}" yacy
        fi
        chown -R yacy:yacy "${YACY_INSTALL_DIR}"

        # systemd unit
        cat > /etc/systemd/system/yacy.service <<UNIT
[Unit]
Description=YaCy peer-to-peer search engine
After=network.target

[Service]
Type=simple
User=yacy
WorkingDirectory=${YACY_INSTALL_DIR}
ExecStart=${YACY_INSTALL_DIR}/startYACY.sh -f
ExecStop=${YACY_INSTALL_DIR}/stopYACY.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable yacy
        systemctl restart yacy
INNER
}

provision_yacy() {
    [ -d "$PROVISION_DIR" ] || { log "No provisioning dir — skipping"; return; }
    log "Provisioning peer seed + blacklist ..."

    if [ -f "$PROVISION_DIR/peers.seed.txt" ]; then
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- bash -c "install -d -m 0755 /var/lib/yacy && chown yacy:yacy /var/lib/yacy"
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
            tee "/var/lib/yacy/peers.seed.txt" > /dev/null < "$PROVISION_DIR/peers.seed.txt"
    fi
    if [ -f "$PROVISION_DIR/blacklist.txt" ]; then
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
            tee "/var/lib/yacy/blacklist.txt" > /dev/null < "$PROVISION_DIR/blacklist.txt"
    fi
}

generate_admin_password() {
    if [ ! -f "$SECRETS_DIR/yacy-admin" ]; then
        local pw; pw=$(openssl rand -hex 16)
        echo "$pw" > "$SECRETS_DIR/yacy-admin"
        chmod 600 "$SECRETS_DIR/yacy-admin"
        log "Generated YaCy admin password (32 hex chars) at $SECRETS_DIR/yacy-admin"
    fi
}

# Inject the generated password into YaCy's yacy.conf as a Digest hash so
# the admin login works immediately. Without this, the operator couldn't
# log in: YaCy's installed default hash doesn't match the password file.
#
# YaCy uses HTTP Digest authentication with the realm string copied from
# the `adminRealm` pref (a long human-readable sentence). The expected
# hash format is:
#     adminAccountBase64MD5=MD5:<md5sum of "admin:<realm>:<password>">
#
# Computed host-side (md5sum is in coreutils, no java dep needed; matches
# the output of YaCy's own bin/passwd.sh script which calls
# `net.yacy.cora.order.Digest -strfhex` internally).
configure_yacy_admin() {
    local pw_file="$SECRETS_DIR/yacy-admin"
    [ -f "$pw_file" ] || { log "no password file at $pw_file, skipping admin inject"; return; }

    local pw realm hash yacy_conf
    pw=$(cat "$pw_file")
    yacy_conf="/opt/yacy/DATA/SETTINGS/yacy.conf"

    # Pull the realm string from the running YaCy config inside the LXC.
    realm=$(lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c "grep '^adminRealm=' $yacy_conf | cut -d= -f2-" 2>/dev/null || true)
    [ -z "$realm" ] && realm="YaCy"

    hash=$(printf 'admin:%s:%s' "$realm" "$pw" | md5sum | cut -d' ' -f1)
    [ -z "$hash" ] && { log "WARN: md5sum produced empty hash, skipping admin inject"; return; }

    # Skip if the right hash is already set (idempotent).
    if lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- grep -q "^adminAccountBase64MD5=MD5:${hash}$" "$yacy_conf" 2>/dev/null; then
        log "YaCy admin hash already matches generated password — skipping"
        return
    fi

    log "Injecting YaCy admin Digest hash into yacy.conf ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl stop yacy 2>/dev/null || true
    # YaCy rewrites the conf when running; pause it before editing.
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sed -i \
        "s|^adminAccountBase64MD5=.*|adminAccountBase64MD5=MD5:${hash}|" "$yacy_conf"
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl start yacy 2>/dev/null || true
}

# Public/LAN search must render results for anonymous visitors. YaCy's
# adminAccountForLocalhost=true makes every request from a local/proxy IP
# (127.*, 10.*, 192.168.* — see the proxyClient pref) be treated as a pseudo
# admin. The search page then sets authSearch=1 and appends `&auth` to the
# yacysearchitem.html AJAX that renders each hit; those requests demand a real
# admin credential the anonymous browser doesn't carry, get 401, and NO result
# ever renders — the box shows an empty result list to LAN users while the raw
# index (yacysearch.json) is full. Turning it off keeps admin behind the
# password we set (configure_yacy_admin) and lets anonymous search render.
configure_search_access() {
    local yacy_conf="/opt/yacy/DATA/SETTINGS/yacy.conf"
    if lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
        grep -q '^adminAccountForLocalhost=false$' "$yacy_conf" 2>/dev/null; then
        log "adminAccountForLocalhost already disabled — skipping"
        return
    fi
    log "Disabling adminAccountForLocalhost (public search render fix) ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl stop yacy 2>/dev/null || true
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sed -i \
        "s|^adminAccountForLocalhost=.*|adminAccountForLocalhost=false|" "$yacy_conf"
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl start yacy 2>/dev/null || true
}

mark_provisioned() {
    install -d -m 0755 -o secubox -g secubox "$STATE_DIR"
    date -Iseconds > "$SENTINEL"
}

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
    install_yacy_in_lxc
    generate_admin_password
    configure_yacy_admin
    configure_search_access
    provision_yacy
    mark_provisioned
    log "OK — LXC '$LXC_NAME' at $LXC_IP, yacy provisioned + running on port 8090."
    log "Web UI: https://<host>/yacy/  (admin / $(cat "$SECRETS_DIR/yacy-admin"))"
}

main "$@"
