#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-grafana :: install-lxc.sh
# CyberMind — https://cybermind.fr
#
# Idempotent LXC bootstrap for the Grafana module. Safe to re-run.
# Follows docs/MODULE-GUIDELINES.md §3.

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-grafana}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.70}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly PROVISION_DIR="${SECUBOX_PROVISION_DIR:-/usr/share/secubox/lib/grafana/provision}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/grafana}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"

log()  { printf '[grafana-install] %s\n' "$*"; }
fail() { printf '[grafana-install] ERROR: %s\n' "$*" >&2; exit 1; }

# ── Preflight ────────────────────────────────────────────────────────────────
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
        # Persist via a systemd-networkd unit so it survives reboot.
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

# ── LXC lifecycle ────────────────────────────────────────────────────────────
lxc_state() {
    lxc-info -n "$LXC_NAME" -P "$LXC_PATH" 2>/dev/null \
        | awk -F: '/^State:/ { gsub(/ /,"",$2); print tolower($2) }'
}

create_lxc() {
    if [ -d "$LXC_PATH/$LXC_NAME/rootfs" ]; then
        log "LXC '$LXC_NAME' already exists at $LXC_PATH — skipping debootstrap"
        return
    fi
    log "Creating LXC '$LXC_NAME' (debian $DEBIAN_SUITE) ..."
    lxc-create -n "$LXC_NAME" -t debian -P "$LXC_PATH" -- -r "$DEBIAN_SUITE"
}

write_lxc_config() {
    log "Pinning LXC network: $LXC_IP/24 on $LXC_BRIDGE, gw $LXC_GW"
    cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
# SecuBox-managed — see secubox-grafana / install-lxc.sh
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
    if [ "$(lxc_state)" = "running" ]; then
        log "LXC '$LXC_NAME' already running"
        return
    fi
    log "Starting LXC '$LXC_NAME' ..."
    lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
}

wait_for_network() {
    log "Waiting for LXC network ..."
    for _ in $(seq 1 30); do
        if lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- ping -c1 -W1 "$LXC_GW" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "LXC '$LXC_NAME' did not reach $LXC_GW within 30s"
}

# ── Grafana install inside LXC ───────────────────────────────────────────────
install_grafana_in_lxc() {
    log "Installing Grafana OSS in '$LXC_NAME' ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- bash -e <<'INNER'
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        apt-get install -y --no-install-recommends \
            apt-transport-https software-properties-common ca-certificates curl gnupg wget

        if [ ! -f /etc/apt/sources.list.d/grafana.list ]; then
            install -d /etc/apt/keyrings
            wget -q -O /etc/apt/keyrings/grafana.gpg https://apt.grafana.com/gpg.key
            echo 'deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main' \
                > /etc/apt/sources.list.d/grafana.list
            apt-get update -q
        fi

        apt-get install -y --no-install-recommends grafana
        systemctl enable grafana-server
INNER
}

# ── Provisioning (datasources + dashboards) ──────────────────────────────────
provision_grafana() {
    [ -d "$PROVISION_DIR" ] || { log "No provisioning dir at $PROVISION_DIR — skipping"; return; }
    log "Provisioning datasources + dashboards from $PROVISION_DIR ..."

    # Push provisioning into LXC's /etc/grafana/provisioning/
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- mkdir -p \
        /etc/grafana/provisioning/datasources \
        /etc/grafana/provisioning/dashboards \
        /var/lib/grafana/dashboards

    if [ -d "$PROVISION_DIR/datasources" ]; then
        for f in "$PROVISION_DIR/datasources/"*.yaml; do
            [ -f "$f" ] || continue
            lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
                tee "/etc/grafana/provisioning/datasources/$(basename "$f")" > /dev/null < "$f"
        done
    fi

    # The dashboards.yaml provisioner tells Grafana where to pick up the JSONs.
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- bash -c "cat > /etc/grafana/provisioning/dashboards/secubox.yaml <<'PROV'
apiVersion: 1
providers:
  - name: secubox
    orgId: 1
    folder: SecuBox
    type: file
    disableDeletion: false
    updateIntervalSeconds: 60
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
PROV
"

    if [ -d "$PROVISION_DIR/dashboards" ]; then
        for f in "$PROVISION_DIR/dashboards/"*.json; do
            [ -f "$f" ] || continue
            lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
                tee "/var/lib/grafana/dashboards/$(basename "$f")" > /dev/null < "$f"
        done
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
            chown -R grafana:grafana /var/lib/grafana/dashboards
    fi

    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl restart grafana-server
}

# ── Admin password + API key ─────────────────────────────────────────────────
generate_secrets() {
    if [ ! -f "$SECRETS_DIR/grafana-admin" ]; then
        local pw
        pw=$(openssl rand -hex 16)
        echo "$pw" > "$SECRETS_DIR/grafana-admin"
        chmod 600 "$SECRETS_DIR/grafana-admin"
        log "Setting Grafana admin password ..."
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- \
            grafana-cli --homepath /usr/share/grafana admin reset-admin-password "$pw" || true
    fi
}

# ── Sentinel ─────────────────────────────────────────────────────────────────
mark_provisioned() {
    install -d -m 0755 -o secubox -g secubox "$STATE_DIR"
    date -Iseconds > "$SENTINEL"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    require_cmds
    ensure_dirs
    ensure_bridge
    create_lxc
    write_lxc_config
    start_lxc
    wait_for_network
    install_grafana_in_lxc
    generate_secrets
    provision_grafana
    mark_provisioned
    log "OK — LXC '$LXC_NAME' at $LXC_IP, grafana-server provisioned + running."
    log "Web UI: https://<host>/grafana/  (admin / $(cat "$SECRETS_DIR/grafana-admin"))"
}

main "$@"
