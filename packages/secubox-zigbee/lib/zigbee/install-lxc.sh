#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-zigbee :: install-lxc.sh
#
# Idempotent LXC bootstrap for zigbee2mqtt 2.x. Safe to re-run.
# Inherits the lessons from #240 mqtt v2.4.0:
#   - migrate_from_v1() pattern (mask any host-side z2m if previously installed)
#   - bash `is-active` check instead of `list-unit-files | grep` prefilter
# Follows docs/MODULE-GUIDELINES.md §3 + §7.
#
# Hard limits (per docs/superpowers/specs/2026-05-20-secubox-zigbee-mqtt-iot-stack.md):
#   - permit_join: false in production config (operator opens explicitly + timed)
#   - network_key / pan_id / ext_pan_id: GENERATE — never hard-coded
#   - User systemd inside LXC: zigbee2mqtt (non-root), with dialout group for /dev tty access
#   - z2m credentials read from /etc/secubox/secrets/mqtt-z2m (provisioned by secubox-mqtt)

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-zigbee}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.111}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly MQTT_LXC_IP="${SECUBOX_MQTT_LXC_IP:-10.100.0.110}"
readonly MQTT_PORT="${SECUBOX_MQTT_PORT:-1883}"
readonly Z2M_FRONTEND_PORT="${SECUBOX_Z2M_FRONTEND_PORT:-8080}"
readonly Z2M_VERSION="${SECUBOX_Z2M_VERSION:-2.10.1}"
readonly NODE_MAJOR="${SECUBOX_NODE_MAJOR:-20}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/zigbee}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"

log()  { printf '[zigbee-install] %s\n' "$*"; }
fail() { printf '[zigbee-install] ERROR: %s\n' "$*" >&2; exit 1; }

require_cmds() {
    for c in lxc-create lxc-info lxc-start lxc-attach openssl nft; do
        command -v "$c" >/dev/null 2>&1 || fail "$c not installed"
    done
}

ensure_dirs() {
    install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 -o secubox -g secubox "$STATE_DIR"
    # NOTE: the secrets dir must be group-readable by `secubox` so the host
    # FastAPI (uvicorn @ /run/secubox/zigbee.sock, runs as `secubox`) can
    # read /etc/secubox/secrets/mqtt-z2m. `install -d` on an existing dir
    # doesn't always re-apply mode/owner on bookworm; chmod/chown explicitly.
    install -d "$SECRETS_DIR"
    chmod 0750         "$SECRETS_DIR"
    chown root:secubox "$SECRETS_DIR"
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

migrate_from_v1() {
    if systemctl is-active --quiet zigbee2mqtt 2>/dev/null; then
        log "Stopping host-side zigbee2mqtt (legacy install) ..."
        systemctl stop zigbee2mqtt    2>/dev/null || true
        systemctl disable zigbee2mqtt 2>/dev/null || true
        systemctl mask zigbee2mqtt    2>/dev/null || true
    fi
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
    lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" \
        -- --dist debian --release "$DEBIAN_SUITE" \
           --arch "$(dpkg --print-architecture)"
}

# Bind-mount /dev/secubox-zgb (from the udev rule) into the LXC with the
# 'optional' flag so the LXC starts even without the dongle plugged in —
# z2m will crash-loop until the device shows up.
write_lxc_config() {
    log "Pinning network: $LXC_IP/24 on $LXC_BRIDGE; passing /dev/secubox-zgb if present"
    cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
# SecuBox-managed — see secubox-zigbee / install-lxc.sh
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
# v2.6.0: start after the mqtt LXC. lxc-autostart honours start.order
# (lower runs first) and start.delay (seconds to sleep BEFORE the next
# container in the same order group). mqtt is at order=10/delay=5; we
# go order=20 + delay=20 so z2m gets 20s after mqtt's start to let
# mosquitto bind 1883 before z2m tries to connect. The 2026-05-23
# incident wiped database.db because z2m crash-looped against a dead
# MQTT broker.
lxc.start.order = 20
lxc.start.delay = 20
lxc.mount.entry = /dev/secubox-zgb dev/secubox-zgb none bind,create=file,optional 0 0
# Also bind /dev/serial/by-id so z2m's adapter auto-discovery can match the
# manufacturer regex (e.g. ".*sonoff.*lite.*mg21.*" for the SONOFF MG21).
# Without this, the configuration.yaml port: must be the bare /dev/secubox-zgb
# AND z2m must match by USB VID/PID alone — which v2.10+ doesn't always do.
lxc.mount.entry = /dev/serial/by-id dev/serial/by-id none bind,create=dir,optional 0 0
# LES NOEUDS ttyUSB0/ttyACM0 NE SONT PLUS MONTES, et la raison invoquee pour
# le faire etait fausse. Elle disait que /dev/secubox-zgb, etant un lien, se
# resoudrait vers un ttyUSB0 absent dans le conteneur. Un bind-mount SUIT le
# lien et monte sa CIBLE : verifie le 2026-08-12 sur gk2, /dev/secubox-zgb est
# un vrai peripherique caractere (188,0) a l'interieur, sans aucun autre
# montage.
#
# Les monter avait deux couts reels :
#   - ils reintroduisaient DANS le conteneur les noms dependant de l'ordre
#     d'enumeration, que le nom de role existe justement pour eviter ;
#   - avec `create=file`, LXC fabriquait un FICHIER VIDE quand l'hote n'avait
#     pas le noeud. Constate : /dev/ttyACM0 present dans le conteneur en
#     `---------- 0 octet`, alors qu'aucun ttyACM n'existe sur l'hote. Un
#     fichier qui ressemble a un peripherique et n'en est pas — exactement ce
#     qui fait chercher au mauvais endroit.
lxc.cgroup2.devices.allow = c 188:* rwm
lxc.cgroup2.devices.allow = c 166:* rwm
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

ensure_resolv() {
    log "Seeding /etc/resolv.conf in LXC ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c '
        rm -f /etc/resolv.conf
        printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf
    '
}

# Install Node 20 from NodeSource + zigbee2mqtt from npm registry.
# zigbee2mqtt 2.x requires Node 20; Debian bookworm ships Node 18.
#
# IMPORTANT lesson from the v2.0.0 attempt: the GitHub release tag ships
# only TypeScript sources — `npm start` calls `pnpm run build` which is
# fragile (had a `worker-timers-broker` TS error in 2.0.0). The npm tarball,
# however, ships a pre-built dist/ with all compiled JS — so installing via
# `npm install zigbee2mqtt@<ver>` skips the entire build chain.
install_zigbee2mqtt_in_lxc() {
    log "Installing Node ${NODE_MAJOR} + zigbee2mqtt v${Z2M_VERSION} in '$LXC_NAME' ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- env NODE_MAJOR="$NODE_MAJOR" Z2M_VERSION="$Z2M_VERSION" \
        bash -e <<'INNER'
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive

        apt-get update -q
        apt-get install -y --no-install-recommends \
            ca-certificates curl wget gnupg make g++ python3 \
            udev

        if [ ! -f /etc/apt/keyrings/nodesource.gpg ]; then
            install -d -m 0755 /etc/apt/keyrings
            curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
                | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
            chmod 0644 /etc/apt/keyrings/nodesource.gpg
            echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
                > /etc/apt/sources.list.d/nodesource.list
            apt-get update -q
        fi
        apt-get install -y --no-install-recommends nodejs

        getent group  zigbee2mqtt >/dev/null || groupadd --system zigbee2mqtt
        getent passwd zigbee2mqtt >/dev/null || useradd --system --gid zigbee2mqtt \
            --home /opt/zigbee2mqtt --no-create-home --shell /usr/sbin/nologin zigbee2mqtt
        usermod -aG dialout zigbee2mqtt 2>/dev/null || true

        # /opt/zigbee2mqtt is the prefix. The actual daemon lives in
        # node_modules/zigbee2mqtt after `npm install zigbee2mqtt@<ver>`,
        # and the runtime data dir is /opt/zigbee2mqtt/data (env Z2M_DATA).
        install -d -m 0755 -o zigbee2mqtt -g zigbee2mqtt /opt/zigbee2mqtt
        install -d -m 0755 -o zigbee2mqtt -g zigbee2mqtt /opt/zigbee2mqtt/data

        # Clean any leftover from a previous git-clone install attempt.
        # We're switching to npm-install layout; .git and old dist/ are
        # safe to drop.
        if [ -d /opt/zigbee2mqtt/.git ]; then
            rm -rf /opt/zigbee2mqtt/.git /opt/zigbee2mqtt/node_modules \
                   /opt/zigbee2mqtt/package*.json /opt/zigbee2mqtt/index.js \
                   /opt/zigbee2mqtt/cli.js /opt/zigbee2mqtt/dist /opt/zigbee2mqtt/.npm
        fi

        # Bootstrap a minimal package.json so `npm install <pkg>` works.
        if [ ! -f /opt/zigbee2mqtt/package.json ]; then
            cd /opt/zigbee2mqtt
            # NOTE: sudo is broken in unprivileged LXC; runuser is the
            # drop-in replacement that doesn't care about /etc/sudo.conf
            # ownership.
            runuser -u zigbee2mqtt -- bash -c 'cd /opt/zigbee2mqtt && npm init -y' >/dev/null
        fi

        cd /opt/zigbee2mqtt
        runuser -u zigbee2mqtt -- bash -c \
            "cd /opt/zigbee2mqtt && npm install --omit=dev --no-audit --no-fund zigbee2mqtt@${Z2M_VERSION}" 2>&1 | tail -5

        # NOTE: the env var z2m actually reads is ZIGBEE2MQTT_DATA — NOT Z2M_DATA.
        # The Z2M_* prefix is reserved for v2.x onboarding-related flags
        # (e.g. Z2M_ONBOARD_NO_SERVER). v2.4.0 set the wrong var, so z2m fell
        # back to its module-default data dir at
        # /opt/zigbee2mqtt/node_modules/zigbee2mqtt/data and never read our
        # configuration.yaml. Fixed in v2.4.1.
        #
        # Z2M_ONBOARD_NO_SERVER=1 skips the first-run web wizard so adapter
        # init proceeds directly when configuration.yaml is complete.
        cat > /etc/systemd/system/zigbee2mqtt.service <<UNIT
[Unit]
Description=zigbee2mqtt
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=zigbee2mqtt
WorkingDirectory=/opt/zigbee2mqtt/node_modules/zigbee2mqtt
Environment=ZIGBEE2MQTT_DATA=/opt/zigbee2mqtt/data
Environment=Z2M_ONBOARD_NO_SERVER=1
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=10
# Bind-mounted /dev/tty* nodes land inside the LXC as root:root with
# the host's 0660 perms. The host's `dialout` GID doesn't map to the
# LXC's `zigbee2mqtt` user (different user namespace), so without
# this chmod the z2m user can't open the device. Idempotent + cheap;
# `|| true` survives the dongle-absent case. See secubox-zigbee #zigbee-prod-502.
ExecStartPre=/bin/sh -c '[ -e /dev/ttyUSB0 ] && /bin/chmod 0666 /dev/ttyUSB0 || true'
ExecStartPre=/bin/sh -c '[ -e /dev/ttyACM0 ] && /bin/chmod 0666 /dev/ttyACM0 || true'
# v2.6.0: refuse to start until the MQTT broker answers on 1883.
# Without this, z2m crash-loops when MQTT is briefly down and ends up
# writing degraded state to database.db (the 2026-05-23 incident
# regenerated network_key + lost 5 devices). 60s budget, 2s probe
# interval; if the broker never comes up we exit non-zero and let
# systemd retry per Restart=.
ExecStartPre=/bin/sh -c 'for i in \$(seq 1 30); do if (echo > /dev/tcp/10.100.0.110/1883) >/dev/null 2>&1; then exit 0; fi; sleep 2; done; echo "MQTT 10.100.0.110:1883 unreachable after 60s — refusing to start z2m" >&2; exit 1'
ExecStart=/usr/bin/node /opt/zigbee2mqtt/node_modules/zigbee2mqtt/index.js

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/zigbee2mqtt/data /opt/zigbee2mqtt/node_modules/zigbee2mqtt
DeviceAllow=/dev/secubox-zgb rw
DeviceAllow=/dev/ttyUSB0 rw
DeviceAllow=/dev/ttyACM0 rw

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
INNER
}

# Render configuration.yaml inside the LXC, wiring z2m to the SecuBox
# Mosquitto broker. Credentials pulled from /etc/secubox/secrets/mqtt-z2m
# (provisioned by secubox-mqtt v2.4 — that's a hard Depends).
configure_zigbee2mqtt() {
    log "Rendering zigbee2mqtt configuration.yaml ..."

    local z2m_pw_file="$SECRETS_DIR/mqtt-z2m"
    [ -f "$z2m_pw_file" ] || fail "missing $z2m_pw_file — install secubox-mqtt first and run 'mqttctl install'"
    local z2m_pw; z2m_pw=$(cat "$z2m_pw_file")

    # Detect the connected adapter type by USB VID/PID. We auto-pick the
    # adapter + port to write into configuration.yaml so the operator
    # doesn't have to touch YAML for the common dongles. If nothing's
    # plugged in yet, default to zstack/CC2652P (most common) and let z2m
    # re-detect on next restart once the dongle appears.
    local detected_adapter="zstack"
    local detected_port="/dev/secubox-zgb"
    # SONOFF Dongle Lite MG21 (10c4:ea60, Silicon Labs EFR32MG21)
    if lsusb 2>/dev/null | grep -qE "10c4:ea60.*Silicon Labs|SONOFF.*MG21"; then
        detected_adapter="ember"
    fi
    # LE PORT RESTE /dev/secubox-zgb, TOUJOURS. La version precedente lui
    # substituait le chemin /dev/serial/by-id/usb-SONOFF_*MG21*, pour aider la
    # decouverte d'adaptateur de z2m 2.x qui compare une expression reguliere
    # de fabricant au chemin. Cette decouverte ne sert a rien ici : `adapter:`
    # est ecrit explicitement juste en dessous.
    #
    # Le cout, lui, etait reel : le chemin by-id contient le NUMERO DE SERIE du
    # dongle. Le remplacer — panne, montee en gamme — changeait le chemin, et la
    # configuration pointait vers un peripherique disparu. Le nom de role, lui,
    # designe « le coordinateur Zigbee », quel qu'il soit.
    log "  · detected adapter: $detected_adapter ($detected_port)"

    local stage=/tmp/zigbee2mqtt-config.$$
    cat > "$stage" <<YAML
# /opt/zigbee2mqtt/data/configuration.yaml
# Generated by secubox-zigbee install-lxc.sh — operator overrides go in
# operator-overrides.yaml (loaded after this).
homeassistant:
  enabled: false
permit_join: false
mqtt:
  base_topic: zigbee2mqtt
  server: 'mqtt://${MQTT_LXC_IP}:${MQTT_PORT}'
  user: z2m
  password: '${z2m_pw}'
  keepalive: 60
serial:
  port: ${detected_port}
  adapter: ${detected_adapter}
advanced:
  network_key: GENERATE
  pan_id: GENERATE
  ext_pan_id: GENERATE
  channel: 20
  log_level: warning
  log_output: ['file']
  log_directory: /opt/zigbee2mqtt/data/log
  log_file: '%TIMESTAMP%.log'
  timestamp_format: 'YYYY-MM-DD HH:mm:ss'
frontend:
  enabled: true
  port: ${Z2M_FRONTEND_PORT}
  host: 0.0.0.0
device_options:
  legacy: false
YAML

    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- install -d -m 0755 -o zigbee2mqtt -g zigbee2mqtt /opt/zigbee2mqtt/data
    cat "$stage" | lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- tee /opt/zigbee2mqtt/data/configuration.yaml >/dev/null
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- chown zigbee2mqtt:zigbee2mqtt /opt/zigbee2mqtt/data/configuration.yaml
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- chmod 0640 /opt/zigbee2mqtt/data/configuration.yaml
    rm -f "$stage"

    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl enable zigbee2mqtt 2>/dev/null || true
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl restart zigbee2mqtt 2>/dev/null || true
}

# Install the udev rule on the host so /dev/secubox-zgb is created when a
# Zigbee dongle gets plugged in. LXC bind-mount is optional — the LXC starts
# regardless of dongle presence.
install_udev_rule() {
    local rule_file=/etc/udev/rules.d/99-secubox-zigbee.rules
    log "Installing udev rule for Zigbee dongles ..."
    cat > "$rule_file" <<'UDEV'
# /etc/udev/rules.d/99-secubox-zigbee.rules
# Installed by secubox-zigbee (#241, updated v2.4.2 for hotplug → LXC).
# Order matters: ATTRS{product} filter MUST come before the generic CP210x
# rule below, otherwise the SONOFF MG21 would land as -alt and z2m's adapter
# discovery wouldn't pick it up.
#
# What the SYMLINK lines do:
#   * Create /dev/secubox-zgb pointing at the zigbee radio kernel device.
#   * The LXC config bind-mounts BOTH /dev/secubox-zgb AND the underlying
#     /dev/ttyUSB0 / /dev/ttyACM0 nodes, so the symlinks actually resolve
#     to a real device inside the container.
#
# What the RUN line does (NEW in v2.4.2):
#   * On a hotplug event (dongle re-inserted after the LXC was already
#     running), `lxc-device add zigbee /dev/<kernel>` pushes the device
#     node into the running container AND adds the cgroup permission.
#     Without this, a replugged dongle stays invisible inside the LXC
#     until the container restarts — which is the failure mode that
#     produced 4500+ crash-loop restarts of zigbee2mqtt on gk2.
#   * `|| true` keeps udev's overall ruleset healthy when the LXC is
#     stopped (lxc-device exits non-zero in that case).

# SONOFF Dongle Lite MG21 (Silicon Labs EFR32MG21 behind a CP210x bridge)
SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", \
    ATTRS{product}=="SONOFF Dongle Lite MG21", \
    SYMLINK+="secubox-zgb", MODE="0660", GROUP="dialout", \
    RUN+="/bin/sh -c '/usr/bin/lxc-device -n zigbee add /dev/%k || true'"

# Sonoff Zigbee 3.0 USB Plus (CC2652P)
SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="55d4", \
    SYMLINK+="secubox-zgb", MODE="0660", GROUP="dialout", \
    RUN+="/bin/sh -c '/usr/bin/lxc-device -n zigbee add /dev/%k || true'"

# ConBee II (fallback)
SUBSYSTEM=="tty", ATTRS{idVendor}=="1cf1", ATTRS{idProduct}=="0030", \
    SYMLINK+="secubox-zgb", MODE="0660", GROUP="dialout", \
    RUN+="/bin/sh -c '/usr/bin/lxc-device -n zigbee add /dev/%k || true'"

# Generic CP210x without the SONOFF descriptor — secondary symlink only
SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", \
    SYMLINK+="secubox-zgb-alt", MODE="0660", GROUP="dialout"
UDEV
    chmod 0644 "$rule_file"
    udevadm control --reload-rules
    udevadm trigger --subsystem-match=tty 2>/dev/null || true
}

mark_provisioned() {
    install -d -m 0755 -o secubox -g secubox "$STATE_DIR"
    date -Iseconds > "$SENTINEL"
}

main() {
    require_cmds
    migrate_from_v1
    ensure_dirs
    install_udev_rule
    ensure_bridge
    ensure_masquerade
    create_lxc
    write_lxc_config
    start_lxc
    wait_for_network
    ensure_resolv
    install_zigbee2mqtt_in_lxc
    configure_zigbee2mqtt
    mark_provisioned
    log "OK — LXC '$LXC_NAME' at $LXC_IP, zigbee2mqtt provisioned."
    log "  · Frontend (LXC) : http://$LXC_IP:$Z2M_FRONTEND_PORT/"
    log "  · MQTT bridge    : mqtt://$MQTT_LXC_IP:$MQTT_PORT (user z2m)"
    log "  · Radio symlink  : /dev/secubox-zgb  (CC2652P / ConBee II)"
    log "  · Status         : zigbeectl status   (radio absent → 'device: absent')"
}

main "$@"
