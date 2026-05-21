#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-authelia :: install-lxc.sh
#
# Idempotent LXC bootstrap for the Authelia SSO IdP. Safe to re-run.
# Inherits all 9 install-lxc fixes from v2.11.1:
#   1. lxc-create -t download (unprivileged-compatible)
#   2. ensure_masquerade() 10.100.0.0/24
#   3. ensure_resolv() via lxc-attach + unlink symlink
#   4. (no apt repo dance like grafana — Authelia is a single binary)
# Follows docs/MODULE-GUIDELINES.md §3.

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-authelia}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.20}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly AUTHELIA_VERSION="${SECUBOX_AUTHELIA_VERSION:-4.39.5}"
readonly AUTHELIA_HTTP_PORT="${SECUBOX_AUTHELIA_PORT:-9091}"
# Hub domain — the canonical SecuBox WebUI vhost where the SSO portal is
# mounted under /auth/. Authelia REQUIRES a session.cookies[] entry per
# top-level domain it serves, otherwise the SPA gets 403 on /auth/api/state.
# Override via env when deploying on a non-default hub (gk2.secubox.in etc.).
readonly SECUBOX_HUB_DOMAIN="${SECUBOX_HUB_DOMAIN:-gk2.secubox.in}"
readonly PROVISION_DIR="${SECUBOX_PROVISION_DIR:-/usr/share/secubox/lib/authelia/provision}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/authelia}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"

log()  { printf '[authelia-install] %s\n' "$*"; }
fail() { printf '[authelia-install] ERROR: %s\n' "$*" >&2; exit 1; }

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

write_lxc_config() {
    log "Pinning network: $LXC_IP/24 on $LXC_BRIDGE"
    cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
# SecuBox-managed — see secubox-authelia / install-lxc.sh
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

ensure_resolv() {
    log "Seeding /etc/resolv.conf in LXC ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c '
        rm -f /etc/resolv.conf
        printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf
    '
}

# ── Authelia install inside LXC ──────────────────────────────────────────────
# Authelia is a single static Go binary. We download from the upstream GitHub
# release matching the LXC's architecture, drop into /opt/authelia/, write a
# systemd unit, and let preflight regenerate the configuration.yml from the
# host-mounted /etc/secubox/authelia.toml on every restart.
install_authelia_in_lxc() {
    local lxc_arch
    lxc_arch=$(lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- dpkg --print-architecture 2>/dev/null | tr -d '\r\n')
    log "Installing Authelia $AUTHELIA_VERSION ($lxc_arch) in '$LXC_NAME' ..."

    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- env \
        AUTHELIA_VERSION="$AUTHELIA_VERSION" \
        AUTHELIA_ARCH="$lxc_arch" \
        bash -e <<'INNER'
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -q
        apt-get install -y --no-install-recommends \
            ca-certificates curl tar

        if ! id -u authelia >/dev/null 2>&1; then
            useradd -r -s /bin/false -d /var/lib/authelia -m authelia
        fi

        install -d -m 0750 -o authelia -g authelia \
            /etc/authelia /var/lib/authelia /var/log/authelia

        if [ ! -x /opt/authelia/authelia ]; then
            mkdir -p /opt/authelia
            cd /tmp
            url="https://github.com/authelia/authelia/releases/download/v${AUTHELIA_VERSION}/authelia-v${AUTHELIA_VERSION}-linux-${AUTHELIA_ARCH}.tar.gz"
            echo "Downloading $url ..."
            curl -fsSL "$url" -o authelia.tar.gz
            tar xzf authelia.tar.gz
            # Tarball ships authelia-linux-<arch> binary
            for f in authelia-linux-*; do
                [ -f "$f" ] && mv "$f" /opt/authelia/authelia
            done
            chmod +x /opt/authelia/authelia
            rm -f authelia.tar.gz authelia-*.sig man/* completions/* 2>/dev/null || true
            chown -R authelia:authelia /opt/authelia
        fi

        cat > /etc/systemd/system/authelia.service <<UNIT
[Unit]
Description=Authelia SSO portal
After=network.target

[Service]
Type=simple
User=authelia
Group=authelia
WorkingDirectory=/var/lib/authelia
ExecStart=/opt/authelia/authelia --config /etc/authelia/configuration.yml
Restart=on-failure
RestartSec=5
ReadWritePaths=/var/lib/authelia /var/log/authelia /etc/authelia

[Install]
WantedBy=multi-user.target
UNIT
        systemctl daemon-reload
        systemctl enable authelia.service
INNER
}

# ── Render configuration.yml from /etc/secubox/authelia.toml ────────────────
# The host-side TOML is the operator-facing config; we render Authelia's YAML
# host-side (with proper variable substitution) and pipe into the LXC via
# lxc-attach stdin. Authelia 4.39+ schema (server.address, identity_validation
# replaces top-level jwt_secret, jwks for OIDC).
render_authelia_config() {
    local jwt_secret store_key
    [ -f "$SECRETS_DIR/authelia-jwt" ]   || openssl rand -hex 32 > "$SECRETS_DIR/authelia-jwt"
    [ -f "$SECRETS_DIR/authelia-store" ] || openssl rand -hex 32 > "$SECRETS_DIR/authelia-store"
    chmod 600 "$SECRETS_DIR/authelia-jwt" "$SECRETS_DIR/authelia-store"
    jwt_secret=$(cat "$SECRETS_DIR/authelia-jwt")
    store_key=$(cat "$SECRETS_DIR/authelia-store")

    log "Rendering /etc/authelia/configuration.yml ..."

    # 1. users_database.yml — convert /etc/secubox/users.json (v2 schema, argon2id
    #    hashes) to Authelia's file-backend format.
    python3 - <<PYEOF
import json, os, sys
users_json = "/etc/secubox/users.json"
out = "/tmp/authelia-users.yml"

if not os.path.exists(users_json):
    sys.exit("/etc/secubox/users.json missing — secubox-users must be installed first")

doc = json.load(open(users_json))
yml = "users:\n"
n = 0
for u in doc.get("users", []):
    if not u.get("enabled", True): continue
    if not u.get("password_hash"): continue   # skip users with null hash
    yml += f"  {u['username']}:\n"
    yml += f"    displayname: {u['username']}\n"
    yml += f"    password: '{u['password_hash']}'\n"
    yml += f"    email: {u.get('email') or u['username']+'@secubox.local'}\n"
    yml += f"    groups: [{u.get('role', 'user')}]\n"
    n += 1
open(out, "w").write(yml)
print(f"Rendered {n} users to {out}")
PYEOF

    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c "cat > /etc/authelia/users_database.yml" \
        < /tmp/authelia-users.yml
    rm -f /tmp/authelia-users.yml

    # 2. configuration.yml — Authelia 4.39+ schema. Variables substituted
    #    HOST-SIDE (we don't trust env-expansion-inside-quoted-heredoc).
    #    OIDC disabled for v1.0.0: enabling it requires a JWKS RSA key pair
    #    and at least one fully-configured client. v1.1.0 wizard handles that.
    cat > /tmp/authelia-config.yml <<CONF
# /etc/authelia/configuration.yml — SecuBox-managed (Authelia 4.39+)
# Re-rendered by autheliactl reload from /etc/secubox/authelia.toml + secrets.
# Do NOT edit by hand — your changes will be overwritten.

theme: dark

server:
  # Path prefix /auth (NO trailing slash — Authelia 4.39+ rejects it).
  # Tells Authelia the React UI lives under /auth/ on the canonical hub
  # vhost. Without this, the SPA makes API calls to /api/state etc.
  # which 404 because nginx only routes /auth/ → the LXC.
  address: 'tcp://0.0.0.0:${AUTHELIA_HTTP_PORT}/auth'

log:
  level: info
  format: text
  file_path: /var/log/authelia/authelia.log

identity_validation:
  reset_password:
    jwt_secret: ${jwt_secret}

authentication_backend:
  file:
    path: /etc/authelia/users_database.yml
    password:
      algorithm: argon2id

access_control:
  default_policy: deny
  rules:
    - domain: "*.maegia.tv"
      policy: one_factor
    # SecuBox hub vhost (admin.<hub>, lyrion.<hub>, zigbee.<hub>, etc.)
    - domain: "${SECUBOX_HUB_DOMAIN}"
      policy: one_factor
    - domain: "*.${SECUBOX_HUB_DOMAIN}"
      policy: one_factor

session:
  # One cookie entry per top-level domain. Authelia returns 403 on /auth/api/*
  # if the request's Host header doesn't match any cookies[].domain — that's
  # the symptom we saw on admin.${SECUBOX_HUB_DOMAIN} before this entry existed.
  cookies:
    - name: authelia_session
      domain: maegia.tv
      authelia_url: 'https://auth.maegia.tv/'
      expiration: 3600
      inactivity: 300
    - name: authelia_session
      domain: ${SECUBOX_HUB_DOMAIN}
      # SSO portal moved to its own vhost in #310 — sibling vhosts (zigbee,
      # lyrion, nextcloud) now redirect here for login. The canonical hub
      # /auth/ is the operator dashboard, not the portal anymore.
      authelia_url: 'https://sso.${SECUBOX_HUB_DOMAIN}/'
      expiration: 3600
      inactivity: 300
  secret: ${jwt_secret}

storage:
  encryption_key: ${store_key}
  local:
    path: /var/lib/authelia/db.sqlite3

notifier:
  filesystem:
    filename: /var/lib/authelia/notifications.txt

# OIDC identity provider — disabled in v1.0.0. Enable via 'autheliactl wizard'
# in v1.1.0 (will generate the JWKS RSA key + at least one client).
# identity_providers:
#   oidc:
#     hmac_secret: ${jwt_secret}
#     jwks:
#       - key_id: 'secubox-oidc'
#         algorithm: 'RS256'
#         key: |
#           -----BEGIN RSA PRIVATE KEY-----
#           ...
#     clients:
#       - client_id: 'secubox-grafana'
#         ...
CONF

    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c "cat > /etc/authelia/configuration.yml" \
        < /tmp/authelia-config.yml
    rm -f /tmp/authelia-config.yml

    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- chown -R authelia:authelia /etc/authelia
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- systemctl restart authelia.service
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
    install_authelia_in_lxc
    render_authelia_config
    mark_provisioned
    log "OK — LXC '$LXC_NAME' at $LXC_IP, authelia provisioned + running on port $AUTHELIA_HTTP_PORT."
    log "Web UI: https://auth.maegia.tv/  (operator: configure DNS + HAProxy vhost)"
    log "Secrets: $SECRETS_DIR/authelia-{jwt,store}"
}

main "$@"
