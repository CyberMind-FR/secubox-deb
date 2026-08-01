#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-peertube :: install-lxc.sh
# CyberMind — https://cybermind.fr
#
# Idempotent native-LXC bootstrap for the PeerTube module. Safe to re-run.
# Follows docs/MODULE-GUIDELINES.md §3 (mirror of grafana/yacy/rustdesk).
#
# PeerTube is installed NATIVELY inside a dedicated Debian LXC (its own
# systemd `peertube.service`), NOT in a Docker/Podman container — podman in
# an unprivileged LXC repeatedly hits CNI bridge / iptables failures on the
# Marvell arm64 boards. The host nginx vhost proxies the public hostname to
# this LXC at <LXC_IP>:9000.
#
# Stack inside the LXC: Node 22 (PeerTube 8.x requires >=22) + PostgreSQL 15
# + Redis + ffmpeg, installed via pnpm. msgpackr-extract native acceleration
# is disabled (arm64 prebuilt binding is broken; JS fallback is correct).

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-peertube}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.120}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly DATA_DIR="${SECUBOX_DATA_DIR:-/data/peertube}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/peertube}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
# Public hostname baked into PeerTube's webserver config. Override per board.
readonly PUBLIC_HOSTNAME="${SECUBOX_PEERTUBE_HOSTNAME:-peertube.gk2.secubox.in}"
# LXC root's host-side UID (idmap u 0 100000) — bind-mounts must be owned by
# this so LXC root can chown them to the in-container service UIDs.
readonly LXC_ROOT_UID="${SECUBOX_LXC_ROOT_UID:-100000}"

log()  { printf '[peertube-install] %s\n' "$*"; }
fail() { printf '[peertube-install] ERROR: %s\n' "$*" >&2; exit 1; }

la() { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

# ── Preflight ────────────────────────────────────────────────────────────────
require_cmds() {
    for c in lxc-create lxc-info lxc-start lxc-attach openssl; do
        command -v "$c" >/dev/null 2>&1 || fail "$c not installed"
    done
}

ensure_dirs() {
    install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 -o secubox -g secubox "$STATE_DIR" 2>/dev/null \
        || install -d -m 0755 "$STATE_DIR"
    install -d -m 0700 -o root -g root "$SECRETS_DIR"
    # Bind-mount targets, owned by the LXC root UID so the container can chown
    # them to postgres/redis/peertube during install.
    for d in storage config postgres redis; do
        install -d -m 0750 "$DATA_DIR/$d"
    done
    chown -R "$LXC_ROOT_UID:$LXC_ROOT_UID" "$DATA_DIR"
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
    # NAT outbound from 10.100.0.0/24 so the LXC can reach the internet (apt,
    # NodeSource, GitHub release download). systemd-networkd's IPMasquerade
    # only lands when it manages the bridge; add an explicit nft rule too.
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
        log "LXC '$LXC_NAME' already exists at $LXC_PATH — skipping debootstrap"
        return
    fi
    log "Creating LXC '$LXC_NAME' (debian $DEBIAN_SUITE) ..."
    lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" -- \
        --dist debian --release "$DEBIAN_SUITE" --arch "$(dpkg --print-architecture)"
}

write_lxc_config() {
    log "Pinning LXC network: $LXC_IP/24 on $LXC_BRIDGE; bind mounts under $DATA_DIR"
    # NOTE: debian.common.conf (NOT common.conf) — postgresql-15's postinst +
    # initdb fail under the stricter common.conf+apparmor=generated defaults
    # in an unprivileged LXC. debian.common.conf is the working template.
    cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
# SecuBox-managed — see secubox-peertube / install-lxc.sh
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

# Persist user data + DB outside the container so backups/upgrades are clean.
lxc.mount.entry = $DATA_DIR/storage var/www/peertube/storage none bind,create=dir 0 0
lxc.mount.entry = $DATA_DIR/config var/www/peertube/config none bind,create=dir 0 0
lxc.mount.entry = $DATA_DIR/postgres var/lib/postgresql none bind,create=dir 0 0
lxc.mount.entry = $DATA_DIR/redis var/lib/redis none bind,create=dir 0 0

# Memory cap (soft) — peertube + postgres + redis + node ≈ 800-1200M peak.
# Tune via /etc/secubox/tuning/lxc-memory-high.toml (secubox-system-tuning).
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
        if la ping -c1 -W1 "$LXC_GW" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    fail "LXC '$LXC_NAME' did not reach $LXC_GW within 30s"
}

# ── PeerTube install inside LXC ──────────────────────────────────────────────
install_peertube_in_lxc() {
    log "Installing PeerTube (native) in '$LXC_NAME' — this takes several minutes ..."
    local db_pw
    db_pw="$(cat "$SECRETS_DIR/peertube-db" 2>/dev/null || true)"
    if [ -z "$db_pw" ]; then
        db_pw="$(openssl rand -hex 16)"
        echo "$db_pw" > "$SECRETS_DIR/peertube-db"
        chmod 600 "$SECRETS_DIR/peertube-db"
    fi
    local pt_secret
    pt_secret="$(cat "$SECRETS_DIR/peertube-secret" 2>/dev/null || true)"
    if [ -z "$pt_secret" ]; then
        pt_secret="$(openssl rand -hex 32)"
        echo "$pt_secret" > "$SECRETS_DIR/peertube-secret"
        chmod 600 "$SECRETS_DIR/peertube-secret"
    fi

    la env \
        DB_PW="$db_pw" PT_SECRET="$pt_secret" PUBLIC_HOSTNAME="$PUBLIC_HOSTNAME" \
        DEBIAN_FRONTEND=noninteractive LC_ALL=C LANG=C \
        bash -e <<'INNER'
set -euo pipefail

echo '[1/8] apt prereqs'
apt-get update -q
apt-get install -y -q --no-install-recommends \
    curl sudo unzip ca-certificates gnupg ffmpeg postgresql postgresql-contrib \
    openssl g++ make redis-server git python3 python3-pip python-is-python3 cron wget

echo '[2/8] Node 22 (NodeSource, signed apt repo — no curl|bash)'
if ! node -v 2>/dev/null | grep -qE '^v(2[2-9]|[3-9][0-9])'; then
    install -d /etc/apt/keyrings
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
    chmod 644 /etc/apt/keyrings/nodesource.gpg
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list
    apt-get update -q
    apt-get install -y -q --allow-downgrades nodejs
fi
corepack enable || true

echo '[3/8] peertube system user'
id -u peertube >/dev/null 2>&1 || useradd -m -d /var/www/peertube -s /bin/bash peertube

echo '[4/8] postgres + redis + database'
service postgresql start || systemctl start postgresql || true
# Redis must persist with an append-only file (#943). PeerTube keeps its job
# QUEUE in redis but the "a job is pending" COUNTER in postgres
# (videoJobInfo.pendingTranscode). Debian's default is `appendonly no`, so a
# container restart loses every queued job while the counters survive —
# PeerTube then answers 409 video_already_being_transcoded to every relaunch,
# forever, and the videos stay in TO_TRANSCODE with no HLS playlist:
# unplayable, silently. Cost us 87 videos on gk2, stuck since 2026-07-14.
# `appendfsync everysec` is Debian's default and is the right trade-off here.
if ! grep -qE '^appendonly yes' /etc/redis/redis.conf 2>/dev/null; then
    sed -i 's/^appendonly no/appendonly yes/' /etc/redis/redis.conf 2>/dev/null || true
    grep -qE '^appendonly yes' /etc/redis/redis.conf 2>/dev/null || \
        echo 'appendonly yes' >> /etc/redis/redis.conf
fi
service redis-server start || systemctl start redis-server || true
sleep 3
# Belt and braces: enable it live too, in case redis was already running with
# the old config (upgrade path — no restart needed, no queue lost).
redis-cli config set appendonly yes >/dev/null 2>&1 || true
sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='peertube'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER peertube WITH PASSWORD '${DB_PW}';"
sudo -u postgres psql -c "ALTER USER peertube WITH PASSWORD '${DB_PW}';"
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='peertube_prod'" | grep -q 1 || \
    sudo -u postgres createdb -O peertube -E UTF8 -T template0 peertube_prod
sudo -u postgres psql -d peertube_prod -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"   2>/dev/null || true
sudo -u postgres psql -d peertube_prod -c "CREATE EXTENSION IF NOT EXISTS unaccent;"  2>/dev/null || true

echo '[5/8] download PeerTube release'
install -d -o peertube -g peertube /var/www/peertube
cd /var/www/peertube
sudo -u peertube mkdir -p versions config storage
VERSION=$(curl -s https://api.github.com/repos/Chocobozzz/PeerTube/releases/latest | grep tag_name | cut -d '"' -f 4)
echo "  installing PeerTube $VERSION"
cd versions
if [ ! -d "peertube-$VERSION" ]; then
    sudo -u peertube wget -q "https://github.com/Chocobozzz/PeerTube/releases/download/$VERSION/peertube-$VERSION.zip"
    sudo -u peertube unzip -q "peertube-$VERSION.zip"
    rm -f "peertube-$VERSION.zip"
fi
cd /var/www/peertube
sudo -u peertube ln -sfn "versions/peertube-$VERSION" peertube-latest

echo '[6/8] pnpm install (MSGPACKR native accel disabled for arm64)'
cd /var/www/peertube/peertube-latest
sudo -H -u peertube --preserve-env=MSGPACKR_NATIVE_ACCELERATION_DISABLED \
    env MSGPACKR_NATIVE_ACCELERATION_DISABLED=1 \
    pnpm install --prod --frozen-lockfile --reporter=append-only

echo '[7/8] config (production.yaml)'
sudo -u peertube cp -n /var/www/peertube/peertube-latest/config/default.yaml            /var/www/peertube/config/default.yaml
sudo -u peertube cp -n /var/www/peertube/peertube-latest/config/production.yaml.example /var/www/peertube/config/production.yaml
python3 - "$PUBLIC_HOSTNAME" "$PT_SECRET" "$DB_PW" <<'PY'
import re, sys, pathlib
hostname, secret, db_pw = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path('/var/www/peertube/config/production.yaml')
lines = p.read_text().splitlines()

def find_in_block(top, sub):
    in_blk = False
    for i, l in enumerate(lines):
        if re.match(rf'^{re.escape(top)}\s*:', l):
            in_blk = True; continue
        if in_blk:
            if l and not l.startswith((' ', '\t', '#')):
                return None
            if re.match(rf'^\s+{re.escape(sub)}\s*:', l):
                return i
    return None

def set_kv(top, sub, value):
    i = find_in_block(top, sub)
    if i is None:
        return
    cur = lines[i]; ind = cur[:len(cur)-len(cur.lstrip())]
    lines[i] = f"{ind}{sub}: {value}"

# listen.hostname 127.0.0.1 -> 0.0.0.0 so the host nginx reaches the LXC iface
set_kv('listen', 'hostname', "'0.0.0.0'")
set_kv('listen', 'port', '9000')
set_kv('webserver', 'https', 'true')
set_kv('webserver', 'hostname', f"'{hostname}'")
set_kv('webserver', 'port', '443')
set_kv('secrets', 'peertube', f"'{secret}'")
set_kv('database', 'password', f"'{db_pw}'")

for idx, l in enumerate(lines):
    if re.match(r'^admin\s*:', l):
        for j in range(idx+1, min(idx+12, len(lines))):
            if re.match(r'^\s+email\s*:', lines[j]):
                lines[j] = re.sub(r"(:\s*).*$", r"\1'admin@cybermind.fr'", lines[j]); break
        break

# Enable native HTTP import (yt-dlp). Path: import → videos → http → enabled.
# Tracks nesting depth so we only flip the import.videos.http.enabled flag.
in_import = in_videos = in_http = False
def indent(s): return len(s) - len(s.lstrip())
for i, l in enumerate(lines):
    s = l.strip()
    if re.match(r'^import\s*:', l) and indent(l) == 0:
        in_import = True; in_videos = in_http = False; continue
    if in_import and l and indent(l) == 0 and not l.startswith('#'):
        in_import = in_videos = in_http = False
    if in_import and re.match(r'^\s+videos\s*:', l):
        in_videos = True; in_http = False; continue
    if in_import and in_videos and re.match(r'^\s+http\s*:', l):
        in_http = True; continue
    if in_import and in_videos and in_http and re.match(r'^\s+enabled\s*:', l):
        ind = l[:indent(l)]
        lines[i] = f"{ind}enabled: true"
        in_http = False

p.write_text('\n'.join(lines) + '\n')
print('  production.yaml patched (incl. import.videos.http.enabled)')
PY

echo '[8/8] systemd unit + ownership'
cat > /etc/systemd/system/peertube.service <<'UNIT'
[Unit]
Description=PeerTube
After=network.target postgresql.service redis-server.service

[Service]
Type=simple
Environment=NODE_ENV=production
Environment=NODE_CONFIG_DIR=/var/www/peertube/config
User=peertube
ExecStart=/usr/bin/npm start
WorkingDirectory=/var/www/peertube/peertube-latest
Restart=always
RestartSec=5
LimitNOFILE=30000

[Install]
WantedBy=multi-user.target
UNIT
chown -R peertube:peertube /var/www/peertube
systemctl daemon-reload
systemctl enable peertube.service
systemctl restart peertube.service
echo '=== PeerTube install complete ==='
INNER
}

verify() {
    log "Verifying PeerTube is listening on $LXC_IP:9000 ..."
    for _ in $(seq 1 30); do
        if curl -fsS -o /dev/null --max-time 3 "http://$LXC_IP:9000/api/v1/config"; then
            log "OK — PeerTube responding."
            return 0
        fi
        sleep 2
    done
    log "WARN: PeerTube not yet responding on $LXC_IP:9000 (first boot can take a while; check 'lxc-attach -n $LXC_NAME -P $LXC_PATH -- journalctl -u peertube')."
}

capture_admin() {
    # PeerTube logs the auto-generated root password once on first boot. Persist
    # it to a host secret so the SecuBox dashboard can authenticate for write
    # ops (video import, user/channel management). Operator should rotate it in
    # the web UI; if they do, update this file or the dashboard re-auth fails.
    [ -s "$SECRETS_DIR/peertube-admin" ] && return 0
    local pw=""
    for _ in $(seq 1 15); do
        pw="$(la journalctl -u peertube --no-pager 2>/dev/null \
            | grep -m1 'User password:' | sed 's/.*User password: //')" || true
        [ -n "$pw" ] && break
        sleep 2
    done
    if [ -n "$pw" ]; then
        printf '%s\n' "$pw" > "$SECRETS_DIR/peertube-admin"
        chmod 600 "$SECRETS_DIR/peertube-admin"
        log "Initial admin: root / $pw  (saved to $SECRETS_DIR/peertube-admin — rotate via web UI)"
    else
        log "WARN: could not capture initial root password from journal; set $SECRETS_DIR/peertube-admin manually for dashboard write ops."
    fi
}

mark_provisioned() { date -Iseconds > "$SENTINEL"; }

# ── Main ─────────────────────────────────────────────────────────────────────
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
    install_peertube_in_lxc
    verify
    capture_admin
    mark_provisioned
    log "Done — LXC '$LXC_NAME' at $LXC_IP, PeerTube native install running."
    log "Public URL (wire HAProxy SNI + nginx vhost separately): https://$PUBLIC_HOSTNAME/"
}

main "$@"
