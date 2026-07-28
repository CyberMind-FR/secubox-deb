#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-torrent :: install-lxc.sh
# CyberMind — https://cybermind.fr
#
# Idempotent LXC bootstrap + app deploy for the secubox-torrent module
# (v2.0, WebTorrent streaming pivot). Creates the dedicated Debian LXC,
# installs Node, then deploys the WebTorrent engine (webtorrent + fastify
# + better-sqlite3, optionally @roamhq/wrtc — see SPIKE-RESULT.md) and its
# in-LXC systemd unit. The host nginx vhost (../nginx/torrent.conf) proxies
# torrent.gk2.secubox.in to this LXC at $LXC_IP:8090.
set -euo pipefail
readonly LXC_NAME="${SECUBOX_LXC_NAME:-torrent}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.160}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
# Predictable veth pair name (default LXC naming is a random vethXXXXXX on
# every start) — the host nft egress drop-in (../nft/torrent-egress.nft)
# matches on this exact name.
readonly LXC_VETH="${SECUBOX_LXC_VETH:-veth-torrent0}"
readonly DATA_DIR="${SECUBOX_DATA_DIR:-/data/torrent}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/torrent}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
# Unprivileged LXC: container-root maps to this host UID (idmap below). The
# bind-mounted /data/torrent must be owned by it so the container can write.
readonly LXC_ROOT_UID="${SECUBOX_LXC_ROOT_UID:-100000}"
log() { printf '[torrent-install] %s\n' "$*"; }
la()  { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

mkdir -p "$STATE_DIR" "$DATA_DIR"
chown -R "$LXC_ROOT_UID:$LXC_ROOT_UID" "$DATA_DIR"
if [ -f "$SENTINEL" ]; then log "already provisioned; skipping create"; else
  # Use the DOWNLOAD template (not -t debian): gk2 runs UNPRIVILEGED containers
  # and the debian template refuses ("can't be used for unprivileged
  # containers"). Download template + idmap is the working pattern (matches
  # secubox-peertube).
  lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" -- \
    --dist debian --release bookworm --arch "$(dpkg --print-architecture)"
  # idmap: the download template copies /etc/lxc/default.conf, which on gk2
  # already provides the unprivileged u/g 0->100000 65536 mapping. Only add it
  # if absent — a DUPLICATE mapping makes newuidmap fail ("write to uid_map
  # failed: Invalid argument") and the container ABORTS at start.
  if ! grep -q '^lxc.idmap' "$LXC_PATH/$LXC_NAME/config"; then
    printf 'lxc.idmap = u 0 %s 65536\nlxc.idmap = g 0 %s 65536\n' \
      "$LXC_ROOT_UID" "$LXC_ROOT_UID" >> "$LXC_PATH/$LXC_NAME/config"
  fi
  # static IP on br-lxc (config appended)
  cat >> "$LXC_PATH/$LXC_NAME/config" <<EOF
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.veth.pair = $LXC_VETH
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW

# Persist downloaded torrent data + the library DB on host storage (survives
# LXC re-provisioning). server.js also statfs()'s /data for the disk-floor
# purge signal, so this must be a real mount, not container-overlay space.
lxc.mount.entry = $DATA_DIR data/torrent none bind,create=dir 0 0
EOF
  lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
  sleep 5
  la apt-get update
  la apt-get install -y --no-install-recommends nodejs npm ca-certificates python3 build-essential
  touch "$SENTINEL"
fi
log "node version: $(la node --version 2>/dev/null || echo MISSING)"

# --- app deploy (runs every postinst; idempotent) ---
APP_SRC="${SECUBOX_APP_SRC:-/usr/lib/secubox/torrent/app}"
la mkdir -p /opt/secubox-torrent/app /opt/secubox-torrent/www
tar -C "$APP_SRC" -cf - . | la tar -C /opt/secubox-torrent/app -xf -
tar -C /usr/share/secubox/www/torrent -cf - . | la tar -C /opt/secubox-torrent/www -xf -
la bash -lc 'cd /opt/secubox-torrent/app && npm ci --omit=dev || npm install --omit=dev'
# env file from host TOML values (exported by postinst into these vars)
la bash -c "cat > /opt/secubox-torrent/torrent.env <<EOF
TORRENT_DOWNLOAD_DIR=/data/torrent
TORRENT_MAX_ACTIVE=${TORRENT_MAX_ACTIVE:-5}
TORRENT_WEBRTC=${TORRENT_WEBRTC:-true}
TORRENT_PORT=8090
TORRENT_EPHEMERAL_TTL_HOURS=${TORRENT_TTL:-6}
TORRENT_DISK_FLOOR_GB=${TORRENT_FLOOR:-5}
EOF"
# the unit ships alongside this script (Task 8 installs both under the same
# /usr/lib/secubox/torrent/ dir so $(dirname "$0") resolves on the board)
tar -C "$(dirname "$0")" -cf - secubox-torrent.service | la tar -C /etc/systemd/system -xf -
la systemctl daemon-reload
la systemctl enable --now secubox-torrent.service
log "torrent LXC app deployed + started on $LXC_IP:8090"
