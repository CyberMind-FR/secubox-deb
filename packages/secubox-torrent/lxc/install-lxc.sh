#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-torrent :: install-lxc.sh
# CyberMind — https://cybermind.fr
#
# Skeleton, idempotent LXC bootstrap for the secubox-torrent module (v2.0,
# WebTorrent streaming pivot). Creates the dedicated Debian LXC + installs
# Node so later tasks can layer the WebTorrent engine (webtorrent + fastify
# + better-sqlite3, optionally @roamhq/wrtc — see SPIKE-RESULT.md) on top.
# NOT executed against prod in this task; full provisioning (bridge/nat
# setup, app deploy, systemd unit, nginx wiring) lands in a later task.
set -euo pipefail
readonly LXC_NAME="${SECUBOX_LXC_NAME:-torrent}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.130}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DATA_DIR="${SECUBOX_DATA_DIR:-/data/torrent}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/torrent}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
log() { printf '[torrent-install] %s\n' "$*"; }
la()  { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

mkdir -p "$STATE_DIR" "$DATA_DIR"
if [ -f "$SENTINEL" ]; then log "already provisioned; skipping create"; else
  lxc-create -n "$LXC_NAME" -P "$LXC_PATH" -t debian -- -r bookworm -a arm64
  # network: static IP on br-lxc (config appended to the container config)
  cat >> "$LXC_PATH/$LXC_NAME/config" <<EOF
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
EOF
  lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
  sleep 5
  la apt-get update
  la apt-get install -y --no-install-recommends nodejs npm ca-certificates
  touch "$SENTINEL"
fi
log "node version: $(la node --version 2>/dev/null || echo MISSING)"
