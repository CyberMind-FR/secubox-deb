#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-ytsas :: install-lxc.sh
# CyberMind — https://cybermind.fr
#
# Idempotent LXC bootstrap + app deploy for the secubox-ytsas module
# (YouTube/web-media SAS, yt-dlp fetch engine). Creates the dedicated
# unprivileged Debian LXC, installs Python + yt-dlp (+ ffmpeg for format
# merging) + FastAPI/uvicorn, then deploys the SAS app and its in-LXC systemd
# unit. The host nginx vhost (../nginx/ytsas.conf) proxies
# ytsas.gk2.secubox.in to this LXC at $LXC_IP:8091.
#
# Mirrors packages/secubox-torrent/lxc/install-lxc.sh (Node → Python swap).
set -euo pipefail
readonly LXC_NAME="${SECUBOX_LXC_NAME:-ytsas}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.180}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
# Predictable veth pair name (default LXC naming is a random vethXXXXXX on
# every start) — the host nft egress drop-in (../nft/ytsas-egress.nft) matches
# on this exact name.
readonly LXC_VETH="${SECUBOX_LXC_VETH:-veth-ytsas0}"
readonly DATA_DIR="${SECUBOX_DATA_DIR:-/data/ytsas}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/ytsas}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
# Unprivileged LXC: container-root maps to this host UID (idmap below). The
# bind-mounted /data/ytsas must be owned by it so the container can write.
readonly LXC_ROOT_UID="${SECUBOX_LXC_ROOT_UID:-100000}"
readonly PORT="${SECUBOX_YTSAS_PORT:-8091}"
log() { printf '[ytsas-install] %s\n' "$*"; }
la()  { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

mkdir -p "$STATE_DIR" "$DATA_DIR"
chown -R "$LXC_ROOT_UID:$LXC_ROOT_UID" "$DATA_DIR"
if [ -f "$SENTINEL" ]; then log "already provisioned; skipping create"; else
  # Use the DOWNLOAD template (not -t debian): gk2 runs UNPRIVILEGED containers
  # and the debian template refuses ("can't be used for unprivileged
  # containers"). Download template + idmap is the working pattern (matches
  # secubox-torrent / secubox-peertube).
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

# Persist downloaded media + the SQLite library on host storage (survives LXC
# re-provisioning). Downloads land in /data/ytsas/<id>/, library.db at
# /data/ytsas/library.db; must be a real mount, not container-overlay space.
lxc.mount.entry = $DATA_DIR data/ytsas none bind,create=dir 0 0
EOF
  lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
  sleep 5
  # Seed DNS: the download-template rootfs ships no resolver, so apt/pip can't
  # resolve deb.debian.org / pypi.org. Matches secubox-torrent/peertube.
  la sh -c 'rm -f /etc/resolv.conf; printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf'
  la apt-get update
  # ffmpeg: yt-dlp merges the best video+audio streams with it (mp4/webm).
  la apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv ca-certificates ffmpeg curl
  touch "$SENTINEL"
fi
log "python version: $(la python3 --version 2>/dev/null || echo MISSING)"

# --- Python deps (yt-dlp auto-updated EVERY run: sites change constantly, a
# stale yt-dlp silently breaks fetches). PEP 668 externally-managed env in the
# container → --break-system-packages (dedicated single-purpose LXC). ---
la pip3 install --break-system-packages --upgrade yt-dlp fastapi uvicorn \
  || log "WARN pip install/upgrade failed (network?) — keeping existing versions"
log "yt-dlp version: $(la yt-dlp --version 2>/dev/null || echo MISSING)"

# Cookie vault dir INSIDE the LXC (age-gated/private auth cookies uploaded via
# the webui land here; stays in the container, never on the host). Leaf dir.
la mkdir -p /var/lib/secubox/ytsas

# --- app deploy (runs every postinst; idempotent) ---
APP_SRC="${SECUBOX_APP_SRC:-/usr/lib/secubox/ytsas/app}"
la mkdir -p /opt/secubox-ytsas/app /opt/secubox-ytsas/www
tar -C "$APP_SRC" -cf - . | la tar -C /opt/secubox-ytsas/app -xf -
tar -C /usr/share/secubox/www/ytsas -cf - . | la tar -C /opt/secubox-ytsas/www -xf -

# env file from host TOML values (exported by postinst into these vars). The
# in-LXC unit reads it (EnvironmentFile). Paths are the app contract.
la bash -c "cat > /opt/secubox-ytsas/ytsas.env <<EOF
YTSAS_DOWNLOAD_DIR=/data/ytsas
YTSAS_DB=/data/ytsas/library.db
YTSAS_COOKIES=/var/lib/secubox/ytsas/cookies.txt
YTSAS_CONSERVE_QUEUE=/data/ytsas/.conserve-queue
YTSAS_CONSERVE_RESULTS=/data/ytsas/.conserve-results
YTSAS_PORT=$PORT
YTSAS_MAX_ACTIVE=${YTSAS_MAX_ACTIVE:-3}
YTSAS_EPHEMERAL_TTL_HOURS=${YTSAS_TTL:-6}
YTSAS_DISK_FLOOR_GB=${YTSAS_FLOOR:-5}
EOF"

# the unit ships alongside this script (rules installs both under the same
# /usr/lib/secubox/ytsas/ dir so $(dirname "$0") resolves on the board)
tar -C "$(dirname "$0")" -cf - secubox-ytsas.service | la tar -C /etc/systemd/system -xf -
la systemctl daemon-reload
la systemctl enable secubox-ytsas.service
# `enable --now` does NOT restart an already-running unit — so an in-place app
# upgrade (re-copied code above) would keep serving the OLD code. Restart so
# the new code is actually loaded (start-if-stopped is covered by restart too).
la systemctl restart secubox-ytsas.service
log "ytsas LXC app deployed + started on $LXC_IP:$PORT"
