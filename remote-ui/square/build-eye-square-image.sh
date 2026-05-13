#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: remote-ui/square — build-eye-square-image.sh
# Builds a Raspberry Pi OS Bookworm arm64 image for the Pi 4B/400 Eye Square variant.
set -euo pipefail
readonly MODULE="build-eye-square-image"
readonly VERSION="0.1.0"

BASE_IMAGE="${BASE_IMAGE:-}"
OUT_DIR="${OUT_DIR:-/tmp}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$(dirname "$SCRIPT_DIR")/.." && pwd)"

usage() {
    cat <<EOF
Usage: $0 [-i base-image.img.xz] [-o /output/dir]
Build a SecuBox Eye Square arm64 image targeting Pi 4B / Pi 400.

Options:
  -i BASE   Raspberry Pi OS Bookworm arm64 base .img.xz (auto-downloaded if missing)
  -o DIR    Output directory (default: /tmp)
EOF
}

while getopts "i:o:h" opt; do
    case $opt in
        i) BASE_IMAGE="$OPTARG" ;;
        o) OUT_DIR="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

log() { echo "[$MODULE] $*"; }
err() { echo "[$MODULE] ERROR: $*" >&2; }

# Require root
if [ "$(id -u)" -ne 0 ]; then
    err "Must run as root (uses losetup, mount, chroot)"; exit 1
fi

# Download base image if needed
BASE_URL="https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2024-11-19/2024-11-19-raspios-bookworm-arm64-lite.img.xz"
if [ -z "$BASE_IMAGE" ]; then
    BASE_IMAGE="$OUT_DIR/raspios-lite-arm64.img.xz"
    if [ ! -f "$BASE_IMAGE" ]; then
        log "Downloading base image..."
        wget -q -O "$BASE_IMAGE" "$BASE_URL"
    fi
fi

WORK_IMG="$OUT_DIR/secubox-eye-square-work.img"
log "Decompressing to $WORK_IMG"
xzcat "$BASE_IMAGE" > "$WORK_IMG"

log "Growing image by 2 GB"
truncate -s +2G "$WORK_IMG"

LOOP=$(losetup --partscan --find --show "$WORK_IMG")
log "Loop device: $LOOP"
parted "$LOOP" --script resizepart 2 100%
e2fsck -fy "${LOOP}p2" || true
resize2fs "${LOOP}p2"

BOOT_MNT=$(mktemp -d)
ROOT_MNT=$(mktemp -d)
mount "${LOOP}p1" "$BOOT_MNT"
mount "${LOOP}p2" "$ROOT_MNT"
trap 'umount "$BOOT_MNT" 2>/dev/null || true; umount "$ROOT_MNT/proc" "$ROOT_MNT/dev" "$ROOT_MNT/sys" 2>/dev/null || true; umount "$ROOT_MNT" 2>/dev/null || true; losetup -d "$LOOP" 2>/dev/null || true' EXIT

cp /usr/bin/qemu-aarch64-static "$ROOT_MNT/usr/bin/"
mount -t proc none "$ROOT_MNT/proc"
mount -o bind /dev "$ROOT_MNT/dev"
mount -o bind /sys "$ROOT_MNT/sys"

log "Installing apt packages in chroot..."
# PySide6 + qasync are NOT in Debian Bookworm — only PySide2 is. To keep the
# code identical to what we tested (PySide6 imports), install via pip inside
# the chroot. arm64 PEP 668 enforces --break-system-packages.
chroot "$ROOT_MNT" /bin/bash -c "
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    chromium openbox xserver-xorg xinit unclutter \
    python3-fastapi python3-uvicorn python3-websockets \
    python3-httpx python3-pip \
    nginx-light apparmor-utils
pip install --break-system-packages pyside6 qasync
"

log "Installing remote-ui/common/ and remote-ui/round/ payloads..."
mkdir -p "$ROOT_MNT/var/www"
cp -r "$REPO_ROOT/remote-ui/common" "$ROOT_MNT/var/www/common"
mkdir -p "$ROOT_MNT/var/www/secubox-round"
cp "$REPO_ROOT/remote-ui/round/index.html" "$ROOT_MNT/var/www/secubox-round/"
# Inject square-bridge.js into the served index.html
sed -i 's|</body>|<script src="/local/square-bridge.js"></script></body>|' \
    "$ROOT_MNT/var/www/secubox-round/index.html"
mkdir -p "$ROOT_MNT/var/www/secubox-square"
cp "$REPO_ROOT/remote-ui/square/square-bridge.js" "$ROOT_MNT/var/www/secubox-square/"

log "Installing config files (systemd, openbox, nginx, udev, apparmor, firstboot)..."
cp -r "$REPO_ROOT/remote-ui/square/files/." "$ROOT_MNT/"
chmod +x "$ROOT_MNT/usr/local/sbin/firstboot.sh"
chmod +x "$ROOT_MNT/home/secubox/.xinitrc"
chmod +x "$ROOT_MNT/etc/openbox/autostart"

log "Installing Python packages..."
mkdir -p "$ROOT_MNT/usr/lib/python3/dist-packages"
cp -r "$REPO_ROOT/packages/secubox-eye-square/helper/eye_square_helper" \
    "$ROOT_MNT/usr/lib/python3/dist-packages/"
cp -r "$REPO_ROOT/packages/secubox-eye-square/right_panel/secubox_eye_square_right_panel" \
    "$ROOT_MNT/usr/lib/python3/dist-packages/"

log "Creating secubox-eye-square system user + secubox login user + runtime dirs..."
chroot "$ROOT_MNT" /bin/bash -c "
# Helper service runs as this system user (privileged operations, capabilities)
useradd --system --no-create-home --shell /usr/sbin/nologin secubox-eye-square || true

# secubox is the LOGIN user that runs the kiosk: xinit, chromium, right-panel.
# Default password 'secubox' (changed via the eye-square.toml login_pass field
# downstream; this OS-level password is for tty/SSH access if anyone needs it).
# firstboot.sh imports authorized_keys from /boot/firmware/secubox-key.pub.
# render group needed for chromium /dev/dri access on Pi 4B.
useradd --create-home --shell /bin/bash --groups sudo,video,audio,input,render,tty secubox || true
echo 'secubox:secubox' | chpasswd

mkdir -p /run/secubox /var/log/secubox /home/secubox/.config/openbox /home/secubox/.ssh
chown secubox-eye-square:secubox-eye-square /run/secubox /var/log/secubox
chown -R secubox:secubox /home/secubox
chmod 700 /home/secubox/.ssh
"

log "Installing /usr/local/sbin/ symlinks for shared OTG scripts..."
# Phase 1's common/shell/secubox-otg-gadget.sh lands at /var/www/common/shell/
# (via the nginx-aliased remote-ui/common deploy). The systemd unit
# secubox-otg-gadget.service calls /usr/local/sbin/secubox-otg-gadget.sh —
# bridge that path here. Same for host-up.sh (used by udev on SecuBox hosts).
chroot "$ROOT_MNT" /bin/bash -c "
ln -sf /var/www/common/shell/secubox-otg-gadget.sh /usr/local/sbin/secubox-otg-gadget.sh
ln -sf /var/www/common/shell/secubox-otg-host-up.sh /usr/local/sbin/secubox-otg-host-up.sh
"

log "Patching /boot/firmware/config.txt..."
cat >> "$BOOT_MNT/config.txt" <<'EOF'

# SecuBox Eye Square — Pi 4B + 7" 800x480 DSI + USB-C peripheral
dtoverlay=vc4-kms-v3d
display_auto_detect=1
dtoverlay=dwc2,dr_mode=peripheral
enable_uart=0
EOF

log "Adding kernel modules to /etc/modules..."
cat >> "$ROOT_MNT/etc/modules" <<'EOF'
dwc2
libcomposite
configfs
EOF

log "Enabling systemd units + masking Pi OS userconfig/getty + setting graphical.target..."
chroot "$ROOT_MNT" /bin/bash -c "
# Mask the two Pi OS services that hijack tty1 and reset default.target.
# userconfig.service prompts for user setup on first boot and, if it doesn't
# find a desktop env, runs raspi-config to flip default.target → multi-user.target.
# getty@tty1.service competes with secubox-kiosk-x.service for /dev/tty1.
systemctl mask userconfig.service || true
systemctl mask getty@tty1.service || true

systemctl enable ssh.service || true
systemctl enable nginx || true
systemctl enable secubox-firstboot.service || true
systemctl enable secubox-otg-gadget.service || true
systemctl enable secubox-eye-square-helper.service || true
systemctl enable secubox-kiosk-x.service || true
systemctl enable secubox-square-chromium.service || true
systemctl enable secubox-square-right-panel.service || true
systemctl set-default graphical.target || true
"

log "Activating AppArmor profile..."
chroot "$ROOT_MNT" /bin/bash -c "
apparmor_parser -r /etc/apparmor.d/secubox-eye-square-helper || true
"

log "Cleaning apt cache..."
chroot "$ROOT_MNT" /bin/bash -c "apt-get clean; rm -rf /var/lib/apt/lists/*"

umount "$ROOT_MNT/proc" "$ROOT_MNT/dev" "$ROOT_MNT/sys"
umount "$BOOT_MNT" "$ROOT_MNT"
losetup -d "$LOOP"
trap - EXIT

OUT_IMG="$OUT_DIR/secubox-eye-square_${VERSION}_arm64.img.xz"
log "Compressing to $OUT_IMG (this may take several minutes)..."
xz -T0 -e -9 -c "$WORK_IMG" > "$OUT_IMG"
rm -f "$WORK_IMG"

log "Built: $OUT_IMG"
log "Size: $(du -h "$OUT_IMG" | cut -f1)"
