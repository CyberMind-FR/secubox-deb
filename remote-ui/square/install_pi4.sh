#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: remote-ui/square — install_pi4.sh
# Flash a SecuBox Eye Square arm64 image to an SD card + seed first-boot config.
set -euo pipefail
readonly MODULE="install_pi4"

DEVICE=""
IMAGE=""
SSID=""
PSK=""
HOSTNAME_VAL=""
USERNAME="secubox"
PUBKEY=""
WIFI_KIOSK=0

usage() {
    cat <<EOF
Usage: $0 -d DEVICE -i IMAGE [-s SSID -p PSK] [-h HOSTNAME] [-u USER] [-k PUBKEY] [-w]

Required:
  -d DEVICE    SD card block device (e.g. /dev/sdb, /dev/mmcblk1)
  -i IMAGE     Path to secubox-eye-square_*.img.xz

Optional:
  -s SSID      WiFi SSID
  -p PSK       WiFi password (WPA2)
  -h HOSTNAME  hostname (default: auto-generated at first boot)
  -u USER      username (default: secubox)
  -k PUBKEY    Path to SSH public key
  -w           Pre-seed WiFi credentials (kiosk-mode)
EOF
    exit 1
}

while getopts "d:i:s:p:h:u:k:w" opt; do
    case $opt in
        d) DEVICE="$OPTARG" ;;
        i) IMAGE="$OPTARG" ;;
        s) SSID="$OPTARG" ;;
        p) PSK="$OPTARG" ;;
        h) HOSTNAME_VAL="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        k) PUBKEY="$OPTARG" ;;
        w) WIFI_KIOSK=1 ;;
        *) usage ;;
    esac
done

[ -z "$DEVICE" ] && usage
[ -z "$IMAGE" ] && usage

# Safety: refuse system disks
for forbidden in /dev/sda /dev/nvme0n1 /dev/mmcblk0; do
    if [ "$DEVICE" = "$forbidden" ]; then
        echo "[$MODULE] REFUSING to flash $forbidden (system disk)" >&2
        exit 1
    fi
done

if [ ! -b "$DEVICE" ]; then
    echo "[$MODULE] ERROR: $DEVICE is not a block device" >&2; exit 1
fi

echo "[$MODULE] About to flash $IMAGE to $DEVICE."
echo "[$MODULE] ALL DATA ON $DEVICE WILL BE ERASED."
read -rp "Type 'YES' to continue: " confirm
[ "$confirm" = "YES" ] || { echo "Aborted."; exit 1; }

echo "[$MODULE] Flashing..."
xzcat "$IMAGE" | dd of="$DEVICE" bs=4M status=progress conv=fsync
sync

BOOT_MNT=$(mktemp -d)
mount "${DEVICE}1" "$BOOT_MNT" 2>/dev/null || mount "${DEVICE}p1" "$BOOT_MNT"

touch "$BOOT_MNT/ssh"

if [ -n "${SSID:-}" ] && [ -n "${PSK:-}" ]; then
    cat > "$BOOT_MNT/wpa_supplicant.conf" <<EOFWPA
country=FR
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="$SSID"
    psk="$PSK"
    key_mgmt=WPA-PSK
}
EOFWPA
fi

if [ -n "${PUBKEY:-}" ] && [ -f "$PUBKEY" ]; then
    cp "$PUBKEY" "$BOOT_MNT/secubox-key.pub"
fi

cat > "$BOOT_MNT/secubox-eye-square.toml" <<EOFTOML
# Operator-edited config. firstboot.sh moves to /etc/secubox/eye-square.toml then deletes.
[transport]
api_otg_base = "http://10.55.0.1:8000"
api_wifi_base = "http://secubox.local:8000"
login_user = "dashboard"
login_pass = "CHANGE-ME-BEFORE-DEPLOYMENT"
simulate = false

[right_panel]
auto_switch_on_alert = false
idle_return_seconds = 300
EOFTOML

[ -n "${HOSTNAME_VAL:-}" ] && echo "$HOSTNAME_VAL" > "$BOOT_MNT/secubox-hostname"

umount "$BOOT_MNT"
rmdir "$BOOT_MNT"

echo "[$MODULE] Done. Insert SD into Pi 4B/400 (powered via GPIO 5V) and boot."
