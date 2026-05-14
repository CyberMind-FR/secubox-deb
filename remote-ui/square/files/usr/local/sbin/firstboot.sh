#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: remote-ui/square — firstboot.sh
# Validates GPIO 5V power (USB-C peripheral mode requirement),
# sets hostname, imports SSH key + eye-square.toml from /boot/firmware,
# enables systemd units, then disables itself.
set -euo pipefail
readonly MODULE="secubox-eye-square-firstboot"
readonly STAMP=/etc/.secubox-eye-square-firstboot-done

log() { echo "[$MODULE] $*"; }

if [ -e "$STAMP" ]; then
    log "firstboot already done; exit."
    exit 0
fi

# ──────────────────────────────────────────────────────────────────────────────
# 1. Power-source validation — USB-C peripheral mode requires GPIO 5V power
# ──────────────────────────────────────────────────────────────────────────────
POE_ONLINE=0
if [ -r /sys/class/power_supply/rpi-poe-power-supply/online ]; then
    POE_ONLINE=$(cat /sys/class/power_supply/rpi-poe-power-supply/online)
fi
GPIO_OK=0
if grep -q '^over_voltage' /boot/firmware/config.txt 2>/dev/null; then
    GPIO_OK=1
fi
if [ "$POE_ONLINE" = "0" ] && [ "$GPIO_OK" = "0" ]; then
    log "WARNING: cannot confirm GPIO 5V power. USB-C peripheral mode may not work."
    log "If USB gadget fails to enumerate, power board via GPIO pins 2/6 or PoE HAT."
    systemctl mask secubox-otg-gadget.service || true
fi

# ──────────────────────────────────────────────────────────────────────────────
# 2. Resize root partition to fill SD
# ──────────────────────────────────────────────────────────────────────────────
ROOT_DEV=$(findmnt -no SOURCE /)
ROOT_DISK=$(lsblk -no PKNAME "$ROOT_DEV" 2>/dev/null | head -1)
if [ -n "$ROOT_DISK" ]; then
    log "Resizing $ROOT_DEV"
    parted "/dev/$ROOT_DISK" --script resizepart 2 100% || true
    resize2fs "$ROOT_DEV" || true
fi

# ──────────────────────────────────────────────────────────────────────────────
# 3. Hostname based on board model + last 6 hex of serial
# ──────────────────────────────────────────────────────────────────────────────
MODEL=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "rpi")
SERIAL_FULL=$(tr -d '\0' < /sys/firmware/devicetree/base/serial-number 2>/dev/null || echo "000000000000")
SERIAL_SHORT="${SERIAL_FULL: -6}"
case "$MODEL" in
    *"Pi 400"*) PREFIX="secubox-eye-square-400" ;;
    *)          PREFIX="secubox-eye-square" ;;
esac
HOSTNAME="${PREFIX}-${SERIAL_SHORT}"
echo "$HOSTNAME" > /etc/hostname
sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$HOSTNAME/" /etc/hosts
hostnamectl set-hostname "$HOSTNAME" || true
log "Hostname: $HOSTNAME"

# ──────────────────────────────────────────────────────────────────────────────
# 4. Import SSH authorized_keys from /boot/firmware/secubox-key.pub
# ──────────────────────────────────────────────────────────────────────────────
if [ -f /boot/firmware/secubox-key.pub ]; then
    mkdir -p /home/secubox/.ssh
    cat /boot/firmware/secubox-key.pub >> /home/secubox/.ssh/authorized_keys
    chmod 700 /home/secubox/.ssh
    chmod 600 /home/secubox/.ssh/authorized_keys
    chown -R secubox:secubox /home/secubox/.ssh || true
    rm -f /boot/firmware/secubox-key.pub
    log "SSH authorized_keys installed"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 5. Bootstrap eye-square.toml from /boot/firmware/secubox-eye-square.toml
# ──────────────────────────────────────────────────────────────────────────────
if [ -f /boot/firmware/secubox-eye-square.toml ]; then
    mkdir -p /etc/secubox
    cp /boot/firmware/secubox-eye-square.toml /etc/secubox/eye-square.toml
    chmod 600 /etc/secubox/eye-square.toml
    chown root:secubox-eye-square /etc/secubox/eye-square.toml || true
    rm -f /boot/firmware/secubox-eye-square.toml
    log "eye-square.toml installed"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 6. Enable services
# ──────────────────────────────────────────────────────────────────────────────
systemctl enable secubox-otg-gadget.service || true
systemctl enable secubox-eye-square-helper.service || true
systemctl enable secubox-square-kiosk.service || true

# ──────────────────────────────────────────────────────────────────────────────
# 7. Mark done
# ──────────────────────────────────────────────────────────────────────────────
touch "$STAMP"
log "firstboot complete"
