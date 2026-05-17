#!/usr/bin/env bash
# remote-ui/round/files/usr/local/sbin/eye-firstboot-hostname.sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Set the Pi's hostname to eye-<usb-gadget-serial> exactly once at first boot.
set -euo pipefail

MARKER=/var/lib/secubox/eye-firstboot-hostname.done
[[ -f "$MARKER" ]] && exit 0
mkdir -p "$(dirname "$MARKER")"

serial=$(awk '/^Serial/ {print $3; exit}' /proc/cpuinfo)
[[ -n "$serial" ]] || exit 1

new_host="eye-${serial}"
hostnamectl set-hostname "$new_host"
tab=$'\t'
sed -i -E "s/^127\.0\.1\.1.*/127.0.1.1${tab}${new_host}/" /etc/hosts || true

touch "$MARKER"
