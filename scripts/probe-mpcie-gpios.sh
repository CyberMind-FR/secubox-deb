#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: probe-mpcie-gpios.sh
#
# Hardware investigation runbook for issue #345 — find which CP0 GPIO drives
# W_DISABLE# / PERST# / PWR_EN on the MOCHAbin mPCIe slot J5.
#
# Background: the kernel DTS patch from #255 wired the UTMI PHY to
# cp0_usb3_1 (the mPCIe USB controller) — so the SoC USB pipe is alive
# on the slot, but plugging an EP06 modem still doesn't enumerate. The
# slot's control lines (W_DISABLE#, PWR_EN, possibly WAKE#) are NOT
# declared in the current DTS, so they come up in whatever default state
# the SoC pad config leaves them in — which may be holding the modem
# powered-down. This runbook drives each *unrequested* CP0 GPIO HIGH one
# at a time, watching for a new USB enumeration event.
#
# Prerequisites: run ON THE BOARD (gk2), as root, with a known-good
# mPCIe device (EP06 modem or any mPCIe-USB device) physically seated
# in J5 and the screw tightened.
#
# Safety: this script ONLY touches CP0 GPIO lines that gpioinfo reports
# as "unused input". It snapshots dmesg + lsusb before each probe, flips
# a single line to output-HIGH for SETTLE_SEC seconds, snapshots again,
# then releases the line (libgpiod auto-restores to input on close).
# Lines marked [used] (by the kernel for SFP+, PHY reset, etc.) are
# skipped — never touched.

set -euo pipefail

readonly MODULE="probe-mpcie-gpios"
readonly VERSION="0.1.0"
readonly LOG_DIR="/var/log/secubox"
readonly LOG_FILE="${LOG_DIR}/mpcie-probe-$(date +%Y%m%d-%H%M%S).log"
readonly SETTLE_SEC="${SETTLE_SEC:-3}"
# Which gpiochips to probe. gpiochip1 = cp0_gpio0, gpiochip2 = cp0_gpio1.
# These are the two big CP0 banks on the Armada-7040. AP807 (gpiochip0)
# is system-controller / never wired to slot J5, so we skip it. SFP+
# expander (gpiochip3) and CP210x (gpiochip4) are obviously unrelated.
readonly CHIPS="${CHIPS:-gpiochip1 gpiochip2}"

usage() {
	cat <<EOF
${MODULE} v${VERSION} — sweep CP0 GPIO lines to find mPCIe J5 W_DISABLE#

usage:
  $0                       sweep all unused lines on ${CHIPS}
  $0 --baseline            snapshot only — no probing
  $0 --line gpiochipN K    probe a single line (e.g. --line gpiochip2 14)
  $0 --help

env vars:
  SETTLE_SEC=N             seconds to hold each line HIGH (default 3)
  CHIPS="gpiochipA gpiochipB"   chips to sweep (default: gpiochip1 gpiochip2)

output:
  ${LOG_DIR}/mpcie-probe-<timestamp>.log

prerequisites: run as root on the MOCHAbin, with an mPCIe device
seated in J5 (preferably the EP06 modem). The script logs:
  - baseline dmesg + lsusb -t
  - for each probed line: pre/post dmesg diff + lsusb diff
A successful probe shows a new "usb 2-1.X: new high-speed USB device"
line in the post-dmesg, AND a new device in lsusb.

EOF
}

require_root() {
	if [[ $EUID -ne 0 ]]; then
		echo "error: must run as root (need gpiochip + dmesg access)" >&2
		exit 1
	fi
}

require_libgpiod() {
	for cmd in gpiodetect gpioinfo gpioset; do
		if ! command -v "$cmd" >/dev/null; then
			echo "error: $cmd not found — install libgpiod (apt install gpiod)" >&2
			exit 1
		fi
	done
}

setup_log() {
	mkdir -p "${LOG_DIR}"
	exec > >(tee -a "${LOG_FILE}") 2>&1
	echo "=== ${MODULE} v${VERSION} — $(date -Is) ==="
	echo "log: ${LOG_FILE}"
}

snapshot_baseline() {
	echo
	echo "=== baseline ==="
	echo "--- kernel ---"
	uname -a
	echo "--- gpiodetect ---"
	gpiodetect
	echo "--- gpioinfo (probed chips: ${CHIPS}) ---"
	for chip in ${CHIPS}; do
		gpioinfo "$chip"
	done
	echo "--- lsusb -t ---"
	lsusb -t
	echo "--- lsusb ---"
	lsusb
	echo "--- lspci -tv ---"
	lspci -tv 2>/dev/null || echo "(lspci not installed)"
	echo "--- recent dmesg (last 60s) ---"
	dmesg -T --since '60 sec ago' 2>/dev/null | tail -30 || dmesg | tail -30
}

# Returns 0 if the line is safe to probe (currently "unused input").
# gpioinfo line format:
#   "	line  14:      unnamed       unused   input  active-high "
#   "	line   0:      unnamed      \"reset\"  output  active-low [used]"
# We check three things:
#   - label is "unnamed" (no consumer-side naming)
#   - direction is "input"
#   - NOT tagged [used]
line_is_safe() {
	local info="$1"
	[[ "$info" != *"[used]"* ]] || return 1
	[[ "$info" == *"input"* ]] || return 1
	[[ "$info" == *"unused"* ]] || return 1
	return 0
}

probe_line() {
	local chip="$1"
	local n="$2"

	echo
	echo "── probe ${chip} line ${n} ──"

	# Snapshot pre-state
	local pre_lsusb pre_dmesg_tail
	pre_lsusb=$(lsusb | sort)
	pre_dmesg_tail=$(dmesg | tail -1)

	# Drive HIGH for SETTLE_SEC; gpioset --mode=time is reliable but
	# blocks for the duration. Spawn in background so we can race a
	# read of dmesg.
	timeout "$((SETTLE_SEC + 2))" gpioset --mode=time --sec="${SETTLE_SEC}" \
		"${chip}" "${n}=1" &
	local gpio_pid=$!

	sleep "$((SETTLE_SEC - 1))"

	# Snapshot post-state (while still HIGH)
	local post_lsusb post_dmesg
	post_lsusb=$(lsusb | sort)
	# dmesg lines since pre_dmesg_tail
	post_dmesg=$(dmesg | awk -v marker="${pre_dmesg_tail}" '
		BEGIN { capture=0 }
		index($0, marker) { capture=1; next }
		capture { print }
	')

	# Wait for gpioset to finish — releases the line (libgpiod
	# restores it to input automatically).
	wait "${gpio_pid}" 2>/dev/null || true

	# Diff lsusb
	local lsusb_diff
	lsusb_diff=$(diff <(echo "${pre_lsusb}") <(echo "${post_lsusb}") || true)

	if [[ -n "${lsusb_diff}" ]] || echo "${post_dmesg}" | grep -qiE 'new (high|full|low|super)-speed usb|quectel|2c7c'; then
		echo "  *** CHANGE DETECTED ***"
		echo "  --- lsusb diff ---"
		echo "${lsusb_diff:-(no diff)}"
		echo "  --- new dmesg ---"
		echo "${post_dmesg}" | sed 's/^/    /'
	else
		echo "  no change"
	fi
}

sweep_chip() {
	local chip="$1"
	echo
	echo "=== sweep ${chip} ==="
	# Parse gpioinfo; for each "unused input" line, run probe.
	while IFS= read -r line; do
		if [[ "$line" =~ line\ +([0-9]+): ]]; then
			local n="${BASH_REMATCH[1]}"
			if line_is_safe "$line"; then
				probe_line "${chip}" "${n}"
			fi
		fi
	done < <(gpioinfo "${chip}")
}

main() {
	require_root
	require_libgpiod

	case "${1:-}" in
		--help|-h)
			usage; exit 0 ;;
		--baseline)
			setup_log
			snapshot_baseline
			exit 0 ;;
		--line)
			[[ $# -eq 3 ]] || { usage; exit 1; }
			setup_log
			snapshot_baseline
			probe_line "$2" "$3"
			exit 0 ;;
		"")
			setup_log
			snapshot_baseline
			for chip in ${CHIPS}; do
				sweep_chip "${chip}"
			done
			echo
			echo "=== sweep complete — review ${LOG_FILE} for any *** CHANGE DETECTED *** ==="
			;;
		*)
			usage; exit 1 ;;
	esac
}

main "$@"
