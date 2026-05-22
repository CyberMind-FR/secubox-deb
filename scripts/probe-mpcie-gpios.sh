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
# powered-down. This runbook drives carefully-selected CP0 GPIO lines
# HIGH one at a time, watching for a new USB enumeration event.
#
# Prerequisites: run ON THE BOARD (gk2), as root, with a known-good
# mPCIe device (EP06 modem or any mPCIe-USB device) physically seated
# in J5 and the screw tightened.
#
# Safety (v0.2.0): gpioinfo's "[used]" tag only reflects lines the
# kernel *requested* — some unrequested lines on the MOCHAbin are
# physically wired to critical functions (eth switch reset, USB hub
# power-enable, pca9554 IRQ, etc.) and driving them HIGH crashed
# gk2 on the v0.1.0 blanket sweep (incident 2026-05-22). v0.2.0
# therefore:
#   1. Skips known-dangerous lines unconditionally (DANGER_LINES).
#   2. Defaults to --dry-run (lists candidates without driving them).
#   3. Requires --commit AND --line for the actual probe — no
#      blanket sweep mode anymore.
#   4. Refuses to touch gpiochip2 (CP0 GPIO1) entirely without an
#      explicit --allow-chip2 flag (we have no per-line schematic
#      mapping for that bank yet).

set -euo pipefail

readonly MODULE="probe-mpcie-gpios"
readonly VERSION="0.2.0"

# Lines known (from DTS inspection) to be wired to critical board
# functions even when gpioinfo reports them as "unused input". Format:
# "chip:line". Driving any of these would risk a board crash.
readonly -a DANGER_LINES=(
	# gpiochip1 = cp0_gpio0
	"gpiochip1:1"   # mpp1 — cp0_switch_pins gpio function (Topaz reset)
	"gpiochip1:9"   # mpp9 — cp0_pcie_reset_pins (PCIe2 PERST#); driving it can crash the slot
	"gpiochip1:27"  # mpp27 — pca9554_int (SFP+ I/O expander IRQ); IRQ storm risk
	# gpiochip2 = cp0_gpio1 — entire bank held off by default
	# (no per-line schematic; require --allow-chip2 to probe)
)
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
${MODULE} v${VERSION} — probe one CP0 GPIO line to find mPCIe J5 W_DISABLE#

usage:
  $0                                snapshot + list dry-run candidates (default)
  $0 --baseline                     snapshot only — no candidate listing
  $0 --line gpiochipN K             dry-run a single line (refuses if danger-listed)
  $0 --line gpiochipN K --commit    actually drive the line HIGH for SETTLE_SEC
  $0 --allow-chip2 ...              required to touch any gpiochip2 line
  $0 --help

env vars:
  SETTLE_SEC=N                      seconds to hold the line HIGH (default 3)

output:
  ${LOG_DIR}/mpcie-probe-<timestamp>.log

WARNING — read this before --commit:

  v0.1.0 of this script ran a blanket sweep across all "unused input"
  CP0 GPIOs. That took gk2 hard-down on 2026-05-22 — some unrequested
  lines are physically wired to critical functions (eth switch reset,
  PCIe2 PERST#, pca9554 IRQ, etc.) even though the kernel never
  requests them. v0.2.0 therefore refuses to run a blanket sweep at
  all, and the default mode just lists candidates without driving
  anything.

  When you do --commit a single line, make sure you can physically
  reach the MOCHAbin to power-cycle it if the board locks up.

prerequisites: run as root on the MOCHAbin, with an mPCIe device
(preferably the EP06 modem) physically seated in J5 and the retention
screw tightened.

A successful probe shows a new "usb 2-1.X: new high-speed USB device"
line in the post-dmesg diff AND a new device in lsusb.

EOF
}

# True if "chip:line" matches an entry in DANGER_LINES (case-sensitive).
is_danger_line() {
	local key="$1"
	local entry
	for entry in "${DANGER_LINES[@]}"; do
		[[ "$entry" == "$key" ]] && return 0
	done
	return 1
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

# gpioinfo line format:
#   "	line  14:      unnamed       unused   input  active-high "
#   "	line   0:      unnamed      \"reset\"  output  active-low [used]"
# A "candidate" is: unnamed + unused + input + NOT in DANGER_LINES.
line_is_candidate() {
	local chip="$1"
	local info="$2"
	local n
	if [[ "$info" =~ line\ +([0-9]+): ]]; then
		n="${BASH_REMATCH[1]}"
	else
		return 1
	fi
	[[ "$info" != *"[used]"* ]] || return 1
	[[ "$info" == *"input"* ]] || return 1
	[[ "$info" == *"unused"* ]] || return 1
	is_danger_line "${chip}:${n}" && return 1
	return 0
}

list_candidates() {
	local chip="$1"
	echo
	echo "=== candidates on ${chip} ==="
	while IFS= read -r line; do
		if line_is_candidate "${chip}" "${line}"; then
			# Extract line number for the summary
			[[ "$line" =~ line\ +([0-9]+): ]] && echo "  ${chip}:${BASH_REMATCH[1]}"
		fi
	done < <(gpioinfo "${chip}")
}

probe_line_commit() {
	local chip="$1"
	local n="$2"

	# Hard gate — never drive a danger-listed line, even with --commit.
	if is_danger_line "${chip}:${n}"; then
		echo "REFUSED: ${chip}:${n} is in DANGER_LINES — driving it" \
			"risks crashing the board (see header comment)." >&2
		exit 1
	fi

	# gpiochip2 entirely off-limits without --allow-chip2.
	if [[ "${chip}" == "gpiochip2" && "${ALLOW_CHIP2:-0}" != "1" ]]; then
		echo "REFUSED: gpiochip2 (cp0_gpio1) requires --allow-chip2 — no" \
			"per-line schematic mapping for that bank yet." >&2
		exit 1
	fi

	echo
	echo "── probe ${chip} line ${n} (COMMIT, HIGH for ${SETTLE_SEC}s) ──"

	local pre_lsusb pre_dmesg_tail
	pre_lsusb=$(lsusb | sort)
	pre_dmesg_tail=$(dmesg | tail -1)

	# Drive HIGH for SETTLE_SEC seconds. gpioset releases the line
	# (libgpiod restores it to input on close).
	timeout "$((SETTLE_SEC + 2))" gpioset --mode=time --sec="${SETTLE_SEC}" \
		"${chip}" "${n}=1" &
	local gpio_pid=$!
	sleep "$((SETTLE_SEC - 1))"

	local post_lsusb post_dmesg
	post_lsusb=$(lsusb | sort)
	post_dmesg=$(dmesg | awk -v marker="${pre_dmesg_tail}" '
		BEGIN { capture=0 }
		index($0, marker) { capture=1; next }
		capture { print }
	')

	wait "${gpio_pid}" 2>/dev/null || true

	local lsusb_diff
	lsusb_diff=$(diff <(echo "${pre_lsusb}") <(echo "${post_lsusb}") || true)

	if [[ -n "${lsusb_diff}" ]] || echo "${post_dmesg}" | grep -qiE 'new (high|full|low|super)-speed usb|quectel|2c7c'; then
		echo "  *** CHANGE DETECTED ***"
		echo "  --- lsusb diff ---"
		echo "${lsusb_diff:-(no diff)}"
		echo "  --- new dmesg ---"
		printf '    %s\n' "${post_dmesg}"
	else
		echo "  no change"
	fi
}

probe_line_dryrun() {
	local chip="$1"
	local n="$2"
	echo
	echo "── DRY-RUN ${chip}:${n} ──"
	if is_danger_line "${chip}:${n}"; then
		echo "  REFUSED: in DANGER_LINES"
		return
	fi
	if [[ "${chip}" == "gpiochip2" && "${ALLOW_CHIP2:-0}" != "1" ]]; then
		echo "  REFUSED: gpiochip2 requires --allow-chip2"
		return
	fi
	# Verify the line is currently unrequested and an input.
	local info
	info=$(gpioinfo "${chip}" 2>/dev/null | awk -v n="${n}" '$2 == n":"')
	if [[ -z "${info}" ]]; then
		echo "  ERROR: line ${n} not found on ${chip}"
		return
	fi
	if [[ "${info}" == *"[used]"* ]]; then
		echo "  REFUSED: line is currently [used] by the kernel"
		return
	fi
	echo "  OK: --commit would drive ${chip}:${n} HIGH for ${SETTLE_SEC}s"
}

main() {
	require_root
	require_libgpiod

	local mode="default"
	local chip=""
	local n=""
	local commit=0

	while [[ $# -gt 0 ]]; do
		case "$1" in
			--help|-h)
				usage; exit 0 ;;
			--baseline)
				mode="baseline"; shift ;;
			--line)
				[[ $# -ge 3 ]] || { usage; exit 1; }
				mode="line"; chip="$2"; n="$3"; shift 3 ;;
			--commit)
				commit=1; shift ;;
			--allow-chip2)
				ALLOW_CHIP2=1; shift ;;
			*)
				usage; exit 1 ;;
		esac
	done

	setup_log

	case "${mode}" in
		baseline)
			snapshot_baseline
			;;
		line)
			snapshot_baseline
			if [[ "${commit}" == "1" ]]; then
				probe_line_commit "${chip}" "${n}"
			else
				probe_line_dryrun "${chip}" "${n}"
				echo
				echo "(dry-run — pass --commit to actually drive the line)"
			fi
			;;
		default)
			snapshot_baseline
			list_candidates gpiochip1
			if [[ "${ALLOW_CHIP2:-0}" == "1" ]]; then
				list_candidates gpiochip2
			else
				echo
				echo "=== gpiochip2 candidates suppressed ==="
				echo "  pass --allow-chip2 to list (no per-line schematic yet)"
			fi
			echo
			echo "=== next step ==="
			echo "  pick a candidate, then:"
			echo "    $0 --line <chip> <line>           # dry-run"
			echo "    $0 --line <chip> <line> --commit  # actually drive"
			;;
	esac
}

main "$@"
