#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# process-ops dispatches a request file to a result file (#798).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
export SECUBOX_PEERTUBE_OPS_DIR="$tmp/ops"; mkdir -p "$SECUBOX_PEERTUBE_OPS_DIR"
# Results go in a SEPARATE dir so a lingering result can't keep the
# DirectoryNotEmpty= watcher on ops/ re-firing (start-limit-hit, #798).
export SECUBOX_PEERTUBE_RESULTS_DIR="$tmp/results"; mkdir -p "$SECUBOX_PEERTUBE_RESULTS_DIR"
printf '{"op":"ping","id":"deadbeef"}' > "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.request.json"
bash "$here/sbin/peertubectl" process-ops
[ -f "$SECUBOX_PEERTUBE_RESULTS_DIR/deadbeef.result.json" ] || { echo "no result written"; exit 1; }
grep -q '"status": *"done"' "$SECUBOX_PEERTUBE_RESULTS_DIR/deadbeef.result.json" || { echo "ping not done"; exit 1; }
[ -f "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.request.json" ] && { echo "request not removed"; exit 1; }
# Regression: the result must NOT land in ops/ (that is what looped the watcher).
[ -f "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.result.json" ] && { echo "result leaked into ops/ (would re-trigger watcher)"; exit 1; }
# ops/ must be empty after draining, or peertube-ops.path re-fires → start-limit-hit.
[ -z "$(ls -A "$SECUBOX_PEERTUBE_OPS_DIR")" ] || { echo "ops/ not empty after process-ops: $(ls -A "$SECUBOX_PEERTUBE_OPS_DIR")"; exit 1; }
echo "PASS process-ops ping (result in results/, ops/ empty)"

printf '{"op":"reset-admin-password","id":"cafe0001","password":"x"}' > "$SECUBOX_PEERTUBE_OPS_DIR/cafe0001.request.json"
bash "$here/sbin/peertubectl" process-ops
grep -q '"status"' "$SECUBOX_PEERTUBE_RESULTS_DIR/cafe0001.result.json" || { echo "reset op produced no result"; exit 1; }
grep -q 'unknown op' "$SECUBOX_PEERTUBE_RESULTS_DIR/cafe0001.result.json" && { echo "reset op fell through to unknown-op (dispatch mismatch)"; exit 1; }
[ -z "$(ls -A "$SECUBOX_PEERTUBE_OPS_DIR")" ] || { echo "ops/ not empty after reset dispatch"; exit 1; }
echo "PASS reset-admin-password dispatches (ops/ empty)"
