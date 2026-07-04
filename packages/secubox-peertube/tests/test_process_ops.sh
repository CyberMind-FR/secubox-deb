#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# process-ops dispatches a request file to a result file (#798).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
export SECUBOX_PEERTUBE_OPS_DIR="$tmp/ops"; mkdir -p "$SECUBOX_PEERTUBE_OPS_DIR"
printf '{"op":"ping","id":"deadbeef"}' > "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.request.json"
bash "$here/sbin/peertubectl" process-ops
[ -f "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.result.json" ] || { echo "no result written"; exit 1; }
grep -q '"status": *"done"' "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.result.json" || { echo "ping not done"; exit 1; }
[ -f "$SECUBOX_PEERTUBE_OPS_DIR/deadbeef.request.json" ] && { echo "request not removed"; exit 1; }
echo "PASS process-ops ping"

printf '{"op":"reset-admin-password","id":"cafe0001","password":"x"}' > "$SECUBOX_PEERTUBE_OPS_DIR/cafe0001.request.json"
bash "$here/sbin/peertubectl" process-ops
grep -q '"status"' "$SECUBOX_PEERTUBE_OPS_DIR/cafe0001.result.json" || { echo "reset op produced no result"; exit 1; }
grep -q 'unknown op' "$SECUBOX_PEERTUBE_OPS_DIR/cafe0001.result.json" && { echo "reset op fell through to unknown-op (dispatch mismatch)"; exit 1; }
echo "PASS reset-admin-password dispatches"
