#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Phase 2 deploy-time helper. Idempotently makes the board's
# /usr/local/bin/sync-mitmproxy-routes.sh treat 10.100.0.10–.12 as
# live containers (mail/horde/roundcube) instead of "dead" ones that
# get auto-rerouted to webui.
#
# Also adds the rspamd.gk2.secubox.in entry to /srv/mitmproxy/haproxy-routes.json
# (host copy AND mitmproxy LXC copy) so the Rspamd web UI is reachable via WAF.

set -euo pipefail

SCRIPT=/usr/local/bin/sync-mitmproxy-routes.sh
if [ -f "$SCRIPT" ]; then
    # Remove 10.100.0.10, .11, .12 from DEAD_CONTAINER_IPS if present (idempotent).
    for ip in 10.100.0.10 10.100.0.11 10.100.0.12; do
        sed -i "s| ${ip}||g" "$SCRIPT" || true
    done
    if grep -q '^DEAD_CONTAINER_IPS=' "$SCRIPT"; then
        echo "[phase2] DEAD_CONTAINER_IPS now: $(grep '^DEAD_CONTAINER_IPS=' "$SCRIPT")"
    fi
else
    echo "[phase2] $SCRIPT not found — skipping sync-script patch"
fi

# Apply the route in two places (host + mitmproxy LXC) and detect/repair drift.
#
# Phase 2 lesson (deploy 2026-05-16): the host copy update succeeded but the
# LXC copy did not on first run — gate 11 of the smoke caught it. We now
# verify each write reads back the expected value and fail loudly if not.

RSPAMD_HOST="${RSPAMD_HOST:-10.100.0.10}"
RSPAMD_CTRL_PORT="${RSPAMD_CTRL_PORT:-11334}"
RSPAMD_FQDN="${RSPAMD_FQDN:-rspamd.gk2.secubox.in}"

apply_route_python() {
    # stdin: json path
    # args: fqdn host port
    python3 - "$@" <<'PY'
import json, sys
path, fqdn, host, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
try:
    d = json.load(open(path))
except FileNotFoundError:
    print(f"[phase2] {path} not present — created with single entry")
    d = {}
expected = [host, port]
d[fqdn] = expected
json.dump(d, open(path, "w"), indent=2)
# Read back + verify
verify = json.load(open(path))
got = verify.get(fqdn)
if got != expected:
    print(f"[phase2] FAILED verify in {path}: got {got!r}, expected {expected!r}", file=sys.stderr)
    sys.exit(1)
print(f"[phase2] {path}: {fqdn} → {expected}")
PY
}

# 1) Host copy.
HOST_JSON=/srv/mitmproxy/haproxy-routes.json
if [ -d "$(dirname "$HOST_JSON")" ]; then
    apply_route_python "$HOST_JSON" "$RSPAMD_FQDN" "$RSPAMD_HOST" "$RSPAMD_CTRL_PORT"
else
    echo "[phase2] $(dirname "$HOST_JSON") not present, skipping host copy"
fi

# 2) mitmproxy LXC copy — write via `lxc-attach` so we don't have to guess
# where the LXC rootfs is mounted. Also restart mitmproxy to pick up the new
# route map (it reads at startup, not live).
if command -v lxc-attach >/dev/null 2>&1 && lxc-info -n mitmproxy 2>/dev/null | grep -q RUNNING; then
    lxc-attach -n mitmproxy -- bash -c "
        python3 - /srv/mitmproxy/haproxy-routes.json '$RSPAMD_FQDN' '$RSPAMD_HOST' '$RSPAMD_CTRL_PORT' <<'PY'
import json, sys
path, fqdn, host, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
try:
    d = json.load(open(path))
except FileNotFoundError:
    d = {}
expected = [host, port]
d[fqdn] = expected
json.dump(d, open(path, 'w'), indent=2)
verify = json.load(open(path))
got = verify.get(fqdn)
if got != expected:
    print(f'[phase2] LXC copy verify FAILED: got {got!r}, expected {expected!r}', file=sys.stderr)
    sys.exit(1)
print(f'[phase2] LXC copy {path}: {fqdn} → {expected}')
PY
"
    lxc-attach -n mitmproxy -- systemctl restart mitmproxy 2>&1 | tail -2 || true
else
    echo "[phase2] mitmproxy LXC not running, skipping LXC copy"
fi

echo "[phase2] route-sync patch complete"
