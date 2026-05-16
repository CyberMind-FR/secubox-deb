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

# Add rspamd.gk2.secubox.in route in both the host copy and the mitmproxy LXC copy.
add_route() {
    local file="$1"
    [ -f "$file" ] || { echo "[phase2] $file not present, skipping"; return 0; }
    python3 - "$file" <<'PY'
import sys, json
path = sys.argv[1]
d = json.load(open(path))
d["rspamd.gk2.secubox.in"] = ["10.100.0.10", 11334]
json.dump(d, open(path, "w"), indent=2)
print(f"[phase2] added rspamd.gk2 → [10.100.0.10, 11334] in {path}")
PY
}

add_route /srv/mitmproxy/haproxy-routes.json
if command -v lxc-attach >/dev/null 2>&1 && lxc-info -n mitmproxy 2>/dev/null | grep -q RUNNING; then
    # The LXC has its own copy. Bind the same json into the LXC via attach.
    lxc-attach -n mitmproxy -- python3 - /srv/mitmproxy/haproxy-routes.json <<'PY'
import sys, json
path = sys.argv[1]
d = json.load(open(path))
d["rspamd.gk2.secubox.in"] = ["10.100.0.10", 11334]
json.dump(d, open(path, "w"), indent=2)
print(f"[phase2] LXC copy updated: {path}")
PY
    lxc-attach -n mitmproxy -- systemctl restart mitmproxy 2>&1 | tail -2 || true
fi

echo "[phase2] route-sync patch complete"
