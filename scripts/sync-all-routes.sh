#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox Routes Auto-Sync - All Services
# Syncs routes from streamlit, metablogizer, and other services into the
# sbxwaf routes table (/etc/secubox/waf/haproxy-routes.json, hot-reloaded).

set -euo pipefail

ROUTES_FILE="/etc/secubox/waf/haproxy-routes.json"
LOG_TAG="routes-sync"

log() { logger -t "$LOG_TAG" "$1"; echo "[$(date +%H:%M:%S)] $1"; }

log "Starting full routes sync..."

# Legacy: the old mitmproxy WAF ran in an LXC. sbxwaf is now a host daemon,
# so this container start is a guarded no-op on current boxes.
if lxc-info -n mitmproxy 2>/dev/null | grep -q "STOPPED"; then
    log "Starting legacy mitmproxy container..."
    lxc-start -n mitmproxy 2>/dev/null || true
    sleep 3
fi

# Get container IPs
STREAMLIT_IP=$(lxc-attach -n streamlit -- ip -4 addr show eth0 2>/dev/null | grep -oP "inet \K[\d.]+" || echo "10.100.0.50")
GITEA_IP=$(lxc-attach -n gitea -- ip -4 addr show eth0 2>/dev/null | grep -oP "inet \K[\d.]+" || echo "10.100.0.40")

python3 << PYEOF
import json
import subprocess
from pathlib import Path

routes_file = "$ROUTES_FILE"
streamlit_ip = "$STREAMLIT_IP"
gitea_ip = "$GITEA_IP"
host_ip = "192.168.1.200"

# Load existing routes
routes = {}
if Path(routes_file).exists():
    routes = json.loads(Path(routes_file).read_text())

updated = 0

# 1. Streamlit instances
try:
    import tomllib
    with open("/etc/secubox/streamlit.toml", "rb") as f:
        cfg = tomllib.load(f)
    for name, inst in cfg.get("instances", {}).items():
        domain = inst.get("domain", f"{name}.gk2.secubox.in")
        port = inst.get("port")
        if port:
            routes[domain] = [streamlit_ip, int(port)]
            updated += 1
    print(f"Streamlit: {updated} routes")
except Exception as e:
    print(f"Streamlit error: {e}")

# 2. Metablogizer sites (static sites served by nginx on 9080)
try:
    result = subprocess.run(
        ["curl", "-s", "--unix-socket", "/run/secubox/metablogizer.sock", "http://localhost/access"],
        capture_output=True, text=True, timeout=5
    )
    data = json.loads(result.stdout)
    mb_count = 0
    for site in data.get("sites", []):
        domain = site.get("domain")
        if domain and site.get("published"):
            routes[domain] = [host_ip, 8900]
            mb_count += 1
    print(f"Metablogizer: {mb_count} routes")
    updated += mb_count
except Exception as e:
    print(f"Metablogizer error: {e}")

# 3. Fixed routes
routes["admin.gk2.secubox.in"] = [host_ip, 9080]
routes["git.gk2.secubox.in"] = [gitea_ip, 3000]

# Save routes
Path(routes_file).write_text(json.dumps(routes, indent=2, sort_keys=True))
print(f"Total: {len(routes)} routes saved")
PYEOF

# sbxwaf reads /etc/secubox/waf/haproxy-routes.json directly and hot-reloads it,
# so writing the table above is the functional sync. The legacy copy into the
# old mitmproxy WAF LXC below is kept guarded and is a no-op on current boxes.
if lxc-info -n mitmproxy 2>/dev/null | grep -q "RUNNING"; then
    log "Syncing to legacy mitmproxy container..."
    lxc-attach -n mitmproxy -- tee /etc/secubox/waf/haproxy-routes.json < "$ROUTES_FILE" > /dev/null || true
    lxc-attach -n mitmproxy -- pkill -HUP mitmdump 2>/dev/null || true
fi

log "Routes sync complete"
