#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox Routes Auto-Sync - All Services
# Syncs routes from streamlit, metablogizer, and other services to mitmproxy

set -euo pipefail

ROUTES_FILE="/srv/mitmproxy/haproxy-routes.json"
LOG_TAG="routes-sync"

log() { logger -t "$LOG_TAG" "$1"; echo "[$(date +%H:%M:%S)] $1"; }

log "Starting full routes sync..."

# Ensure mitmproxy container is running
if ! lxc-info -n mitmproxy 2>/dev/null | grep -q "RUNNING"; then
    log "Starting mitmproxy container..."
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

# Copy routes to mitmproxy container
log "Syncing to mitmproxy container..."
cat "$ROUTES_FILE" | lxc-attach -n mitmproxy -- tee /srv/mitmproxy/haproxy-routes.json > /dev/null

# Reload mitmproxy
lxc-attach -n mitmproxy -- pkill -HUP mitmdump 2>/dev/null || true

log "Routes sync complete"
