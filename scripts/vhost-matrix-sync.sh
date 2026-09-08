#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# vhost-matrix-sync.sh — Synchronize HAProxy vhosts to the sbxwaf routes table and health prober
# SecuBox-DEB :: Infrastructure Workflow Automation
# CyberMind — Gérald Kerma
set -euo pipefail

VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

# Paths
HAPROXY_CFG="${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}"
# sbxwaf routes table (hot-reloaded by secubox-waf-ng); var kept for compatibility
MITMPROXY_ROUTES="/etc/secubox/waf/haproxy-routes.json"
HEALTH_VHOSTS="/var/cache/secubox/health/vhost-matrix.json"
VHOST_MATRIX="/var/lib/secubox/haproxy/vhost-matrix.json"
LOG_FILE="/var/log/secubox/vhost-matrix-sync.log"

# Backend host IP used when a matrix entry resolves to 127.0.0.1.
# Legacy default (10.100.0.1) was the LXC bridge; kept as an overridable default.
MITMPROXY_HOST_IP="${MITMPROXY_HOST_IP:-10.100.0.1}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $*"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $*" >> "$LOG_FILE" 2>/dev/null || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $*" >> "$LOG_FILE" 2>/dev/null || true; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >> "$LOG_FILE" 2>/dev/null || true; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

# ═══════════════════════════════════════════════════════════════════════════════
# EXTRACT VHOST MATRIX FROM HAPROXY
# ═══════════════════════════════════════════════════════════════════════════════

extract_vhost_matrix() {
    # Log to stderr so stdout only contains the JSON result
    echo -e "${BLUE}[INFO]${NC} Extracting vhost→backend matrix from HAProxy config..." >&2

    if [ ! -f "$HAPROXY_CFG" ]; then
        error "HAProxy config not found: $HAPROXY_CFG"
        return 1
    fi

    # Use Python for reliable parsing
    local matrix
    matrix=$(python3 << PYEOF
import re
import json

with open("$HAPROXY_CFG") as f:
    content = f.read()

# Extract backends with their servers
backends = {}
for m in re.finditer(r"^backend\s+(\S+).*?(?=^backend|\Z)", content, re.MULTILINE | re.DOTALL):
    backend_name = m.group(1)
    backend_block = m.group(0)
    server_match = re.search(r"server\s+\S+\s+(\d+\.\d+\.\d+\.\d+):(\d+)", backend_block)
    if server_match:
        backends[backend_name] = {"ip": server_match.group(1), "port": int(server_match.group(2))}

# Extract ACLs
acls = {}
for m in re.finditer(r"acl\s+(\S+)\s+hdr\(host\)\s+-i\s+(\S+)", content):
    acls[m.group(1)] = m.group(2)

# Extract use_backend rules and build vhost matrix
vhosts = {}
for m in re.finditer(r"use_backend\s+(\S+)\s+if\s+(\S+)", content):
    backend_name = m.group(1)
    acl_name = m.group(2)

    # Skip WAF inspector backends
    if "waf" in backend_name.lower() or "mitmproxy" in backend_name.lower():
        continue

    hostname = acls.get(acl_name)
    backend = backends.get(backend_name)

    if hostname and backend and hostname not in vhosts:
        vhosts[hostname] = {
            "backend": backend_name,
            "ip": backend["ip"],
            "port": backend["port"],
            "waf": True
        }

print(json.dumps(vhosts, indent=2))
PYEOF
)

    # Validate JSON
    if ! echo "$matrix" | jq . >/dev/null 2>&1; then
        error "Failed to generate valid JSON matrix"
        return 1
    fi

    local count
    count=$(echo "$matrix" | jq 'keys | length')
    echo -e "${BLUE}[INFO]${NC} Extracted $count vhost mappings" >&2

    echo "$matrix"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GENERATE SBXWAF ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

generate_mitmproxy_routes() {
    local matrix="$1"

    # Log to stderr so stdout only contains the JSON result
    echo -e "${BLUE}[INFO]${NC} Generating sbxwaf routes..." >&2

    # Convert matrix to sbxwaf routes format: {"hostname": ["ip", port]}
    # Rewrite 127.0.0.1 to MITMPROXY_HOST_IP for the routed backend
    local routes
    routes=$(echo "$matrix" | jq --arg host "$MITMPROXY_HOST_IP" '
        to_entries | map({
            key: .key,
            value: [
                (if .value.ip == "127.0.0.1" then $host else .value.ip end),
                .value.port
            ]
        }) | from_entries
    ')

    local count
    count=$(echo "$routes" | jq 'keys | length')
    echo -e "${BLUE}[INFO]${NC} Generated $count sbxwaf routes" >&2

    echo "$routes"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SYNC TO SBXWAF
# ═══════════════════════════════════════════════════════════════════════════════

sync_mitmproxy() {
    local routes="$1"

    log "Syncing routes to sbxwaf..."

    # Ensure directory exists
    mkdir -p "$(dirname "$MITMPROXY_ROUTES")"

    # Write the routes table (sbxwaf hot-reloads it)
    echo "$routes" | jq . > "$MITMPROXY_ROUTES"
    success "Routes written to $MITMPROXY_ROUTES"

    # Nudge sbxwaf to reload the routes table
    systemctl reload secubox-waf-ng 2>/dev/null || true

    # Legacy guarded step: signal the old mitmproxy WAF LXC if it still exists
    # (no-op on current boxes).
    if lxc-info -n mitmproxy-waf -s 2>/dev/null | grep -q "RUNNING"; then
        log "Signaling legacy mitmproxy WAF LXC to reload..."
        lxc-attach -n mitmproxy-waf -- pkill -HUP mitmdump 2>/dev/null || true
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# SYNC TO HEALTH PROBER
# ═══════════════════════════════════════════════════════════════════════════════

sync_health_prober() {
    local matrix="$1"

    log "Syncing vhost matrix to health prober..."

    # Ensure directory exists
    mkdir -p "$(dirname "$HEALTH_VHOSTS")"

    # Write matrix for health prober consumption
    echo "$matrix" | jq . > "$HEALTH_VHOSTS"
    success "Matrix written to $HEALTH_VHOSTS"

    # Restart health prober if running
    if systemctl is-active --quiet secubox-health-prober 2>/dev/null; then
        log "Restarting health prober..."
        systemctl restart secubox-health-prober
        success "Health prober restarted"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# SAVE MASTER MATRIX
# ═══════════════════════════════════════════════════════════════════════════════

save_matrix() {
    local matrix="$1"

    log "Saving master vhost matrix..."

    mkdir -p "$(dirname "$VHOST_MATRIX")"
    echo "$matrix" | jq . > "$VHOST_MATRIX"
    success "Master matrix saved to $VHOST_MATRIX"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SHOW MATRIX STATUS
# ═══════════════════════════════════════════════════════════════════════════════

show_status() {
    log "=== VHost Matrix Status ==="

    echo ""
    printf "%-40s %-20s %-18s %s\n" "HOSTNAME" "BACKEND" "ENDPOINT" "WAF"
    printf "%s\n" "$(printf '%.0s-' {1..95})"

    if [ -f "$VHOST_MATRIX" ]; then
        jq -r 'to_entries[] | [.key, .value.backend, (.value.ip + ":" + (.value.port|tostring)), (if .value.waf then "✓" else "✗" end)] | @tsv' "$VHOST_MATRIX" | \
        while IFS=$'\t' read -r host backend endpoint waf; do
            printf "%-40s %-20s %-18s %s\n" "$host" "$backend" "$endpoint" "$waf"
        done | sort
    else
        warn "No matrix file found. Run 'sync' first."
    fi

    echo ""

    # Summary
    local haproxy_vhosts mitmproxy_routes health_vhosts
    haproxy_vhosts=$(grep -cE 'hdr\(host\).*-i' "$HAPROXY_CFG" 2>/dev/null || echo "0")
    mitmproxy_routes=$(jq 'keys | length' "$MITMPROXY_ROUTES" 2>/dev/null || echo "0")
    health_vhosts=$(jq 'keys | length' "$HEALTH_VHOSTS" 2>/dev/null || echo "0")

    log "Summary:"
    echo "  HAProxy vhosts:     $haproxy_vhosts"
    echo "  sbxwaf routes:      $mitmproxy_routes"
    echo "  Health prober:      $health_vhosts"

    # Check sync status
    if [ "$mitmproxy_routes" -lt "$((haproxy_vhosts / 2))" ]; then
        warn "sbxwaf routes appear out of sync. Run 'sync' to update."
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# FULL SYNC
# ═══════════════════════════════════════════════════════════════════════════════

cmd_sync() {
    log "=== VHost Matrix Full Sync ==="

    # Extract matrix from HAProxy
    local matrix
    matrix=$(extract_vhost_matrix)

    if [ -z "$matrix" ] || [ "$matrix" = "{}" ]; then
        error "No vhost mappings found in HAProxy config"
        return 1
    fi

    # Save master matrix
    save_matrix "$matrix"

    # Generate and sync mitmproxy routes
    local routes
    routes=$(generate_mitmproxy_routes "$matrix")
    sync_mitmproxy "$routes"

    # Sync to health prober
    sync_health_prober "$matrix"

    echo ""
    success "VHost matrix sync completed"

    # Show summary
    show_status
}

# ═══════════════════════════════════════════════════════════════════════════════
# RELOAD SERVICES
# ═══════════════════════════════════════════════════════════════════════════════

cmd_reload() {
    log "=== Reloading Services ==="

    # Reload HAProxy
    if systemctl is-active --quiet haproxy; then
        log "Reloading HAProxy..."
        systemctl reload haproxy
        success "HAProxy reloaded"
    fi

    # Reload sbxwaf (host daemon)
    if systemctl is-active --quiet secubox-waf-ng 2>/dev/null; then
        log "Reloading sbxwaf..."
        systemctl reload secubox-waf-ng 2>/dev/null || true
        success "sbxwaf reloaded"
    fi

    # Legacy guarded step: signal the old mitmproxy WAF LXC if it still exists
    if lxc-info -n mitmproxy-waf -s 2>/dev/null | grep -q "RUNNING"; then
        log "Signaling legacy mitmproxy WAF LXC..."
        lxc-attach -n mitmproxy-waf -- pkill -HUP mitmdump 2>/dev/null || true
    fi

    # Restart health prober
    if systemctl is-active --quiet secubox-health-prober; then
        log "Restarting health prober..."
        systemctl restart secubox-health-prober
        success "Health prober restarted"
    fi

    success "All services reloaded"
}

# ═══════════════════════════════════════════════════════════════════════════════
# USAGE
# ═══════════════════════════════════════════════════════════════════════════════

usage() {
    cat <<EOF
$SCRIPT_NAME v$VERSION — VHost Matrix Synchronization

Usage: $SCRIPT_NAME <command>

Commands:
  sync      Extract HAProxy vhosts and sync to sbxwaf + health prober
  status    Show current vhost matrix status
  reload    Reload all related services (HAProxy, sbxwaf, health prober)
  help      Show this help

Environment:
  HAPROXY_CFG         HAProxy config path (default: /etc/haproxy/haproxy.cfg)
  MITMPROXY_HOST_IP   Backend host IP for sbxwaf routes (default: 10.100.0.1)

Examples:
  $SCRIPT_NAME sync       # Full sync from HAProxy to all consumers
  $SCRIPT_NAME status     # Show current matrix state
  $SCRIPT_NAME reload     # Reload all services

EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

    case "${1:-}" in
        sync)    cmd_sync ;;
        status)  show_status ;;
        reload)  cmd_reload ;;
        help|-h|--help) usage ;;
        *)
            [ -n "${1:-}" ] && error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
