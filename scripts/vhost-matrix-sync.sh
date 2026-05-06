#!/bin/bash
# vhost-matrix-sync.sh — Synchronize HAProxy vhosts to mitmproxy routes and health prober
# SecuBox-DEB :: Infrastructure Workflow Automation
# CyberMind — Gérald Kerma
set -euo pipefail

VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

# Paths
HAPROXY_CFG="${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}"
MITMPROXY_ROUTES="/srv/mitmproxy-waf/data/routes.json"
HEALTH_VHOSTS="/var/cache/secubox/health/vhost-matrix.json"
VHOST_MATRIX="/var/lib/secubox/haproxy/vhost-matrix.json"
LOG_FILE="/var/log/secubox/vhost-matrix-sync.log"

# LXC mitmproxy bridge IP (not localhost - routes are used inside LXC)
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
    log "Extracting vhost→backend matrix from HAProxy config..."

    if [ ! -f "$HAPROXY_CFG" ]; then
        error "HAProxy config not found: $HAPROXY_CFG"
        return 1
    fi

    # Parse HAProxy config to extract:
    # 1. ACL name → hostname mappings
    # 2. Backend → server IP:port mappings
    # 3. use_backend → ACL mappings

    local matrix
    matrix=$(awk '
    BEGIN {
        print "{"
        first = 1
    }

    # Capture backend definitions: backend <name>
    /^backend / {
        current_backend = $2
    }

    # Capture server lines: server <name> <ip>:<port>
    /^[[:space:]]+server / {
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) {
                split($i, addr, ":")
                backends[current_backend] = addr[1] ":" addr[2]
                break
            }
        }
    }

    # Capture ACL definitions: acl <name> hdr(host) -i <hostname>
    /^[[:space:]]+acl .* hdr\(host\) -i / {
        acl_name = $2
        hostname = $NF
        acls[acl_name] = hostname
    }

    # Capture use_backend rules: use_backend <backend> if <acl>
    /^[[:space:]]+use_backend .* if / {
        backend = $2
        acl = $4

        # Skip WAF inspector backends (traffic goes through WAF first)
        if (backend ~ /waf_inspector|mitmproxy_inspector/) {
            next
        }

        hostname = acls[acl]
        server = backends[backend]

        if (hostname && server) {
            split(server, parts, ":")
            ip = parts[1]
            port = parts[2]

            if (!first) print ","
            first = 0

            printf "  \"%s\": {\n", hostname
            printf "    \"backend\": \"%s\",\n", backend
            printf "    \"ip\": \"%s\",\n", ip
            printf "    \"port\": %s,\n", port
            printf "    \"waf\": true\n"
            printf "  }"
        }
    }

    END {
        print "\n}"
    }
    ' "$HAPROXY_CFG")

    # Validate JSON
    if ! echo "$matrix" | jq . >/dev/null 2>&1; then
        error "Failed to generate valid JSON matrix"
        return 1
    fi

    local count
    count=$(echo "$matrix" | jq 'keys | length')
    log "Extracted $count vhost mappings"

    echo "$matrix"
}

# ═══════════════════════════════════════════════════════════════════════════════
# GENERATE MITMPROXY ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

generate_mitmproxy_routes() {
    local matrix="$1"

    log "Generating mitmproxy routes..."

    # Convert matrix to mitmproxy format: {"hostname": ["ip", port]}
    # Use MITMPROXY_HOST_IP instead of 127.0.0.1 for LXC container access
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
    log "Generated $count mitmproxy routes"

    echo "$routes"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SYNC TO MITMPROXY
# ═══════════════════════════════════════════════════════════════════════════════

sync_mitmproxy() {
    local routes="$1"

    log "Syncing routes to mitmproxy..."

    # Ensure directory exists
    mkdir -p "$(dirname "$MITMPROXY_ROUTES")"

    # Write routes
    echo "$routes" | jq . > "$MITMPROXY_ROUTES"
    success "Routes written to $MITMPROXY_ROUTES"

    # Reload mitmproxy if running in LXC
    if lxc-info -n mitmproxy-waf -s 2>/dev/null | grep -q "RUNNING"; then
        log "Signaling mitmproxy to reload..."
        lxc-attach -n mitmproxy-waf -- pkill -HUP mitmdump 2>/dev/null || true
        success "mitmproxy reloaded"
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
    echo "  Mitmproxy routes:   $mitmproxy_routes"
    echo "  Health prober:      $health_vhosts"

    # Check sync status
    if [ "$mitmproxy_routes" -lt "$((haproxy_vhosts / 2))" ]; then
        warn "Mitmproxy routes appear out of sync. Run 'sync' to update."
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

    # Reload mitmproxy
    if lxc-info -n mitmproxy-waf -s 2>/dev/null | grep -q "RUNNING"; then
        log "Signaling mitmproxy..."
        lxc-attach -n mitmproxy-waf -- pkill -HUP mitmdump 2>/dev/null || true
        success "mitmproxy signaled"
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
  sync      Extract HAProxy vhosts and sync to mitmproxy + health prober
  status    Show current vhost matrix status
  reload    Reload all related services (HAProxy, mitmproxy, health prober)
  help      Show this help

Environment:
  HAPROXY_CFG         HAProxy config path (default: /etc/haproxy/haproxy.cfg)
  MITMPROXY_HOST_IP   Host IP for mitmproxy routes (default: 10.100.0.1)

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
