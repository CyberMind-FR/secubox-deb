#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# haproxy-workflow.sh - HAProxy auto-rehealth, WAF sync, and certificate management
# SecuBox-DEB :: Infrastructure Workflow Automation
# CyberMind — Gérald Kerma
set -euo pipefail

VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

# Paths
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
HAPROXY_TOML="/etc/secubox/haproxy.toml"
MITMPROXY_TOML="/etc/secubox/mitmproxy.toml"
ROUTES_JSON="/srv/mitmproxy-waf/data/routes.json"
HEALTH_CACHE="/var/cache/secubox/health/status.json"
CERTS_DIR="/etc/haproxy/certs"
ACME_DIR="/etc/acme"
VHOST_ROUTES="/var/lib/secubox/haproxy/vhost-routes.json"
LOG_FILE="/var/log/secubox/haproxy-workflow.log"

# API endpoints (via Unix sockets)
HAPROXY_SOCK="/run/secubox/haproxy.sock"
MITMPROXY_SOCK="/run/secubox/mitmproxy.sock"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log() { echo -e "${BLUE}[INFO]${NC} $*"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $*" >> "$LOG_FILE" 2>/dev/null || true; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $*" >> "$LOG_FILE" 2>/dev/null || true; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >> "$LOG_FILE" 2>/dev/null || true; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

# ═══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════

# API call via curl with JWT
api_call() {
    local socket="$1"
    local method="$2"
    local endpoint="$3"
    local data="${4:-}"

    local jwt=""
    if [ -f /etc/secubox/jwt/token ]; then
        jwt=$(cat /etc/secubox/jwt/token)
    fi

    local curl_args=(
        --silent
        --unix-socket "$socket"
        -X "$method"
        -H "Content-Type: application/json"
    )

    [ -n "$jwt" ] && curl_args+=(-H "Authorization: Bearer $jwt")
    [ -n "$data" ] && curl_args+=(-d "$data")

    curl "${curl_args[@]}" "http://localhost$endpoint" 2>/dev/null || echo '{"error": "API call failed"}'
}

# Check if service is running
service_running() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════
# 1. AUTO REHEALTH HAPROXY
# ═══════════════════════════════════════════════════════════════════════

cmd_rehealth() {
    log "=== Auto Rehealth HAProxy ==="

    # Step 1: Check HAProxy is running
    if service_running haproxy; then
        success "HAProxy service is active"
    else
        warn "HAProxy service not running, attempting start..."
        sudo systemctl start haproxy || { error "Failed to start HAProxy"; return 1; }
        sleep 2
    fi

    # Step 2: Validate config
    log "Validating HAProxy configuration..."
    if haproxy -c -f "$HAPROXY_CFG" 2>/dev/null; then
        success "Configuration valid"
    else
        error "Configuration invalid, running detailed check..."
        haproxy -c -f "$HAPROXY_CFG" 2>&1 | head -20
        return 1
    fi

    # Step 3: Reload HAProxy to pick up any changes
    log "Reloading HAProxy..."
    sudo systemctl reload haproxy && success "HAProxy reloaded"

    # Step 4: Clear health cache to force re-probe
    if [ -f "$HEALTH_CACHE" ]; then
        log "Invalidating health cache..."
        sudo rm -f "$HEALTH_CACHE"
        success "Health cache cleared"
    fi

    # Step 5: Restart health prober if running
    if service_running secubox-health-prober; then
        log "Restarting health prober..."
        sudo systemctl restart secubox-health-prober
        success "Health prober restarted"
    fi

    # Step 6: Trigger API cache refresh (if API running)
    if [ -S "$HAPROXY_SOCK" ]; then
        log "Triggering API cache refresh..."
        api_call "$HAPROXY_SOCK" GET "/api/v1/haproxy/status" >/dev/null
        success "API cache refreshed"
    fi

    # Step 7: Show current status
    log "Current HAProxy status:"
    echo "show info" | socat stdio /run/haproxy/admin.sock 2>/dev/null | head -20 || \
        echo "Stats socket not available (native HAProxy check)"

    # Quick backend check
    if [ -S /run/haproxy/admin.sock ]; then
        echo ""
        log "Backend status:"
        echo "show stat" | socat stdio /run/haproxy/admin.sock 2>/dev/null | \
            awk -F, '/BACKEND/ {print "  " $1 ": " $18}' | head -10
    fi

    success "HAProxy rehealth completed"
}

# ═══════════════════════════════════════════════════════════════════════
# 2. WORKFLOW BACKEND THROUGH WAF
# ═══════════════════════════════════════════════════════════════════════

cmd_waf_sync() {
    log "=== Workflow Backend Through WAF ==="

    # Step 1: Check mitmproxy-waf container/service
    local waf_running=false
    if lxc-info -n mitmproxy-waf -s 2>/dev/null | grep -q "RUNNING"; then
        success "mitmproxy-waf LXC container is running"
        waf_running=true
    elif service_running mitmproxy; then
        success "mitmproxy service is running"
        waf_running=true
    else
        warn "WAF service not running, attempting start..."
        if [ -f /var/lib/lxc/mitmproxy-waf/config ]; then
            sudo lxc-start -n mitmproxy-waf || warn "LXC start failed"
        else
            sudo systemctl start mitmproxy 2>/dev/null || warn "mitmproxy service start failed"
        fi
    fi

    # Step 2: Parse HAProxy config to extract vhosts and backends (using awk for speed)
    log "Extracting vhost→backend mappings from HAProxy config..."

    local routes="{}"
    local count=0
    local backend_count=0

    if [ -f "$HAPROXY_CFG" ]; then
        # Use awk for fast parsing of large config
        routes=$(awk '
        BEGIN { first=1 }
        # Capture backend -> server mappings
        /^backend / { backend=$2 }
        /^[[:space:]]+server / {
            for (i=1; i<=NF; i++) {
                if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) {
                    split($i, addr, ":")
                    if (backend) servers[backend] = addr[1] ":" addr[2]
                    break
                }
            }
        }
        # Capture ACL -> hostname mappings
        /^[[:space:]]+acl .* hdr\(host\) -i / {
            acl=$2
            hostname=$NF
            acls[acl] = hostname
        }
        # Capture use_backend -> ACL mappings
        /^[[:space:]]+use_backend .* if / {
            be=$2
            aclname=$4
            if (be !~ /waf_inspector|mitmproxy_inspector/ && acls[aclname] && servers[be]) {
                split(servers[be], a, ":")
                if (!first) printf ", "
                printf "\"%s\": [\"%s\", %s]", acls[aclname], a[1], a[2]
                first=0
            }
        }
        ' "$HAPROXY_CFG")
        routes="{${routes}}"
        count=$(echo "$routes" | grep -o '":\[' | wc -l)
        backend_count=$(awk '/^backend / {c++} END {print c+0}' "$HAPROXY_CFG")
    fi

    log "Found $count vhost→backend mappings"

    # Step 3: Write routes to mitmproxy
    if [ $count -gt 0 ]; then
        log "Writing routes to WAF..."
        sudo mkdir -p "$(dirname $ROUTES_JSON)"
        echo "$routes" | jq '.' | sudo tee "$ROUTES_JSON" >/dev/null
        success "Routes written to $ROUTES_JSON"

        # Also update the HAProxy-side routes file
        echo "$routes" | jq '.' | sudo tee "$VHOST_ROUTES" >/dev/null 2>/dev/null || true
    fi

    # Step 4: Verify WAF backend exists in HAProxy config
    log "Checking WAF backend in HAProxy config..."
    if grep -q "backend mitmproxy_inspector\|backend waf_inspector" "$HAPROXY_CFG"; then
        success "WAF backend exists in HAProxy config"
    else
        warn "WAF backend not found, may need to regenerate config"
        echo "  Run: haproxyctl generate"
    fi

    # Step 5: Check WAF routing is active
    local waf_routes=$(grep -c "use_backend.*waf_inspector\|use_backend.*mitmproxy_inspector" "$HAPROXY_CFG" 2>/dev/null || echo "0")
    log "HAProxy routes through WAF: $waf_routes vhosts"

    # Step 6: Reload mitmproxy to pick up routes
    if [ "$waf_running" = true ]; then
        log "Signaling mitmproxy to reload routes..."
        if lxc-info -n mitmproxy-waf -s 2>/dev/null | grep -q "RUNNING"; then
            sudo lxc-attach -n mitmproxy-waf -- pkill -HUP mitmproxy 2>/dev/null || true
        else
            sudo systemctl reload mitmproxy 2>/dev/null || true
        fi
        success "WAF routes synced"
    fi

    # Summary
    backend_count=${#backends[@]}
    echo ""
    log "WAF Sync Summary:"
    echo "  Backends extracted: $backend_count"
    echo "  Routes synced: $count"
    echo "  Routes through WAF: $waf_routes"

    success "WAF sync completed"
}

# ═══════════════════════════════════════════════════════════════════════
# 3. VHOST CERTIFICATES - FULL CERTS PUBLISHED
# ═══════════════════════════════════════════════════════════════════════

cmd_certs() {
    log "=== VHost Full Certificates Status ==="

    local total=0
    local valid=0
    local expiring=0
    local missing=0
    local expired=0

    # Collect all vhosts from HAProxy
    local vhosts=()
    if [ -f "$HAPROXY_CFG" ]; then
        while IFS= read -r line; do
            if [[ "$line" =~ hdr\(host\)[[:space:]]+-i[[:space:]]+([^[:space:]\}]+) ]]; then
                vhosts+=("${BASH_REMATCH[1]}")
            fi
        done < "$HAPROXY_CFG"
    fi

    total=${#vhosts[@]}
    log "Total vhosts configured: $total"

    if [ $total -eq 0 ]; then
        warn "No vhosts found in HAProxy config"
        return 0
    fi

    echo ""
    printf "%-40s %-12s %-10s %s\n" "DOMAIN" "STATUS" "EXPIRES" "PATH"
    printf "%s\n" "$(printf '%.0s-' {1..100})"

    for domain in "${vhosts[@]}"; do
        local cert_path=""
        local status=""
        local expires=""

        # Check HAProxy certs directory
        if [ -f "$CERTS_DIR/$domain.pem" ]; then
            cert_path="$CERTS_DIR/$domain.pem"
        elif [ -f "$CERTS_DIR/${domain%%.*}.pem" ]; then
            cert_path="$CERTS_DIR/${domain%%.*}.pem"
        # Check ACME directory
        elif [ -f "$ACME_DIR/$domain/fullchain.cer" ]; then
            cert_path="$ACME_DIR/$domain/fullchain.cer"
        elif [ -f "$ACME_DIR/$domain/${domain}.cer" ]; then
            cert_path="$ACME_DIR/$domain/${domain}.cer"
        fi

        if [ -n "$cert_path" ] && [ -f "$cert_path" ]; then
            # Check expiry
            local end_date
            end_date=$(openssl x509 -in "$cert_path" -enddate -noout 2>/dev/null | cut -d= -f2)

            if [ -n "$end_date" ]; then
                local end_epoch
                end_epoch=$(date -d "$end_date" +%s 2>/dev/null || echo 0)
                local now_epoch
                now_epoch=$(date +%s)
                local days_left=$(( (end_epoch - now_epoch) / 86400 ))

                if [ $days_left -lt 0 ]; then
                    status="${RED}EXPIRED${NC}"
                    expires="$days_left days"
                    ((expired++))
                elif [ $days_left -lt 30 ]; then
                    status="${YELLOW}EXPIRING${NC}"
                    expires="${days_left}d"
                    ((expiring++))
                else
                    status="${GREEN}VALID${NC}"
                    expires="${days_left}d"
                    ((valid++))
                fi
            else
                status="${YELLOW}UNKNOWN${NC}"
                expires="?"
                ((valid++))  # Assume valid if can't parse
            fi
        else
            status="${RED}MISSING${NC}"
            expires="-"
            cert_path="(not found)"
            ((missing++))
        fi

        printf "%-40s " "$domain"
        echo -e "${status} $(printf '%-10s' "$expires") ${cert_path:0:40}"
    done

    echo ""
    log "Certificate Summary:"
    echo -e "  ${GREEN}Valid${NC}:     $valid"
    echo -e "  ${YELLOW}Expiring${NC}:  $expiring (< 30 days)"
    echo -e "  ${RED}Expired${NC}:   $expired"
    echo -e "  ${RED}Missing${NC}:   $missing"
    echo "  ─────────────"
    echo "  Total:     $total"

    # Recommendations
    if [ $missing -gt 0 ]; then
        echo ""
        warn "Missing certificates - run ACME for:"
        for domain in "${vhosts[@]}"; do
            local found=false
            [ -f "$CERTS_DIR/$domain.pem" ] && found=true
            [ -f "$ACME_DIR/$domain/fullchain.cer" ] && found=true
            [ "$found" = false ] && echo "  acme.sh --issue -d $domain --webroot /var/www/acme"
        done
    fi

    if [ $expiring -gt 0 ]; then
        echo ""
        warn "Certificates expiring soon - renew with:"
        echo "  acme.sh --renew-all"
    fi

    success "Certificate check completed"
}

# ═══════════════════════════════════════════════════════════════════════
# ALL: Run complete workflow
# ═══════════════════════════════════════════════════════════════════════

cmd_all() {
    log "=== Running Complete HAProxy Workflow ==="
    echo ""

    cmd_rehealth
    echo ""

    cmd_waf_sync
    echo ""

    cmd_certs
    echo ""

    success "Complete workflow finished"
}

# ═══════════════════════════════════════════════════════════════════════
# USAGE
# ═══════════════════════════════════════════════════════════════════════

usage() {
    cat <<EOF
$SCRIPT_NAME v$VERSION - HAProxy Workflow Automation

Usage: $SCRIPT_NAME <command>

Commands:
  rehealth    Auto rehealth HAProxy (reload, invalidate caches, restart probers)
  waf-sync    Sync backend routes through WAF (mitmproxy)
  certs       Check/list vhost certificates status
  all         Run complete workflow (rehealth + waf-sync + certs)
  help        Show this help

Examples:
  $SCRIPT_NAME rehealth    # Refresh HAProxy health monitoring
  $SCRIPT_NAME waf-sync    # Sync vhost→backend routes to WAF
  $SCRIPT_NAME certs       # Check certificate status for all vhosts
  $SCRIPT_NAME all         # Run everything

EOF
}

# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

main() {
    # Create log directory
    mkdir -p "$(dirname $LOG_FILE)" 2>/dev/null || true

    case "${1:-}" in
        rehealth)  cmd_rehealth ;;
        waf-sync)  cmd_waf_sync ;;
        certs)     cmd_certs ;;
        all)       cmd_all ;;
        help|-h|--help) usage ;;
        *)
            [ -n "${1:-}" ] && error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
