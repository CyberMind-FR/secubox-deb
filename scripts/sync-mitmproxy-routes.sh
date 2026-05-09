#!/bin/bash
# SecuBox Route Sync - Ensures HAProxy vhosts are synced to mitmproxy routes
# Run periodically via cron or systemd timer
#
# Features:
# - Syncs HAProxy domains to mitmproxy routes
# - Syncs metablogizer domains from nginx config
# - Fixes dead container routes (10.100.0.10-50) to point to webui
# - Runs via systemd timer every 5 minutes

set -euo pipefail

LXC_CONTAINER="mitmproxy"
ROUTES_FILE="/srv/mitmproxy/haproxy-routes.json"
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
NGINX_METABLOG="/etc/nginx/sites-enabled/metablogizer"

WEBUI_PORT=9080
METABLOG_PORT=8900
BACKEND_IP="10.100.0.1"

# Dead container IPs to fix (not running LXC containers)
DEAD_CONTAINER_IPS="10.100.0.10 10.100.0.20 10.100.0.30 10.100.0.40 10.100.0.50"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Get current routes from container
get_current_routes() {
    lxc-attach -n "$LXC_CONTAINER" -- cat "$ROUTES_FILE" 2>/dev/null || echo "{}"
}

# Get all domains from HAProxy that use mitmproxy_inspector
get_haproxy_domains() {
    grep "use_backend mitmproxy_inspector" "$HAPROXY_CFG" | \
        grep -oP 'host_\K[a-z0-9_]+(?= )' | \
        sed 's/_/./g' | sort -u
}

# Get all metablog domains from nginx
get_metablog_domains() {
    grep 'server_name' "$NGINX_METABLOG" 2>/dev/null | \
        sed 's/.*server_name //;s/;.*//' | sort -u
}

# Determine the correct port for a domain
get_port_for_domain() {
    local domain="$1"

    # Check if it's a metablog domain
    if grep -q "server_name $domain" "$NGINX_METABLOG" 2>/dev/null; then
        echo "$METABLOG_PORT"
        return
    fi

    # Default to webui
    echo "$WEBUI_PORT"
}

# Fix routes pointing to dead containers
fix_dead_container_routes() {
    local routes_json="$1"
    local fixed=0

    for dead_ip in $DEAD_CONTAINER_IPS; do
        # Find domains pointing to this dead IP and fix them
        local domains
        domains=$(echo "$routes_json" | jq -r --arg ip "$dead_ip" 'to_entries[] | select(.value[0] == $ip) | .key')

        for domain in $domains; do
            [[ -z "$domain" ]] && continue
            log "Fixing dead route: $domain ($dead_ip -> $BACKEND_IP:$WEBUI_PORT)"
            routes_json=$(echo "$routes_json" | jq --arg d "$domain" --arg ip "$BACKEND_IP" --argjson p "$WEBUI_PORT" '.[$d] = [$ip, $p]')
            fixed=$((fixed + 1))
        done
    done

    echo "$routes_json"
    return $fixed
}

# Main sync
main() {
    log "Starting route sync..."

    local current_routes
    current_routes=$(get_current_routes)

    local updated=0
    local routes_json="$current_routes"

    # Fix dead container routes first
    routes_json=$(fix_dead_container_routes "$routes_json")
    updated=$((updated + $?)) || true

    # Sync HAProxy domains
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue

        port=$(get_port_for_domain "$domain")

        # Check if route exists with correct port
        existing=$(echo "$routes_json" | jq -r --arg d "$domain" '.[$d] // empty')

        if [[ -z "$existing" ]] || ! echo "$existing" | jq -e ".[1] == $port" >/dev/null 2>&1; then
            log "Updating route: $domain -> $BACKEND_IP:$port"
            routes_json=$(echo "$routes_json" | jq --arg d "$domain" --arg ip "$BACKEND_IP" --argjson p "$port" '.[$d] = [$ip, $p]')
            updated=$((updated + 1))
        fi
    done < <(get_haproxy_domains)

    # Sync metablog domains
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue

        existing=$(echo "$routes_json" | jq -r --arg d "$domain" '.[$d] // empty')

        if [[ -z "$existing" ]] || ! echo "$existing" | jq -e ".[1] == $METABLOG_PORT" >/dev/null 2>&1; then
            log "Updating metablog route: $domain -> $BACKEND_IP:$METABLOG_PORT"
            routes_json=$(echo "$routes_json" | jq --arg d "$domain" --arg ip "$BACKEND_IP" --argjson p "$METABLOG_PORT" '.[$d] = [$ip, $p]')
            updated=$((updated + 1))
        fi
    done < <(get_metablog_domains)

    if [[ $updated -gt 0 ]]; then
        log "Updating $updated routes in mitmproxy container..."
        echo "$routes_json" | lxc-attach -n "$LXC_CONTAINER" -- tee "$ROUTES_FILE" > /dev/null
        lxc-attach -n "$LXC_CONTAINER" -- systemctl restart mitmproxy
        log "Routes synced and mitmproxy restarted"
    else
        log "All routes up to date"
    fi

    log "Sync complete"
}

main "$@"
