#!/bin/bash
# SecuBox Performance Benchmark - Service Startup Time
#
# Measures cold-start time for SecuBox services using systemd-analyze.
# Outputs timing data for optimization targeting.
#
# Usage:
#     ./startup-time.sh                  # All secubox services
#     ./startup-time.sh --service hub    # Specific service
#     ./startup-time.sh --csv            # CSV output
#     ./startup-time.sh --full           # Include dependency chain
#
# CyberMind - https://cybermind.fr
# Author: Gerald Kerma <gandalf@gk2.net>

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Thresholds (seconds)
WARN_THRESHOLD=3
CRIT_THRESHOLD=5

# Parse args
CSV_MODE=false
FULL_MODE=false
SPECIFIC_SERVICE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --csv) CSV_MODE=true; shift ;;
        --full) FULL_MODE=true; shift ;;
        --service) SPECIFIC_SERVICE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--csv] [--full] [--service NAME]"
            echo ""
            echo "Options:"
            echo "  --csv         Output CSV format"
            echo "  --full        Include dependency chain analysis"
            echo "  --service     Measure specific service only"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

get_secubox_services() {
    systemctl list-unit-files --type=service 2>/dev/null | \
        grep -E 'secubox-|eye-remote' | \
        awk '{print $1}' | \
        sed 's/\.service$//'
}

measure_service_startup() {
    local service=$1
    local unit="${service}.service"

    # Check if service exists
    if ! systemctl list-unit-files "$unit" &>/dev/null; then
        echo "0 0 not_found"
        return
    fi

    # Get activation time from systemd
    local active_enter
    local inactive_exit
    local startup_time=0

    active_enter=$(systemctl show -p ActiveEnterTimestampMonotonic "$unit" --value 2>/dev/null || echo "0")
    inactive_exit=$(systemctl show -p InactiveExitTimestampMonotonic "$unit" --value 2>/dev/null || echo "0")

    if [[ "$active_enter" != "0" ]] && [[ "$inactive_exit" != "0" ]]; then
        # Convert microseconds to seconds
        startup_time=$(echo "scale=3; ($active_enter - $inactive_exit) / 1000000" | bc 2>/dev/null || echo "0")
    fi

    # Get state
    local state
    state=$(systemctl is-active "$unit" 2>/dev/null || echo "unknown")

    # Get memory usage (for correlation)
    local mem_kb=0
    local pid
    pid=$(systemctl show -p MainPID "$unit" --value 2>/dev/null || echo "0")
    if [[ "$pid" != "0" ]] && [[ -n "$pid" ]]; then
        mem_kb=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo "0")
    fi

    echo "$startup_time $mem_kb $state"
}

cold_restart_measure() {
    local service=$1
    local unit="${service}.service"

    echo -n "  Stopping... " >&2
    systemctl stop "$unit" 2>/dev/null || true
    sleep 1

    echo -n "Starting... " >&2
    local start_time
    start_time=$(date +%s.%N)

    systemctl start "$unit" 2>/dev/null

    # Wait for active state (max 30s)
    local timeout=30
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if systemctl is-active "$unit" &>/dev/null; then
            break
        fi
        sleep 0.1
        elapsed=$(echo "$elapsed + 0.1" | bc)
    done

    local end_time
    end_time=$(date +%s.%N)

    local startup
    startup=$(echo "$end_time - $start_time" | bc)

    echo "Done." >&2
    echo "$startup"
}

print_header() {
    if $CSV_MODE; then
        echo "timestamp,service,startup_s,mem_kb,state,verdict"
    else
        echo ""
        echo -e "${CYAN}SecuBox Service Startup Analysis${NC}"
        echo ""
        printf "%-35s %12s %12s %10s %10s\n" "SERVICE" "STARTUP (s)" "MEMORY (KB)" "STATE" "VERDICT"
        printf "%s\n" "$(printf '=%.0s' {1..85})"
    fi
}

print_service() {
    local service=$1
    local startup=$2
    local mem_kb=$3
    local state=$4
    local timestamp

    timestamp=$(date -Iseconds)

    # Determine verdict
    local verdict="OK"
    local color=$GREEN

    if [[ "$state" != "active" ]]; then
        verdict="INACTIVE"
        color=$YELLOW
    elif (( $(echo "$startup > $CRIT_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        verdict="SLOW"
        color=$RED
    elif (( $(echo "$startup > $WARN_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        verdict="WARN"
        color=$YELLOW
    fi

    if $CSV_MODE; then
        echo "$timestamp,$service,$startup,$mem_kb,$state,$verdict"
    else
        printf "%-35s %12.3f %12d %10s ${color}%10s${NC}\n" \
            "$service" "$startup" "$mem_kb" "$state" "$verdict"
    fi
}

analyze_boot_chain() {
    echo ""
    echo -e "${CYAN}Boot Chain Analysis${NC}"
    echo ""

    # System boot time
    echo "System Boot Time:"
    systemd-analyze time 2>/dev/null || echo "  (systemd-analyze not available)"

    echo ""
    echo "Critical Chain (SecuBox services):"
    systemd-analyze critical-chain 2>/dev/null | grep -E 'secubox|eye-remote' | head -20 || true

    echo ""
    echo "Blame (top 10 slowest):"
    systemd-analyze blame 2>/dev/null | grep -E 'secubox|eye-remote' | head -10 || true
}

run_analysis() {
    local services

    if [[ -n "$SPECIFIC_SERVICE" ]]; then
        services=("$SPECIFIC_SERVICE")
    else
        mapfile -t services < <(get_secubox_services)
    fi

    if [[ ${#services[@]} -eq 0 ]]; then
        echo "No SecuBox services found."
        exit 1
    fi

    print_header

    local total_startup=0
    local count=0

    for service in "${services[@]}"; do
        read -r startup mem_kb state < <(measure_service_startup "$service")

        if [[ "$state" != "not_found" ]]; then
            print_service "$service" "$startup" "$mem_kb" "$state"
            total_startup=$(echo "$total_startup + $startup" | bc 2>/dev/null || echo "$total_startup")
            ((count++)) || true
        fi
    done

    if ! $CSV_MODE; then
        printf "%s\n" "$(printf '-%.0s' {1..85})"
        printf "%-35s %12.3f %12s %10s\n" "TOTAL ($count services)" "$total_startup" "" ""

        if $FULL_MODE; then
            analyze_boot_chain
        fi

        # Recommendations
        echo ""
        if (( $(echo "$total_startup > 15" | bc -l 2>/dev/null || echo 0) )); then
            echo -e "${YELLOW}Recommendation: Total startup > 15s. Consider:${NC}"
            echo "  - Lazy loading for non-critical services"
            echo "  - Reducing service dependencies"
            echo "  - Using socket activation"
        fi
    fi
}

# Main
run_analysis
