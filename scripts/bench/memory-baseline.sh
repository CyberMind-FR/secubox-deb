#!/bin/bash
# SecuBox Performance Benchmark - Memory Baseline
#
# Tracks per-service memory usage (RSS, PSS, USS)
# Outputs CSV and summary report.
#
# Usage:
#     ./memory-baseline.sh                    # All secubox services
#     ./memory-baseline.sh --csv > mem.csv   # CSV output
#     ./memory-baseline.sh --watch           # Continuous monitoring
#
# CyberMind - https://cybermind.fr
# Author: Gerald Kerma <gandalf@gk2.net>

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Thresholds (MB)
WARN_THRESHOLD=80
CRIT_THRESHOLD=150

# Parse args
CSV_MODE=false
WATCH_MODE=false
INTERVAL=5

while [[ $# -gt 0 ]]; do
    case $1 in
        --csv) CSV_MODE=true; shift ;;
        --watch) WATCH_MODE=true; shift ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--csv] [--watch] [--interval N]"
            echo ""
            echo "Options:"
            echo "  --csv       Output CSV format"
            echo "  --watch     Continuous monitoring mode"
            echo "  --interval  Seconds between samples (default: 5)"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Check for smem (preferred) or fallback to /proc
if command -v smem &>/dev/null; then
    USE_SMEM=true
else
    USE_SMEM=false
    if ! $CSV_MODE; then
        echo "Note: 'smem' not installed. Using /proc fallback (RSS only)."
        echo "Install smem for PSS/USS metrics: apt install smem"
        echo ""
    fi
fi

get_service_memory() {
    local service=$1
    local pid

    # Get main PID
    pid=$(systemctl show -p MainPID "$service" --value 2>/dev/null || echo "0")

    if [[ "$pid" == "0" ]] || [[ -z "$pid" ]]; then
        echo "0 0 0"
        return
    fi

    if $USE_SMEM; then
        # smem gives PSS (Proportional Set Size) - best metric
        smem -P "^$pid\$" -c "pss uss rss" -H -k 2>/dev/null | \
            awk 'NR==1 {print $1/1024, $2/1024, $3/1024}' || echo "0 0 0"
    else
        # Fallback: read RSS from /proc
        local rss_kb
        rss_kb=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo "0")
        local rss_mb=$((rss_kb / 1024))
        echo "$rss_mb $rss_mb $rss_mb"
    fi
}

get_all_services() {
    systemctl list-units --type=service --state=running 2>/dev/null | \
        grep -E 'secubox-|eye-remote' | \
        awk '{print $1}' | \
        sed 's/\.service$//'
}

print_header() {
    if $CSV_MODE; then
        echo "timestamp,service,pss_mb,uss_mb,rss_mb,status"
    else
        printf "\n%-30s %10s %10s %10s %8s\n" "SERVICE" "PSS (MB)" "USS (MB)" "RSS (MB)" "STATUS"
        printf "%s\n" "$(printf '=%.0s' {1..70})"
    fi
}

print_service() {
    local service=$1
    local pss=$2
    local uss=$3
    local rss=$4
    local timestamp

    timestamp=$(date -Iseconds)

    # Determine status
    local status="OK"
    local color=$GREEN

    if (( $(echo "$rss > $CRIT_THRESHOLD" | bc -l) )); then
        status="CRITICAL"
        color=$RED
    elif (( $(echo "$rss > $WARN_THRESHOLD" | bc -l) )); then
        status="WARNING"
        color=$YELLOW
    fi

    if $CSV_MODE; then
        echo "$timestamp,$service,$pss,$uss,$rss,$status"
    else
        printf "%-30s %10.1f %10.1f %10.1f ${color}%8s${NC}\n" \
            "$service" "$pss" "$uss" "$rss" "$status"
    fi
}

collect_baseline() {
    local services
    mapfile -t services < <(get_all_services)

    if [[ ${#services[@]} -eq 0 ]]; then
        echo "No SecuBox services found running."
        exit 1
    fi

    print_header

    local total_pss=0
    local total_rss=0
    local count=0

    for service in "${services[@]}"; do
        read -r pss uss rss < <(get_service_memory "$service")

        if [[ "$rss" != "0" ]]; then
            print_service "$service" "$pss" "$uss" "$rss"
            total_pss=$(echo "$total_pss + $pss" | bc)
            total_rss=$(echo "$total_rss + $rss" | bc)
            ((count++)) || true
        fi
    done

    if ! $CSV_MODE; then
        printf "%s\n" "$(printf '-%.0s' {1..70})"
        printf "%-30s %10.1f %10s %10.1f\n" "TOTAL ($count services)" "$total_pss" "" "$total_rss"

        # System totals
        echo ""
        echo "System Memory:"
        free -h | head -2

        # Recommendations
        if (( $(echo "$total_rss > 500" | bc -l) )); then
            echo ""
            echo -e "${YELLOW}Warning: Total Python service memory > 500MB${NC}"
            echo "Consider reducing MAX_HISTORY_ENTRIES or enabling more aggressive caching."
        fi
    fi
}

watch_memory() {
    echo "Watching SecuBox service memory (Ctrl+C to stop)..."
    echo "Interval: ${INTERVAL}s"
    echo ""

    while true; do
        clear
        echo "SecuBox Memory Monitor - $(date)"
        collect_baseline
        sleep "$INTERVAL"
    done
}

# Main
if $WATCH_MODE; then
    watch_memory
else
    collect_baseline
fi
