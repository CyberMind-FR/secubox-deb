#!/bin/bash
# SecuBox Performance Benchmark - CPU Profiling
#
# Generates flame graphs for Python services using py-spy.
# Outputs SVG flame graphs for performance analysis.
#
# Usage:
#     ./cpu-profile.sh --service hub --duration 30
#     ./cpu-profile.sh --all --duration 60
#     ./cpu-profile.sh --pid 1234 --output /tmp/profile.svg
#
# Requirements:
#     pip3 install py-spy
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

# Defaults
DURATION=30
OUTPUT_DIR="/var/cache/secubox/profiles"
SPECIFIC_SERVICE=""
SPECIFIC_PID=""
PROFILE_ALL=false
NATIVE=false
SUBPROCESSES=false

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --service) SPECIFIC_SERVICE="$2"; shift 2 ;;
        --pid) SPECIFIC_PID="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --all) PROFILE_ALL=true; shift ;;
        --native) NATIVE=true; shift ;;
        --subprocesses) SUBPROCESSES=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --service NAME    Profile specific SecuBox service"
            echo "  --pid PID         Profile specific process ID"
            echo "  --duration N      Recording duration in seconds (default: 30)"
            echo "  --output DIR      Output directory (default: /var/cache/secubox/profiles)"
            echo "  --all             Profile all running SecuBox Python services"
            echo "  --native          Include native stack frames"
            echo "  --subprocesses    Include subprocesses"
            echo ""
            echo "Examples:"
            echo "  $0 --service hub --duration 60"
            echo "  $0 --all --duration 30"
            echo "  $0 --pid 1234 --native"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

check_requirements() {
    if ! command -v py-spy &>/dev/null; then
        echo -e "${RED}Error: py-spy not installed${NC}"
        echo "Install with: pip3 install py-spy"
        echo "Or: apt install py-spy (if available)"
        exit 1
    fi

    # Check for root (py-spy needs it)
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}Warning: py-spy typically requires root privileges${NC}"
        echo "Run with: sudo $0 $*"
    fi
}

get_python_services() {
    systemctl list-units --type=service --state=running 2>/dev/null | \
        grep -E 'secubox-|eye-remote' | \
        awk '{print $1}' | \
        sed 's/\.service$//'
}

get_service_pid() {
    local service=$1
    systemctl show -p MainPID "${service}.service" --value 2>/dev/null || echo "0"
}

is_python_process() {
    local pid=$1
    local exe
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")
    [[ "$exe" == *python* ]]
}

profile_service() {
    local service=$1
    local pid
    local output_file
    local timestamp

    timestamp=$(date +%Y%m%d-%H%M%S)
    pid=$(get_service_pid "$service")

    if [[ "$pid" == "0" ]] || [[ -z "$pid" ]]; then
        echo -e "${YELLOW}Service $service not running, skipping${NC}"
        return 1
    fi

    if ! is_python_process "$pid"; then
        echo -e "${YELLOW}Service $service (PID $pid) is not Python, skipping${NC}"
        return 1
    fi

    output_file="${OUTPUT_DIR}/${service}-${timestamp}.svg"
    mkdir -p "$OUTPUT_DIR"

    echo -e "${CYAN}Profiling $service (PID $pid) for ${DURATION}s...${NC}"

    local py_spy_args=("record" "-d" "$DURATION" "-o" "$output_file" "-p" "$pid" "-f" "speedscope")

    if $NATIVE; then
        py_spy_args+=("--native")
    fi

    if $SUBPROCESSES; then
        py_spy_args+=("--subprocesses")
    fi

    # Run py-spy
    if py-spy "${py_spy_args[@]}" 2>/dev/null; then
        echo -e "${GREEN}Flame graph saved: $output_file${NC}"

        # Also generate SVG format
        local svg_file="${output_file%.svg}-flame.svg"
        py-spy record -d "$DURATION" -o "$svg_file" -p "$pid" --format flamegraph 2>/dev/null || true
        if [[ -f "$svg_file" ]]; then
            echo -e "${GREEN}SVG flame graph: $svg_file${NC}"
        fi

        return 0
    else
        echo -e "${RED}Failed to profile $service${NC}"
        return 1
    fi
}

profile_pid() {
    local pid=$1
    local output_file
    local timestamp

    timestamp=$(date +%Y%m%d-%H%M%S)

    if [[ ! -d "/proc/$pid" ]]; then
        echo -e "${RED}PID $pid not found${NC}"
        exit 1
    fi

    if ! is_python_process "$pid"; then
        echo -e "${YELLOW}Warning: PID $pid may not be a Python process${NC}"
    fi

    output_file="${OUTPUT_DIR}/pid-${pid}-${timestamp}.svg"
    mkdir -p "$OUTPUT_DIR"

    echo -e "${CYAN}Profiling PID $pid for ${DURATION}s...${NC}"

    local py_spy_args=("record" "-d" "$DURATION" "-o" "$output_file" "-p" "$pid")

    if $NATIVE; then
        py_spy_args+=("--native")
    fi

    if $SUBPROCESSES; then
        py_spy_args+=("--subprocesses")
    fi

    if py-spy "${py_spy_args[@]}"; then
        echo -e "${GREEN}Flame graph saved: $output_file${NC}"
    else
        echo -e "${RED}Failed to profile PID $pid${NC}"
        exit 1
    fi
}

quick_top() {
    local pid=$1
    local duration=${2:-5}

    echo -e "${CYAN}Quick CPU sample (${duration}s) for PID $pid:${NC}"
    py-spy top --pid "$pid" 2>/dev/null &
    local pyspy_pid=$!
    sleep "$duration"
    kill "$pyspy_pid" 2>/dev/null || true
}

show_summary() {
    echo ""
    echo -e "${CYAN}Profile Summary${NC}"
    echo "==============="
    echo ""

    if [[ -d "$OUTPUT_DIR" ]]; then
        echo "Recent profiles:"
        ls -lt "$OUTPUT_DIR"/*.svg 2>/dev/null | head -10 || echo "  (none)"

        local total_size
        total_size=$(du -sh "$OUTPUT_DIR" 2>/dev/null | awk '{print $1}')
        echo ""
        echo "Total profile storage: $total_size"
    fi

    echo ""
    echo "View flame graphs:"
    echo "  - Open .svg files in browser"
    echo "  - Use speedscope.app for .json profiles"
    echo "  - Install flamegraph-rs for CLI viewing"
}

run_dump() {
    # Quick dump of current Python call stacks (no recording)
    local service=$1
    local pid

    pid=$(get_service_pid "$service")

    if [[ "$pid" == "0" ]] || [[ -z "$pid" ]]; then
        echo -e "${YELLOW}Service $service not running${NC}"
        return 1
    fi

    echo -e "${CYAN}Call stack dump for $service (PID $pid):${NC}"
    py-spy dump --pid "$pid" 2>/dev/null || echo "  (failed)"
}

# Main
check_requirements

mkdir -p "$OUTPUT_DIR"

echo ""
echo -e "${CYAN}SecuBox CPU Profiler${NC}"
echo "===================="
echo "Output directory: $OUTPUT_DIR"
echo "Duration: ${DURATION}s"
echo ""

if [[ -n "$SPECIFIC_PID" ]]; then
    profile_pid "$SPECIFIC_PID"
elif [[ -n "$SPECIFIC_SERVICE" ]]; then
    profile_service "secubox-$SPECIFIC_SERVICE" || profile_service "$SPECIFIC_SERVICE" || exit 1
elif $PROFILE_ALL; then
    echo "Profiling all SecuBox Python services..."
    echo ""

    mapfile -t services < <(get_python_services)

    if [[ ${#services[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No SecuBox services found running${NC}"
        exit 1
    fi

    success=0
    for service in "${services[@]}"; do
        if profile_service "$service"; then
            ((success++)) || true
        fi
        echo ""
    done

    echo -e "${GREEN}Profiled $success services${NC}"
else
    echo "No target specified. Options:"
    echo "  --service NAME    Profile specific service"
    echo "  --pid PID         Profile specific PID"
    echo "  --all             Profile all SecuBox services"
    echo ""
    echo "Currently running SecuBox Python services:"

    mapfile -t services < <(get_python_services)
    for service in "${services[@]}"; do
        pid=$(get_service_pid "$service")
        if is_python_process "$pid" 2>/dev/null; then
            echo "  - $service (PID $pid)"
        fi
    done

    exit 0
fi

show_summary
