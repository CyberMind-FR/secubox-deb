#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: scripts/sbxwaf-bench.sh
#
# Shadow-run bench harness for secubox-waf-ng (ref #744).
# Drives wrk or hey against the mitmproxy fleet (legacy) and the sbxwaf
# shadow worker (new), captures req/s, p99 latency, and RSS, then prints a
# comparison table with PASS/FAIL against the go/no-go gates:
#
#   Gate 1: req/s·core_sbxwaf  > 5 × req/s·core_mitmproxy
#   Gate 2: p99_sbxwaf         < (1/3) × p99_mitmproxy
#   Gate 3: RSS_sbxwaf         < (1/4) × RSS_mitmproxy_fleet
#
# Dependencies (auto-detected in order of preference):
#   wrk   — https://github.com/wg/wrk   (apt install wrk)
#   hey   — https://github.com/rakyll/hey (go install github.com/rakyll/hey@latest)
#
# Usage:
#   # Defaults: legacy=10.100.0.60:8080 shadow=127.0.0.1:8081 duration=30s conns=50
#   bash scripts/sbxwaf-bench.sh
#
#   # Custom targets
#   LEGACY_ADDR=10.100.0.60:8080  \
#   SHADOW_ADDR=127.0.0.1:8081    \
#   DURATION=60                   \
#   CONNECTIONS=100               \
#   bash scripts/sbxwaf-bench.sh
#
# Environment variables:
#   LEGACY_ADDR      mitmproxy fleet address (host:port)    [10.100.0.60:8080]
#   SHADOW_ADDR      sbxwaf shadow worker address (host:port) [127.0.0.1:8081]
#   BENCH_HOST       HTTP Host header to present             [secubox.local]
#   DURATION         Bench duration in seconds               [30]
#   CONNECTIONS      Concurrent connections                  [50]
#   LEGACY_CORES     vCPU count for legacy fleet (divisor)  [4]
#   SHADOW_CORES     vCPU count for sbxwaf workers (divisor)[2]
#   LEGACY_UNIT      systemd unit pattern for RSS (legacy)   [secubox-toolbox-ng-worker@*]
#   SHADOW_UNIT      systemd unit for RSS (shadow)           [secubox-waf-ng-worker@1]
#   SKIP_BLOCKED     Set to 1 to skip the blocked-payload request [0]
#
# Output:
#   Comparison table printed to stdout.
#   On all gates PASS → exit 0.
#   On any gate FAIL  → exit 1.
#
# NOTE: Run as root (or a user with systemctl read access) to collect RSS
# via MemoryCurrent.  Falls back to ps VmRSS if systemctl is unavailable.

set -euo pipefail

# ── Defaults (overridable via env) ─────────────────────────────────────────────
LEGACY_ADDR="${LEGACY_ADDR:-10.100.0.60:8080}"
SHADOW_ADDR="${SHADOW_ADDR:-127.0.0.1:8081}"
BENCH_HOST="${BENCH_HOST:-secubox.local}"
DURATION="${DURATION:-30}"
CONNECTIONS="${CONNECTIONS:-50}"
LEGACY_CORES="${LEGACY_CORES:-4}"
SHADOW_CORES="${SHADOW_CORES:-2}"
LEGACY_UNIT="${LEGACY_UNIT:-secubox-toolbox-ng-worker@}"
SHADOW_UNIT="${SHADOW_UNIT:-secubox-waf-ng-worker@1}"
SKIP_BLOCKED="${SKIP_BLOCKED:-0}"

# Gate thresholds (multipliers / fractions)
GATE_RPS_FACTOR=5      # sbxwaf req/s·core must be > 5× mitmproxy
GATE_P99_FRAC="0.333"  # sbxwaf p99 must be < 1/3 of mitmproxy p99
GATE_RSS_FRAC="0.250"  # sbxwaf RSS must be < 1/4 of mitmproxy fleet RSS

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${CYAN}[bench]${NC} $*" >&2; }
err()  { echo -e "${RED}[bench]${NC} $*" >&2; }

# ── Tool detection ─────────────────────────────────────────────────────────────
detect_tool() {
    if command -v wrk &>/dev/null; then
        echo "wrk"
    elif command -v hey &>/dev/null; then
        echo "hey"
    else
        err "No load tool found. Install one of:"
        err "  wrk : apt install wrk"
        err "  hey : go install github.com/rakyll/hey@latest"
        exit 1
    fi
}

BENCH_TOOL="$(detect_tool)"
log "Using load tool: ${BENCH_TOOL}"

# ── RSS helpers ────────────────────────────────────────────────────────────────
# Returns RSS in MiB for a systemd unit pattern (sum across instances).
get_rss_systemd() {
    local unit_pattern="$1"
    local total_bytes=0
    # Expand pattern to matching units
    local units
    units=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null \
        | awk '{print $1}' | grep "^${unit_pattern}" || true)
    if [[ -z "$units" ]]; then
        echo "0"
        return
    fi
    while IFS= read -r unit; do
        local mem
        mem=$(systemctl show -p MemoryCurrent "$unit" --value 2>/dev/null || echo "0")
        # MemoryCurrent can be "[not set]" when cgroups v1 or unsupported
        if [[ "$mem" =~ ^[0-9]+$ ]]; then
            total_bytes=$(( total_bytes + mem ))
        fi
    done <<<"$units"
    # Convert bytes → MiB
    echo $(( total_bytes / 1048576 ))
}

get_rss_ps() {
    local pattern="$1"
    local total_kb=0
    while IFS= read -r line; do
        total_kb=$(( total_kb + line ))
    done < <(ps aux 2>/dev/null \
        | awk -v pat="$pattern" '$0 ~ pat {print $6}' || true)
    echo $(( total_kb / 1024 ))
}

get_rss_mib() {
    local unit_pattern="$1"
    local rss
    rss=$(get_rss_systemd "$unit_pattern")
    if [[ "$rss" == "0" ]]; then
        # Fallback: ps VmRSS using service name as grep pattern
        rss=$(get_rss_ps "${unit_pattern}")
    fi
    echo "$rss"
}

# ── Bench primitives ───────────────────────────────────────────────────────────
# Runs wrk or hey against a URL, returns two lines: "RPS <value>" "P99 <ms>"
# P99 is in milliseconds.
run_bench_wrk() {
    local url="$1"
    local host="$2"
    local duration="${3}s"
    local conns="$4"

    local output
    output=$(wrk -t"$conns" -c"$conns" -d"$duration" \
        -H "Host: $host" "$url" 2>&1) || true

    local rps
    rps=$(echo "$output" | grep -E 'Requests/sec:' | awk '{print $2}' | head -1)
    rps="${rps:-0}"

    # wrk reports percentile latencies in the format:
    #   99%    234.56ms  or  99%      1.23s
    local p99_raw
    p99_raw=$(echo "$output" | grep -E '^\s+99%' | awk '{print $2}' | head -1)
    local p99_ms
    p99_ms=$(parse_latency_to_ms "$p99_raw")

    echo "RPS $rps"
    echo "P99 $p99_ms"
}

run_bench_hey() {
    local url="$1"
    local host="$2"
    local duration="$3"
    local conns="$4"

    local output
    output=$(hey -z "${duration}s" -c "$conns" \
        -host "$host" "$url" 2>&1) || true

    local rps
    rps=$(echo "$output" | grep -E 'Requests/sec:' | awk '{print $2}' | head -1)
    rps="${rps:-0}"

    # hey reports: "  99% in 0.2345 secs"
    local p99_raw
    p99_raw=$(echo "$output" | grep -E '^\s+99%' | awk '{print $3}' | head -1)
    local p99_ms
    if [[ -n "$p99_raw" ]]; then
        p99_ms=$(awk "BEGIN {printf \"%.1f\", $p99_raw * 1000}" 2>/dev/null || echo "0")
    else
        p99_ms="0"
    fi

    echo "RPS $rps"
    echo "P99 $p99_ms"
}

# Parse wrk latency string (e.g. "234.56ms", "1.23s", "456us") to ms
parse_latency_to_ms() {
    local raw="${1:-}"
    if [[ -z "$raw" ]]; then
        echo "0"
        return
    fi
    if [[ "$raw" =~ ([0-9.]+)ms$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$raw" =~ ([0-9.]+)s$ ]]; then
        awk "BEGIN {printf \"%.1f\", ${BASH_REMATCH[1]} * 1000}"
    elif [[ "$raw" =~ ([0-9.]+)us$ ]]; then
        awk "BEGIN {printf \"%.3f\", ${BASH_REMATCH[1]} / 1000}"
    else
        echo "0"
    fi
}

run_bench() {
    local url="$1"
    local host="$2"
    local duration="$3"
    local conns="$4"

    case "$BENCH_TOOL" in
        wrk) run_bench_wrk "$url" "$host" "$duration" "$conns" ;;
        hey) run_bench_hey "$url" "$host" "$duration" "$conns" ;;
    esac
}

# ── per-core req/s arithmetic ─────────────────────────────────────────────────
per_core() {
    local rps="$1"
    local cores="$2"
    awk "BEGIN {printf \"%.1f\", $rps / $cores}"
}

# ── gate evaluation ────────────────────────────────────────────────────────────
# Returns "PASS" or "FAIL"
gate_pass() {
    local condition="$1"   # awk expression, prints "1" if pass
    local result
    result=$(awk "BEGIN {print ($condition) ? \"PASS\" : \"FAIL\"}")
    echo "$result"
}

pass_color() {
    local verdict="$1"
    if [[ "$verdict" == "PASS" ]]; then
        echo -e "${GREEN}PASS${NC}"
    else
        echo -e "${RED}FAIL${NC}"
    fi
}

# ── main benchmark sequence ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}SecuBox WAF-NG Shadow Bench Harness${NC} (ref #744)"
printf '═%.0s' {1..60}; echo
echo ""
echo "Load tool      : ${BENCH_TOOL}"
echo "Legacy (mitm)  : http://${LEGACY_ADDR}  (${LEGACY_CORES} workers)"
echo "Shadow (sbxwaf): http://${SHADOW_ADDR}  (${SHADOW_CORES} workers)"
echo "Duration       : ${DURATION}s"
echo "Connections    : ${CONNECTIONS}"
echo "Host header    : ${BENCH_HOST}"
echo ""

# ── URLs for benign media GET, benign API GET ──────────────────────────────────
URL_MEDIA_LEGACY="http://${LEGACY_ADDR}/media/poster.jpg"
URL_API_LEGACY="http://${LEGACY_ADDR}/api/v1/hub/status"
URL_MEDIA_SHADOW="http://${SHADOW_ADDR}/media/poster.jpg"
URL_API_SHADOW="http://${SHADOW_ADDR}/api/v1/hub/status"

# ── Collect RSS BEFORE load ────────────────────────────────────────────────────
log "Collecting RSS baseline..."
LEGACY_RSS_PRE=$(get_rss_mib "${LEGACY_UNIT}")
SHADOW_RSS_PRE=$(get_rss_mib "${SHADOW_UNIT}")
log "Legacy RSS pre-bench : ${LEGACY_RSS_PRE} MiB"
log "Shadow RSS pre-bench : ${SHADOW_RSS_PRE} MiB"

# ── Run bench against legacy ───────────────────────────────────────────────────
log "Benchmarking LEGACY (mitmproxy) — media GET..."
{
    read -r _rk_key LEGACY_MEDIA_RPS
    read -r _p99_key LEGACY_MEDIA_P99
} < <(run_bench "$URL_MEDIA_LEGACY" "$BENCH_HOST" "$DURATION" "$CONNECTIONS")

log "Benchmarking LEGACY (mitmproxy) — API GET..."
{
    read -r _rk_key LEGACY_API_RPS
    read -r _p99_key LEGACY_API_P99
} < <(run_bench "$URL_API_LEGACY" "$BENCH_HOST" "$DURATION" "$CONNECTIONS")

# Aggregate: average across the two benign requests
LEGACY_AVG_RPS=$(awk "BEGIN {printf \"%.1f\", ($LEGACY_MEDIA_RPS + $LEGACY_API_RPS) / 2}")
LEGACY_AVG_P99=$(awk "BEGIN {printf \"%.1f\", ($LEGACY_MEDIA_P99 + $LEGACY_API_P99) / 2}")

# ── Run bench against shadow ───────────────────────────────────────────────────
log "Benchmarking SHADOW (sbxwaf) — media GET..."
{
    read -r _rk_key SHADOW_MEDIA_RPS
    read -r _p99_key SHADOW_MEDIA_P99
} < <(run_bench "$URL_MEDIA_SHADOW" "$BENCH_HOST" "$DURATION" "$CONNECTIONS")

log "Benchmarking SHADOW (sbxwaf) — API GET..."
{
    read -r _rk_key SHADOW_API_RPS
    read -r _p99_key SHADOW_API_P99
} < <(run_bench "$URL_API_SHADOW" "$BENCH_HOST" "$DURATION" "$CONNECTIONS")

# Optional: blocked-payload request (expect 403/ban; not included in perf gates)
if [[ "$SKIP_BLOCKED" != "1" ]]; then
    log "Benchmarking SHADOW (sbxwaf) — blocked payload (SQLi, expect 403)..."
    BLOCKED_URL="http://${SHADOW_ADDR}/?id=1+union+select+1,2,3"
    {
        read -r _rk_key SHADOW_BLOCKED_RPS
        read -r _p99_key SHADOW_BLOCKED_P99
    } < <(run_bench "$BLOCKED_URL" "$BENCH_HOST" "$DURATION" "$CONNECTIONS")
    log "Shadow blocked req/s: ${SHADOW_BLOCKED_RPS}  p99: ${SHADOW_BLOCKED_P99}ms"
fi

# ── Collect RSS AFTER load ─────────────────────────────────────────────────────
log "Collecting RSS after load..."
LEGACY_RSS_POST=$(get_rss_mib "${LEGACY_UNIT}")
SHADOW_RSS_POST=$(get_rss_mib "${SHADOW_UNIT}")

# Use the higher of pre/post RSS (conservative: avoid transient spike illusion)
LEGACY_RSS=$(( LEGACY_RSS_POST > LEGACY_RSS_PRE ? LEGACY_RSS_POST : LEGACY_RSS_PRE ))
SHADOW_RSS=$(( SHADOW_RSS_POST > SHADOW_RSS_PRE ? SHADOW_RSS_POST : SHADOW_RSS_PRE ))

# ── Per-core req/s ─────────────────────────────────────────────────────────────
LEGACY_AVG_RPS_SHADOW=$(awk "BEGIN {printf \"%.1f\", ($SHADOW_MEDIA_RPS + $SHADOW_API_RPS) / 2}")
LEGACY_PERCORE=$(per_core "$LEGACY_AVG_RPS" "$LEGACY_CORES")
SHADOW_PERCORE=$(per_core "$LEGACY_AVG_RPS_SHADOW" "$SHADOW_CORES")
SHADOW_AVG_P99=$(awk "BEGIN {printf \"%.1f\", ($SHADOW_MEDIA_P99 + $SHADOW_API_P99) / 2}")

# ── Gate evaluation ────────────────────────────────────────────────────────────
# Gate 1: sbxwaf req/s·core > 5 × legacy req/s·core
G1=$(gate_pass "$SHADOW_PERCORE > $GATE_RPS_FACTOR * $LEGACY_PERCORE")
G1_REQUIRED=$(awk "BEGIN {printf \"%.1f\", $GATE_RPS_FACTOR * $LEGACY_PERCORE}")

# Gate 2: sbxwaf p99 < (1/3) × legacy p99
G2=$(gate_pass "$LEGACY_AVG_P99 > 0 && $SHADOW_AVG_P99 < $GATE_P99_FRAC * $LEGACY_AVG_P99")
G2_REQUIRED=$(awk "BEGIN {printf \"%.1f\", $GATE_P99_FRAC * $LEGACY_AVG_P99}")

# Gate 3: sbxwaf RSS < (1/4) × legacy fleet RSS
G3=$(gate_pass "$LEGACY_RSS > 0 && $SHADOW_RSS < $GATE_RSS_FRAC * $LEGACY_RSS")
G3_REQUIRED=$(awk "BEGIN {printf \"%.0f\", $GATE_RSS_FRAC * $LEGACY_RSS}")

# ── Print comparison table ─────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Benchmark Results${NC}"
printf '─%.0s' {1..60}; echo
printf "%-30s %12s %12s\n" "Metric" "Legacy(mitm)" "Shadow(sbxwaf)"
printf "%-30s %12s %12s\n" "$(printf '─%.0s' {1..30})" "$(printf '─%.0s' {1..12})" "$(printf '─%.0s' {1..14})"
printf "%-30s %12s %12s\n"  "avg req/s (benign)"    "${LEGACY_AVG_RPS}"     "${LEGACY_AVG_RPS_SHADOW}"
printf "%-30s %12s %12s\n"  "worker count"           "${LEGACY_CORES}"       "${SHADOW_CORES}"
printf "%-30s %12s %12s\n"  "req/s·core"             "${LEGACY_PERCORE}"     "${SHADOW_PERCORE}"
printf "%-30s %12s %12s\n"  "avg p99 latency (ms)"  "${LEGACY_AVG_P99}"     "${SHADOW_AVG_P99}"
printf "%-30s %12s %12s\n"  "RSS (MiB, post-bench)" "${LEGACY_RSS}"         "${SHADOW_RSS}"
echo ""
echo -e "${BOLD}Go/No-Go Gates${NC}"
printf '─%.0s' {1..60}; echo
printf "%-34s %-12s %-14s %s\n" "Gate" "Required" "Actual" "Verdict"
printf "%-34s %-12s %-14s %s\n" "$(printf '─%.0s' {1..34})" "$(printf '─%.0s' {1..12})" "$(printf '─%.0s' {1..14})" "───────"

printf "%-34s %-12s %-14s " \
    "G1: req/s·core > 5× legacy" \
    "> ${G1_REQUIRED}" \
    "${SHADOW_PERCORE}"
echo -e "$(pass_color "$G1")"

printf "%-34s %-12s %-14s " \
    "G2: p99 < 1/3 legacy p99" \
    "< ${G2_REQUIRED}ms" \
    "${SHADOW_AVG_P99}ms"
echo -e "$(pass_color "$G2")"

printf "%-34s %-12s %-14s " \
    "G3: RSS < 1/4 legacy RSS" \
    "< ${G3_REQUIRED}MiB" \
    "${SHADOW_RSS}MiB"
echo -e "$(pass_color "$G3")"

echo ""

# ── Overall verdict ────────────────────────────────────────────────────────────
OVERALL_PASS=true
for gate in "$G1" "$G2" "$G3"; do
    [[ "$gate" == "PASS" ]] || OVERALL_PASS=false
done

if $OVERALL_PASS; then
    echo -e "${GREEN}${BOLD}ALL GATES PASS — proceed to cutover (CUTOVER.md §3).${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}ONE OR MORE GATES FAILED — do NOT cut over; investigate before retry.${NC}"
    if [[ "$G1" == "FAIL" ]]; then
        echo "  G1 failed: sbxwaf req/s·core (${SHADOW_PERCORE}) not > ${GATE_RPS_FACTOR}× legacy (${LEGACY_PERCORE})."
        echo "  Check: worker count, CPU pinning, Go goroutine pool settings."
    fi
    if [[ "$G2" == "FAIL" ]]; then
        echo "  G2 failed: sbxwaf p99 (${SHADOW_AVG_P99}ms) not < 1/3 of legacy p99 (${LEGACY_AVG_P99}ms)."
        echo "  Check: upstream connect latency, RE2 rule compilation cache warm."
    fi
    if [[ "$G3" == "FAIL" ]]; then
        echo "  G3 failed: sbxwaf RSS (${SHADOW_RSS}MiB) not < 1/4 of legacy RSS (${LEGACY_RSS}MiB)."
        echo "  Check: media-cache-dir size, go runtime GOGC setting."
    fi
    exit 1
fi
