# SecuBox Performance Benchmark Suite

Performance testing and profiling tools for SecuBox services.
Designed for ARM64 constrained devices (ESPRESSObin 1GB, MOCHAbin 8GB).

## Quick Start

```bash
# Install dependencies
pip3 install httpx locust py-spy
apt install smem bc

# Run API latency test
./api-latency.py --host 192.168.255.250 --requests 50

# Check memory baseline
./memory-baseline.sh

# Profile CPU usage
sudo ./cpu-profile.sh --service hub --duration 30

# Load test with Locust
locust -f locustfile.py --host https://192.168.255.250
```

## Scripts

### api-latency.py
Measures API endpoint response times with P50/P95/P99 statistics.

```bash
# Test all default endpoints
./api-latency.py --host 192.168.255.250 --requests 100

# Test specific endpoint
./api-latency.py --host 10.55.0.1 --endpoints /api/v1/system/metrics

# JSON output for automation
./api-latency.py --host 192.168.255.250 --json > report.json

# Use HTTP instead of HTTPS
./api-latency.py --host localhost --http
```

**Output:**
```
Endpoint                                           P50       P99     OK
----------------------------------------------------------------------
/api/v1/system/metrics                           12.3ms    45.2ms  50/50
/api/v1/hub/status                               23.1ms    89.7ms  50/50
```

### memory-baseline.sh
Tracks per-service memory usage (RSS, PSS, USS).

```bash
# All SecuBox services
./memory-baseline.sh

# CSV output for graphing
./memory-baseline.sh --csv > memory.csv

# Continuous monitoring
./memory-baseline.sh --watch --interval 10
```

**Requires:** `smem` for PSS/USS metrics, falls back to /proc for RSS only.

**Output:**
```
SERVICE                        PSS (MB)   USS (MB)   RSS (MB)   STATUS
======================================================================
secubox-hub                        23.4       18.2       45.6       OK
secubox-crowdsec                   34.1       28.9       67.2       OK
```

### startup-time.sh
Measures service cold-start times using systemd timing data.

```bash
# All services
./startup-time.sh

# Specific service
./startup-time.sh --service hub

# Full dependency chain analysis
./startup-time.sh --full

# CSV output
./startup-time.sh --csv
```

**Output:**
```
SERVICE                             STARTUP (s)  MEMORY (KB)      STATE    VERDICT
===================================================================================
secubox-hub                               1.234        45678     active         OK
secubox-crowdsec                          2.567        67890     active       WARN
```

### cpu-profile.sh
Generates flame graphs for Python services using py-spy.

```bash
# Profile specific service
sudo ./cpu-profile.sh --service hub --duration 30

# Profile all Python services
sudo ./cpu-profile.sh --all --duration 60

# Profile specific PID
sudo ./cpu-profile.sh --pid 1234

# Include native code frames
sudo ./cpu-profile.sh --service hub --native
```

**Requires:** `py-spy` (`pip3 install py-spy`), root privileges.

**Output:** SVG flame graphs in `/var/cache/secubox/profiles/`

### locustfile.py
Load testing scenarios for Locust framework.

```bash
# Web UI mode (open http://localhost:8089)
locust -f locustfile.py --host https://192.168.255.250

# Headless mode
locust -f locustfile.py --host https://192.168.255.250 \
       --headless -u 10 -r 2 -t 60s

# ESPRESSObin light load
locust -f locustfile.py --host https://192.168.255.250 \
       --headless -u 5 -r 1 -t 120s --tags lite

# Stress test
locust -f locustfile.py --host https://192.168.255.250 \
       --headless -u 50 -r 10 -t 30s --tags stress
```

**User Classes:**
- `SecuBoxUser` - Realistic dashboard browsing (1-3s wait)
- `StressUser` - Maximum throughput testing (no wait)
- `CacheTestUser` - Cache hit ratio testing
- `EspressoBinUser` - Light load for 1GB devices
- `MochabinUser` - Heavy load for 8GB devices

## Performance Targets

| Metric | ESPRESSObin | MOCHAbin |
|--------|-------------|----------|
| API P50 latency | < 100ms | < 50ms |
| API P99 latency | < 500ms | < 200ms |
| Service RSS | < 50MB | < 100MB |
| Total Python RSS | < 400MB | < 1GB |
| Cold start | < 5s | < 3s |
| Cache hit ratio | > 90% | > 95% |

## Dependencies

### Required
```bash
# Python packages
pip3 install httpx

# System tools
apt install bc
```

### Recommended
```bash
# Memory profiling
apt install smem

# CPU profiling
pip3 install py-spy

# Load testing
pip3 install locust

# Additional monitoring
apt install linux-perf sysstat htop iotop
```

## Integration

### CI Pipeline
```yaml
# .github/workflows/perf-test.yml
- name: Run API latency test
  run: |
    ./scripts/bench/api-latency.py --host localhost --json > latency.json
    python3 -c "import json; d=json.load(open('latency.json')); exit(1 if max(r['p99_ms'] for r in d['results']) > 500 else 0)"
```

### Cron Monitoring
```bash
# /etc/cron.d/secubox-bench
*/15 * * * * root /opt/secubox/scripts/bench/memory-baseline.sh --csv >> /var/log/secubox/memory.csv
```

## Author

CyberMind - https://cybermind.fr
Gerald Kerma <gandalf@gk2.net>
