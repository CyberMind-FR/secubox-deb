# Eye Remote Gateway & Emulator

## Overview

The `secubox-eye-gateway` tool provides development and testing capabilities for the Eye Remote dashboard without requiring physical SecuBox hardware.

## Installation

```bash
# From source
cd tools/secubox-eye-gateway
pip install -e .

# Verify installation
secubox-eye-gateway --help
```

## Usage Modes

### Emulator Mode (Default)

Simulates a SecuBox with configurable metrics profiles:

```bash
# Run with default profile (normal)
secubox-eye-gateway

# Run with specific profile
secubox-eye-gateway --profile stressed --port 8765

# Available profiles:
#   idle     - Low activity system
#   normal   - Typical workload
#   busy     - Heavy utilization
#   stressed - Near-critical levels
```

### Gateway Mode (Future)

Proxy to real SecuBox hardware:

```bash
# Proxy to real SecuBox
secubox-eye-gateway --mode gateway --target 192.168.1.100:8000
```

### Fleet Mode (Future)

Aggregate multiple SecuBox devices:

```bash
# Fleet aggregation
secubox-eye-gateway --mode fleet \
    --device secubox-1:192.168.1.101:8000 \
    --device secubox-2:192.168.1.102:8000
```

## API Endpoints

### Health Check

```
GET /api/v1/health
```

Response:
```json
{
    "status": "healthy",
    "version": "1.0.0",
    "mode": "emulator",
    "profile": "stressed"
}
```

### System Metrics

```
GET /api/v1/system/metrics
```

Response:
```json
{
    "cpu_percent": 85.3,
    "memory_percent": 72.1,
    "disk_percent": 45.8,
    "cpu_temp": 68.5,
    "load_avg_1": 2.34,
    "uptime_seconds": 345600,
    "hostname": "secubox-emulated",
    "timestamp": "2026-04-21T22:00:00Z"
}
```

### Device Discovery

```
GET /api/v1/eye-remote/discover
```

Response:
```json
{
    "device_id": "9a0f3d1f",
    "device_name": "Test SecuBox",
    "device_type": "emulator",
    "profile": "stressed",
    "api_version": "1.0.0",
    "capabilities": ["metrics", "pairing", "commands"]
}
```

## Metrics Profiles

### idle

Low-activity system at rest.

| Metric | Range |
|--------|-------|
| CPU | 2-8% |
| Memory | 20-30% |
| Disk | 15-25% |
| Temperature | 38-45°C |
| Load | 0.05-0.15 |

### normal

Typical production workload.

| Metric | Range |
|--------|-------|
| CPU | 15-35% |
| Memory | 40-55% |
| Disk | 25-40% |
| Temperature | 48-55°C |
| Load | 0.3-0.8 |

### busy

Heavy processing load.

| Metric | Range |
|--------|-------|
| CPU | 55-75% |
| Memory | 65-80% |
| Disk | 35-55% |
| Temperature | 58-68°C |
| Load | 1.5-2.5 |

### stressed

Near-critical system state.

| Metric | Range |
|--------|-------|
| CPU | 80-95% |
| Memory | 85-95% |
| Disk | 60-85% |
| Temperature | 70-80°C |
| Load | 3.0-5.0 |

## Dashboard Integration

### Configure Dashboard to Use Emulator

Edit the Eye Remote dashboard configuration:

```javascript
// In dashboard config
const CFG = {
    API_OTG_BASE: 'http://localhost:8765',  // Gateway emulator
    API_WIFI_BASE: 'http://localhost:8765',
    SIMULATE: false,  // Use real API
    // ...
};
```

### Test Sequence

1. Start the gateway emulator:
   ```bash
   secubox-eye-gateway --profile busy --port 8765
   ```

2. Open dashboard in browser:
   ```bash
   firefox http://localhost:8080
   ```

3. Dashboard fetches metrics from emulator every 2 seconds

4. Switch profiles to test different states:
   ```bash
   # Stop and restart with different profile
   secubox-eye-gateway --profile stressed --port 8765
   ```

## Development

### Project Structure

```
tools/secubox-eye-gateway/
├── gateway/
│   ├── __init__.py
│   ├── cli.py          # Click CLI interface
│   ├── emulator.py     # Metrics emulation logic
│   └── server.py       # FastAPI server
├── pyproject.toml      # Package configuration
└── README.md
```

### Adding Custom Profiles

Edit `gateway/emulator.py`:

```python
PROFILES = {
    # ... existing profiles ...
    "custom": {
        "cpu_base": 50,
        "cpu_variance": 10,
        "mem_base": 60,
        "mem_variance": 5,
        # ...
    }
}
```

### Running Tests

```bash
cd tools/secubox-eye-gateway
pytest tests/ -v
```

## Troubleshooting

### Port Already in Use

```bash
# Find process using port
lsof -i :8765

# Kill it
kill -9 <PID>

# Or use different port
secubox-eye-gateway --port 8766
```

### Connection Refused

Check that the gateway is running and accessible:

```bash
curl http://localhost:8765/api/v1/health
```

### CORS Issues

The gateway includes CORS headers for all origins. If issues persist, check browser console for specific errors.

## Related Documentation

- [Eye Remote Implementation](Eye-Remote-Implementation.md)
- [Eye Remote Hardware](Eye-Remote-Hardware.md)
- [SecuBox API Reference](../api/README.md)

---

*CyberMind · SecuBox Eye Remote Gateway · April 2026*
