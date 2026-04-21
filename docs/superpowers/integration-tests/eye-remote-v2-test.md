# Eye Remote v2.0.0 Integration Test Guide

SecuBox-Deb :: Eye Remote Integration Tests
CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

---

## Prerequisites

- Python 3.11+
- SecuBox development environment
- Network access (localhost)
- Virtual environment activated

## Quick Verification

Run all module import checks at once:

```bash
cd packages/secubox-eye-remote
python3 -c "
from models.device import PairedDevice, DeviceScope
from core.device_registry import DeviceRegistry
from core.token_manager import generate_device_token, hash_token
print('All API modules: OK')
"

cd remote-ui/round
python3 -c "
from agent.config import load_config, Config
from agent.secubox_client import SecuBoxClient
from agent.metrics_bridge import MetricsBridge
from agent.device_manager import DeviceManager
print('All agent modules: OK')
"
```

## Test 1: Gateway Emulator

The gateway emulator simulates a SecuBox device for development and testing.

### Install Gateway

```bash
cd tools/secubox-eye-gateway
pip install -e .
```

### Run Gateway with Different Profiles

```bash
# Normal profile (default)
cd tools/secubox-eye-gateway
python -c "from gateway.main import main; main.callback(port=8000, host='0.0.0.0', name='Test SecuBox', profile='normal')"

# Stressed profile (high load simulation)
python -c "from gateway.main import main; main.callback(port=8000, host='0.0.0.0', name='Test SecuBox', profile='stressed')"

# Available profiles: idle, normal, busy, stressed
```

### Test API Endpoints

In a separate terminal while gateway is running:

```bash
# Test health endpoint
curl -s http://localhost:8000/api/v1/health | jq .
# Expected: {"status": "healthy", "device_id": "...", ...}

# Test metrics endpoint
curl -s http://localhost:8000/api/v1/system/metrics | jq .
# Expected: {"cpu_percent": ..., "memory_percent": ..., ...}

# Test discovery endpoint
curl -s http://localhost:8000/api/v1/eye-remote/discover | jq .
# Expected: {"device_id": "...", "name": "Test SecuBox", "version": "...", ...}
```

Expected: All endpoints return valid JSON with emulated data.

## Test 2: Unit Tests

Run the full test suite:

```bash
cd packages/secubox-eye-remote
python -m pytest tests/ -v
```

Expected output:

```
tests/test_device_registry.py::test_registry_add_device PASSED
tests/test_device_registry.py::test_registry_persists_to_file PASSED
tests/test_device_registry.py::test_registry_remove_device PASSED
tests/test_device_registry.py::test_registry_list_devices PASSED
tests/test_device_registry.py::test_registry_update_last_seen PASSED
tests/test_device_registry.py::test_registry_validate_token PASSED
tests/test_device_registry.py::test_registry_get_nonexistent_device PASSED
tests/test_device_registry.py::test_registry_remove_nonexistent_device PASSED
tests/test_token_manager.py::test_generate_device_token PASSED
tests/test_token_manager.py::test_hash_token PASSED
tests/test_token_manager.py::test_verify_token PASSED
tests/test_token_manager.py::test_generate_pairing_code PASSED
tests/test_token_manager.py::test_tokens_are_unique PASSED

============================== 13 passed ==============================
```

## Test 3: Eye Agent with Gateway

Test the agent connecting to the emulated gateway.

### Create Test Config

```bash
mkdir -p /tmp/secubox-eye-test
cat > /tmp/secubox-eye-test/config.toml << 'EOF'
[device]
id = "eye-test-001"
name = "Test Dashboard"

[[secubox]]
name = "Test SecuBox"
host = "127.0.0.1:8000"
token = "test-token"
active = true
EOF
```

### Start Gateway in Background

```bash
cd tools/secubox-eye-gateway
python -c "from gateway.main import main; main.callback(port=8000, host='127.0.0.1', name='Test SecuBox', profile='normal')" &
GATEWAY_PID=$!
sleep 2
echo "Gateway running with PID: $GATEWAY_PID"
```

### Run Agent

```bash
cd remote-ui/round
timeout 10 python -m agent.main /tmp/secubox-eye-test/config.toml &
AGENT_PID=$!
sleep 5
echo "Agent running with PID: $AGENT_PID"
```

### Check Metrics Socket

```bash
# Socket may require elevated permissions
ls -la /run/secubox-eye/metrics.sock || echo "Socket may need root access"

# Or check agent logs
journalctl -u secubox-eye-agent --no-pager -n 20 || echo "No systemd logs (running manually)"
```

### Cleanup

```bash
kill $AGENT_PID $GATEWAY_PID 2>/dev/null
rm -rf /tmp/secubox-eye-test
```

## Test 4: API Module Comprehensive Check

```bash
cd packages/secubox-eye-remote
python3 << 'EOF'
from models.device import PairedDevice, DeviceScope, TransportType
from core.device_registry import DeviceRegistry
from core.token_manager import generate_device_token, hash_token, verify_token
import tempfile
import os

print("=== Token Manager Tests ===")
# Test token generation
token = generate_device_token("test-device")
print(f"Generated token: {token[:16]}...")
assert len(token) >= 32, "Token too short"

# Test token hashing
hashed = hash_token(token)
print(f"Token hash: {hashed[:16]}...")
assert len(hashed) == 64, "SHA256 hash should be 64 chars"

# Test token verification
assert verify_token(token, hashed), "Token verification failed"
print("Token verification: PASS")

print("\n=== Device Model Tests ===")
# Test device creation
device = PairedDevice(
    device_id="test-001",
    name="Test Device",
    token_hash=hashed,
    transport=TransportType.WIFI,
    scopes=[DeviceScope.METRICS_READ],
)
print(f"Device created: {device.device_id}")
print(f"Device name: {device.name}")
print(f"Transport: {device.transport}")
print(f"Scopes: {device.scopes}")

print("\n=== Device Registry Tests ===")
# Test registry with temp file
with tempfile.TemporaryDirectory() as tmpdir:
    registry_file = os.path.join(tmpdir, "devices.json")
    registry = DeviceRegistry(registry_file)

    # Add device
    registry.add_device(device)
    print(f"Device added to registry")

    # Retrieve device
    retrieved = registry.get_device("test-001")
    assert retrieved is not None, "Failed to retrieve device"
    assert retrieved.name == "Test Device", "Device name mismatch"
    print(f"Device retrieved: {retrieved.device_id}")

    # List devices
    devices = registry.list_devices()
    assert len(devices) == 1, "Should have 1 device"
    print(f"Total devices: {len(devices)}")

    # Validate token
    valid = registry.validate_token("test-001", token)
    assert valid, "Token validation failed"
    print("Token validation: PASS")

print("\n=== All Tests PASSED ===")
EOF
```

Expected output:
```
=== Token Manager Tests ===
Generated token: sec_xxxxxxxxxxxx...
Token hash: xxxxxxxxxxxxxxxx...
Token verification: PASS

=== Device Model Tests ===
Device created: test-001
Device name: Test Device
Transport: TransportType.WIFI
Scopes: [<DeviceScope.METRICS_READ: 'metrics:read'>]

=== Device Registry Tests ===
Device added to registry
Device retrieved: test-001
Total devices: 1
Token validation: PASS

=== All Tests PASSED ===
```

## Test 5: Debian Package Build (Optional)

Test the Debian package build process:

```bash
cd packages/secubox-eye-remote

# Check debian files exist
ls -la debian/

# Dry run package build (requires dpkg-buildpackage)
dpkg-buildpackage -us -uc -b --check-command=true 2>&1 | head -30 || echo "dpkg-buildpackage not available or build check only"
```

## Success Criteria

| Test | Status | Notes |
|------|--------|-------|
| Gateway starts and responds to all endpoints | [ ] | All profiles work |
| Agent connects to gateway and polls metrics | [ ] | Config loads correctly |
| All Python modules import without errors | [ ] | API + Agent modules |
| Token generation and verification works | [ ] | SHA256 hashing |
| Device model instantiation works | [ ] | All fields validate |
| Device registry CRUD operations work | [ ] | Persistence to JSON |
| Unit tests pass (13/13) | [ ] | pytest passes |

## Troubleshooting

### Import Errors

If you see import errors, ensure you're in the correct directory and the virtual environment is activated:

```bash
source .venv/bin/activate
export PYTHONPATH="${PYTHONPATH}:$(pwd)/packages/secubox-eye-remote"
```

### Gateway Won't Start

Check if the port is already in use:

```bash
ss -tlnp | grep 8000
```

### Agent Socket Permission Denied

The metrics socket requires write access to `/run/secubox-eye/`:

```bash
sudo mkdir -p /run/secubox-eye
sudo chown $USER:$USER /run/secubox-eye
```

### Tests Failing

Ensure all dependencies are installed:

```bash
pip install pytest pytest-asyncio
```

---

## Version Information

- Eye Remote: v2.0.0
- Gateway Emulator: v1.0.0
- Python: 3.11+
- SecuBox-Deb: Current development version
