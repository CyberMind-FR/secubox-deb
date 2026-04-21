# Eye Remote v2.0.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect Eye Remote to real SecuBox metrics with auto-authentication, bidirectional control, and multi-SecuBox support.

**Architecture:** Eye Remote runs an agent (`secubox-eye-agent`) that manages connections to multiple SecuBoxes, authenticates via device tokens, and feeds metrics to the dashboard via Unix socket. SecuBox runs a new module (`secubox-eye-remote`) with device registry, pairing flow, and WebUI. A development gateway tool (`secubox-eye-gateway`) enables local testing with emulated or proxied SecuBoxes.

**Tech Stack:** Python 3.11+, FastAPI, asyncio, websockets, aiohttp, PIL, TOML config, systemd services

**Spec:** `docs/superpowers/specs/2026-04-21-eye-remote-integration-design.md`

---

## File Structure Overview

### Eye Remote Side (Pi Zero W)

```
remote-ui/round/
├── agent/
│   ├── __init__.py
│   ├── main.py              # Entry point, asyncio loop
│   ├── config.py            # TOML config loader
│   ├── secubox_client.py    # HTTP/WS client to one SecuBox
│   ├── device_manager.py    # Multi-SecuBox connections
│   ├── metrics_bridge.py    # Unix socket server for dashboard
│   ├── command_handler.py   # WebSocket command processing
│   └── pairing.py           # Pairing flow + QR generation
├── fb_dashboard.py          # Enhanced to read from agent
├── secubox-eye-agent.service
├── config.toml.example
└── tests/
    ├── test_config.py
    ├── test_secubox_client.py
    ├── test_device_manager.py
    └── test_metrics_bridge.py
```

### SecuBox Side (New Module)

```
packages/secubox-eye-remote/
├── api/
│   ├── __init__.py
│   ├── main.py              # FastAPI app
│   └── routers/
│       ├── __init__.py
│       ├── devices.py       # Device registry CRUD
│       ├── pairing.py       # Pairing endpoints
│       ├── metrics.py       # Metrics endpoint for Eye
│       └── websocket.py     # WS for commands
├── core/
│   ├── __init__.py
│   ├── device_registry.py   # JSON storage for devices
│   └── token_manager.py     # Token generation/validation
├── models/
│   ├── __init__.py
│   └── device.py            # Pydantic models
├── www/
│   ├── index.html           # Management dashboard
│   └── js/eye-remote.js
├── debian/
│   ├── control
│   ├── postinst
│   ├── prerm
│   └── rules
├── nginx/eye-remote.conf
├── menu.d/50-eye-remote.json
└── tests/
    ├── test_device_registry.py
    ├── test_token_manager.py
    └── test_api.py
```

### Gateway Tool

```
tools/secubox-eye-gateway/
├── gateway/
│   ├── __init__.py
│   ├── main.py              # CLI entry (click)
│   ├── server.py            # FastAPI app
│   ├── emulator.py          # Fake metrics
│   └── profiles.py          # Emulation profiles
├── fleet.toml.example
├── requirements.txt
├── setup.py
└── README.md
```

---

## Phase 1: Eye Remote Agent — Basic Metrics

### Task 1: Agent Config Module

**Files:**
- Create: `remote-ui/round/agent/__init__.py`
- Create: `remote-ui/round/agent/config.py`
- Create: `remote-ui/round/config.toml.example`
- Test: `remote-ui/round/tests/test_config.py`

- [ ] **Step 1: Create agent package init**

```python
# remote-ui/round/agent/__init__.py
"""
SecuBox Eye Remote Agent
Manages connections to SecuBox appliances and feeds metrics to dashboard.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
__version__ = "2.0.0"
```

- [ ] **Step 2: Write failing test for config loader**

```python
# remote-ui/round/tests/test_config.py
"""Tests for agent config module."""
import pytest
from pathlib import Path
import tempfile

def test_load_config_from_file():
    """Config should load from TOML file."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-test-001"
name = "Test Eye"

[[secubox]]
name = "Lab"
host = "10.55.0.1"
token = "test-token"
active = true
''')
        f.flush()

        config = load_config(Path(f.name))

        assert config.device.id == "eye-test-001"
        assert config.device.name == "Test Eye"
        assert len(config.secuboxes) == 1
        assert config.secuboxes[0].name == "Lab"
        assert config.secuboxes[0].host == "10.55.0.1"
        assert config.secuboxes[0].active is True


def test_get_active_secubox():
    """Should return the active SecuBox config."""
    from agent.config import load_config, get_active_secubox

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[[secubox]]
name = "Primary"
host = "10.55.0.1"
token = "token1"
active = true

[[secubox]]
name = "Secondary"
host = "192.168.1.100"
token = "token2"
active = false
''')
        f.flush()

        config = load_config(Path(f.name))
        active = get_active_secubox(config)

        assert active.name == "Primary"
        assert active.host == "10.55.0.1"


def test_config_default_values():
    """Config should have sensible defaults."""
    from agent.config import load_config

    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write('''
[device]
id = "eye-001"

[[secubox]]
name = "Lab"
host = "10.55.0.1"
token = "token"
active = true
''')
        f.flush()

        config = load_config(Path(f.name))

        # Should have default fallback
        assert config.secuboxes[0].fallback is None
        assert config.secuboxes[0].poll_interval == 2.0
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_config.py -v`
Expected: FAIL with "No module named 'agent.config'"

- [ ] **Step 4: Write config module**

```python
# remote-ui/round/agent/config.py
"""
SecuBox Eye Remote — Configuration loader
Loads device and SecuBox connection config from TOML file.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DEFAULT_CONFIG_PATH = Path("/etc/secubox-eye/config.toml")


@dataclass
class DeviceConfig:
    """Eye Remote device configuration."""
    id: str
    name: str = "Eye Remote"


@dataclass
class SecuBoxConfig:
    """Configuration for one SecuBox connection."""
    name: str
    host: str
    token: str
    active: bool = False
    fallback: Optional[str] = None
    poll_interval: float = 2.0


@dataclass
class Config:
    """Full agent configuration."""
    device: DeviceConfig
    secuboxes: list[SecuBoxConfig] = field(default_factory=list)


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    """
    Load configuration from TOML file.

    Args:
        path: Path to config file

    Returns:
        Parsed Config object
    """
    with open(path, "rb") as f:
        data = tomllib.load(f)

    device_data = data.get("device", {})
    device = DeviceConfig(
        id=device_data.get("id", "eye-unknown"),
        name=device_data.get("name", "Eye Remote"),
    )

    secuboxes = []
    for sb_data in data.get("secubox", []):
        secuboxes.append(SecuBoxConfig(
            name=sb_data.get("name", "SecuBox"),
            host=sb_data.get("host", "10.55.0.1"),
            token=sb_data.get("token", ""),
            active=sb_data.get("active", False),
            fallback=sb_data.get("fallback"),
            poll_interval=sb_data.get("poll_interval", 2.0),
        ))

    return Config(device=device, secuboxes=secuboxes)


def get_active_secubox(config: Config) -> Optional[SecuBoxConfig]:
    """
    Get the currently active SecuBox config.

    Returns:
        Active SecuBox config or None if none active
    """
    for sb in config.secuboxes:
        if sb.active:
            return sb
    return config.secuboxes[0] if config.secuboxes else None


def set_active_secubox(config: Config, name: str) -> bool:
    """
    Set a SecuBox as active by name.

    Args:
        config: Config object
        name: Name of SecuBox to activate

    Returns:
        True if found and activated
    """
    found = False
    for sb in config.secuboxes:
        if sb.name == name:
            sb.active = True
            found = True
        else:
            sb.active = False
    return found
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd remote-ui/round && python -m pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 6: Create example config file**

```toml
# remote-ui/round/config.toml.example
# SecuBox Eye Remote Configuration
# Copy to /etc/secubox-eye/config.toml

[device]
id = "eye-remote-001"
name = "Dashboard Principale"

# Primary SecuBox (via USB OTG)
[[secubox]]
name = "Home Lab"
host = "10.55.0.1"
fallback = "secubox.local"
token = "YOUR_DEVICE_TOKEN"
active = true
poll_interval = 2.0

# Secondary SecuBox (via WiFi)
# [[secubox]]
# name = "Office"
# host = "192.168.1.100"
# token = "OTHER_DEVICE_TOKEN"
# active = false
```

- [ ] **Step 7: Commit**

```bash
git add remote-ui/round/agent/ remote-ui/round/tests/ remote-ui/round/config.toml.example
git commit -m "feat(eye-agent): Add config module with TOML loader"
```

---

### Task 2: SecuBox HTTP Client

**Files:**
- Create: `remote-ui/round/agent/secubox_client.py`
- Test: `remote-ui/round/tests/test_secubox_client.py`

- [ ] **Step 1: Write failing test for SecuBox client**

```python
# remote-ui/round/tests/test_secubox_client.py
"""Tests for SecuBox HTTP client."""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

@pytest.fixture
def mock_response():
    """Create a mock aiohttp response."""
    response = AsyncMock()
    response.status = 200
    response.json = AsyncMock(return_value={
        "cpu_percent": 34.5,
        "mem_percent": 67.2,
        "disk_percent": 45.0,
        "wifi_rssi": -55,
        "load_avg_1": 0.82,
        "cpu_temp": 52.3,
        "uptime_seconds": 86400,
        "hostname": "secubox-lab",
        "modules_active": ["AUTH", "WALL", "BOOT"]
    })
    return response


@pytest.mark.asyncio
async def test_fetch_metrics_success(mock_response):
    """Should fetch and parse metrics from SecuBox API."""
    from agent.secubox_client import SecuBoxClient

    with patch('aiohttp.ClientSession.get', return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_response))):
        client = SecuBoxClient(host="10.55.0.1", token="test-token")
        metrics = await client.fetch_metrics()

        assert metrics["cpu_percent"] == 34.5
        assert metrics["hostname"] == "secubox-lab"
        assert "AUTH" in metrics["modules_active"]


@pytest.mark.asyncio
async def test_fetch_metrics_with_fallback():
    """Should try fallback host if primary fails."""
    from agent.secubox_client import SecuBoxClient

    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        call_count += 1

        cm = AsyncMock()
        if "10.55.0.1" in url:
            # Primary fails
            cm.__aenter__ = AsyncMock(side_effect=Exception("Connection refused"))
        else:
            # Fallback succeeds
            response = AsyncMock()
            response.status = 200
            response.json = AsyncMock(return_value={"cpu_percent": 50.0})
            cm.__aenter__ = AsyncMock(return_value=response)
        cm.__aexit__ = AsyncMock()
        return cm

    with patch('aiohttp.ClientSession.get', side_effect=mock_get):
        client = SecuBoxClient(
            host="10.55.0.1",
            token="test-token",
            fallback="secubox.local"
        )
        metrics = await client.fetch_metrics()

        assert metrics["cpu_percent"] == 50.0
        assert call_count >= 2  # Tried both hosts


@pytest.mark.asyncio
async def test_client_uses_bearer_token():
    """Should include device token in Authorization header."""
    from agent.secubox_client import SecuBoxClient

    captured_headers = {}

    async def mock_get(url, headers=None, **kwargs):
        nonlocal captured_headers
        captured_headers = headers or {}

        cm = AsyncMock()
        response = AsyncMock()
        response.status = 200
        response.json = AsyncMock(return_value={"cpu_percent": 10.0})
        cm.__aenter__ = AsyncMock(return_value=response)
        cm.__aexit__ = AsyncMock()
        return cm

    with patch('aiohttp.ClientSession.get', side_effect=mock_get):
        client = SecuBoxClient(host="10.55.0.1", token="my-secret-token")
        await client.fetch_metrics()

        assert "Authorization" in captured_headers
        assert captured_headers["Authorization"] == "Bearer my-secret-token"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_secubox_client.py -v`
Expected: FAIL with "No module named 'agent.secubox_client'"

- [ ] **Step 3: Write SecuBox client**

```python
# remote-ui/round/agent/secubox_client.py
"""
SecuBox Eye Remote — SecuBox HTTP Client
Async HTTP client for fetching metrics from SecuBox API.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

import aiohttp

log = logging.getLogger(__name__)

METRICS_ENDPOINT = "/api/v1/system/metrics"
HEALTH_ENDPOINT = "/api/v1/health"
DEFAULT_TIMEOUT = 5.0


@dataclass
class SecuBoxClient:
    """
    Async HTTP client for one SecuBox.

    Handles:
    - Token-based authentication
    - Automatic fallback to secondary host
    - Connection health checking
    """
    host: str
    token: str
    fallback: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT

    _session: Optional[aiohttp.ClientSession] = None
    _using_fallback: bool = False

    def __post_init__(self):
        self._using_fallback = False

    @property
    def current_host(self) -> str:
        """Return the currently active host."""
        if self._using_fallback and self.fallback:
            return self.fallback
        return self.host

    @property
    def base_url(self) -> str:
        """Return base URL for API calls."""
        host = self.current_host
        if not host.startswith("http"):
            host = f"http://{host}"
        if ":" not in host.split("//")[1]:
            host = f"{host}:8000"
        return host

    def _headers(self) -> dict:
        """Return request headers with auth token."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def fetch_metrics(self) -> dict:
        """
        Fetch system metrics from SecuBox.

        Returns:
            Dict with cpu_percent, mem_percent, disk_percent, etc.

        Raises:
            Exception if both primary and fallback fail
        """
        session = await self._get_session()

        # Try primary host
        try:
            self._using_fallback = False
            url = f"{self.base_url}{METRICS_ENDPOINT}"
            log.debug("Fetching metrics from %s", url)

            async with session.get(url, headers=self._headers()) as resp:
                if resp.status == 200:
                    return await resp.json()
                log.warning("Primary host returned %d", resp.status)
        except Exception as e:
            log.warning("Primary host failed: %s", e)

        # Try fallback if available
        if self.fallback:
            try:
                self._using_fallback = True
                url = f"{self.base_url}{METRICS_ENDPOINT}"
                log.debug("Trying fallback: %s", url)

                async with session.get(url, headers=self._headers()) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    log.warning("Fallback host returned %d", resp.status)
            except Exception as e:
                log.warning("Fallback host failed: %s", e)

        # Both failed
        raise ConnectionError(f"Cannot connect to SecuBox at {self.host} or {self.fallback}")

    async def check_health(self) -> bool:
        """
        Check if SecuBox API is reachable.

        Returns:
            True if healthy
        """
        session = await self._get_session()

        for using_fallback in [False, True]:
            if using_fallback and not self.fallback:
                continue

            self._using_fallback = using_fallback
            url = f"{self.base_url}{HEALTH_ENDPOINT}"

            try:
                async with session.get(url, headers=self._headers()) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass

        return False

    @property
    def transport(self) -> str:
        """Return transport type based on current host."""
        host = self.current_host
        if "10.55.0" in host:
            return "otg"
        return "wifi"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd remote-ui/round && python -m pytest tests/test_secubox_client.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/secubox_client.py remote-ui/round/tests/test_secubox_client.py
git commit -m "feat(eye-agent): Add async SecuBox HTTP client with fallback"
```

---

### Task 3: Metrics Bridge (Unix Socket Server)

**Files:**
- Create: `remote-ui/round/agent/metrics_bridge.py`
- Test: `remote-ui/round/tests/test_metrics_bridge.py`

- [ ] **Step 1: Write failing test for metrics bridge**

```python
# remote-ui/round/tests/test_metrics_bridge.py
"""Tests for metrics bridge Unix socket server."""
import pytest
import asyncio
import json
import tempfile
from pathlib import Path

@pytest.mark.asyncio
async def test_bridge_serves_metrics():
    """Bridge should serve metrics over Unix socket."""
    from agent.metrics_bridge import MetricsBridge

    with tempfile.TemporaryDirectory() as tmpdir:
        sock_path = Path(tmpdir) / "metrics.sock"

        bridge = MetricsBridge(socket_path=sock_path)

        # Update with test metrics
        bridge.update_metrics({
            "cpu_percent": 42.0,
            "hostname": "test-secubox"
        }, secubox_name="Test", transport="otg")

        # Start server
        server_task = asyncio.create_task(bridge.start())
        await asyncio.sleep(0.1)  # Let server start

        # Connect as client
        reader, writer = await asyncio.open_unix_connection(str(sock_path))

        # Read metrics
        data = await reader.read(4096)
        metrics = json.loads(data.decode())

        assert metrics["metrics"]["cpu_percent"] == 42.0
        assert metrics["secubox"]["name"] == "Test"
        assert metrics["secubox"]["transport"] == "otg"

        writer.close()
        await writer.wait_closed()

        # Cleanup
        bridge.stop()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


@pytest.mark.asyncio
async def test_bridge_handles_multiple_clients():
    """Bridge should handle multiple concurrent clients."""
    from agent.metrics_bridge import MetricsBridge

    with tempfile.TemporaryDirectory() as tmpdir:
        sock_path = Path(tmpdir) / "metrics.sock"

        bridge = MetricsBridge(socket_path=sock_path)
        bridge.update_metrics({"cpu_percent": 50.0}, "Lab", "wifi")

        server_task = asyncio.create_task(bridge.start())
        await asyncio.sleep(0.1)

        # Connect multiple clients
        async def read_metrics():
            reader, writer = await asyncio.open_unix_connection(str(sock_path))
            data = await reader.read(4096)
            writer.close()
            await writer.wait_closed()
            return json.loads(data.decode())

        results = await asyncio.gather(
            read_metrics(),
            read_metrics(),
            read_metrics()
        )

        for r in results:
            assert r["metrics"]["cpu_percent"] == 50.0

        bridge.stop()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_metrics_bridge.py -v`
Expected: FAIL with "No module named 'agent.metrics_bridge'"

- [ ] **Step 3: Write metrics bridge**

```python
# remote-ui/round/agent/metrics_bridge.py
"""
SecuBox Eye Remote — Metrics Bridge
Unix socket server that feeds metrics to the dashboard.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

DEFAULT_SOCKET_PATH = Path("/run/secubox-eye/metrics.sock")


@dataclass
class MetricsBridge:
    """
    Unix socket server for sharing metrics with dashboard.

    The dashboard connects and reads the latest metrics as JSON.
    Connection is stateless - each read gets current state.
    """
    socket_path: Path = DEFAULT_SOCKET_PATH

    _metrics: dict = field(default_factory=dict)
    _secubox_name: str = ""
    _secubox_host: str = ""
    _transport: str = "sim"
    _timestamp: str = ""
    _server: Optional[asyncio.Server] = None
    _running: bool = False

    def update_metrics(
        self,
        metrics: dict,
        secubox_name: str = "",
        transport: str = "sim",
        secubox_host: str = ""
    ):
        """
        Update the current metrics.

        Args:
            metrics: Dict with cpu_percent, mem_percent, etc.
            secubox_name: Name of the active SecuBox
            transport: Transport type (otg, wifi, sim)
            secubox_host: Host address
        """
        self._metrics = metrics
        self._secubox_name = secubox_name
        self._secubox_host = secubox_host
        self._transport = transport
        self._timestamp = datetime.utcnow().isoformat() + "Z"

    def get_payload(self) -> dict:
        """
        Get the full payload for clients.

        Returns:
            Dict with secubox info, metrics, and timestamp
        """
        return {
            "secubox": {
                "name": self._secubox_name,
                "host": self._secubox_host,
                "transport": self._transport,
            },
            "metrics": self._metrics,
            "alerts": {
                "global_level": "nominal",
                "items": []
            },
            "timestamp": self._timestamp,
        }

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Handle a client connection."""
        try:
            payload = self.get_payload()
            data = json.dumps(payload).encode()
            writer.write(data)
            await writer.drain()
        except Exception as e:
            log.debug("Client error: %s", e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        """Start the Unix socket server."""
        # Ensure directory exists
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove stale socket
        if self.socket_path.exists():
            self.socket_path.unlink()

        self._running = True
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self.socket_path)
        )

        # Set permissions (world-readable for dashboard)
        self.socket_path.chmod(0o666)

        log.info("Metrics bridge listening on %s", self.socket_path)

        async with self._server:
            await self._server.serve_forever()

    def stop(self):
        """Stop the server."""
        self._running = False
        if self._server:
            self._server.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd remote-ui/round && python -m pytest tests/test_metrics_bridge.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/metrics_bridge.py remote-ui/round/tests/test_metrics_bridge.py
git commit -m "feat(eye-agent): Add metrics bridge Unix socket server"
```

---

### Task 4: Device Manager (Multi-SecuBox)

**Files:**
- Create: `remote-ui/round/agent/device_manager.py`
- Test: `remote-ui/round/tests/test_device_manager.py`

- [ ] **Step 1: Write failing test for device manager**

```python
# remote-ui/round/tests/test_device_manager.py
"""Tests for multi-SecuBox device manager."""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from agent.config import Config, DeviceConfig, SecuBoxConfig


@pytest.fixture
def test_config():
    """Create test configuration with multiple SecuBoxes."""
    return Config(
        device=DeviceConfig(id="eye-test", name="Test Eye"),
        secuboxes=[
            SecuBoxConfig(name="Primary", host="10.55.0.1", token="token1", active=True),
            SecuBoxConfig(name="Secondary", host="192.168.1.100", token="token2", active=False),
        ]
    )


@pytest.mark.asyncio
async def test_manager_connects_to_active_secubox(test_config):
    """Manager should connect to the active SecuBox."""
    from agent.device_manager import DeviceManager

    with patch('agent.device_manager.SecuBoxClient') as MockClient:
        mock_instance = AsyncMock()
        mock_instance.fetch_metrics = AsyncMock(return_value={"cpu_percent": 30.0})
        mock_instance.check_health = AsyncMock(return_value=True)
        MockClient.return_value = mock_instance

        manager = DeviceManager(test_config)
        await manager.connect()

        # Should have connected to Primary
        assert manager.active_secubox.name == "Primary"
        MockClient.assert_called_with(
            host="10.55.0.1",
            token="token1",
            fallback=None
        )


@pytest.mark.asyncio
async def test_manager_switches_secubox(test_config):
    """Manager should switch between SecuBoxes."""
    from agent.device_manager import DeviceManager

    with patch('agent.device_manager.SecuBoxClient') as MockClient:
        mock_instance = AsyncMock()
        mock_instance.fetch_metrics = AsyncMock(return_value={"cpu_percent": 50.0})
        mock_instance.check_health = AsyncMock(return_value=True)
        mock_instance.close = AsyncMock()
        MockClient.return_value = mock_instance

        manager = DeviceManager(test_config)
        await manager.connect()

        assert manager.active_secubox.name == "Primary"

        # Switch to Secondary
        await manager.switch_to("Secondary")

        assert manager.active_secubox.name == "Secondary"


@pytest.mark.asyncio
async def test_manager_polls_metrics(test_config):
    """Manager should poll metrics at configured interval."""
    from agent.device_manager import DeviceManager

    call_count = 0

    with patch('agent.device_manager.SecuBoxClient') as MockClient:
        async def mock_fetch():
            nonlocal call_count
            call_count += 1
            return {"cpu_percent": float(call_count * 10)}

        mock_instance = AsyncMock()
        mock_instance.fetch_metrics = mock_fetch
        mock_instance.check_health = AsyncMock(return_value=True)
        mock_instance.transport = "otg"
        MockClient.return_value = mock_instance

        manager = DeviceManager(test_config)
        await manager.connect()

        # Poll a few times
        for _ in range(3):
            metrics = await manager.poll_metrics()
            await asyncio.sleep(0.01)

        assert call_count == 3


def test_manager_lists_secuboxes(test_config):
    """Manager should list all configured SecuBoxes."""
    from agent.device_manager import DeviceManager

    manager = DeviceManager(test_config)
    secuboxes = manager.list_secuboxes()

    assert len(secuboxes) == 2
    assert secuboxes[0]["name"] == "Primary"
    assert secuboxes[0]["active"] is True
    assert secuboxes[1]["name"] == "Secondary"
    assert secuboxes[1]["active"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd remote-ui/round && python -m pytest tests/test_device_manager.py -v`
Expected: FAIL with "No module named 'agent.device_manager'"

- [ ] **Step 3: Write device manager**

```python
# remote-ui/round/agent/device_manager.py
"""
SecuBox Eye Remote — Device Manager
Manages connections to multiple SecuBox appliances.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional, Callable

from .config import Config, SecuBoxConfig, get_active_secubox, set_active_secubox
from .secubox_client import SecuBoxClient

log = logging.getLogger(__name__)


@dataclass
class DeviceManager:
    """
    Manages connections to multiple SecuBox appliances.

    Handles:
    - Connecting to the active SecuBox
    - Switching between SecuBoxes
    - Polling metrics
    - Notifying listeners of metric updates
    """
    config: Config

    _client: Optional[SecuBoxClient] = None
    _active_config: Optional[SecuBoxConfig] = None
    _listeners: list[Callable] = None
    _last_metrics: dict = None

    def __post_init__(self):
        self._listeners = []
        self._last_metrics = {}
        self._active_config = get_active_secubox(self.config)

    @property
    def active_secubox(self) -> Optional[SecuBoxConfig]:
        """Return the active SecuBox configuration."""
        return self._active_config

    @property
    def transport(self) -> str:
        """Return current transport type."""
        if self._client:
            return self._client.transport
        return "sim"

    def list_secuboxes(self) -> list[dict]:
        """
        List all configured SecuBoxes.

        Returns:
            List of dicts with name, host, active status
        """
        return [
            {
                "name": sb.name,
                "host": sb.host,
                "active": sb.active,
            }
            for sb in self.config.secuboxes
        ]

    async def connect(self):
        """
        Connect to the active SecuBox.

        Creates HTTP client and verifies connectivity.
        """
        if not self._active_config:
            log.warning("No active SecuBox configured")
            return

        # Close existing client
        if self._client:
            await self._client.close()

        # Create new client
        self._client = SecuBoxClient(
            host=self._active_config.host,
            token=self._active_config.token,
            fallback=self._active_config.fallback,
        )

        # Check health
        healthy = await self._client.check_health()
        if healthy:
            log.info("Connected to %s via %s",
                     self._active_config.name, self._client.transport)
        else:
            log.warning("SecuBox %s not reachable", self._active_config.name)

    async def switch_to(self, name: str) -> bool:
        """
        Switch to a different SecuBox.

        Args:
            name: Name of SecuBox to switch to

        Returns:
            True if switch successful
        """
        # Find the target
        target = None
        for sb in self.config.secuboxes:
            if sb.name == name:
                target = sb
                break

        if not target:
            log.error("SecuBox '%s' not found", name)
            return False

        # Update active status
        set_active_secubox(self.config, name)
        self._active_config = target

        # Reconnect
        await self.connect()

        log.info("Switched to %s", name)
        return True

    async def poll_metrics(self) -> dict:
        """
        Poll metrics from the active SecuBox.

        Returns:
            Dict with metrics or empty dict on failure
        """
        if not self._client:
            return {}

        try:
            metrics = await self._client.fetch_metrics()
            self._last_metrics = metrics

            # Notify listeners
            for listener in self._listeners:
                try:
                    listener(metrics, self._active_config.name, self._client.transport)
                except Exception as e:
                    log.warning("Listener error: %s", e)

            return metrics
        except Exception as e:
            log.warning("Failed to poll metrics: %s", e)
            return self._last_metrics or {}

    def add_listener(self, callback: Callable[[dict, str, str], None]):
        """
        Add a metrics update listener.

        Args:
            callback: Function(metrics, secubox_name, transport)
        """
        self._listeners.append(callback)

    async def close(self):
        """Close all connections."""
        if self._client:
            await self._client.close()
            self._client = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd remote-ui/round && python -m pytest tests/test_device_manager.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add remote-ui/round/agent/device_manager.py remote-ui/round/tests/test_device_manager.py
git commit -m "feat(eye-agent): Add multi-SecuBox device manager"
```

---

### Task 5: Agent Main Entry Point

**Files:**
- Create: `remote-ui/round/agent/main.py`
- Create: `remote-ui/round/secubox-eye-agent`
- Create: `remote-ui/round/secubox-eye-agent.service`

- [ ] **Step 1: Write agent main module**

```python
# remote-ui/round/agent/main.py
"""
SecuBox Eye Remote — Agent Main
Entry point for the Eye Remote agent service.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path

from .config import load_config, DEFAULT_CONFIG_PATH
from .device_manager import DeviceManager
from .metrics_bridge import MetricsBridge

log = logging.getLogger(__name__)

# Default paths
SOCKET_PATH = Path("/run/secubox-eye/metrics.sock")
PID_FILE = Path("/run/secubox-eye/agent.pid")


class EyeAgent:
    """
    Main Eye Remote agent.

    Coordinates:
    - DeviceManager: SecuBox connections
    - MetricsBridge: Dashboard communication
    - Polling loop: Regular metrics updates
    """

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.config = None
        self.device_manager = None
        self.metrics_bridge = None
        self._running = False
        self._poll_task = None
        self._bridge_task = None

    async def start(self):
        """Start the agent."""
        log.info("Starting Eye Remote Agent v2.0.0")

        # Load config
        try:
            self.config = load_config(self.config_path)
            log.info("Loaded config: device=%s, secuboxes=%d",
                     self.config.device.id, len(self.config.secuboxes))
        except Exception as e:
            log.error("Failed to load config: %s", e)
            sys.exit(1)

        # Create components
        self.device_manager = DeviceManager(self.config)
        self.metrics_bridge = MetricsBridge(socket_path=SOCKET_PATH)

        # Wire up metrics updates
        self.device_manager.add_listener(self._on_metrics_update)

        # Connect to SecuBox
        await self.device_manager.connect()

        # Start services
        self._running = True
        self._bridge_task = asyncio.create_task(self.metrics_bridge.start())
        self._poll_task = asyncio.create_task(self._poll_loop())

        # Write PID file
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(asyncio.current_task().get_coro().cr_frame.f_locals.get('self', {}).get('_pid', 0)))

        log.info("Agent started")

        # Wait for shutdown
        await asyncio.gather(self._bridge_task, self._poll_task, return_exceptions=True)

    def _on_metrics_update(self, metrics: dict, secubox_name: str, transport: str):
        """Handle metrics update from device manager."""
        self.metrics_bridge.update_metrics(
            metrics=metrics,
            secubox_name=secubox_name,
            transport=transport,
            secubox_host=self.device_manager.active_secubox.host if self.device_manager.active_secubox else ""
        )

    async def _poll_loop(self):
        """Main polling loop."""
        while self._running:
            try:
                await self.device_manager.poll_metrics()
            except Exception as e:
                log.warning("Poll error: %s", e)

            # Get poll interval from active config
            interval = 2.0
            if self.device_manager.active_secubox:
                interval = self.device_manager.active_secubox.poll_interval

            await asyncio.sleep(interval)

    async def stop(self):
        """Stop the agent."""
        log.info("Stopping agent...")
        self._running = False

        if self._poll_task:
            self._poll_task.cancel()

        self.metrics_bridge.stop()

        if self._bridge_task:
            self._bridge_task.cancel()

        await self.device_manager.close()

        # Remove PID file
        if PID_FILE.exists():
            PID_FILE.unlink()

        log.info("Agent stopped")


async def main():
    """Main entry point."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Parse args
    config_path = DEFAULT_CONFIG_PATH
    if len(sys.argv) > 1:
        config_path = Path(sys.argv[1])

    agent = EyeAgent(config_path)

    # Handle signals
    loop = asyncio.get_running_loop()

    def handle_signal():
        asyncio.create_task(agent.stop())

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, handle_signal)

    await agent.start()


def run():
    """Run the agent."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Create executable wrapper**

```python
#!/usr/bin/env python3
# remote-ui/round/secubox-eye-agent
"""SecuBox Eye Remote Agent executable."""
from agent.main import run

if __name__ == "__main__":
    run()
```

- [ ] **Step 3: Create systemd service**

```ini
# remote-ui/round/secubox-eye-agent.service
[Unit]
Description=SecuBox Eye Remote Agent
After=network.target pigpiod.service
Wants=pigpiod.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /usr/lib/secubox-eye/agent/main.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Runtime directory
RuntimeDirectory=secubox-eye
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 4: Commit**

```bash
git add remote-ui/round/agent/main.py remote-ui/round/secubox-eye-agent remote-ui/round/secubox-eye-agent.service
chmod +x remote-ui/round/secubox-eye-agent
git commit -m "feat(eye-agent): Add main entry point and systemd service"
```

---

### Task 6: Update Dashboard to Read from Agent

**Files:**
- Modify: `remote-ui/round/fb_dashboard.py`

- [ ] **Step 1: Update fb_dashboard.py to read from Unix socket**

```python
# Add to remote-ui/round/fb_dashboard.py after the imports

import socket as sock_module

AGENT_SOCKET = '/run/secubox-eye/metrics.sock'


class AgentMetricsSource:
    """Fetch metrics from Eye Agent via Unix socket."""

    def __init__(self):
        self.mode = 'SIM'
        self.sim = SimulatedMetrics()
        self._last_data = None

    def _read_from_socket(self) -> dict:
        """Read metrics from agent Unix socket."""
        try:
            s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect(AGENT_SOCKET)
            data = s.recv(8192)
            s.close()
            return json.loads(data.decode())
        except Exception as e:
            return None

    def get_metrics(self):
        """Get current metrics from agent or simulation."""
        data = self._read_from_socket()

        if data and 'metrics' in data:
            self._last_data = data
            transport = data.get('secubox', {}).get('transport', 'SIM')
            mode = transport.upper() if transport in ('otg', 'wifi') else 'SIM'
            self.mode = mode

            metrics = data['metrics']
            # Map API fields to dashboard fields
            return {
                'cpu': metrics.get('cpu_percent', 0),
                'mem': metrics.get('mem_percent', 0),
                'disk': metrics.get('disk_percent', 0),
                'load': metrics.get('load_avg_1', 0),
                'temp': metrics.get('cpu_temp', 0),
                'wifi': metrics.get('wifi_rssi', -80),
                'uptime': metrics.get('uptime_seconds', 0),
                'hostname': metrics.get('hostname', 'secubox'),
            }, mode

        # Fallback to simulation
        self.mode = 'SIM'
        return self.sim.update(), 'SIM'
```

- [ ] **Step 2: Update main() to use AgentMetricsSource**

Replace in `main()`:
```python
def main():
    print('SecuBox Eye Remote - Framebuffer Dashboard')
    print(f'Display: {WIDTH}x{HEIGHT}')
    print('Press Ctrl+C to exit')

    # Try agent first, fall back to direct API
    if os.path.exists(AGENT_SOCKET):
        print('Using Eye Agent for metrics')
        source = AgentMetricsSource()
    else:
        print('Agent not running, using direct API')
        source = MetricsSource()

    while True:
        try:
            metrics, mode = source.get_metrics()
            img = draw_dashboard(metrics, mode)
            write_to_fb(img)
            time.sleep(1)
        except KeyboardInterrupt:
            print('\nExiting...')
            break
        except Exception as e:
            print(f'Error: {e}')
            time.sleep(1)
```

- [ ] **Step 3: Commit**

```bash
git add remote-ui/round/fb_dashboard.py
git commit -m "feat(dashboard): Add Unix socket support for agent metrics"
```

---

## Phase 2: SecuBox Module — Device Registry & API

### Task 7: Create SecuBox Module Skeleton

**Files:**
- Create: `packages/secubox-eye-remote/api/__init__.py`
- Create: `packages/secubox-eye-remote/api/main.py`
- Create: `packages/secubox-eye-remote/core/__init__.py`
- Create: `packages/secubox-eye-remote/models/__init__.py`
- Create: `packages/secubox-eye-remote/models/device.py`

- [ ] **Step 1: Create package directories**

```bash
mkdir -p packages/secubox-eye-remote/{api/routers,core,models,www/js,debian,nginx,menu.d,tests}
```

- [ ] **Step 2: Create Pydantic models**

```python
# packages/secubox-eye-remote/models/__init__.py
"""SecuBox Eye Remote — Pydantic models."""
from .device import *
```

```python
# packages/secubox-eye-remote/models/device.py
"""
SecuBox Eye Remote — Device Models
Pydantic models for Eye Remote device management.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TransportType(str, Enum):
    """Transport types for Eye Remote connection."""
    OTG = "otg"
    WIFI = "wifi"
    NONE = "none"


class DeviceCapability(str, Enum):
    """Capabilities an Eye Remote device can have."""
    SCREENSHOT = "screenshot"
    REBOOT = "reboot"
    OTA = "ota"
    SERIAL = "serial"


class DeviceScope(str, Enum):
    """Permission scopes for Eye Remote devices."""
    METRICS_READ = "metrics:read"
    SERVICES_RESTART = "services:restart"
    OTG_CONTROL = "otg:control"
    ALERTS_DISMISS = "alerts:dismiss"
    SYSTEM_LOCKDOWN = "system:lockdown"
    SYSTEM_REBOOT = "system:reboot"


class PairedDevice(BaseModel):
    """A paired Eye Remote device."""
    device_id: str = Field(..., description="Unique device identifier")
    name: str = Field(..., description="User-friendly device name")
    token_hash: str = Field(..., description="SHA256 hash of device token")
    paired_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None
    transport: TransportType = TransportType.NONE
    firmware: str = "unknown"
    capabilities: list[DeviceCapability] = Field(default_factory=list)
    scopes: list[DeviceScope] = Field(default_factory=lambda: [DeviceScope.METRICS_READ])
    ssh_pubkey: Optional[str] = None
    ssh_enabled: bool = False


class DeviceListResponse(BaseModel):
    """Response for listing devices."""
    devices: list[PairedDevice]
    count: int


class PairRequest(BaseModel):
    """Request to pair a new device."""
    device_id: str
    name: str = "Eye Remote"
    pubkey: Optional[str] = None
    capabilities: list[DeviceCapability] = Field(default_factory=list)


class PairResponse(BaseModel):
    """Response after successful pairing."""
    success: bool
    device_id: str
    token: str = Field(..., description="Device token (only returned once)")
    ssh_user: Optional[str] = None
    ssh_port: int = 22


class CommandRequest(BaseModel):
    """Request to send command to Eye Remote."""
    cmd: str = Field(..., description="Command: screenshot, reboot, config_update, ota_update")
    params: dict = Field(default_factory=dict)


class CommandResponse(BaseModel):
    """Response from command execution."""
    success: bool
    request_id: str
    data: Optional[dict] = None
    error: Optional[str] = None
```

- [ ] **Step 3: Create core __init__**

```python
# packages/secubox-eye-remote/core/__init__.py
"""SecuBox Eye Remote — Core modules."""
```

- [ ] **Step 4: Create API __init__**

```python
# packages/secubox-eye-remote/api/__init__.py
"""SecuBox Eye Remote — FastAPI application."""
```

- [ ] **Step 5: Create FastAPI main app**

```python
# packages/secubox-eye-remote/api/main.py
"""
SecuBox Eye Remote — FastAPI Application
Management API for Eye Remote devices.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

app = FastAPI(
    title="SecuBox Eye Remote",
    description="Management API for Eye Remote devices",
    version="2.0.0",
)

# CORS for WebUI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files (WebUI)
www_path = Path(__file__).parent.parent / "www"
if www_path.exists():
    app.mount("/static", StaticFiles(directory=str(www_path)), name="static")


@app.get("/api/v1/eye-remote/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "module": "secubox-eye-remote", "version": "2.0.0"}


# Import routers (added in later tasks)
# from .routers import devices, pairing, metrics, websocket
# app.include_router(devices.router, prefix="/api/v1/eye-remote")
# app.include_router(pairing.router, prefix="/api/v1/eye-remote")
# app.include_router(metrics.router, prefix="/api/v1/eye-remote")
# app.include_router(websocket.router, prefix="/api/v1/eye-remote")
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-eye-remote/
git commit -m "feat(secubox-eye-remote): Create module skeleton with models"
```

---

### Task 8: Device Registry

**Files:**
- Create: `packages/secubox-eye-remote/core/device_registry.py`
- Test: `packages/secubox-eye-remote/tests/test_device_registry.py`

- [ ] **Step 1: Write failing test**

```python
# packages/secubox-eye-remote/tests/test_device_registry.py
"""Tests for device registry."""
import pytest
import tempfile
from pathlib import Path

def test_registry_add_device():
    """Should add a device to registry."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice, DeviceScope

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        device = PairedDevice(
            device_id="eye-001",
            name="Test Eye",
            token_hash="sha256:abc123",
            scopes=[DeviceScope.METRICS_READ]
        )

        registry.add_device(device)

        retrieved = registry.get_device("eye-001")
        assert retrieved is not None
        assert retrieved.name == "Test Eye"


def test_registry_persists_to_file():
    """Registry should persist devices to JSON file."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice

    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir) / "devices.json"

        # Create and save
        registry1 = DeviceRegistry(storage_path=storage_path)
        registry1.add_device(PairedDevice(
            device_id="eye-002",
            name="Persisted Eye",
            token_hash="sha256:def456"
        ))

        # Load in new instance
        registry2 = DeviceRegistry(storage_path=storage_path)

        device = registry2.get_device("eye-002")
        assert device is not None
        assert device.name == "Persisted Eye"


def test_registry_remove_device():
    """Should remove a device from registry."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        registry.add_device(PairedDevice(
            device_id="eye-003",
            name="To Remove",
            token_hash="sha256:ghi789"
        ))

        assert registry.get_device("eye-003") is not None

        registry.remove_device("eye-003")

        assert registry.get_device("eye-003") is None


def test_registry_update_last_seen():
    """Should update device last_seen timestamp."""
    from core.device_registry import DeviceRegistry
    from models.device import PairedDevice
    from datetime import datetime

    with tempfile.TemporaryDirectory() as tmpdir:
        registry = DeviceRegistry(storage_path=Path(tmpdir) / "devices.json")

        registry.add_device(PairedDevice(
            device_id="eye-004",
            name="Active Eye",
            token_hash="sha256:jkl012"
        ))

        before = registry.get_device("eye-004").last_seen

        registry.update_last_seen("eye-004", transport="otg")

        after = registry.get_device("eye-004")
        assert after.last_seen is not None
        assert after.transport.value == "otg"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-eye-remote && python -m pytest tests/test_device_registry.py -v`
Expected: FAIL

- [ ] **Step 3: Write device registry**

```python
# packages/secubox-eye-remote/core/device_registry.py
"""
SecuBox Eye Remote — Device Registry
Manages paired Eye Remote devices.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Optional

from models.device import PairedDevice, TransportType

log = logging.getLogger(__name__)

DEFAULT_STORAGE_PATH = Path("/var/lib/secubox/eye-remote/devices.json")


class DeviceRegistry:
    """
    Registry for paired Eye Remote devices.

    Stores device info in a JSON file.
    Thread-safe for concurrent access.
    """

    def __init__(self, storage_path: Path = DEFAULT_STORAGE_PATH):
        self.storage_path = storage_path
        self._devices: dict[str, PairedDevice] = {}
        self._lock = Lock()
        self._load()

    def _load(self):
        """Load devices from storage file."""
        if not self.storage_path.exists():
            return

        try:
            with open(self.storage_path) as f:
                data = json.load(f)

            for device_id, device_data in data.items():
                self._devices[device_id] = PairedDevice(**device_data)

            log.info("Loaded %d devices from registry", len(self._devices))
        except Exception as e:
            log.error("Failed to load device registry: %s", e)

    def _save(self):
        """Save devices to storage file."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            device_id: device.model_dump(mode='json')
            for device_id, device in self._devices.items()
        }

        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def add_device(self, device: PairedDevice):
        """
        Add or update a device in the registry.

        Args:
            device: Device to add
        """
        with self._lock:
            self._devices[device.device_id] = device
            self._save()
            log.info("Added device: %s", device.device_id)

    def get_device(self, device_id: str) -> Optional[PairedDevice]:
        """
        Get a device by ID.

        Args:
            device_id: Device identifier

        Returns:
            Device or None if not found
        """
        with self._lock:
            return self._devices.get(device_id)

    def remove_device(self, device_id: str) -> bool:
        """
        Remove a device from the registry.

        Args:
            device_id: Device to remove

        Returns:
            True if device was removed
        """
        with self._lock:
            if device_id in self._devices:
                del self._devices[device_id]
                self._save()
                log.info("Removed device: %s", device_id)
                return True
            return False

    def list_devices(self) -> list[PairedDevice]:
        """
        List all paired devices.

        Returns:
            List of all devices
        """
        with self._lock:
            return list(self._devices.values())

    def update_last_seen(
        self,
        device_id: str,
        transport: str = "none"
    ):
        """
        Update a device's last_seen timestamp.

        Args:
            device_id: Device to update
            transport: Current transport type
        """
        with self._lock:
            device = self._devices.get(device_id)
            if device:
                device.last_seen = datetime.utcnow()
                device.transport = TransportType(transport)
                self._save()

    def validate_token(self, device_id: str, token_hash: str) -> bool:
        """
        Validate a device token.

        Args:
            device_id: Device ID
            token_hash: SHA256 hash of token to validate

        Returns:
            True if token is valid
        """
        with self._lock:
            device = self._devices.get(device_id)
            if device and device.token_hash == token_hash:
                return True
            return False


# Singleton instance
_registry: Optional[DeviceRegistry] = None


def get_device_registry() -> DeviceRegistry:
    """Get the global device registry instance."""
    global _registry
    if _registry is None:
        _registry = DeviceRegistry()
    return _registry
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-eye-remote && python -m pytest tests/test_device_registry.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-remote/core/device_registry.py packages/secubox-eye-remote/tests/
git commit -m "feat(secubox-eye-remote): Add device registry with JSON persistence"
```

---

### Task 9: Token Manager

**Files:**
- Create: `packages/secubox-eye-remote/core/token_manager.py`
- Test: `packages/secubox-eye-remote/tests/test_token_manager.py`

- [ ] **Step 1: Write failing test**

```python
# packages/secubox-eye-remote/tests/test_token_manager.py
"""Tests for token manager."""
import pytest

def test_generate_device_token():
    """Should generate a secure device token."""
    from core.token_manager import generate_device_token

    token = generate_device_token("eye-001")

    assert token is not None
    assert len(token) >= 32  # At least 32 chars
    assert "eye-001" not in token  # Token should not contain device ID


def test_hash_token():
    """Should hash token with SHA256."""
    from core.token_manager import hash_token

    token = "my-secret-token"
    hashed = hash_token(token)

    assert hashed.startswith("sha256:")
    assert len(hashed) > 10


def test_verify_token():
    """Should verify token against hash."""
    from core.token_manager import hash_token, verify_token

    token = "test-token-12345"
    hashed = hash_token(token)

    assert verify_token(token, hashed) is True
    assert verify_token("wrong-token", hashed) is False


def test_generate_pairing_code():
    """Should generate a 6-char pairing code."""
    from core.token_manager import generate_pairing_code

    code = generate_pairing_code()

    assert len(code) == 7  # Format: XXX-XXX
    assert "-" in code
    assert code.replace("-", "").isalnum()


def test_pairing_codes_are_unique():
    """Generated pairing codes should be unique."""
    from core.token_manager import generate_pairing_code

    codes = [generate_pairing_code() for _ in range(100)]
    unique_codes = set(codes)

    # Should have very few (ideally 0) collisions
    assert len(unique_codes) >= 95
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-eye-remote && python -m pytest tests/test_token_manager.py -v`
Expected: FAIL

- [ ] **Step 3: Write token manager**

```python
# packages/secubox-eye-remote/core/token_manager.py
"""
SecuBox Eye Remote — Token Manager
Handles device token generation and validation.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import hashlib
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional

# Pairing code alphabet (no confusing chars like 0/O, 1/l/I)
PAIRING_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def generate_device_token(device_id: str) -> str:
    """
    Generate a secure device token.

    Args:
        device_id: Device identifier (not included in token)

    Returns:
        Random 48-character token
    """
    return secrets.token_urlsafe(36)


def hash_token(token: str) -> str:
    """
    Hash a token with SHA256.

    Args:
        token: Token to hash

    Returns:
        Hash in format "sha256:<hex>"
    """
    h = hashlib.sha256(token.encode()).hexdigest()
    return f"sha256:{h}"


def verify_token(token: str, token_hash: str) -> bool:
    """
    Verify a token against its hash.

    Args:
        token: Token to verify
        token_hash: Expected hash

    Returns:
        True if token matches hash
    """
    computed = hash_token(token)
    return secrets.compare_digest(computed, token_hash)


def generate_pairing_code() -> str:
    """
    Generate a 6-character pairing code.

    Format: XXX-XXX (e.g., "A7X-K9M")

    Returns:
        Pairing code string
    """
    chars = ''.join(secrets.choice(PAIRING_ALPHABET) for _ in range(6))
    return f"{chars[:3]}-{chars[3:]}"


class PairingSession:
    """
    Temporary pairing session.

    Tracks pairing codes and their expiry.
    """

    def __init__(self, ttl_minutes: int = 5):
        self.ttl = timedelta(minutes=ttl_minutes)
        self._sessions: dict[str, dict] = {}

    def create(self, secubox_host: str) -> dict:
        """
        Create a new pairing session.

        Args:
            secubox_host: Host address to include in pairing info

        Returns:
            Dict with code, url, expires_at
        """
        code = generate_pairing_code()
        expires_at = datetime.utcnow() + self.ttl

        session = {
            "code": code,
            "host": secubox_host,
            "expires_at": expires_at,
            "url": f"secubox://{secubox_host}/pair?code={code}",
        }

        self._sessions[code] = session
        return session

    def validate(self, code: str) -> Optional[dict]:
        """
        Validate a pairing code.

        Args:
            code: Pairing code to validate

        Returns:
            Session dict if valid, None if expired or invalid
        """
        session = self._sessions.get(code)
        if not session:
            return None

        if datetime.utcnow() > session["expires_at"]:
            del self._sessions[code]
            return None

        return session

    def consume(self, code: str) -> Optional[dict]:
        """
        Validate and consume a pairing code (one-time use).

        Args:
            code: Pairing code

        Returns:
            Session dict if valid
        """
        session = self.validate(code)
        if session:
            del self._sessions[code]
        return session

    def cleanup(self):
        """Remove expired sessions."""
        now = datetime.utcnow()
        expired = [
            code for code, session in self._sessions.items()
            if now > session["expires_at"]
        ]
        for code in expired:
            del self._sessions[code]


# Singleton pairing session manager
_pairing_session: Optional[PairingSession] = None


def get_pairing_session() -> PairingSession:
    """Get the global pairing session manager."""
    global _pairing_session
    if _pairing_session is None:
        _pairing_session = PairingSession()
    return _pairing_session
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-eye-remote && python -m pytest tests/test_token_manager.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-eye-remote/core/token_manager.py packages/secubox-eye-remote/tests/test_token_manager.py
git commit -m "feat(secubox-eye-remote): Add token manager with pairing codes"
```

---

### Task 10: API Routers (Devices, Pairing, Metrics)

**Files:**
- Create: `packages/secubox-eye-remote/api/routers/__init__.py`
- Create: `packages/secubox-eye-remote/api/routers/devices.py`
- Create: `packages/secubox-eye-remote/api/routers/pairing.py`
- Create: `packages/secubox-eye-remote/api/routers/metrics.py`

- [ ] **Step 1: Create routers __init__**

```python
# packages/secubox-eye-remote/api/routers/__init__.py
"""SecuBox Eye Remote — API Routers."""
from . import devices, pairing, metrics
```

- [ ] **Step 2: Create devices router**

```python
# packages/secubox-eye-remote/api/routers/devices.py
"""
SecuBox Eye Remote — Devices Router
Device management endpoints.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Depends

from secubox_core.auth import require_jwt
from core.device_registry import get_device_registry
from models.device import DeviceListResponse, PairedDevice

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=DeviceListResponse)
async def list_devices(user=Depends(require_jwt)):
    """List all paired Eye Remote devices."""
    registry = get_device_registry()
    devices = registry.list_devices()
    return DeviceListResponse(devices=devices, count=len(devices))


@router.get("/{device_id}", response_model=PairedDevice)
async def get_device(device_id: str, user=Depends(require_jwt)):
    """Get details of a specific device."""
    registry = get_device_registry()
    device = registry.get_device(device_id)
    if not device:
        raise HTTPException(404, f"Device {device_id} not found")
    return device


@router.delete("/{device_id}")
async def unpair_device(device_id: str, user=Depends(require_jwt)):
    """Unpair (remove) a device."""
    registry = get_device_registry()
    if registry.remove_device(device_id):
        return {"success": True, "message": f"Device {device_id} unpaired"}
    raise HTTPException(404, f"Device {device_id} not found")
```

- [ ] **Step 3: Create pairing router**

```python
# packages/secubox-eye-remote/api/routers/pairing.py
"""
SecuBox Eye Remote — Pairing Router
Device pairing endpoints.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import socket
from fastapi import APIRouter, HTTPException, Request

from core.device_registry import get_device_registry
from core.token_manager import (
    generate_device_token,
    hash_token,
    get_pairing_session,
)
from models.device import (
    PairRequest,
    PairResponse,
    PairedDevice,
    DeviceCapability,
    DeviceScope,
)

router = APIRouter(prefix="/pair", tags=["pairing"])


def get_local_ip() -> str:
    """Get local IP address for pairing URL."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "10.55.0.1"


@router.get("/qr")
async def generate_pairing_qr(request: Request):
    """
    Generate a pairing QR code / URL.

    Returns pairing info that can be encoded in a QR code.
    """
    pairing = get_pairing_session()
    host = get_local_ip()

    session = pairing.create(host)

    return {
        "code": session["code"],
        "url": session["url"],
        "host": host,
        "expires_in": 300,  # 5 minutes
        "qr_content": session["url"],
    }


@router.get("/discover")
async def discover():
    """
    Discovery endpoint for Eye Remote.

    Returns SecuBox info without authentication.
    """
    return {
        "name": socket.gethostname(),
        "version": "2.0.0",
        "api_version": "v1",
        "eye_remote_supported": True,
    }


@router.post("", response_model=PairResponse)
async def pair_device(request: PairRequest):
    """
    Complete device pairing.

    Called by Eye Remote after scanning QR code.
    """
    registry = get_device_registry()

    # Check if device already paired
    existing = registry.get_device(request.device_id)
    if existing:
        raise HTTPException(400, f"Device {request.device_id} already paired")

    # Generate token
    token = generate_device_token(request.device_id)
    token_hash = hash_token(token)

    # Default scopes
    scopes = [DeviceScope.METRICS_READ]
    if DeviceCapability.REBOOT in request.capabilities:
        scopes.append(DeviceScope.SERVICES_RESTART)

    # Create device record
    device = PairedDevice(
        device_id=request.device_id,
        name=request.name,
        token_hash=token_hash,
        capabilities=request.capabilities,
        scopes=scopes,
        ssh_pubkey=request.pubkey,
        ssh_enabled=request.pubkey is not None,
    )

    registry.add_device(device)

    # TODO: If pubkey provided, add to authorized_keys

    return PairResponse(
        success=True,
        device_id=request.device_id,
        token=token,  # Only returned once!
        ssh_user=f"eye-{request.device_id[:8]}" if request.pubkey else None,
    )
```

- [ ] **Step 4: Create metrics router**

```python
# packages/secubox-eye-remote/api/routers/metrics.py
"""
SecuBox Eye Remote — Metrics Router
Metrics endpoint for Eye Remote devices.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import hashlib
from fastapi import APIRouter, HTTPException, Header
from typing import Optional

from core.device_registry import get_device_registry
from core.token_manager import hash_token

# Import system metrics from secubox-system
try:
    from secubox_core.system import get_system_metrics
except ImportError:
    # Fallback for standalone testing
    async def get_system_metrics():
        return {
            "cpu_percent": 25.0,
            "mem_percent": 50.0,
            "disk_percent": 30.0,
            "wifi_rssi": -60,
            "load_avg_1": 0.5,
            "cpu_temp": 45.0,
            "uptime_seconds": 3600,
            "hostname": "secubox-dev",
            "modules_active": ["AUTH", "WALL", "BOOT"],
        }

router = APIRouter(tags=["metrics"])


def validate_device_token(authorization: str) -> str:
    """
    Validate device token from Authorization header.

    Returns device_id if valid.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")

    token = authorization[7:]
    token_hash = hash_token(token)

    registry = get_device_registry()

    # Find device with matching token
    for device in registry.list_devices():
        if device.token_hash == token_hash:
            # Update last seen
            registry.update_last_seen(device.device_id, transport="unknown")
            return device.device_id

    raise HTTPException(401, "Invalid device token")


@router.get("/metrics")
async def get_metrics(authorization: Optional[str] = Header(None)):
    """
    Get system metrics for Eye Remote.

    Requires valid device token in Authorization header.
    """
    device_id = validate_device_token(authorization)

    metrics = await get_system_metrics()

    return metrics
```

- [ ] **Step 5: Update main.py to include routers**

```python
# Update packages/secubox-eye-remote/api/main.py
# Add after the static files mount:

from .routers import devices, pairing, metrics

app.include_router(devices.router, prefix="/api/v1/eye-remote")
app.include_router(pairing.router, prefix="/api/v1/eye-remote")
app.include_router(metrics.router, prefix="/api/v1/eye-remote")
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-eye-remote/api/
git commit -m "feat(secubox-eye-remote): Add API routers for devices, pairing, metrics"
```

---

## Phase 3: Gateway/Emulator Tool

### Task 11: Gateway CLI and Emulator

**Files:**
- Create: `tools/secubox-eye-gateway/gateway/__init__.py`
- Create: `tools/secubox-eye-gateway/gateway/main.py`
- Create: `tools/secubox-eye-gateway/gateway/emulator.py`
- Create: `tools/secubox-eye-gateway/gateway/profiles.py`
- Create: `tools/secubox-eye-gateway/gateway/server.py`
- Create: `tools/secubox-eye-gateway/setup.py`
- Create: `tools/secubox-eye-gateway/requirements.txt`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p tools/secubox-eye-gateway/gateway
```

- [ ] **Step 2: Create profiles module**

```python
# tools/secubox-eye-gateway/gateway/profiles.py
"""
SecuBox Eye Gateway — Emulation Profiles
Predefined metric profiles for emulation mode.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Tuple, List

PROFILES = {
    "idle": {
        "cpu": (5, 15),
        "mem": (20, 35),
        "disk": (20, 30),
        "temp": (38, 45),
        "load": (0.1, 0.3),
        "wifi": (-45, -35),
        "alerts": [],
    },
    "normal": {
        "cpu": (20, 45),
        "mem": (40, 60),
        "disk": (30, 50),
        "temp": (45, 55),
        "load": (0.3, 1.0),
        "wifi": (-55, -45),
        "alerts": [],
    },
    "busy": {
        "cpu": (60, 85),
        "mem": (70, 85),
        "disk": (50, 70),
        "temp": (55, 68),
        "load": (1.5, 3.0),
        "wifi": (-65, -50),
        "alerts": ["warn:cpu", "warn:mem"],
    },
    "stressed": {
        "cpu": (85, 99),
        "mem": (90, 98),
        "disk": (80, 95),
        "temp": (70, 82),
        "load": (3.0, 6.0),
        "wifi": (-75, -60),
        "alerts": ["crit:cpu", "crit:mem", "warn:temp"],
    },
}


@dataclass
class EmulatedMetrics:
    """Emulated metrics with realistic drift."""

    profile: str = "normal"
    _cpu: float = 30.0
    _mem: float = 50.0
    _disk: float = 40.0
    _temp: float = 50.0
    _load: float = 0.5
    _wifi: int = -50
    _uptime: int = 0

    def _drift(self, current: float, range_tuple: Tuple[float, float], step: float = 2.0) -> float:
        """Add realistic drift to a value."""
        low, high = range_tuple
        delta = random.uniform(-step, step)
        new_val = current + delta
        return max(low, min(high, new_val))

    def update(self) -> dict:
        """Generate next metrics with drift."""
        p = PROFILES.get(self.profile, PROFILES["normal"])

        self._cpu = self._drift(self._cpu, p["cpu"])
        self._mem = self._drift(self._mem, p["mem"], 1.0)
        self._disk = self._drift(self._disk, p["disk"], 0.1)
        self._temp = self._drift(self._temp, p["temp"], 0.5)
        self._load = self._drift(self._load, p["load"], 0.1)
        self._wifi = int(self._drift(float(self._wifi), p["wifi"], 2.0))
        self._uptime += 1

        return {
            "cpu_percent": round(self._cpu, 1),
            "mem_percent": round(self._mem, 1),
            "disk_percent": round(self._disk, 1),
            "cpu_temp": round(self._temp, 1),
            "load_avg_1": round(self._load, 2),
            "wifi_rssi": self._wifi,
            "uptime_seconds": self._uptime,
            "hostname": f"secubox-{self.profile}",
            "secubox_version": "2.0.0-emulated",
            "modules_active": ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"],
        }
```

- [ ] **Step 3: Create emulator module**

```python
# tools/secubox-eye-gateway/gateway/emulator.py
"""
SecuBox Eye Gateway — Emulator
Emulates SecuBox API for local development.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from .profiles import EmulatedMetrics


class SecuBoxEmulator:
    """
    Emulates a SecuBox instance.

    Provides fake metrics with configurable profile.
    """

    def __init__(self, name: str, profile: str = "normal"):
        self.name = name
        self.profile = profile
        self._metrics = EmulatedMetrics(profile=profile)

    def get_metrics(self) -> dict:
        """Get current emulated metrics."""
        metrics = self._metrics.update()
        metrics["hostname"] = self.name
        return metrics

    def get_health(self) -> dict:
        """Get health status."""
        return {"status": "ok", "emulated": True}
```

- [ ] **Step 4: Create server module**

```python
# tools/secubox-eye-gateway/gateway/server.py
"""
SecuBox Eye Gateway — FastAPI Server
Serves emulated or proxied SecuBox API.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

from .emulator import SecuBoxEmulator

app = FastAPI(
    title="SecuBox Eye Gateway",
    description="Development gateway for Eye Remote",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global emulator instance (set by CLI)
_emulator: Optional[SecuBoxEmulator] = None


def set_emulator(emulator: SecuBoxEmulator):
    """Set the active emulator."""
    global _emulator
    _emulator = emulator


@app.get("/api/v1/health")
async def health():
    """Health check endpoint."""
    if _emulator:
        return _emulator.get_health()
    return {"status": "ok"}


@app.get("/api/v1/system/metrics")
async def get_metrics():
    """Get system metrics (emulated or proxied)."""
    if not _emulator:
        raise HTTPException(500, "No emulator configured")
    return _emulator.get_metrics()


@app.get("/api/v1/eye-remote/metrics")
async def get_eye_metrics():
    """Eye Remote metrics endpoint."""
    if not _emulator:
        raise HTTPException(500, "No emulator configured")
    return _emulator.get_metrics()


@app.get("/api/v1/eye-remote/discover")
async def discover():
    """Discovery endpoint."""
    name = _emulator.name if _emulator else "secubox-gateway"
    return {
        "name": name,
        "version": "2.0.0",
        "api_version": "v1",
        "eye_remote_supported": True,
        "emulated": True,
    }
```

- [ ] **Step 5: Create main CLI**

```python
# tools/secubox-eye-gateway/gateway/main.py
"""
SecuBox Eye Gateway — CLI Entry Point
Development gateway for Eye Remote.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""
from __future__ import annotations

import click
import uvicorn

from .emulator import SecuBoxEmulator
from .server import app, set_emulator


@click.command()
@click.option("--port", "-p", default=8000, help="Port to listen on")
@click.option("--host", "-h", default="0.0.0.0", help="Host to bind to")
@click.option("--name", "-n", default="secubox-dev", help="Emulated SecuBox name")
@click.option(
    "--profile",
    type=click.Choice(["idle", "normal", "busy", "stressed"]),
    default="normal",
    help="Emulation profile"
)
def main(port: int, host: str, name: str, profile: str):
    """
    SecuBox Eye Gateway - Development server for Eye Remote.

    Emulates SecuBox API for local testing.
    """
    click.echo(f"Starting SecuBox Eye Gateway")
    click.echo(f"  Name: {name}")
    click.echo(f"  Profile: {profile}")
    click.echo(f"  Listening on {host}:{port}")
    click.echo()
    click.echo("Endpoints:")
    click.echo(f"  GET http://{host}:{port}/api/v1/health")
    click.echo(f"  GET http://{host}:{port}/api/v1/system/metrics")
    click.echo(f"  GET http://{host}:{port}/api/v1/eye-remote/discover")
    click.echo()

    # Create emulator
    emulator = SecuBoxEmulator(name=name, profile=profile)
    set_emulator(emulator)

    # Run server
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Create package init**

```python
# tools/secubox-eye-gateway/gateway/__init__.py
"""SecuBox Eye Gateway — Development tool for Eye Remote."""
__version__ = "1.0.0"
```

- [ ] **Step 7: Create setup.py and requirements**

```python
# tools/secubox-eye-gateway/setup.py
from setuptools import setup, find_packages

setup(
    name="secubox-eye-gateway",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "click>=8.0.0",
    ],
    entry_points={
        "console_scripts": [
            "secubox-eye-gateway=gateway.main:main",
        ],
    },
)
```

```
# tools/secubox-eye-gateway/requirements.txt
fastapi>=0.100.0
uvicorn>=0.23.0
click>=8.0.0
httpx>=0.24.0
```

- [ ] **Step 8: Commit**

```bash
git add tools/secubox-eye-gateway/
git commit -m "feat(eye-gateway): Add development gateway with emulator"
```

---

## Phase 4: Debian Packaging & Integration

### Task 12: SecuBox Module Debian Packaging

**Files:**
- Create: `packages/secubox-eye-remote/debian/control`
- Create: `packages/secubox-eye-remote/debian/rules`
- Create: `packages/secubox-eye-remote/debian/postinst`
- Create: `packages/secubox-eye-remote/debian/prerm`
- Create: `packages/secubox-eye-remote/nginx/eye-remote.conf`
- Create: `packages/secubox-eye-remote/menu.d/50-eye-remote.json`

- [ ] **Step 1: Create debian/control**

```
# packages/secubox-eye-remote/debian/control
Source: secubox-eye-remote
Section: admin
Priority: optional
Maintainer: Gérald Kerma <gandalf@gk2.net>
Build-Depends: debhelper-compat (= 13), python3
Standards-Version: 4.6.2

Package: secubox-eye-remote
Architecture: all
Depends: ${misc:Depends},
         python3,
         python3-fastapi,
         python3-uvicorn,
         python3-websockets,
         python3-qrcode,
         secubox-core
Description: SecuBox Eye Remote Management Module
 Management API and WebUI for Eye Remote devices
 (HyperPixel 2.1 Round on Raspberry Pi Zero W).
 .
 Features:
  - Device pairing with QR codes
  - Real-time metrics streaming
  - Remote commands (screenshot, reboot, OTA)
  - Serial console passthrough
```

- [ ] **Step 2: Create debian/rules**

```makefile
# packages/secubox-eye-remote/debian/rules
#!/usr/bin/make -f

%:
	dh $@ --with python3

override_dh_auto_install:
	# Install Python modules
	install -d debian/secubox-eye-remote/usr/lib/python3/dist-packages/secubox_eye_remote
	cp -r api core models debian/secubox-eye-remote/usr/lib/python3/dist-packages/secubox_eye_remote/

	# Install www
	install -d debian/secubox-eye-remote/usr/share/secubox/www/eye-remote
	cp -r www/* debian/secubox-eye-remote/usr/share/secubox/www/eye-remote/

	# Install nginx config
	install -d debian/secubox-eye-remote/etc/nginx/secubox.d
	install -m 644 nginx/eye-remote.conf debian/secubox-eye-remote/etc/nginx/secubox.d/

	# Install menu
	install -d debian/secubox-eye-remote/usr/share/secubox/menu.d
	install -m 644 menu.d/50-eye-remote.json debian/secubox-eye-remote/usr/share/secubox/menu.d/

	# Install systemd service
	install -d debian/secubox-eye-remote/etc/systemd/system
	install -m 644 secubox-eye-remote.service debian/secubox-eye-remote/etc/systemd/system/
```

- [ ] **Step 3: Create debian/postinst**

```bash
#!/bin/bash
# packages/secubox-eye-remote/debian/postinst
set -e

case "$1" in
    configure)
        # Create data directory
        mkdir -p /var/lib/secubox/eye-remote
        chown secubox:secubox /var/lib/secubox/eye-remote

        # Enable and start service
        systemctl daemon-reload
        systemctl enable secubox-eye-remote.service
        systemctl start secubox-eye-remote.service || true

        # Reload nginx
        systemctl reload nginx || true
        ;;
esac

exit 0
```

- [ ] **Step 4: Create debian/prerm**

```bash
#!/bin/bash
# packages/secubox-eye-remote/debian/prerm
set -e

case "$1" in
    remove|upgrade)
        systemctl stop secubox-eye-remote.service || true
        systemctl disable secubox-eye-remote.service || true
        ;;
esac

exit 0
```

- [ ] **Step 5: Create nginx config**

```nginx
# packages/secubox-eye-remote/nginx/eye-remote.conf
# SecuBox Eye Remote - Nginx configuration

location /eye-remote/ {
    alias /usr/share/secubox/www/eye-remote/;
    index index.html;
}

location /api/v1/eye-remote/ {
    proxy_pass http://unix:/run/secubox/eye-remote.sock;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

- [ ] **Step 6: Create menu entry**

```json
{
  "id": "eye-remote",
  "title": "Eye Remote",
  "icon": "eye",
  "path": "/eye-remote/",
  "order": 50,
  "category": "system",
  "description": "Manage Eye Remote display devices"
}
```

- [ ] **Step 7: Create systemd service**

```ini
# packages/secubox-eye-remote/secubox-eye-remote.service
[Unit]
Description=SecuBox Eye Remote Management
After=network.target secubox-system.service
Wants=secubox-system.service

[Service]
Type=simple
User=secubox
Group=secubox
ExecStart=/usr/bin/uvicorn secubox_eye_remote.api.main:app --uds /run/secubox/eye-remote.sock
Restart=always
RestartSec=5

RuntimeDirectory=secubox
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-eye-remote/debian/ packages/secubox-eye-remote/nginx/ packages/secubox-eye-remote/menu.d/ packages/secubox-eye-remote/secubox-eye-remote.service
git commit -m "feat(secubox-eye-remote): Add Debian packaging"
```

---

### Task 13: Update Build Script for Eye Agent

**Files:**
- Modify: `remote-ui/round/build-eye-remote-image.sh`

- [ ] **Step 1: Add agent installation to build script**

Add after the framebuffer dashboard installation section:

```bash
# Install Eye Agent
log "Installing Eye Agent..."
mkdir -p "$ROOT_MNT/usr/lib/secubox-eye/agent"
mkdir -p "$ROOT_MNT/etc/secubox-eye"

# Copy agent modules
cp -r "$SCRIPT_DIR/agent/"*.py "$ROOT_MNT/usr/lib/secubox-eye/agent/"

# Copy example config
cp "$SCRIPT_DIR/config.toml.example" "$ROOT_MNT/etc/secubox-eye/config.toml"

# Install agent service
cp "$SCRIPT_DIR/secubox-eye-agent.service" "$ROOT_MNT/etc/systemd/system/"

# Enable agent service
run_in_chroot systemctl enable secubox-eye-agent.service
```

- [ ] **Step 2: Update version**

```bash
VERSION="2.0.0"
```

- [ ] **Step 3: Commit**

```bash
git add remote-ui/round/build-eye-remote-image.sh
git commit -m "feat(eye-remote): Update build script for v2.0.0 with agent"
```

---

## Final Task: Integration Test

### Task 14: End-to-End Test

- [ ] **Step 1: Start gateway emulator**

```bash
cd tools/secubox-eye-gateway
pip install -e .
secubox-eye-gateway --name "Test SecuBox" --profile normal --port 8000
```

- [ ] **Step 2: Create test config**

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

- [ ] **Step 3: Run agent with test config**

```bash
cd remote-ui/round
python -m agent.main /tmp/secubox-eye-test/config.toml
```

- [ ] **Step 4: Verify metrics socket**

```bash
# In another terminal
nc -U /run/secubox-eye/metrics.sock | jq .
```

Expected output:
```json
{
  "secubox": {
    "name": "Test SecuBox",
    "host": "127.0.0.1:8000",
    "transport": "wifi"
  },
  "metrics": {
    "cpu_percent": 32.5,
    ...
  }
}
```

- [ ] **Step 5: Commit test documentation**

```bash
git add docs/
git commit -m "docs: Add integration test instructions for Eye Remote v2.0.0"
```

---

## Summary

**Total Tasks:** 14
**Estimated Implementation Time:** Varies by task complexity

### Phase Breakdown:
1. **Phase 1 (Tasks 1-6):** Eye Remote Agent — Config, HTTP client, metrics bridge, device manager, main entry
2. **Phase 2 (Tasks 7-10):** SecuBox Module — Models, registry, token manager, API routers
3. **Phase 3 (Task 11):** Gateway Tool — CLI, emulator, server
4. **Phase 4 (Tasks 12-14):** Packaging & Integration — Debian package, build script, e2e test

### Key Deliverables:
- `remote-ui/round/agent/` — Eye Remote agent package
- `packages/secubox-eye-remote/` — SecuBox management module
- `tools/secubox-eye-gateway/` — Development gateway tool
- Updated `fb_dashboard.py` with agent support
- Debian packaging for SecuBox module
- Updated build script for Eye Remote image
