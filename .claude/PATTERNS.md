# PATTERNS — RPCD → FastAPI
*Référence de portage issue du code source réel*

---

## Pattern 1 — Endpoint GET simple (status, lecture)

### Source RPCD shell (`luci.crowdsec-dashboard/status`)
```sh
#!/bin/sh
. /usr/share/libubox/jshn.sh

status() {
    json_init
    local enabled=$(uci -q get crowdsec.config.enabled || echo "1")
    local running=0
    pgrep crowdsec >/dev/null && running=1
    json_add_boolean "enabled" "$enabled"
    json_add_boolean "running" "$running"
    json_add_string "version" "$(crowdsec -version 2>&1 | head -1)"
    json_print
}

case "$1" in
    list) echo '{"status":{}}' ;;
    call) case "$2" in status) status ;; esac ;;
esac
```

### Cible FastAPI (`api/routers/status.py`)
```python
from fastapi import APIRouter, Depends
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger
import subprocess, shutil

router = APIRouter()
log = get_logger("crowdsec")

@router.get("/status")
async def status(user=Depends(require_jwt)):
    running = subprocess.run(
        ["pgrep", "crowdsec"], capture_output=True
    ).returncode == 0

    version = ""
    if shutil.which("crowdsec"):
        r = subprocess.run(
            ["crowdsec", "-version"], capture_output=True, text=True
        )
        version = r.stdout.strip().splitlines()[0] if r.stdout else ""

    return {
        "running": running,
        "version": version,
        "enabled": True,   # systemctl is-enabled crowdsec
    }
```

---

## Pattern 2 — Proxy vers API locale (CrowdSec LAPI)

### Source RPCD shell
```sh
decisions() {
    local lapi_url=$(uci -q get crowdsec.config.lapi_url || echo "http://127.0.0.1:8080")
    local api_key=$(uci -q get crowdsec.config.lapi_key || echo "")
    curl -s -H "X-Api-Key: $api_key" "$lapi_url/v1/decisions" | jsonfilter -e '@'
}
```

### Cible FastAPI
```python
import httpx
from secubox_core.config import get_config

@router.get("/decisions")
async def decisions(user=Depends(require_jwt)):
    cfg = get_config("crowdsec")
    async with httpx.AsyncClient() as client:
        r = await client.get(
            f"{cfg['lapi_url']}/v1/decisions",
            headers={"X-Api-Key": cfg["lapi_key"]},
            timeout=10.0,
        )
        return r.json() or []
```

---

## Pattern 3 — Action POST avec paramètres (ban/unban)

### Source RPCD shell
```sh
ban() {
    local ip=$(echo "$ARGS" | jsonfilter -e '@.ip')
    local duration=$(echo "$ARGS" | jsonfilter -e '@.duration' || echo "24h")
    local reason=$(echo "$ARGS" | jsonfilter -e '@.reason' || echo "manual")
    cscli decisions add --ip "$ip" --duration "$duration" --reason "$reason"
    json_init
    json_add_boolean "success" "1"
    json_print
}
```

### Cible FastAPI
```python
from pydantic import BaseModel

class BanRequest(BaseModel):
    ip: str
    duration: str = "24h"
    reason: str = "manual"

@router.post("/ban")
async def ban(req: BanRequest, user=Depends(require_jwt)):
    result = subprocess.run(
        ["cscli", "decisions", "add",
         "--ip", req.ip,
         "--duration", req.duration,
         "--reason", req.reason],
        capture_output=True, text=True,
    )
    return {"success": result.returncode == 0, "output": result.stdout}
```

---

## Pattern 4 — Lecture WireGuard (subprocess wg)

### Source RPCD shell
```sh
status() {
    json_init
    json_add_array "interfaces"
    for iface in $(wg show interfaces 2>/dev/null); do
        json_add_object
        json_add_string "name" "$iface"
        local pubkey=$(wg show $iface public-key 2>/dev/null)
        local port=$(wg show $iface listen-port 2>/dev/null)
        json_add_string "public_key" "$pubkey"
        json_add_int "listen_port" "${port:-0}"
        # Count peers
        local peers=$(wg show $iface peers 2>/dev/null | wc -l)
        json_add_int "peer_count" "$peers"
        json_close_object
    done
    json_close_array
    json_print
}
```

### Cible FastAPI
```python
import subprocess, re

@router.get("/status")
async def wg_status(user=Depends(require_jwt)):
    interfaces = []
    ifaces_r = subprocess.run(
        ["wg", "show", "interfaces"], capture_output=True, text=True
    )
    for iface in ifaces_r.stdout.strip().split():
        pubkey = subprocess.run(
            ["wg", "show", iface, "public-key"],
            capture_output=True, text=True
        ).stdout.strip()
        port = subprocess.run(
            ["wg", "show", iface, "listen-port"],
            capture_output=True, text=True
        ).stdout.strip()
        peers = subprocess.run(
            ["wg", "show", iface, "peers"],
            capture_output=True, text=True
        ).stdout.strip().splitlines()

        interfaces.append({
            "name": iface,
            "public_key": pubkey,
            "listen_port": int(port) if port.isdigit() else 0,
            "peer_count": len([p for p in peers if p]),
        })
    return {"interfaces": interfaces}
```

---

## Pattern 5 — Netplan mode switching (network-modes)

### Source RPCD shell
```sh
apply_mode() {
    local mode=$(echo "$ARGS" | jsonfilter -e '@.mode')
    # Backup current config
    cp /etc/config/network /etc/network-modes-backup/network.$(date +%s)
    # Apply mode template
    cp /etc/network-modes/$mode.conf /etc/config/network
    /etc/init.d/network reload
    json_init
    json_add_boolean "success" "1"
    json_add_string "mode" "$mode"
    json_print
}
```

### Cible FastAPI — avec templates netplan
```python
import shutil, subprocess
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

MODES_DIR   = Path("/etc/secubox/netmodes")
NETPLAN_DIR = Path("/etc/netplan")
BACKUP_DIR  = Path("/var/lib/secubox/netmodes-backup")

class ModeRequest(BaseModel):
    mode: str  # router | sniffer-inline | sniffer-passive | access-point | relay

@router.post("/apply_mode")
async def apply_mode(req: ModeRequest, user=Depends(require_jwt)):
    template_path = MODES_DIR / f"{req.mode}.yaml.j2"
    if not template_path.exists():
        raise HTTPException(400, f"Mode inconnu: {req.mode}")

    # Backup
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    for f in NETPLAN_DIR.glob("00-secubox*.yaml"):
        shutil.copy(f, BACKUP_DIR / f"{f.name}.{ts}")

    # Render template
    env = Environment(loader=FileSystemLoader(str(MODES_DIR)))
    tpl = env.get_template(f"{req.mode}.yaml.j2")
    rendered = tpl.render(board=get_config("global")["board"])

    # Apply
    out = NETPLAN_DIR / "00-secubox.yaml"
    out.write_text(rendered)
    result = subprocess.run(
        ["netplan", "apply"], capture_output=True, text=True
    )
    return {
        "success": result.returncode == 0,
        "mode": req.mode,
        "stderr": result.stderr[:500] if result.stderr else "",
    }
```

---

## Pattern 6 — Réécriture XHR (JS frontend)

### Avant (LuCI ubus/rpc)
```javascript
'require rpc';

var callDecisions = rpc.declare({
    object: 'luci.crowdsec-dashboard',
    method: 'decisions',
    expect: { decisions: [] }
});

// Dans load():
return callDecisions().then(function(data) { ... });
```

### Après (fetch REST)
```javascript
// api.js remplacé — plus de rpc.declare
async function callDecisions() {
    const r = await fetch('/api/v1/crowdsec/decisions', {
        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('sbx_token') }
    });
    if (!r.ok) throw new Error(r.status);
    return r.json();
}

// Dans load():
return callDecisions().then(function(data) { ... });
```

### Script `scripts/rewrite-xhr.py` fait ce remplacement automatiquement.

---

## Pattern 7 — Structure `api/main.py` d'un module

```python
# packages/secubox-<module>/api/main.py
from fastapi import FastAPI
from secubox_core.auth import router as auth_router
from .routers import status, decisions, alerts, bouncers

app = FastAPI(
    title="secubox-<module>",
    root_path="/api/v1/<module>",
)

# Auth router (login endpoint)
app.include_router(auth_router, prefix="/auth")

# Module routers
app.include_router(status.router,    tags=["status"])
app.include_router(decisions.router, tags=["decisions"])
app.include_router(alerts.router,    tags=["alerts"])
app.include_router(bouncers.router,  tags=["bouncers"])


@app.get("/health")
async def health():
    return {"status": "ok", "module": "<module>"}
```

---

## Pattern 8 — Unit systemd

```ini
# debian/secubox-<module>.service
[Unit]
Description=SecuBox <Module> API
After=network.target secubox-core.service
Requires=secubox-core.service

[Service]
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/<module>
ExecStart=/usr/bin/uvicorn api.main:app \
    --uds /run/secubox/<module>.sock \
    --log-level warning
ExecStartPost=/bin/chmod 660 /run/secubox/<module>.sock
Restart=on-failure
RestartSec=5

# Sandboxing
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run/secubox /var/lib/secubox /etc/secubox

[Install]
WantedBy=multi-user.target
```

---

## Pattern 9 — `debian/control`

```
Source: secubox-<module>
Section: net
Priority: optional
Maintainer: Gandalf / CyberMind <gk@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://cybermind.fr/secubox

Package: secubox-<module>
Architecture: all
Depends: ${misc:Depends}, secubox-core (>= 1.0),
 python3-uvicorn, <dépendances spécifiques>
Description: SecuBox <Module> — <description courte>
 <Description longue sur plusieurs lignes.>
 Port Debian bookworm du module luci-app-<module> de SecuBox OpenWrt.
```

---

## Pattern 10 — `debian/postinst`

```bash
#!/bin/bash
set -e

case "$1" in
  configure)
    # Créer utilisateur système si absent
    if ! id -u secubox >/dev/null 2>&1; then
      adduser --system --group --no-create-home --home /var/lib/secubox secubox
    fi

    # Répertoires runtime
    install -d -o secubox -g secubox -m 750 /run/secubox
    install -d -o secubox -g secubox -m 750 /var/lib/secubox

    # Activer et démarrer le service
    systemctl daemon-reload
    systemctl enable secubox-<module>.service
    systemctl start  secubox-<module>.service  || true

    # Recharger nginx si installé
    systemctl reload nginx 2>/dev/null || true
    ;;
esac
#DEBHELPER#
```

---

## Pattern 11 — Container Runtime (LXC ONLY)

**CRITICAL REQUIREMENT: Use LXC containers exclusively. NEVER use Docker or Podman.**

### Container Creation
```python
# Create Debian bookworm LXC container
subprocess.run([
    "lxc-create", "-n", CONTAINER_NAME,
    "-t", "download",
    "--",
    "-d", "debian",
    "-r", "bookworm",
    "-a", "amd64"
], timeout=600)
```

### Container Status Check
```python
def lxc_running() -> bool:
    """Check if LXC container is running."""
    result = subprocess.run(
        ["lxc-info", "-n", CONTAINER_NAME, "-s"],
        capture_output=True, text=True
    )
    return "RUNNING" in result.stdout

def lxc_get_ip() -> Optional[str]:
    """Get LXC container IP."""
    result = subprocess.run(
        ["lxc-info", "-n", CONTAINER_NAME, "-iH"],
        capture_output=True, text=True
    )
    return result.stdout.strip().split("\n")[0] if result.returncode == 0 else None
```

### Execute Commands Inside LXC
```python
def lxc_exec(cmd: List[str], timeout: int = 60):
    """Execute command inside LXC container."""
    return subprocess.run(
        ["lxc-attach", "-n", CONTAINER_NAME, "--"] + cmd,
        capture_output=True, text=True, timeout=timeout
    )
```

### USB Device Passthrough
```python
# Add to container config
lxc_config = f"/var/lib/lxc/{CONTAINER_NAME}/config"
with open(lxc_config, "a") as f:
    f.write(f"lxc.mount.entry = /dev/ttyUSB0 dev/ttyUSB0 none bind,create=file 0 0\n")
    f.write("lxc.cgroup2.devices.allow = c 188:* rwm\n")  # ttyUSB
    f.write("lxc.cgroup2.devices.allow = c 166:* rwm\n")  # ttyACM
```

### Dependencies for LXC packages
```
Depends: ..., lxc, lxc-templates
```

### Why LXC over Docker/Podman
- Native Linux container technology (no daemon overhead)
- Better integration with systemd cgroups
- Persistent containers by default
- Direct USB/hardware passthrough
- Lower memory footprint
- Full system containers (init, services)

---

## Pattern 12 — Module Web UI Requirements

**CRITICAL: All module frontends MUST include the shared sidebar and CRT theme.**

### Required CSS Includes
```html
<head>
    <link rel="stylesheet" href="/shared/crt-light.css">
    <link rel="stylesheet" href="/shared/sidebar-light.css">
    <!-- Module-specific styles -->
</head>
```

### Required HTML Structure
```html
<body class="crt-light">
    <nav class="sidebar" id="sidebar"></nav>
    <main class="main-content">
        <div class="container">
            <!-- Module content here -->
        </div>
    </main>
    <script src="/shared/sidebar.js"></script>
</body>
```

### Theme-Aware CSS Variables
Each module defines accent colors with dark mode support:
```css
:root {
    --module-accent: #00bcd4;      /* Light mode color */
    --module-accent-dim: #0097a7;
}

body.dark {
    --module-accent: #4dd0e1;      /* Dark mode color */
    --module-accent-dim: #00acc1;
}

.accent { color: var(--module-accent); }
.accent-bg { background: var(--module-accent); }
```

### Shared Resources Location
- `/shared/crt-light.css` - Light theme (P31 phosphor)
- `/shared/crt-system.css` - Dark theme (VT100 green)
- `/shared/sidebar-light.css` - Light sidebar
- `/shared/sidebar.css` - Dark sidebar
- `/shared/sidebar.js` - Dynamic menu loader

### Menu Integration
Module must provide `menu.d/*.json` with fields:
```json
{
  "id": "module-name",
  "name": "Display Name",
  "icon": "🔧",
  "path": "/module/",
  "category": "apps",
  "order": 800,
  "description": "Short description"
}
```

**Required fields**: `name` (not `title`), emoji `icon`, `path`, `category`, `order`

---

## Pattern 13 — Performance: Background Refresh Cache

**CRITICAL for stats endpoints.** Never block API responses with expensive computations.

### Problem: Blocking Stats Collection
```python
# BAD: 500ms+ blocking on every request
@router.get("/stats")
async def get_stats():
    data = await expensive_collection()  # subprocess calls, file parsing
    return data
```

### Solution: Pre-computed Cache with Instant Response
```python
import asyncio
import json
from pathlib import Path
from secubox_core.logger import get_logger

log = get_logger("module")
CACHE_FILE = Path("/var/cache/secubox/module/stats.json")
_cache: dict = {}
_cache_lock = asyncio.Lock()

async def _refresh_cache():
    """Background task: refresh cache every 60s."""
    while True:
        try:
            data = await _compute_stats()  # expensive work
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(data))
            async with _cache_lock:
                _cache.update(data)
            log.debug("cache refreshed")
        except Exception as e:
            log.error(f"cache refresh failed: {e}")
        await asyncio.sleep(60)

@app.on_event("startup")
async def startup():
    # Load existing cache file if available
    if CACHE_FILE.exists():
        try:
            _cache.update(json.loads(CACHE_FILE.read_text()))
        except Exception:
            pass
    asyncio.create_task(_refresh_cache())

@router.get("/stats")
async def get_stats():
    """Instant response from pre-computed cache."""
    if _cache:
        return _cache
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text())
    return {"error": "cache not ready", "retry_after": 5}
```

### When to Apply
- Dashboard stats endpoints
- Log aggregation endpoints
- Metrics collection (CPU, mem, disk, network)
- CrowdSec decisions/alerts lists
- Any endpoint reading files or calling subprocesses

### When NOT to Apply
- Real-time actions (start/stop/restart/ban/unban)
- Configuration changes
- User-initiated operations requiring immediate feedback

---

## Pattern 14 — Performance: Parallel Subprocess Execution

### Problem: Sequential CLI Calls
```python
# BAD: 7-10 seconds total
decisions = await run("cscli decisions list")  # 2s
alerts = await run("cscli alerts list")        # 2s
metrics = await run("cscli metrics")           # 3s
bouncers = await run("cscli bouncers list")    # 2s
```

### Solution: asyncio.gather() Parallelization
```python
import asyncio

async def run_cmd(cmd: str, timeout: float = 30.0) -> str:
    """Run subprocess asynchronously with timeout."""
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return stdout.decode() if proc.returncode == 0 else ""
    except asyncio.TimeoutError:
        proc.kill()
        return ""

async def get_crowdsec_status():
    # GOOD: 2-3 seconds total (parallel execution)
    decisions, alerts, metrics, bouncers = await asyncio.gather(
        run_cmd("cscli decisions list -o json"),
        run_cmd("cscli alerts list -o json"),
        run_cmd("cscli metrics -o json"),
        run_cmd("cscli bouncers list -o json"),
    )
    return {
        "decisions": json.loads(decisions) if decisions else [],
        "alerts": json.loads(alerts) if alerts else [],
        "metrics": json.loads(metrics) if metrics else {},
        "bouncers": json.loads(bouncers) if bouncers else [],
    }
```

---

## Pattern 15 — Performance: Memory Limits in Systemd

### Service Memory Configuration
```ini
# debian/secubox-module.service
[Service]
# Memory limits (adjust per device profile)
MemoryMax=100M           # Hard limit - OOM kill if exceeded
MemoryHigh=80M           # Soft limit - triggers reclaim pressure

# For ESPRESSObin (1GB RAM) - lighter limits
# MemoryMax=50M
# MemoryHigh=40M

# Prevent memory leaks from consuming system
MemorySwapMax=50M        # Limit swap usage per service
```

### Drop-in Override for Device Profiles
```bash
# /etc/systemd/system/secubox-module.service.d/memory.conf
[Service]
MemoryMax=50M    # ESPRESSObin profile
MemoryHigh=40M
```

---

## Pattern 16 — Performance: Streaming Large Responses

### Problem: Loading Entire File into Memory
```python
# BAD: Loads 100MB log file into memory
@router.get("/logs")
async def get_logs():
    content = Path("/var/log/secubox/audit.log").read_text()
    return {"logs": content}
```

### Solution: StreamingResponse with Generator
```python
from fastapi.responses import StreamingResponse
import aiofiles

@router.get("/logs")
async def get_logs():
    """Stream logs without loading entire file."""
    async def generate():
        async with aiofiles.open("/var/log/secubox/audit.log") as f:
            async for line in f:
                yield line

    return StreamingResponse(
        generate(),
        media_type="text/plain",
        headers={"X-Content-Type-Options": "nosniff"}
    )

# For JSON: paginate instead of streaming
@router.get("/logs/json")
async def get_logs_paginated(offset: int = 0, limit: int = 100):
    """Paginated log access."""
    lines = []
    async with aiofiles.open("/var/log/secubox/audit.log") as f:
        for i, line in enumerate(await f.readlines()):
            if i < offset:
                continue
            if len(lines) >= limit:
                break
            lines.append(line.strip())
    return {"logs": lines, "offset": offset, "limit": limit}
```

---

## Pattern 17 — Performance: History Limits by Device

```python
from secubox_core.config import get_config

# Device-specific history limits
DEVICE_PROFILES = {
    "espressobin": {  # 1GB RAM
        "max_history_entries": 1000,
        "max_log_lines": 500,
        "cache_ttl_seconds": 120,
        "uvicorn_workers": 1,
    },
    "mochabin": {  # 8GB RAM
        "max_history_entries": 10000,
        "max_log_lines": 5000,
        "cache_ttl_seconds": 60,
        "uvicorn_workers": 4,
    },
    "default": {
        "max_history_entries": 5000,
        "max_log_lines": 2000,
        "cache_ttl_seconds": 60,
        "uvicorn_workers": 2,
    },
}

def get_device_profile() -> dict:
    """Get performance profile for current device."""
    cfg = get_config("global")
    board = cfg.get("board", "default")
    return DEVICE_PROFILES.get(board, DEVICE_PROFILES["default"])

# Usage
profile = get_device_profile()
MAX_HISTORY = profile["max_history_entries"]
```

---

## Pattern 18 — Performance: Efficient Config Reading

### Problem: Re-reading TOML on Every Request
```python
# BAD: File I/O on every API call
@router.get("/status")
async def status():
    config = toml.load("/etc/secubox/module.toml")  # I/O every time
    return {"enabled": config.get("enabled", True)}
```

### Solution: LRU Cache with TTL
```python
from functools import lru_cache
import time
import toml

_config_cache = {}
_config_mtime = {}

def get_module_config(module: str, ttl: int = 30) -> dict:
    """Read config with file modification check."""
    path = f"/etc/secubox/{module}.toml"
    try:
        mtime = os.path.getmtime(path)
        if module in _config_cache and _config_mtime.get(module) == mtime:
            return _config_cache[module]

        config = toml.load(path)
        _config_cache[module] = config
        _config_mtime[module] = mtime
        return config
    except Exception:
        return _config_cache.get(module, {})

# Even simpler: @lru_cache for truly static configs
@lru_cache(maxsize=32)
def get_static_config(module: str) -> dict:
    """For configs that rarely change - clear cache on service restart."""
    return toml.load(f"/etc/secubox/{module}.toml")
```

---

## Pattern 19 — Performance Verification Checklist

Before marking a module complete, verify:

```
□ No blocking subprocess calls in GET endpoints
□ Stats endpoints use background refresh pattern
□ Memory limits defined in systemd service
□ Large responses use streaming or pagination
□ Config reads use caching (LRU or mtime-based)
□ Parallel execution for multiple CLI calls
□ History/log limits respect device profile
□ P99 latency < 500ms (ESPRESSObin) or < 200ms (MOCHAbin)
□ Service RSS < 50MB (ESPRESSObin) or < 100MB (MOCHAbin)
```

### Quick Performance Test Commands
```bash
# API latency
./scripts/bench/api-latency.py --host $HOST --requests 50

# Memory per service
./scripts/bench/memory-baseline.sh

# Load test
locust -f scripts/bench/locustfile.py --host https://$HOST \
       --headless -u 10 -r 2 -t 60s
```
