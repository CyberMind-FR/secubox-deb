"""secubox-hub — Dashboard central SecuBox"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_board_info, get_config
from secubox_core.logger import get_logger
from secubox_core.kiosk import (
    detect_board_type, get_board_profile, get_board_capabilities,
    get_interface_classification,
)
import subprocess
import json
import asyncio
import os
import time
from pathlib import Path

app = FastAPI(title="secubox-hub", version="1.7.0", root_path="/api/v1/hub")

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

# Auth router already has prefix="/auth" in secubox_core.auth
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
public_router = APIRouter(prefix="/public", tags=["public"])
log = get_logger("hub")


# ══════════════════════════════════════════════════════════════════
# Menu Cache — Double-buffer pre-cache for instant response
# ══════════════════════════════════════════════════════════════════
MENU_CACHE_FILE = Path("/var/cache/secubox/menu.json")
_menu_cache: dict = {}
_menu_cache_lock = asyncio.Lock()


def _compute_menu_sync() -> dict:
    """Compute full menu (synchronous, called from thread).

    Only includes modules that have actual www directories with HTML content.
    Skips items without ID, console-only items, and modules without frontends.
    """
    menu_items = _load_menu_definitions()

    # Filter to only installed modules and check active status
    installed_items = []
    for item in menu_items:
        module_id = item.get("id", "")

        # Skip items without a valid ID
        if not module_id:
            continue

        # Skip console-only items (no web interface)
        if item.get("console_only"):
            continue

        # Hub is always installed
        if module_id == "hub":
            item_copy = item.copy()
            item_copy["installed"] = True
            item_copy["active"] = True
            installed_items.append(item_copy)
            continue

        # Check if module is installed (has www directory with content)
        if _check_module_installed(module_id):
            item_copy = item.copy()
            item_copy["installed"] = True
            item_copy["active"] = _check_module_active(module_id)
            installed_items.append(item_copy)

    # Group by category
    categories = {}
    for item in installed_items:
        cat = item.get("category", "other")
        if cat not in categories:
            cat_meta = CATEGORY_META.get(cat, {"name": cat.title(), "icon": "📦", "order": 99})
            categories[cat] = {
                "id": cat,
                "name": cat_meta["name"],
                "icon": cat_meta["icon"],
                "order": cat_meta["order"],
                "items": []
            }
        categories[cat]["items"].append(item)

    # Sort items within each category
    for cat in categories.values():
        cat["items"].sort(key=lambda x: x.get("order", 999))

    # Sort categories by order
    sorted_categories = sorted(categories.values(), key=lambda x: x["order"])

    return {
        "categories": sorted_categories,
        "total_installed": len(installed_items),
        "total_active": sum(1 for i in installed_items if i.get("active")),
        "cached_at": time.time(),
    }


async def _refresh_menu_cache():
    """Background task to refresh menu cache every 30s."""
    global _menu_cache
    import concurrent.futures

    while True:
        try:
            # Run synchronous computation in thread pool
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                loop = asyncio.get_event_loop()
                menu_data = await loop.run_in_executor(pool, _compute_menu_sync)

            # Update in-memory cache
            async with _menu_cache_lock:
                _menu_cache = menu_data

            # Persist to file for fast startup
            try:
                MENU_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
                MENU_CACHE_FILE.write_text(json.dumps(menu_data))
            except Exception as e:
                log.debug("Menu cache file write failed: %s", e)

            log.debug("Menu cache refreshed: %d modules", menu_data.get("total_installed", 0))
        except Exception as e:
            log.error("Menu cache refresh failed: %s", e)

        await asyncio.sleep(30)  # Refresh every 30s


def _load_menu_cache_from_file() -> dict:
    """Load menu cache from file (for fast startup)."""
    if MENU_CACHE_FILE.exists():
        try:
            return json.loads(MENU_CACHE_FILE.read_text())
        except Exception:
            pass
    return {}


# ══════════════════════════════════════════════════════════════════
# Public Endpoints — No authentication required
# ══════════════════════════════════════════════════════════════════
@public_router.get("/menu")
async def public_menu():
    """Public menu endpoint for sidebar navigation (no auth required).

    Double-buffer cache: ALWAYS returns the current snapshot instantly and never
    computes on the request path (a sync systemctl walk here, multiplied by the
    sidebar's polling, is what froze the shared aggregator loop). The background
    refresher — kicked here because mounted sub-apps get no startup/middleware —
    fills the buffer within a few seconds; until then we serve the file snapshot
    or an explicit `warming` placeholder.
    """
    global _menu_cache
    _ensure_bg()

    # Active buffer (instant).
    if _menu_cache:
        return _menu_cache

    # Cold start: last-good snapshot persisted to file (cheap read, no systemctl).
    file_cache = _load_menu_cache_from_file()
    if file_cache:
        _menu_cache = file_cache
        return file_cache

    # Nothing yet — never block; the background task will fill it shortly.
    return {"categories": [], "total_installed": 0, "total_active": 0, "warming": True}


@public_router.get("/info")
def public_info():
    """Public info endpoint for login page (no auth required)."""
    # Get version from build-info.json
    version = "1.7.0"
    build_info_path = Path("/etc/secubox/build-info.json")
    if build_info_path.exists():
        try:
            import json
            data = json.loads(build_info_path.read_text())
            version = data.get("version", version)
        except Exception:
            pass

    # Check auth mode
    auth_mode = "Standard"
    config_path = Path("/etc/secubox/secubox.conf")
    if config_path.exists():
        try:
            import tomllib
            with open(config_path, "rb") as f:
                config = tomllib.load(f)
                if config.get("auth", {}).get("zkp_enabled", False):
                    auth_mode = "ZKP"
        except Exception:
            pass

    # Check for ZKP service
    try:
        r = subprocess.run(["systemctl", "is-active", "secubox-zkp"],
                          capture_output=True, text=True, timeout=2)
        if r.stdout.strip() == "active":
            auth_mode = "ZKP"
    except Exception:
        pass

    return {
        "version": version,
        "auth_mode": auth_mode,
        "name": "SecuBox",
    }


@public_router.get("/led_status")
async def public_led_status():
    """Public LED status endpoint — reads actual hardware LED colors from sysfs.

    Returns the current RGB color of each of the 3 MOCHAbin LEDs.
    LED1 = Hardware health, LED2 = Services health, LED3 = Security status.
    """
    led_base = Path("/sys/class/leds")

    def read_led_brightness(color: str, led_num: int) -> int:
        """Read brightness value for a specific LED color channel."""
        path = led_base / f"{color}:led{led_num}" / "brightness"
        try:
            return int(path.read_text().strip())
        except Exception:
            return 0

    def brightness_to_hex(r: int, g: int, b: int) -> str:
        """Convert RGB brightness values (0-255) to hex color."""
        # Normalize to 0-255 range (LED max is typically 255)
        r = min(255, max(0, r))
        g = min(255, max(0, g))
        b = min(255, max(0, b))
        return f"#{r:02x}{g:02x}{b:02x}"

    # Read actual hardware LED values
    leds = {}
    for led_num in [1, 2, 3]:
        r = read_led_brightness("red", led_num)
        g = read_led_brightness("green", led_num)
        b = read_led_brightness("blue", led_num)
        leds[f"led{led_num}"] = {
            "r": r, "g": g, "b": b,
            "color": brightness_to_hex(r, g, b)
        }

    return {
        "led1": leds["led1"]["color"],  # Hardware health (bottom)
        "led2": leds["led2"]["color"],  # Services health (middle)
        "led3": leds["led3"]["color"],  # Security status (top)
        "raw": leds,  # Full RGB values for debugging
    }


@public_router.get("/health-batch")
async def public_health_batch():
    """Batch health snapshot for the sidebar LEDs.

    Double-buffer cache: returns the last fully-built snapshot instantly and
    NEVER rebuilds on the request path. The previous cold-miss rebuilt under a
    lock, so concurrent sidebar polls serialized behind a ~3 s systemctl walk
    and starved the shared loop. The background refresher (kicked here) swaps in
    a complete snapshot atomically — so we never serve partial/bad counts.
    """
    _ensure_bg()
    hb = _cache.get("health_batch")
    if hb:
        return hb
    # Not warmed yet — serve an explicit placeholder rather than block/compute.
    return {"modules": {}, "count": 0, "warming": True}


app.include_router(public_router)

# ══════════════════════════════════════════════════════════════════
# Performance Cache — Avoid repeated subprocess calls
# ══════════════════════════════════════════════════════════════════
_cache = {
    "services": {},       # module_id -> {name, active, socket}
    "menu": None,         # Full menu response
    "system_stats": {},   # CPU, memory, disk
    "last_refresh": 0,
    "health_batch": None, # {modules: {...}, count: int} snapshot for sidebar LEDs
    "health_batch_ts": 0, # monotonic-ish wall time of last health_batch build
}
CACHE_TTL = 5  # seconds - cache valid for 5 seconds

# Collapse a thundering herd of concurrent cold requests (the background loop is
# starved >10s, e.g. under aggregator saturation) to a single refresh each.
_services_warm_lock = asyncio.Lock()
_health_batch_lock = asyncio.Lock()

# MODULES dict is dynamically populated from installed services
# These are the "expected" core modules - actual list comes from systemd
CORE_MODULES = {
    "crowdsec": "secubox-crowdsec",
    "netdata":  "secubox-netdata",
    "wireguard":"secubox-wireguard",
    "dpi":      "secubox-dpi",
    "netmodes": "secubox-netmodes",
    "nac":      "secubox-nac",
    "qos":      "secubox-qos",
    "vhost":    "secubox-vhost",
    "system":   "secubox-system",
    "auth":     "secubox-auth",
    "mediaflow":"secubox-mediaflow",
    "cdn":      "secubox-cdn",
}

def _discover_modules() -> dict:
    """Dynamically discover enabled/active secubox modules from systemd."""
    modules = {}
    try:
        # Get enabled or active services only
        r = subprocess.run(
            ["systemctl", "list-units", "secubox-*.service", "--no-pager", "--no-legend", "--all"],
            capture_output=True, text=True, timeout=10
        )
        for line in r.stdout.strip().split("\n"):
            if not line.strip():
                continue
            # Format: UNIT LOAD ACTIVE SUB DESCRIPTION
            parts = line.split(None, 4)
            if len(parts) >= 4:
                svc = parts[0].replace(".service", "")
                # Skip runtime/core services
                if svc in ("secubox-core", "secubox-runtime", "secubox-firstboot", "secubox-console"):
                    continue
                mod_id = svc.replace("secubox-", "")
                modules[mod_id] = svc
    except Exception as e:
        log.warning("Module discovery failed: %s, using defaults", e)
        return CORE_MODULES.copy()
    # If discovery found modules, use them; otherwise fall back to defaults
    return modules if modules else CORE_MODULES.copy()

# Initialize MODULES with defaults - will be refreshed asynchronously
MODULES = CORE_MODULES.copy()
_modules_discovered = False


def _refresh_services_cache():
    """Refresh all service statuses in one batch (called by background task)."""
    # Get all service statuses in parallel using a single systemctl call
    all_services = list(MODULES.values())
    try:
        # Single call to get all service states
        r = subprocess.run(
            ["systemctl", "is-active", "--"] + all_services,
            capture_output=True, text=True, timeout=5
        )
        states = r.stdout.strip().split("\n")
        for i, svc in enumerate(all_services):
            state = states[i] if i < len(states) else "unknown"
            sock = Path(f"/run/secubox/{svc.replace('secubox-','')}.sock")
            _cache["services"][svc] = {
                "name": svc,
                "active": state == "active",
                "socket": sock.exists()
            }
    except Exception as e:
        log.warning("Cache refresh failed: %s", e)


def _refresh_health_batch():
    """Build the sidebar health snapshot in ONE systemctl list-units call.

    Stores _cache["health_batch"] = {modules, count} + stamps health_batch_ts.
    Shared by the background loop and the /public/health-batch cold-miss path so
    the request never makes its own (3.3 s) synchronous systemctl call.
    """
    modules = {}
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service",
             "--state=running,failed,inactive", "--no-legend", "--plain",
             "secubox-*"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 4:
                unit, _load, active, sub = parts[0], parts[1], parts[2], parts[3]
                if unit.startswith("secubox-") and unit.endswith(".service"):
                    mod_id = unit[8:-8]
                    if active == "active" and sub == "running":
                        modules[mod_id] = {"status": "ok", "msg": "Running"}
                    elif active == "active":
                        modules[mod_id] = {"status": "warn", "msg": f"Active ({sub})"}
                    elif active == "failed":
                        modules[mod_id] = {"status": "error", "msg": "Failed"}
                    else:
                        modules[mod_id] = {"status": "warn", "msg": f"{active}/{sub}"}
    except Exception as e:
        log.warning("health-batch systemctl error: %s", e)

    socket_dir = Path("/run/secubox")
    if socket_dir.exists():
        for sock in socket_dir.glob("*.sock"):
            mod_id = sock.stem
            if mod_id not in modules:
                modules[mod_id] = {"status": "ok", "msg": "Socket active"}

    _cache["health_batch"] = {"modules": modules, "count": len(modules)}
    _cache["health_batch_ts"] = time.time()


def _refresh_system_stats():
    """Refresh system stats (CPU, memory, disk)."""
    try:
        import psutil
        _cache["system_stats"] = {
            "cpu_percent": psutil.cpu_percent(interval=None),  # Non-blocking
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
            "load_avg": list(psutil.getloadavg()),
        }
    except Exception as e:
        log.warning("System stats refresh failed: %s", e)


_version_refresh_counter = 0

async def _background_cache_refresh():
    """Background task to refresh cache every CACHE_TTL seconds.

    The blocking systemctl/psutil work is offloaded to a thread so it never
    stalls the (possibly shared, aggregator) event loop.
    """
    global _version_refresh_counter
    while True:
        try:
            await asyncio.to_thread(_refresh_services_cache)
            await asyncio.to_thread(_refresh_system_stats)
            await asyncio.to_thread(_refresh_health_batch)
            _cache["last_refresh"] = time.time()
            # Refresh package versions every 12 cycles (~60s)
            _version_refresh_counter += 1
            if _version_refresh_counter >= 12:
                _version_refresh_counter = 0
                await asyncio.to_thread(_refresh_package_versions)
        except Exception as e:
            log.error("Background cache error: %s", e)
        await asyncio.sleep(CACHE_TTL)


# Whether the background warm-up + refresh loops have been kicked off. Guarded
# so it runs exactly once whether triggered by the startup hook (standalone
# uvicorn) OR lazily on the first request (when served in-process by the
# aggregator, where mounted sub-apps' startup/lifespan never fires).
_bg_started = False


async def _start_background_once():
    """Idempotently warm the caches and start the periodic refresh tasks."""
    global _bg_started, _modules_discovered, _menu_cache
    if _bg_started:
        return
    _bg_started = True
    # Discover modules off the event loop.
    try:
        discovered = await asyncio.to_thread(_discover_modules)
        if discovered:
            MODULES.clear()
            MODULES.update(discovered)
            _modules_discovered = True
            log.info("Discovered %d modules", len(MODULES))
    except Exception as e:
        log.warning("Module discovery failed: %s, using defaults", e)
    # Initial cache warm, off the event loop.
    try:
        await asyncio.to_thread(_refresh_services_cache)
        await asyncio.to_thread(_refresh_system_stats)
        await asyncio.to_thread(_refresh_health_batch)
        _cache["last_refresh"] = time.time()
    except Exception as e:
        log.warning("Initial cache warm failed: %s", e)
    # Load menu cache from file (instant navbar).
    _menu_cache = _load_menu_cache_from_file()
    if _menu_cache:
        log.info("Menu cache loaded from file: %d modules", _menu_cache.get("total_installed", 0))
    # Start periodic background tasks.
    asyncio.create_task(_background_cache_refresh())
    asyncio.create_task(_refresh_menu_cache())
    log.info("Background cache tasks started")


@app.on_event("startup")
async def startup():
    """Start background tasks when run as a standalone uvicorn service."""
    await _start_background_once()


def _ensure_bg() -> None:
    """Reliably kick the background warm-up + refresh loops from the request path.

    Mounted in the aggregator, a sub-app receives neither startup/lifespan nor
    `@app.middleware` events — so the navbar status endpoints trigger the warm-up
    themselves on first hit. Fire-and-forget: never blocks or delays the request.
    Idempotent (``_start_background_once`` guards on ``_bg_started``).
    """
    if _bg_started:
        return
    try:
        asyncio.create_task(_start_background_once())
    except RuntimeError:
        # No running loop yet (e.g. import time) — a later request retries.
        pass


# Kept for the standalone-uvicorn path; harmless (no-op) when mounted.
@app.middleware("http")
async def _lazy_background_start(request, call_next):
    _ensure_bg()
    return await call_next(request)


_version_cache: dict = {}

def _get_package_version(pkg_name: str) -> str:
    """Get installed package version via dpkg (cached)."""
    if pkg_name in _version_cache:
        return _version_cache[pkg_name]
    # Don't block - return placeholder and let background task fill it
    return "-"


def _refresh_package_versions():
    """Refresh all package versions in one batch call (non-blocking)."""
    global _version_cache
    try:
        # Single dpkg call for all secubox packages
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package} ${Version}\n", "secubox-*"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0:
            for line in r.stdout.strip().split("\n"):
                if " " in line:
                    pkg, ver = line.split(" ", 1)
                    _version_cache[pkg] = ver.split("-")[0] if ver else "-"
    except Exception as e:
        log.debug("Package version refresh failed: %s", e)


def _svc(name: str) -> dict:
    """Get service status from cache (fast) or direct call (fallback)."""
    if name in _cache["services"] and (time.time() - _cache["last_refresh"]) < CACHE_TTL * 2:
        svc_data = _cache["services"][name].copy()
        # Add version from version cache
        svc_data["version"] = _version_cache.get(name, "-")
        return svc_data
    # Fallback to direct call if cache miss (no version lookup to stay fast)
    try:
        r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=2)
        sock = Path(f"/run/secubox/{name.replace('secubox-','')}.sock")
        return {"name": name, "active": r.stdout.strip() == "active",
                "socket": sock.exists(), "version": _version_cache.get(name, "-")}
    except Exception:
        return {"name": name, "active": False, "socket": False, "version": "-"}


async def _ensure_services_warm():
    """Refresh the services cache in ONE batched call when cold/stale.

    Replaces the ~16 per-module `systemctl is-active` fallbacks inside _svc()
    with a single offloaded `is-active -- [all]` so dashboard/status/modules cold
    paths cost one call instead of sixteen, and never block the shared loop.
    """
    if (time.time() - _cache["last_refresh"]) < CACHE_TTL * 2:
        return
    async with _services_warm_lock:
        # Re-check under the lock: a concurrent waiter may have just refreshed.
        if (time.time() - _cache["last_refresh"]) < CACHE_TTL * 2:
            return
        await asyncio.to_thread(_refresh_services_cache)
        _cache["last_refresh"] = time.time()


@router.get("/status")
async def status(user=Depends(require_jwt)):
    board = get_board_info()
    await _ensure_services_warm()
    # Offload _svc() — blocking systemctl on a cold cache must not stall the loop.
    modules_status = await asyncio.to_thread(lambda: {k: _svc(v) for k, v in MODULES.items()})
    active = sum(1 for m in modules_status.values() if m["active"])
    return {**board, "modules": modules_status,
            "active_modules": active, "total_modules": len(MODULES)}

@router.get("/modules")
async def modules(user=Depends(require_jwt)):
    await _ensure_services_warm()
    return await asyncio.to_thread(lambda: [{"id": k, **_svc(v)} for k, v in MODULES.items()])

@router.get("/alerts")
async def alerts(user=Depends(require_jwt)):
    # Use the cached _svc() (offloaded) instead of an un-timed per-module
    # systemctl loop that blocked the shared aggregator event loop.
    await _ensure_services_warm()
    statuses = await asyncio.to_thread(lambda: {m: _svc(svc) for m, svc in MODULES.items()})
    return [{"type": "service_down", "module": m, "service": MODULES[m],
             "severity": "warning"}
            for m, st in statuses.items() if not st.get("active")]

@router.get("/monitoring")
async def monitoring(user=Depends(require_jwt)):
    # Use cached stats (non-blocking)
    stats = _cache.get("system_stats", {})
    return {
        "cpu": stats.get("cpu_percent", 0),
        "mem": stats.get("memory_percent", 0),
        "load": stats.get("load_avg", [0, 0, 0])
    }

@router.get("/settings")
async def settings(user=Depends(require_jwt)):
    return get_config()


def _get_build_info() -> dict:
    """Get build metadata from /etc/secubox/build-info.json."""
    build_file = Path("/etc/secubox/build-info.json")
    if build_file.exists():
        try:
            return json.loads(build_file.read_text())
        except Exception:
            pass
    return {"build_timestamp": None, "version": "dev"}


@router.get("/dashboard")
async def dashboard(user=Depends(require_jwt)):
    """Données complètes du dashboard (uses cached stats for speed)."""
    board = get_board_info()
    await _ensure_services_warm()
    # Offload _svc() — on a cold cache it makes blocking systemctl calls that
    # must not stall the shared aggregator event loop.
    modules_status = await asyncio.to_thread(lambda: {k: _svc(v) for k, v in MODULES.items()})
    active = sum(1 for m in modules_status.values() if m["active"])
    build_info = _get_build_info()

    # Use cached system stats (non-blocking)
    stats = _cache.get("system_stats", {})

    return {
        "board": board,
        "modules": modules_status,
        "active_modules": active,
        "total_modules": len(MODULES),
        "cpu_percent": stats.get("cpu_percent", 0),
        "memory_percent": stats.get("memory_percent", 0),
        "disk_percent": stats.get("disk_percent", 0),
        "load_avg": stats.get("load_avg", [0, 0, 0]),
        "uptime": int(float(Path("/proc/uptime").read_text().split()[0])),
        "build_info": build_info,
    }


@router.get("/widgets")
async def widgets(user=Depends(require_jwt)):
    """Configuration des widgets dashboard."""
    widgets_file = Path("/var/lib/secubox/widgets.json")
    if widgets_file.exists():
        import json
        return json.loads(widgets_file.read_text())
    return [
        {"id": "system", "type": "system_info", "position": 0, "enabled": True},
        {"id": "modules", "type": "module_status", "position": 1, "enabled": True},
        {"id": "security", "type": "security_alerts", "position": 2, "enabled": True},
        {"id": "network", "type": "network_stats", "position": 3, "enabled": True},
    ]


class WidgetRequest(BaseModel):
    widgets: list[dict]


@router.post("/save_widgets")
async def save_widgets(req: WidgetRequest, user=Depends(require_jwt)):
    import json
    widgets_file = Path("/var/lib/secubox/widgets.json")
    widgets_file.parent.mkdir(parents=True, exist_ok=True)
    widgets_file.write_text(json.dumps(req.widgets, indent=2))
    return {"success": True}


@router.get("/security_summary")
async def security_summary(user=Depends(require_jwt)):
    """Résumé de sécurité."""
    return {
        "crowdsec_alerts": 0,
        "blocked_ips": 0,
        "quarantined_clients": 0,
        "threats_blocked_24h": 0,
        "last_scan": None,
    }


@router.get("/network_summary")
def network_summary(user=Depends(require_jwt)):
    """Résumé réseau with IP addresses."""
    import json

    # Get interface states
    r = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True)
    try:
        links = json.loads(r.stdout)
        ifaces = [l for l in links if l.get("ifname") != "lo"]
        up_count = sum(1 for l in ifaces if "UP" in l.get("flags", []))
    except Exception:
        ifaces = []
        up_count = 0

    # Get IP addresses for common interfaces
    lan_ip = None
    wan_ip = None

    # Try to get IP addresses using ip -j addr
    r2 = subprocess.run(["ip", "-j", "addr", "show"], capture_output=True, text=True)
    try:
        addrs = json.loads(r2.stdout)
        for iface in addrs:
            ifname = iface.get("ifname", "")
            addr_info = iface.get("addr_info", [])
            for ai in addr_info:
                if ai.get("family") == "inet":
                    ip = ai.get("local")
                    if ip:
                        # LAN interfaces
                        if ifname in ("br-lan", "br0", "lan0", "lan"):
                            lan_ip = ip
                        # WAN interfaces
                        elif ifname in ("br-wan", "wan", "eth0", "wan0", "enp1s0"):
                            wan_ip = ip
                        # If no LAN yet, use any bridged interface
                        elif ifname.startswith("br") and not lan_ip:
                            lan_ip = ip
    except Exception:
        pass

    # Fallback to default network
    if not lan_ip:
        lan_ip = "192.168.10.1"
    if not wan_ip:
        wan_ip = "N/A"

    return {
        "interfaces": len(ifaces),
        "interfaces_up": up_count,
        "wan_status": "connected" if wan_ip and wan_ip != "N/A" else "disconnected",
        "lan_clients": 0,
        "lan_ip": lan_ip,
        "wan_ip": wan_ip,
    }


@router.get("/quick_actions")
async def quick_actions(user=Depends(require_jwt)):
    """Actions rapides disponibles."""
    return [
        {"id": "restart_services", "label": "Redémarrer les services", "icon": "refresh"},
        {"id": "check_updates", "label": "Vérifier les mises à jour", "icon": "download"},
        {"id": "run_diagnostic", "label": "Diagnostic système", "icon": "search"},
        {"id": "backup_config", "label": "Sauvegarder la config", "icon": "save"},
    ]


class ActionRequest(BaseModel):
    action: str


@router.post("/execute_action")
def execute_action(req: ActionRequest, user=Depends(require_jwt)):
    if req.action == "restart_services":
        for svc in list(MODULES.values())[:5]:
            subprocess.run(["systemctl", "restart", svc], capture_output=True)
        return {"success": True, "message": "Services redémarrés"}
    elif req.action == "check_updates":
        r = subprocess.run(["apt", "update"], capture_output=True, text=True)
        return {"success": r.returncode == 0}
    elif req.action == "run_diagnostic":
        return {"success": True, "redirect": "/api/v1/system/diagnostics"}
    elif req.action == "backup_config":
        return {"success": True, "redirect": "/api/v1/system/backup"}
    return {"success": False, "error": "Unknown action"}


@router.get("/notifications")
async def notifications(user=Depends(require_jwt)):
    """Notifications système."""
    notifs_file = Path("/var/lib/secubox/notifications.json")
    if notifs_file.exists():
        import json
        return json.loads(notifs_file.read_text())
    return []


@router.post("/dismiss_notification")
async def dismiss_notification(notification_id: str, user=Depends(require_jwt)):
    import json
    notifs_file = Path("/var/lib/secubox/notifications.json")
    if notifs_file.exists():
        notifs = json.loads(notifs_file.read_text())
        notifs = [n for n in notifs if n.get("id") != notification_id]
        notifs_file.write_text(json.dumps(notifs, indent=2))
    return {"success": True}


@router.post("/dismiss_all_notifications")
async def dismiss_all_notifications(user=Depends(require_jwt)):
    notifs_file = Path("/var/lib/secubox/notifications.json")
    notifs_file.write_text("[]") if notifs_file.parent.exists() else None
    return {"success": True}


@router.get("/theme")
async def theme(user=Depends(require_jwt)):
    """Thème de l'interface."""
    import json
    prefs_file = Path("/var/lib/secubox/preferences.json")
    if prefs_file.exists():
        prefs = json.loads(prefs_file.read_text())
        return {"theme": prefs.get("theme", "dark")}
    return {"theme": "dark"}


class ThemeRequest(BaseModel):
    theme: str


@router.post("/set_theme")
async def set_theme(req: ThemeRequest, user=Depends(require_jwt)):
    import json
    prefs_file = Path("/var/lib/secubox/preferences.json")
    prefs_file.parent.mkdir(parents=True, exist_ok=True)
    prefs = {}
    if prefs_file.exists():
        prefs = json.loads(prefs_file.read_text())
    prefs["theme"] = req.theme
    prefs_file.write_text(json.dumps(prefs, indent=2))
    return {"success": True}


@router.get("/version")
def version(user=Depends(require_jwt)):
    """Version SecuBox."""
    r = subprocess.run(["dpkg", "-l", "secubox-hub"], capture_output=True, text=True)
    version_str = "1.0.0"
    for line in r.stdout.splitlines():
        if "secubox-hub" in line:
            parts = line.split()
            if len(parts) >= 3:
                version_str = parts[2]
    return {
        "version": version_str,
        "codename": "Armada",
        "build_date": "2026-04",
    }


@router.get("/about")
async def about(user=Depends(require_jwt)):
    board = get_board_info()
    return {
        "product": "SecuBox",
        "version": "1.7.0",
        "board": board,
        "project_url": "https://secubox.gondwana.systems",
        "support_email": "support@cybermind.fr",
    }


class ServiceActionRequest(BaseModel):
    module: str
    action: str  # start, stop, restart, enable, disable


@router.post("/module_control")
def module_control(req: ServiceActionRequest, user=Depends(require_jwt)):
    """Contrôler un module."""
    if req.module not in MODULES:
        return {"success": False, "error": "Module inconnu"}
    svc = MODULES[req.module]
    if req.action not in ("start", "stop", "restart", "enable", "disable"):
        return {"success": False, "error": "Action invalide"}
    r = subprocess.run(["systemctl", req.action, svc], capture_output=True, text=True)
    log.info("module_control: %s %s → %s", req.action, svc, r.returncode == 0)
    return {"success": r.returncode == 0, "output": r.stderr[:200]}


@router.get("/module_status")
async def module_status(module: str, user=Depends(require_jwt)):
    """Statut d'un module."""
    if module not in MODULES:
        return {"error": "Module inconnu"}
    return _svc(MODULES[module])


@router.get("/module_logs")
def module_logs(module: str, lines: int = 50, user=Depends(require_jwt)):
    """Logs d'un module."""
    if module not in MODULES:
        return {"error": "Module inconnu"}
    r = subprocess.run(
        ["journalctl", "-u", MODULES[module], "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


@router.get("/uptime")
async def uptime(user=Depends(require_jwt)):
    """Uptime système."""
    uptime_sec = int(float(Path("/proc/uptime").read_text().split()[0]))
    days = uptime_sec // 86400
    hours = (uptime_sec % 86400) // 3600
    mins = (uptime_sec % 3600) // 60
    return {
        "seconds": uptime_sec,
        "days": days,
        "hours": hours,
        "minutes": mins,
        "uptime": f"{days}d {hours}h {mins}m",
        "formatted": f"{days}d {hours}h {mins}m",
    }


@router.get("/boot_mode")
def boot_mode(user=Depends(require_jwt)):
    """Get current boot mode (kiosk or console)."""
    kiosk_enabled = Path("/var/lib/secubox/.kiosk-enabled").exists()
    kiosk_running = False
    try:
        import subprocess
        r = subprocess.run(["systemctl", "is-active", "secubox-kiosk"], capture_output=True, text=True)
        kiosk_running = r.stdout.strip() == "active"
    except Exception:
        pass

    if kiosk_enabled and kiosk_running:
        mode = "kiosk"
    elif kiosk_enabled:
        mode = "kiosk-pending"
    else:
        mode = "console"

    return {
        "mode": mode,
        "kiosk_enabled": kiosk_enabled,
        "kiosk_running": kiosk_running,
    }


@router.get("/auth_mode")
def auth_mode(user=Depends(require_jwt)):
    """Get current authentication mode (ZKP or standard)."""
    # Check if ZKP authentication is enabled
    zkp_enabled = False
    config_path = Path("/etc/secubox/secubox.conf")
    if config_path.exists():
        try:
            import tomllib
            with open(config_path, "rb") as f:
                config = tomllib.load(f)
                zkp_enabled = config.get("auth", {}).get("zkp_enabled", False)
        except Exception:
            pass

    # Also check for ZKP service
    zkp_running = False
    try:
        import subprocess
        r = subprocess.run(["systemctl", "is-active", "secubox-zkp"], capture_output=True, text=True)
        zkp_running = r.stdout.strip() == "active"
    except Exception:
        pass

    mode = "ZKP" if (zkp_enabled or zkp_running) else "Standard"

    return {
        "mode": mode,
        "zkp_enabled": zkp_enabled,
        "zkp_running": zkp_running,
    }


@router.get("/cpu")
async def cpu(user=Depends(require_jwt)):
    import psutil
    # Use cached CPU percent (non-blocking)
    stats = _cache.get("system_stats", {})
    return {
        "percent": stats.get("cpu_percent", 0),
        "count": psutil.cpu_count(),
        "freq_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else 0,
    }


@router.get("/memory")
async def memory(user=Depends(require_jwt)):
    import psutil
    mem = psutil.virtual_memory()
    return {
        "total_mb": mem.total // 1024 // 1024,
        "used_mb": mem.used // 1024 // 1024,
        "available_mb": mem.available // 1024 // 1024,
        "percent": mem.percent,
    }


@router.get("/disk")
async def disk(user=Depends(require_jwt)):
    import psutil
    d = psutil.disk_usage("/")
    return {
        "total_gb": d.total // 1024**3,
        "used_gb": d.used // 1024**3,
        "free_gb": d.free // 1024**3,
        "percent": d.percent,
    }


@router.get("/network_stats")
async def network_stats(user=Depends(require_jwt)):
    import psutil
    counters = psutil.net_io_counters()
    return {
        "bytes_sent": counters.bytes_sent,
        "bytes_recv": counters.bytes_recv,
        "packets_sent": counters.packets_sent,
        "packets_recv": counters.packets_recv,
    }


@router.get("/recent_events")
async def recent_events(user=Depends(require_jwt)):
    """Événements récents."""
    return []


@router.get("/system_health")
async def system_health(user=Depends(require_jwt)):
    """Score de santé système (uses cached stats)."""
    # Use cached stats (non-blocking)
    stats = _cache.get("system_stats", {})
    cpu = stats.get("cpu_percent", 0)
    mem = stats.get("memory_percent", 0)
    disk = stats.get("disk_percent", 0)

    modules_status = [_svc(v) for v in MODULES.values()]
    active = sum(1 for m in modules_status if m["active"])
    module_health = (active / len(MODULES)) * 100

    resource_health = 100 - max(cpu, mem, disk) / 2
    overall = int((module_health + resource_health) / 2)

    return {
        "overall": overall,
        "module_health": int(module_health),
        "resource_health": int(resource_health),
        "issues": [m["name"] for m in modules_status if not m["active"]],
    }


@router.get("/preferences")
async def preferences(user=Depends(require_jwt)):
    import json
    prefs_file = Path("/var/lib/secubox/preferences.json")
    if prefs_file.exists():
        return json.loads(prefs_file.read_text())
    return {"theme": "dark", "language": "fr", "notifications": True}


class PreferencesRequest(BaseModel):
    theme: str = "dark"
    language: str = "fr"
    notifications: bool = True


@router.post("/save_preferences")
async def save_preferences(req: PreferencesRequest, user=Depends(require_jwt)):
    import json
    prefs_file = Path("/var/lib/secubox/preferences.json")
    prefs_file.parent.mkdir(parents=True, exist_ok=True)
    prefs_file.write_text(json.dumps(req.model_dump(), indent=2))
    return {"success": True}


@router.get("/logs")
def logs(lines: int = 100, user=Depends(require_jwt)):
    """Logs système."""
    r = subprocess.run(
        ["journalctl", "-n", str(lines), "--no-pager", "-o", "short"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


@router.get("/check_updates")
def check_updates(user=Depends(require_jwt)):
    """Vérifier les mises à jour."""
    subprocess.run(["apt", "update"], capture_output=True)
    r = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
    updates = []
    for line in r.stdout.splitlines()[1:]:
        if line.strip():
            updates.append(line.split("/")[0])
    return {"updates_available": len(updates), "packages": updates[:20]}


@router.post("/apply_updates")
async def apply_updates(user=Depends(require_jwt)):
    """Appliquer les mises à jour."""
    log.warning("System update requested")
    return {"success": True, "message": "Run 'apt upgrade' manually for safety"}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "hub", "version": "1.7.0"}


# ══════════════════════════════════════════════════════════════════
# Module Health Monitor Endpoints
# ══════════════════════════════════════════════════════════════════

MODULE_HEALTH_CACHE = Path("/var/cache/secubox/health/modules.json")
VHOST_HEALTH_CACHE = Path("/var/cache/secubox/health/status.json")


@router.get("/module-health/summary")
async def module_health_summary(user=Depends(require_jwt)):
    """Get module health summary (healthy/degraded/down counts)."""
    try:
        if MODULE_HEALTH_CACHE.exists():
            data = json.loads(MODULE_HEALTH_CACHE.read_text())
            # Use pre-computed values from cache if available
            if "ok" in data and "degraded" in data:
                return {
                    "health_percent": data.get("health_pct", 0),
                    "healthy": data.get("ok", 0),
                    "degraded": data.get("degraded", 0),
                    "down": data.get("down", 0),
                    "total": data.get("total", 0),
                }
            # Fallback: compute from modules dict
            modules = data.get("modules", {})
            healthy = sum(1 for m in modules.values() if m.get("overall") == "ok")
            degraded = sum(1 for m in modules.values() if m.get("overall") == "degraded")
            down = sum(1 for m in modules.values() if m.get("overall") in ("down", "error"))
            total = len(modules)
            return {
                "health_percent": (healthy / max(total, 1)) * 100,
                "healthy": healthy,
                "degraded": degraded,
                "down": down,
                "total": total,
            }
    except Exception as e:
        log.debug("Module health cache read failed: %s", e)

    # Fallback: compute from menu data
    menu = _menu_cache or _load_menu_cache_from_file()
    if menu and menu.get("categories"):
        items = [i for c in menu["categories"] for i in c.get("items", [])]
        active = sum(1 for i in items if i.get("active"))
        total = len(items)
        return {
            "health_percent": (active / max(total, 1)) * 100,
            "healthy": active,
            "degraded": 0,
            "down": total - active,
            "total": total,
        }

    return {"health_percent": 0, "healthy": 0, "degraded": 0, "down": 0, "total": 0}


@router.get("/module-health/status")
async def module_health_status(user=Depends(require_jwt)):
    """Get detailed module health status."""
    try:
        if MODULE_HEALTH_CACHE.exists():
            return json.loads(MODULE_HEALTH_CACHE.read_text())
    except Exception:
        pass
    return {"modules": {}, "timestamp": time.time()}


@router.get("/module-health/alerts")
async def module_health_alerts(user=Depends(require_jwt)):
    """Get modules that are degraded or down."""
    try:
        if MODULE_HEALTH_CACHE.exists():
            data = json.loads(MODULE_HEALTH_CACHE.read_text())
            modules = data.get("modules", {})
            alerts = [
                {"name": name, "status": m.get("overall"), "message": m.get("message", "")}
                for name, m in modules.items()
                if m.get("overall") in ("degraded", "down", "error")
            ]
            return {"alerts": alerts}
    except Exception:
        pass
    return {"alerts": []}


@router.get("/health-monitor/summary")
async def vhost_health_summary(user=Depends(require_jwt)):
    """Get VHost health summary (ok/slow/placeholder/down counts).

    The prober at /usr/lib/secubox/health/prober.py classifies HTTP 4xx/5xx
    (other than 503) as a separate "error" status. From an operator POV
    that's the same as "down" — they merge into a single 🔴 bucket on the
    dashboard. The fallback path below already does this correctly; the
    pre-computed path used to drop the "error" count, which made
    operators see ok+slow+down counts that didn't sum to total. Fixed
    in #392 by merging data["error"] into the returned "down".
    """
    try:
        if VHOST_HEALTH_CACHE.exists():
            data = json.loads(VHOST_HEALTH_CACHE.read_text())
            # Use pre-computed values if available
            if "ok" in data:
                return {
                    "health_percent": data.get("health_pct", 0),
                    "ok": data.get("ok", 0),
                    "slow": data.get("slow", 0),
                    "placeholder": data.get("placeholder", 0),
                    "down": data.get("down", 0) + data.get("error", 0),
                    "total": data.get("total", 0),
                }
            # Fallback: compute from vhosts dict
            vhosts = data.get("vhosts", {})
            ok = sum(1 for v in vhosts.values() if v.get("status") == "ok")
            slow = sum(1 for v in vhosts.values() if v.get("status") == "slow")
            placeholder = sum(1 for v in vhosts.values() if v.get("status") == "placeholder")
            down = sum(1 for v in vhosts.values() if v.get("status") in ("down", "error", "timeout"))
            total = len(vhosts)
            real_total = total - placeholder
            return {
                "health_percent": (ok + slow) / max(real_total, 1) * 100,
                "ok": ok,
                "slow": slow,
                "placeholder": placeholder,
                "down": down,
                "total": total,
            }
    except Exception as e:
        log.debug("VHost health cache read failed: %s", e)
    return {"health_percent": 0, "ok": 0, "slow": 0, "placeholder": 0, "down": 0, "total": 0}


@router.get("/health-monitor/status")
async def vhost_health_status(user=Depends(require_jwt)):
    """Get detailed VHost health status."""
    try:
        if VHOST_HEALTH_CACHE.exists():
            return json.loads(VHOST_HEALTH_CACHE.read_text())
    except Exception:
        pass
    return {"vhosts": {}, "timestamp": time.time()}


@router.get("/health-monitor/alerts")
async def vhost_health_alerts(user=Depends(require_jwt)):
    """Get VHosts that are down or slow."""
    try:
        if VHOST_HEALTH_CACHE.exists():
            data = json.loads(VHOST_HEALTH_CACHE.read_text())
            vhosts = data.get("vhosts", {})
            alerts = [
                {"domain": domain, "status": v.get("status"), "response_time": v.get("response_time", 0)}
                for domain, v in vhosts.items()
                if v.get("status") in ("slow", "down", "error", "timeout")
            ]
            return {"alerts": alerts[:20]}  # Limit to 20
    except Exception:
        pass
    return {"alerts": []}


# ══════════════════════════════════════════════════════════════════
# Auto-Repair System
# ══════════════════════════════════════════════════════════════════

REPAIR_LOG = Path("/var/log/secubox/repairs.log")
REPAIR_HISTORY = Path("/var/cache/secubox/repair-history.json")

# Known repair actions per issue type
REPAIR_ACTIONS = {
    "service_dead": ["restart"],
    "socket_missing": ["create_socket_dir", "restart"],
    "socket_permission": ["fix_socket_perms", "restart"],
    "api_timeout": ["restart"],
    "api_error": ["clear_cache", "restart"],
    "high_memory": ["restart"],
    "dependency_failed": ["restart_deps", "restart"],
}


def _log_repair(module: str, action: str, success: bool, message: str = ""):
    """Log repair action."""
    REPAIR_LOG.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().isoformat()
    with open(REPAIR_LOG, "a") as f:
        f.write(f"{timestamp} | {module} | {action} | {'OK' if success else 'FAIL'} | {message}\n")


def _save_repair_history(module: str, actions: list, success: bool):
    """Save repair to history."""
    REPAIR_HISTORY.parent.mkdir(parents=True, exist_ok=True)
    history = []
    if REPAIR_HISTORY.exists():
        try:
            history = json.loads(REPAIR_HISTORY.read_text())
        except Exception:
            pass
    history.insert(0, {
        "timestamp": datetime.now().isoformat(),
        "module": module,
        "actions": actions,
        "success": success
    })
    # Keep last 100 repairs
    REPAIR_HISTORY.write_text(json.dumps(history[:100], indent=2))


def _run_repair_action(module: str, action: str) -> tuple[bool, str]:
    """Execute a single repair action."""
    svc = f"secubox-{module}" if not module.startswith("secubox-") else module

    try:
        if action == "restart":
            result = subprocess.run(
                ["systemctl", "restart", svc],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return True, f"Restarted {svc}"
            return False, result.stderr

        elif action == "create_socket_dir":
            socket_dir = Path(f"/run/secubox")
            socket_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(socket_dir, 0o755)
            return True, f"Created {socket_dir}"

        elif action == "fix_socket_perms":
            socket_path = Path(f"/run/secubox/{module}.sock")
            if socket_path.exists():
                os.chmod(socket_path, 0o666)
                return True, f"Fixed perms on {socket_path}"
            return True, "Socket not found, will be recreated"

        elif action == "clear_cache":
            cache_dir = Path(f"/var/cache/secubox/{module}")
            if cache_dir.exists():
                import shutil
                shutil.rmtree(cache_dir, ignore_errors=True)
                return True, f"Cleared cache {cache_dir}"
            return True, "No cache to clear"

        elif action == "restart_deps":
            # Common dependencies
            deps = {
                "haproxy": ["nginx"],
                "waf": ["haproxy"],
                "crowdsec": [],
                "wireguard": [],
            }
            mod_name = module.replace("secubox-", "")
            for dep in deps.get(mod_name, []):
                subprocess.run(["systemctl", "restart", f"secubox-{dep}"], timeout=30)
            return True, f"Restarted dependencies"

        else:
            return False, f"Unknown action: {action}"

    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)


def _diagnose_module(module: str) -> list[str]:
    """Diagnose module issues and return list of problems."""
    svc = f"secubox-{module}" if not module.startswith("secubox-") else module
    mod_name = module.replace("secubox-", "")
    issues = []

    # Check service status
    try:
        result = subprocess.run(
            ["systemctl", "is-active", svc],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout.strip() != "active":
            issues.append("service_dead")
    except Exception:
        issues.append("service_dead")

    # Check socket
    socket_path = Path(f"/run/secubox/{mod_name}.sock")
    if not socket_path.exists():
        issues.append("socket_missing")
    elif not os.access(socket_path, os.W_OK):
        issues.append("socket_permission")

    # Check API responsiveness
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--unix-socket", str(socket_path), "http://localhost/health"],
            capture_output=True, text=True, timeout=5
        )
        code = result.stdout.strip()
        if code not in ("200", "401"):  # 401 is OK (needs auth)
            issues.append("api_error")
    except subprocess.TimeoutExpired:
        issues.append("api_timeout")
    except Exception:
        pass

    return issues


@router.get("/repair/status")
async def repair_status():
    """Get repair system status (public)."""
    history = []
    if REPAIR_HISTORY.exists():
        try:
            history = json.loads(REPAIR_HISTORY.read_text())[:10]
        except Exception:
            pass

    return {
        "enabled": True,
        "recent_repairs": history,
        "log_path": str(REPAIR_LOG)
    }


@router.post("/repair/{module}", dependencies=[Depends(require_jwt)])
async def repair_module(module: str):
    """Attempt to repair a specific module."""
    log.info("Auto-repair requested for: %s", module)

    # Diagnose issues
    issues = _diagnose_module(module)
    if not issues:
        return {"success": True, "module": module, "message": "No issues detected", "actions": []}

    # Collect repair actions
    actions_to_run = []
    for issue in issues:
        actions_to_run.extend(REPAIR_ACTIONS.get(issue, ["restart"]))
    # Deduplicate while preserving order
    actions_to_run = list(dict.fromkeys(actions_to_run))

    # Execute repairs
    results = []
    all_success = True
    for action in actions_to_run:
        success, msg = _run_repair_action(module, action)
        results.append({"action": action, "success": success, "message": msg})
        _log_repair(module, action, success, msg)
        if not success:
            all_success = False

    _save_repair_history(module, actions_to_run, all_success)

    # Verify fix
    time.sleep(2)
    remaining_issues = _diagnose_module(module)

    return {
        "success": all_success and len(remaining_issues) == 0,
        "module": module,
        "issues_found": issues,
        "actions": results,
        "issues_remaining": remaining_issues
    }


@router.post("/repair/all", dependencies=[Depends(require_jwt)])
async def repair_all_modules():
    """Diagnose and repair all failed modules."""
    log.info("Auto-repair ALL requested")

    # Get list of secubox services
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=failed,inactive",
             "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=10
        )
        failed = [
            line.split()[0].replace(".service", "")
            for line in result.stdout.strip().split("\n")
            if line.strip() and "secubox-" in line
        ]
    except Exception:
        failed = []

    # Also check for services that are active but unhealthy
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=active",
             "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().split("\n"):
            if "secubox-" in line:
                svc = line.split()[0].replace(".service", "")
                mod = svc.replace("secubox-", "")
                issues = _diagnose_module(mod)
                if issues and svc not in failed:
                    failed.append(svc)
    except Exception:
        pass

    if not failed:
        return {"success": True, "message": "All modules healthy", "repaired": []}

    # Repair each failed module
    repaired = []
    for svc in failed[:10]:  # Limit to 10 at a time
        mod = svc.replace("secubox-", "")
        result = await repair_module(mod)
        repaired.append({"module": mod, "result": result})

    return {
        "success": all(r["result"].get("success") for r in repaired),
        "repaired": repaired,
        "total_failed": len(failed)
    }


@router.get("/repair/diagnose/{module}", dependencies=[Depends(require_jwt)])
async def diagnose_module(module: str):
    """Diagnose a module without repairing."""
    issues = _diagnose_module(module)
    suggested_actions = []
    for issue in issues:
        suggested_actions.extend(REPAIR_ACTIONS.get(issue, ["restart"]))
    suggested_actions = list(dict.fromkeys(suggested_actions))

    return {
        "module": module,
        "issues": issues,
        "suggested_actions": suggested_actions,
        "healthy": len(issues) == 0
    }


# ══════════════════════════════════════════════════════════════════
# Network Mode Selection (integrates with secubox-netmodes)
# ══════════════════════════════════════════════════════════════════

NETMODES_STATE_FILE = Path("/var/lib/secubox/netmodes-state.json")

AVAILABLE_NETWORK_MODES = {
    "router": {
        "name": "Router",
        "desc": "Full NAT router with DHCP, NAC, DPI",
        "icon": "🔀",
        "recommended_for": ["home", "office", "smb"],
    },
    "sniffer-inline": {
        "name": "Inline Sniffer",
        "desc": "Transparent bridge with dual-stream DPI (tc mirred)",
        "icon": "🔍",
        "recommended_for": ["security_audit", "monitoring"],
    },
    "sniffer-passive": {
        "name": "Passive Sniffer",
        "desc": "Out-of-band monitoring via SPAN/TAP port",
        "icon": "👁️",
        "recommended_for": ["readonly_monitoring", "compliance"],
    },
    "access-point": {
        "name": "Access Point",
        "desc": "WiFi AP 802.11r/k/v with band steering",
        "icon": "📡",
        "recommended_for": ["wireless_extension"],
    },
    "relay": {
        "name": "VPN Relay",
        "desc": "Network relay with WireGuard VPN and optimized MTU",
        "icon": "🔗",
        "recommended_for": ["remote_site", "vpn_gateway"],
    },
}


def _get_netmodes_state() -> dict:
    """Read current network mode state."""
    if NETMODES_STATE_FILE.exists():
        try:
            return json.loads(NETMODES_STATE_FILE.read_text())
        except Exception:
            pass
    return {"current_mode": "router", "pending_mode": None, "last_change": None}


@router.get("/network_mode")
async def get_network_mode(user=Depends(require_jwt)):
    """
    Get current network mode and available modes.
    Used by dashboard to display network mode widget.
    """
    state = _get_netmodes_state()
    current_mode = state.get("current_mode", "router")
    mode_info = AVAILABLE_NETWORK_MODES.get(current_mode, {})

    # Get board info for recommendations
    board_type = detect_board_type()
    board_profile = get_board_profile(board_type)
    iface_class = get_interface_classification(board_type)

    return {
        "current_mode": current_mode,
        "mode_name": mode_info.get("name", current_mode),
        "mode_desc": mode_info.get("desc", ""),
        "mode_icon": mode_info.get("icon", "🔀"),
        "pending_mode": state.get("pending_mode"),
        "last_change": state.get("last_change"),
        "board_type": board_type,
        "board_profile": board_profile,
        "interfaces": {
            "wan": iface_class.get("wan", []),
            "lan": iface_class.get("lan", []),
            "sfp": iface_class.get("sfp", []),
        },
        "available_modes": [
            {"id": k, **v} for k, v in AVAILABLE_NETWORK_MODES.items()
        ],
    }


class NetworkModeRequest(BaseModel):
    mode: str
    dry_run: bool = False


@router.post("/network_mode")
async def set_network_mode(req: NetworkModeRequest, user=Depends(require_jwt)):
    """
    Change network mode (requires authentication).
    Proxies to secubox-netmodes API.
    """
    if req.mode not in AVAILABLE_NETWORK_MODES:
        raise HTTPException(400, f"Invalid mode: {req.mode}")

    # Call secubox-netmodes API via socket
    netmodes_sock = Path("/run/secubox/netmodes.sock")
    if not netmodes_sock.exists():
        return {"success": False, "error": "secubox-netmodes not running"}

    try:
        import httpx

        async with httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=str(netmodes_sock))
        ) as client:
            if req.dry_run:
                # Preview changes
                resp = await client.get(
                    f"http://localhost/preview_changes?mode={req.mode}",
                    timeout=30
                )
            else:
                # Apply mode
                resp = await client.post(
                    "http://localhost/apply_mode",
                    json={"mode": req.mode},
                    timeout=60
                )

            if resp.status_code == 200:
                result = resp.json()
                log.info("Network mode change: %s -> %s", req.mode, result.get("success", "unknown"))
                return result
            else:
                return {"success": False, "error": f"API error: {resp.status_code}"}

    except ImportError:
        # Fallback: direct subprocess call to netplan
        log.warning("httpx not available, using fallback")
        return {"success": False, "error": "httpx not installed for socket communication"}
    except Exception as e:
        log.error("network_mode error: %s", e)
        return {"success": False, "error": str(e)}


@router.get("/network_mode/preview")
async def preview_network_mode(mode: str, user=Depends(require_jwt)):
    """Preview what configuration would be applied for a mode."""
    if mode not in AVAILABLE_NETWORK_MODES:
        raise HTTPException(400, f"Invalid mode: {mode}")

    board_type = detect_board_type()
    iface_class = get_interface_classification(board_type)

    wan = iface_class.get("wan", ["eth0"])[0] if iface_class.get("wan") else "eth0"
    lan = iface_class.get("lan", [])
    lan_str = ", ".join(lan) if lan else ""

    # Generate preview YAML based on mode
    if mode == "router":
        yaml_preview = f"""network:
  version: 2
  renderer: networkd

  ethernets:
    {wan}:
      dhcp4: true
      optional: true
"""
        for iface in lan:
            yaml_preview += f"""    {iface}:
      optional: true
"""
        if lan:
            yaml_preview += f"""
  bridges:
    br-lan:
      interfaces: [{lan_str}]
      addresses: [192.168.1.1/24]
      dhcp4: false
"""
    elif mode in ("sniffer-inline", "sniffer-passive"):
        yaml_preview = f"""network:
  version: 2
  renderer: networkd

  ethernets:
    {wan}:
      dhcp4: false
      optional: true
"""
        for iface in lan:
            yaml_preview += f"""    {iface}:
      dhcp4: false
      optional: true
"""
        yaml_preview += f"""
  bridges:
    br0:
      interfaces: [{wan}, {lan_str}]
      dhcp4: true
      parameters:
        stp: false
"""
    else:
        yaml_preview = f"""network:
  version: 2
  renderer: networkd

  ethernets:
    {wan}:
      dhcp4: true
"""

    return {
        "mode": mode,
        "mode_info": AVAILABLE_NETWORK_MODES.get(mode, {}),
        "board_type": board_type,
        "interfaces": iface_class,
        "yaml_preview": yaml_preview,
    }


@router.get("/board_summary")
async def board_summary(user=Depends(require_jwt)):
    """
    Quick board summary for dashboard widgets.
    Uses secubox_core.kiosk functions.
    """
    board_type = detect_board_type()
    profile = get_board_profile(board_type)
    caps = get_board_capabilities(board_type)
    ifaces = get_interface_classification(board_type)

    return {
        "board_type": board_type,
        "profile": profile,
        "capabilities": caps,
        "interfaces": ifaces,
    }


# ── Dynamic Menu System ──────────────────────────────────────────

MENU_DIR = Path("/usr/share/secubox/menu.d")

# Default menu definitions (used if menu.d files don't exist)
DEFAULT_MENU = [
    {"id": "hub", "name": "Dashboard", "category": "root", "icon": "🏠", "path": "/", "order": 0},
    {"id": "system", "name": "System Hub", "category": "root", "icon": "🔧", "path": "/system/", "order": 10},
    {"id": "crowdsec", "name": "CrowdSec", "category": "wall", "icon": "🛡️", "path": "/crowdsec/", "order": 100},
    {"id": "waf", "name": "WAF", "category": "wall", "icon": "🔥", "path": "/waf/", "order": 105},
    {"id": "wireguard", "name": "WireGuard VPN", "category": "mesh", "icon": "🔐", "path": "/wireguard/", "order": 110},
    {"id": "auth", "name": "Auth Guardian", "category": "auth", "icon": "🔑", "path": "/auth/", "order": 120},
    {"id": "nac", "name": "Client Guardian", "category": "auth", "icon": "👥", "path": "/nac/", "order": 130},
    {"id": "netmodes", "name": "Network Modes", "category": "mesh", "icon": "🔀", "path": "/netmodes/", "order": 200},
    {"id": "dpi", "name": "DPI", "category": "mind", "icon": "🔍", "path": "/dpi/", "order": 210},
    {"id": "qos", "name": "Bandwidth Manager", "category": "mesh", "icon": "📶", "path": "/qos/", "order": 220},
    {"id": "vhost", "name": "Virtual Hosts", "category": "mesh", "icon": "🌍", "path": "/vhost/", "order": 230},
    {"id": "cdn", "name": "CDN Cache", "category": "mesh", "icon": "💾", "path": "/cdn/", "order": 240},
    {"id": "haproxy", "name": "HAProxy", "category": "mesh", "icon": "⚖️", "path": "/haproxy/", "order": 250},
    {"id": "dns", "name": "DNS", "category": "mesh", "icon": "🌐", "path": "/dns/", "order": 260},
    {"id": "netdata", "name": "Netdata", "category": "mind", "icon": "📊", "path": "/netdata/", "order": 300},
    {"id": "mediaflow", "name": "Media Flow", "category": "boot", "icon": "📺", "path": "/mediaflow/", "order": 310},
    {"id": "droplet", "name": "Droplet", "category": "boot", "icon": "📤", "path": "/droplet/", "order": 400},
    {"id": "metablogizer", "name": "MetaBlogizer", "category": "mind", "icon": "📝", "path": "/metablogizer/", "order": 410},
    {"id": "publish", "name": "Publish", "category": "boot", "icon": "🚀", "path": "/publish/", "order": 420},
    {"id": "streamlit", "name": "Streamlit", "category": "mesh", "icon": "🎯", "path": "/streamlit/", "order": 500},
    {"id": "streamforge", "name": "StreamForge", "category": "mesh", "icon": "🔨", "path": "/streamforge/", "order": 510},
    {"id": "users", "name": "Users", "category": "auth", "icon": "👤", "path": "/users/", "order": 600},
    {"id": "mail", "name": "Mail Server", "category": "mesh", "icon": "📧", "path": "/mail/", "order": 610},
    {"id": "webmail", "name": "Webmail", "category": "mesh", "icon": "📬", "path": "/webmail/", "order": 620},
    {"id": "mail-lxc", "name": "Mail LXC", "category": "mesh", "icon": "📧", "path": "/mail-lxc/", "order": 630},
    {"id": "webmail-lxc", "name": "Webmail LXC", "category": "mesh", "icon": "📬", "path": "/webmail-lxc/", "order": 640},
    {"id": "portal", "name": "Portal", "category": "root", "icon": "🚪", "path": "/portal/", "order": 140},
]

CATEGORY_META = {
    # SecuBox 6-module color system (Charte §Six Module Color System).
    # Every menu.d entry MUST set `category` to one of these six. The
    # ordering mirrors the charter's complementary-pair sequence:
    # AUTH/WALL/BOOT then their counterparts MIND/ROOT/MESH.
    "auth": {"name": "Auth", "icon": "🎯", "order": 0, "color": "#C04E24"},
    "wall": {"name": "Wall", "icon": "🛡️", "order": 1, "color": "#9A6010"},
    "boot": {"name": "Boot", "icon": "🚀", "order": 2, "color": "#803018"},
    "mind": {"name": "Mind", "icon": "🧠", "order": 3, "color": "#3D35A0"},
    "root": {"name": "Root", "icon": "⚙️", "order": 4, "color": "#0A5840"},
    "mesh": {"name": "Mesh", "icon": "🌐", "order": 5, "color": "#104A88"},
}


def _load_menu_definitions() -> list:
    """Load menu definitions from menu.d directory or use defaults."""
    import json
    menu_items = []

    if MENU_DIR.exists():
        for f in sorted(MENU_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                if isinstance(data, list):
                    menu_items.extend(data)
                elif isinstance(data, dict):
                    menu_items.append(data)
            except Exception as e:
                log.warning("Failed to load menu %s: %s", f.name, e)

    # If no menu files found, use defaults
    if not menu_items:
        menu_items = DEFAULT_MENU.copy()

    return menu_items


def _check_module_installed(module_id: str) -> bool:
    """Check if a module is installed AND has a usable frontend.

    A module is considered installed if it has a www directory with content.
    Services without frontends are not shown in the menu.
    """
    # Reject empty or invalid module IDs
    if not module_id or not isinstance(module_id, str):
        return False

    # Hub is always installed
    if module_id == "hub":
        return True

    # Portal is part of hub package
    if module_id == "portal":
        portal_path = Path("/usr/share/secubox/www/portal")
        return portal_path.exists() and (portal_path / "index.html").exists()

    # Check for www directory with an index.html or any html file
    www_path = Path(f"/usr/share/secubox/www/{module_id}")
    if www_path.exists() and www_path.is_dir():
        # Check for index.html or any content
        if (www_path / "index.html").exists():
            return True
        # Check for any HTML files
        if list(www_path.glob("*.html")):
            return True

    return False


def _check_module_active(module_id: str) -> bool:
    """Check if a module's service is active (uses cache)."""
    svc_name = f"secubox-{module_id}"

    # Check cache first
    if svc_name in _cache["services"]:
        return _cache["services"][svc_name].get("active", False)

    # Check for socket (for socket-based services)
    sock = Path(f"/run/secubox/{module_id}.sock")
    if sock.exists():
        return True

    # Check systemd service directly (for TCP port services)
    result = subprocess.run(
        ["systemctl", "is-active", svc_name],
        capture_output=True, text=True
    )
    return result.stdout.strip() == "active"


@router.get("/menu")
async def menu(user=Depends(require_jwt)):
    """
    Dynamic menu endpoint (authenticated).
    Returns categorized menu items for installed modules only.
    Uses pre-computed cache for instant response.
    """
    global _menu_cache

    # Return from in-memory cache (instant)
    if _menu_cache:
        return _menu_cache

    # Fallback to file cache
    file_cache = _load_menu_cache_from_file()
    if file_cache:
        _menu_cache = file_cache
        return file_cache

    # Last resort: compute synchronously
    return _compute_menu_sync()


app.include_router(router)


# ══════════════════════════════════════════════════════════════════
# Firewall Summary — nftables counters for SOC dashboard
#
# Cache (/var/cache/secubox/nft-*) is populated every 30s by
# secubox-nft-cache.timer (shipped by this package). It is a speed
# optimisation — the dashboard widget must never go blank because the
# cache is missing or stale. If the cache file is absent or older than
# NFT_CACHE_MAX_AGE seconds we fall back to a realtime `sudo nft list`
# call AND nudge systemd to refresh the cache for the next request.
# ══════════════════════════════════════════════════════════════════

NFT_CACHE_DIR = "/var/cache/secubox"
NFT_CACHE_MAX_AGE = 60  # seconds before we consider the cache stale


def _parse_nft_counters(text: str) -> dict:
    counters: dict = {}
    current_counter = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("counter "):
            parts = line.split()
            if len(parts) >= 2:
                current_counter = parts[1]
        elif "packets" in line and current_counter:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "packets" and i + 1 < len(parts):
                    try:
                        packets = int(parts[i + 1])
                    except ValueError:
                        break
                    counters[current_counter] = counters.get(current_counter, 0) + packets
                    break
    return counters


def _parse_nft_ruleset_json(text: str) -> tuple:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return 0, 0, 0
    nftables = data.get("nftables", [])
    tables = sum(1 for x in nftables if "table" in x)
    chains = sum(1 for x in nftables if "chain" in x)
    rules = sum(1 for x in nftables if "rule" in x)
    return tables, chains, rules


def _read_cache(path: str, max_age: int | None = None) -> tuple:
    """Return (contents, age_seconds) or (None, None) if unreadable.
    When max_age is given, also return (None, age) if older than that —
    callers can still use the stale contents by reading the file again
    with max_age=None."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None, None
    age = time.time() - st.st_mtime
    if max_age is not None and age > max_age:
        return None, age
    try:
        with open(path, "r") as f:
            return f.read(), age
    except OSError:
        return None, age


def _nft_realtime(args: list) -> str | None:
    """Run `sudo /usr/sbin/nft <args>` with a tight timeout. Returns
    stdout on success, None on any failure (including the silent
    failure that happens when the hub runs under NoNewPrivileges=true,
    which blocks setuid traversal so sudo itself can never elevate).

    The sudoers fragment shipped by this package whitelists `nft list *`
    for user secubox — useful if the operator ever decides to drop the
    NoNewPrivileges sandbox; harmless otherwise."""
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/sbin/nft"] + args,
            capture_output=True, text=True, timeout=3,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return r.stdout


def _trigger_cache_refresh() -> None:
    """Fire-and-forget systemctl start of the cache populator. Used
    when we just served a realtime response so the next request lands
    on a hot cache. The hub runs as user `secubox`; the sudoers
    fragment shipped by this package whitelists the start of this one
    specific unit, password-less."""
    try:
        subprocess.Popen(
            ["sudo", "-n", "/usr/bin/systemctl", "--no-block", "start",
             "secubox-nft-cache.service"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError):
        pass


@public_router.get("/firewall_summary")
def firewall_summary():
    """nftables stats for the SOC dashboard widget.

    Strategy: fresh cache → realtime → stale cache.

    1. If the cache files are fresh (mtime within NFT_CACHE_MAX_AGE),
       parse them — fast path, no privileged calls.
    2. Otherwise try realtime via `sudo nft list ...`. This works ONLY
       if the hub is not sandboxed by NoNewPrivileges; on the shipped
       systemd unit it is, so realtime is best-effort.
    3. If realtime returned nothing, fall back to the *stale* cache —
       showing slightly old data is far better than zeros on the SOC
       widget. The systemd timer will refresh the cache shortly.

    `source` in the response tells the frontend which path we took:
    "cache", "realtime", "cache-stale", or "none"."""
    try:
        ruleset_path = os.path.join(NFT_CACHE_DIR, "nft-ruleset.json")
        counters_path = os.path.join(NFT_CACHE_DIR, "nft-counters.txt")
        lastrun_path = os.path.join(NFT_CACHE_DIR, "nft-cache.lastrun")

        ruleset_text, _ = _read_cache(ruleset_path, NFT_CACHE_MAX_AGE)
        counters_text, _ = _read_cache(counters_path, NFT_CACHE_MAX_AGE)

        source = "cache"
        if ruleset_text is None or counters_text is None:
            source = "realtime"
            # `-j` is a global option for nft and must come before the
            # command. The sudoers fragment shipped by this package
            # whitelists both `nft list *` and `nft -j list *` — useful
            # if the operator drops NoNewPrivileges from the hub unit.
            rt_ruleset = _nft_realtime(["-j", "list", "ruleset"])
            rt_counters = _nft_realtime(["list", "counters"])
            if rt_ruleset is not None:
                ruleset_text = rt_ruleset
            if rt_counters is not None:
                counters_text = rt_counters
            _trigger_cache_refresh()

            # Realtime denied (NoNewPrivileges blocks sudo) — fall back
            # to the stale cache rather than returning zeros. The timer
            # will refresh the cache to a fresh state within ~30 s.
            if ruleset_text is None:
                ruleset_text, _ = _read_cache(ruleset_path)
                if ruleset_text:
                    source = "cache-stale"
            if counters_text is None:
                counters_text, _ = _read_cache(counters_path)
                if counters_text and source != "cache-stale":
                    source = "cache-stale"

            if ruleset_text is None and counters_text is None:
                source = "none"

        tables = chains = rules = 0
        if ruleset_text:
            tables, chains, rules = _parse_nft_ruleset_json(ruleset_text)

        counters = _parse_nft_counters(counters_text) if counters_text else {}
        processed = counters.get("processed", 0)
        dropped = sum(v for k, v in counters.items() if "blacklist" in k.lower())

        # systemd state of nftables.service.
        status = "inactive"
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "nftables.service"],
                capture_output=True, text=True, timeout=2,
            )
            if r.stdout.strip() == "active":
                status = "active"
        except Exception:
            pass
        # Rules in the kernel but systemd inactive (e.g. firstboot
        # loaded them with `nft -f`) — surface as active for the widget.
        if status == "inactive" and rules > 0:
            status = "active-manual"

        last_cache_run = None
        try:
            with open(lastrun_path, "r") as f:
                last_cache_run = f.read().strip()
        except FileNotFoundError:
            pass

        return {
            "status": status,
            "tables": tables,
            "chains": chains,
            "rules": rules,
            "processed": processed,
            "dropped": dropped,
            "accepted": processed - dropped if processed > dropped else 0,
            "counters": counters,
            "cache_last_run": last_cache_run,
            "source": source,
        }
    except Exception as e:
        return {"error": str(e), "status": "error", "tables": 0, "chains": 0, "rules": 0, "dropped": 0, "accepted": 0, "processed": 0}


app.include_router(public_router)  # Re-include for firewall_summary
