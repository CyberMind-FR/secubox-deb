"""secubox-picobrew — FastAPI application for Homebrew/Fermentation Controller.

SecuBox-Deb :: PicoBrew Controller
CyberMind — https://cybermind.fr
Author: Gerald Kerma <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Provides temperature monitoring, fermentation profiles, session logging,
recipe management, and alerts for temperature deviations.
"""
import asyncio
import json
import subprocess
import glob
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
import uuid

from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-picobrew", version="1.0.0", root_path="/api/v1/picobrew")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("picobrew")

# Configuration paths
CONFIG_FILE = Path("/etc/secubox/picobrew.toml")
DATA_PATH = Path("/var/lib/secubox/picobrew")
CACHE_FILE = Path("/var/cache/secubox/picobrew/sensors.json")

DEFAULT_CONFIG = {
    "poll_interval": 30,  # seconds
    "temp_unit": "C",     # C or F
    "alert_threshold": 2.0,  # degrees deviation before alert
    "sensor_types": ["ds18b20", "dht22", "bme280"],
}


# ============================================================================
# Models
# ============================================================================

class TempUnit(str, Enum):
    CELSIUS = "C"
    FAHRENHEIT = "F"


class SensorType(str, Enum):
    DS18B20 = "ds18b20"
    DHT22 = "dht22"
    BME280 = "bme280"
    TILT = "tilt"
    ISPINDEL = "ispindel"
    MANUAL = "manual"


class SensorReading(BaseModel):
    sensor_id: str
    sensor_type: SensorType
    temperature: float
    humidity: Optional[float] = None
    gravity: Optional[float] = None
    battery: Optional[float] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class Sensor(BaseModel):
    id: str
    name: str
    type: SensorType
    address: Optional[str] = None  # Hardware address for 1-wire, BLE MAC for Tilt
    enabled: bool = True
    calibration_offset: float = 0.0
    last_reading: Optional[SensorReading] = None


class ProfileStep(BaseModel):
    day: int
    target_temp: float
    ramp_time: int = 0  # hours to reach target


class FermentationProfile(BaseModel):
    name: str
    description: Optional[str] = ""
    steps: List[ProfileStep]
    created: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class BrewSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str
    recipe_name: Optional[str] = None
    profile_name: Optional[str] = None
    sensor_id: Optional[str] = None
    start_time: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: Optional[str] = None
    status: str = "active"  # active, completed, aborted
    notes: Optional[str] = ""
    og: Optional[float] = None  # Original gravity
    fg: Optional[float] = None  # Final gravity
    readings: List[SensorReading] = []


class Recipe(BaseModel):
    name: str
    style: Optional[str] = ""
    og_target: Optional[float] = None
    fg_target: Optional[float] = None
    fermentation_profile: Optional[str] = None
    ingredients: Optional[str] = ""
    instructions: Optional[str] = ""
    created: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    session_id: Optional[str] = None
    sensor_id: str
    alert_type: str  # temp_high, temp_low, sensor_offline, battery_low
    message: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    acknowledged: bool = False


class PicobrewConfig(BaseModel):
    poll_interval: int = 30
    temp_unit: TempUnit = TempUnit.CELSIUS
    alert_threshold: float = 2.0


class AddProfileRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    steps: List[ProfileStep]


class AddRecipeRequest(BaseModel):
    name: str
    style: Optional[str] = ""
    og_target: Optional[float] = None
    fg_target: Optional[float] = None
    fermentation_profile: Optional[str] = None
    ingredients: Optional[str] = ""
    instructions: Optional[str] = ""


class StartSessionRequest(BaseModel):
    name: str
    recipe_name: Optional[str] = None
    profile_name: Optional[str] = None
    sensor_id: Optional[str] = None
    og: Optional[float] = None
    notes: Optional[str] = ""


# ============================================================================
# Storage Helpers
# ============================================================================

def ensure_data_dirs():
    """Ensure data directories exist."""
    for subdir in ["sensors", "profiles", "sessions", "recipes", "alerts"]:
        (DATA_PATH / subdir).mkdir(parents=True, exist_ok=True)
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)


def get_config() -> dict:
    """Load picobrew configuration."""
    if CONFIG_FILE.exists():
        try:
            import tomllib
            return tomllib.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def load_json_file(path: Path) -> dict:
    """Load a JSON file."""
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {}


def save_json_file(path: Path, data: dict):
    """Save data to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def list_json_files(directory: Path) -> List[dict]:
    """List all JSON files in a directory."""
    items = []
    if directory.exists():
        for f in directory.glob("*.json"):
            try:
                items.append(json.loads(f.read_text()))
            except Exception:
                pass
    return items


# ============================================================================
# Sensor Detection & Reading
# ============================================================================

def detect_1wire_sensors() -> List[dict]:
    """Detect DS18B20 1-wire temperature sensors."""
    sensors = []
    w1_path = Path("/sys/bus/w1/devices")
    if w1_path.exists():
        for device in w1_path.glob("28-*"):
            sensor_id = device.name
            sensors.append({
                "id": sensor_id,
                "type": "ds18b20",
                "address": sensor_id,
                "path": str(device / "w1_slave")
            })
    return sensors


def read_ds18b20(device_path: str) -> Optional[float]:
    """Read temperature from DS18B20 sensor."""
    try:
        path = Path(device_path)
        if path.exists():
            content = path.read_text()
            if "YES" in content:
                temp_str = content.split("t=")[-1].strip()
                return float(temp_str) / 1000.0
    except Exception:
        pass
    return None


def detect_i2c_sensors() -> List[dict]:
    """Detect I2C sensors (BME280, etc.)."""
    sensors = []
    # Check for i2c devices
    i2c_path = Path("/sys/bus/i2c/devices")
    if i2c_path.exists():
        # BME280 typically at address 0x76 or 0x77
        for addr in ["0076", "0077"]:
            for bus in i2c_path.glob(f"*-{addr}"):
                sensors.append({
                    "id": f"bme280-{addr}",
                    "type": "bme280",
                    "address": f"0x{addr}",
                    "bus": bus.name.split("-")[0]
                })
    return sensors


def detect_usb_sensors() -> List[dict]:
    """Detect USB temperature sensors."""
    sensors = []
    # Look for common USB temperature loggers
    for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*"]:
        for path in glob.glob(pattern):
            # Could be a USB temperature sensor
            sensors.append({
                "id": f"usb-{Path(path).name}",
                "type": "manual",
                "address": path
            })
    return sensors


async def read_all_sensors() -> List[SensorReading]:
    """Read all configured sensors."""
    readings = []
    sensors_dir = DATA_PATH / "sensors"

    for sensor_file in sensors_dir.glob("*.json"):
        try:
            sensor = json.loads(sensor_file.read_text())
            if not sensor.get("enabled", True):
                continue

            reading = None
            if sensor["type"] == "ds18b20":
                w1_path = f"/sys/bus/w1/devices/{sensor['address']}/w1_slave"
                temp = read_ds18b20(w1_path)
                if temp is not None:
                    temp += sensor.get("calibration_offset", 0.0)
                    reading = SensorReading(
                        sensor_id=sensor["id"],
                        sensor_type=SensorType.DS18B20,
                        temperature=temp
                    )
            elif sensor["type"] == "manual":
                # Manual sensors use last stored reading
                if sensor.get("last_reading"):
                    reading = SensorReading(**sensor["last_reading"])

            if reading:
                readings.append(reading)
        except Exception as e:
            log.error(f"Error reading sensor {sensor_file.name}: {e}")

    return readings


# ============================================================================
# Background Cache Refresh
# ============================================================================

_cache: dict = {"sensors": [], "last_update": None}


async def refresh_cache():
    """Background task to refresh sensor cache."""
    ensure_data_dirs()
    while True:
        try:
            readings = await read_all_sensors()
            _cache["sensors"] = [r.model_dump() for r in readings]
            _cache["last_update"] = datetime.utcnow().isoformat()

            # Save to file cache
            save_json_file(CACHE_FILE, _cache)

            # Check for alerts
            await check_alerts(readings)

            # Log readings to active sessions
            await log_session_readings(readings)

        except Exception as e:
            log.error(f"Cache refresh failed: {e}")

        config = get_config()
        await asyncio.sleep(config.get("poll_interval", 30))


async def check_alerts(readings: List[SensorReading]):
    """Check readings against active session targets and generate alerts."""
    config = get_config()
    threshold = config.get("alert_threshold", 2.0)

    sessions = list_json_files(DATA_PATH / "sessions")
    active_sessions = [s for s in sessions if s.get("status") == "active"]

    for session in active_sessions:
        if not session.get("profile_name") or not session.get("sensor_id"):
            continue

        # Load profile
        profile_file = DATA_PATH / "profiles" / f"{session['profile_name']}.json"
        if not profile_file.exists():
            continue

        profile = json.loads(profile_file.read_text())

        # Calculate current target temp based on session start and profile
        start = datetime.fromisoformat(session["start_time"])
        days_elapsed = (datetime.utcnow() - start).days

        target_temp = None
        for step in sorted(profile.get("steps", []), key=lambda s: s["day"]):
            if step["day"] <= days_elapsed:
                target_temp = step["target_temp"]

        if target_temp is None:
            continue

        # Find reading for this session's sensor
        for reading in readings:
            if reading.sensor_id == session["sensor_id"]:
                deviation = abs(reading.temperature - target_temp)
                if deviation > threshold:
                    alert_type = "temp_high" if reading.temperature > target_temp else "temp_low"
                    alert = Alert(
                        session_id=session["id"],
                        sensor_id=reading.sensor_id,
                        alert_type=alert_type,
                        message=f"Temperature {reading.temperature:.1f} is {deviation:.1f} degrees from target {target_temp:.1f}"
                    )
                    # Save alert
                    alert_file = DATA_PATH / "alerts" / f"{alert.id}.json"
                    save_json_file(alert_file, alert.model_dump())
                    log.warning(f"Alert: {alert.message}")


async def log_session_readings(readings: List[SensorReading]):
    """Log readings to active sessions."""
    sessions_dir = DATA_PATH / "sessions"

    for session_file in sessions_dir.glob("*.json"):
        try:
            session = json.loads(session_file.read_text())
            if session.get("status") != "active":
                continue

            sensor_id = session.get("sensor_id")
            if not sensor_id:
                continue

            for reading in readings:
                if reading.sensor_id == sensor_id:
                    # Append reading to session
                    if "readings" not in session:
                        session["readings"] = []
                    session["readings"].append(reading.model_dump())

                    # Keep only last 1000 readings to prevent file bloat
                    if len(session["readings"]) > 1000:
                        session["readings"] = session["readings"][-1000:]

                    save_json_file(session_file, session)
                    break
        except Exception as e:
            log.error(f"Error logging to session {session_file.name}: {e}")


@app.on_event("startup")
async def startup():
    """Start background tasks."""
    ensure_data_dirs()
    asyncio.create_task(refresh_cache())


# ============================================================================
# Public Endpoints (no auth required)
# ============================================================================

@router.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "picobrew"}


@router.get("/status")
async def status():
    """Get overall system status."""
    config = get_config()

    # Count entities
    sensors = list_json_files(DATA_PATH / "sensors")
    sessions = list_json_files(DATA_PATH / "sessions")
    active_sessions = [s for s in sessions if s.get("status") == "active"]
    profiles = list_json_files(DATA_PATH / "profiles")
    recipes = list_json_files(DATA_PATH / "recipes")
    alerts = list_json_files(DATA_PATH / "alerts")
    unack_alerts = [a for a in alerts if not a.get("acknowledged", False)]

    # Get latest readings from cache
    latest_readings = []
    if CACHE_FILE.exists():
        cache_data = load_json_file(CACHE_FILE)
        latest_readings = cache_data.get("sensors", [])

    return {
        "running": True,
        "sensor_count": len(sensors),
        "active_sessions": len(active_sessions),
        "profile_count": len(profiles),
        "recipe_count": len(recipes),
        "unread_alerts": len(unack_alerts),
        "poll_interval": config.get("poll_interval", 30),
        "temp_unit": config.get("temp_unit", "C"),
        "last_reading": _cache.get("last_update"),
        "latest_readings": latest_readings[:5]  # Last 5 readings
    }


# ============================================================================
# Sensor Endpoints
# ============================================================================

@router.get("/sensors")
async def get_sensors(user=Depends(require_jwt)):
    """Get list of all configured sensors."""
    sensors = list_json_files(DATA_PATH / "sensors")

    # Add latest readings
    cache_data = load_json_file(CACHE_FILE) if CACHE_FILE.exists() else {}
    readings_map = {r["sensor_id"]: r for r in cache_data.get("sensors", [])}

    for sensor in sensors:
        sensor["last_reading"] = readings_map.get(sensor["id"])

    return {"sensors": sensors}


@router.get("/sensors/detect")
async def detect_sensors(user=Depends(require_jwt)):
    """Detect available hardware sensors."""
    detected = []

    # 1-wire (DS18B20)
    detected.extend(detect_1wire_sensors())

    # I2C (BME280, etc.)
    detected.extend(detect_i2c_sensors())

    # USB
    detected.extend(detect_usb_sensors())

    return {"detected": detected}


@router.post("/sensors")
async def add_sensor(sensor: Sensor, user=Depends(require_jwt)):
    """Add a new sensor."""
    ensure_data_dirs()
    sensor_file = DATA_PATH / "sensors" / f"{sensor.id}.json"

    if sensor_file.exists():
        raise HTTPException(400, "Sensor with this ID already exists")

    save_json_file(sensor_file, sensor.model_dump())
    log.info(f"Sensor {sensor.id} added by {user.get('sub', 'unknown')}")

    return {"success": True, "sensor": sensor.model_dump()}


@router.get("/sensors/{sensor_id}")
async def get_sensor(sensor_id: str, user=Depends(require_jwt)):
    """Get sensor details."""
    sensor_file = DATA_PATH / "sensors" / f"{sensor_id}.json"

    if not sensor_file.exists():
        raise HTTPException(404, "Sensor not found")

    sensor = load_json_file(sensor_file)

    # Add latest reading
    cache_data = load_json_file(CACHE_FILE) if CACHE_FILE.exists() else {}
    for r in cache_data.get("sensors", []):
        if r["sensor_id"] == sensor_id:
            sensor["last_reading"] = r
            break

    return sensor


@router.delete("/sensors/{sensor_id}")
async def delete_sensor(sensor_id: str, user=Depends(require_jwt)):
    """Delete a sensor."""
    sensor_file = DATA_PATH / "sensors" / f"{sensor_id}.json"

    if not sensor_file.exists():
        raise HTTPException(404, "Sensor not found")

    sensor_file.unlink()
    log.info(f"Sensor {sensor_id} deleted by {user.get('sub', 'unknown')}")

    return {"success": True}


@router.post("/sensors/{sensor_id}/reading")
async def add_manual_reading(sensor_id: str, temperature: float, humidity: Optional[float] = None,
                             gravity: Optional[float] = None, user=Depends(require_jwt)):
    """Add a manual reading for a sensor."""
    sensor_file = DATA_PATH / "sensors" / f"{sensor_id}.json"

    if not sensor_file.exists():
        raise HTTPException(404, "Sensor not found")

    sensor = load_json_file(sensor_file)

    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=SensorType(sensor.get("type", "manual")),
        temperature=temperature,
        humidity=humidity,
        gravity=gravity
    )

    sensor["last_reading"] = reading.model_dump()
    save_json_file(sensor_file, sensor)

    return {"success": True, "reading": reading.model_dump()}


# ============================================================================
# Profile Endpoints
# ============================================================================

@router.get("/profiles")
async def get_profiles(user=Depends(require_jwt)):
    """Get all fermentation profiles."""
    profiles = list_json_files(DATA_PATH / "profiles")
    return {"profiles": profiles}


@router.get("/profile/{name}")
async def get_profile(name: str, user=Depends(require_jwt)):
    """Get a specific fermentation profile."""
    profile_file = DATA_PATH / "profiles" / f"{name}.json"

    if not profile_file.exists():
        raise HTTPException(404, "Profile not found")

    return load_json_file(profile_file)


@router.post("/profile/add")
async def add_profile(req: AddProfileRequest, user=Depends(require_jwt)):
    """Add a new fermentation profile."""
    ensure_data_dirs()

    # Sanitize name for filename
    safe_name = "".join(c for c in req.name if c.isalnum() or c in "._- ")
    profile_file = DATA_PATH / "profiles" / f"{safe_name}.json"

    profile = FermentationProfile(
        name=req.name,
        description=req.description or "",
        steps=req.steps
    )

    save_json_file(profile_file, profile.model_dump())
    log.info(f"Profile {req.name} added by {user.get('sub', 'unknown')}")

    return {"success": True, "profile": profile.model_dump()}


@router.delete("/profile/{name}")
async def delete_profile(name: str, user=Depends(require_jwt)):
    """Delete a fermentation profile."""
    profile_file = DATA_PATH / "profiles" / f"{name}.json"

    if not profile_file.exists():
        raise HTTPException(404, "Profile not found")

    profile_file.unlink()
    log.info(f"Profile {name} deleted by {user.get('sub', 'unknown')}")

    return {"success": True}


# ============================================================================
# Session Endpoints
# ============================================================================

@router.get("/sessions")
async def get_sessions(status: Optional[str] = None, user=Depends(require_jwt)):
    """Get all brew sessions."""
    sessions = list_json_files(DATA_PATH / "sessions")

    if status:
        sessions = [s for s in sessions if s.get("status") == status]

    # Sort by start time, newest first
    sessions.sort(key=lambda s: s.get("start_time", ""), reverse=True)

    return {"sessions": sessions}


@router.get("/session/{session_id}")
async def get_session(session_id: str, user=Depends(require_jwt)):
    """Get a specific brew session with all readings."""
    session_file = DATA_PATH / "sessions" / f"{session_id}.json"

    if not session_file.exists():
        raise HTTPException(404, "Session not found")

    return load_json_file(session_file)


@router.post("/session/start")
async def start_session(req: StartSessionRequest, user=Depends(require_jwt)):
    """Start a new brew session."""
    ensure_data_dirs()

    session = BrewSession(
        name=req.name,
        recipe_name=req.recipe_name,
        profile_name=req.profile_name,
        sensor_id=req.sensor_id,
        og=req.og,
        notes=req.notes or ""
    )

    session_file = DATA_PATH / "sessions" / f"{session.id}.json"
    save_json_file(session_file, session.model_dump())

    log.info(f"Session {session.id} started by {user.get('sub', 'unknown')}")

    return {"success": True, "session": session.model_dump()}


@router.post("/session/{session_id}/end")
async def end_session(session_id: str, fg: Optional[float] = None,
                      notes: Optional[str] = None, user=Depends(require_jwt)):
    """End a brew session."""
    session_file = DATA_PATH / "sessions" / f"{session_id}.json"

    if not session_file.exists():
        raise HTTPException(404, "Session not found")

    session = load_json_file(session_file)
    session["status"] = "completed"
    session["end_time"] = datetime.utcnow().isoformat()

    if fg is not None:
        session["fg"] = fg
    if notes:
        session["notes"] = (session.get("notes", "") + "\n" + notes).strip()

    save_json_file(session_file, session)
    log.info(f"Session {session_id} ended by {user.get('sub', 'unknown')}")

    return {"success": True, "session": session}


@router.delete("/session/{session_id}")
async def delete_session(session_id: str, user=Depends(require_jwt)):
    """Delete a brew session."""
    session_file = DATA_PATH / "sessions" / f"{session_id}.json"

    if not session_file.exists():
        raise HTTPException(404, "Session not found")

    session_file.unlink()
    log.info(f"Session {session_id} deleted by {user.get('sub', 'unknown')}")

    return {"success": True}


@router.get("/session/{session_id}/readings")
async def get_session_readings(session_id: str,
                               limit: int = Query(100, le=1000),
                               user=Depends(require_jwt)):
    """Get readings for a session (for charting)."""
    session_file = DATA_PATH / "sessions" / f"{session_id}.json"

    if not session_file.exists():
        raise HTTPException(404, "Session not found")

    session = load_json_file(session_file)
    readings = session.get("readings", [])

    # Return last N readings
    return {"readings": readings[-limit:]}


# ============================================================================
# Recipe Endpoints
# ============================================================================

@router.get("/recipes")
async def get_recipes(user=Depends(require_jwt)):
    """Get all recipes."""
    recipes = list_json_files(DATA_PATH / "recipes")
    return {"recipes": recipes}


@router.get("/recipe/{name}")
async def get_recipe(name: str, user=Depends(require_jwt)):
    """Get a specific recipe."""
    # Try exact match first, then fuzzy
    for recipe_file in (DATA_PATH / "recipes").glob("*.json"):
        recipe = load_json_file(recipe_file)
        if recipe.get("name") == name:
            return recipe

    raise HTTPException(404, "Recipe not found")


@router.post("/recipe/add")
async def add_recipe(req: AddRecipeRequest, user=Depends(require_jwt)):
    """Add a new recipe."""
    ensure_data_dirs()

    # Sanitize name for filename
    safe_name = "".join(c for c in req.name if c.isalnum() or c in "._- ")
    recipe_file = DATA_PATH / "recipes" / f"{safe_name}.json"

    recipe = Recipe(
        name=req.name,
        style=req.style,
        og_target=req.og_target,
        fg_target=req.fg_target,
        fermentation_profile=req.fermentation_profile,
        ingredients=req.ingredients,
        instructions=req.instructions
    )

    save_json_file(recipe_file, recipe.model_dump())
    log.info(f"Recipe {req.name} added by {user.get('sub', 'unknown')}")

    return {"success": True, "recipe": recipe.model_dump()}


@router.delete("/recipe/{name}")
async def delete_recipe(name: str, user=Depends(require_jwt)):
    """Delete a recipe."""
    for recipe_file in (DATA_PATH / "recipes").glob("*.json"):
        recipe = load_json_file(recipe_file)
        if recipe.get("name") == name:
            recipe_file.unlink()
            log.info(f"Recipe {name} deleted by {user.get('sub', 'unknown')}")
            return {"success": True}

    raise HTTPException(404, "Recipe not found")


# ============================================================================
# Alert Endpoints
# ============================================================================

@router.get("/alerts")
async def get_alerts(acknowledged: Optional[bool] = None,
                     limit: int = Query(50, le=200),
                     user=Depends(require_jwt)):
    """Get alerts."""
    alerts = list_json_files(DATA_PATH / "alerts")

    if acknowledged is not None:
        alerts = [a for a in alerts if a.get("acknowledged", False) == acknowledged]

    # Sort by timestamp, newest first
    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)

    return {"alerts": alerts[:limit]}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, user=Depends(require_jwt)):
    """Acknowledge an alert."""
    alert_file = DATA_PATH / "alerts" / f"{alert_id}.json"

    if not alert_file.exists():
        raise HTTPException(404, "Alert not found")

    alert = load_json_file(alert_file)
    alert["acknowledged"] = True
    save_json_file(alert_file, alert)

    return {"success": True}


@router.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: str, user=Depends(require_jwt)):
    """Delete an alert."""
    alert_file = DATA_PATH / "alerts" / f"{alert_id}.json"

    if not alert_file.exists():
        raise HTTPException(404, "Alert not found")

    alert_file.unlink()

    return {"success": True}


@router.post("/alerts/clear")
async def clear_alerts(acknowledged_only: bool = True, user=Depends(require_jwt)):
    """Clear alerts."""
    alerts_dir = DATA_PATH / "alerts"
    count = 0

    for alert_file in alerts_dir.glob("*.json"):
        try:
            alert = load_json_file(alert_file)
            if acknowledged_only and not alert.get("acknowledged", False):
                continue
            alert_file.unlink()
            count += 1
        except Exception:
            pass

    log.info(f"Cleared {count} alerts by {user.get('sub', 'unknown')}")
    return {"success": True, "cleared": count}


# ============================================================================
# Configuration Endpoints
# ============================================================================

@router.get("/config")
async def get_picobrew_config(user=Depends(require_jwt)):
    """Get picobrew configuration."""
    return get_config()


@router.post("/config")
async def set_picobrew_config(config: PicobrewConfig, user=Depends(require_jwt)):
    """Update picobrew configuration."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

    content = f"""# PicoBrew Fermentation Controller configuration
poll_interval = {config.poll_interval}
temp_unit = "{config.temp_unit.value}"
alert_threshold = {config.alert_threshold}
"""
    CONFIG_FILE.write_text(content)
    log.info(f"Config updated by {user.get('sub', 'unknown')}")

    return {"success": True}


# ============================================================================
# Built-in Profiles (Common fermentation schedules)
# ============================================================================

BUILTIN_PROFILES = [
    {
        "name": "Ale Standard",
        "description": "Standard ale fermentation at 18-20C",
        "steps": [
            {"day": 0, "target_temp": 18.0, "ramp_time": 0},
            {"day": 3, "target_temp": 19.0, "ramp_time": 12},
            {"day": 7, "target_temp": 20.0, "ramp_time": 24},
            {"day": 14, "target_temp": 4.0, "ramp_time": 48}
        ]
    },
    {
        "name": "Lager Classic",
        "description": "Traditional lager with cold conditioning",
        "steps": [
            {"day": 0, "target_temp": 10.0, "ramp_time": 0},
            {"day": 7, "target_temp": 12.0, "ramp_time": 24},
            {"day": 14, "target_temp": 2.0, "ramp_time": 48},
            {"day": 28, "target_temp": 0.0, "ramp_time": 24}
        ]
    },
    {
        "name": "Belgian Saison",
        "description": "Warm fermentation for Belgian Saison",
        "steps": [
            {"day": 0, "target_temp": 20.0, "ramp_time": 0},
            {"day": 2, "target_temp": 24.0, "ramp_time": 24},
            {"day": 5, "target_temp": 28.0, "ramp_time": 24},
            {"day": 10, "target_temp": 30.0, "ramp_time": 12}
        ]
    },
    {
        "name": "Cold Crash",
        "description": "Quick cold crash for clearing",
        "steps": [
            {"day": 0, "target_temp": 18.0, "ramp_time": 0},
            {"day": 1, "target_temp": 4.0, "ramp_time": 12},
            {"day": 3, "target_temp": 0.0, "ramp_time": 6}
        ]
    }
]


@router.get("/profiles/builtin")
async def get_builtin_profiles(user=Depends(require_jwt)):
    """Get list of built-in fermentation profiles."""
    return {"profiles": BUILTIN_PROFILES}


@router.post("/profiles/import/{name}")
async def import_builtin_profile(name: str, user=Depends(require_jwt)):
    """Import a built-in profile to user profiles."""
    for profile in BUILTIN_PROFILES:
        if profile["name"] == name:
            ensure_data_dirs()
            safe_name = "".join(c for c in name if c.isalnum() or c in "._- ")
            profile_file = DATA_PATH / "profiles" / f"{safe_name}.json"

            profile_data = FermentationProfile(
                name=profile["name"],
                description=profile["description"],
                steps=[ProfileStep(**s) for s in profile["steps"]]
            )

            save_json_file(profile_file, profile_data.model_dump())
            log.info(f"Imported builtin profile {name} by {user.get('sub', 'unknown')}")

            return {"success": True, "profile": profile_data.model_dump()}

    raise HTTPException(404, "Built-in profile not found")


app.include_router(router)
