"""
SecuBox-Deb :: MQTT Broker Management
CyberMind — https://cybermind.fr
Author: Gerald Kerma <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

MQTT broker (Mosquitto) management module with:
- Broker status and health monitoring
- Client management
- Topic tracking
- User/ACL management
- Configuration management
- Real-time statistics
"""

import subprocess
import json
import asyncio
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(
    title="secubox-mqtt",
    version="1.0.0",
    root_path="/api/v1/mqtt"
)
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("mqtt")

# Configuration paths
MOSQUITTO_CONF = Path("/etc/mosquitto/mosquitto.conf")
MOSQUITTO_PASSWD = Path("/etc/mosquitto/passwd")
MOSQUITTO_ACL = Path("/etc/mosquitto/acl")
MOSQUITTO_PID = Path("/var/run/mosquitto.pid")
DATA_DIR = Path("/var/lib/secubox/mqtt")
STATS_CACHE_FILE = DATA_DIR / "stats_cache.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# In-memory stats cache
_stats_cache: Dict[str, Any] = {}
_stats_task: Optional[asyncio.Task] = None


# ═══════════════════════════════════════════════════════════════════════════
# Models
# ═══════════════════════════════════════════════════════════════════════════

class MqttUser(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=4)


class MqttAclEntry(BaseModel):
    user: Optional[str] = None  # None = pattern applies to all
    topic: str
    access: str = Field(..., pattern="^(read|write|readwrite|deny)$")


class MqttConfig(BaseModel):
    listener_port: int = Field(default=1883, ge=1, le=65535)
    listener_address: str = "0.0.0.0"
    allow_anonymous: bool = False
    persistence: bool = True
    log_type: str = "all"
    max_connections: int = Field(default=100, ge=1, le=10000)
    max_inflight_messages: int = Field(default=20, ge=1, le=65535)
    max_queued_messages: int = Field(default=1000, ge=0, le=100000)


# ═══════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════

def _service_active(service: str) -> bool:
    """Check if a systemd service is active."""
    result = subprocess.run(
        ["systemctl", "is-active", service],
        capture_output=True, text=True
    )
    return result.stdout.strip() == "active"


def _service_enabled(service: str) -> bool:
    """Check if a systemd service is enabled."""
    result = subprocess.run(
        ["systemctl", "is-enabled", service],
        capture_output=True, text=True
    )
    return result.stdout.strip() == "enabled"


def _service_control(service: str, action: str) -> dict:
    """Control a systemd service."""
    if action not in ("start", "stop", "restart", "reload"):
        return {"success": False, "error": "Invalid action"}

    result = subprocess.run(
        ["systemctl", action, service],
        capture_output=True, text=True
    )
    return {
        "success": result.returncode == 0,
        "action": action,
        "service": service,
        "error": result.stderr[:200] if result.returncode != 0 else None
    }


def _get_mosquitto_version() -> str:
    """Get Mosquitto version."""
    try:
        result = subprocess.run(
            ["mosquitto", "-h"],
            capture_output=True, text=True
        )
        # Version is usually in first line
        for line in (result.stdout + result.stderr).splitlines():
            if "mosquitto version" in line.lower():
                return line.strip()
        return "unknown"
    except FileNotFoundError:
        return "not installed"


def _get_client_count() -> int:
    """Get number of connected clients from $SYS topics or logs."""
    # Try mosquitto_sub to get $SYS/broker/clients/connected
    try:
        result = subprocess.run(
            ["mosquitto_sub", "-h", "localhost", "-t", "$SYS/broker/clients/connected",
             "-C", "1", "-W", "2"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0 and result.stdout.strip().isdigit():
            return int(result.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass
    return 0


def _get_message_stats() -> Dict[str, int]:
    """Get message statistics from $SYS topics."""
    stats = {
        "messages_received": 0,
        "messages_sent": 0,
        "bytes_received": 0,
        "bytes_sent": 0,
        "messages_stored": 0,
        "subscriptions": 0
    }

    sys_topics = {
        "$SYS/broker/messages/received": "messages_received",
        "$SYS/broker/messages/sent": "messages_sent",
        "$SYS/broker/bytes/received": "bytes_received",
        "$SYS/broker/bytes/sent": "bytes_sent",
        "$SYS/broker/messages/stored": "messages_stored",
        "$SYS/broker/subscriptions/count": "subscriptions"
    }

    for topic, key in sys_topics.items():
        try:
            result = subprocess.run(
                ["mosquitto_sub", "-h", "localhost", "-t", topic, "-C", "1", "-W", "2"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    stats[key] = int(result.stdout.strip())
                except ValueError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return stats


def _parse_mosquitto_conf() -> Dict[str, Any]:
    """Parse mosquitto.conf into a dictionary."""
    config = {
        "listener_port": 1883,
        "listener_address": "0.0.0.0",
        "allow_anonymous": False,
        "persistence": True,
        "log_type": "all",
        "max_connections": 100,
        "max_inflight_messages": 20,
        "max_queued_messages": 1000,
        "password_file": None,
        "acl_file": None,
    }

    if not MOSQUITTO_CONF.exists():
        return config

    try:
        content = MOSQUITTO_CONF.read_text()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if " " in line:
                key, value = line.split(None, 1)
                key = key.lower()

                if key == "listener":
                    parts = value.split()
                    config["listener_port"] = int(parts[0])
                    if len(parts) > 1:
                        config["listener_address"] = parts[1]
                elif key == "allow_anonymous":
                    config["allow_anonymous"] = value.lower() == "true"
                elif key == "persistence":
                    config["persistence"] = value.lower() == "true"
                elif key == "log_type":
                    config["log_type"] = value
                elif key == "max_connections":
                    config["max_connections"] = int(value)
                elif key == "max_inflight_messages":
                    config["max_inflight_messages"] = int(value)
                elif key == "max_queued_messages":
                    config["max_queued_messages"] = int(value)
                elif key == "password_file":
                    config["password_file"] = value
                elif key == "acl_file":
                    config["acl_file"] = value
    except Exception as e:
        log.error(f"Error parsing mosquitto.conf: {e}")

    return config


def _write_mosquitto_conf(config: MqttConfig) -> bool:
    """Write mosquitto.conf from model."""
    try:
        lines = [
            "# Mosquitto configuration - managed by SecuBox",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            f"listener {config.listener_port} {config.listener_address}",
            f"allow_anonymous {'true' if config.allow_anonymous else 'false'}",
            f"persistence {'true' if config.persistence else 'false'}",
            f"persistence_location /var/lib/mosquitto/",
            f"log_type {config.log_type}",
            f"max_connections {config.max_connections}",
            f"max_inflight_messages {config.max_inflight_messages}",
            f"max_queued_messages {config.max_queued_messages}",
            "",
            "# Authentication",
            f"password_file {MOSQUITTO_PASSWD}",
            f"acl_file {MOSQUITTO_ACL}",
            "",
            "# System topics",
            "sys_interval 10",
        ]

        MOSQUITTO_CONF.write_text("\n".join(lines) + "\n")
        return True
    except Exception as e:
        log.error(f"Error writing mosquitto.conf: {e}")
        return False


def _get_users() -> List[str]:
    """Get list of MQTT users from password file."""
    users = []
    if MOSQUITTO_PASSWD.exists():
        try:
            content = MOSQUITTO_PASSWD.read_text()
            for line in content.splitlines():
                if ":" in line:
                    username = line.split(":")[0]
                    if username:
                        users.append(username)
        except Exception:
            pass
    return users


def _add_user(username: str, password: str) -> bool:
    """Add MQTT user using mosquitto_passwd."""
    try:
        # Create file if it doesn't exist
        if not MOSQUITTO_PASSWD.exists():
            MOSQUITTO_PASSWD.touch()

        result = subprocess.run(
            ["mosquitto_passwd", "-b", str(MOSQUITTO_PASSWD), username, password],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        log.error("mosquitto_passwd not found")
        return False


def _delete_user(username: str) -> bool:
    """Delete MQTT user using mosquitto_passwd."""
    try:
        result = subprocess.run(
            ["mosquitto_passwd", "-D", str(MOSQUITTO_PASSWD), username],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def _get_acl() -> List[Dict[str, str]]:
    """Parse ACL file into list of entries."""
    entries = []
    if not MOSQUITTO_ACL.exists():
        return entries

    try:
        content = MOSQUITTO_ACL.read_text()
        current_user = None

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("user "):
                current_user = line.split(None, 1)[1]
            elif line.startswith("pattern "):
                # Pattern applies to current user or all if none set
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    access = parts[1] if parts[1] in ("read", "write", "readwrite", "deny") else "readwrite"
                    topic = parts[2] if len(parts) > 2 else parts[1]
                    entries.append({
                        "user": current_user,
                        "type": "pattern",
                        "access": access,
                        "topic": topic
                    })
            elif line.startswith("topic "):
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    access = parts[1] if parts[1] in ("read", "write", "readwrite", "deny") else "readwrite"
                    topic = parts[2] if len(parts) > 2 else parts[1]
                    entries.append({
                        "user": current_user,
                        "type": "topic",
                        "access": access,
                        "topic": topic
                    })
    except Exception as e:
        log.error(f"Error parsing ACL: {e}")

    return entries


def _write_acl(entries: List[Dict[str, str]]) -> bool:
    """Write ACL file from list of entries."""
    try:
        lines = [
            "# Mosquitto ACL - managed by SecuBox",
            f"# Generated: {datetime.now().isoformat()}",
            ""
        ]

        # Group by user
        by_user: Dict[Optional[str], List[Dict]] = {}
        for entry in entries:
            user = entry.get("user")
            if user not in by_user:
                by_user[user] = []
            by_user[user].append(entry)

        # Write global rules first (user = None)
        if None in by_user:
            lines.append("# Global rules")
            for entry in by_user[None]:
                entry_type = entry.get("type", "topic")
                access = entry.get("access", "readwrite")
                topic = entry.get("topic", "#")
                lines.append(f"{entry_type} {access} {topic}")
            lines.append("")
            del by_user[None]

        # Write per-user rules
        for user, user_entries in by_user.items():
            lines.append(f"user {user}")
            for entry in user_entries:
                entry_type = entry.get("type", "topic")
                access = entry.get("access", "readwrite")
                topic = entry.get("topic", "#")
                lines.append(f"{entry_type} {access} {topic}")
            lines.append("")

        MOSQUITTO_ACL.write_text("\n".join(lines))
        return True
    except Exception as e:
        log.error(f"Error writing ACL: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Background Stats Collection
# ═══════════════════════════════════════════════════════════════════════════

async def _refresh_stats_cache():
    """Background task to refresh stats cache."""
    global _stats_cache

    while True:
        try:
            running = _service_active("mosquitto")

            stats = {
                "running": running,
                "clients": 0,
                "messages": {},
                "timestamp": datetime.now().isoformat()
            }

            if running:
                stats["clients"] = _get_client_count()
                stats["messages"] = _get_message_stats()

            _stats_cache = stats

            # Persist to file
            try:
                STATS_CACHE_FILE.write_text(json.dumps(stats, indent=2))
            except Exception:
                pass

        except Exception as e:
            log.error(f"Stats refresh error: {e}")

        await asyncio.sleep(60)


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _stats_task
    _stats_task = asyncio.create_task(_refresh_stats_cache())
    log.info("SecuBox MQTT API started")


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _stats_task
    if _stats_task:
        _stats_task.cancel()


# ═══════════════════════════════════════════════════════════════════════════
# API Endpoints - Status & Health
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/status")
async def get_status():
    """Get MQTT broker status."""
    running = _service_active("mosquitto")
    enabled = _service_enabled("mosquitto")
    version = _get_mosquitto_version()

    status = {
        "running": running,
        "enabled": enabled,
        "version": version,
        "clients": 0,
        "messages_received": 0,
        "messages_sent": 0,
    }

    if running:
        if _stats_cache:
            status["clients"] = _stats_cache.get("clients", 0)
            messages = _stats_cache.get("messages", {})
            status["messages_received"] = messages.get("messages_received", 0)
            status["messages_sent"] = messages.get("messages_sent", 0)
        else:
            status["clients"] = _get_client_count()
            msg_stats = _get_message_stats()
            status["messages_received"] = msg_stats.get("messages_received", 0)
            status["messages_sent"] = msg_stats.get("messages_sent", 0)

    return status


@router.get("/health")
async def health():
    """Health check endpoint."""
    running = _service_active("mosquitto")
    return {
        "status": "ok" if running else "degraded",
        "module": "mqtt",
        "version": "1.0.0",
        "running": running
    }


# ═══════════════════════════════════════════════════════════════════════════
# API Endpoints - Clients & Topics
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/clients")
async def get_clients(user=Depends(require_jwt)):
    """Get connected MQTT clients list."""
    if not _service_active("mosquitto"):
        return {"clients": [], "error": "Broker not running"}

    clients = []

    # Get clients from $SYS topics
    try:
        # Get connected clients count
        count = _get_client_count()

        # Try to get more info from logs or $SYS
        result = subprocess.run(
            ["journalctl", "-u", "mosquitto", "-n", "100", "--no-pager", "-o", "cat"],
            capture_output=True, text=True, timeout=5
        )

        # Parse connection logs for client info
        client_pattern = re.compile(r"New connection from (\S+) on port \d+")
        client_ids = set()

        for line in result.stdout.splitlines():
            match = client_pattern.search(line)
            if match:
                client_ids.add(match.group(1))

        # Build client list from recent connections
        for i, client_ip in enumerate(list(client_ids)[:50]):
            clients.append({
                "id": f"client_{i}",
                "address": client_ip,
                "connected": True,
                "protocol": "mqtt"
            })

    except Exception as e:
        log.error(f"Error getting clients: {e}")

    return {
        "clients": clients,
        "total": len(clients),
        "connected_count": _get_client_count()
    }


@router.get("/topics")
async def get_topics(user=Depends(require_jwt)):
    """Get active MQTT topics."""
    if not _service_active("mosquitto"):
        return {"topics": [], "error": "Broker not running"}

    topics = []

    # Get topics from $SYS
    sys_topics = [
        "$SYS/broker/version",
        "$SYS/broker/uptime",
        "$SYS/broker/clients/connected",
        "$SYS/broker/clients/total",
        "$SYS/broker/messages/received",
        "$SYS/broker/messages/sent",
        "$SYS/broker/subscriptions/count",
    ]

    for topic in sys_topics:
        try:
            result = subprocess.run(
                ["mosquitto_sub", "-h", "localhost", "-t", topic, "-C", "1", "-W", "2"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                topics.append({
                    "name": topic,
                    "type": "system",
                    "last_value": result.stdout.strip(),
                    "retained": True
                })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    return {
        "topics": topics,
        "total": len(topics),
        "note": "Shows $SYS topics. User topics are not tracked without wildcard subscription."
    }


# ═══════════════════════════════════════════════════════════════════════════
# API Endpoints - Statistics
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    """Get detailed MQTT broker statistics."""
    if not _service_active("mosquitto"):
        return {
            "running": False,
            "error": "Broker not running"
        }

    # Use cache if available
    if _stats_cache:
        return _stats_cache

    # Otherwise collect fresh
    stats = {
        "running": True,
        "clients": _get_client_count(),
        "messages": _get_message_stats(),
        "timestamp": datetime.now().isoformat()
    }

    return stats


# ═══════════════════════════════════════════════════════════════════════════
# API Endpoints - Service Control
# ═══════════════════════════════════════════════════════════════════════════

@router.post("/start")
async def start_broker(user=Depends(require_jwt)):
    """Start Mosquitto broker."""
    log.info(f"Starting mosquitto (user: {user})")
    return _service_control("mosquitto", "start")


@router.post("/stop")
async def stop_broker(user=Depends(require_jwt)):
    """Stop Mosquitto broker."""
    log.info(f"Stopping mosquitto (user: {user})")
    return _service_control("mosquitto", "stop")


@router.post("/restart")
async def restart_broker(user=Depends(require_jwt)):
    """Restart Mosquitto broker."""
    log.info(f"Restarting mosquitto (user: {user})")
    return _service_control("mosquitto", "restart")


# ═══════════════════════════════════════════════════════════════════════════
# API Endpoints - Configuration
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/config")
async def get_config_endpoint(user=Depends(require_jwt)):
    """Get Mosquitto configuration."""
    config = _parse_mosquitto_conf()
    return {
        "config": config,
        "config_file": str(MOSQUITTO_CONF),
        "exists": MOSQUITTO_CONF.exists()
    }


@router.post("/config")
async def update_config(config: MqttConfig, user=Depends(require_jwt)):
    """Update Mosquitto configuration."""
    log.info(f"Updating mosquitto config (user: {user})")

    # Backup existing config
    if MOSQUITTO_CONF.exists():
        backup_path = MOSQUITTO_CONF.with_suffix(f".conf.{datetime.now().strftime('%Y%m%d%H%M%S')}")
        try:
            backup_path.write_text(MOSQUITTO_CONF.read_text())
        except Exception:
            pass

    success = _write_mosquitto_conf(config)

    if success:
        # Reload mosquitto
        reload_result = _service_control("mosquitto", "reload")
        return {
            "success": True,
            "config": config.model_dump(),
            "reload": reload_result
        }

    return {
        "success": False,
        "error": "Failed to write configuration"
    }


# ═══════════════════════════════════════════════════════════════════════════
# API Endpoints - User Management
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/users")
async def list_users(user=Depends(require_jwt)):
    """List MQTT users."""
    users = _get_users()
    return {
        "users": [{"username": u, "enabled": True} for u in users],
        "total": len(users),
        "password_file": str(MOSQUITTO_PASSWD)
    }


@router.post("/users")
async def add_user_endpoint(mqtt_user: MqttUser, user=Depends(require_jwt)):
    """Add MQTT user."""
    log.info(f"Adding MQTT user: {mqtt_user.username} (by: {user})")

    existing = _get_users()
    if mqtt_user.username in existing:
        raise HTTPException(400, f"User {mqtt_user.username} already exists")

    success = _add_user(mqtt_user.username, mqtt_user.password)

    if success:
        # Reload mosquitto to pick up new user
        _service_control("mosquitto", "reload")
        return {
            "success": True,
            "username": mqtt_user.username,
            "message": "User created successfully"
        }

    raise HTTPException(500, "Failed to create user")


@router.delete("/users/{username}")
async def delete_user_endpoint(username: str, user=Depends(require_jwt)):
    """Delete MQTT user."""
    log.info(f"Deleting MQTT user: {username} (by: {user})")

    existing = _get_users()
    if username not in existing:
        raise HTTPException(404, f"User {username} not found")

    success = _delete_user(username)

    if success:
        # Reload mosquitto
        _service_control("mosquitto", "reload")
        return {
            "success": True,
            "username": username,
            "message": "User deleted successfully"
        }

    raise HTTPException(500, "Failed to delete user")


# ═══════════════════════════════════════════════════════════════════════════
# API Endpoints - ACL Management
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/acl")
async def get_acl_endpoint(user=Depends(require_jwt)):
    """Get MQTT access control list."""
    entries = _get_acl()
    return {
        "entries": entries,
        "total": len(entries),
        "acl_file": str(MOSQUITTO_ACL)
    }


@router.post("/acl")
async def update_acl(entry: MqttAclEntry, user=Depends(require_jwt)):
    """Add or update ACL entry."""
    log.info(f"Updating ACL: {entry.topic} (by: {user})")

    entries = _get_acl()

    # Add new entry
    entries.append({
        "user": entry.user,
        "type": "topic",
        "access": entry.access,
        "topic": entry.topic
    })

    success = _write_acl(entries)

    if success:
        # Reload mosquitto
        _service_control("mosquitto", "reload")
        return {
            "success": True,
            "entry": entry.model_dump(),
            "message": "ACL updated successfully"
        }

    raise HTTPException(500, "Failed to update ACL")


@router.delete("/acl")
async def delete_acl_entry(topic: str, acl_user: Optional[str] = Query(None), user=Depends(require_jwt)):
    """Delete ACL entry."""
    log.info(f"Deleting ACL entry: {topic} for user {acl_user} (by: {user})")

    entries = _get_acl()
    original_count = len(entries)

    # Filter out matching entry
    entries = [e for e in entries if not (e.get("topic") == topic and e.get("user") == acl_user)]

    if len(entries) == original_count:
        raise HTTPException(404, "ACL entry not found")

    success = _write_acl(entries)

    if success:
        _service_control("mosquitto", "reload")
        return {
            "success": True,
            "message": "ACL entry deleted"
        }

    raise HTTPException(500, "Failed to update ACL")


# ═══════════════════════════════════════════════════════════════════════════
# API Endpoints - Logs
# ═══════════════════════════════════════════════════════════════════════════

@router.get("/logs")
async def get_logs(lines: int = Query(default=50, le=500), user=Depends(require_jwt)):
    """Get Mosquitto logs."""
    try:
        result = subprocess.run(
            ["journalctl", "-u", "mosquitto", "-n", str(lines), "--no-pager"],
            capture_output=True, text=True, timeout=10
        )
        return {
            "lines": result.stdout.splitlines(),
            "total": len(result.stdout.splitlines())
        }
    except Exception as e:
        return {"error": str(e), "lines": []}


# Include router
app.include_router(router)
