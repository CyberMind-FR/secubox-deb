"""
SecuBox-Deb :: secubox-nettweak
CyberMind - https://cybermind.fr
Author: Gerald KERMA <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate

Network tuning module - sysctl and TCP/IP stack optimization.
"""
import subprocess
import re
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger

app = FastAPI(title="secubox-nettweak", version="1.0.0", root_path="/api/v1/nettweak")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("nettweak")

# Configuration paths
CONFIG_FILE = Path("/etc/secubox/nettweak.toml")
SYSCTL_CONF = Path("/etc/sysctl.d/90-secubox-nettweak.conf")
DATA_DIR = Path("/var/lib/secubox/nettweak")

# Key sysctl parameters to expose
SYSCTL_PARAMS = {
    # Core network settings
    "net.core.rmem_max": {
        "description": "Maximum receive socket buffer size",
        "category": "net",
        "default": 212992,
        "min": 4096,
        "max": 134217728,
        "unit": "bytes"
    },
    "net.core.wmem_max": {
        "description": "Maximum send socket buffer size",
        "category": "net",
        "default": 212992,
        "min": 4096,
        "max": 134217728,
        "unit": "bytes"
    },
    "net.core.rmem_default": {
        "description": "Default receive socket buffer size",
        "category": "net",
        "default": 212992,
        "min": 4096,
        "max": 134217728,
        "unit": "bytes"
    },
    "net.core.wmem_default": {
        "description": "Default send socket buffer size",
        "category": "net",
        "default": 212992,
        "min": 4096,
        "max": 134217728,
        "unit": "bytes"
    },
    "net.core.netdev_max_backlog": {
        "description": "Maximum number of packets queued on input",
        "category": "net",
        "default": 1000,
        "min": 100,
        "max": 100000,
        "unit": "packets"
    },
    "net.core.somaxconn": {
        "description": "Maximum listen queue size",
        "category": "net",
        "default": 4096,
        "min": 128,
        "max": 65535,
        "unit": "connections"
    },
    "net.core.optmem_max": {
        "description": "Maximum ancillary buffer size",
        "category": "net",
        "default": 20480,
        "min": 4096,
        "max": 1048576,
        "unit": "bytes"
    },
    # TCP settings
    "net.ipv4.tcp_rmem": {
        "description": "TCP receive buffer (min default max)",
        "category": "tcp",
        "default": "4096 131072 6291456",
        "type": "triple",
        "unit": "bytes"
    },
    "net.ipv4.tcp_wmem": {
        "description": "TCP send buffer (min default max)",
        "category": "tcp",
        "default": "4096 16384 4194304",
        "type": "triple",
        "unit": "bytes"
    },
    "net.ipv4.tcp_window_scaling": {
        "description": "Enable TCP window scaling (RFC 1323)",
        "category": "tcp",
        "default": 1,
        "type": "bool"
    },
    "net.ipv4.tcp_timestamps": {
        "description": "Enable TCP timestamps (RFC 1323)",
        "category": "tcp",
        "default": 1,
        "type": "bool"
    },
    "net.ipv4.tcp_sack": {
        "description": "Enable TCP selective acknowledgements",
        "category": "tcp",
        "default": 1,
        "type": "bool"
    },
    "net.ipv4.tcp_fastopen": {
        "description": "TCP Fast Open mode (0=off, 1=client, 2=server, 3=both)",
        "category": "tcp",
        "default": 3,
        "min": 0,
        "max": 3,
        "unit": ""
    },
    "net.ipv4.tcp_fin_timeout": {
        "description": "Time to hold socket in FIN-WAIT-2 state",
        "category": "tcp",
        "default": 60,
        "min": 5,
        "max": 120,
        "unit": "seconds"
    },
    "net.ipv4.tcp_keepalive_time": {
        "description": "Interval before keepalive probes begin",
        "category": "tcp",
        "default": 7200,
        "min": 300,
        "max": 86400,
        "unit": "seconds"
    },
    "net.ipv4.tcp_keepalive_intvl": {
        "description": "Interval between keepalive probes",
        "category": "tcp",
        "default": 75,
        "min": 10,
        "max": 300,
        "unit": "seconds"
    },
    "net.ipv4.tcp_keepalive_probes": {
        "description": "Number of keepalive probes before timeout",
        "category": "tcp",
        "default": 9,
        "min": 1,
        "max": 30,
        "unit": "probes"
    },
    "net.ipv4.tcp_max_syn_backlog": {
        "description": "Maximum SYN backlog queue size",
        "category": "tcp",
        "default": 2048,
        "min": 128,
        "max": 65535,
        "unit": "connections"
    },
    "net.ipv4.tcp_syncookies": {
        "description": "Enable SYN flood protection",
        "category": "tcp",
        "default": 1,
        "type": "bool"
    },
    "net.ipv4.tcp_tw_reuse": {
        "description": "Reuse TIME-WAIT sockets for new connections",
        "category": "tcp",
        "default": 2,
        "min": 0,
        "max": 2,
        "unit": ""
    },
    "net.ipv4.tcp_mtu_probing": {
        "description": "Enable TCP MTU probing",
        "category": "tcp",
        "default": 0,
        "min": 0,
        "max": 2,
        "unit": ""
    },
    "net.ipv4.tcp_slow_start_after_idle": {
        "description": "Slow start after idle period",
        "category": "tcp",
        "default": 1,
        "type": "bool"
    },
    "net.ipv4.tcp_congestion_control": {
        "description": "TCP congestion control algorithm",
        "category": "tcp",
        "default": "cubic",
        "type": "string",
        "options": ["cubic", "reno", "bbr", "htcp", "vegas"]
    },
    # IP settings
    "net.ipv4.ip_forward": {
        "description": "Enable IPv4 forwarding",
        "category": "net",
        "default": 0,
        "type": "bool"
    },
    "net.ipv4.conf.all.rp_filter": {
        "description": "Reverse path filtering (0=off, 1=strict, 2=loose)",
        "category": "net",
        "default": 2,
        "min": 0,
        "max": 2,
        "unit": ""
    },
    "net.ipv4.conf.default.rp_filter": {
        "description": "Default reverse path filtering",
        "category": "net",
        "default": 2,
        "min": 0,
        "max": 2,
        "unit": ""
    },
    "net.ipv4.conf.all.accept_redirects": {
        "description": "Accept ICMP redirects",
        "category": "net",
        "default": 0,
        "type": "bool"
    },
    "net.ipv4.conf.all.send_redirects": {
        "description": "Send ICMP redirects",
        "category": "net",
        "default": 1,
        "type": "bool"
    },
    "net.ipv4.conf.all.accept_source_route": {
        "description": "Accept source routing",
        "category": "net",
        "default": 0,
        "type": "bool"
    },
    "net.ipv4.icmp_echo_ignore_broadcasts": {
        "description": "Ignore ICMP broadcast pings",
        "category": "net",
        "default": 1,
        "type": "bool"
    },
    "net.ipv4.icmp_ignore_bogus_error_responses": {
        "description": "Ignore bogus ICMP error responses",
        "category": "net",
        "default": 1,
        "type": "bool"
    },
    # IPv6 settings
    "net.ipv6.conf.all.forwarding": {
        "description": "Enable IPv6 forwarding",
        "category": "net",
        "default": 0,
        "type": "bool"
    },
    "net.ipv6.conf.all.accept_redirects": {
        "description": "Accept IPv6 ICMP redirects",
        "category": "net",
        "default": 0,
        "type": "bool"
    },
}

# Predefined tuning profiles
PROFILES = {
    "default": {
        "name": "Default",
        "description": "Standard Linux defaults",
        "settings": {}  # Empty = use system defaults
    },
    "performance": {
        "name": "Performance",
        "description": "High throughput for bulk transfers",
        "settings": {
            "net.core.rmem_max": 16777216,
            "net.core.wmem_max": 16777216,
            "net.core.rmem_default": 1048576,
            "net.core.wmem_default": 1048576,
            "net.core.netdev_max_backlog": 5000,
            "net.core.somaxconn": 8192,
            "net.ipv4.tcp_rmem": "4096 1048576 16777216",
            "net.ipv4.tcp_wmem": "4096 1048576 16777216",
            "net.ipv4.tcp_window_scaling": 1,
            "net.ipv4.tcp_timestamps": 1,
            "net.ipv4.tcp_sack": 1,
            "net.ipv4.tcp_fastopen": 3,
            "net.ipv4.tcp_tw_reuse": 2,
            "net.ipv4.tcp_slow_start_after_idle": 0,
            "net.ipv4.tcp_mtu_probing": 1,
            "net.ipv4.tcp_congestion_control": "bbr"
        }
    },
    "low-latency": {
        "name": "Low Latency",
        "description": "Optimized for real-time applications",
        "settings": {
            "net.core.rmem_max": 8388608,
            "net.core.wmem_max": 8388608,
            "net.core.rmem_default": 262144,
            "net.core.wmem_default": 262144,
            "net.core.netdev_max_backlog": 10000,
            "net.core.somaxconn": 4096,
            "net.ipv4.tcp_rmem": "4096 262144 8388608",
            "net.ipv4.tcp_wmem": "4096 262144 8388608",
            "net.ipv4.tcp_window_scaling": 1,
            "net.ipv4.tcp_timestamps": 0,
            "net.ipv4.tcp_sack": 1,
            "net.ipv4.tcp_fastopen": 3,
            "net.ipv4.tcp_fin_timeout": 15,
            "net.ipv4.tcp_keepalive_time": 600,
            "net.ipv4.tcp_keepalive_intvl": 30,
            "net.ipv4.tcp_keepalive_probes": 5,
            "net.ipv4.tcp_tw_reuse": 2,
            "net.ipv4.tcp_slow_start_after_idle": 0,
            "net.ipv4.tcp_congestion_control": "bbr"
        }
    },
    "security": {
        "name": "Security Hardened",
        "description": "Maximum security, defense in depth",
        "settings": {
            "net.ipv4.tcp_syncookies": 1,
            "net.ipv4.tcp_max_syn_backlog": 4096,
            "net.ipv4.tcp_timestamps": 0,
            "net.ipv4.conf.all.rp_filter": 1,
            "net.ipv4.conf.default.rp_filter": 1,
            "net.ipv4.conf.all.accept_redirects": 0,
            "net.ipv4.conf.all.send_redirects": 0,
            "net.ipv4.conf.all.accept_source_route": 0,
            "net.ipv4.icmp_echo_ignore_broadcasts": 1,
            "net.ipv4.icmp_ignore_bogus_error_responses": 1,
            "net.ipv6.conf.all.accept_redirects": 0,
            "net.ipv4.ip_forward": 0,
            "net.ipv6.conf.all.forwarding": 0
        }
    },
    "router": {
        "name": "Router Mode",
        "description": "Optimized for packet forwarding",
        "settings": {
            "net.ipv4.ip_forward": 1,
            "net.ipv6.conf.all.forwarding": 1,
            "net.core.rmem_max": 8388608,
            "net.core.wmem_max": 8388608,
            "net.core.netdev_max_backlog": 10000,
            "net.ipv4.tcp_syncookies": 1,
            "net.ipv4.conf.all.rp_filter": 2,
            "net.ipv4.conf.default.rp_filter": 2,
            "net.ipv4.conf.all.accept_redirects": 0,
            "net.ipv4.conf.all.send_redirects": 1
        }
    }
}


class SysctlSetting(BaseModel):
    """Single sysctl setting."""
    key: str
    value: str


class ApplyRequest(BaseModel):
    """Request to apply settings or profile."""
    profile: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None
    persist: bool = Field(default=True, description="Save to sysctl.conf")


def _run_cmd(cmd: List[str], timeout: int = 10) -> tuple:
    """Run command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def _get_sysctl_value(key: str) -> Optional[str]:
    """Get current sysctl value."""
    success, stdout, _ = _run_cmd(["sysctl", "-n", key])
    if success:
        return stdout.strip()
    return None


def _set_sysctl_value(key: str, value: str) -> tuple:
    """Set sysctl value (runtime only)."""
    return _run_cmd(["sysctl", "-w", f"{key}={value}"])


def _get_all_sysctl_values() -> Dict[str, Any]:
    """Get all managed sysctl values with metadata."""
    result = {}
    for key, meta in SYSCTL_PARAMS.items():
        current = _get_sysctl_value(key)
        result[key] = {
            "value": current,
            "description": meta.get("description", ""),
            "category": meta.get("category", "other"),
            "default": meta.get("default"),
            "type": meta.get("type", "int"),
            "unit": meta.get("unit", ""),
        }
        if "min" in meta:
            result[key]["min"] = meta["min"]
        if "max" in meta:
            result[key]["max"] = meta["max"]
        if "options" in meta:
            result[key]["options"] = meta["options"]
    return result


def _get_tcp_settings() -> Dict[str, Any]:
    """Get TCP-related sysctl values."""
    result = {}
    for key, meta in SYSCTL_PARAMS.items():
        if meta.get("category") == "tcp":
            current = _get_sysctl_value(key)
            result[key] = {
                "value": current,
                "description": meta.get("description", ""),
                "default": meta.get("default"),
                "type": meta.get("type", "int"),
                "unit": meta.get("unit", ""),
            }
            if "min" in meta:
                result[key]["min"] = meta["min"]
            if "max" in meta:
                result[key]["max"] = meta["max"]
            if "options" in meta:
                result[key]["options"] = meta["options"]
    return result


def _get_net_settings() -> Dict[str, Any]:
    """Get network-related sysctl values."""
    result = {}
    for key, meta in SYSCTL_PARAMS.items():
        if meta.get("category") == "net":
            current = _get_sysctl_value(key)
            result[key] = {
                "value": current,
                "description": meta.get("description", ""),
                "default": meta.get("default"),
                "type": meta.get("type", "int"),
                "unit": meta.get("unit", ""),
            }
            if "min" in meta:
                result[key]["min"] = meta["min"]
            if "max" in meta:
                result[key]["max"] = meta["max"]
    return result


def _save_sysctl_conf(settings: Dict[str, Any]) -> bool:
    """Save settings to sysctl.d config file."""
    try:
        SYSCTL_CONF.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# SecuBox Network Tuning Configuration",
            f"# Generated: {datetime.now().isoformat()}",
            "# Do not edit manually - managed by secubox-nettweak",
            ""
        ]
        for key, value in sorted(settings.items()):
            if key in SYSCTL_PARAMS:
                lines.append(f"{key} = {value}")

        SYSCTL_CONF.write_text("\n".join(lines) + "\n")
        log.info("Saved sysctl config to %s", SYSCTL_CONF)
        return True
    except Exception as e:
        log.error("Failed to save sysctl config: %s", e)
        return False


def _load_saved_settings() -> Dict[str, str]:
    """Load settings from sysctl.d config file."""
    settings = {}
    if SYSCTL_CONF.exists():
        try:
            for line in SYSCTL_CONF.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        settings[key.strip()] = value.strip()
        except Exception as e:
            log.warning("Failed to load sysctl config: %s", e)
    return settings


def _get_available_congestion_controls() -> List[str]:
    """Get list of available TCP congestion control algorithms."""
    success, stdout, _ = _run_cmd(["sysctl", "-n", "net.ipv4.tcp_available_congestion_control"])
    if success:
        return stdout.split()
    return ["cubic", "reno"]


def _detect_current_profile() -> Optional[str]:
    """Detect which profile best matches current settings."""
    current = {}
    for key in SYSCTL_PARAMS:
        val = _get_sysctl_value(key)
        if val is not None:
            current[key] = val

    best_match = None
    best_score = 0

    for profile_id, profile in PROFILES.items():
        if not profile["settings"]:
            continue
        matches = 0
        total = len(profile["settings"])
        for key, expected in profile["settings"].items():
            if str(current.get(key)) == str(expected):
                matches += 1
        score = matches / total if total > 0 else 0
        if score > best_score and score >= 0.8:
            best_match = profile_id
            best_score = score

    return best_match


# API Endpoints

@router.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "module": "nettweak", "version": "1.0.0"}


@router.get("/status")
async def status():
    """Get current network tuning status."""
    saved_settings = _load_saved_settings()
    current_profile = _detect_current_profile()
    available_cc = _get_available_congestion_controls()

    # Get a few key metrics for summary
    tcp_cc = _get_sysctl_value("net.ipv4.tcp_congestion_control")
    ip_forward = _get_sysctl_value("net.ipv4.ip_forward")
    tcp_fastopen = _get_sysctl_value("net.ipv4.tcp_fastopen")

    return {
        "active_profile": current_profile,
        "saved_settings_count": len(saved_settings),
        "config_file": str(SYSCTL_CONF),
        "config_exists": SYSCTL_CONF.exists(),
        "available_congestion_controls": available_cc,
        "summary": {
            "tcp_congestion_control": tcp_cc,
            "ip_forwarding": ip_forward == "1",
            "tcp_fastopen": tcp_fastopen
        },
        "timestamp": datetime.now().isoformat()
    }


@router.get("/profiles")
async def get_profiles():
    """Get available tuning profiles."""
    current = _detect_current_profile()
    profiles = []
    for pid, profile in PROFILES.items():
        profiles.append({
            "id": pid,
            "name": profile["name"],
            "description": profile["description"],
            "settings_count": len(profile["settings"]),
            "active": pid == current
        })
    return {"profiles": profiles, "current": current}


@router.get("/profile/{profile_id}")
async def get_profile(profile_id: str, user=Depends(require_jwt)):
    """Get detailed profile settings."""
    if profile_id not in PROFILES:
        raise HTTPException(status_code=404, detail="Profile not found")

    profile = PROFILES[profile_id]
    settings_detail = []
    for key, value in profile["settings"].items():
        meta = SYSCTL_PARAMS.get(key, {})
        current = _get_sysctl_value(key)
        settings_detail.append({
            "key": key,
            "profile_value": value,
            "current_value": current,
            "description": meta.get("description", ""),
            "matches": str(current) == str(value)
        })

    return {
        "id": profile_id,
        "name": profile["name"],
        "description": profile["description"],
        "settings": settings_detail
    }


@router.get("/settings")
async def get_all_settings(user=Depends(require_jwt)):
    """Get all managed sysctl settings."""
    return {
        "settings": _get_all_sysctl_values(),
        "saved": _load_saved_settings(),
        "timestamp": datetime.now().isoformat()
    }


@router.get("/tcp")
async def get_tcp_stack(user=Depends(require_jwt)):
    """Get TCP stack settings."""
    return {
        "settings": _get_tcp_settings(),
        "timestamp": datetime.now().isoformat()
    }


@router.get("/net")
async def get_net_stack(user=Depends(require_jwt)):
    """Get network stack settings."""
    return {
        "settings": _get_net_settings(),
        "timestamp": datetime.now().isoformat()
    }


@router.post("/apply")
async def apply_settings(request: ApplyRequest, user=Depends(require_jwt)):
    """Apply a profile or custom settings."""
    settings_to_apply = {}

    if request.profile:
        if request.profile not in PROFILES:
            raise HTTPException(status_code=400, detail="Unknown profile")
        settings_to_apply = PROFILES[request.profile]["settings"].copy()
        log.info("Applying profile '%s' by %s", request.profile, user.get("sub"))

    if request.settings:
        # Merge custom settings
        for key, value in request.settings.items():
            if key not in SYSCTL_PARAMS:
                log.warning("Ignoring unknown sysctl key: %s", key)
                continue
            settings_to_apply[key] = value

    if not settings_to_apply:
        return {"success": True, "message": "No settings to apply", "applied": 0}

    # Apply settings
    results = []
    errors = []
    for key, value in settings_to_apply.items():
        success, _, stderr = _set_sysctl_value(key, str(value))
        if success:
            results.append({"key": key, "value": str(value), "success": True})
        else:
            errors.append({"key": key, "value": str(value), "error": stderr})
            results.append({"key": key, "value": str(value), "success": False, "error": stderr})

    # Persist if requested
    persisted = False
    if request.persist and not errors:
        # Merge with existing saved settings
        saved = _load_saved_settings()
        saved.update({k: str(v) for k, v in settings_to_apply.items()})
        persisted = _save_sysctl_conf(saved)

    log.info("Applied %d settings (%d errors) by %s",
             len(results) - len(errors), len(errors), user.get("sub"))

    return {
        "success": len(errors) == 0,
        "applied": len(results) - len(errors),
        "errors": len(errors),
        "persisted": persisted,
        "results": results
    }


@router.post("/set/{key}")
async def set_single(key: str, setting: SysctlSetting, user=Depends(require_jwt)):
    """Set a single sysctl value."""
    if key not in SYSCTL_PARAMS:
        raise HTTPException(status_code=400, detail="Unknown sysctl key")

    success, _, stderr = _set_sysctl_value(key, setting.value)
    if not success:
        raise HTTPException(status_code=500, detail=f"Failed to set: {stderr}")

    log.info("Set %s=%s by %s", key, setting.value, user.get("sub"))
    return {"success": True, "key": key, "value": setting.value}


@router.post("/reload")
async def reload_sysctl(user=Depends(require_jwt)):
    """Reload sysctl configuration from files."""
    success, stdout, stderr = _run_cmd(["sysctl", "--system"])

    if success:
        log.info("Reloaded sysctl by %s", user.get("sub"))
        return {"success": True, "output": stdout[:500]}
    else:
        return {"success": False, "error": stderr[:500]}


@router.post("/reset")
async def reset_to_defaults(user=Depends(require_jwt)):
    """Reset to system defaults (remove custom config)."""
    try:
        if SYSCTL_CONF.exists():
            SYSCTL_CONF.unlink()
            log.info("Removed custom sysctl config by %s", user.get("sub"))

        # Reload system defaults
        success, stdout, stderr = _run_cmd(["sysctl", "--system"])

        return {
            "success": True,
            "message": "Custom config removed, system defaults reloaded",
            "reload_output": stdout[:300] if success else stderr[:300]
        }
    except Exception as e:
        log.error("Reset failed: %s", e)
        return {"success": False, "error": str(e)}


@router.get("/summary")
async def summary():
    """Get nettweak summary for dashboard widget."""
    status_info = await status()

    return {
        "active_profile": status_info.get("active_profile"),
        "config_exists": status_info.get("config_exists", False),
        "ip_forwarding": status_info.get("summary", {}).get("ip_forwarding", False),
        "tcp_cc": status_info.get("summary", {}).get("tcp_congestion_control", "unknown"),
        "timestamp": datetime.now().isoformat()
    }


app.include_router(router)
