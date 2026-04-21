"""
SecuBox Eye Gateway — FastAPI server for development.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .emulator import SecuBoxEmulator

# Global emulator instance
_emulator: Optional[SecuBoxEmulator] = None


def set_emulator(emulator: SecuBoxEmulator) -> None:
    """Set the global emulator instance.

    Args:
        emulator: SecuBoxEmulator instance to use
    """
    global _emulator
    _emulator = emulator


def get_emulator() -> SecuBoxEmulator:
    """Get the global emulator instance.

    Returns:
        The configured SecuBoxEmulator

    Raises:
        HTTPException: If emulator is not configured
    """
    if _emulator is None:
        raise HTTPException(
            status_code=503,
            detail="Emulator not configured"
        )
    return _emulator


# FastAPI application
app = FastAPI(
    title="SecuBox Eye Gateway",
    description="Development gateway for SecuBox Eye Remote",
    version="1.0.0",
)

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint.

    Returns:
        Health status of the emulated device
    """
    emulator = get_emulator()
    return emulator.get_health()


@app.get("/api/v1/system/metrics")
async def system_metrics() -> Dict[str, Any]:
    """Get system metrics.

    Returns:
        Current system metrics with realistic drift
    """
    emulator = get_emulator()
    return emulator.get_metrics()


@app.get("/api/v1/eye-remote/metrics")
async def eye_remote_metrics() -> Dict[str, Any]:
    """Get metrics formatted for Eye Remote display.

    Returns:
        Metrics in Eye Remote format
    """
    emulator = get_emulator()
    metrics = emulator.get_metrics()

    # Format for Eye Remote display
    return {
        "system": {
            "cpu": metrics["cpu_percent"],
            "memory": metrics["memory_percent"],
            "disk": metrics["disk_percent"],
            "temperature": metrics["temperature"],
            "load": metrics["load_avg"],
        },
        "network": {
            "wifi_signal": metrics["wifi_signal"],
        },
        "alerts": {
            "active": metrics["active_alerts"],
            "critical": max(0, metrics["active_alerts"] - 2),
            "warning": min(metrics["active_alerts"], 2),
        },
        "device": {
            "name": metrics["device_name"],
            "id": metrics["device_id"],
            "uptime": metrics["uptime"],
            "profile": metrics["profile"],
            "emulated": metrics["emulated"],
        },
        "timestamp": metrics["timestamp"],
    }


@app.get("/api/v1/eye-remote/discover")
async def discover() -> Dict[str, Any]:
    """Device discovery endpoint.

    Returns:
        Device discovery information
    """
    emulator = get_emulator()
    return emulator.get_discovery_info()


@app.get("/")
async def root() -> Dict[str, str]:
    """Root endpoint with basic info."""
    return {
        "name": "SecuBox Eye Gateway",
        "version": "1.0.0",
        "description": "Development gateway for Eye Remote",
        "docs": "/docs",
    }
