#!/usr/bin/env python3
"""
SecuBox Eye Remote - OTG Status API
Expose l'état OTG via une API locale pour le dashboard et le menu.

Endpoints :
    GET  /otg/status     - État complet OTG
    GET  /otg/mode       - Mode actuel
    POST /otg/mode       - Changer de mode
    GET  /otg/connection - État connexion USB

Usage :
    uvicorn otg_api:app --uds /run/secubox/otg.sock
    # ou
    python3 otg_api.py  # port 8081

CyberMind - https://cybermind.fr
"""

import os
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
except ImportError:
    print("FastAPI non installé: pip install fastapi uvicorn")
    sys.exit(1)

from usb_host_detector import UsbHostDetector, OtgModeManager

# ==============================================================================
# Models
# ==============================================================================

class OtgStatus(BaseModel):
    """État complet du gadget OTG."""
    udc: Optional[str]
    udc_state: str
    connected: bool
    configured: bool
    mode: str
    mode_description: str
    available_modes: dict
    timestamp: str


class OtgConnection(BaseModel):
    """État de connexion USB."""
    connected: bool
    configured: bool
    state: str
    host_type: Optional[str] = None


class OtgModeRequest(BaseModel):
    """Requête de changement de mode."""
    mode: str


class OtgModeResponse(BaseModel):
    """Réponse au changement de mode."""
    success: bool
    previous_mode: str
    current_mode: str
    message: str


# ==============================================================================
# API
# ==============================================================================

app = FastAPI(
    title="SecuBox Eye Remote OTG API",
    description="API locale pour l'état et le contrôle du gadget USB OTG",
    version="1.0.0"
)

# Singletons
_detector: Optional[UsbHostDetector] = None
_manager: Optional[OtgModeManager] = None


def get_detector() -> UsbHostDetector:
    global _detector
    if _detector is None:
        _detector = UsbHostDetector()
    return _detector


def get_manager() -> OtgModeManager:
    global _manager
    if _manager is None:
        _manager = OtgModeManager()
    return _manager


@app.get("/otg/status", response_model=OtgStatus)
async def get_otg_status():
    """Retourne l'état complet du gadget OTG."""
    detector = get_detector()
    manager = get_manager()

    return OtgStatus(
        udc=detector.udc_name,
        udc_state=detector.get_state(),
        connected=detector.is_connected(),
        configured=detector.is_configured(),
        mode=manager.current_mode,
        mode_description=manager.MODES.get(manager.current_mode, "unknown"),
        available_modes=manager.MODES,
        timestamp=datetime.now().isoformat()
    )


@app.get("/otg/mode")
async def get_otg_mode():
    """Retourne le mode OTG actuel."""
    manager = get_manager()
    return {
        "mode": manager.current_mode,
        "description": manager.MODES.get(manager.current_mode, "unknown")
    }


@app.post("/otg/mode", response_model=OtgModeResponse)
async def set_otg_mode(request: OtgModeRequest):
    """Change le mode OTG."""
    manager = get_manager()
    previous_mode = manager.current_mode

    if request.mode not in manager.MODES:
        raise HTTPException(
            status_code=400,
            detail=f"Mode invalide: {request.mode}. Modes disponibles: {list(manager.MODES.keys())}"
        )

    success = manager.switch_mode(request.mode)

    return OtgModeResponse(
        success=success,
        previous_mode=previous_mode,
        current_mode=manager.current_mode,
        message="Mode changé" if success else "Échec du changement de mode"
    )


@app.get("/otg/connection", response_model=OtgConnection)
async def get_otg_connection():
    """Retourne l'état de connexion USB."""
    detector = get_detector()
    state = detector.get_state()

    # Déterminer le type d'host
    host_type = None
    if state == "configured":
        host_type = "os"  # OS standard
    elif state == "powered":
        host_type = "bootloader"  # Possiblement U-Boot

    return OtgConnection(
        connected=detector.is_connected(),
        configured=detector.is_configured(),
        state=state,
        host_type=host_type
    )


@app.get("/otg/modes")
async def list_otg_modes():
    """Liste tous les modes OTG disponibles."""
    manager = get_manager()
    return {
        "current": manager.current_mode,
        "modes": manager.MODES
    }


# ==============================================================================
# Dashboard/Menu Integration
# ==============================================================================

@app.get("/otg/widget")
async def get_otg_widget():
    """
    Retourne les données formatées pour le widget dashboard/menu.

    Format optimisé pour l'affichage :
    - icon: icône à afficher
    - color: couleur selon l'état
    - label: texte court
    - detail: texte détaillé
    """
    detector = get_detector()
    manager = get_manager()

    state = detector.get_state()
    connected = detector.is_connected()
    mode = manager.current_mode

    # Déterminer l'icône et la couleur
    if not connected:
        icon = "usb_off"
        color = "#6b6b7a"  # gris
        label = "USB"
        detail = "Déconnecté"
    elif state == "configured":
        icon = "usb"
        color = "#0A5840"  # ROOT green
        label = mode.upper()
        detail = f"Connecté ({manager.MODES.get(mode, mode)})"
    elif state == "powered":
        icon = "usb_pending"
        color = "#9A6010"  # WALL orange
        label = "BOOT"
        detail = "Bootloader détecté"
    else:
        icon = "usb"
        color = "#104A88"  # MESH blue
        label = state.upper()
        detail = f"État: {state}"

    return {
        "icon": icon,
        "color": color,
        "label": label,
        "detail": detail,
        "mode": mode,
        "state": state,
        "connected": connected
    }


# ==============================================================================
# Main
# ==============================================================================

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("OTG_API_PORT", 8081))
    socket_path = os.environ.get("OTG_API_SOCKET")

    if socket_path:
        print(f"Starting OTG API on socket: {socket_path}")
        uvicorn.run(app, uds=socket_path)
    else:
        print(f"Starting OTG API on port: {port}")
        uvicorn.run(app, host="127.0.0.1", port=port)
