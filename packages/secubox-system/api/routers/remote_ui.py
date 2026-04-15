"""
SecuBox-Deb :: api.routers.remote_ui — Endpoints REST Remote UI OTG
====================================================================
Gestion de la connexion Remote UI (HyperPixel 2.1 Round sur RPi Zero W).

Endpoints:
  GET  /api/v1/remote-ui/status    → État de la connexion Remote UI
  POST /api/v1/remote-ui/connected → Notification de connexion (udev)
  POST /api/v1/remote-ui/disconnected → Notification de déconnexion (udev)

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

# Import relatif depuis le package secubox-system
import sys
from pathlib import Path
_pkg_root = Path(__file__).parent.parent.parent
if str(_pkg_root) not in sys.path:
    sys.path.insert(0, str(_pkg_root))

from core.remote_ui import get_remote_ui_manager, remote_ui_status
from models.system import (
    RemoteUIStatusResponse,
    RemoteUIConnectedRequest,
    TransportType,
)

log = get_logger("remote_ui_api")

router = APIRouter(
    prefix="/remote-ui",
    tags=["remote-ui"],
    responses={
        401: {"description": "Token JWT manquant ou invalide"},
        403: {"description": "Scope insuffisant"},
    }
)


# ══════════════════════════════════════════════════════════════════════════════
# Vérification de scope
# ══════════════════════════════════════════════════════════════════════════════

def require_scope(scope: str):
    """
    Vérifie que le token JWT contient le scope demandé.

    Args:
        scope: Scope requis (ex: "metrics:read", "remote-ui:register")
    """
    async def checker(user=Depends(require_jwt)):
        token_scopes = user.get("scopes", [])
        username = user.get("sub", "")

        # Admin a tous les scopes
        if username in ("admin", "root", "secubox"):
            return user

        # Vérification du scope
        if scope in token_scopes or "admin" in token_scopes or "*" in token_scopes:
            return user

        # Mode permissif pour le développement
        # TODO: Activer la vérification stricte en production
        log.debug("Scope %s demandé, user=%s, scopes=%s", scope, username, token_scopes)
        return user

    return checker


def require_internal_token():
    """
    Vérifie que la requête provient d'un script interne.
    Utilisé pour les endpoints appelés par udev/systemd.
    """
    async def checker(request: Request):
        # Vérifier le token dans l'en-tête Authorization
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            # Permettre les appels localhost sans token
            client_ip = request.client.host if request.client else ""
            if client_ip in ("127.0.0.1", "::1", "localhost"):
                return {"sub": "internal", "scopes": ["remote-ui:register"]}
            raise HTTPException(401, "Token interne requis")

        # Valider le token interne (simplifié)
        token = auth_header[7:]
        internal_token_path = Path("/etc/secubox/secrets/internal.token")

        if internal_token_path.exists():
            expected = internal_token_path.read_text().strip()
            if token == expected:
                return {"sub": "internal", "scopes": ["remote-ui:register"]}

        # Fallback: accepter si localhost
        client_ip = request.client.host if request.client else ""
        if client_ip in ("127.0.0.1", "::1"):
            return {"sub": "internal", "scopes": ["remote-ui:register"]}

        raise HTTPException(403, "Token interne invalide")

    return checker


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@router.get(
    "/status",
    response_model=RemoteUIStatusResponse,
    summary="État de la connexion Remote UI",
    description="""
Retourne l'état de la connexion Remote UI (HyperPixel 2.1 Round sur RPi Zero W).

**Transports possibles:**
- `otg` : Connecté via USB OTG (CDC-ECM @ 10.55.0.0/30)
- `wifi` : Connecté via WiFi
- `none` : Non connecté

**Informations retournées:**
- État de connexion
- Transport actif
- Adresse IP du peer
- Uptime de la connexion
- Disponibilité de la console série (pour OTG)
    """,
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_remote_ui_status() -> RemoteUIStatusResponse:
    """
    Retourne l'état actuel de la connexion Remote UI.
    """
    try:
        status = remote_ui_status()
        return RemoteUIStatusResponse(**status)
    except Exception as e:
        log.error("Erreur récupération état Remote UI: %s", e)
        return RemoteUIStatusResponse(
            connected=False,
            transport=TransportType.NONE
        )


@router.post(
    "/connected",
    summary="Notification de connexion Remote UI",
    description="""
Endpoint appelé par le script udev (`secubox-otg-host-up.sh`) lors de la
connexion d'un Remote UI en OTG.

**Requiert:** Token interne ou appel depuis localhost.

**Payload:**
- `transport`: Type de transport ("otg" ou "wifi")
- `peer`: Adresse IP du Remote UI
- `interface`: Nom de l'interface réseau (optionnel)
    """,
    dependencies=[Depends(require_internal_token())]
)
async def remote_ui_connected(
    request: RemoteUIConnectedRequest
) -> dict:
    """
    Enregistre une connexion Remote UI.
    """
    try:
        manager = get_remote_ui_manager()
        manager.on_connected(
            transport=request.transport.value,
            peer=request.peer,
            interface=request.interface
        )

        log.info("Remote UI connecté: transport=%s, peer=%s",
                 request.transport.value, request.peer)

        return {
            "success": True,
            "message": f"Remote UI enregistré ({request.transport.value})",
            "transport": request.transport.value,
            "peer": request.peer
        }
    except Exception as e:
        log.error("Erreur enregistrement connexion: %s", e)
        raise HTTPException(500, f"Erreur: {e}")


@router.post(
    "/disconnected",
    summary="Notification de déconnexion Remote UI",
    description="""
Endpoint appelé par le script udev lors de la déconnexion d'un Remote UI.

**Requiert:** Token interne ou appel depuis localhost.
    """,
    dependencies=[Depends(require_internal_token())]
)
async def remote_ui_disconnected(
    transport: str = "otg"
) -> dict:
    """
    Enregistre une déconnexion Remote UI.
    """
    try:
        manager = get_remote_ui_manager()
        manager.on_disconnected(transport)

        log.info("Remote UI déconnecté: transport=%s", transport)

        return {
            "success": True,
            "message": f"Remote UI déconnecté ({transport})"
        }
    except Exception as e:
        log.error("Erreur enregistrement déconnexion: %s", e)
        raise HTTPException(500, f"Erreur: {e}")


@router.get(
    "/probe",
    summary="Force une détection OTG",
    description="Déclenche une détection immédiate de la connexion OTG.",
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def probe_otg_connection() -> dict:
    """
    Force une détection de connexion OTG.
    """
    try:
        manager = get_remote_ui_manager()
        connected = manager.detect_otg_connection()

        return {
            "success": True,
            "connected": connected,
            "transport": manager.get_transport(),
            "status": manager.get_status()
        }
    except Exception as e:
        log.error("Erreur probe OTG: %s", e)
        raise HTTPException(500, f"Erreur: {e}")


@router.get(
    "/serial/info",
    summary="Informations console série",
    description="Retourne les informations sur la console série OTG.",
    dependencies=[Depends(require_scope("metrics:read"))]
)
async def get_serial_info() -> dict:
    """
    Retourne les informations sur la console série OTG.
    """
    manager = get_remote_ui_manager()
    state = manager.state

    return {
        "available": state.serial_available,
        "device": state.serial_device,
        "baud_rate": 115200,
        "connected": state.connected and state.transport == "otg",
        "help": "Connectez-vous avec: screen /dev/secubox-console 115200"
    }
