"""
SecuBox Eye Remote - WebSocket Command Router
Endpoint WebSocket bidirectionnel pour la communication en temps reel
avec les appareils Eye Remote.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
from pydantic import BaseModel, Field

from ...core.device_registry import get_device_registry
from ...core.token_manager import hash_token

log = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


# =============================================================================
# Enumerations et Modeles
# =============================================================================


class Command(str, Enum):
    """Commandes supportees pour Eye Remote."""
    SCREENSHOT = "screenshot"          # Capture ecran, retourne PNG base64
    REBOOT = "reboot"                  # Redemarrage de Eye Remote
    CONFIG_UPDATE = "config_update"    # Mise a jour de la configuration
    LOCKDOWN = "lockdown"              # Activer mode lockdown sur SecuBox
    UNLOCK = "unlock"                  # Desactiver mode lockdown
    SERVICE_RESTART = "service_restart"  # Redemarrer un service
    OTA_UPDATE = "ota_update"          # Declencher mise a jour OTA


class MessageType(str, Enum):
    """Types de messages WebSocket."""
    COMMAND = "command"        # Commande envoyee a Eye Remote
    RESPONSE = "response"      # Reponse d'Eye Remote
    METRICS = "metrics"        # Mise a jour des metriques
    STATUS = "status"          # Mise a jour du statut
    AUTH = "auth"              # Authentification
    ERROR = "error"            # Message d'erreur
    PING = "ping"              # Heartbeat ping
    PONG = "pong"              # Heartbeat pong


class WSMessage(BaseModel):
    """Format de message WebSocket bidirectionnel."""
    type: MessageType = Field(..., description="Type de message")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="ID unique du message")
    cmd: Optional[Command] = Field(default=None, description="Commande (si type=command)")
    params: dict = Field(default_factory=dict, description="Parametres de la commande")
    data: dict = Field(default_factory=dict, description="Donnees de reponse")
    error: str = Field(default="", description="Message d'erreur")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        use_enum_values = True


class ConnectionState(BaseModel):
    """Etat d'une connexion WebSocket."""
    device_id: str
    connected_at: datetime
    last_activity: datetime
    transport: str = "websocket"
    authenticated: bool = False


# =============================================================================
# Gestionnaire de Connexions
# =============================================================================


class ConnectionManager:
    """
    Gestionnaire des connexions WebSocket actives.

    Gere:
    - Enregistrement/desenregistrement des connexions
    - Envoi de messages aux appareils specifiques
    - Broadcast vers tous les clients WebUI
    - Tracking de l'etat des connexions
    """

    def __init__(self):
        # Connexions des appareils Eye Remote: device_id -> WebSocket
        self._device_connections: dict[str, WebSocket] = {}
        # Connexions des clients WebUI: connection_id -> WebSocket
        self._webui_connections: dict[str, WebSocket] = {}
        # Etat des connexions
        self._connection_states: dict[str, ConnectionState] = {}
        # Commandes en attente de reponse: message_id -> asyncio.Future
        self._pending_commands: dict[str, asyncio.Future] = {}
        # Lock pour acces concurrent
        self._lock = asyncio.Lock()

    async def connect_device(self, device_id: str, websocket: WebSocket):
        """
        Enregistrer une connexion d'appareil Eye Remote.

        Args:
            device_id: Identifiant unique de l'appareil
            websocket: Connexion WebSocket
        """
        async with self._lock:
            # Fermer l'ancienne connexion si existante
            if device_id in self._device_connections:
                old_ws = self._device_connections[device_id]
                try:
                    await old_ws.close(code=status.WS_1008_POLICY_VIOLATION)
                except Exception:
                    pass

            self._device_connections[device_id] = websocket
            self._connection_states[device_id] = ConnectionState(
                device_id=device_id,
                connected_at=datetime.now(timezone.utc),
                last_activity=datetime.now(timezone.utc),
                authenticated=True
            )
            log.info("Appareil connecte: %s", device_id)

    async def disconnect_device(self, device_id: str):
        """Desenregistrer un appareil."""
        async with self._lock:
            if device_id in self._device_connections:
                del self._device_connections[device_id]
                log.info("Appareil deconnecte: %s", device_id)
            if device_id in self._connection_states:
                del self._connection_states[device_id]

    async def connect_webui(self, connection_id: str, websocket: WebSocket):
        """Enregistrer une connexion client WebUI."""
        async with self._lock:
            self._webui_connections[connection_id] = websocket
            log.debug("Client WebUI connecte: %s", connection_id)

    async def disconnect_webui(self, connection_id: str):
        """Desenregistrer un client WebUI."""
        async with self._lock:
            if connection_id in self._webui_connections:
                del self._webui_connections[connection_id]
                log.debug("Client WebUI deconnecte: %s", connection_id)

    def is_device_connected(self, device_id: str) -> bool:
        """Verifier si un appareil est connecte."""
        return device_id in self._device_connections

    def get_device_state(self, device_id: str) -> Optional[ConnectionState]:
        """Obtenir l'etat d'une connexion."""
        return self._connection_states.get(device_id)

    def list_connected_devices(self) -> list[str]:
        """Lister tous les appareils connectes."""
        return list(self._device_connections.keys())

    async def send_to_device(
        self,
        device_id: str,
        message: WSMessage,
        timeout: float = 30.0
    ) -> Optional[WSMessage]:
        """
        Envoyer une commande a un appareil et attendre la reponse.

        Args:
            device_id: ID de l'appareil cible
            message: Message a envoyer
            timeout: Timeout en secondes

        Returns:
            Reponse de l'appareil ou None si timeout/erreur
        """
        websocket = self._device_connections.get(device_id)
        if not websocket:
            log.warning("Appareil non connecte: %s", device_id)
            return None

        # Creer un Future pour attendre la reponse
        future: asyncio.Future = asyncio.Future()
        self._pending_commands[message.id] = future

        try:
            # Envoyer la commande
            await websocket.send_json(message.model_dump(mode='json'))
            log.debug("Commande envoyee a %s: %s", device_id, message.cmd)

            # Attendre la reponse
            response = await asyncio.wait_for(future, timeout=timeout)
            return response
        except asyncio.TimeoutError:
            log.warning("Timeout commande %s vers %s", message.cmd, device_id)
            return None
        except Exception as e:
            log.error("Erreur envoi commande a %s: %s", device_id, e)
            return None
        finally:
            # Nettoyer le Future
            self._pending_commands.pop(message.id, None)

    async def send_to_device_nowait(self, device_id: str, message: WSMessage) -> bool:
        """
        Envoyer un message a un appareil sans attendre de reponse.

        Args:
            device_id: ID de l'appareil cible
            message: Message a envoyer

        Returns:
            True si envoye avec succes
        """
        websocket = self._device_connections.get(device_id)
        if not websocket:
            return False

        try:
            await websocket.send_json(message.model_dump(mode='json'))
            return True
        except Exception as e:
            log.error("Erreur envoi a %s: %s", device_id, e)
            return False

    def resolve_response(self, message_id: str, response: WSMessage):
        """
        Resoudre un Future en attente avec la reponse recue.

        Args:
            message_id: ID du message original
            response: Reponse recue
        """
        future = self._pending_commands.get(message_id)
        if future and not future.done():
            future.set_result(response)

    async def broadcast_to_webui(self, message: WSMessage):
        """
        Diffuser un message a tous les clients WebUI.

        Args:
            message: Message a diffuser
        """
        if not self._webui_connections:
            return

        data = message.model_dump(mode='json')
        disconnected = []

        for conn_id, websocket in self._webui_connections.items():
            try:
                await websocket.send_json(data)
            except Exception:
                disconnected.append(conn_id)

        # Nettoyer les connexions mortes
        for conn_id in disconnected:
            await self.disconnect_webui(conn_id)

    async def update_activity(self, device_id: str):
        """Mettre a jour le timestamp d'activite."""
        if device_id in self._connection_states:
            self._connection_states[device_id].last_activity = datetime.now(timezone.utc)


# Instance singleton du gestionnaire de connexions
connection_manager = ConnectionManager()


# =============================================================================
# Fonctions d'Authentification
# =============================================================================


def authenticate_device(device_id: str, token: str) -> bool:
    """
    Authentifier un appareil avec son token.

    Args:
        device_id: ID de l'appareil
        token: Token en clair

    Returns:
        True si authentification reussie
    """
    if not device_id or not token:
        return False

    registry = get_device_registry()
    device = registry.get_device(device_id)

    if not device:
        log.warning("Appareil inconnu: %s", device_id)
        return False

    # Verifier le hash du token
    token_hashed = hash_token(token)
    if device.token_hash != token_hashed:
        log.warning("Token invalide pour: %s", device_id)
        return False

    # Mettre a jour last_seen
    registry.update_last_seen(device_id, "websocket")

    log.info("Authentification reussie: %s", device_id)
    return True


async def handle_auth_message(
    websocket: WebSocket,
    device_id: str,
    message: dict
) -> bool:
    """
    Gerer un message d'authentification.

    Args:
        websocket: Connexion WebSocket
        device_id: ID de l'appareil
        message: Message recu

    Returns:
        True si authentification reussie
    """
    token = message.get("params", {}).get("token", "")

    if authenticate_device(device_id, token):
        # Enregistrer la connexion
        await connection_manager.connect_device(device_id, websocket)

        # Envoyer confirmation
        response = WSMessage(
            type=MessageType.STATUS,
            id=message.get("id", str(uuid.uuid4())),
            data={"authenticated": True, "device_id": device_id}
        )
        await websocket.send_json(response.model_dump(mode='json'))
        return True
    else:
        # Envoyer erreur
        response = WSMessage(
            type=MessageType.ERROR,
            id=message.get("id", str(uuid.uuid4())),
            error="Authentication failed"
        )
        await websocket.send_json(response.model_dump(mode='json'))
        return False


# =============================================================================
# Handlers de Messages
# =============================================================================


async def handle_device_message(
    device_id: str,
    message: dict
):
    """
    Traiter un message recu d'un appareil Eye Remote.

    Args:
        device_id: ID de l'appareil source
        message: Message recu
    """
    msg_type = message.get("type", "")
    msg_id = message.get("id", "")

    await connection_manager.update_activity(device_id)

    if msg_type == MessageType.RESPONSE.value:
        # Reponse a une commande - resoudre le Future en attente
        response = WSMessage(**message)
        connection_manager.resolve_response(msg_id, response)
        log.debug("Reponse recue de %s pour %s", device_id, msg_id)

    elif msg_type == MessageType.METRICS.value:
        # Mise a jour des metriques - diffuser aux clients WebUI
        metrics_msg = WSMessage(
            type=MessageType.METRICS,
            id=str(uuid.uuid4()),
            data={
                "device_id": device_id,
                "metrics": message.get("data", {})
            }
        )
        await connection_manager.broadcast_to_webui(metrics_msg)
        log.debug("Metriques recues de %s", device_id)

    elif msg_type == MessageType.STATUS.value:
        # Mise a jour de statut - diffuser aux clients WebUI
        status_msg = WSMessage(
            type=MessageType.STATUS,
            id=str(uuid.uuid4()),
            data={
                "device_id": device_id,
                "status": message.get("data", {})
            }
        )
        await connection_manager.broadcast_to_webui(status_msg)
        log.debug("Statut recu de %s", device_id)

    elif msg_type == MessageType.PONG.value:
        # Reponse au heartbeat
        log.debug("Pong recu de %s", device_id)

    else:
        log.warning("Type de message inconnu de %s: %s", device_id, msg_type)


# =============================================================================
# Endpoints WebSocket
# =============================================================================


@router.websocket("/ws/{device_id}")
async def websocket_device_endpoint(
    websocket: WebSocket,
    device_id: str,
    token: Optional[str] = Query(None)
):
    """
    Endpoint WebSocket pour les appareils Eye Remote.

    L'authentification peut se faire:
    1. Via query param ?token=xxx
    2. Via premier message {"type": "auth", "params": {"token": "xxx"}}

    Args:
        websocket: Connexion WebSocket
        device_id: Identifiant de l'appareil
        token: Token d'authentification optionnel
    """
    await websocket.accept()

    authenticated = False

    # Authentification via query param
    if token:
        if authenticate_device(device_id, token):
            await connection_manager.connect_device(device_id, websocket)
            authenticated = True

            # Envoyer confirmation
            welcome = WSMessage(
                type=MessageType.STATUS,
                data={"authenticated": True, "device_id": device_id}
            )
            await websocket.send_json(welcome.model_dump(mode='json'))
        else:
            error = WSMessage(
                type=MessageType.ERROR,
                error="Invalid token"
            )
            await websocket.send_json(error.model_dump(mode='json'))
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    try:
        while True:
            # Recevoir un message
            data = await websocket.receive_json()

            if not authenticated:
                # Premier message doit etre l'authentification
                if data.get("type") == MessageType.AUTH.value:
                    authenticated = await handle_auth_message(
                        websocket, device_id, data
                    )
                    if not authenticated:
                        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                        return
                else:
                    error = WSMessage(
                        type=MessageType.ERROR,
                        error="Authentication required"
                    )
                    await websocket.send_json(error.model_dump(mode='json'))
            else:
                # Traiter le message
                await handle_device_message(device_id, data)

    except WebSocketDisconnect:
        log.info("Appareil deconnecte: %s", device_id)
    except Exception as e:
        log.error("Erreur WebSocket %s: %s", device_id, e)
    finally:
        await connection_manager.disconnect_device(device_id)


@router.websocket("/ws/webui/{connection_id}")
async def websocket_webui_endpoint(
    websocket: WebSocket,
    connection_id: str
):
    """
    Endpoint WebSocket pour les clients WebUI.

    Recoit les mises a jour de metriques et statut des appareils.
    Peut envoyer des commandes aux appareils via messages.

    Args:
        websocket: Connexion WebSocket
        connection_id: ID unique de la connexion
    """
    await websocket.accept()
    await connection_manager.connect_webui(connection_id, websocket)

    # Envoyer la liste des appareils connectes
    devices = connection_manager.list_connected_devices()
    welcome = WSMessage(
        type=MessageType.STATUS,
        data={
            "connected": True,
            "devices": devices
        }
    )
    await websocket.send_json(welcome.model_dump(mode='json'))

    try:
        while True:
            data = await websocket.receive_json()

            if data.get("type") == MessageType.COMMAND.value:
                # Relayer la commande a l'appareil cible
                target_device = data.get("params", {}).get("device_id")
                if not target_device:
                    error = WSMessage(
                        type=MessageType.ERROR,
                        id=data.get("id", str(uuid.uuid4())),
                        error="device_id required"
                    )
                    await websocket.send_json(error.model_dump(mode='json'))
                    continue

                # Creer le message de commande
                command_msg = WSMessage(
                    type=MessageType.COMMAND,
                    id=data.get("id", str(uuid.uuid4())),
                    cmd=data.get("cmd"),
                    params=data.get("params", {})
                )

                # Envoyer et attendre la reponse
                response = await connection_manager.send_to_device(
                    target_device, command_msg
                )

                if response:
                    await websocket.send_json(response.model_dump(mode='json'))
                else:
                    error = WSMessage(
                        type=MessageType.ERROR,
                        id=command_msg.id,
                        error="Command timeout or device not connected"
                    )
                    await websocket.send_json(error.model_dump(mode='json'))

            elif data.get("type") == MessageType.PING.value:
                pong = WSMessage(type=MessageType.PONG, id=data.get("id", ""))
                await websocket.send_json(pong.model_dump(mode='json'))

    except WebSocketDisconnect:
        log.debug("Client WebUI deconnecte: %s", connection_id)
    except Exception as e:
        log.error("Erreur WebSocket WebUI %s: %s", connection_id, e)
    finally:
        await connection_manager.disconnect_webui(connection_id)


# =============================================================================
# API REST pour les commandes
# =============================================================================


@router.get("/devices/connected")
async def get_connected_devices() -> dict[str, Any]:
    """
    Lister les appareils Eye Remote actuellement connectes.

    Returns:
        Liste des appareils avec leur etat
    """
    devices = []
    for device_id in connection_manager.list_connected_devices():
        state = connection_manager.get_device_state(device_id)
        if state:
            devices.append({
                "device_id": device_id,
                "connected_at": state.connected_at.isoformat(),
                "last_activity": state.last_activity.isoformat(),
                "transport": state.transport
            })

    return {
        "devices": devices,
        "count": len(devices)
    }


@router.post("/devices/{device_id}/command")
async def send_device_command(
    device_id: str,
    cmd: Command,
    params: Optional[dict] = None
) -> dict[str, Any]:
    """
    Envoyer une commande a un appareil Eye Remote.

    Args:
        device_id: ID de l'appareil cible
        cmd: Commande a executer
        params: Parametres optionnels

    Returns:
        Reponse de l'appareil
    """
    if not connection_manager.is_device_connected(device_id):
        return {
            "success": False,
            "error": f"Device {device_id} not connected"
        }

    message = WSMessage(
        type=MessageType.COMMAND,
        cmd=cmd,
        params=params or {}
    )

    response = await connection_manager.send_to_device(device_id, message)

    if response:
        return {
            "success": True,
            "request_id": message.id,
            "data": response.data,
            "error": response.error
        }
    else:
        return {
            "success": False,
            "request_id": message.id,
            "error": "Command timeout"
        }


@router.post("/devices/{device_id}/screenshot")
async def request_screenshot(device_id: str) -> dict[str, Any]:
    """
    Demander une capture d'ecran a un appareil Eye Remote.

    Args:
        device_id: ID de l'appareil

    Returns:
        Image PNG encodee en base64
    """
    return await send_device_command(device_id, Command.SCREENSHOT)


@router.post("/devices/{device_id}/reboot")
async def request_reboot(device_id: str) -> dict[str, Any]:
    """
    Redemarrer un appareil Eye Remote.

    Args:
        device_id: ID de l'appareil

    Returns:
        Confirmation du redemarrage
    """
    return await send_device_command(device_id, Command.REBOOT)


@router.post("/devices/{device_id}/lockdown")
async def request_lockdown(device_id: str, enable: bool = True) -> dict[str, Any]:
    """
    Activer/desactiver le mode lockdown sur le SecuBox associe.

    Args:
        device_id: ID de l'appareil
        enable: True pour activer, False pour desactiver

    Returns:
        Confirmation de l'action
    """
    cmd = Command.LOCKDOWN if enable else Command.UNLOCK
    return await send_device_command(device_id, cmd)


@router.post("/devices/{device_id}/service/{service_name}/restart")
async def request_service_restart(
    device_id: str,
    service_name: str
) -> dict[str, Any]:
    """
    Redemarrer un service sur l'appareil Eye Remote.

    Args:
        device_id: ID de l'appareil
        service_name: Nom du service systemd

    Returns:
        Confirmation du redemarrage
    """
    return await send_device_command(
        device_id,
        Command.SERVICE_RESTART,
        {"service": service_name}
    )


# =============================================================================
# Heartbeat Task
# =============================================================================


async def heartbeat_task():
    """
    Tache de fond pour envoyer des pings periodiques aux appareils.
    Detecte les connexions mortes.
    """
    while True:
        await asyncio.sleep(30)  # Ping toutes les 30 secondes

        for device_id in connection_manager.list_connected_devices():
            ping = WSMessage(type=MessageType.PING)
            success = await connection_manager.send_to_device_nowait(device_id, ping)
            if not success:
                log.warning("Heartbeat echoue pour %s", device_id)


def start_heartbeat():
    """Demarrer la tache de heartbeat en arriere-plan."""
    asyncio.create_task(heartbeat_task())


# Fonction d'acces au gestionnaire de connexions (pour les autres modules)
def get_connection_manager() -> ConnectionManager:
    """Obtenir l'instance du gestionnaire de connexions."""
    return connection_manager
