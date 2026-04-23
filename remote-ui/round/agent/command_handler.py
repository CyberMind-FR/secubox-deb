"""
SecuBox Eye Remote - Command Handler
Gestionnaire de commandes pour l'agent Eye Remote.
Connecte au SecuBox via WebSocket et execute les commandes localement.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import os
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)


# =============================================================================
# Types et Constantes
# =============================================================================


class Command(str, Enum):
    """Commandes supportees par Eye Remote."""
    SCREENSHOT = "screenshot"          # Capture ecran, retourne PNG base64
    REBOOT = "reboot"                  # Redemarrage de Eye Remote
    CONFIG_UPDATE = "config_update"    # Mise a jour de la configuration
    LOCKDOWN = "lockdown"              # Activer mode lockdown sur SecuBox
    UNLOCK = "unlock"                  # Desactiver mode lockdown
    SERVICE_RESTART = "service_restart"  # Redemarrer un service
    OTA_UPDATE = "ota_update"          # Declencher mise a jour OTA


class MessageType(str, Enum):
    """Types de messages WebSocket."""
    COMMAND = "command"
    RESPONSE = "response"
    METRICS = "metrics"
    STATUS = "status"
    AUTH = "auth"
    ERROR = "error"
    PING = "ping"
    PONG = "pong"


# Configuration par defaut du framebuffer
FRAMEBUFFER_PATH = Path("/dev/fb0")
FRAMEBUFFER_WIDTH = 480
FRAMEBUFFER_HEIGHT = 480
FRAMEBUFFER_BPP = 32  # Bits per pixel (BGRA)

# Chemin du fichier de configuration
CONFIG_PATH = Path("/etc/secubox-eye/config.toml")

# Services autorises au redemarrage
ALLOWED_SERVICES = {
    "secubox-eye-agent",
    "secubox-eye-ui",
    "nginx",
    "NetworkManager",
}


# =============================================================================
# Exceptions
# =============================================================================


class CommandError(Exception):
    """Erreur lors de l'execution d'une commande."""
    pass


class ScreenshotError(CommandError):
    """Erreur lors de la capture d'ecran."""
    pass


class ServiceError(CommandError):
    """Erreur lors de la gestion d'un service."""
    pass


# =============================================================================
# Fonctions de Capture d'Ecran
# =============================================================================


def capture_screenshot_framebuffer() -> str:
    """
    Capturer l'ecran via le framebuffer Linux.

    Lit /dev/fb0 et convertit en PNG base64.
    Compatible HyperPixel 2.1 Round (480x480 BGRA).

    Returns:
        Image PNG encodee en base64

    Raises:
        ScreenshotError: Si la capture echoue
    """
    try:
        from PIL import Image
    except ImportError:
        raise ScreenshotError("PIL/Pillow non disponible")

    if not FRAMEBUFFER_PATH.exists():
        raise ScreenshotError(f"Framebuffer {FRAMEBUFFER_PATH} non trouve")

    try:
        # Lire les donnees brutes du framebuffer
        bytes_per_pixel = FRAMEBUFFER_BPP // 8
        buffer_size = FRAMEBUFFER_WIDTH * FRAMEBUFFER_HEIGHT * bytes_per_pixel

        with open(FRAMEBUFFER_PATH, 'rb') as fb:
            data = fb.read(buffer_size)

        if len(data) < buffer_size:
            log.warning("Framebuffer tronque: %d/%d bytes", len(data), buffer_size)
            # Completer avec des zeros si necessaire
            data = data + bytes(buffer_size - len(data))

        # Convertir BGRA vers RGBA pour PIL
        img = Image.frombytes(
            'RGBA',
            (FRAMEBUFFER_WIDTH, FRAMEBUFFER_HEIGHT),
            data,
            'raw',
            'BGRA'
        )

        # Encoder en PNG base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG', optimize=True)
        png_data = buffer.getvalue()

        encoded = base64.b64encode(png_data).decode('ascii')
        log.info("Screenshot capture: %d bytes -> %d chars base64",
                 len(png_data), len(encoded))

        return encoded

    except PermissionError:
        raise ScreenshotError(f"Acces refuse a {FRAMEBUFFER_PATH}")
    except Exception as e:
        raise ScreenshotError(f"Erreur capture: {e}")


def capture_screenshot_scrot() -> str:
    """
    Capturer l'ecran via scrot (fallback).

    Utilise l'outil scrot pour X11/Wayland.

    Returns:
        Image PNG encodee en base64

    Raises:
        ScreenshotError: Si la capture echoue
    """
    import tempfile

    try:
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
            tmp_path = tmp.name

        # Essayer scrot
        result = subprocess.run(
            ['scrot', '-o', tmp_path],
            capture_output=True,
            timeout=5
        )

        if result.returncode != 0:
            raise ScreenshotError(f"scrot erreur: {result.stderr.decode()}")

        with open(tmp_path, 'rb') as f:
            png_data = f.read()

        os.unlink(tmp_path)

        return base64.b64encode(png_data).decode('ascii')

    except FileNotFoundError:
        raise ScreenshotError("scrot non installe")
    except subprocess.TimeoutExpired:
        raise ScreenshotError("Timeout scrot")
    except Exception as e:
        raise ScreenshotError(f"Erreur scrot: {e}")


def capture_screenshot() -> str:
    """
    Capturer l'ecran avec la meilleure methode disponible.

    Tente d'abord le framebuffer, puis scrot en fallback.

    Returns:
        Image PNG encodee en base64
    """
    # Essayer le framebuffer en premier (plus rapide, pas de X)
    try:
        return capture_screenshot_framebuffer()
    except ScreenshotError as e:
        log.debug("Framebuffer non disponible: %s", e)

    # Fallback sur scrot
    try:
        return capture_screenshot_scrot()
    except ScreenshotError as e:
        log.debug("scrot non disponible: %s", e)

    raise ScreenshotError("Aucune methode de capture disponible")


# =============================================================================
# Fonctions Systeme
# =============================================================================


def execute_reboot(delay: int = 0) -> bool:
    """
    Redemarrer le systeme.

    Args:
        delay: Delai en secondes avant redemarrage

    Returns:
        True si la commande a ete lancee
    """
    try:
        cmd = ['sudo', 'shutdown', '-r']
        if delay > 0:
            cmd.append(f'+{delay // 60}')  # Convertir en minutes
        else:
            cmd.append('now')

        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log.info("Redemarrage programme dans %d secondes", delay)
        return True

    except Exception as e:
        log.error("Erreur redemarrage: %s", e)
        return False


def restart_service(service_name: str) -> bool:
    """
    Redemarrer un service systemd.

    Args:
        service_name: Nom du service (sans .service)

    Returns:
        True si le redemarrage a reussi
    """
    # Verifier que le service est autorise
    if service_name not in ALLOWED_SERVICES:
        log.warning("Service non autorise: %s", service_name)
        raise ServiceError(f"Service {service_name} non autorise")

    try:
        result = subprocess.run(
            ['sudo', 'systemctl', 'restart', service_name],
            capture_output=True,
            timeout=30
        )

        if result.returncode == 0:
            log.info("Service %s redemarre", service_name)
            return True
        else:
            error = result.stderr.decode().strip()
            log.error("Erreur redemarrage %s: %s", service_name, error)
            raise ServiceError(error)

    except subprocess.TimeoutExpired:
        raise ServiceError(f"Timeout redemarrage {service_name}")
    except Exception as e:
        raise ServiceError(str(e))


def update_config(config_data: dict) -> bool:
    """
    Mettre a jour la configuration de l'agent.

    Args:
        config_data: Nouvelle configuration (partielle ou complete)

    Returns:
        True si la mise a jour a reussi
    """
    import tomllib

    def write_toml(data: dict, indent: int = 0) -> str:
        """Ecrire un dictionnaire en format TOML simple."""
        lines = []
        prefix = "  " * indent
        tables = []

        for key, value in data.items():
            if isinstance(value, dict):
                tables.append((key, value))
            elif isinstance(value, str):
                lines.append(f'{prefix}{key} = "{value}"')
            elif isinstance(value, bool):
                lines.append(f'{prefix}{key} = {"true" if value else "false"}')
            elif isinstance(value, (int, float)):
                lines.append(f'{prefix}{key} = {value}')
            elif isinstance(value, list):
                items = ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in value)
                lines.append(f'{prefix}{key} = [{items}]')

        for table_key, table_value in tables:
            lines.append(f'\n[{table_key}]')
            lines.append(write_toml(table_value, 0))

        return "\n".join(lines)

    try:
        # Charger la config actuelle
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'rb') as f:
                current = tomllib.load(f)
        else:
            current = {}

        # Merger les nouvelles valeurs (recursif)
        def deep_merge(base: dict, update: dict) -> dict:
            result = base.copy()
            for key, value in update.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            return result

        merged = deep_merge(current, config_data)

        # Ecrire la nouvelle config
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, 'w') as f:
            f.write(write_toml(merged))

        log.info("Configuration mise a jour")
        return True

    except Exception as e:
        log.error("Erreur mise a jour config: %s", e)
        return False


def trigger_ota_update() -> dict:
    """
    Declencher une mise a jour OTA.

    Lance le script de mise a jour en arriere-plan.

    Returns:
        Dict avec le statut de la mise a jour
    """
    ota_script = Path("/usr/local/bin/secubox-eye-update.sh")

    if not ota_script.exists():
        return {
            "success": False,
            "error": "Script de mise a jour non trouve"
        }

    try:
        # Lancer en arriere-plan
        subprocess.Popen(
            ['sudo', str(ota_script)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

        return {
            "success": True,
            "message": "Mise a jour OTA demarree"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


# =============================================================================
# Gestionnaire de Commandes
# =============================================================================


@dataclass
class CommandHandler:
    """
    Gestionnaire de commandes pour Eye Remote.

    Execute les commandes recues du SecuBox et retourne les resultats.
    Peut etre etendu avec des handlers personnalises.
    """

    # Handlers personnalises: commande -> callback
    _custom_handlers: dict[str, Callable] = field(default_factory=dict)

    # Callback pour actions sur le SecuBox (lockdown, etc.)
    _secubox_action_callback: Optional[Callable] = None

    def register_handler(self, command: str, handler: Callable):
        """
        Enregistrer un handler personnalise pour une commande.

        Args:
            command: Nom de la commande
            handler: Fonction async qui prend (params: dict) -> dict
        """
        self._custom_handlers[command] = handler
        log.debug("Handler enregistre pour: %s", command)

    def set_secubox_action_callback(self, callback: Callable):
        """
        Definir le callback pour les actions SecuBox.

        Args:
            callback: Fonction async qui prend (action: str, params: dict) -> dict
        """
        self._secubox_action_callback = callback

    async def execute(self, command: str, params: Optional[dict] = None) -> dict:
        """
        Executer une commande.

        Args:
            command: Nom de la commande
            params: Parametres optionnels

        Returns:
            Dict avec le resultat de la commande
        """
        params = params or {}
        log.info("Execution commande: %s params=%s", command, params)

        try:
            # Verifier d'abord les handlers personnalises
            if command in self._custom_handlers:
                handler = self._custom_handlers[command]
                import inspect
                if inspect.iscoroutinefunction(handler):
                    return await handler(params)
                else:
                    return handler(params)

            # Commandes internes
            if command == Command.SCREENSHOT.value:
                return await self._handle_screenshot(params)

            elif command == Command.REBOOT.value:
                return await self._handle_reboot(params)

            elif command == Command.CONFIG_UPDATE.value:
                return await self._handle_config_update(params)

            elif command == Command.SERVICE_RESTART.value:
                return await self._handle_service_restart(params)

            elif command == Command.OTA_UPDATE.value:
                return await self._handle_ota_update(params)

            elif command in (Command.LOCKDOWN.value, Command.UNLOCK.value):
                return await self._handle_lockdown(command, params)

            else:
                log.warning("Commande inconnue: %s", command)
                return {
                    "success": False,
                    "error": f"Commande inconnue: {command}"
                }

        except Exception as e:
            log.error("Erreur execution %s: %s", command, e)
            return {
                "success": False,
                "error": str(e)
            }

    async def _handle_screenshot(self, params: dict) -> dict:
        """Capturer une capture d'ecran."""
        try:
            # Executer dans un thread pour ne pas bloquer
            loop = asyncio.get_event_loop()
            image_data = await loop.run_in_executor(None, capture_screenshot)

            return {
                "success": True,
                "image": image_data,
                "format": "png",
                "encoding": "base64",
                "width": FRAMEBUFFER_WIDTH,
                "height": FRAMEBUFFER_HEIGHT
            }

        except ScreenshotError as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def _handle_reboot(self, params: dict) -> dict:
        """Redemarrer le systeme."""
        delay = params.get("delay", 0)

        if execute_reboot(delay):
            return {
                "success": True,
                "message": f"Redemarrage dans {delay} secondes"
            }
        else:
            return {
                "success": False,
                "error": "Echec du redemarrage"
            }

    async def _handle_config_update(self, params: dict) -> dict:
        """Mettre a jour la configuration."""
        config_data = params.get("config", {})

        if not config_data:
            return {
                "success": False,
                "error": "Aucune configuration fournie"
            }

        if update_config(config_data):
            return {
                "success": True,
                "message": "Configuration mise a jour"
            }
        else:
            return {
                "success": False,
                "error": "Echec mise a jour configuration"
            }

    async def _handle_service_restart(self, params: dict) -> dict:
        """Redemarrer un service."""
        service = params.get("service")

        if not service:
            return {
                "success": False,
                "error": "Nom du service requis"
            }

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, restart_service, service)

            return {
                "success": True,
                "message": f"Service {service} redemarre"
            }

        except ServiceError as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def _handle_ota_update(self, params: dict) -> dict:
        """Declencher une mise a jour OTA."""
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, trigger_ota_update)
        return result

    async def _handle_lockdown(self, command: str, params: dict) -> dict:
        """
        Activer/desactiver le mode lockdown sur SecuBox.

        Cette commande est relayee au SecuBox via le callback.
        """
        if not self._secubox_action_callback:
            return {
                "success": False,
                "error": "Callback SecuBox non configure"
            }

        try:
            action = "enable" if command == Command.LOCKDOWN.value else "disable"
            result = await self._secubox_action_callback("lockdown", {
                "action": action,
                **params
            })
            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


# =============================================================================
# Client WebSocket
# =============================================================================


@dataclass
class WebSocketClient:
    """
    Client WebSocket pour la connexion au SecuBox.

    Gere:
    - Connexion avec authentification par token
    - Reconnexion automatique
    - Reception et traitement des commandes
    - Envoi des reponses et metriques
    """

    host: str
    device_id: str
    token: str
    command_handler: CommandHandler
    port: int = 8000
    ssl: bool = False
    reconnect_delay: float = 5.0
    max_reconnect_attempts: int = -1  # -1 = infini

    _ws: Optional[Any] = field(default=None, repr=False)
    _running: bool = field(default=False, repr=False)
    _connected: bool = field(default=False, repr=False)
    _reconnect_attempts: int = field(default=0, repr=False)
    _receive_task: Optional[asyncio.Task] = field(default=None, repr=False)

    # Callbacks
    _on_connect: Optional[Callable] = field(default=None, repr=False)
    _on_disconnect: Optional[Callable] = field(default=None, repr=False)
    _on_error: Optional[Callable] = field(default=None, repr=False)

    def __post_init__(self):
        self._running = False
        self._connected = False
        self._reconnect_attempts = 0

    @property
    def ws_url(self) -> str:
        """Construire l'URL WebSocket."""
        protocol = "wss" if self.ssl else "ws"
        return f"{protocol}://{self.host}:{self.port}/api/v1/eye-remote/ws/{self.device_id}?token={self.token}"

    @property
    def is_connected(self) -> bool:
        """Verifier si connecte."""
        return self._connected

    def on_connect(self, callback: Callable):
        """Definir le callback de connexion."""
        self._on_connect = callback

    def on_disconnect(self, callback: Callable):
        """Definir le callback de deconnexion."""
        self._on_disconnect = callback

    def on_error(self, callback: Callable):
        """Definir le callback d'erreur."""
        self._on_error = callback

    async def connect(self):
        """
        Etablir la connexion WebSocket.

        Gere l'authentification et demarre la boucle de reception.
        """
        try:
            import websockets
        except ImportError:
            log.error("websockets non installe: pip install websockets")
            return False

        try:
            log.info("Connexion a %s...", self.ws_url.split("?")[0])

            self._ws = await websockets.connect(
                self.ws_url,
                ping_interval=20,
                ping_timeout=10,
                close_timeout=5
            )

            self._connected = True
            self._reconnect_attempts = 0
            log.info("Connecte au SecuBox")

            if self._on_connect:
                try:
                    await self._on_connect()
                except Exception as e:
                    log.warning("Erreur callback on_connect: %s", e)

            return True

        except Exception as e:
            log.error("Erreur connexion: %s", e)
            self._connected = False

            if self._on_error:
                try:
                    await self._on_error(e)
                except Exception:
                    pass

            return False

    async def disconnect(self):
        """Fermer la connexion."""
        self._running = False
        self._connected = False

        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass

        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

        log.info("Deconnecte du SecuBox")

        if self._on_disconnect:
            try:
                await self._on_disconnect()
            except Exception:
                pass

    async def send_message(self, msg_type: str, data: Optional[dict] = None, **kwargs) -> bool:
        """
        Envoyer un message au SecuBox.

        Args:
            msg_type: Type de message
            data: Donnees du message
            **kwargs: Champs additionnels

        Returns:
            True si envoye avec succes
        """
        if not self._ws or not self._connected:
            return False

        message: dict[str, Any] = {
            "type": msg_type,
            "id": kwargs.get("id", str(uuid.uuid4())),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if data is not None:
            message["data"] = data
        message.update(kwargs)

        try:
            await self._ws.send(json.dumps(message))
            return True
        except Exception as e:
            log.error("Erreur envoi message: %s", e)
            return False

    async def send_response(
        self,
        request_id: str,
        data: Optional[dict] = None,
        error: Optional[str] = None
    ) -> bool:
        """
        Envoyer une reponse a une commande.

        Args:
            request_id: ID de la requete originale
            data: Donnees de reponse
            error: Message d'erreur optionnel

        Returns:
            True si envoye avec succes
        """
        kwargs: dict[str, Any] = {"id": request_id}
        if error is not None:
            kwargs["error"] = error
        return await self.send_message(
            MessageType.RESPONSE.value,
            data=data,
            **kwargs
        )

    async def send_metrics(self, metrics: dict) -> bool:
        """
        Envoyer une mise a jour des metriques.

        Args:
            metrics: Dict avec les metriques

        Returns:
            True si envoye avec succes
        """
        return await self.send_message(
            MessageType.METRICS.value,
            data=metrics
        )

    async def send_status(self, status: dict) -> bool:
        """
        Envoyer une mise a jour du statut.

        Args:
            status: Dict avec le statut

        Returns:
            True si envoye avec succes
        """
        return await self.send_message(
            MessageType.STATUS.value,
            data=status
        )

    async def _handle_message(self, raw: str):
        """
        Traiter un message recu.

        Args:
            raw: Message JSON brut
        """
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("Message JSON invalide: %s", raw[:100])
            return

        msg_type = message.get("type", "")
        msg_id = message.get("id", "")

        if msg_type == MessageType.COMMAND.value:
            # Executer la commande
            cmd = message.get("cmd", "")
            params = message.get("params", {})

            log.info("Commande recue: %s (id=%s)", cmd, msg_id)

            result = await self.command_handler.execute(cmd, params)

            # Envoyer la reponse
            error = result.pop("error", None) if not result.get("success", True) else None
            await self.send_response(msg_id, data=result, error=error)

        elif msg_type == MessageType.PING.value:
            # Repondre au heartbeat
            await self.send_message(MessageType.PONG.value, id=msg_id)

        elif msg_type == MessageType.STATUS.value:
            # Confirmation de statut (authentification, etc.)
            data = message.get("data", {})
            if data.get("authenticated"):
                log.info("Authentification confirmee")

        elif msg_type == MessageType.ERROR.value:
            error = message.get("error", "Unknown error")
            log.error("Erreur du serveur: %s", error)

        else:
            log.debug("Message type inconnu: %s", msg_type)

    async def _receive_loop(self):
        """Boucle de reception des messages."""
        try:
            import websockets
        except ImportError:
            return

        while self._running and self._ws:
            try:
                raw = await self._ws.recv()
                await self._handle_message(raw)

            except websockets.ConnectionClosed as e:
                log.warning("Connexion fermee: %s", e)
                self._connected = False
                break

            except asyncio.CancelledError:
                break

            except Exception as e:
                log.error("Erreur reception: %s", e)
                await asyncio.sleep(0.1)

    async def run(self):
        """
        Boucle principale avec reconnexion automatique.

        Maintient la connexion active et gere les reconnexions.
        """
        self._running = True

        while self._running:
            # Connexion
            if not self._connected:
                success = await self.connect()

                if not success:
                    self._reconnect_attempts += 1

                    if (self.max_reconnect_attempts > 0 and
                            self._reconnect_attempts >= self.max_reconnect_attempts):
                        log.error("Nombre max de tentatives atteint")
                        break

                    log.info("Reconnexion dans %.1fs (tentative %d)...",
                             self.reconnect_delay, self._reconnect_attempts)
                    await asyncio.sleep(self.reconnect_delay)
                    continue

            # Boucle de reception
            self._receive_task = asyncio.create_task(self._receive_loop())
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass

            # Deconnexion detectee
            if self._running:
                self._connected = False
                if self._on_disconnect:
                    try:
                        await self._on_disconnect()
                    except Exception:
                        pass

                log.info("Reconnexion dans %.1fs...", self.reconnect_delay)
                await asyncio.sleep(self.reconnect_delay)

    async def stop(self):
        """Arreter le client proprement."""
        self._running = False
        await self.disconnect()


# =============================================================================
# Factory Function
# =============================================================================


def create_command_client(
    host: str,
    device_id: str,
    token: str,
    port: int = 8000,
    ssl: bool = False
) -> tuple[WebSocketClient, CommandHandler]:
    """
    Creer un client WebSocket avec son gestionnaire de commandes.

    Args:
        host: Adresse du SecuBox
        device_id: ID de l'appareil
        token: Token d'authentification
        port: Port API (defaut 8000)
        ssl: Utiliser WSS (defaut False)

    Returns:
        Tuple (WebSocketClient, CommandHandler)
    """
    handler = CommandHandler()
    client = WebSocketClient(
        host=host,
        device_id=device_id,
        token=token,
        command_handler=handler,
        port=port,
        ssl=ssl
    )

    return client, handler


# =============================================================================
# Exemple d'Utilisation
# =============================================================================


async def main():
    """Exemple d'utilisation du command handler."""
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Configuration exemple
    host = os.environ.get("SECUBOX_HOST", "10.55.0.1")
    device_id = os.environ.get("DEVICE_ID", "eye-remote-001")
    token = os.environ.get("DEVICE_TOKEN", "")

    if not token:
        log.error("DEVICE_TOKEN non defini")
        sys.exit(1)

    # Creer le client
    client, handler = create_command_client(host, device_id, token)

    # Callbacks optionnels
    async def on_connect():
        log.info("Connecte - envoi statut initial")
        await client.send_status({
            "state": "ready",
            "firmware": "2.0.0"
        })

    async def on_disconnect():
        log.info("Deconnecte - nettoyage...")

    client.on_connect(on_connect)
    client.on_disconnect(on_disconnect)

    # Handler personnalise exemple
    def custom_handler(params: dict) -> dict:
        return {"success": True, "message": "Commande personnalisee executee"}

    handler.register_handler("custom_cmd", custom_handler)

    # Lancer le client
    try:
        await client.run()
    except KeyboardInterrupt:
        log.info("Arret demande...")
    finally:
        await client.stop()


if __name__ == "__main__":
    asyncio.run(main())
