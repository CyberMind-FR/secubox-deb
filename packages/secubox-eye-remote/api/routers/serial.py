"""
SecuBox Eye Remote — Serial Console Router
Endpoint WebSocket pour l'acces console serie aux appareils Eye Remote.

Permet l'acces terminal distant via xterm.js depuis la WebUI SecuBox.
Le SecuBox voit /dev/ttyACM0 quand un Eye Remote est connecte via USB OTG.

CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException, status
from pydantic import BaseModel, Field

from ...core.device_registry import get_device_registry
from ...core.token_manager import hash_token

log = logging.getLogger(__name__)

router = APIRouter(prefix="/serial", tags=["serial"])


# =============================================================================
# Configuration
# =============================================================================

# Chemin par defaut du port serie ACM (USB OTG)
DEFAULT_SERIAL_DEVICE = "/dev/ttyACM0"

# Configuration serie par defaut
DEFAULT_BAUD_RATE = 115200
DEFAULT_BYTESIZE = 8
DEFAULT_PARITY = "N"
DEFAULT_STOPBITS = 1

# Taille du buffer de lecture
READ_BUFFER_SIZE = 4096

# Timeout de lecture serie (ms)
SERIAL_READ_TIMEOUT = 0.1


# =============================================================================
# Modeles
# =============================================================================


class SerialConfig(BaseModel):
    """Configuration du port serie."""
    device: str = Field(default=DEFAULT_SERIAL_DEVICE, description="Chemin du device serie")
    baud_rate: int = Field(default=DEFAULT_BAUD_RATE, description="Debit en bauds")
    bytesize: int = Field(default=DEFAULT_BYTESIZE, description="Bits de donnees (5-8)")
    parity: str = Field(default=DEFAULT_PARITY, description="Parite (N/E/O/M/S)")
    stopbits: float = Field(default=DEFAULT_STOPBITS, description="Bits de stop (1/1.5/2)")


class SerialStatus(BaseModel):
    """Statut de la connexion serie."""
    connected: bool = Field(..., description="Port serie connecte")
    device: str = Field(..., description="Chemin du device")
    baud_rate: int = Field(..., description="Debit actuel")
    clients: int = Field(default=0, description="Nombre de clients WebSocket connectes")
    writer_client: Optional[str] = Field(default=None, description="ID du client en ecriture")
    opened_at: Optional[datetime] = Field(default=None, description="Timestamp ouverture")


class SerialDeviceInfo(BaseModel):
    """Informations sur un device serie disponible."""
    path: str = Field(..., description="Chemin du device")
    exists: bool = Field(..., description="Le device existe")
    readable: bool = Field(default=False, description="Lisible")
    writable: bool = Field(default=False, description="Modifiable")


# =============================================================================
# Gestionnaire de Connexions Serie
# =============================================================================


@dataclass
class SerialClient:
    """Client WebSocket connecte au port serie."""
    client_id: str
    websocket: WebSocket
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    can_write: bool = False


class SerialConnectionManager:
    """
    Gestionnaire de connexions serie avec broadcast WebSocket.

    Caracteristiques:
    - Un seul port serie ouvert a la fois
    - Plusieurs clients WebSocket peuvent lire (broadcast)
    - Seul le premier client peut ecrire
    - Gestion gracieuse des deconnexions
    """

    def __init__(self):
        # Clients WebSocket connectes: client_id -> SerialClient
        self._clients: dict[str, SerialClient] = {}
        # Port serie ouvert
        self._serial: Optional[asyncio.StreamReader | asyncio.StreamWriter] = None
        self._serial_reader: Optional[asyncio.StreamReader] = None
        self._serial_writer: Optional[asyncio.StreamWriter] = None
        # Configuration actuelle
        self._config: Optional[SerialConfig] = None
        # Timestamp ouverture
        self._opened_at: Optional[datetime] = None
        # ID du client avec droits d'ecriture (premier connecte)
        self._writer_client_id: Optional[str] = None
        # Lock pour acces concurrent
        self._lock = asyncio.Lock()
        # Tache de lecture serie
        self._read_task: Optional[asyncio.Task] = None

    async def open_serial(self, config: SerialConfig) -> bool:
        """
        Ouvrir le port serie.

        Args:
            config: Configuration du port serie

        Returns:
            True si ouverture reussie
        """
        async with self._lock:
            if self._serial_reader is not None:
                log.debug("Port serie deja ouvert")
                return True

            if not Path(config.device).exists():
                log.error("Device serie introuvable: %s", config.device)
                return False

            try:
                # Ouvrir le port serie avec asyncio
                # Note: pyserial-asyncio serait ideal mais on utilise une approche
                # basee sur os.open + asyncio pour eviter une dependance supplementaire
                self._serial_reader, self._serial_writer = await self._open_serial_async(config)
                self._config = config
                self._opened_at = datetime.now(timezone.utc)

                log.info(
                    "Port serie ouvert: %s @ %d bauds",
                    config.device, config.baud_rate
                )

                # Demarrer la tache de lecture
                self._read_task = asyncio.create_task(self._serial_read_loop())

                return True

            except Exception as e:
                log.error("Erreur ouverture serie %s: %s", config.device, e)
                return False

    async def _open_serial_async(
        self,
        config: SerialConfig
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Ouvrir le port serie en mode asynchrone.

        Utilise une approche low-level avec os.open + termios pour
        eviter la dependance pyserial-asyncio.
        """
        import termios
        import tty

        # Ouvrir le device en mode non-bloquant
        fd = os.open(config.device, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)

        # Configurer les attributs termios
        attrs = termios.tcgetattr(fd)

        # Mapper le baud rate
        baud_map = {
            9600: termios.B9600,
            19200: termios.B19200,
            38400: termios.B38400,
            57600: termios.B57600,
            115200: termios.B115200,
            230400: termios.B230400,
            460800: termios.B460800,
            921600: termios.B921600,
        }
        baud = baud_map.get(config.baud_rate, termios.B115200)

        # Input flags: desactiver tout le traitement
        attrs[0] = 0  # iflag

        # Output flags: desactiver tout le traitement
        attrs[1] = 0  # oflag

        # Control flags: 8N1
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL | baud

        # Local flags: mode raw
        attrs[3] = 0  # lflag

        # Control characters
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 1  # 0.1 secondes timeout

        # Appliquer les attributs
        termios.tcsetattr(fd, termios.TCSANOW, attrs)

        # Flush les buffers
        termios.tcflush(fd, termios.TCIOFLUSH)

        # Creer les streams asyncio
        loop = asyncio.get_event_loop()

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)

        transport, _ = await loop.create_connection(
            lambda: protocol,
            sock=self._fd_to_socket(fd)
        )

        writer = asyncio.StreamWriter(transport, protocol, reader, loop)

        # Stocker le fd pour le fermer plus tard
        self._serial_fd = fd

        return reader, writer

    def _fd_to_socket(self, fd: int):
        """
        Convertir un file descriptor en objet socket-like.

        Necessaire pour asyncio.create_connection.
        """
        import socket

        # Creer un socket a partir du fd
        sock = socket.socket(fileno=fd)
        sock.setblocking(False)
        return sock

    async def close_serial(self):
        """Fermer le port serie."""
        async with self._lock:
            # Annuler la tache de lecture
            if self._read_task:
                self._read_task.cancel()
                try:
                    await self._read_task
                except asyncio.CancelledError:
                    pass
                self._read_task = None

            # Fermer le writer
            if self._serial_writer:
                self._serial_writer.close()
                try:
                    await self._serial_writer.wait_closed()
                except Exception:
                    pass
                self._serial_writer = None

            self._serial_reader = None

            # Fermer le fd si necessaire
            if hasattr(self, '_serial_fd'):
                try:
                    os.close(self._serial_fd)
                except OSError:
                    pass
                del self._serial_fd

            self._config = None
            self._opened_at = None

            log.info("Port serie ferme")

    async def _serial_read_loop(self):
        """
        Boucle de lecture serie.

        Lit en continu du port serie et broadcast aux clients WebSocket.
        """
        while True:
            try:
                if not self._serial_reader:
                    break

                # Lire les donnees disponibles
                data = await asyncio.wait_for(
                    self._serial_reader.read(READ_BUFFER_SIZE),
                    timeout=SERIAL_READ_TIMEOUT
                )

                if data:
                    # Broadcast aux clients
                    await self._broadcast_to_clients(data)

            except asyncio.TimeoutError:
                # Timeout normal, continuer
                continue
            except asyncio.CancelledError:
                log.debug("Tache lecture serie annulee")
                break
            except Exception as e:
                log.error("Erreur lecture serie: %s", e)
                await asyncio.sleep(0.5)

    async def _broadcast_to_clients(self, data: bytes):
        """
        Diffuser les donnees serie a tous les clients WebSocket.

        Args:
            data: Donnees brutes a envoyer
        """
        if not self._clients:
            return

        disconnected = []

        for client_id, client in self._clients.items():
            try:
                # Envoyer en mode bytes (binaire)
                await client.websocket.send_bytes(data)
            except Exception as e:
                log.warning("Erreur envoi a %s: %s", client_id, e)
                disconnected.append(client_id)

        # Nettoyer les connexions mortes
        for client_id in disconnected:
            await self.disconnect_client(client_id)

    async def write_serial(self, client_id: str, data: bytes) -> bool:
        """
        Ecrire sur le port serie.

        Seul le client avec droits d'ecriture peut ecrire.

        Args:
            client_id: ID du client emetteur
            data: Donnees a ecrire

        Returns:
            True si ecriture reussie
        """
        async with self._lock:
            # Verifier les droits d'ecriture
            if self._writer_client_id and client_id != self._writer_client_id:
                log.warning(
                    "Client %s tente d'ecrire sans droits (writer=%s)",
                    client_id, self._writer_client_id
                )
                return False

            if not self._serial_writer:
                log.warning("Port serie non ouvert pour ecriture")
                return False

            try:
                self._serial_writer.write(data)
                await self._serial_writer.drain()
                return True
            except Exception as e:
                log.error("Erreur ecriture serie: %s", e)
                return False

    async def connect_client(
        self,
        client_id: str,
        websocket: WebSocket,
        config: SerialConfig
    ) -> bool:
        """
        Connecter un nouveau client WebSocket.

        Le premier client obtient les droits d'ecriture.

        Args:
            client_id: ID unique du client
            websocket: Connexion WebSocket
            config: Configuration serie souhaitee

        Returns:
            True si connexion reussie
        """
        # Ouvrir le port serie si necessaire
        if self._serial_reader is None:
            if not await self.open_serial(config):
                return False

        async with self._lock:
            # Creer le client
            is_first = len(self._clients) == 0
            client = SerialClient(
                client_id=client_id,
                websocket=websocket,
                can_write=is_first
            )

            self._clients[client_id] = client

            # Premier client = droits d'ecriture
            if is_first:
                self._writer_client_id = client_id
                log.info("Client %s connecte avec droits d'ecriture", client_id)
            else:
                log.info("Client %s connecte en lecture seule", client_id)

            return True

    async def disconnect_client(self, client_id: str):
        """
        Deconnecter un client WebSocket.

        Si c'etait le writer, le prochain client devient writer.

        Args:
            client_id: ID du client a deconnecter
        """
        async with self._lock:
            if client_id not in self._clients:
                return

            del self._clients[client_id]
            log.info("Client %s deconnecte", client_id)

            # Si c'etait le writer, promouvoir le suivant
            if self._writer_client_id == client_id:
                self._writer_client_id = None
                if self._clients:
                    next_client = next(iter(self._clients.keys()))
                    self._writer_client_id = next_client
                    self._clients[next_client].can_write = True
                    log.info("Client %s promu en writer", next_client)

            # Fermer le port si plus de clients
            if not self._clients:
                # Liberer le lock avant close_serial
                pass

        # Fermer hors du lock
        if not self._clients:
            await self.close_serial()

    def get_status(self) -> SerialStatus:
        """Obtenir le statut de la connexion serie."""
        return SerialStatus(
            connected=self._serial_reader is not None,
            device=self._config.device if self._config else DEFAULT_SERIAL_DEVICE,
            baud_rate=self._config.baud_rate if self._config else DEFAULT_BAUD_RATE,
            clients=len(self._clients),
            writer_client=self._writer_client_id,
            opened_at=self._opened_at
        )

    def is_writer(self, client_id: str) -> bool:
        """Verifier si un client a les droits d'ecriture."""
        return self._writer_client_id == client_id


# Instance singleton
serial_manager = SerialConnectionManager()


# =============================================================================
# Fonctions d'Authentification
# =============================================================================


def authenticate_for_serial(device_id: str, token: str) -> bool:
    """
    Authentifier un client pour l'acces serie.

    Args:
        device_id: ID de l'appareil Eye Remote
        token: Token d'authentification

    Returns:
        True si authentification reussie
    """
    if not device_id or not token:
        return False

    registry = get_device_registry()
    device = registry.get_device(device_id)

    if not device:
        log.warning("Appareil inconnu pour acces serie: %s", device_id)
        return False

    # Verifier le hash du token
    token_hashed = hash_token(token)
    if device.token_hash != token_hashed:
        log.warning("Token invalide pour acces serie: %s", device_id)
        return False

    log.info("Acces serie autorise pour: %s", device_id)
    return True


# =============================================================================
# Endpoints REST
# =============================================================================


@router.get("/status", response_model=SerialStatus)
async def get_serial_status() -> SerialStatus:
    """
    Obtenir le statut de la connexion serie.

    Returns:
        Statut de la connexion serie.
    """
    return serial_manager.get_status()


@router.get("/devices")
async def list_serial_devices() -> list[SerialDeviceInfo]:
    """
    Lister les devices serie disponibles.

    Recherche les devices ttyACM* et ttyUSB* courants.

    Returns:
        Liste des devices serie detectes.
    """
    devices = []

    # Patterns de devices a rechercher
    patterns = [
        "/dev/ttyACM*",
        "/dev/ttyUSB*",
        "/dev/ttyGS*",
    ]

    for pattern in patterns:
        import glob
        for path in glob.glob(pattern):
            info = SerialDeviceInfo(
                path=path,
                exists=True,
                readable=os.access(path, os.R_OK),
                writable=os.access(path, os.W_OK)
            )
            devices.append(info)

    return devices


# =============================================================================
# Endpoint WebSocket Serie
# =============================================================================


@router.websocket("/console/{device_id}")
async def websocket_serial_console(
    websocket: WebSocket,
    device_id: str,
    token: Optional[str] = Query(None),
    baud: int = Query(DEFAULT_BAUD_RATE, description="Baud rate"),
    device: str = Query(DEFAULT_SERIAL_DEVICE, description="Serial device path")
):
    """
    Endpoint WebSocket pour la console serie.

    Authentification via query param token.
    Les donnees sont transmises en binaire (bytes).

    Protocol:
    - Client envoie bytes -> ecrit sur port serie
    - Serveur envoie bytes -> donnees lues du port serie

    Args:
        websocket: Connexion WebSocket
        device_id: ID de l'appareil Eye Remote
        token: Token d'authentification
        baud: Baud rate (defaut: 115200)
        device: Chemin du device serie (defaut: /dev/ttyACM0)
    """
    # Authentification requise
    if not token:
        log.warning("Tentative connexion serie sans token: %s", device_id)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    if not authenticate_for_serial(device_id, token):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Accepter la connexion
    await websocket.accept()

    # Generer un ID client unique
    client_id = f"{device_id}_{id(websocket)}"

    # Configuration serie
    config = SerialConfig(
        device=device,
        baud_rate=baud
    )

    # Connecter le client
    if not await serial_manager.connect_client(client_id, websocket, config):
        error_msg = b"ERROR: Cannot open serial port\r\n"
        await websocket.send_bytes(error_msg)
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return

    # Informer le client de ses droits
    is_writer = serial_manager.is_writer(client_id)
    if is_writer:
        await websocket.send_bytes(b"\r\n[Serial console connected - read/write]\r\n")
    else:
        await websocket.send_bytes(b"\r\n[Serial console connected - read-only]\r\n")

    try:
        # Boucle de reception des donnees du client
        while True:
            # Recevoir en mode bytes
            data = await websocket.receive_bytes()

            if data:
                # Ecrire sur le port serie
                success = await serial_manager.write_serial(client_id, data)
                if not success and is_writer:
                    log.warning("Echec ecriture serie pour %s", client_id)

    except WebSocketDisconnect:
        log.info("Client serie deconnecte: %s", client_id)
    except Exception as e:
        log.error("Erreur WebSocket serie %s: %s", client_id, e)
    finally:
        await serial_manager.disconnect_client(client_id)


# =============================================================================
# Fonctions Utilitaires
# =============================================================================


def get_serial_manager() -> SerialConnectionManager:
    """Obtenir l'instance du gestionnaire de connexions serie."""
    return serial_manager
