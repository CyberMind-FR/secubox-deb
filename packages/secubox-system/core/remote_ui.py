"""
SecuBox-Deb :: core.remote_ui — Gestionnaire de connexion Remote UI
====================================================================
Maintient l'état du transport actif (OTG / WiFi / absent) et détecte
la présence de l'interface secubox-round via polling ou événements udev.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from secubox_core.logger import get_logger

log = get_logger("remote_ui")


# ══════════════════════════════════════════════════════════════════════════════
# Configuration par défaut
# ══════════════════════════════════════════════════════════════════════════════

OTG_INTERFACE = "secubox-round"
OTG_HOST_IP = "10.55.0.1"
OTG_PEER_IP = "10.55.0.2"
OTG_NETWORK = "10.55.0.0/30"
STATE_FILE = Path("/run/secubox/remote-ui-otg.state")
SERIAL_CONSOLE = Path("/dev/secubox-console")
PROBE_INTERVAL = 30  # secondes


# ══════════════════════════════════════════════════════════════════════════════
# État de connexion
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RemoteUIState:
    """État de la connexion Remote UI."""
    connected: bool = False
    transport: str = "none"  # "otg" | "wifi" | "none"
    peer_ip: str = ""
    interface: str = ""
    connected_at: float = 0.0
    last_seen: float = 0.0
    serial_available: bool = False
    serial_device: str = ""
    error_count: int = 0

    def uptime_seconds(self) -> int:
        """Calcule l'uptime de la connexion."""
        if not self.connected or self.connected_at == 0:
            return 0
        return int(time.time() - self.connected_at)

    def last_seen_iso(self) -> str:
        """Retourne last_seen au format ISO 8601."""
        if self.last_seen == 0:
            return ""
        return datetime.fromtimestamp(self.last_seen).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dictionnaire pour l'API."""
        return {
            "connected": self.connected,
            "transport": self.transport,
            "peer_ip": self.peer_ip,
            "interface": self.interface,
            "uptime_seconds": self.uptime_seconds(),
            "last_seen": self.last_seen_iso(),
            "serial_available": self.serial_available,
            "serial_device": self.serial_device,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Gestionnaire Remote UI (Singleton)
# ══════════════════════════════════════════════════════════════════════════════

class RemoteUIManager:
    """
    Gestionnaire de connexion Remote UI.

    Gère l'état du transport OTG/WiFi et détecte la présence du Remote UI.
    Utilisé par l'API /api/v1/remote-ui/* et le système d'événements.
    """

    _instance: Optional["RemoteUIManager"] = None
    _state: RemoteUIState
    _probe_task: Optional[asyncio.Task] = None

    def __new__(cls) -> "RemoteUIManager":
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._state = RemoteUIState()
            cls._instance._probe_task = None
        return cls._instance

    @property
    def state(self) -> RemoteUIState:
        """Accès à l'état actuel."""
        return self._state

    # ─────────────────────────────────────────────────────────────────────────
    # Détection de l'interface OTG
    # ─────────────────────────────────────────────────────────────────────────

    def _check_interface_exists(self) -> bool:
        """Vérifie si l'interface secubox-round existe."""
        interface_path = Path(f"/sys/class/net/{OTG_INTERFACE}")
        return interface_path.exists()

    def _check_interface_up(self) -> bool:
        """Vérifie si l'interface est UP."""
        operstate_path = Path(f"/sys/class/net/{OTG_INTERFACE}/operstate")
        if not operstate_path.exists():
            return False
        try:
            state = operstate_path.read_text().strip()
            return state in ("up", "unknown")  # unknown = carrier sans IP
        except Exception:
            return False

    def _check_peer_reachable(self) -> bool:
        """Vérifie si le peer est joignable (ping rapide)."""
        import subprocess
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", OTG_PEER_IP],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_serial_console(self) -> tuple[bool, str]:
        """Vérifie si la console série est disponible."""
        if SERIAL_CONSOLE.is_symlink():
            target = os.readlink(SERIAL_CONSOLE)
            if Path(target).exists() or Path(f"/dev/{target}").exists():
                return True, str(SERIAL_CONSOLE)

        # Chercher un ttyACM disponible
        for tty in Path("/dev").glob("ttyACM*"):
            if tty.is_char_device():
                return True, str(tty)

        return False, ""

    def _read_state_file(self) -> Optional[Dict]:
        """Lit le fichier d'état écrit par le script udev."""
        if not STATE_FILE.exists():
            return None
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception as e:
            log.warning("Erreur lecture fichier état: %s", e)
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Détection complète
    # ─────────────────────────────────────────────────────────────────────────

    def detect_otg_connection(self) -> bool:
        """
        Détecte si un Remote UI est connecté en OTG.
        Met à jour l'état interne.

        Returns:
            True si connecté en OTG, False sinon.
        """
        # 1. Vérifier l'interface
        if not self._check_interface_exists():
            self._update_disconnected()
            return False

        # 2. Vérifier l'état de l'interface
        if not self._check_interface_up():
            log.debug("Interface %s existe mais pas UP", OTG_INTERFACE)
            self._update_disconnected()
            return False

        # 3. Lire le fichier d'état (écrit par udev)
        state_data = self._read_state_file()

        # 4. Vérifier la console série
        serial_ok, serial_dev = self._check_serial_console()

        # 5. Mettre à jour l'état
        now = time.time()

        if not self._state.connected:
            # Nouvelle connexion
            self._state.connected_at = now
            log.info("Remote UI OTG connecté sur %s", OTG_INTERFACE)

        self._state.connected = True
        self._state.transport = "otg"
        self._state.interface = OTG_INTERFACE
        self._state.peer_ip = state_data.get("peer_ip", OTG_PEER_IP) if state_data else OTG_PEER_IP
        self._state.last_seen = now
        self._state.serial_available = serial_ok
        self._state.serial_device = serial_dev
        self._state.error_count = 0

        return True

    def _update_disconnected(self):
        """Met à jour l'état en déconnecté."""
        if self._state.connected and self._state.transport == "otg":
            log.info("Remote UI OTG déconnecté")

        self._state.connected = False
        self._state.transport = "none"
        self._state.interface = ""
        self._state.peer_ip = ""
        self._state.serial_available = False
        self._state.serial_device = ""

    # ─────────────────────────────────────────────────────────────────────────
    # API pour les événements udev
    # ─────────────────────────────────────────────────────────────────────────

    def on_connected(self, transport: str, peer: str, interface: str = "") -> None:
        """
        Appelé lors d'une connexion (par l'API depuis le script udev).

        Args:
            transport: Type de transport ("otg" ou "wifi")
            peer: Adresse IP du peer
            interface: Nom de l'interface réseau
        """
        now = time.time()

        log.info("Remote UI connecté: transport=%s, peer=%s, interface=%s",
                 transport, peer, interface)

        self._state.connected = True
        self._state.transport = transport
        self._state.peer_ip = peer
        self._state.interface = interface or OTG_INTERFACE
        self._state.connected_at = now
        self._state.last_seen = now
        self._state.error_count = 0

        # Vérifier la console série si OTG
        if transport == "otg":
            serial_ok, serial_dev = self._check_serial_console()
            self._state.serial_available = serial_ok
            self._state.serial_device = serial_dev

    def on_disconnected(self, transport: str) -> None:
        """
        Appelé lors d'une déconnexion (par l'API depuis le script udev).

        Args:
            transport: Type de transport déconnecté
        """
        log.info("Remote UI déconnecté: transport=%s", transport)

        if self._state.transport == transport:
            self._update_disconnected()

    # ─────────────────────────────────────────────────────────────────────────
    # Probe périodique
    # ─────────────────────────────────────────────────────────────────────────

    async def start_probe_task(self, interval: int = PROBE_INTERVAL) -> None:
        """
        Démarre la tâche de probe périodique.

        Args:
            interval: Intervalle entre les probes en secondes.
        """
        if self._probe_task is not None and not self._probe_task.done():
            log.debug("Probe task déjà en cours")
            return

        self._probe_task = asyncio.create_task(self._probe_loop(interval))
        log.info("Probe task démarrée (interval=%ds)", interval)

    async def stop_probe_task(self) -> None:
        """Arrête la tâche de probe périodique."""
        if self._probe_task is not None:
            self._probe_task.cancel()
            try:
                await self._probe_task
            except asyncio.CancelledError:
                pass
            self._probe_task = None
            log.info("Probe task arrêtée")

    async def _probe_loop(self, interval: int) -> None:
        """Boucle de probe périodique."""
        while True:
            try:
                self.detect_otg_connection()
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Erreur dans probe loop: %s", e)
                await asyncio.sleep(interval)

    # ─────────────────────────────────────────────────────────────────────────
    # API de consultation
    # ─────────────────────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """
        Retourne l'état actuel pour l'API.

        Returns:
            Dict compatible avec RemoteUIStatusResponse.
        """
        # Refresh l'état si OTG
        if self._state.transport == "otg" or not self._state.connected:
            self.detect_otg_connection()

        return self._state.to_dict()

    def is_connected(self) -> bool:
        """Retourne True si un Remote UI est connecté."""
        return self._state.connected

    def get_transport(self) -> str:
        """Retourne le transport actif."""
        return self._state.transport


# ══════════════════════════════════════════════════════════════════════════════
# Accesseurs globaux
# ══════════════════════════════════════════════════════════════════════════════

def get_remote_ui_manager() -> RemoteUIManager:
    """Retourne l'instance singleton du gestionnaire Remote UI."""
    return RemoteUIManager()


def remote_ui_status() -> Dict[str, Any]:
    """Raccourci pour obtenir l'état Remote UI."""
    return get_remote_ui_manager().get_status()
