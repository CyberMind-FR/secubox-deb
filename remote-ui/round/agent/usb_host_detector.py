#!/usr/bin/env python3
"""
SecuBox Eye Remote - USB Host Detector
Détecte la connexion USB host et permet de changer de mode OTG dynamiquement.

Méthodes de détection :
1. UDC state via /sys/class/udc/*/state
2. VBUS via GPIO (si disponible)
3. Kernel uevent via pyudev

Usage:
    python3 usb_host_detector.py --mode monitor
    python3 usb_host_detector.py --mode switch --target flash

CyberMind - https://cybermind.fr
"""

import os
import sys
import time
import signal
import subprocess
import logging
from pathlib import Path
from typing import Optional, Callable

# Configuration
UDC_PATH = Path("/sys/class/udc")
GADGET_SCRIPT = "/usr/local/sbin/secubox-otg-gadget.sh"

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger("usb-detector")


class UsbHostDetector:
    """Détecte l'état de connexion USB host."""

    # États possibles du contrôleur UDC
    STATE_NOT_ATTACHED = "not attached"
    STATE_ATTACHED = "attached"
    STATE_POWERED = "powered"
    STATE_CONFIGURED = "configured"
    STATE_SUSPENDED = "suspended"

    def __init__(self):
        self.udc_name = self._find_udc()
        self.callbacks: list[Callable] = []
        self._running = False

    def _find_udc(self) -> Optional[str]:
        """Trouve le contrôleur UDC disponible."""
        if not UDC_PATH.exists():
            return None
        udcs = list(UDC_PATH.iterdir())
        if udcs:
            return udcs[0].name
        return None

    @property
    def udc_state_path(self) -> Optional[Path]:
        """Chemin vers le fichier d'état UDC."""
        if self.udc_name:
            return UDC_PATH / self.udc_name / "state"
        return None

    def get_state(self) -> str:
        """Lit l'état actuel du contrôleur UDC."""
        if self.udc_state_path and self.udc_state_path.exists():
            return self.udc_state_path.read_text().strip()
        return self.STATE_NOT_ATTACHED

    def is_connected(self) -> bool:
        """Vérifie si un host USB est connecté."""
        state = self.get_state()
        return state in (self.STATE_CONFIGURED, self.STATE_POWERED, self.STATE_ATTACHED)

    def is_configured(self) -> bool:
        """Vérifie si le gadget est configuré par l'host."""
        return self.get_state() == self.STATE_CONFIGURED

    def on_state_change(self, callback: Callable):
        """Enregistre un callback pour les changements d'état."""
        self.callbacks.append(callback)

    def monitor(self, interval: float = 0.5):
        """Surveille les changements d'état en continu."""
        self._running = True
        last_state = None

        log.info(f"Monitoring UDC: {self.udc_name}")

        while self._running:
            current_state = self.get_state()

            if current_state != last_state:
                log.info(f"State change: {last_state} -> {current_state}")

                for callback in self.callbacks:
                    try:
                        callback(last_state, current_state)
                    except Exception as e:
                        log.error(f"Callback error: {e}")

                last_state = current_state

            time.sleep(interval)

    def stop(self):
        """Arrête la surveillance."""
        self._running = False


class UsbHostDetectorUevent:
    """Détection via uevents kernel (nécessite pyudev)."""

    def __init__(self):
        self._context = None
        self._monitor = None

    def setup(self):
        """Configure la surveillance uevent."""
        try:
            import pyudev
            self._context = pyudev.Context()
            self._monitor = pyudev.Monitor.from_netlink(self._context)
            self._monitor.filter_by(subsystem='udc')
            return True
        except ImportError:
            log.warning("pyudev non disponible, fallback vers polling")
            return False

    def monitor(self, callback: Callable):
        """Surveille les événements UDC."""
        if not self._monitor:
            return

        import pyudev
        observer = pyudev.MonitorObserver(self._monitor, callback)
        observer.start()
        return observer


class OtgModeManager:
    """Gère les modes OTG du gadget composite."""

    MODES = {
        "normal": "ECM + ACM (réseau + série)",
        "flash": "Mass Storage bootable + ACM (recovery)",
        "debug": "ECM + Mass Storage R/W + ACM (debug)",
        "tty": "HID Keyboard + ACM (virtual keyboard)",
        "auth": "FIDO2/U2F HID + ACM (security key)"
    }

    def __init__(self):
        self.current_mode = "normal"
        self.detector = UsbHostDetector()

    def switch_mode(self, mode: str) -> bool:
        """Change le mode OTG."""
        if mode not in self.MODES:
            log.error(f"Mode inconnu: {mode}")
            log.info(f"Modes disponibles: {list(self.MODES.keys())}")
            return False

        log.info(f"Switching to mode: {mode} ({self.MODES[mode]})")

        if os.path.exists(GADGET_SCRIPT):
            try:
                result = subprocess.run(
                    [GADGET_SCRIPT, mode],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    self.current_mode = mode
                    log.info(f"Mode changed to: {mode}")
                    return True
                else:
                    log.error(f"Script error: {result.stderr}")
                    return False
            except subprocess.TimeoutExpired:
                log.error("Timeout changing mode")
                return False
            except Exception as e:
                log.error(f"Error: {e}")
                return False
        else:
            log.warning(f"Script not found: {GADGET_SCRIPT}")
            return False

    def get_status(self) -> dict:
        """Retourne l'état actuel."""
        return {
            "udc": self.detector.udc_name,
            "state": self.detector.get_state(),
            "connected": self.detector.is_connected(),
            "configured": self.detector.is_configured(),
            "mode": self.current_mode,
            "mode_desc": self.MODES.get(self.current_mode, "unknown")
        }


class DynamicModeSelector:
    """Sélectionne le mode OTG basé sur des critères automatiques."""

    def __init__(self, manager: OtgModeManager):
        self.manager = manager
        self.rules = []

    def add_rule(self, condition: Callable, mode: str):
        """Ajoute une règle de sélection automatique."""
        self.rules.append((condition, mode))

    def evaluate(self):
        """Évalue les règles et change de mode si nécessaire."""
        for condition, mode in self.rules:
            try:
                if condition():
                    if self.manager.current_mode != mode:
                        log.info(f"Rule triggered: switching to {mode}")
                        self.manager.switch_mode(mode)
                    return
            except Exception as e:
                log.error(f"Rule evaluation error: {e}")


def detect_host_type() -> Optional[str]:
    """
    Tente de détecter le type d'host connecté.

    Possibilités :
    - SecuBox (via handshake réseau après configuration)
    - U-Boot (powered mais pas de configuration pendant 3s)
    - PC standard (configuration rapide < 2s)
    """
    detector = UsbHostDetector()

    # Attendre la configuration ou timeout
    start = time.time()
    powered_since = None

    while time.time() - start < 5:
        state = detector.get_state()

        if state == "configured":
            # Host a configuré le gadget - OS standard
            return "standard"

        elif state == "powered":
            # Host présent (VBUS) mais pas de configuration
            if powered_since is None:
                powered_since = time.time()
            elif time.time() - powered_since > 3.0:
                # Powered > 3s sans config = U-Boot ou bootloader
                return "uboot"

        elif state == "not attached":
            powered_since = None

        time.sleep(0.2)

    return None


class AutoModeService:
    """
    Service de détection automatique et changement de mode OTG.

    Logique :
    - U-Boot détecté (powered sans config) → mode storage (flash)
    - OS standard configuré → mode normal (ECM+ACM)
    - Déconnexion → retour mode normal
    """

    def __init__(self):
        self.manager = OtgModeManager()
        self.detector = self.manager.detector
        self._running = False
        self._last_state = None
        self._powered_since = None

    def on_state_change(self, old_state: str, new_state: str):
        """Gère les changements d'état UDC."""
        log.info(f"State: {old_state} -> {new_state}")

        if new_state == "configured":
            # Host OS a configuré le gadget
            if self.manager.current_mode == "flash":
                # Était en mode flash pour U-Boot, retour normal
                log.info("Host configured, switching to normal mode")
                self.manager.switch_mode("normal")

        elif new_state == "not attached":
            # Déconnexion - retour mode normal
            if self.manager.current_mode != "normal":
                log.info("Disconnected, returning to normal mode")
                self.manager.switch_mode("normal")
            self._powered_since = None

    def check_uboot_timeout(self):
        """Vérifie si on est en mode U-Boot (powered sans config)."""
        state = self.detector.get_state()

        if state == "powered":
            if self._powered_since is None:
                self._powered_since = time.time()
            elif time.time() - self._powered_since > 3.0:
                # Powered > 3s sans configuration = U-Boot
                if self.manager.current_mode != "flash":
                    log.info("U-Boot detected (powered without config), switching to flash/storage mode")
                    self.manager.switch_mode("flash")
                self._powered_since = None  # Reset pour éviter répétition

        elif state != "powered":
            self._powered_since = None

    def run(self):
        """Boucle principale du service."""
        self._running = True
        log.info("AutoModeService started")
        log.info(f"UDC: {self.detector.udc_name}")

        while self._running:
            try:
                current_state = self.detector.get_state()

                # Détecter changement d'état
                if current_state != self._last_state:
                    self.on_state_change(self._last_state, current_state)
                    self._last_state = current_state

                # Vérifier timeout U-Boot
                self.check_uboot_timeout()

            except Exception as e:
                log.error(f"Service error: {e}")

            time.sleep(0.5)

    def stop(self):
        """Arrête le service."""
        self._running = False
        log.info("AutoModeService stopped")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="USB Host Detector for SecuBox Eye Remote")
    parser.add_argument("--mode", choices=["monitor", "status", "switch", "detect", "service"],
                        default="status", help="Action à effectuer")
    parser.add_argument("--target", type=str, help="Mode cible pour switch")
    args = parser.parse_args()

    manager = OtgModeManager()

    if args.mode == "status":
        status = manager.get_status()
        print("=== USB OTG Status ===")
        for key, value in status.items():
            print(f"  {key}: {value}")

    elif args.mode == "monitor":
        detector = manager.detector

        def on_change(old, new):
            print(f"[EVENT] {old} -> {new}")
            if new == "configured":
                print("[INFO] Host connected and configured")
            elif new == "not attached":
                print("[INFO] Host disconnected")

        detector.on_state_change(on_change)

        def signal_handler(_sig, _frame):
            print("\nStopping monitor...")
            detector.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        print("Monitoring USB host connection (Ctrl+C to stop)...")
        detector.monitor()

    elif args.mode == "service":
        # Mode service systemd avec changement de mode automatique
        service = AutoModeService()

        def signal_handler(_sig, _frame):
            log.info("Signal received, stopping service...")
            service.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        service.run()

    elif args.mode == "switch":
        if not args.target:
            print("Error: --target required for switch mode")
            print(f"Available modes: {list(OtgModeManager.MODES.keys())}")
            sys.exit(1)
        success = manager.switch_mode(args.target)
        sys.exit(0 if success else 1)

    elif args.mode == "detect":
        print("Detecting host type...")
        host_type = detect_host_type()
        if host_type:
            print(f"Detected: {host_type}")
        else:
            print("No host detected or timeout")


if __name__ == "__main__":
    main()
