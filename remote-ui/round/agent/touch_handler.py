"""
SecuBox Eye Remote - Touch Gesture Handler
Gestionnaire de gestes tactiles pour l'ecran HyperPixel 2.1 Round.

Architecture:
- Lecture des evenements tactiles via evdev (/dev/input/eventX)
- Detection des gestes: swipe, tap, long press, multi-touch
- Integration avec device_manager et ws_client pour les actions

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from device_manager import DeviceManager
    from command_handler import WebSocketClient

log = logging.getLogger(__name__)


# =============================================================================
# Configuration de l'ecran HyperPixel 2.1 Round
# =============================================================================

# Dimensions de l'ecran circulaire (pixels)
DISPLAY_WIDTH = 480
DISPLAY_HEIGHT = 480
CENTER_X = DISPLAY_WIDTH // 2   # 240
CENTER_Y = DISPLAY_HEIGHT // 2  # 240

# Seuils de detection des gestes (pixels et millisecondes)
SWIPE_THRESHOLD = 50            # Distance minimale pour un swipe
LONG_PRESS_MS = 800             # Duree minimale pour un long press
TAP_MAX_MS = 200                # Duree maximale pour un tap simple
SWIPE_TOP_ZONE = 50             # Zone superieure pour swipe down (overlay)

# Multi-touch
THREE_FINGER_TIMEOUT_MS = 300   # Fenetre pour detecter 3 doigts

# Rayons des anneaux de modules (depuis CLAUDE.md)
# L'anneau correspond a la zone touchable autour du rayon indique
MODULE_RINGS = {
    "AUTH": {"radius": 214, "color": "#C04E24", "inner": 207, "outer": 221},
    "WALL": {"radius": 201, "color": "#9A6010", "inner": 194, "outer": 207},
    "BOOT": {"radius": 188, "color": "#803018", "inner": 181, "outer": 194},
    "MIND": {"radius": 175, "color": "#3D35A0", "inner": 168, "outer": 181},
    "ROOT": {"radius": 162, "color": "#0A5840", "inner": 155, "outer": 168},
    "MESH": {"radius": 149, "color": "#104A88", "inner": 142, "outer": 155},
}

# Zone centrale (pour long press device list)
CENTER_RADIUS = 80  # Zone centrale de 80px de rayon


# =============================================================================
# Slice Detection for Radial Menu
# =============================================================================

# Zone radii for slice detection
CENTER_ZONE_RADIUS = 60      # Center area (not a slice)
OUTER_ZONE_RADIUS = 220      # Outside visible circle


def get_slice_from_touch(x: int, y: int) -> Optional[int]:
    """
    Convertir des coordonnees tactiles en index de tranche (0-5).

    La tranche 0 est en haut (12h), puis les tranches tournent
    dans le sens horaire: 1=2h, 2=4h, 3=6h, 4=8h, 5=10h.

    Args:
        x: Coordonnee X du touch
        y: Coordonnee Y du touch

    Returns:
        Index de tranche (0-5) ou None si hors zone
    """
    dx = x - CENTER_X
    dy = y - CENTER_Y
    distance = math.sqrt(dx * dx + dy * dy)

    # Zone centrale -> pas une tranche
    if distance < CENTER_ZONE_RADIUS:
        return None

    # Hors du cercle visible -> ignorer
    if distance > OUTER_ZONE_RADIUS:
        return None

    # Calculer l'angle (0 = haut, sens horaire)
    # atan2(dx, -dy) donne l'angle depuis le haut
    angle = math.degrees(math.atan2(dx, -dy))
    if angle < 0:
        angle += 360

    # Chaque tranche fait 60 degres, decale de 30 pour centrer
    # la tranche 0 sur le haut
    slice_index = int((angle + 30) % 360 // 60)
    return slice_index


# =============================================================================
# Types de gestes detectes
# =============================================================================

class Gesture(Enum):
    """Types de gestes tactiles reconnus."""
    NONE = auto()
    TAP = auto()                # Tap simple sur un point
    DOUBLE_TAP = auto()         # Double tap rapide (non implemente pour l'instant)
    LONG_PRESS = auto()         # Appui long (>800ms)
    SWIPE_LEFT = auto()         # Balayage vers la gauche
    SWIPE_RIGHT = auto()        # Balayage vers la droite
    SWIPE_UP = auto()           # Balayage vers le haut
    SWIPE_DOWN = auto()         # Balayage vers le bas (depuis zone top)
    THREE_FINGER_TAP = auto()   # Tap a trois doigts (emergency lockdown)
    PINCH = auto()              # Pincement (non implemente pour l'instant)


# =============================================================================
# Etat du geste en cours
# =============================================================================

@dataclass
class TouchPoint:
    """Un point de contact tactile."""
    slot: int               # Slot evdev (0-9 pour multi-touch)
    tracking_id: int        # ID de tracking unique
    x: int                  # Position X actuelle
    y: int                  # Position Y actuelle
    start_x: int = 0        # Position X initiale
    start_y: int = 0        # Position Y initiale
    start_time: float = 0.0 # Timestamp du premier contact
    active: bool = True     # Point encore actif


@dataclass
class GestureState:
    """Etat complet du geste multi-touch en cours."""
    # Points de contact actifs (slot -> TouchPoint)
    touch_points: dict[int, TouchPoint] = field(default_factory=dict)

    # Statistiques
    max_touch_count: int = 0    # Nombre max de doigts detectes
    gesture_started: bool = False

    # Timestamps
    first_touch_time: float = 0.0
    last_event_time: float = 0.0

    def reset(self):
        """Reinitialiser l'etat pour un nouveau geste."""
        self.touch_points.clear()
        self.max_touch_count = 0
        self.gesture_started = False
        self.first_touch_time = 0.0
        self.last_event_time = 0.0

    @property
    def active_count(self) -> int:
        """Nombre de points de contact actifs."""
        return sum(1 for tp in self.touch_points.values() if tp.active)

    @property
    def primary_point(self) -> Optional[TouchPoint]:
        """Retourne le point de contact principal (slot 0 ou premier actif)."""
        if 0 in self.touch_points and self.touch_points[0].active:
            return self.touch_points[0]
        for tp in self.touch_points.values():
            if tp.active:
                return tp
        return None


# =============================================================================
# Gestionnaire de gestes tactiles
# =============================================================================

@dataclass
class TouchHandler:
    """
    Gestionnaire de gestes tactiles pour HyperPixel 2.1 Round.

    Lit les evenements evdev et detecte les gestes:
    - Swipe gauche/droite: changer de SecuBox
    - Tap sur anneau module: redemarrer le service
    - 3-finger tap: lockdown d'urgence
    - Swipe down (depuis top): toggle overlay info
    - Long press centre: afficher liste des devices

    Attributes:
        device_manager: Gestionnaire des connexions SecuBox
        ws_client: Client WebSocket pour les commandes
    """

    device_manager: Optional[Any] = None  # Type: DeviceManager
    ws_client: Optional[Any] = None       # Type: WebSocketClient

    # Peripherique evdev
    _touch_device: Optional[Any] = field(default=None, repr=False)
    _device_path: Optional[Path] = field(default=None, repr=False)

    # Etat du geste
    _state: GestureState = field(default_factory=GestureState, repr=False)

    # Etat de l'UI
    _info_overlay_visible: bool = field(default=False, repr=False)
    _device_list_visible: bool = field(default=False, repr=False)

    # Controle de la boucle d'evenements
    _running: bool = field(default=False, repr=False)
    _event_task: Optional[asyncio.Task] = field(default=None, repr=False)

    # Callbacks externes pour l'UI
    _on_overlay_toggle: Optional[Callable[[bool], None]] = field(default=None, repr=False)
    _on_device_list_toggle: Optional[Callable[[bool], None]] = field(default=None, repr=False)
    _on_secubox_switch: Optional[Callable[[str], None]] = field(default=None, repr=False)
    _on_gesture: Optional[Callable[[Gesture, dict], None]] = field(default=None, repr=False)

    # Slot courant pour multi-touch
    _current_slot: int = field(default=0, repr=False)

    # ==========================================================================
    # Initialisation et detection du peripherique
    # ==========================================================================

    def _find_touch_device(self) -> Optional[Path]:
        """
        Trouver le peripherique tactile HyperPixel.

        Recherche dans /dev/input/eventX les peripheriques capacitifs.
        Priorite au HyperPixel 2.1 Round (Goodix ou FT5x06).

        Returns:
            Path vers le peripherique ou None si non trouve
        """
        try:
            import evdev
        except ImportError:
            log.error("Module evdev non installe: pip install evdev")
            return None

        input_dir = Path("/dev/input")
        candidates = []

        for event_path in sorted(input_dir.glob("event*")):
            try:
                device = evdev.InputDevice(str(event_path))
                caps = device.capabilities()

                # Verifier si c'est un peripherique tactile (ABS_MT_SLOT)
                # Code ABS_MT_SLOT = 0x2f = 47
                if evdev.ecodes.EV_ABS in caps:
                    abs_caps = dict(caps[evdev.ecodes.EV_ABS])
                    if evdev.ecodes.ABS_MT_SLOT in abs_caps:
                        # C'est un peripherique multi-touch
                        name = device.name.lower()
                        log.debug("Touch device trouve: %s (%s)", device.name, event_path)

                        # Priorite au HyperPixel / Goodix / FT5x06
                        if any(x in name for x in ['goodix', 'ft5', 'hyperpixel', 'touch']):
                            candidates.insert(0, event_path)
                        else:
                            candidates.append(event_path)

                device.close()

            except (OSError, PermissionError) as e:
                log.debug("Impossible de lire %s: %s", event_path, e)
                continue

        if candidates:
            log.info("Peripherique tactile selectionne: %s", candidates[0])
            return candidates[0]

        log.warning("Aucun peripherique tactile trouve")
        return None

    async def start(self):
        """
        Demarrer le gestionnaire de gestes.

        Initialise le peripherique evdev et demarre la boucle d'evenements.
        """
        try:
            import evdev
        except ImportError:
            log.error("Module evdev non installe - gestes desactives")
            return False

        # Trouver le peripherique tactile
        self._device_path = self._find_touch_device()
        if not self._device_path:
            log.warning("Pas de peripherique tactile - mode simulation")
            return False

        # Ouvrir le peripherique
        try:
            self._touch_device = evdev.InputDevice(str(self._device_path))
            log.info("Peripherique tactile ouvert: %s", self._touch_device.name)
        except (OSError, PermissionError) as e:
            log.error("Erreur ouverture peripherique: %s", e)
            return False

        # Demarrer la boucle d'evenements
        self._running = True
        self._event_task = asyncio.create_task(self._event_loop())

        log.info("TouchHandler demarre")
        return True

    async def stop(self):
        """Arreter le gestionnaire de gestes."""
        self._running = False

        if self._event_task:
            self._event_task.cancel()
            try:
                await self._event_task
            except asyncio.CancelledError:
                pass
            self._event_task = None

        if self._touch_device:
            try:
                self._touch_device.close()
            except Exception:
                pass
            self._touch_device = None

        log.info("TouchHandler arrete")

    # ==========================================================================
    # Callbacks pour l'integration UI
    # ==========================================================================

    def on_overlay_toggle(self, callback: Callable[[bool], None]):
        """Callback quand l'overlay info est toggle."""
        self._on_overlay_toggle = callback

    def on_device_list_toggle(self, callback: Callable[[bool], None]):
        """Callback quand la liste des devices est toggle."""
        self._on_device_list_toggle = callback

    def on_secubox_switch(self, callback: Callable[[str], None]):
        """Callback quand on change de SecuBox."""
        self._on_secubox_switch = callback

    def on_gesture(self, callback: Callable[[Gesture, dict], None]):
        """Callback generique pour tous les gestes."""
        self._on_gesture = callback

    # ==========================================================================
    # Boucle d'evenements evdev
    # ==========================================================================

    async def _event_loop(self):
        """
        Boucle principale de lecture des evenements tactiles.

        Lit les evenements evdev en async et appelle _process_event.
        """
        import evdev

        log.debug("Boucle d'evenements demarree")

        try:
            async for event in self._touch_device.async_read_loop():
                if not self._running:
                    break

                await self._process_event(event)

        except asyncio.CancelledError:
            log.debug("Boucle d'evenements annulee")
        except OSError as e:
            log.error("Erreur lecture evenements: %s", e)
        except Exception as e:
            log.error("Erreur inattendue: %s", e)

    async def _process_event(self, event):
        """
        Traiter un evenement evdev individuel.

        Types d'evenements geres:
        - EV_ABS / ABS_MT_SLOT: changement de slot (doigt)
        - EV_ABS / ABS_MT_TRACKING_ID: debut/fin de contact
        - EV_ABS / ABS_MT_POSITION_X/Y: position du doigt
        - EV_SYN / SYN_REPORT: fin de trame, detection du geste

        Args:
            event: Evenement evdev
        """
        import evdev

        now = time.time()

        if event.type == evdev.ecodes.EV_ABS:
            # Evenement de position absolue

            if event.code == evdev.ecodes.ABS_MT_SLOT:
                # Changement de slot (multi-touch)
                self._current_slot = event.value

            elif event.code == evdev.ecodes.ABS_MT_TRACKING_ID:
                # Debut ou fin de contact
                slot = self._current_slot

                if event.value >= 0:
                    # Nouveau contact
                    self._state.touch_points[slot] = TouchPoint(
                        slot=slot,
                        tracking_id=event.value,
                        x=0, y=0,
                        start_x=0, start_y=0,
                        start_time=now,
                        active=True
                    )

                    # Premier contact global?
                    if self._state.first_touch_time == 0.0:
                        self._state.first_touch_time = now
                        self._state.gesture_started = True

                    # Mettre a jour le max de doigts
                    self._state.max_touch_count = max(
                        self._state.max_touch_count,
                        self._state.active_count
                    )

                    log.debug("Contact slot=%d tracking_id=%d", slot, event.value)

                else:
                    # Fin de contact (tracking_id = -1)
                    if slot in self._state.touch_points:
                        self._state.touch_points[slot].active = False
                        log.debug("Fin contact slot=%d", slot)

            elif event.code == evdev.ecodes.ABS_MT_POSITION_X:
                # Position X
                slot = self._current_slot
                if slot in self._state.touch_points:
                    tp = self._state.touch_points[slot]
                    if tp.start_x == 0 and tp.start_y == 0:
                        tp.start_x = event.value
                    tp.x = event.value

            elif event.code == evdev.ecodes.ABS_MT_POSITION_Y:
                # Position Y
                slot = self._current_slot
                if slot in self._state.touch_points:
                    tp = self._state.touch_points[slot]
                    if tp.start_x == 0 and tp.start_y == 0:
                        tp.start_y = event.value
                    tp.y = event.value

        elif event.type == evdev.ecodes.EV_SYN:
            if event.code == evdev.ecodes.SYN_REPORT:
                # Fin de trame - traiter l'etat complet
                self._state.last_event_time = now

                # Verifier si tous les contacts sont termines
                if self._state.gesture_started and self._state.active_count == 0:
                    # Geste termine - analyser et executer
                    gesture = self._detect_gesture()
                    if gesture != Gesture.NONE:
                        await self._execute_gesture(gesture)

                    # Reset pour le prochain geste
                    self._state.reset()

    # ==========================================================================
    # Detection des gestes
    # ==========================================================================

    def _detect_gesture(self) -> Gesture:
        """
        Analyser l'etat du geste et determiner le type.

        Algorithme:
        1. Verifier le nombre de doigts utilises
        2. Calculer la duree du geste
        3. Calculer le deplacement (delta X/Y)
        4. Appliquer les seuils pour determiner le geste

        Returns:
            Type de geste detecte
        """
        state = self._state

        # Recuperer le point principal (premier contact)
        primary = None
        for tp in state.touch_points.values():
            if primary is None or tp.start_time < primary.start_time:
                primary = tp

        if primary is None:
            return Gesture.NONE

        # Calculer la duree
        duration_ms = (state.last_event_time - primary.start_time) * 1000

        # Calculer le deplacement
        dx = primary.x - primary.start_x
        dy = primary.y - primary.start_y
        distance = math.sqrt(dx * dx + dy * dy)

        log.debug(
            "Analyse geste: fingers=%d duration=%.0fms dx=%d dy=%d dist=%.0f",
            state.max_touch_count, duration_ms, dx, dy, distance
        )

        # 1. Three-finger tap (emergency lockdown)
        if state.max_touch_count >= 3:
            if duration_ms < TAP_MAX_MS * 2 and distance < SWIPE_THRESHOLD:
                log.info("Geste detecte: THREE_FINGER_TAP")
                return Gesture.THREE_FINGER_TAP

        # 2. Swipe horizontal (changement de SecuBox)
        if abs(dx) > SWIPE_THRESHOLD and abs(dx) > abs(dy) * 1.5:
            if dx < 0:
                log.info("Geste detecte: SWIPE_LEFT (dx=%d)", dx)
                return Gesture.SWIPE_LEFT
            else:
                log.info("Geste detecte: SWIPE_RIGHT (dx=%d)", dx)
                return Gesture.SWIPE_RIGHT

        # 3. Swipe down depuis le haut (toggle overlay)
        if (dy > SWIPE_THRESHOLD and
            primary.start_y < SWIPE_TOP_ZONE and
            abs(dy) > abs(dx) * 1.5):
            log.info("Geste detecte: SWIPE_DOWN (from top)")
            return Gesture.SWIPE_DOWN

        # 4. Long press au centre (device list)
        if duration_ms > LONG_PRESS_MS and distance < SWIPE_THRESHOLD / 2:
            dist_from_center = math.sqrt(
                (primary.x - CENTER_X) ** 2 +
                (primary.y - CENTER_Y) ** 2
            )
            if dist_from_center < CENTER_RADIUS:
                log.info("Geste detecte: LONG_PRESS (center)")
                return Gesture.LONG_PRESS

        # 5. Tap simple
        if duration_ms < TAP_MAX_MS and distance < SWIPE_THRESHOLD / 2:
            log.info("Geste detecte: TAP at (%d, %d)", primary.x, primary.y)
            return Gesture.TAP

        log.debug("Geste non reconnu")
        return Gesture.NONE

    def _detect_module_from_position(self, x: int, y: int) -> Optional[str]:
        """
        Determiner le module touche en fonction de la position.

        Calcule la distance depuis le centre et verifie si elle
        correspond a l'anneau d'un module.

        Args:
            x: Position X du touch
            y: Position Y du touch

        Returns:
            Nom du module ("AUTH", "WALL", etc.) ou None
        """
        # Distance depuis le centre
        dist = math.sqrt((x - CENTER_X) ** 2 + (y - CENTER_Y) ** 2)

        # Verifier chaque anneau de module
        for module_name, ring in MODULE_RINGS.items():
            if ring["inner"] <= dist <= ring["outer"]:
                log.debug(
                    "Module detecte: %s (dist=%.0f, inner=%d, outer=%d)",
                    module_name, dist, ring["inner"], ring["outer"]
                )
                return module_name

        log.debug("Aucun module a dist=%.0f", dist)
        return None

    # ==========================================================================
    # Execution des gestes
    # ==========================================================================

    async def _execute_gesture(self, gesture: Gesture):
        """
        Executer l'action correspondant au geste detecte.

        Args:
            gesture: Type de geste detecte
        """
        primary = self._state.primary_point

        # Callback generique
        if self._on_gesture:
            try:
                self._on_gesture(gesture, {
                    "x": primary.x if primary else 0,
                    "y": primary.y if primary else 0,
                    "fingers": self._state.max_touch_count,
                })
            except Exception as e:
                log.warning("Erreur callback on_gesture: %s", e)

        # Actions specifiques
        if gesture == Gesture.SWIPE_LEFT:
            await self.on_swipe_left()

        elif gesture == Gesture.SWIPE_RIGHT:
            await self.on_swipe_right()

        elif gesture == Gesture.TAP:
            if primary:
                module = self._detect_module_from_position(primary.x, primary.y)
                if module:
                    await self.on_module_tap(module)

        elif gesture == Gesture.THREE_FINGER_TAP:
            await self.on_three_finger_tap()

        elif gesture == Gesture.SWIPE_DOWN:
            await self.on_swipe_down()

        elif gesture == Gesture.LONG_PRESS:
            await self.on_long_press_center()

    # ==========================================================================
    # Actions de gestes
    # ==========================================================================

    async def on_swipe_left(self):
        """
        Geste swipe gauche: passer au SecuBox precedent.

        Parcourt la liste des SecuBox configures et active le precedent.
        """
        if not self.device_manager:
            log.warning("DeviceManager non configure - swipe ignore")
            return

        boxes = self.device_manager.list_secuboxes()
        if len(boxes) < 2:
            log.debug("Moins de 2 SecuBox configures - pas de switch")
            return

        # Trouver l'index du SecuBox actif
        current_idx = None
        for i, box in enumerate(boxes):
            if box.get("active"):
                current_idx = i
                break

        if current_idx is None:
            current_idx = 0

        # Calculer l'index precedent (wrap around)
        prev_idx = (current_idx - 1) % len(boxes)
        prev_name = boxes[prev_idx]["name"]

        log.info("Switch vers SecuBox precedent: %s", prev_name)

        # Executer le switch
        try:
            success = await self.device_manager.switch_to(prev_name)
            if success and self._on_secubox_switch:
                self._on_secubox_switch(prev_name)
        except Exception as e:
            log.error("Erreur switch SecuBox: %s", e)

    async def on_swipe_right(self):
        """
        Geste swipe droite: passer au SecuBox suivant.

        Parcourt la liste des SecuBox configures et active le suivant.
        """
        if not self.device_manager:
            log.warning("DeviceManager non configure - swipe ignore")
            return

        boxes = self.device_manager.list_secuboxes()
        if len(boxes) < 2:
            log.debug("Moins de 2 SecuBox configures - pas de switch")
            return

        # Trouver l'index du SecuBox actif
        current_idx = None
        for i, box in enumerate(boxes):
            if box.get("active"):
                current_idx = i
                break

        if current_idx is None:
            current_idx = 0

        # Calculer l'index suivant (wrap around)
        next_idx = (current_idx + 1) % len(boxes)
        next_name = boxes[next_idx]["name"]

        log.info("Switch vers SecuBox suivant: %s", next_name)

        # Executer le switch
        try:
            success = await self.device_manager.switch_to(next_name)
            if success and self._on_secubox_switch:
                self._on_secubox_switch(next_name)
        except Exception as e:
            log.error("Erreur switch SecuBox: %s", e)

    async def on_module_tap(self, module: str):
        """
        Geste tap sur anneau module: redemarrer le service.

        Envoie une commande service_restart via WebSocket.

        Args:
            module: Nom du module ("AUTH", "WALL", etc.)
        """
        log.info("Tap sur module: %s", module)

        if not self.ws_client:
            log.warning("WebSocket client non configure - tap ignore")
            return

        # Nom du service systemd
        service_name = f"secubox-{module.lower()}"

        try:
            # Envoyer la commande via WebSocket
            await self.ws_client.send_message(
                "command",
                cmd="service_restart",
                params={"service": service_name}
            )
            log.info("Commande service_restart envoyee: %s", service_name)
        except Exception as e:
            log.error("Erreur envoi commande: %s", e)

    async def on_three_finger_tap(self):
        """
        Geste 3-finger tap: lockdown d'urgence.

        Active le mode lockdown sur le SecuBox via WebSocket.
        C'est une action de securite critique.
        """
        log.warning("LOCKDOWN D'URGENCE DECLENCHE (3-finger tap)")

        if not self.ws_client:
            log.error("WebSocket client non configure - lockdown impossible")
            return

        try:
            # Envoyer la commande lockdown
            await self.ws_client.send_message(
                "command",
                cmd="lockdown",
                params={"action": "enable", "reason": "emergency_gesture"}
            )
            log.info("Commande lockdown envoyee")
        except Exception as e:
            log.error("Erreur envoi lockdown: %s", e)

    async def on_swipe_down(self):
        """
        Geste swipe down depuis le haut: toggle overlay info.

        Affiche/masque l'overlay d'informations detaillees.
        """
        self._info_overlay_visible = not self._info_overlay_visible

        log.info(
            "Toggle overlay info: %s",
            "visible" if self._info_overlay_visible else "cache"
        )

        if self._on_overlay_toggle:
            try:
                self._on_overlay_toggle(self._info_overlay_visible)
            except Exception as e:
                log.warning("Erreur callback overlay: %s", e)

    async def on_long_press_center(self):
        """
        Geste long press au centre: afficher liste des devices.

        Affiche/masque la liste des SecuBox configures.
        """
        self._device_list_visible = not self._device_list_visible

        log.info(
            "Toggle device list: %s",
            "visible" if self._device_list_visible else "cache"
        )

        if self._on_device_list_toggle:
            try:
                self._on_device_list_toggle(self._device_list_visible)
            except Exception as e:
                log.warning("Erreur callback device list: %s", e)

    # ==========================================================================
    # Proprietes d'etat
    # ==========================================================================

    @property
    def is_running(self) -> bool:
        """Verifier si le handler est actif."""
        return self._running

    @property
    def info_overlay_visible(self) -> bool:
        """Etat de l'overlay info."""
        return self._info_overlay_visible

    @property
    def device_list_visible(self) -> bool:
        """Etat de la liste des devices."""
        return self._device_list_visible

    @property
    def touch_device_name(self) -> Optional[str]:
        """Nom du peripherique tactile."""
        if self._touch_device:
            return self._touch_device.name
        return None


# =============================================================================
# Factory function
# =============================================================================

def create_touch_handler(
    device_manager: Optional[Any] = None,
    ws_client: Optional[Any] = None
) -> TouchHandler:
    """
    Creer un gestionnaire de gestes tactiles.

    Args:
        device_manager: Gestionnaire des connexions SecuBox
        ws_client: Client WebSocket pour les commandes

    Returns:
        Instance de TouchHandler configuree
    """
    return TouchHandler(
        device_manager=device_manager,
        ws_client=ws_client
    )


# =============================================================================
# Exemple d'utilisation
# =============================================================================

async def main():
    """Exemple d'utilisation du TouchHandler."""
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    log.info("Demarrage du test TouchHandler")

    # Creer le handler sans device_manager ni ws_client (mode demo)
    handler = create_touch_handler()

    # Callback de demonstration
    def on_gesture_demo(gesture: Gesture, data: dict):
        print(f">>> Geste detecte: {gesture.name} - data={data}")

    handler.on_gesture(on_gesture_demo)

    # Demarrer
    success = await handler.start()
    if not success:
        log.error("Echec demarrage - verifiez les permissions /dev/input/")
        sys.exit(1)

    log.info("TouchHandler actif - peripherique: %s", handler.touch_device_name)
    log.info("Testez les gestes sur l'ecran. Ctrl+C pour quitter.")

    try:
        # Attendre indefiniment
        while handler.is_running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        log.info("Arret demande")
    finally:
        await handler.stop()

    log.info("Test termine")


if __name__ == "__main__":
    asyncio.run(main())
