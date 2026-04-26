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
# Touch Enable/Disable Flag
# =============================================================================
# Set to False to completely disable touch input (for defective hardware)
TOUCH_ENABLED = False

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
LONG_PRESS_MS = 200             # Duree minimale pour un long press (reduced for ghost-heavy hardware)
TAP_MAX_MS = 200                # Duree maximale pour un tap simple
SWIPE_TOP_ZONE = 50             # Zone superieure pour swipe down (overlay)

# Multi-touch
THREE_FINGER_TIMEOUT_MS = 300   # Fenetre pour detecter 3 doigts

# =============================================================================
# Ghost Touch Filtering (HyperPixel 2.1 Round ft5x06 workaround)
# =============================================================================
# The ft5x06 capacitive touch controller can generate spurious events
# due to EMI, display interference, or environmental factors.

# Minimum touch duration to consider valid (ms) - filters ultra-short ghost touches
# Note: set low because hardware generates frequent interruptions; use position/stability for filtering
GHOST_MIN_DURATION_MS = 20

# Minimum time between end of one gesture and start of next (ms)
GHOST_DEBOUNCE_MS = 200

# Edge zones to ignore (pixels from screen edge) - ghost touches often at edges
GHOST_EDGE_MARGIN = 8

# Minimum position values to consider valid (sometimes ghost at 0,0)
GHOST_MIN_POS = 5

# Maximum rate of touch events per second before considered noise
GHOST_MAX_EVENTS_PER_SEC = 80

# Maximum rate of new touch contacts per second (real users can't tap this fast)
GHOST_MAX_CONTACTS_PER_SEC = 5

# Track recent contact starts for rate limiting
GHOST_CONTACT_WINDOW_SEC = 1.0

# Position stability threshold - ghosts jump around, real touches are stable
GHOST_MAX_Y_RANGE = 80  # Max Y variance during a single touch (ghosts often >200)

# Touch stitching - bridge short gaps caused by ghost interruptions
GHOST_STITCH_MAX_GAP_MS = 200  # Max gap to consider same touch (extended for noisy hardware)
GHOST_STITCH_MAX_DISTANCE = 50  # Max position change to stitch

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
CENTER_RADIUS = 220  # Zone centrale de 220px de rayon (covers most of 480px screen for noisy touch)


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
    # Ghost filtering: track position stability
    min_y: int = 9999       # Minimum Y seen during touch
    max_y: int = 0          # Maximum Y seen during touch


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

    # Menu integration
    _menu_navigator: Optional[Any] = field(default=None, repr=False)  # Type: MenuNavigator
    _action_executor: Optional[Any] = field(default=None, repr=False)  # Type: ActionExecutor
    _on_menu_render: Optional[Callable[[Any], None]] = field(default=None, repr=False)

    # Slot courant pour multi-touch
    _current_slot: int = field(default=0, repr=False)

    # Ghost touch filtering state
    _last_gesture_end: float = field(default=0.0, repr=False)
    _event_count_window: list = field(default_factory=list, repr=False)
    _contact_start_window: list = field(default_factory=list, repr=False)
    _ghost_filter_enabled: bool = field(default=True, repr=False)
    _ghost_filter_log_suppress: float = field(default=0.0, repr=False)

    # Touch stitching state - bridge short gaps in continuous touches
    _stitch_last_end_time: float = field(default=0.0, repr=False)
    _stitch_last_x: int = field(default=0, repr=False)
    _stitch_last_y: int = field(default=0, repr=False)
    _stitch_accumulated_time: float = field(default=0.0, repr=False)
    _stitch_original_start_time: float = field(default=0.0, repr=False)

    # Long press accumulator - track time at center position across ghost interruptions
    _lp_accum_start: float = field(default=0.0, repr=False)
    _lp_accum_total_ms: float = field(default=0.0, repr=False)
    _lp_accum_last_time: float = field(default=0.0, repr=False)
    _lp_accum_last_pos: tuple = field(default=(0, 0), repr=False)

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
        # Check if touch is globally disabled (defective hardware)
        if not TOUCH_ENABLED:
            log.warning("Touch disabled via TOUCH_ENABLED flag - staying in dashboard mode")
            return False

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

    def set_menu_navigator(self, navigator: Any):
        """
        Definir le navigateur de menu.

        Args:
            navigator: Instance de MenuNavigator
        """
        self._menu_navigator = navigator

    def set_action_executor(self, executor: Any):
        """
        Definir l'executeur d'actions.

        Args:
            executor: Instance de ActionExecutor
        """
        self._action_executor = executor

    def on_menu_render(self, callback: Callable[[Any], None]):
        """
        Callback pour notifier que le menu doit etre rendu.

        Args:
            callback: Fonction appellee avec MenuState en argument
        """
        self._on_menu_render = callback

    # ==========================================================================
    # Ghost Touch Filtering
    # ==========================================================================

    def _is_ghost_touch_position(self, x: int, y: int) -> bool:
        """
        Verifier si une position est probablement un ghost touch.

        Args:
            x: Position X
            y: Position Y

        Returns:
            True si la position semble etre un ghost touch
        """
        if not self._ghost_filter_enabled:
            return False

        # Position (0, 0) ou tres proche - souvent ghost
        if x < GHOST_MIN_POS and y < GHOST_MIN_POS:
            log.debug("Ghost filter: position near origin (%d, %d)", x, y)
            return True

        # Position dans les marges extremes de l'ecran
        if (x < GHOST_EDGE_MARGIN or x > DISPLAY_WIDTH - GHOST_EDGE_MARGIN or
            y < GHOST_EDGE_MARGIN or y > DISPLAY_HEIGHT - GHOST_EDGE_MARGIN):
            log.debug("Ghost filter: position at edge (%d, %d)", x, y)
            return True

        return False

    def _is_event_rate_excessive(self, now: float) -> bool:
        """
        Verifier si le taux d'evenements est excessif (indicateur de bruit).

        Args:
            now: Timestamp actuel

        Returns:
            True si le taux d'evenements semble anormal
        """
        if not self._ghost_filter_enabled:
            return False

        # Nettoyer les evenements anciens (plus de 1 seconde)
        cutoff = now - 1.0
        self._event_count_window = [t for t in self._event_count_window if t > cutoff]

        # Ajouter l'evenement actuel
        self._event_count_window.append(now)

        # Verifier le taux
        if len(self._event_count_window) > GHOST_MAX_EVENTS_PER_SEC:
            # Suppress excessive logging (only log once per second)
            if now - self._ghost_filter_log_suppress > 1.0:
                log.debug("Ghost filter: excessive event rate (%d/sec)",
                         len(self._event_count_window))
                self._ghost_filter_log_suppress = now
            return True

        return False

    def _is_contact_rate_excessive(self, now: float) -> bool:
        """
        Verifier si le taux de nouveaux contacts est excessif.

        Real users cannot start more than ~5 touch contacts per second.

        Args:
            now: Timestamp actuel

        Returns:
            True si trop de contacts ont commence recemment
        """
        if not self._ghost_filter_enabled:
            return False

        # Nettoyer les contacts anciens
        cutoff = now - GHOST_CONTACT_WINDOW_SEC
        self._contact_start_window = [t for t in self._contact_start_window if t > cutoff]

        # Verifier le taux
        if len(self._contact_start_window) >= GHOST_MAX_CONTACTS_PER_SEC:
            return True

        # Enregistrer ce nouveau contact
        self._contact_start_window.append(now)
        return False

    def _is_in_debounce_period(self, now: float) -> bool:
        """
        Verifier si on est dans la periode de debounce apres un geste.

        Args:
            now: Timestamp actuel

        Returns:
            True si on doit ignorer les touches (debounce)
        """
        if not self._ghost_filter_enabled:
            return False

        if self._last_gesture_end > 0:
            elapsed_ms = (now - self._last_gesture_end) * 1000
            if elapsed_ms < GHOST_DEBOUNCE_MS:
                log.debug("Ghost filter: in debounce period (%.0fms)", elapsed_ms)
                return True

        return False

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

        # Track event rate (for statistics, doesn't block processing)
        self._is_event_rate_excessive(now)

        if event.type == evdev.ecodes.EV_ABS:
            # Evenement de position absolue

            if event.code == evdev.ecodes.ABS_MT_SLOT:
                # Changement de slot (multi-touch)
                self._current_slot = event.value

            elif event.code == evdev.ecodes.ABS_MT_TRACKING_ID:
                # Debut ou fin de contact
                slot = self._current_slot

                if event.value >= 0:
                    # Ghost touch filter: only accept slot 0 to reduce ghost interference
                    # Multi-touch ghosts often use higher slots
                    if slot > 0 and self._ghost_filter_enabled:
                        log.debug("Ghost filter: ignoring slot %d (multi-touch disabled)", slot)
                        return

                    # Ghost touch filter: check if contact rate is excessive
                    if self._is_contact_rate_excessive(now):
                        # Too many contacts starting - likely ghost touches
                        return

                    # Ghost touch filter: check debounce
                    if self._is_in_debounce_period(now):
                        return

                    # Check for touch stitching - is this a continuation of previous touch?
                    is_stitch = False
                    effective_start_time = now

                    if self._stitch_last_end_time > 0:
                        gap_ms = (now - self._stitch_last_end_time) * 1000
                        if gap_ms < GHOST_STITCH_MAX_GAP_MS:
                            # Close enough in time - might be stitching
                            is_stitch = True
                            effective_start_time = self._stitch_original_start_time
                            log.debug("Touch stitch: bridging %.0fms gap", gap_ms)

                    # Nouveau contact
                    self._state.touch_points[slot] = TouchPoint(
                        slot=slot,
                        tracking_id=event.value,
                        x=0, y=0,
                        start_x=0, start_y=0,
                        start_time=effective_start_time,
                        active=True
                    )

                    # If not stitching, this is a fresh touch - record as potential stitch start
                    if not is_stitch:
                        self._stitch_original_start_time = now

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
                        tp = self._state.touch_points[slot]
                        tp.active = False

                        # Save state for potential stitching
                        self._stitch_last_end_time = now
                        self._stitch_last_x = tp.x
                        self._stitch_last_y = tp.y

                        log.debug("Fin contact slot=%d at (%d,%d)", slot, tp.x, tp.y)

            elif event.code == evdev.ecodes.ABS_MT_POSITION_X:
                # Position X
                slot = self._current_slot
                if slot in self._state.touch_points:
                    tp = self._state.touch_points[slot]
                    if tp.start_x == 0 and tp.start_y == 0:
                        tp.start_x = event.value
                    tp.x = event.value

                    # Ghost filter: check if position looks suspicious after we have both X and Y
                    if tp.start_x > 0 and tp.start_y > 0:
                        if self._is_ghost_touch_position(tp.start_x, tp.start_y):
                            log.debug("Ghost filter: invalidating touch at edge/origin")
                            tp.active = False

            elif event.code == evdev.ecodes.ABS_MT_POSITION_Y:
                # Position Y
                slot = self._current_slot
                if slot in self._state.touch_points:
                    tp = self._state.touch_points[slot]
                    if tp.start_x == 0 and tp.start_y == 0:
                        tp.start_y = event.value
                    tp.y = event.value

                    # Track min/max Y for stability detection
                    tp.min_y = min(tp.min_y, event.value)
                    tp.max_y = max(tp.max_y, event.value)

                    # Ghost filter: check if position looks suspicious after we have both X and Y
                    if tp.start_x > 0 and tp.start_y > 0:
                        if self._is_ghost_touch_position(tp.start_x, tp.start_y):
                            log.debug("Ghost filter: invalidating touch at edge/origin")
                            tp.active = False

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

                    # Update debounce timestamp (even if gesture was filtered)
                    self._last_gesture_end = now

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

        # Ghost filter: reject ultra-short touches (likely noise)
        if duration_ms < GHOST_MIN_DURATION_MS:
            log.debug("Ghost filter: touch too short (%.0fms < %dms)",
                     duration_ms, GHOST_MIN_DURATION_MS)
            return Gesture.NONE

        # Ghost filter: check positions (allow if END position is valid, even if start was corrupted)
        start_suspicious = self._is_ghost_touch_position(primary.start_x, primary.start_y)
        end_suspicious = self._is_ghost_touch_position(primary.x, primary.y)

        if start_suspicious and end_suspicious:
            # Both positions bad = definitely ghost
            log.debug("Ghost filter: both positions suspicious start=(%d,%d) end=(%d,%d)",
                     primary.start_x, primary.start_y, primary.x, primary.y)
            return Gesture.NONE

        if start_suspicious and not end_suspicious and duration_ms > 30:
            # Start was corrupted but end is valid and touch was long enough = likely real
            log.info("Ghost filter: accepting touch with corrupted start, valid end=(%d,%d)",
                    primary.x, primary.y)
            # Use end position as effective position - treat as stationary touch
            primary.start_x = primary.x
            primary.start_y = primary.y
            # Recalculate movement as zero (stationary)
            dx = 0
            dy = 0
            distance = 0

        # Ghost filter: reject unstable Y positions (ghosts jump around vertically)
        y_range = primary.max_y - primary.min_y
        if y_range > GHOST_MAX_Y_RANGE and distance < SWIPE_THRESHOLD:
            # Large Y variance but small total movement = ghost, not swipe
            log.debug("Ghost filter: unstable Y position (range=%d > %d)",
                     y_range, GHOST_MAX_Y_RANGE)
            return Gesture.NONE

        # 1. Three-finger tap (emergency lockdown)
        if state.max_touch_count >= 3:
            if duration_ms < TAP_MAX_MS * 2 and distance < SWIPE_THRESHOLD:
                log.info("Geste detecte: THREE_FINGER_TAP")
                return Gesture.THREE_FINGER_TAP

        # 2. Swipe horizontal (changement de SecuBox)
        # Require minimum duration and non-edge start to filter ghost swipes
        start_at_edge = (primary.start_x < GHOST_EDGE_MARGIN or
                        primary.start_x > DISPLAY_WIDTH - GHOST_EDGE_MARGIN or
                        primary.start_y < GHOST_EDGE_MARGIN or
                        primary.start_y > DISPLAY_HEIGHT - GHOST_EDGE_MARGIN)
        if abs(dx) > SWIPE_THRESHOLD and abs(dx) > abs(dy) * 1.5 and duration_ms > 200 and not start_at_edge:
            if dx < 0:
                log.info("Geste detecte: SWIPE_LEFT (dx=%d)", dx)
                return Gesture.SWIPE_LEFT
            else:
                log.info("Geste detecte: SWIPE_RIGHT (dx=%d)", dx)
                return Gesture.SWIPE_RIGHT

        # 3. Swipe down depuis le haut (toggle overlay)
        # Require minimum duration and non-edge start position to filter ghost swipes
        if (dy > SWIPE_THRESHOLD and
            primary.start_y < SWIPE_TOP_ZONE and
            primary.start_y > GHOST_EDGE_MARGIN and  # Not at edge (ghost filter)
            abs(dy) > abs(dx) * 1.5 and
            duration_ms > 200):  # Longer duration to filter ghosts
            log.info("Geste detecte: SWIPE_DOWN (from top)")
            return Gesture.SWIPE_DOWN

        # 3b. Swipe up depuis le bas (enter menu - replaces long press for ghost-heavy hardware)
        # Note: ghost-corrupted starts have start_y=0, so we detect by END position in top zone
        # If start was corrupted (near 0) and end is in top half with large movement, it's swipe-up
        start_corrupted = primary.start_y < GHOST_EDGE_MARGIN
        end_in_top_zone = primary.y < CENTER_Y - 40  # Top zone (y < 200)
        large_vertical_movement = abs(dy) > SWIPE_THRESHOLD * 1.5

        log.debug("SWIPE_UP check: start_y=%d corrupted=%s end_y=%d in_top=%s dy=%d large=%s dur=%dms",
                 primary.start_y, start_corrupted, primary.y, end_in_top_zone, dy, large_vertical_movement, duration_ms)

        if (start_corrupted and end_in_top_zone and large_vertical_movement and
            abs(dy) > abs(dx) * 1.2 and duration_ms > 20):
            log.info("Geste detecte: SWIPE_UP (from bottom, corrupted start) - enter menu")
            return Gesture.SWIPE_UP

        # Normal swipe up (non-corrupted start)
        SWIPE_BOTTOM_ZONE = DISPLAY_HEIGHT - 80  # Bottom 80px
        if (dy < -SWIPE_THRESHOLD and  # Negative dy = upward
            primary.start_y > SWIPE_BOTTOM_ZONE and
            abs(dy) > abs(dx) * 1.5 and
            duration_ms > 150):
            log.info("Geste detecte: SWIPE_UP (from bottom) - enter menu")
            return Gesture.SWIPE_UP

        # 4. Long press au centre (disabled - unreliable with ghost touch hardware)
        dist_from_center = math.sqrt(
            (primary.x - CENTER_X) ** 2 +
            (primary.y - CENTER_Y) ** 2
        )
        log.debug("Long press check: dur=%.0fms (>%d?) dist=%.0f (<%d?) center_dist=%.0f (<%d?)",
                 duration_ms, LONG_PRESS_MS, distance, SWIPE_THRESHOLD // 2,
                 dist_from_center, CENTER_RADIUS)

        # Check long press with accumulator for ghost-interrupted touches
        # Long press detection - accumulate qualifying touches regardless of position
        # (position consistency disabled due to hardware ghost touch defect)
        MIN_DURATION_FOR_ACCUM = 25  # ms - minimum touch duration to count
        MIN_TOUCHES_FOR_LP = 5       # Need 5+ qualifying touches
        ACCUM_TIMEOUT_MS = 3000      # Reset if no qualifying touch for 3s

        if distance < SWIPE_THRESHOLD / 2 and dist_from_center < CENTER_RADIUS:
            now = time.time()
            time_since_last = (now - self._lp_accum_last_time) * 1000 if self._lp_accum_last_time > 0 else 9999

            # Only count touches with minimum duration
            if duration_ms >= MIN_DURATION_FOR_ACCUM:
                if time_since_last < ACCUM_TIMEOUT_MS:
                    # Continuation - add to accumulator
                    self._lp_accum_total_ms += duration_ms
                    self._lp_accum_count = getattr(self, '_lp_accum_count', 0) + 1
                else:
                    # Timeout - new sequence
                    self._lp_accum_total_ms = duration_ms
                    self._lp_accum_count = 1

                self._lp_accum_last_time = now
                log.debug("Long press accumulator: %.0fms total=%.0fms count=%d",
                         duration_ms, self._lp_accum_total_ms, self._lp_accum_count)

            # Check if both thresholds met
            accum_count = getattr(self, '_lp_accum_count', 0)
            if self._lp_accum_total_ms > LONG_PRESS_MS and accum_count >= MIN_TOUCHES_FOR_LP:
                log.info("Geste detecte: LONG_PRESS - %.0fms over %d touches",
                        self._lp_accum_total_ms, accum_count)
                self._lp_accum_total_ms = 0
                self._lp_accum_count = 0
                return Gesture.LONG_PRESS
            else:
                return Gesture.NONE
        else:
            # Touch not at center - only reset if clearly outside (not a ghost at edge)
            # Don't reset for ghost touches that land far from center
            if dist_from_center > CENTER_RADIUS * 2:  # Very far from center = intentional move away
                self._lp_accum_total_ms = 0
                log.debug("Long press accumulator reset: touch too far from center (%.0f)", dist_from_center)

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

        Routage en fonction du mode menu/dashboard.

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

        # Verifier si on est en mode menu
        in_menu_mode = False
        if self._menu_navigator:
            try:
                from menu_navigator import MenuMode
                in_menu_mode = self._menu_navigator.state.mode == MenuMode.MENU
            except ImportError:
                pass

        # 3-finger tap: emergency exit (prioritaire sur tout)
        if gesture == Gesture.THREE_FINGER_TAP:
            if in_menu_mode:
                self._handle_emergency_exit()
            else:
                await self.on_three_finger_tap()
            return

        # Long press centre: toggle menu (si menu navigator configure)
        if gesture == Gesture.LONG_PRESS:
            await self.on_long_press_center()
            return

        # Swipe up from bottom: enter menu (alternative to long press for ghost-heavy hardware)
        if gesture == Gesture.SWIPE_UP:
            log.info("SWIPE_UP detected - entering menu")
            await self.on_long_press_center()  # Reuse same handler
            return

        # Si en mode menu, router differemment
        if in_menu_mode:
            if gesture == Gesture.TAP and primary:
                # Tap sur tranche = selection menu
                self._handle_slice_tap(primary.x, primary.y)

            elif gesture == Gesture.SWIPE_LEFT:
                # Swipe gauche = rotation selection
                if self._menu_navigator:
                    current = self._menu_navigator.state.selected_index
                    self._menu_navigator.state.selected_index = (current - 1) % 6
                    if self._on_menu_render:
                        self._on_menu_render(self._menu_navigator.state)

            elif gesture == Gesture.SWIPE_RIGHT:
                # Swipe droite = rotation selection
                if self._menu_navigator:
                    current = self._menu_navigator.state.selected_index
                    self._menu_navigator.state.selected_index = (current + 1) % 6
                    if self._on_menu_render:
                        self._on_menu_render(self._menu_navigator.state)

        else:
            # Mode dashboard: gestes normaux
            if gesture == Gesture.SWIPE_LEFT:
                await self.on_swipe_left()

            elif gesture == Gesture.SWIPE_RIGHT:
                await self.on_swipe_right()

            elif gesture == Gesture.TAP:
                if primary:
                    module = self._detect_module_from_position(primary.x, primary.y)
                    if module:
                        await self.on_module_tap(module)

            elif gesture == Gesture.SWIPE_DOWN:
                await self.on_swipe_down()

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
        Geste long press au centre: toggle menu ou afficher liste devices.

        Si le menu est integre, toggle menu/dashboard.
        Sinon, affiche/masque la liste des SecuBox configures.
        """
        # Si menu navigator est configure, utiliser le menu
        if self._menu_navigator:
            self._handle_menu_toggle()
            return

        # Sinon, fallback sur device list
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
    # Menu Integration Methods
    # ==========================================================================

    def _handle_menu_toggle(self):
        """
        Toggle entre mode menu et mode dashboard.

        Appele lors d'un long press centre si menu navigator configure.
        """
        if not self._menu_navigator:
            log.warning("MenuNavigator non configure - toggle menu ignore")
            return

        # Import dynamique pour eviter circular import
        from menu_navigator import MenuMode

        if self._menu_navigator.state.mode == MenuMode.DASHBOARD:
            log.info("Entree en mode menu")
            self._menu_navigator.enter_menu()
        else:
            log.info("Sortie vers dashboard")
            self._menu_navigator.exit_to_dashboard()

        # Notifier pour re-render
        if self._on_menu_render:
            try:
                self._on_menu_render(self._menu_navigator.state)
            except Exception as e:
                log.warning("Erreur callback menu render: %s", e)

    def _handle_slice_tap(self, x: int, y: int) -> Optional[str]:
        """
        Gerer un tap sur une tranche du menu radial.

        Args:
            x: Coordonnee X du touch
            y: Coordonnee Y du touch

        Returns:
            Action executee ou None
        """
        if not self._menu_navigator:
            log.warning("MenuNavigator non configure - slice tap ignore")
            return None

        # Detecter la tranche touchee
        slice_index = get_slice_from_touch(x, y)
        if slice_index is None:
            log.debug("Tap hors des tranches menu")
            return None

        log.info("Tap sur tranche menu: %d", slice_index)

        # Selectionner la tranche dans le navigateur
        self._menu_navigator.state.selected_index = slice_index
        action = self._menu_navigator.select_current()

        # Executer l'action si presente
        if action and self._action_executor:
            try:
                import asyncio
                asyncio.create_task(self._action_executor.execute(action))
            except Exception as e:
                log.error("Erreur execution action: %s", e)

        # Notifier pour re-render
        if self._on_menu_render:
            try:
                self._on_menu_render(self._menu_navigator.state)
            except Exception as e:
                log.warning("Erreur callback menu render: %s", e)

        return action

    def _handle_emergency_exit(self):
        """
        Sortie d'urgence vers le dashboard (3-finger tap).

        Force le retour au dashboard peu importe l'etat du menu.
        """
        if not self._menu_navigator:
            log.warning("MenuNavigator non configure - emergency exit ignore")
            return

        log.info("Emergency exit vers dashboard")
        self._menu_navigator.exit_to_dashboard()

        # Notifier pour re-render
        if self._on_menu_render:
            try:
                self._on_menu_render(self._menu_navigator.state)
            except Exception as e:
                log.warning("Erreur callback menu render: %s", e)

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
