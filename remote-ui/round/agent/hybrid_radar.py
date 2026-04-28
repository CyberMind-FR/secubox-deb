#!/usr/bin/env python3
"""
SecuBox Eye Remote - Hybrid Radar Visualization
Radar central rotatif + anneaux de métriques avec axes décalés.

Structure :
┌─────────────────────────────────────┐
│                                     │
│   ╭─────────────────────────────╮   │
│   │  MESH ▓▓▓▓▓▓▓░░░░░░░░░░░░  │   │  ← Anneau ext (axe à 300°)
│   │  ╭───────────────────────╮  │   │
│   │  │ ROOT ▓▓▓▓▓░░░░░░░░░░  │  │   │  ← Anneau (axe à 240°)
│   │  │ ╭─────────────────╮   │  │   │
│   │  │ │    ╱╲           │   │  │   │
│   │  │ │   ╱  ╲  RADAR   │   │  │   │  ← Radar central rotatif
│   │  │ │  ╱ ●  ╲         │   │  │   │     (métrique variable)
│   │  │ │ ╱──────╲        │   │  │   │
│   │  │ ╰─────────────────╯   │  │   │
│   │  ╰───────────────────────╯  │   │
│   ╰─────────────────────────────╯   │
│                                     │
└─────────────────────────────────────┘

Chaque anneau :
- A son propre point de départ (axe décalé)
- La progression suit l'arc depuis cet axe
- Crée une "courbe équilibrée" autour du cercle

CyberMind - https://cybermind.fr
"""

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


@dataclass
class RingMetric:
    """Métrique affichée comme anneau."""
    name: str
    label: str
    color: Tuple[int, int, int]
    radius: int               # Rayon de l'anneau
    start_angle: float        # Angle de départ (degrés, 0=droite)
    value: float = 0.0
    min_val: float = 0.0
    max_val: float = 100.0
    warn_threshold: float = 70.0
    crit_threshold: float = 85.0
    unit: str = "%"


# Configuration des anneaux (du plus grand au plus petit)
# Chaque anneau a son propre axe de départ décalé
RING_METRICS = {
    "AUTH": RingMetric(
        name="AUTH", label="CPU", color=(192, 78, 36),
        radius=214, start_angle=0,      # Départ à droite (0°)
        warn_threshold=70, crit_threshold=85, unit="%"
    ),
    "WALL": RingMetric(
        name="WALL", label="MEM", color=(154, 96, 16),
        radius=201, start_angle=60,     # Départ à 60°
        warn_threshold=75, crit_threshold=90, unit="%"
    ),
    "BOOT": RingMetric(
        name="BOOT", label="DISK", color=(128, 48, 24),
        radius=188, start_angle=120,    # Départ à 120°
        warn_threshold=80, crit_threshold=95, unit="%"
    ),
    "MIND": RingMetric(
        name="MIND", label="LOAD", color=(61, 53, 160),
        radius=175, start_angle=180,    # Départ à 180° (gauche)
        warn_threshold=2.0, crit_threshold=4.0, unit="×",
        min_val=0, max_val=8
    ),
    "ROOT": RingMetric(
        name="ROOT", label="TEMP", color=(10, 88, 64),
        radius=162, start_angle=240,    # Départ à 240°
        warn_threshold=65, crit_threshold=75, unit="°C"
    ),
    "MESH": RingMetric(
        name="MESH", label="WIFI", color=(16, 74, 136),
        radius=149, start_angle=300,    # Départ à 300°
        warn_threshold=-70, crit_threshold=-80, unit="dBm",
        min_val=-100, max_val=0
    ),
}


@dataclass
class HybridConfig:
    """Configuration du radar hybride."""
    width: int = 480
    height: int = 480
    center_x: int = 240
    center_y: int = 240

    # Radar central
    radar_radius: int = 120
    radar_inner: int = 20
    sweep_speed: float = 2.0    # Tours par minute

    # Anneaux
    ring_width: int = 10
    ring_gap: int = 3

    # Couleurs
    bg_color: Tuple[int, ...] = (8, 8, 8, 255)
    grid_color: Tuple[int, ...] = (30, 40, 30, 200)
    sweep_color: Tuple[int, ...] = (0, 255, 80, 200)
    text_color: Tuple[int, ...] = (180, 180, 180, 255)
    warn_color: Tuple[int, ...] = (255, 180, 0, 255)
    crit_color: Tuple[int, ...] = (255, 50, 50, 255)


class HybridRadar:
    """
    Radar hybride : centre rotatif + anneaux avec axes décalés.
    """

    def __init__(self, config: Optional[HybridConfig] = None):
        self.config = config or HybridConfig()
        self.rings = {k: RingMetric(**v.__dict__) for k, v in RING_METRICS.items()}
        self.ring_order = ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]

        # Radar central - métrique variable (ex: charge globale)
        self.radar_metric = "system"
        self.radar_value: float = 0.0
        self.radar_history: deque = deque(maxlen=360)

        self._start_time = time.time()

    def _load_font(self, size: int = 11):
        """Charge une police."""
        if not HAS_PIL:
            return None
        try:
            return ImageFont.truetype(
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size)
        except (OSError, IOError):
            try:
                return ImageFont.load_default()
            except Exception:
                return None

    @property
    def sweep_angle(self) -> float:
        """Angle actuel du balayage radar (degrés)."""
        elapsed = time.time() - self._start_time
        rotations = elapsed * (self.config.sweep_speed / 60.0)
        return (rotations * 360) % 360

    def update_ring(self, name: str, value: float):
        """Met à jour un anneau."""
        if name in self.rings:
            self.rings[name].value = value

    def update_radar(self, value: float):
        """Met à jour la métrique centrale du radar."""
        self.radar_value = value
        # Stocker dans l'historique à l'angle actuel
        angle = int(self.sweep_angle)
        while len(self.radar_history) <= angle:
            self.radar_history.append(0)
        if angle < len(self.radar_history):
            # Mettre à jour l'historique
            pass
        self.radar_history.append(value)

    def update_all(self, metrics: Dict[str, float]):
        """Met à jour toutes les métriques."""
        mapping = {
            "cpu_percent": "AUTH",
            "mem_percent": "WALL",
            "disk_percent": "BOOT",
            "load_avg_1": "MIND",
            "cpu_temp": "ROOT",
            "wifi_rssi": "MESH",
        }
        for key, name in mapping.items():
            if key in metrics:
                self.update_ring(name, metrics[key])

        # Radar central = moyenne pondérée ou métrique spécifique
        if "cpu_percent" in metrics:
            self.update_radar(metrics["cpu_percent"])

    def _normalize(self, ring: RingMetric) -> float:
        """Normalise la valeur entre 0 et 1."""
        if ring.max_val == ring.min_val:
            return 0.5
        norm = (ring.value - ring.min_val) / (ring.max_val - ring.min_val)
        return max(0.0, min(1.0, norm))

    def _is_warn(self, ring: RingMetric) -> bool:
        if ring.name == "MESH":
            return ring.value <= ring.warn_threshold
        return ring.value >= ring.warn_threshold

    def _is_crit(self, ring: RingMetric) -> bool:
        if ring.name == "MESH":
            return ring.value <= ring.crit_threshold
        return ring.value >= ring.crit_threshold

    def _deg_to_xy(self, angle_deg: float, radius: float) -> Tuple[float, float]:
        """Angle en degrés (0=droite, sens horaire) vers coordonnées."""
        rad = math.radians(angle_deg)
        x = self.config.center_x + radius * math.cos(rad)
        y = self.config.center_y + radius * math.sin(rad)
        return x, y

    def render(self) -> 'Image.Image':
        """Génère l'image."""
        if not HAS_PIL:
            raise ImportError("PIL requis")

        cfg = self.config
        img = Image.new('RGBA', (cfg.width, cfg.height), cfg.bg_color)
        draw = ImageDraw.Draw(img)

        # 1. Anneaux de métriques (du plus grand au plus petit)
        for name in self.ring_order:
            self._draw_ring(draw, self.rings[name])

        # 2. Grille du radar central
        self._draw_radar_grid(draw)

        # 3. Trace radar (historique)
        self._draw_radar_trace(draw)

        # 4. Balayage radar
        self._draw_radar_sweep(draw)

        # 5. Centre
        self._draw_center(draw)

        return img

    def _draw_ring(self, draw, ring: RingMetric):
        """Dessine un anneau de métrique avec axe décalé."""
        cfg = self.config
        norm = self._normalize(ring)

        # Couleur selon le niveau
        if self._is_crit(ring):
            color = cfg.crit_color
        elif self._is_warn(ring):
            color = cfg.warn_color
        else:
            color = (*ring.color, 255)

        # Arc de progression
        # Départ = start_angle, longueur = norm * 360°
        arc_length = norm * 360

        # Dessiner l'arc de fond (gris)
        bbox = [
            cfg.center_x - ring.radius, cfg.center_y - ring.radius,
            cfg.center_x + ring.radius, cfg.center_y + ring.radius
        ]
        draw.arc(bbox, ring.start_angle, ring.start_angle + 360,
                 fill=cfg.grid_color, width=cfg.ring_width)

        # Dessiner l'arc de valeur (coloré)
        if arc_length > 0:
            draw.arc(bbox, ring.start_angle, ring.start_angle + arc_length,
                     fill=color, width=cfg.ring_width)

        # Point de départ (petit marqueur)
        start_x, start_y = self._deg_to_xy(ring.start_angle, ring.radius)
        marker_size = 3
        draw.ellipse([start_x - marker_size, start_y - marker_size,
                      start_x + marker_size, start_y + marker_size],
                     fill=(255, 255, 255, 150))

        # Point de fin (valeur actuelle)
        end_angle = ring.start_angle + arc_length
        end_x, end_y = self._deg_to_xy(end_angle, ring.radius)
        draw.ellipse([end_x - 4, end_y - 4, end_x + 4, end_y + 4],
                     fill=color, outline=(255, 255, 255, 200))

    def _draw_radar_grid(self, draw):
        """Dessine la grille du radar central."""
        cfg = self.config
        cx, cy = cfg.center_x, cfg.center_y

        # Cercles concentriques
        for pct in [25, 50, 75, 100]:
            r = cfg.radar_inner + (cfg.radar_radius - cfg.radar_inner) * pct / 100
            draw.ellipse([cx - r, cy - r, cx + r, cy + r],
                         outline=cfg.grid_color, width=1)

        # Lignes radiales (tous les 30°)
        for angle in range(0, 360, 30):
            x1, y1 = self._deg_to_xy(angle, cfg.radar_inner)
            x2, y2 = self._deg_to_xy(angle, cfg.radar_radius)
            draw.line([(x1, y1), (x2, y2)], fill=cfg.grid_color, width=1)

    def _draw_radar_trace(self, draw):
        """Dessine la trace historique du radar."""
        cfg = self.config

        if len(self.radar_history) < 2:
            return

        # Dessiner les points historiques avec décroissance
        for i, value in enumerate(self.radar_history):
            if value <= 0:
                continue

            # Angle basé sur l'index
            angle = (i / len(self.radar_history)) * 360

            # Normaliser la valeur (0-100 supposé)
            norm = min(1.0, max(0, value / 100.0))
            r = cfg.radar_inner + (cfg.radar_radius - cfg.radar_inner) * norm

            # Opacité décroissante avec l'âge
            age = len(self.radar_history) - i
            alpha = int(150 * (1 - age / len(self.radar_history)))

            if alpha > 10:
                x, y = self._deg_to_xy(angle, r)
                color = (cfg.sweep_color[0], cfg.sweep_color[1],
                         cfg.sweep_color[2], alpha)
                draw.ellipse([x - 2, y - 2, x + 2, y + 2], fill=color)

    def _draw_radar_sweep(self, draw):
        """Dessine le balayage rotatif du radar."""
        cfg = self.config
        angle = self.sweep_angle

        # Ligne de balayage avec dégradé
        for i in range(15):
            a = angle - i * 2
            alpha = int(200 * (1 - i / 15))
            color = (cfg.sweep_color[0], cfg.sweep_color[1],
                     cfg.sweep_color[2], alpha)

            x1, y1 = cfg.center_x, cfg.center_y
            x2, y2 = self._deg_to_xy(a, cfg.radar_radius)
            draw.line([(x1, y1), (x2, y2)], fill=color, width=2)

        # Ligne principale
        x1, y1 = cfg.center_x, cfg.center_y
        x2, y2 = self._deg_to_xy(angle, cfg.radar_radius)
        draw.line([(x1, y1), (x2, y2)], fill=cfg.sweep_color, width=3)

        # Point de valeur actuelle sur le balayage
        norm = min(1.0, max(0, self.radar_value / 100.0))
        r = cfg.radar_inner + (cfg.radar_radius - cfg.radar_inner) * norm
        px, py = self._deg_to_xy(angle, r)
        draw.ellipse([px - 5, py - 5, px + 5, py + 5],
                     fill=cfg.sweep_color, outline=(255, 255, 255, 200))

    def _draw_center(self, draw):
        """Dessine le centre du radar."""
        cfg = self.config
        r = cfg.radar_inner - 3

        # Couleur selon l'état global
        any_crit = any(self._is_crit(self.rings[n]) for n in self.ring_order)
        any_warn = any(self._is_warn(self.rings[n]) for n in self.ring_order)

        if any_crit:
            color = cfg.crit_color
        elif any_warn:
            color = cfg.warn_color
        else:
            color = (0, 200, 80, 255)

        draw.ellipse([cfg.center_x - r, cfg.center_y - r,
                      cfg.center_x + r, cfg.center_y + r],
                     fill=color, outline=cfg.grid_color)


# =============================================================================
# Demo
# =============================================================================

def demo():
    """Démonstration du radar hybride."""
    import random

    print("SecuBox Hybrid Radar Demo")

    radar = HybridRadar()

    # Simuler plusieurs frames
    for i in range(60):
        metrics = {
            "cpu_percent": 30 + math.sin(i * 0.15) * 25 + random.random() * 10,
            "mem_percent": 45 + math.cos(i * 0.1) * 20 + random.random() * 8,
            "disk_percent": 55 + random.random() * 10,
            "load_avg_1": 1.2 + math.sin(i * 0.08) * 0.8 + random.random() * 0.3,
            "cpu_temp": 48 + math.sin(i * 0.12) * 12 + random.random() * 5,
            "wifi_rssi": -62 + math.cos(i * 0.1) * 15 + random.random() * 8,
        }
        radar.update_all(metrics)
        time.sleep(0.05)

    img = radar.render()
    filename = "/tmp/hybrid_radar.png"
    img.save(filename)
    print(f"Saved: {filename}")


if __name__ == "__main__":
    demo()
