#!/usr/bin/env python3
"""
SecuBox Eye Remote - Radar Metrics Visualization
Affichage radar rotatif avec trace statistique résiduelle.

Le radar tourne en continu, affichant :
- Une aiguille rotative (comme un radar)
- Une trace résiduelle qui s'estompe progressivement
- Les niveaux de métriques sous forme de courbe

Inspiré des écrans radar militaires avec persistence phosphorescente.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from enum import Enum

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = None
    ImageDraw = None


class MetricLevel(Enum):
    """Niveaux d'état des métriques."""
    NOMINAL = "nominal"
    WARN = "warn"
    CRITICAL = "critical"


@dataclass
class MetricSample:
    """Échantillon de métrique avec timestamp."""
    angle: float          # Angle en radians (position sur le radar)
    value: float          # Valeur 0-100%
    level: MetricLevel    # Niveau d'état
    timestamp: float      # Timestamp unix


@dataclass
class RadarConfig:
    """Configuration du radar."""
    # Dimensions
    width: int = 480
    height: int = 480
    center_x: int = 240
    center_y: int = 240
    radius: int = 200

    # Rotation
    rotation_speed: float = 2.0       # Tours par minute
    sweep_width: float = 0.15         # Largeur de l'aiguille en radians

    # Trace résiduelle
    trace_decay: float = 0.85         # Facteur de décroissance (0-1)
    trace_samples: int = 360          # Nombre de samples dans la trace
    trace_max_age: float = 30.0       # Âge max des samples en secondes

    # Couleurs (format RGBA)
    color_background: Tuple[int, ...] = (8, 8, 8, 255)
    color_grid: Tuple[int, ...] = (30, 60, 30, 255)
    color_sweep: Tuple[int, ...] = (0, 255, 65, 200)
    color_nominal: Tuple[int, ...] = (0, 255, 65, 255)
    color_warn: Tuple[int, ...] = (255, 180, 0, 255)
    color_critical: Tuple[int, ...] = (255, 50, 50, 255)
    color_trace: Tuple[int, ...] = (0, 200, 50, 180)

    # Cercles de niveau
    level_rings: List[int] = field(default_factory=lambda: [25, 50, 75, 100])


class RadarMetrics:
    """
    Radar rotatif avec trace statistique résiduelle.

    Usage:
        radar = RadarMetrics()
        radar.add_sample(value=45.2, level=MetricLevel.NOMINAL)
        image = radar.render()
    """

    def __init__(self, config: Optional[RadarConfig] = None):
        self.config = config or RadarConfig()
        self._samples: deque = deque(maxlen=self.config.trace_samples)
        self._start_time = time.time()
        self._current_angle = 0.0

        # Buffer pour la trace résiduelle (persistence phosphorescente)
        self._trace_buffer: List[float] = [0.0] * self.config.trace_samples

    @property
    def current_angle(self) -> float:
        """Angle actuel de l'aiguille en radians."""
        elapsed = time.time() - self._start_time
        rotations = elapsed * (self.config.rotation_speed / 60.0)
        return (rotations * 2 * math.pi) % (2 * math.pi)

    def add_sample(self, value: float, level: MetricLevel = MetricLevel.NOMINAL):
        """Ajoute un échantillon de métrique."""
        angle = self.current_angle
        sample = MetricSample(
            angle=angle,
            value=min(100, max(0, value)),
            level=level,
            timestamp=time.time()
        )
        self._samples.append(sample)

        # Mettre à jour le buffer de trace
        angle_index = int((angle / (2 * math.pi)) * self.config.trace_samples)
        angle_index = angle_index % self.config.trace_samples
        self._trace_buffer[angle_index] = value

    def _decay_trace(self):
        """Applique la décroissance à la trace résiduelle."""
        decay = self.config.trace_decay
        for i in range(len(self._trace_buffer)):
            self._trace_buffer[i] *= decay

    def _angle_to_xy(self, angle: float, radius: float) -> Tuple[int, int]:
        """Convertit angle + rayon en coordonnées x, y."""
        # Angle 0 = haut, rotation sens horaire
        x = self.config.center_x + radius * math.sin(angle)
        y = self.config.center_y - radius * math.cos(angle)
        return int(x), int(y)

    def _level_to_color(self, level: MetricLevel) -> Tuple[int, ...]:
        """Retourne la couleur selon le niveau."""
        if level == MetricLevel.CRITICAL:
            return self.config.color_critical
        elif level == MetricLevel.WARN:
            return self.config.color_warn
        return self.config.color_nominal

    def render(self) -> 'Image.Image':
        """Génère l'image du radar."""
        if Image is None:
            raise ImportError("PIL/Pillow requis pour le rendu")

        # Décroissance de la trace
        self._decay_trace()

        # Créer l'image
        img = Image.new('RGBA', (self.config.width, self.config.height),
                        self.config.color_background)
        draw = ImageDraw.Draw(img)

        # 1. Dessiner la grille
        self._draw_grid(draw)

        # 2. Dessiner la trace résiduelle (courbe statistique)
        self._draw_trace(draw)

        # 3. Dessiner les échantillons récents (points)
        self._draw_samples(draw)

        # 4. Dessiner l'aiguille rotative (sweep)
        self._draw_sweep(draw)

        # 5. Dessiner le centre
        self._draw_center(draw)

        return img

    def _draw_grid(self, draw: 'ImageDraw.Draw'):
        """Dessine la grille de fond."""
        cfg = self.config
        color = cfg.color_grid

        # Cercles de niveau
        for level in cfg.level_rings:
            r = int(cfg.radius * level / 100)
            draw.ellipse(
                [cfg.center_x - r, cfg.center_y - r,
                 cfg.center_x + r, cfg.center_y + r],
                outline=color,
                width=1
            )

        # Lignes radiales (tous les 30°)
        for angle_deg in range(0, 360, 30):
            angle = math.radians(angle_deg)
            x1, y1 = cfg.center_x, cfg.center_y
            x2, y2 = self._angle_to_xy(angle, cfg.radius)
            draw.line([(x1, y1), (x2, y2)], fill=color, width=1)

    def _draw_trace(self, draw: 'ImageDraw.Draw'):
        """Dessine la trace résiduelle (courbe statistique)."""
        cfg = self.config
        num_samples = cfg.trace_samples

        # Dessiner la trace comme une courbe fermée
        points = []
        for i in range(num_samples):
            angle = (i / num_samples) * 2 * math.pi
            value = self._trace_buffer[i]
            if value > 0:
                # Rayon proportionnel à la valeur
                r = cfg.radius * (value / 100.0)
                x, y = self._angle_to_xy(angle, r)
                points.append((x, y))

        # Dessiner les segments de trace
        if len(points) > 1:
            for i in range(len(points) - 1):
                # Opacité décroissante avec l'âge
                alpha = int(180 * (self._trace_buffer[i] / 100.0))
                color = (cfg.color_trace[0], cfg.color_trace[1],
                         cfg.color_trace[2], alpha)
                draw.line([points[i], points[i + 1]], fill=color, width=2)

    def _draw_samples(self, draw: 'ImageDraw.Draw'):
        """Dessine les échantillons récents comme des points."""
        cfg = self.config
        now = time.time()

        for sample in self._samples:
            age = now - sample.timestamp
            if age > cfg.trace_max_age:
                continue

            # Opacité décroissante avec l'âge
            alpha = int(255 * (1 - age / cfg.trace_max_age))
            color = self._level_to_color(sample.level)
            color = (color[0], color[1], color[2], alpha)

            # Position
            r = cfg.radius * (sample.value / 100.0)
            x, y = self._angle_to_xy(sample.angle, r)

            # Taille du point selon le niveau
            size = 3 if sample.level == MetricLevel.NOMINAL else 5
            draw.ellipse([x - size, y - size, x + size, y + size],
                         fill=color)

    def _draw_sweep(self, draw: 'ImageDraw.Draw'):
        """Dessine l'aiguille rotative avec effet de balayage."""
        cfg = self.config
        angle = self.current_angle

        # Dégradé de l'aiguille (plusieurs lignes avec opacité décroissante)
        num_lines = 20
        for i in range(num_lines):
            offset = -cfg.sweep_width * (i / num_lines)
            a = angle + offset
            alpha = int(200 * (1 - i / num_lines))
            color = (cfg.color_sweep[0], cfg.color_sweep[1],
                     cfg.color_sweep[2], alpha)

            x1, y1 = cfg.center_x, cfg.center_y
            x2, y2 = self._angle_to_xy(a, cfg.radius)
            draw.line([(x1, y1), (x2, y2)], fill=color, width=2)

        # Ligne principale de l'aiguille
        x1, y1 = cfg.center_x, cfg.center_y
        x2, y2 = self._angle_to_xy(angle, cfg.radius)
        draw.line([(x1, y1), (x2, y2)], fill=cfg.color_sweep, width=3)

    def _draw_center(self, draw: 'ImageDraw.Draw'):
        """Dessine le point central."""
        cfg = self.config
        size = 8
        draw.ellipse(
            [cfg.center_x - size, cfg.center_y - size,
             cfg.center_x + size, cfg.center_y + size],
            fill=cfg.color_sweep,
            outline=cfg.color_background,
            width=2
        )


class RadarDashboardWidget:
    """
    Widget radar pour intégration dans le dashboard.

    Affiche les métriques SecuBox en mode radar avec :
    - Rotation continue
    - Trace résiduelle phosphorescente
    - Indicateurs de niveau (nominal/warn/critical)
    """

    def __init__(self, metrics_source=None):
        self.radar = RadarMetrics()
        self._metrics_source = metrics_source
        self._last_update = 0
        self._update_interval = 0.5  # secondes

    def update(self):
        """Met à jour le radar avec les dernières métriques."""
        now = time.time()
        if now - self._last_update < self._update_interval:
            return

        self._last_update = now

        if self._metrics_source:
            # Récupérer les métriques depuis la source
            metrics = self._metrics_source.get_metrics()
            value = metrics.get('cpu_percent', 0)
            level = self._value_to_level(value, warn=70, crit=85)
            self.radar.add_sample(value, level)
        else:
            # Mode démo : valeurs simulées
            import random
            value = 30 + random.random() * 40
            level = self._value_to_level(value, warn=60, crit=80)
            self.radar.add_sample(value, level)

    def _value_to_level(self, value: float, warn: float, crit: float) -> MetricLevel:
        """Convertit une valeur en niveau d'état."""
        if value >= crit:
            return MetricLevel.CRITICAL
        elif value >= warn:
            return MetricLevel.WARN
        return MetricLevel.NOMINAL

    def render(self) -> 'Image.Image':
        """Génère l'image du widget radar."""
        self.update()
        return self.radar.render()


# =============================================================================
# Demo / Test
# =============================================================================

def demo():
    """Démonstration du radar en mode simulation."""
    import random

    print("SecuBox Radar Metrics Demo")
    print("Generating radar frames...")

    radar = RadarMetrics()

    # Générer quelques frames
    for frame in range(100):
        # Simuler une métrique
        value = 30 + math.sin(frame * 0.1) * 20 + random.random() * 10
        level = MetricLevel.NOMINAL
        if value > 70:
            level = MetricLevel.WARN
        if value > 85:
            level = MetricLevel.CRITICAL

        radar.add_sample(value, level)

        # Sauvegarder quelques frames
        if frame % 20 == 0:
            img = radar.render()
            filename = f"/tmp/radar_frame_{frame:03d}.png"
            img.save(filename)
            print(f"  Saved: {filename}")

        time.sleep(0.1)

    print("Done! Check /tmp/radar_frame_*.png")


if __name__ == "__main__":
    demo()
