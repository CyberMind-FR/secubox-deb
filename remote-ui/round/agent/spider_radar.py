#!/usr/bin/env python3
"""
SecuBox Eye Remote - Spider/Star Radar Visualization
Graphique en étoile avec chaque métrique sur son propre axe.

   AUTH (CPU)       Chaque métrique a son propre axe radial.
       ↑            Le centre = 0 (min)
       │            Le bord = 100% (max)
MESH ← • → WALL     La valeur est représentée par un point
       │            sur l'axe + une courbe reliant tous les points.
       ↓
   MIND (LOAD)

La courbe forme un polygone fermé montrant
l'équilibre entre toutes les métriques.

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = None
    ImageDraw = None
    ImageFont = None


@dataclass
class SpiderMetric:
    """Métrique pour le graphique spider."""
    name: str
    label: str
    color: Tuple[int, int, int]
    value: float = 0.0
    min_val: float = 0.0
    max_val: float = 100.0
    warn_threshold: float = 70.0
    crit_threshold: float = 85.0
    unit: str = "%"
    history: deque = field(default_factory=lambda: deque(maxlen=30))


# Configuration des 6 modules SecuBox
# Ordre : AUTH en haut, puis sens horaire
SPIDER_MODULES = {
    "AUTH": SpiderMetric(
        name="AUTH", label="CPU", color=(192, 78, 36),
        min_val=0, max_val=100, warn_threshold=70, crit_threshold=85, unit="%"
    ),
    "WALL": SpiderMetric(
        name="WALL", label="MEM", color=(154, 96, 16),
        min_val=0, max_val=100, warn_threshold=75, crit_threshold=90, unit="%"
    ),
    "BOOT": SpiderMetric(
        name="BOOT", label="DISK", color=(128, 48, 24),
        min_val=0, max_val=100, warn_threshold=80, crit_threshold=95, unit="%"
    ),
    "MIND": SpiderMetric(
        name="MIND", label="LOAD", color=(61, 53, 160),
        min_val=0, max_val=8, warn_threshold=2.0, crit_threshold=4.0, unit="×"
    ),
    "ROOT": SpiderMetric(
        name="ROOT", label="TEMP", color=(10, 88, 64),
        min_val=0, max_val=100, warn_threshold=65, crit_threshold=75, unit="°C"
    ),
    "MESH": SpiderMetric(
        name="MESH", label="WIFI", color=(16, 74, 136),
        min_val=-100, max_val=0, warn_threshold=-70, crit_threshold=-80, unit="dBm"
    ),
}


@dataclass
class SpiderConfig:
    """Configuration du graphique spider."""
    width: int = 480
    height: int = 480
    center_x: int = 240
    center_y: int = 240
    radius: int = 160           # Rayon max
    inner_radius: int = 30      # Zone centrale

    # Affichage
    show_grid: bool = True
    show_labels: bool = True
    show_values: bool = True
    show_polygon: bool = True   # Courbe reliant les valeurs
    show_history: bool = True   # Trace historique (polygones estompés)
    show_points: bool = True    # Points sur chaque axe

    # Niveaux de grille (% du max)
    grid_levels: List[int] = field(default_factory=lambda: [25, 50, 75, 100])

    # Couleurs
    color_background: Tuple[int, ...] = (8, 8, 8, 255)
    color_grid: Tuple[int, ...] = (40, 50, 40, 255)
    color_axis: Tuple[int, ...] = (60, 70, 60, 255)
    color_text: Tuple[int, ...] = (200, 200, 200, 255)
    color_polygon: Tuple[int, ...] = (0, 200, 80, 150)  # Remplissage
    color_polygon_line: Tuple[int, ...] = (0, 255, 100, 255)
    color_warn: Tuple[int, ...] = (255, 180, 0, 255)
    color_crit: Tuple[int, ...] = (255, 50, 50, 255)


class SpiderRadar:
    """
    Graphique spider/araignée avec 6 axes radiaux.

    Chaque axe représente une métrique :
    - Centre = valeur minimum
    - Bord = valeur maximum
    - Courbe polygonale relie les 6 valeurs
    """

    def __init__(self, config: Optional[SpiderConfig] = None,
                 modules: Optional[Dict[str, SpiderMetric]] = None):
        self.config = config or SpiderConfig()
        self.modules = modules or {k: SpiderMetric(**{**v.__dict__})
                                   for k, v in SPIDER_MODULES.items()}
        # Ordre des modules (sens horaire depuis le haut)
        self.module_order = ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]

    def _get_font(self, size: int = 12):
        """Charge une police."""
        if ImageFont is None:
            return None
        try:
            return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", size)
        except (OSError, IOError):
            try:
                return ImageFont.truetype("/usr/share/fonts/TTF/DejaVuSansMono.ttf", size)
            except (OSError, IOError):
                return ImageFont.load_default()

    def update_metric(self, name: str, value: float):
        """Met à jour une métrique."""
        if name in self.modules:
            self.modules[name].value = value
            self.modules[name].history.append(value)

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
                self.update_metric(name, metrics[key])

    def _normalize(self, module: SpiderMetric) -> float:
        """Normalise la valeur entre 0 et 1."""
        val = module.value
        min_v, max_v = module.min_val, module.max_val
        if max_v == min_v:
            return 0.5
        normalized = (val - min_v) / (max_v - min_v)
        return max(0, min(1, normalized))

    def _get_angle(self, index: int) -> float:
        """Retourne l'angle pour un index de module (0 = haut)."""
        # 0 = AUTH = haut (-π/2)
        # Sens horaire
        return -math.pi / 2 + (2 * math.pi * index / len(self.module_order))

    def _angle_to_xy(self, angle: float, radius: float) -> Tuple[float, float]:
        """Convertit angle + rayon en coordonnées."""
        x = self.config.center_x + radius * math.cos(angle)
        y = self.config.center_y + radius * math.sin(angle)
        return x, y

    def _get_polygon_points(self, values: Optional[Dict[str, float]] = None) -> List[Tuple[float, float]]:
        """Calcule les points du polygone pour les valeurs données."""
        cfg = self.config
        points = []

        for i, name in enumerate(self.module_order):
            module = self.modules[name]
            angle = self._get_angle(i)

            # Utiliser les valeurs fournies ou les valeurs actuelles
            if values and name in values:
                val = values[name]
                # Normaliser manuellement
                min_v, max_v = module.min_val, module.max_val
                norm = (val - min_v) / (max_v - min_v) if max_v != min_v else 0.5
                norm = max(0, min(1, norm))
            else:
                norm = self._normalize(module)

            # Rayon = inner_radius + (radius - inner_radius) * normalized
            r = cfg.inner_radius + (cfg.radius - cfg.inner_radius) * norm
            x, y = self._angle_to_xy(angle, r)
            points.append((x, y))

        return points

    def _is_critical(self, module: SpiderMetric) -> bool:
        """Vérifie si la métrique est en état critique."""
        if module.name == "MESH":
            return module.value <= module.crit_threshold
        return module.value >= module.crit_threshold

    def _is_warning(self, module: SpiderMetric) -> bool:
        """Vérifie si la métrique est en état warning."""
        if module.name == "MESH":
            return module.value <= module.warn_threshold
        return module.value >= module.warn_threshold

    def render(self) -> 'Image.Image':
        """Génère l'image du graphique spider."""
        if Image is None:
            raise ImportError("PIL/Pillow requis")

        cfg = self.config
        img = Image.new('RGBA', (cfg.width, cfg.height), cfg.color_background)
        draw = ImageDraw.Draw(img)

        # 1. Grille de fond
        if cfg.show_grid:
            self._draw_grid(draw)

        # 2. Axes radiaux
        self._draw_axes(draw)

        # 3. Historique (polygones estompés)
        if cfg.show_history:
            self._draw_history(draw)

        # 4. Polygone principal
        if cfg.show_polygon:
            self._draw_polygon(draw)

        # 5. Points sur les axes
        if cfg.show_points:
            self._draw_points(draw)

        # 6. Labels et valeurs
        if cfg.show_labels:
            self._draw_labels(draw)

        # 7. Centre
        self._draw_center(draw)

        return img

    def _draw_grid(self, draw: 'ImageDraw.Draw'):
        """Dessine la grille concentrique."""
        cfg = self.config

        for level in cfg.grid_levels:
            r = cfg.inner_radius + (cfg.radius - cfg.inner_radius) * level / 100
            # Polygone de grille (hexagone)
            points = []
            for i in range(len(self.module_order)):
                angle = self._get_angle(i)
                x, y = self._angle_to_xy(angle, r)
                points.append((x, y))
            points.append(points[0])  # Fermer

            draw.line(points, fill=cfg.color_grid, width=1)

    def _draw_axes(self, draw: 'ImageDraw.Draw'):
        """Dessine les axes radiaux."""
        cfg = self.config

        for i, name in enumerate(self.module_order):
            angle = self._get_angle(i)
            module = self.modules[name]

            # Ligne de l'axe
            x1, y1 = cfg.center_x, cfg.center_y
            x2, y2 = self._angle_to_xy(angle, cfg.radius)

            # Couleur de l'axe = couleur du module (estompée)
            axis_color = (*module.color, 100)
            draw.line([(x1, y1), (x2, y2)], fill=axis_color, width=2)

    def _draw_history(self, draw: 'ImageDraw.Draw'):
        """Dessine les polygones historiques estompés."""
        cfg = self.config

        # Récupérer l'historique de chaque module
        max_history = min(len(m.history) for m in self.modules.values())
        if max_history < 2:
            return

        for h_idx in range(max_history - 1):
            # Construire les valeurs pour cet instant historique
            values = {}
            for name in self.module_order:
                if h_idx < len(self.modules[name].history):
                    values[name] = self.modules[name].history[h_idx]

            if len(values) == len(self.module_order):
                points = self._get_polygon_points(values)
                # Opacité décroissante avec l'âge
                age = max_history - h_idx
                alpha = int(50 * (age / max_history))
                color = (cfg.color_polygon[0], cfg.color_polygon[1],
                         cfg.color_polygon[2], alpha)
                draw.polygon(points, outline=color)

    def _draw_polygon(self, draw: 'ImageDraw.Draw'):
        """Dessine le polygone principal (valeurs actuelles)."""
        cfg = self.config
        points = self._get_polygon_points()

        # Remplissage semi-transparent
        draw.polygon(points, fill=cfg.color_polygon)

        # Contour
        outline_points = points + [points[0]]
        draw.line(outline_points, fill=cfg.color_polygon_line, width=2)

    def _draw_points(self, draw: 'ImageDraw.Draw'):
        """Dessine les points sur chaque axe."""
        cfg = self.config

        for i, name in enumerate(self.module_order):
            module = self.modules[name]
            angle = self._get_angle(i)
            norm = self._normalize(module)
            r = cfg.inner_radius + (cfg.radius - cfg.inner_radius) * norm
            x, y = self._angle_to_xy(angle, r)

            # Couleur selon le niveau
            if self._is_critical(module):
                color = cfg.color_crit
            elif self._is_warning(module):
                color = cfg.color_warn
            else:
                color = (*module.color, 255)

            # Point
            size = 6
            draw.ellipse([x - size, y - size, x + size, y + size],
                         fill=color, outline=(255, 255, 255, 200))

    def _draw_labels(self, draw: 'ImageDraw.Draw'):
        """Dessine les labels des modules."""
        cfg = self.config
        font = self._get_font(12)
        font_small = self._get_font(10)

        for i, name in enumerate(self.module_order):
            module = self.modules[name]
            angle = self._get_angle(i)

            # Position du label (au-delà du rayon)
            label_radius = cfg.radius + 30
            x, y = self._angle_to_xy(angle, label_radius)

            # Texte du label
            label = f"{module.name}"
            if font:
                bbox = draw.textbbox((0, 0), label, font=font)
                tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
            else:
                tw, th = len(label) * 8, 12

            # Ajuster la position selon l'angle
            text_x = x - tw / 2
            text_y = y - th / 2

            draw.text((text_x, text_y), label, fill=(*module.color, 255), font=font)

            # Valeur sous le label
            if cfg.show_values:
                if module.name == "MIND":
                    val_text = f"{module.value:.1f}{module.unit}"
                elif module.name == "MESH":
                    val_text = f"{int(module.value)}{module.unit}"
                else:
                    val_text = f"{int(module.value)}{module.unit}"

                if font_small:
                    bbox = draw.textbbox((0, 0), val_text, font=font_small)
                    vw = bbox[2] - bbox[0]
                else:
                    vw = len(val_text) * 6

                draw.text((x - vw / 2, y + th / 2 + 2), val_text,
                          fill=cfg.color_text, font=font_small)

    def _draw_center(self, draw: 'ImageDraw.Draw'):
        """Dessine le cercle central."""
        cfg = self.config
        r = cfg.inner_radius - 5

        # Couleur selon l'état global
        any_crit = any(self._is_critical(m) for m in self.modules.values())
        any_warn = any(self._is_warning(m) for m in self.modules.values())

        if any_crit:
            color = cfg.color_crit
        elif any_warn:
            color = cfg.color_warn
        else:
            color = (0, 200, 80, 255)

        draw.ellipse(
            [cfg.center_x - r, cfg.center_y - r,
             cfg.center_x + r, cfg.center_y + r],
            fill=color, outline=cfg.color_axis
        )


# =============================================================================
# Demo
# =============================================================================

def demo():
    """Démonstration du graphique spider."""
    import random

    print("SecuBox Spider Radar Demo")

    spider = SpiderRadar()

    # Simuler plusieurs frames pour l'historique
    for _ in range(20):
        metrics = {
            "cpu_percent": 20 + random.random() * 50,
            "mem_percent": 30 + random.random() * 40,
            "disk_percent": 40 + random.random() * 25,
            "load_avg_1": 0.3 + random.random() * 2,
            "cpu_temp": 35 + random.random() * 30,
            "wifi_rssi": -85 + random.random() * 50,
        }
        spider.update_all(metrics)

    img = spider.render()
    filename = "/tmp/spider_radar.png"
    img.save(filename)
    print(f"Saved: {filename}")


if __name__ == "__main__":
    demo()
