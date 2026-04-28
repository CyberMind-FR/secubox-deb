#!/usr/bin/env python3
"""
SecuBox Eye Remote - Classic Radar Visualization
Radar classique avec 6 métriques équilibrées sur le cercle.

        AUTH (0°)
          │
    MESH  │  WALL
      ╲   │   ╱
       ╲  │  ╱
        ╲ │ ╱
         ●●●  ← Centre (min=0)
        ╱ │ ╲
       ╱  │  ╲
      ╱   │   ╲
    ROOT  │  BOOT
          │
       MIND (180°)

Chaque métrique :
- A son propre axe radial (60° d'écart)
- Croît du centre (0) vers le bord (max)
- Affiche une barre + point de valeur

CyberMind - https://cybermind.fr
"""

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    Image = None
    ImageDraw = None
    ImageFont = None


@dataclass
class RadarMetric:
    """Métrique pour le radar."""
    name: str
    label: str
    color: Tuple[int, int, int]
    angle: float              # Angle en degrés (0=haut, sens horaire)
    value: float = 0.0
    min_val: float = 0.0
    max_val: float = 100.0
    warn_threshold: float = 70.0
    crit_threshold: float = 85.0
    unit: str = "%"
    history: deque = field(default_factory=lambda: deque(maxlen=60))


# 6 modules équilibrés sur 360° (60° d'écart)
# Position : 0° = haut, sens horaire
RADAR_MODULES: Dict[str, RadarMetric] = {
    "AUTH": RadarMetric(
        name="AUTH", label="CPU", color=(192, 78, 36), angle=0,
        min_val=0, max_val=100, warn_threshold=70, crit_threshold=85, unit="%"
    ),
    "WALL": RadarMetric(
        name="WALL", label="MEM", color=(154, 96, 16), angle=60,
        min_val=0, max_val=100, warn_threshold=75, crit_threshold=90, unit="%"
    ),
    "BOOT": RadarMetric(
        name="BOOT", label="DISK", color=(128, 48, 24), angle=120,
        min_val=0, max_val=100, warn_threshold=80, crit_threshold=95, unit="%"
    ),
    "MIND": RadarMetric(
        name="MIND", label="LOAD", color=(61, 53, 160), angle=180,
        min_val=0, max_val=8, warn_threshold=2.0, crit_threshold=4.0, unit="×"
    ),
    "ROOT": RadarMetric(
        name="ROOT", label="TEMP", color=(10, 88, 64), angle=240,
        min_val=0, max_val=100, warn_threshold=65, crit_threshold=75, unit="°C"
    ),
    "MESH": RadarMetric(
        name="MESH", label="WIFI", color=(16, 74, 136), angle=300,
        min_val=-100, max_val=0, warn_threshold=-70, crit_threshold=-80, unit="dBm"
    ),
}


@dataclass
class ClassicRadarConfig:
    """Configuration du radar classique."""
    # Dimensions
    width: int = 480
    height: int = 480
    center_x: int = 240
    center_y: int = 240
    radius: int = 170          # Rayon externe
    inner_radius: int = 20     # Rayon du cercle central

    # Barres de métriques
    bar_width: int = 12        # Largeur des barres radiales
    point_size: int = 8        # Taille du point de valeur

    # Grille
    grid_rings: int = 4        # Nombre de cercles de grille
    show_grid: bool = True
    show_axes: bool = True
    show_labels: bool = True
    show_values: bool = True
    show_polygon: bool = True  # Polygone reliant les valeurs
    show_history: bool = True  # Trace historique

    # Couleurs
    bg_color: Tuple[int, int, int, int] = (8, 8, 8, 255)
    grid_color: Tuple[int, int, int, int] = (30, 40, 30, 200)
    axis_color: Tuple[int, int, int, int] = (50, 60, 50, 255)
    text_color: Tuple[int, int, int, int] = (180, 180, 180, 255)
    polygon_fill: Tuple[int, int, int, int] = (0, 180, 60, 80)
    polygon_line: Tuple[int, int, int, int] = (0, 220, 80, 200)
    warn_color: Tuple[int, int, int, int] = (255, 180, 0, 255)
    crit_color: Tuple[int, int, int, int] = (255, 50, 50, 255)
    nominal_color: Tuple[int, int, int, int] = (0, 200, 80, 255)


class ClassicRadar:
    """
    Radar classique avec 6 métriques équilibrées.

    Chaque métrique a son propre axe radial partant du centre.
    La valeur est représentée par la distance du centre au point.
    """

    def __init__(self, config: Optional[ClassicRadarConfig] = None):
        self.config = config or ClassicRadarConfig()
        self.modules = {k: RadarMetric(**v.__dict__)
                        for k, v in RADAR_MODULES.items()}
        # Ordre pour le polygone (sens horaire depuis AUTH)
        self.order = ["AUTH", "WALL", "BOOT", "MIND", "ROOT", "MESH"]

    def _load_font(self, size: int = 12):
        """Charge une police."""
        if not HAS_PIL or ImageFont is None:
            return None
        for path in [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        ]:
            try:
                return ImageFont.truetype(path, size)
            except (OSError, IOError):
                continue
        return ImageFont.load_default()

    def update(self, name: str, value: float):
        """Met à jour une métrique."""
        if name in self.modules:
            m = self.modules[name]
            m.value = value
            m.history.append(value)

    def update_all(self, metrics: Dict[str, float]):
        """Met à jour toutes les métriques depuis un dict."""
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
                self.update(name, metrics[key])

    def _normalize(self, m: RadarMetric) -> float:
        """Normalise la valeur entre 0 et 1."""
        if m.max_val == m.min_val:
            return 0.5
        norm = (m.value - m.min_val) / (m.max_val - m.min_val)
        return max(0.0, min(1.0, norm))

    def _is_warn(self, m: RadarMetric) -> bool:
        """Vérifie si en warning."""
        if m.name == "MESH":
            return m.value <= m.warn_threshold
        return m.value >= m.warn_threshold

    def _is_crit(self, m: RadarMetric) -> bool:
        """Vérifie si critique."""
        if m.name == "MESH":
            return m.value <= m.crit_threshold
        return m.value >= m.crit_threshold

    def _deg_to_xy(self, angle_deg: float, radius: float) -> Tuple[float, float]:
        """Convertit angle (degrés, 0=haut) + rayon en coordonnées."""
        # 0° = haut, sens horaire
        angle_rad = math.radians(angle_deg - 90)  # -90 pour que 0=haut
        x = self.config.center_x + radius * math.cos(angle_rad)
        y = self.config.center_y + radius * math.sin(angle_rad)
        return x, y

    def _get_value_point(self, m: RadarMetric) -> Tuple[float, float]:
        """Retourne les coordonnées du point de valeur."""
        cfg = self.config
        norm = self._normalize(m)
        r = cfg.inner_radius + (cfg.radius - cfg.inner_radius) * norm
        return self._deg_to_xy(m.angle, r)

    def render(self) -> 'Image.Image':
        """Génère l'image du radar."""
        if not HAS_PIL:
            raise ImportError("PIL/Pillow requis pour le rendu")

        cfg = self.config
        img = Image.new('RGBA', (cfg.width, cfg.height), cfg.bg_color)
        draw = ImageDraw.Draw(img)

        # 1. Grille de fond (cercles concentriques)
        if cfg.show_grid:
            self._draw_grid(draw)

        # 2. Axes radiaux (6 lignes)
        if cfg.show_axes:
            self._draw_axes(draw)

        # 3. Trace historique (polygones estompés)
        if cfg.show_history:
            self._draw_history(draw)

        # 4. Polygone principal (relie les 6 valeurs)
        if cfg.show_polygon:
            self._draw_polygon(draw)

        # 5. Barres et points de valeur
        self._draw_values(draw)

        # 6. Labels et chiffres
        if cfg.show_labels:
            self._draw_labels(draw)

        # 7. Centre
        self._draw_center(draw)

        return img

    def _draw_grid(self, draw):
        """Dessine les cercles concentriques de grille."""
        cfg = self.config
        step = (cfg.radius - cfg.inner_radius) / cfg.grid_rings

        for i in range(1, cfg.grid_rings + 1):
            r = cfg.inner_radius + step * i
            draw.ellipse(
                [cfg.center_x - r, cfg.center_y - r,
                 cfg.center_x + r, cfg.center_y + r],
                outline=cfg.grid_color, width=1
            )

    def _draw_axes(self, draw):
        """Dessine les 6 axes radiaux."""
        cfg = self.config

        for name in self.order:
            m = self.modules[name]
            # Ligne du centre au bord
            x1, y1 = cfg.center_x, cfg.center_y
            x2, y2 = self._deg_to_xy(m.angle, cfg.radius)
            # Couleur = couleur du module, estompée
            color = (*m.color, 80)
            draw.line([(x1, y1), (x2, y2)], fill=color, width=1)

    def _draw_history(self, draw):
        """Dessine les polygones historiques estompés."""
        cfg = self.config

        # Trouver la longueur d'historique commune minimale
        min_len = min(len(self.modules[n].history) for n in self.order)
        if min_len < 2:
            return

        # Dessiner les anciens polygones (les plus vieux = plus transparents)
        for h_idx in range(min_len - 1):
            points = []
            for name in self.order:
                m = self.modules[name]
                val = m.history[h_idx]
                # Normaliser cette valeur historique
                if m.max_val != m.min_val:
                    norm = (val - m.min_val) / (m.max_val - m.min_val)
                    norm = max(0, min(1, norm))
                else:
                    norm = 0.5
                r = cfg.inner_radius + (cfg.radius - cfg.inner_radius) * norm
                x, y = self._deg_to_xy(m.angle, r)
                points.append((x, y))

            # Opacité décroissante avec l'âge
            alpha = int(30 * ((h_idx + 1) / min_len))
            color = (cfg.polygon_line[0], cfg.polygon_line[1],
                     cfg.polygon_line[2], alpha)
            if len(points) >= 3:
                draw.polygon(points, outline=color)

    def _draw_polygon(self, draw):
        """Dessine le polygone reliant les 6 valeurs actuelles."""
        cfg = self.config
        points = [self._get_value_point(self.modules[n]) for n in self.order]

        if len(points) >= 3:
            # Remplissage
            draw.polygon(points, fill=cfg.polygon_fill)
            # Contour
            outline = list(points) + [points[0]]
            draw.line(outline, fill=cfg.polygon_line, width=2)

    def _draw_values(self, draw):
        """Dessine les barres et points de valeur pour chaque métrique."""
        cfg = self.config

        for name in self.order:
            m = self.modules[name]
            norm = self._normalize(m)

            # Couleur selon le niveau
            if self._is_crit(m):
                color = cfg.crit_color
            elif self._is_warn(m):
                color = cfg.warn_color
            else:
                color = (*m.color, 255)

            # Barre du centre vers le point de valeur
            r_val = cfg.inner_radius + (cfg.radius - cfg.inner_radius) * norm
            x1, y1 = self._deg_to_xy(m.angle, cfg.inner_radius)
            x2, y2 = self._deg_to_xy(m.angle, r_val)
            draw.line([(x1, y1), (x2, y2)], fill=color, width=cfg.bar_width)

            # Point à l'extrémité
            ps = cfg.point_size
            draw.ellipse([x2 - ps, y2 - ps, x2 + ps, y2 + ps],
                         fill=color, outline=(255, 255, 255, 200))

    def _draw_labels(self, draw):
        """Dessine les labels et valeurs autour du radar."""
        cfg = self.config
        font = self._load_font(11)
        font_small = self._load_font(9)

        for name in self.order:
            m = self.modules[name]
            # Position du label (au-delà du rayon)
            lx, ly = self._deg_to_xy(m.angle, cfg.radius + 28)

            # Nom du module
            label = m.name
            if font:
                bbox = draw.textbbox((0, 0), label, font=font)
                tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
            else:
                tw, th = len(label) * 7, 11

            draw.text((lx - tw / 2, ly - th / 2), label,
                      fill=(*m.color, 255), font=font)

            # Valeur
            if cfg.show_values:
                if m.name == "MIND":
                    val_text = f"{m.value:.1f}{m.unit}"
                elif m.name == "MESH":
                    val_text = f"{int(m.value)}{m.unit}"
                else:
                    val_text = f"{int(m.value)}{m.unit}"

                if font_small:
                    bbox = draw.textbbox((0, 0), val_text, font=font_small)
                    vw = bbox[2] - bbox[0]
                else:
                    vw = len(val_text) * 6

                draw.text((lx - vw / 2, ly + th / 2 + 2), val_text,
                          fill=cfg.text_color, font=font_small)

    def _draw_center(self, draw):
        """Dessine le cercle central avec indicateur d'état global."""
        cfg = self.config
        r = cfg.inner_radius - 3

        # Couleur selon l'état global
        any_crit = any(self._is_crit(self.modules[n]) for n in self.order)
        any_warn = any(self._is_warn(self.modules[n]) for n in self.order)

        if any_crit:
            color = cfg.crit_color
        elif any_warn:
            color = cfg.warn_color
        else:
            color = cfg.nominal_color

        draw.ellipse(
            [cfg.center_x - r, cfg.center_y - r,
             cfg.center_x + r, cfg.center_y + r],
            fill=color, outline=cfg.axis_color
        )


# =============================================================================
# Demo
# =============================================================================

def demo():
    """Démonstration du radar classique."""
    import random

    print("SecuBox Classic Radar Demo")
    print("-" * 40)

    radar = ClassicRadar()

    # Simuler plusieurs frames pour l'historique
    for i in range(30):
        metrics = {
            "cpu_percent": 25 + math.sin(i * 0.2) * 20 + random.random() * 10,
            "mem_percent": 40 + math.cos(i * 0.15) * 15 + random.random() * 8,
            "disk_percent": 50 + random.random() * 10,
            "load_avg_1": 0.8 + math.sin(i * 0.1) * 0.5 + random.random() * 0.3,
            "cpu_temp": 45 + math.sin(i * 0.08) * 10 + random.random() * 5,
            "wifi_rssi": -65 + math.cos(i * 0.12) * 15 + random.random() * 5,
        }
        radar.update_all(metrics)

    # Générer l'image finale
    img = radar.render()
    filename = "/tmp/classic_radar.png"
    img.save(filename)
    print(f"Image saved: {filename}")

    # Afficher les valeurs
    print("\nCurrent values:")
    for name in radar.order:
        m = radar.modules[name]
        status = "CRIT" if radar._is_crit(m) else ("WARN" if radar._is_warn(m) else "OK")
        print(f"  {name:5} ({m.label:4}): {m.value:6.1f}{m.unit:3} [{status}]")


if __name__ == "__main__":
    demo()
