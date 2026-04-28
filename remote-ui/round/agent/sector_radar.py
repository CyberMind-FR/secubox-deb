#!/usr/bin/env python3
"""
SecuBox Eye Remote - Sector Radar Visualization
Radar avec secteurs angulaires pour chaque module/métrique.

Chaque module a son propre secteur angulaire (60° pour 6 modules).
La valeur de la métrique est représentée par la longueur du rayon
partant du centre (0) vers le bord (100%).

   AUTH (CPU)
      ╲     ╱
       ╲   ╱
   MESH ╲ ╱ WALL
    ────•────
   ROOT ╱ ╲ BOOT
       ╱   ╲
      ╱     ╲
   MIND (LOAD)

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = None
    ImageDraw = None


@dataclass
class ModuleMetric:
    """Métrique d'un module avec historique."""
    name: str
    label: str
    color: Tuple[int, int, int]
    value: float = 0.0
    warn_threshold: float = 70.0
    crit_threshold: float = 85.0
    unit: str = "%"
    history: deque = field(default_factory=lambda: deque(maxlen=60))


# Configuration des 6 modules SecuBox
MODULES = {
    "AUTH": ModuleMetric(
        name="AUTH", label="CPU", color=(192, 78, 36),      # #C04E24
        warn_threshold=70, crit_threshold=85, unit="%"
    ),
    "WALL": ModuleMetric(
        name="WALL", label="MEM", color=(154, 96, 16),      # #9A6010
        warn_threshold=75, crit_threshold=90, unit="%"
    ),
    "BOOT": ModuleMetric(
        name="BOOT", label="DISK", color=(128, 48, 24),     # #803018
        warn_threshold=80, crit_threshold=95, unit="%"
    ),
    "MIND": ModuleMetric(
        name="MIND", label="LOAD", color=(61, 53, 160),     # #3D35A0
        warn_threshold=2.0, crit_threshold=4.0, unit="×"
    ),
    "ROOT": ModuleMetric(
        name="ROOT", label="TEMP", color=(10, 88, 64),      # #0A5840
        warn_threshold=65, crit_threshold=75, unit="°C"
    ),
    "MESH": ModuleMetric(
        name="MESH", label="WIFI", color=(16, 74, 136),     # #104A88
        warn_threshold=-70, crit_threshold=-80, unit="dBm"
    ),
}


@dataclass
class SectorRadarConfig:
    """Configuration du radar sectoriel."""
    # Dimensions
    width: int = 480
    height: int = 480
    center_x: int = 240
    center_y: int = 240
    radius: int = 180
    inner_radius: int = 40      # Rayon du cercle central

    # Secteurs
    num_sectors: int = 6
    sector_gap: float = 0.05    # Écart entre secteurs en radians
    start_angle: float = -math.pi / 2  # Commencer en haut (AUTH)

    # Affichage
    show_grid: bool = True
    show_labels: bool = True
    show_values: bool = True
    show_history: bool = True    # Trace historique
    history_opacity: float = 0.3

    # Couleurs
    color_background: Tuple[int, ...] = (8, 8, 8, 255)
    color_grid: Tuple[int, ...] = (40, 40, 50, 255)
    color_text: Tuple[int, ...] = (200, 200, 200, 255)
    color_warn: Tuple[int, ...] = (255, 180, 0, 255)
    color_crit: Tuple[int, ...] = (255, 50, 50, 255)


class SectorRadar:
    """
    Radar sectoriel avec un secteur par module.

    Chaque secteur affiche :
    - Une barre radiale colorée (0 au centre → 100% au bord)
    - L'historique en trace estompée
    - Le label du module
    - La valeur actuelle
    """

    def __init__(self, config: Optional[SectorRadarConfig] = None,
                 modules: Optional[Dict[str, ModuleMetric]] = None):
        self.config = config or SectorRadarConfig()
        self.modules = modules or MODULES.copy()
        self._font = None

    def _get_font(self, size: int = 14):
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

    def update_metric(self, module_name: str, value: float):
        """Met à jour la valeur d'un module."""
        if module_name in self.modules:
            module = self.modules[module_name]
            module.value = value
            module.history.append(value)

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
        for key, module_name in mapping.items():
            if key in metrics and module_name in self.modules:
                self.update_metric(module_name, metrics[key])

    def _normalize_value(self, module: ModuleMetric) -> float:
        """Normalise la valeur entre 0 et 1."""
        value = module.value

        # Cas spéciaux
        if module.name == "MIND":  # Load avg (0-8)
            return min(1.0, value / 8.0)
        elif module.name == "ROOT":  # Temp (0-100°C)
            return min(1.0, max(0, value / 100.0))
        elif module.name == "MESH":  # RSSI (-100 à 0 dBm)
            # -100 dBm = 0%, 0 dBm = 100%
            return min(1.0, max(0, (value + 100) / 100.0))
        else:
            # Pourcentage standard
            return min(1.0, max(0, value / 100.0))

    def _get_level_color(self, module: ModuleMetric) -> Tuple[int, ...]:
        """Retourne la couleur selon le niveau d'alerte."""
        value = module.value

        # Inverser pour MESH (plus bas = pire)
        if module.name == "MESH":
            if value <= module.crit_threshold:
                return self.config.color_crit
            elif value <= module.warn_threshold:
                return self.config.color_warn
        else:
            if value >= module.crit_threshold:
                return self.config.color_crit
            elif value >= module.warn_threshold:
                return self.config.color_warn

        return module.color + (255,)

    def _angle_to_xy(self, angle: float, radius: float) -> Tuple[int, int]:
        """Convertit angle + rayon en coordonnées."""
        x = self.config.center_x + radius * math.cos(angle)
        y = self.config.center_y + radius * math.sin(angle)
        return int(x), int(y)

    def render(self) -> 'Image.Image':
        """Génère l'image du radar sectoriel."""
        if Image is None:
            raise ImportError("PIL/Pillow requis")

        cfg = self.config
        img = Image.new('RGBA', (cfg.width, cfg.height), cfg.color_background)
        draw = ImageDraw.Draw(img)

        # 1. Grille de fond
        if cfg.show_grid:
            self._draw_grid(draw)

        # 2. Dessiner chaque secteur
        module_list = list(self.modules.values())
        sector_angle = (2 * math.pi - cfg.num_sectors * cfg.sector_gap) / cfg.num_sectors

        for i, module in enumerate(module_list):
            start = cfg.start_angle + i * (sector_angle + cfg.sector_gap)
            end = start + sector_angle

            # Historique (trace estompée)
            if cfg.show_history and len(module.history) > 1:
                self._draw_history(draw, module, start, end)

            # Barre de valeur actuelle
            self._draw_sector_bar(draw, module, start, end)

            # Label et valeur
            if cfg.show_labels:
                self._draw_label(draw, module, start, end)

        # 3. Cercle central
        self._draw_center(draw)

        return img

    def _draw_grid(self, draw: 'ImageDraw.Draw'):
        """Dessine la grille de fond."""
        cfg = self.config
        color = cfg.color_grid

        # Cercles concentriques (25%, 50%, 75%, 100%)
        for pct in [25, 50, 75, 100]:
            r = cfg.inner_radius + (cfg.radius - cfg.inner_radius) * pct / 100
            draw.ellipse(
                [cfg.center_x - r, cfg.center_y - r,
                 cfg.center_x + r, cfg.center_y + r],
                outline=color, width=1
            )

        # Lignes de séparation des secteurs
        sector_angle = 2 * math.pi / cfg.num_sectors
        for i in range(cfg.num_sectors):
            angle = cfg.start_angle + i * sector_angle
            x1, y1 = self._angle_to_xy(angle, cfg.inner_radius)
            x2, y2 = self._angle_to_xy(angle, cfg.radius)
            draw.line([(x1, y1), (x2, y2)], fill=color, width=1)

    def _draw_sector_bar(self, draw: 'ImageDraw.Draw', module: ModuleMetric,
                          start_angle: float, end_angle: float):
        """Dessine la barre de valeur d'un secteur."""
        cfg = self.config
        normalized = self._normalize_value(module)
        color = self._get_level_color(module)

        # Rayon de la barre (de inner_radius à radius selon la valeur)
        bar_radius = cfg.inner_radius + (cfg.radius - cfg.inner_radius) * normalized

        # Dessiner un arc rempli (pieslice)
        bbox = [
            cfg.center_x - bar_radius, cfg.center_y - bar_radius,
            cfg.center_x + bar_radius, cfg.center_y + bar_radius
        ]
        # Convertir radians en degrés (PIL utilise des degrés)
        start_deg = math.degrees(start_angle)
        end_deg = math.degrees(end_angle)
        draw.pieslice(bbox, start_deg, end_deg, fill=color, outline=color)

        # Découper le cercle intérieur (remplir en noir)
        inner_bbox = [
            cfg.center_x - cfg.inner_radius, cfg.center_y - cfg.inner_radius,
            cfg.center_x + cfg.inner_radius, cfg.center_y + cfg.inner_radius
        ]
        draw.ellipse(inner_bbox, fill=cfg.color_background)

    def _draw_history(self, draw: 'ImageDraw.Draw', module: ModuleMetric,
                      start_angle: float, end_angle: float):
        """Dessine la trace historique du module."""
        cfg = self.config
        history = list(module.history)
        if len(history) < 2:
            return

        # Couleur estompée
        base_color = module.color
        alpha = int(255 * cfg.history_opacity)
        color = (*base_color, alpha)

        # Dessiner des arcs pour chaque point historique
        mid_angle = (start_angle + end_angle) / 2

        for i, value in enumerate(history):
            # Opacité décroissante avec l'âge
            age_factor = (i / len(history)) * cfg.history_opacity
            point_alpha = int(255 * age_factor)
            point_color = (*base_color, point_alpha)

            # Normaliser la valeur historique
            if module.name == "MIND":
                norm = min(1.0, value / 8.0)
            elif module.name == "ROOT":
                norm = min(1.0, max(0, value / 100.0))
            elif module.name == "MESH":
                norm = min(1.0, max(0, (value + 100) / 100.0))
            else:
                norm = min(1.0, max(0, value / 100.0))

            # Position du point
            r = cfg.inner_radius + (cfg.radius - cfg.inner_radius) * norm
            x, y = self._angle_to_xy(mid_angle, r)

            # Petit point
            size = 2
            draw.ellipse([x - size, y - size, x + size, y + size], fill=point_color)

    def _draw_label(self, draw: 'ImageDraw.Draw', module: ModuleMetric,
                    start_angle: float, end_angle: float):
        """Dessine le label et la valeur du module."""
        cfg = self.config
        font = self._get_font(12)
        font_small = self._get_font(10)

        mid_angle = (start_angle + end_angle) / 2

        # Position du label (au-delà du rayon)
        label_radius = cfg.radius + 25
        x, y = self._angle_to_xy(mid_angle, label_radius)

        # Nom du module
        label = module.name
        if font:
            bbox = draw.textbbox((0, 0), label, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
        else:
            text_width, text_height = len(label) * 7, 12

        draw.text((x - text_width // 2, y - text_height // 2),
                  label, fill=module.color + (255,), font=font)

        # Valeur (sous le label)
        if cfg.show_values:
            if module.name == "MIND":
                value_text = f"{module.value:.1f}{module.unit}"
            elif module.name == "MESH":
                value_text = f"{int(module.value)}{module.unit}"
            else:
                value_text = f"{int(module.value)}{module.unit}"

            y_val = y + text_height + 2
            if font_small:
                bbox = draw.textbbox((0, 0), value_text, font=font_small)
                val_width = bbox[2] - bbox[0]
            else:
                val_width = len(value_text) * 6

            draw.text((x - val_width // 2, y_val),
                      value_text, fill=cfg.color_text, font=font_small)

    def _draw_center(self, draw: 'ImageDraw.Draw'):
        """Dessine le cercle central avec état global."""
        cfg = self.config
        r = cfg.inner_radius - 5

        # Couleur selon l'état global
        any_crit = any(
            (m.name != "MESH" and m.value >= m.crit_threshold) or
            (m.name == "MESH" and m.value <= m.crit_threshold)
            for m in self.modules.values()
        )
        any_warn = any(
            (m.name != "MESH" and m.value >= m.warn_threshold) or
            (m.name == "MESH" and m.value <= m.warn_threshold)
            for m in self.modules.values()
        )

        if any_crit:
            center_color = cfg.color_crit
        elif any_warn:
            center_color = cfg.color_warn
        else:
            center_color = (0, 200, 50, 255)  # Vert nominal

        draw.ellipse(
            [cfg.center_x - r, cfg.center_y - r,
             cfg.center_x + r, cfg.center_y + r],
            fill=center_color,
            outline=cfg.color_grid
        )


# =============================================================================
# Demo
# =============================================================================

def demo():
    """Démonstration du radar sectoriel."""
    import random

    print("SecuBox Sector Radar Demo")

    radar = SectorRadar()

    # Simuler des métriques
    for frame in range(10):
        metrics = {
            "cpu_percent": 20 + random.random() * 60,
            "mem_percent": 30 + random.random() * 50,
            "disk_percent": 40 + random.random() * 30,
            "load_avg_1": 0.5 + random.random() * 2,
            "cpu_temp": 40 + random.random() * 25,
            "wifi_rssi": -80 + random.random() * 40,
        }
        radar.update_all(metrics)

    img = radar.render()
    filename = "/tmp/sector_radar.png"
    img.save(filename)
    print(f"Saved: {filename}")


if __name__ == "__main__":
    demo()
