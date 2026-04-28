#!/usr/bin/env python3
"""
SecuBox Eye Remote - Balance Radar Visualization
Graphique équilibré avec min/max sur axes opposés.

Chaque métrique a :
- Son point de départ (min=0) à une extrémité
- Son point max à l'extrémité opposée
- La valeur croît de min vers max le long de l'axe

    AUTH →→→→→→→→→→→→→●      AUTH part de gauche, va vers droite
    ●←←←←←←←←←←←←←←← WALL    WALL part de droite, va vers gauche

Les métriques sont appariées et équilibrées :
    AUTH <---> MIND   (axe vertical)
    WALL <---> ROOT   (axe diagonal ↘)
    BOOT <---> MESH   (axe diagonal ↗)

Cela crée un "papillon" ou "balance" visuelle.

CyberMind - https://cybermind.fr
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
class BalanceMetric:
    """Métrique pour graphique équilibré."""
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


# Paires de modules opposés
# Chaque paire partage un axe, un côté pour chaque métrique
MODULE_PAIRS = [
    # (module_gauche/haut, module_droite/bas)
    ("AUTH", "MIND"),   # Axe vertical : AUTH en haut, MIND en bas
    ("WALL", "ROOT"),   # Axe diagonal ↘ : WALL en haut-droite, ROOT en bas-gauche
    ("BOOT", "MESH"),   # Axe diagonal ↗ : BOOT en bas-droite, MESH en haut-gauche
]

BALANCE_MODULES = {
    "AUTH": BalanceMetric(
        name="AUTH", label="CPU", color=(192, 78, 36),
        min_val=0, max_val=100, warn_threshold=70, crit_threshold=85, unit="%"
    ),
    "WALL": BalanceMetric(
        name="WALL", label="MEM", color=(154, 96, 16),
        min_val=0, max_val=100, warn_threshold=75, crit_threshold=90, unit="%"
    ),
    "BOOT": BalanceMetric(
        name="BOOT", label="DISK", color=(128, 48, 24),
        min_val=0, max_val=100, warn_threshold=80, crit_threshold=95, unit="%"
    ),
    "MIND": BalanceMetric(
        name="MIND", label="LOAD", color=(61, 53, 160),
        min_val=0, max_val=8, warn_threshold=2.0, crit_threshold=4.0, unit="×"
    ),
    "ROOT": BalanceMetric(
        name="ROOT", label="TEMP", color=(10, 88, 64),
        min_val=0, max_val=100, warn_threshold=65, crit_threshold=75, unit="°C"
    ),
    "MESH": BalanceMetric(
        name="MESH", label="WIFI", color=(16, 74, 136),
        min_val=-100, max_val=0, warn_threshold=-70, crit_threshold=-80, unit="dBm"
    ),
}


@dataclass
class BalanceConfig:
    """Configuration du graphique équilibré."""
    width: int = 480
    height: int = 480
    center_x: int = 240
    center_y: int = 240
    radius: int = 180           # Rayon max (du centre au bord)

    # Bandes
    band_width: int = 20        # Largeur des barres de progression
    band_gap: int = 8           # Espace entre les bandes

    # Affichage
    show_grid: bool = True
    show_labels: bool = True
    show_values: bool = True
    show_history: bool = True

    # Couleurs
    color_background: Tuple[int, ...] = (8, 8, 8, 255)
    color_grid: Tuple[int, ...] = (40, 50, 40, 200)
    color_axis: Tuple[int, ...] = (60, 60, 70, 255)
    color_text: Tuple[int, ...] = (200, 200, 200, 255)
    color_warn: Tuple[int, ...] = (255, 180, 0, 255)
    color_crit: Tuple[int, ...] = (255, 50, 50, 255)


class BalanceRadar:
    """
    Graphique équilibré avec axes opposés.

    3 axes traversant le cercle :
    - Chaque axe a 2 métriques, une de chaque côté
    - Chaque métrique croît de son extrémité (min) vers le centre (max)
    - Visuellement, cela crée un "papillon" équilibré
    """

    def __init__(self, config: Optional[BalanceConfig] = None,
                 modules: Optional[Dict[str, BalanceMetric]] = None):
        self.config = config or BalanceConfig()
        self.modules = modules or {k: BalanceMetric(**v.__dict__)
                                   for k, v in BALANCE_MODULES.items()}
        self.pairs = MODULE_PAIRS

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

    def _normalize(self, module: BalanceMetric) -> float:
        """Normalise la valeur entre 0 et 1."""
        val = module.value
        min_v, max_v = module.min_val, module.max_val
        if max_v == min_v:
            return 0.5
        normalized = (val - min_v) / (max_v - min_v)
        return max(0, min(1, normalized))

    def _is_critical(self, module: BalanceMetric) -> bool:
        """Vérifie si critique."""
        if module.name == "MESH":
            return module.value <= module.crit_threshold
        return module.value >= module.crit_threshold

    def _is_warning(self, module: BalanceMetric) -> bool:
        """Vérifie si warning."""
        if module.name == "MESH":
            return module.value <= module.warn_threshold
        return module.value >= module.warn_threshold

    def _get_pair_angle(self, pair_index: int) -> float:
        """Retourne l'angle pour une paire d'axes."""
        # 3 paires = 60° d'écart entre chaque axe
        # Paire 0 (AUTH-MIND) = vertical = -90°
        # Paire 1 (WALL-ROOT) = -90° + 60° = -30°
        # Paire 2 (BOOT-MESH) = -90° + 120° = 30°
        base_angle = -math.pi / 2  # -90° = vertical
        return base_angle + (pair_index * math.pi / 3)  # +60° par paire

    def render(self) -> 'Image.Image':
        """Génère l'image."""
        if Image is None:
            raise ImportError("PIL/Pillow requis")

        cfg = self.config
        img = Image.new('RGBA', (cfg.width, cfg.height), cfg.color_background)
        draw = ImageDraw.Draw(img)

        # 1. Grille de fond
        if cfg.show_grid:
            self._draw_grid(draw)

        # 2. Dessiner chaque paire d'axes
        for pair_idx, (name_a, name_b) in enumerate(self.pairs):
            self._draw_pair(draw, pair_idx, name_a, name_b)

        # 3. Centre
        self._draw_center(draw)

        return img

    def _draw_grid(self, draw: 'ImageDraw.Draw'):
        """Dessine les cercles de grille."""
        cfg = self.config

        # Cercles concentriques
        for pct in [25, 50, 75, 100]:
            r = cfg.radius * pct / 100
            draw.ellipse(
                [cfg.center_x - r, cfg.center_y - r,
                 cfg.center_x + r, cfg.center_y + r],
                outline=cfg.color_grid, width=1
            )

    def _draw_pair(self, draw: 'ImageDraw.Draw', pair_idx: int,
                   name_a: str, name_b: str):
        """Dessine une paire de métriques sur un axe."""
        cfg = self.config
        angle = self._get_pair_angle(pair_idx)

        module_a = self.modules[name_a]
        module_b = self.modules[name_b]

        norm_a = self._normalize(module_a)
        norm_b = self._normalize(module_b)

        # Décalage pour ne pas superposer les bandes
        offset = (pair_idx - 1) * (cfg.band_width + cfg.band_gap)

        # Vecteur perpendiculaire pour le décalage
        perp_angle = angle + math.pi / 2
        offset_x = offset * math.cos(perp_angle)
        offset_y = offset * math.sin(perp_angle)

        cx = cfg.center_x + offset_x
        cy = cfg.center_y + offset_y

        # ===== Module A : du bord vers le centre (son côté) =====
        # Point de départ A = bord dans la direction de l'angle
        start_a_x = cx + cfg.radius * math.cos(angle)
        start_a_y = cy + cfg.radius * math.sin(angle)

        # Point d'arrivée A = vers le centre, distance = norm_a * radius
        # (A croît vers le centre)
        length_a = cfg.radius * norm_a
        end_a_x = cx + (cfg.radius - length_a) * math.cos(angle)
        end_a_y = cy + (cfg.radius - length_a) * math.sin(angle)

        # Couleur A
        if self._is_critical(module_a):
            color_a = cfg.color_crit
        elif self._is_warning(module_a):
            color_a = cfg.color_warn
        else:
            color_a = (*module_a.color, 255)

        # Dessiner la barre A (du bord vers le centre)
        self._draw_bar(draw, start_a_x, start_a_y, end_a_x, end_a_y,
                       cfg.band_width, color_a)

        # ===== Module B : du bord opposé vers le centre =====
        # Point de départ B = bord dans la direction opposée
        start_b_x = cx - cfg.radius * math.cos(angle)
        start_b_y = cy - cfg.radius * math.sin(angle)

        # Point d'arrivée B
        length_b = cfg.radius * norm_b
        end_b_x = cx - (cfg.radius - length_b) * math.cos(angle)
        end_b_y = cy - (cfg.radius - length_b) * math.sin(angle)

        # Couleur B
        if self._is_critical(module_b):
            color_b = cfg.color_crit
        elif self._is_warning(module_b):
            color_b = cfg.color_warn
        else:
            color_b = (*module_b.color, 255)

        # Dessiner la barre B
        self._draw_bar(draw, start_b_x, start_b_y, end_b_x, end_b_y,
                       cfg.band_width, color_b)

        # ===== Labels =====
        if cfg.show_labels:
            self._draw_pair_labels(draw, angle, cx, cy, module_a, module_b)

    def _draw_bar(self, draw: 'ImageDraw.Draw',
                  x1: float, y1: float, x2: float, y2: float,
                  width: int, color: Tuple[int, ...]):
        """Dessine une barre de progression."""
        # Dessiner comme une ligne épaisse avec bouts arrondis
        draw.line([(x1, y1), (x2, y2)], fill=color, width=width)

        # Points aux extrémités
        r = width // 2
        draw.ellipse([x2 - r, y2 - r, x2 + r, y2 + r], fill=color)

    def _draw_pair_labels(self, draw: 'ImageDraw.Draw', angle: float,
                          cx: float, cy: float,
                          module_a: BalanceMetric, module_b: BalanceMetric):
        """Dessine les labels d'une paire."""
        cfg = self.config
        font = self._get_font(11)
        font_small = self._get_font(9)

        label_offset = cfg.radius + 25

        # Label A (côté positif de l'angle)
        ax = cx + label_offset * math.cos(angle)
        ay = cy + label_offset * math.sin(angle)
        self._draw_module_label(draw, ax, ay, module_a, font, font_small)

        # Label B (côté négatif de l'angle)
        bx = cx - label_offset * math.cos(angle)
        by = cy - label_offset * math.sin(angle)
        self._draw_module_label(draw, bx, by, module_b, font, font_small)

    def _draw_module_label(self, draw: 'ImageDraw.Draw',
                           x: float, y: float, module: BalanceMetric,
                           font, font_small):
        """Dessine le label et la valeur d'un module."""
        cfg = self.config

        # Nom
        label = module.name
        if font:
            bbox = draw.textbbox((0, 0), label, font=font)
            tw = bbox[2] - bbox[0]
            th = bbox[3] - bbox[1]
        else:
            tw, th = len(label) * 7, 11

        draw.text((x - tw / 2, y - th / 2), label,
                  fill=(*module.color, 255), font=font)

        # Valeur
        if cfg.show_values:
            if module.name == "MIND":
                val = f"{module.value:.1f}{module.unit}"
            elif module.name == "MESH":
                val = f"{int(module.value)}{module.unit}"
            else:
                val = f"{int(module.value)}{module.unit}"

            if font_small:
                bbox = draw.textbbox((0, 0), val, font=font_small)
                vw = bbox[2] - bbox[0]
            else:
                vw = len(val) * 6

            draw.text((x - vw / 2, y + th / 2 + 2), val,
                      fill=cfg.color_text, font=font_small)

    def _draw_center(self, draw: 'ImageDraw.Draw'):
        """Dessine le centre."""
        cfg = self.config
        r = 15

        # État global
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
    """Démonstration."""
    import random

    print("SecuBox Balance Radar Demo")

    radar = BalanceRadar()

    # Simuler des métriques
    for _ in range(5):
        metrics = {
            "cpu_percent": 20 + random.random() * 60,
            "mem_percent": 30 + random.random() * 50,
            "disk_percent": 40 + random.random() * 30,
            "load_avg_1": 0.5 + random.random() * 3,
            "cpu_temp": 40 + random.random() * 30,
            "wifi_rssi": -90 + random.random() * 50,
        }
        radar.update_all(metrics)

    img = radar.render()
    filename = "/tmp/balance_radar.png"
    img.save(filename)
    print(f"Saved: {filename}")


if __name__ == "__main__":
    demo()
