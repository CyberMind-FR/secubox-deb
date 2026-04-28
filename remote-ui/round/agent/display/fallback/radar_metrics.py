#!/usr/bin/env python3
"""
Run Radar Metrics display on HyperPixel 2.1 Round.
Displays rotating radar with simulated metrics.
"""
import sys
sys.path.insert(0, '/home/pi/agent')

import time
import math
import random

try:
    from radar_metrics import RadarMetrics, MetricLevel, RadarConfig
except ImportError:
    # Inline minimal version if module not found
    from PIL import Image, ImageDraw
    from collections import deque
    from dataclasses import dataclass
    from typing import Tuple, List
    from enum import Enum

    class MetricLevel(Enum):
        NOMINAL = "nominal"
        WARN = "warn"
        CRITICAL = "critical"

    @dataclass
    class RadarConfig:
        width: int = 480
        height: int = 480
        center_x: int = 240
        center_y: int = 240
        radius: int = 200
        rotation_speed: float = 2.0
        trace_decay: float = 0.85
        trace_samples: int = 360

    class RadarMetrics:
        def __init__(self, config=None):
            self.config = config or RadarConfig()
            self._start_time = time.time()
            self._trace_buffer = [0.0] * self.config.trace_samples

        @property
        def current_angle(self):
            elapsed = time.time() - self._start_time
            rotations = elapsed * (self.config.rotation_speed / 60.0)
            return (rotations * 2 * math.pi) % (2 * math.pi)

        def add_sample(self, value, level=MetricLevel.NOMINAL):
            angle = self.current_angle
            angle_index = int((angle / (2 * math.pi)) * self.config.trace_samples)
            angle_index = angle_index % self.config.trace_samples
            self._trace_buffer[angle_index] = min(100, max(0, value))

        def _decay_trace(self):
            for i in range(len(self._trace_buffer)):
                self._trace_buffer[i] *= self.config.trace_decay

        def render(self):
            self._decay_trace()
            cfg = self.config
            img = Image.new('RGBA', (cfg.width, cfg.height), (8, 8, 8, 255))
            draw = ImageDraw.Draw(img)

            # Grid circles
            for level in [25, 50, 75, 100]:
                r = int(cfg.radius * level / 100)
                draw.ellipse([cfg.center_x - r, cfg.center_y - r,
                             cfg.center_x + r, cfg.center_y + r],
                            outline=(30, 60, 30), width=1)

            # Radial lines
            for angle_deg in range(0, 360, 30):
                angle = math.radians(angle_deg)
                x2 = cfg.center_x + cfg.radius * math.sin(angle)
                y2 = cfg.center_y - cfg.radius * math.cos(angle)
                draw.line([(cfg.center_x, cfg.center_y), (x2, y2)],
                         fill=(30, 60, 30), width=1)

            # Trace
            for i in range(cfg.trace_samples):
                angle = (i / cfg.trace_samples) * 2 * math.pi
                value = self._trace_buffer[i]
                if value > 5:
                    r = cfg.radius * (value / 100.0)
                    x = cfg.center_x + r * math.sin(angle)
                    y = cfg.center_y - r * math.cos(angle)
                    alpha = int(180 * (value / 100.0))
                    draw.ellipse([x-2, y-2, x+2, y+2],
                                fill=(0, 200, 50, alpha))

            # Sweep line
            angle = self.current_angle
            for i in range(20):
                offset = -0.15 * (i / 20)
                a = angle + offset
                alpha = int(200 * (1 - i / 20))
                x2 = cfg.center_x + cfg.radius * math.sin(a)
                y2 = cfg.center_y - cfg.radius * math.cos(a)
                draw.line([(cfg.center_x, cfg.center_y), (x2, y2)],
                         fill=(0, 255, 65, alpha), width=2)

            # Main sweep
            x2 = cfg.center_x + cfg.radius * math.sin(angle)
            y2 = cfg.center_y - cfg.radius * math.cos(angle)
            draw.line([(cfg.center_x, cfg.center_y), (x2, y2)],
                     fill=(0, 255, 65), width=3)

            # Center dot
            draw.ellipse([cfg.center_x - 8, cfg.center_y - 8,
                         cfg.center_x + 8, cfg.center_y + 8],
                        fill=(0, 255, 65))

            # Title
            draw.text((10, 10), "SECUBOX RADAR", fill=(0, 200, 100))
            draw.text((10, 30), "Metrics Monitor", fill=(100, 100, 120))

            return img


def main():
    print("SecuBox Radar Metrics - Live Display")
    radar = RadarMetrics()

    frame = 0
    try:
        while True:
            # Simulate metrics
            cpu = 30 + math.sin(frame * 0.05) * 20 + random.random() * 10
            level = MetricLevel.NOMINAL
            if cpu > 70:
                level = MetricLevel.WARN
            if cpu > 85:
                level = MetricLevel.CRITICAL

            radar.add_sample(cpu, level)

            # Render to framebuffer
            img = radar.render()
            rgba = img.convert('RGBA')
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgba.tobytes('raw', 'BGRA'))

            frame += 1
            time.sleep(0.05)  # 20 FPS

    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    main()
