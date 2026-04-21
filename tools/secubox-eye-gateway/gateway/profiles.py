"""
SecuBox Eye Gateway — Emulation profiles with realistic drift.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Tuple
import random
import time


# Emulation profiles with ranges: (min, max, drift_rate)
# drift_rate is the maximum change per update cycle
PROFILES: Dict[str, Dict[str, Tuple[float, float, float]]] = {
    "idle": {
        "cpu": (1.0, 8.0, 0.5),
        "mem": (15.0, 25.0, 0.3),
        "disk": (20.0, 30.0, 0.01),
        "temp": (35.0, 42.0, 0.2),
        "load": (0.01, 0.15, 0.02),
        "wifi": (-45, -35, 1.0),
        "alerts": (0, 1, 0.1),
    },
    "normal": {
        "cpu": (15.0, 40.0, 2.0),
        "mem": (35.0, 55.0, 1.0),
        "disk": (30.0, 50.0, 0.02),
        "temp": (42.0, 52.0, 0.5),
        "load": (0.3, 0.8, 0.05),
        "wifi": (-55, -40, 2.0),
        "alerts": (0, 3, 0.2),
    },
    "busy": {
        "cpu": (50.0, 85.0, 3.0),
        "mem": (60.0, 80.0, 1.5),
        "disk": (50.0, 70.0, 0.05),
        "temp": (55.0, 68.0, 1.0),
        "load": (1.0, 2.5, 0.1),
        "wifi": (-60, -45, 3.0),
        "alerts": (1, 5, 0.3),
    },
    "stressed": {
        "cpu": (85.0, 99.0, 2.0),
        "mem": (80.0, 95.0, 1.0),
        "disk": (70.0, 90.0, 0.1),
        "temp": (68.0, 82.0, 1.5),
        "load": (3.0, 6.0, 0.2),
        "wifi": (-70, -55, 4.0),
        "alerts": (3, 10, 0.5),
    },
}


@dataclass
class EmulatedMetrics:
    """Emulated system metrics with realistic drift behavior."""

    profile: str
    cpu: float = field(default=0.0)
    mem: float = field(default=0.0)
    disk: float = field(default=0.0)
    temp: float = field(default=0.0)
    load: float = field(default=0.0)
    wifi: int = field(default=-50)
    alerts: int = field(default=0)
    _last_update: float = field(default_factory=time.time, repr=False)

    def __post_init__(self) -> None:
        """Initialize with values from the center of profile ranges."""
        if self.profile not in PROFILES:
            raise ValueError(f"Unknown profile: {self.profile}")
        self._initialize_from_profile()

    def _initialize_from_profile(self) -> None:
        """Set initial values from profile center points."""
        profile_data = PROFILES[self.profile]
        for metric, (min_val, max_val, _) in profile_data.items():
            center = (min_val + max_val) / 2
            # Add small random offset
            offset = random.uniform(-0.1, 0.1) * (max_val - min_val)
            value = center + offset
            if metric == "wifi":
                setattr(self, metric, int(value))
            elif metric == "alerts":
                setattr(self, metric, max(0, int(value)))
            else:
                setattr(self, metric, round(value, 1))

    def _drift(self, current: float, min_val: float, max_val: float, drift_rate: float) -> float:
        """Apply realistic drift to a metric value.

        The drift tends toward the center of the range with occasional
        larger movements, simulating real system behavior.
        """
        center = (min_val + max_val) / 2
        distance_from_center = current - center
        range_size = max_val - min_val

        # Tendency to drift back toward center (homeostasis)
        center_pull = -distance_from_center * 0.1

        # Random walk component
        random_drift = random.gauss(0, drift_rate * 0.5)

        # Occasional larger jumps (simulating process starts/stops)
        if random.random() < 0.05:
            random_drift *= 3

        # Apply drift
        new_value = current + center_pull + random_drift

        # Clamp to range
        return max(min_val, min(max_val, new_value))

    def update(self) -> "EmulatedMetrics":
        """Update all metrics with realistic drift.

        Returns self for chaining.
        """
        profile_data = PROFILES[self.profile]
        now = time.time()
        elapsed = now - self._last_update

        # Scale drift by time elapsed (for consistent behavior)
        time_factor = min(elapsed, 5.0)  # Cap at 5 seconds

        for metric, (min_val, max_val, drift_rate) in profile_data.items():
            current = getattr(self, metric)
            scaled_drift = drift_rate * time_factor

            if metric == "wifi":
                new_val = self._drift(float(current), min_val, max_val, scaled_drift)
                setattr(self, metric, int(new_val))
            elif metric == "alerts":
                # Alerts change less frequently
                if random.random() < 0.1 * time_factor:
                    new_val = self._drift(float(current), min_val, max_val, scaled_drift)
                    setattr(self, metric, max(0, int(new_val)))
            else:
                new_val = self._drift(current, min_val, max_val, scaled_drift)
                setattr(self, metric, round(new_val, 1))

        self._last_update = now
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary format."""
        return {
            "cpu_percent": self.cpu,
            "memory_percent": self.mem,
            "disk_percent": self.disk,
            "temperature": self.temp,
            "load_avg": self.load,
            "wifi_signal": self.wifi,
            "active_alerts": self.alerts,
            "profile": self.profile,
            "timestamp": time.time(),
        }
