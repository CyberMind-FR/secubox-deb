"""
SecuBox-Deb :: core.metrics — Collecte métriques système légère (sans psutil)
=============================================================================
Optimisé pour RPi Zero W armhf — lecture directe /proc sans dépendances lourdes.
Cache TTL 1s pour /proc/stat afin d'éviter les lectures répétées.

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict, Any, List

from secubox_core.logger import get_logger
from secubox_core.config import get_config

log = get_logger("metrics")


class _ProcStatCache:
    """
    Cache pour /proc/stat avec TTL.
    Évite les lectures multiples lors de bursts de requêtes.
    """
    def __init__(self, ttl_seconds: float = 1.0):
        self._ttl = ttl_seconds
        self._timestamp: float = 0.0
        self._data: Dict[str, int] = {}
        self._prev_data: Dict[str, int] = {}

    def _parse_cpu_line(self, line: str) -> Dict[str, int]:
        """Parse la ligne 'cpu ...' de /proc/stat."""
        parts = line.split()
        if len(parts) < 8:
            return {}
        return {
            "user": int(parts[1]),
            "nice": int(parts[2]),
            "system": int(parts[3]),
            "idle": int(parts[4]),
            "iowait": int(parts[5]) if len(parts) > 5 else 0,
            "irq": int(parts[6]) if len(parts) > 6 else 0,
            "softirq": int(parts[7]) if len(parts) > 7 else 0,
        }

    def read(self) -> Dict[str, int]:
        """Lit /proc/stat avec cache TTL."""
        now = time.monotonic()
        if now - self._timestamp < self._ttl and self._data:
            return self._data

        self._prev_data = self._data.copy()
        try:
            with open("/proc/stat", "r") as f:
                for line in f:
                    if line.startswith("cpu "):
                        self._data = self._parse_cpu_line(line)
                        break
        except FileNotFoundError:
            log.warning("/proc/stat non trouvé")
            self._data = {}

        self._timestamp = now
        return self._data

    def get_previous(self) -> Dict[str, int]:
        """Retourne les valeurs précédentes pour calcul delta."""
        return self._prev_data


# Cache global pour /proc/stat
_stat_cache = _ProcStatCache(ttl_seconds=1.0)


class SystemMetrics:
    """
    Collecteur de métriques système pour dashboard HyperPixel.
    Toutes les méthodes sont async pour compatibilité FastAPI.
    Aucune dépendance externe (stdlib uniquement).
    """

    @staticmethod
    async def cpu_percent(sample_ms: int = 200) -> float:
        """
        Calcule le pourcentage CPU via delta /proc/stat.
        Attend `sample_ms` millisecondes entre deux lectures.

        Retourne: usage CPU en % (0.0-100.0)
        """
        # Première lecture
        stat1 = _stat_cache.read()
        if not stat1:
            return 0.0

        # Attente pour le delta
        await asyncio.sleep(sample_ms / 1000.0)

        # Deuxième lecture (force refresh en vidant le cache)
        _stat_cache._timestamp = 0  # Force refresh
        stat2 = _stat_cache.read()
        if not stat2:
            return 0.0

        # Calcul du delta
        def total(s: Dict[str, int]) -> int:
            return sum(s.values())

        def idle(s: Dict[str, int]) -> int:
            return s.get("idle", 0) + s.get("iowait", 0)

        total_delta = total(stat2) - total(stat1)
        idle_delta = idle(stat2) - idle(stat1)

        if total_delta <= 0:
            return 0.0

        usage = ((total_delta - idle_delta) / total_delta) * 100.0
        return round(max(0.0, min(100.0, usage)), 1)

    @staticmethod
    async def mem_percent() -> float:
        """
        Calcule le pourcentage mémoire via /proc/meminfo.
        Formule: (MemTotal - MemAvailable) / MemTotal * 100

        Retourne: usage RAM en % (0.0-100.0)
        """
        try:
            meminfo: Dict[str, int] = {}
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].rstrip(":")
                        value = int(parts[1])  # en kB
                        meminfo[key] = value

            total = meminfo.get("MemTotal", 0)
            available = meminfo.get("MemAvailable", 0)

            if total <= 0:
                return 0.0

            used = total - available
            percent = (used / total) * 100.0
            return round(max(0.0, min(100.0, percent)), 1)

        except (FileNotFoundError, ValueError, KeyError) as e:
            log.warning("Erreur lecture /proc/meminfo: %s", e)
            return 0.0

    @staticmethod
    async def disk_percent(path: str = "/") -> float:
        """
        Calcule le pourcentage disque via os.statvfs.

        Args:
            path: Point de montage à analyser

        Retourne: usage disque en % (0.0-100.0)
        """
        try:
            st = os.statvfs(path)
            if st.f_blocks <= 0:
                return 0.0

            used = st.f_blocks - st.f_bfree
            percent = (used / st.f_blocks) * 100.0
            return round(max(0.0, min(100.0, percent)), 1)

        except OSError as e:
            log.warning("Erreur statvfs %s: %s", path, e)
            return 0.0

    @staticmethod
    async def wifi_rssi() -> int:
        """
        Récupère le signal WiFi en dBm via /proc/net/wireless.
        Fallback: iwconfig si /proc/net/wireless absent.

        Retourne: RSSI en dBm (négatif), 0 si filaire ou erreur
        """
        # Méthode 1: /proc/net/wireless
        try:
            with open("/proc/net/wireless", "r") as f:
                for line in f:
                    # Format: iface | status | link | level | noise | ...
                    if "wlan" in line or "wlp" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            # La 3e colonne est le level (signal)
                            level = parts[3].rstrip(".")
                            rssi = int(float(level))
                            # Normaliser en dBm si nécessaire
                            if rssi > 0:
                                rssi = rssi - 256  # Conversion unsigned → signed
                            return rssi
        except FileNotFoundError:
            pass
        except (ValueError, IndexError) as e:
            log.debug("Parse /proc/net/wireless: %s", e)

        # Méthode 2: iwconfig fallback
        try:
            result = subprocess.run(
                ["iwconfig"],
                capture_output=True, text=True, timeout=2
            )
            match = re.search(r"Signal level[=:](-?\d+)\s*dBm", result.stdout)
            if match:
                return int(match.group(1))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return 0  # Filaire ou WiFi non détecté

    @staticmethod
    async def load_avg_1() -> float:
        """
        Retourne le load average 1 minute via os.getloadavg().

        Retourne: load average (float)
        """
        try:
            return round(os.getloadavg()[0], 2)
        except OSError:
            return 0.0

    @staticmethod
    async def cpu_temp() -> float:
        """
        Lit la température CPU en °C.
        Source 1: /sys/class/thermal/thermal_zone0/temp (÷1000)
        Fallback: vcgencmd measure_temp (RPi)

        Retourne: température en °C (float)
        """
        # Méthode 1: sysfs thermal zone
        thermal_path = Path("/sys/class/thermal/thermal_zone0/temp")
        try:
            if thermal_path.exists():
                temp_millic = int(thermal_path.read_text().strip())
                return round(temp_millic / 1000.0, 1)
        except (ValueError, PermissionError) as e:
            log.debug("Lecture thermal_zone0: %s", e)

        # Méthode 2: vcgencmd (Raspberry Pi)
        try:
            result = subprocess.run(
                ["vcgencmd", "measure_temp"],
                capture_output=True, text=True, timeout=2
            )
            match = re.search(r"temp=([\d.]+)", result.stdout)
            if match:
                return round(float(match.group(1)), 1)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return 0.0  # Température non disponible

    @staticmethod
    async def uptime_seconds() -> int:
        """
        Lit l'uptime système via /proc/uptime.

        Retourne: uptime en secondes (int)
        """
        try:
            with open("/proc/uptime", "r") as f:
                uptime_str = f.read().split()[0]
                return int(float(uptime_str))
        except (FileNotFoundError, ValueError, IndexError):
            return 0

    @staticmethod
    async def hostname() -> str:
        """
        Retourne le hostname via socket.gethostname().

        Retourne: hostname (str)
        """
        return socket.gethostname()

    @staticmethod
    async def secubox_version() -> str:
        """
        Lit la version SecuBox depuis /etc/secubox/secubox.conf [meta] version.

        Retourne: version string ou "unknown"
        """
        try:
            cfg = get_config("meta")
            return cfg.get("version", "2.0.0")
        except Exception:
            # Fallback: lecture directe du fichier TOML
            conf_path = Path("/etc/secubox/secubox.conf")
            if conf_path.exists():
                try:
                    import tomllib  # Python 3.11+
                    data = tomllib.loads(conf_path.read_text())
                    return data.get("meta", {}).get("version", "2.0.0")
                except ImportError:
                    # Python < 3.11: regex fallback
                    content = conf_path.read_text()
                    match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
                    if match:
                        return match.group(1)
            return "unknown"

    @staticmethod
    async def modules_active() -> List[str]:
        """
        Liste les modules SecuBox actifs (services systemd running).
        Modules: AUTH, WALL, BOOT, MIND, ROOT, MESH

        Retourne: liste des modules actifs
        """
        module_services = {
            "AUTH": "secubox-auth",
            "WALL": "secubox-crowdsec",  # ou secubox-waf
            "BOOT": "secubox-hub",
            "MIND": "secubox-ai-insights",
            "ROOT": "secubox-system",
            "MESH": "secubox-p2p",
        }

        active = []
        for module, service in module_services.items():
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True, timeout=2
                )
                if result.stdout.strip() == "active":
                    active.append(module)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return active

    @classmethod
    async def collect_all(cls) -> Dict[str, Any]:
        """
        Collecte toutes les métriques en parallèle.
        Optimisé pour minimiser le temps de réponse.

        Retourne: dict avec toutes les métriques
        """
        # Lancer les collectes en parallèle (sauf cpu_percent qui a un délai)
        results = await asyncio.gather(
            cls.cpu_percent(sample_ms=200),
            cls.mem_percent(),
            cls.disk_percent("/"),
            cls.wifi_rssi(),
            cls.load_avg_1(),
            cls.cpu_temp(),
            cls.uptime_seconds(),
            cls.hostname(),
            cls.secubox_version(),
            cls.modules_active(),
            return_exceptions=True,
        )

        # Mapper les résultats
        keys = [
            "cpu_percent", "mem_percent", "disk_percent", "wifi_rssi",
            "load_avg_1", "cpu_temp", "uptime_seconds", "hostname",
            "secubox_version", "modules_active"
        ]

        metrics = {}
        for i, key in enumerate(keys):
            value = results[i]
            if isinstance(value, Exception):
                log.warning("Erreur collecte %s: %s", key, value)
                # Valeurs par défaut selon le type
                if key in ("cpu_percent", "mem_percent", "disk_percent", "load_avg_1", "cpu_temp"):
                    value = 0.0
                elif key in ("wifi_rssi", "uptime_seconds"):
                    value = 0
                elif key == "modules_active":
                    value = []
                else:
                    value = "unknown"
            metrics[key] = value

        return metrics
