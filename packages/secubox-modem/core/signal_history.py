# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Signal History
CyberMind — https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>

Signal strength history storage and retrieval.
"""
import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict

from secubox_core.logger import get_logger

log = get_logger("modem-signal")


@dataclass
class SignalRecord:
    """A single signal measurement."""
    timestamp: str
    rssi: Optional[float] = None
    rsrp: Optional[float] = None
    rsrq: Optional[float] = None
    sinr: Optional[float] = None
    quality_percent: Optional[int] = None
    network_type: str = ""
    operator: str = ""


class SignalHistory:
    """Manages signal strength history with automatic persistence."""

    CACHE_DIR = Path("/var/cache/secubox/modem")
    HISTORY_FILE = CACHE_DIR / "signal_history.json"
    MAX_RECORDS = 7200  # 2 hours at 1 record/second, or 1 hour at 0.5s

    def __init__(self, max_age_hours: float = 1.0):
        self.max_age_hours = max_age_hours
        self._records: List[SignalRecord] = []
        self._lock = asyncio.Lock()
        self._dirty = False
        self._last_save = 0.0
        self._save_interval = 60.0  # Save to disk every 60 seconds

        # Ensure directory exists
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)

        # Load existing history
        self._load()

    def _load(self):
        """Load history from disk."""
        try:
            if self.HISTORY_FILE.exists():
                data = json.loads(self.HISTORY_FILE.read_text())
                records = data.get("records", [])
                self._records = [
                    SignalRecord(**r) for r in records
                ]
                log.debug("Loaded %d signal records from disk", len(self._records))
        except Exception as e:
            log.error("Failed to load signal history: %s", e)
            self._records = []

    def _save(self):
        """Save history to disk."""
        try:
            data = {
                "records": [asdict(r) for r in self._records],
                "updated_at": datetime.now().isoformat(),
            }
            self.HISTORY_FILE.write_text(json.dumps(data, indent=2))
            self._dirty = False
            self._last_save = time.time()
            log.debug("Saved %d signal records to disk", len(self._records))
        except Exception as e:
            log.error("Failed to save signal history: %s", e)

    async def add_record(self, record: SignalRecord):
        """Add a signal record to history."""
        async with self._lock:
            self._records.append(record)
            self._dirty = True

            # Trim old records
            self._trim_old_records()

            # Periodic save
            if time.time() - self._last_save > self._save_interval:
                self._save()

    async def add_measurement(
        self,
        rssi: Optional[float] = None,
        rsrp: Optional[float] = None,
        rsrq: Optional[float] = None,
        sinr: Optional[float] = None,
        quality_percent: Optional[int] = None,
        network_type: str = "",
        operator: str = "",
    ):
        """Add a signal measurement with current timestamp."""
        record = SignalRecord(
            timestamp=datetime.now().isoformat(),
            rssi=rssi,
            rsrp=rsrp,
            rsrq=rsrq,
            sinr=sinr,
            quality_percent=quality_percent,
            network_type=network_type,
            operator=operator,
        )
        await self.add_record(record)

    def _trim_old_records(self):
        """Remove records older than max_age_hours."""
        if not self._records:
            return

        cutoff = datetime.now() - timedelta(hours=self.max_age_hours)
        cutoff_str = cutoff.isoformat()

        # Keep records newer than cutoff, up to MAX_RECORDS
        self._records = [
            r for r in self._records
            if r.timestamp >= cutoff_str
        ][-self.MAX_RECORDS:]

    async def get_history(
        self,
        minutes: int = 60,
        limit: int = 0
    ) -> List[Dict[str, Any]]:
        """Get signal history for the specified time period."""
        async with self._lock:
            cutoff = datetime.now() - timedelta(minutes=minutes)
            cutoff_str = cutoff.isoformat()

            records = [
                asdict(r) for r in self._records
                if r.timestamp >= cutoff_str
            ]

            if limit > 0:
                records = records[-limit:]

            return records

    async def get_latest(self) -> Optional[Dict[str, Any]]:
        """Get the most recent signal record."""
        async with self._lock:
            if self._records:
                return asdict(self._records[-1])
            return None

    async def get_stats(self, minutes: int = 60) -> Dict[str, Any]:
        """Get signal statistics for the time period."""
        records = await self.get_history(minutes=minutes)

        if not records:
            return {"count": 0}

        # Calculate averages for each metric
        metrics = ["rssi", "rsrp", "rsrq", "sinr", "quality_percent"]
        stats = {"count": len(records)}

        for metric in metrics:
            values = [r[metric] for r in records if r.get(metric) is not None]
            if values:
                stats[f"{metric}_avg"] = sum(values) / len(values)
                stats[f"{metric}_min"] = min(values)
                stats[f"{metric}_max"] = max(values)
                stats[f"{metric}_count"] = len(values)

        return stats

    async def flush(self):
        """Force save to disk."""
        async with self._lock:
            if self._dirty:
                self._save()

    async def clear(self):
        """Clear all history."""
        async with self._lock:
            self._records = []
            self._dirty = True
            self._save()


# Global instance
_signal_history: Optional[SignalHistory] = None


def get_signal_history() -> SignalHistory:
    """Get the global signal history instance."""
    global _signal_history
    if _signal_history is None:
        _signal_history = SignalHistory()
    return _signal_history
