# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-nac — background collector + double-cache (#817 Task 4).

Replaces the per-request inline `_discover_clients()` calls (the #808
aggregator SPOF: a shared single-process loop blocked by subprocess-heavy
discovery on every request) with one passive background loop:
`discover()` -> enrich -> `store.upsert()`, publishing an in-memory
`snapshot()` list that FastAPI handlers read as plain `def` (threadpooled,
short, non-blocking). `discover` is imported as a module-level name (not
called via a class attribute) so tests can `monkeypatch.setattr(api.
collector, "discover", ...)` without touching `discovery.py`.

Pure stdlib + local package imports only — no FastAPI import here.
"""
from __future__ import annotations

import asyncio
import logging
import time

from .discovery import discover
from .enrich import classify_device_type, openwrt_fingerprint, oui_vendor, risk_score
from .store import DeviceStore

logger = logging.getLogger("secubox.nac.collector")


class Collector:
    """Background passive-discovery loop with an in-memory double-cache.

    `cycle_once()` is the synchronous unit of work (discover -> enrich ->
    upsert) so tests can drive exactly one cycle deterministically.
    `run_forever()` is the async wrapper that calls it every `interval`
    seconds until cancelled — this is the task started at FastAPI
    `startup`, replacing the old `_monitor_clients()`.
    """

    def __init__(self, store: DeviceStore, oui_map: dict, interval: int = 30):
        self.store = store
        self.oui_map = oui_map
        self.interval = interval
        self._snapshot: list[dict] = []

    def cycle_once(self) -> None:
        """Run one discover -> enrich -> upsert cycle, synchronously.

        A MAC not already present in the store is treated as a new
        client: it is recorded in `device_history` and fired through
        `_emit("client_joined", dev)` (the webhook hook). The in-memory
        snapshot is replaced with this cycle's enriched device list —
        handlers reading `snapshot()` always see the latest completed
        cycle, never a partial one.
        """
        try:
            devices = discover()
        except Exception:  # noqa: BLE001 - the collector loop must never die
            logger.warning("collector: discover() failed", exc_info=True)
            devices = []

        now = int(time.time())
        snapshot: list[dict] = []

        for dev in devices:
            mac = dev.get("mac")
            if not mac:
                continue

            is_new = self.store.get(mac) is None

            hostname = dev.get("hostname", "")
            vendor = oui_vendor(mac, self.oui_map)
            device_type = classify_device_type(hostname, vendor)
            fp = openwrt_fingerprint(hostname, mac)

            # #817 whole-branch fix (I4): OMIT fields the enricher couldn't
            # determine so a re-seen migrated device isn't clobbered by a
            # sentinel through `upsert`'s best-value merge. A None vendor,
            # an "unknown" device_type (and therefore its derived risk) are
            # left out entirely — `upsert` then keeps the stored value on
            # an existing row, and the SQL DEFAULT applies for a new one.
            enriched = {
                **dev,
                "is_router": int(fp["is_router"]),
                "is_openwrt": int(fp["is_openwrt"]),
                "first_seen": now,
                "last_seen": now,
            }
            if vendor:
                enriched["oui_vendor"] = vendor
            if device_type != "unknown":
                score, level = risk_score(device_type, fp["is_router"])
                enriched["device_type"] = device_type
                enriched["risk_score"] = score
                enriched["risk_level"] = level
            self.store.upsert(enriched)

            if is_new:
                self.store.record_event(mac, "client_joined", hostname or "")
                self._emit("client_joined", enriched)

            snapshot.append(enriched)

        self._snapshot = snapshot

    async def run_forever(self) -> None:
        """Call `cycle_once()` every `interval` seconds until cancelled.

        #817 whole-branch fix (I2, now board-critical): `cycle_once()` runs
        a blocking `subprocess.run(["ip","neigh",...])` discovery plus ~280
        SQLite upserts. On the board, nac is mounted in-process by the
        aggregator, so this loop shares its single event loop with ~110
        other modules — running `cycle_once()` inline would block ALL of
        them for the duration of every cycle (#808). Offload it to the
        default threadpool via `run_in_executor` so only a worker thread
        blocks, never the shared loop.
        """
        loop = asyncio.get_running_loop()
        try:
            while True:
                await loop.run_in_executor(None, self.cycle_once)
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            logger.info("collector: run_forever cancelled, exiting cleanly")
            raise

    def snapshot(self) -> list:
        """Return the most recently completed cycle's enriched device dicts."""
        return self._snapshot

    def _emit(self, event: str, dev: dict) -> None:
        """Webhook hook, no-op by default.

        Overridden by `main.py` at startup to fire the existing
        `_notify_webhooks()`; kept as a plain no-op here so `collector.py`
        never imports FastAPI/httpx and tests can capture events by
        swapping this attribute directly.
        """
        return None
