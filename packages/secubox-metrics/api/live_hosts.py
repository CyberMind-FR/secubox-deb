# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: LiveHosts aggregator
Polls the HAProxy admin socket once per minute, ring-buffers per-frontend
request deltas over 60 minutes, and emits a sanitized top-N rollup of the
hostnames being served.
"""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


log = logging.getLogger("secubox.live_hosts")

CACHE_PATH = Path("/var/cache/secubox/metrics/live-hosts.json")


class LiveHostsAggregator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._buckets: collections.deque[dict[str, int]] = collections.deque(maxlen=60)
        self._prev_totals: dict[str, int] = {}
        self._payload: dict = {"enabled": False, "entries": []}
        self._refreshed = False

    # -- public ---------------------------------------------

    def current(self) -> dict:
        if self._refreshed:
            return dict(self._payload)
        if CACHE_PATH.exists():
            try:
                return json.loads(CACHE_PATH.read_text())
            except Exception:
                pass
        return {"enabled": False, "window_minutes": self.cfg["window_minutes"], "entries": []}

    async def run_forever(self) -> None:
        while True:
            try:
                self._payload = await self.refresh_once()
            except Exception as e:
                log.warning("refresh_once raised: %s", e)
            await asyncio.sleep(60)

    async def refresh_once(self) -> dict:
        if not self.cfg.get("enabled"):
            self._refreshed = True
            return self._disabled_payload()
        totals = await asyncio.to_thread(self._read_haproxy_stats)
        if totals is None:
            self._refreshed = True
            return self._disabled_payload()
        kept = self._filter_frontends(totals)
        self._delta_and_buffer(kept)
        entries = self._aggregate()
        payload = {
            "enabled": True,
            "window_minutes": self.cfg["window_minutes"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": entries,
        }
        self._persist(payload)
        self._refreshed = True
        return payload

    # -- helpers --------------------------------------------

    def _filter_frontends(self, totals: dict[str, int]) -> dict[str, int]:
        flt = self.cfg.get("frontend_filter", "*")
        out: dict[str, int] = {}
        for name, n in totals.items():
            if name.startswith("_"):
                continue
            if "." not in name:
                continue
            if flt != "*" and flt not in name:
                continue
            out[name] = n
        return out

    def _delta_and_buffer(self, totals: dict[str, int]) -> None:
        if not self._prev_totals:
            self._buckets.append({k: 0 for k in totals})
            self._prev_totals = dict(totals)
            return
        bucket: dict[str, int] = {}
        for host, cur in totals.items():
            prev = self._prev_totals.get(host)
            if prev is None or cur < prev:
                bucket[host] = 0
            else:
                bucket[host] = cur - prev
        self._buckets.append(bucket)
        self._prev_totals = dict(totals)

    def _aggregate(self) -> list[dict]:
        totals: dict[str, int] = collections.Counter()
        for bucket in self._buckets:
            for host, n in bucket.items():
                totals[host] += n
        entries = [{"host": h, "count": c} for h, c in totals.items() if c > 0]
        entries.sort(key=lambda e: (-e["count"], e["host"]))
        return entries[: self.cfg["top_n"]]

    def _read_haproxy_stats(self) -> Optional[dict[str, int]]:
        sock_path = self.cfg["haproxy_socket"]
        if not Path(sock_path).exists():
            return None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect(sock_path)
                s.sendall(b"show stat\n")
                chunks = []
                while True:
                    data = s.recv(8192)
                    if not data:
                        break
                    chunks.append(data)
            blob = b"".join(chunks).decode("utf-8", errors="replace")
        except Exception as e:
            log.warning("haproxy socket read failed: %s", e)
            return None
        return self._parse_show_stat(blob)

    @staticmethod
    def _parse_show_stat(blob: str) -> dict[str, int]:
        """Extract {frontend_name: req_tot} from `show stat` CSV output."""
        out: dict[str, int] = {}
        lines = blob.splitlines()
        if not lines:
            return out
        header = lines[0].lstrip("# ").split(",")
        try:
            pxname_i = header.index("pxname")
            svname_i = header.index("svname")
            req_tot_i = header.index("req_tot")
        except ValueError:
            return out
        for line in lines[1:]:
            if not line or line.startswith("#"):
                continue
            cols = line.split(",")
            if len(cols) <= max(pxname_i, svname_i, req_tot_i):
                continue
            if cols[svname_i] != "FRONTEND":
                continue
            try:
                out[cols[pxname_i]] = int(cols[req_tot_i] or "0")
            except ValueError:
                continue
        return out

    def _persist(self, payload: dict) -> None:
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = CACHE_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload))
            tmp.replace(CACHE_PATH)
        except Exception as e:
            log.warning("persist failed: %s", e)

    def _disabled_payload(self) -> dict:
        return {
            "enabled": False,
            "window_minutes": self.cfg["window_minutes"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": [],
        }
