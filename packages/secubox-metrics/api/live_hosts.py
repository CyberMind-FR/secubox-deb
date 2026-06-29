# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: LiveHosts aggregator

Counts requests per vhost over the last `window_minutes` by reading the
per-vhost nginx access logs (/var/log/nginx/<vhost>_access.log) and parsing
their combined-format timestamps. Emits a top-N rollup plus the total request
count in the window (used as the denominator for the WAF block rate).

Earlier versions polled the HAProxy admin socket per frontend; that only works
when every vhost has its own HAProxy frontend. This deployment funnels all
vhosts through a single `http-in` frontend (→ mitmproxy/WAF → nginx), so the
authoritative per-vhost signal is the nginx logs. Requires the service user to
be able to read /var/log/nginx (the `adm` group).
"""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("secubox.live_hosts")

CACHE_PATH = Path("/var/cache/secubox/metrics/live-hosts.json")
DEFAULT_LOG_DIR = "/var/log/nginx"
# nginx combined log timestamp: [29/Jun/2026:17:27:38 +0200]
TS_RE = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
TS_FMT = "%d/%b/%Y:%H:%M:%S %z"
# Bound the per-file read so a huge log can't stall the collector. 60 min of a
# busy vhost fits comfortably; older lines beyond this are out of window anyway.
TAIL_BYTES = 3_000_000


class LiveHostsAggregator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
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
        return {"enabled": False, "window_minutes": self.cfg.get("window_minutes", 60),
                "entries": [], "total_requests": 0}

    async def run_forever(self) -> None:
        while True:
            try:
                self._payload = await self.refresh_once()
            except Exception as e:  # noqa: BLE001
                log.warning("refresh_once raised: %s", e)
            await asyncio.sleep(60)

    async def refresh_once(self) -> dict:
        if not self.cfg.get("enabled"):
            self._refreshed = True
            return self._disabled_payload()
        counts, total = await asyncio.to_thread(self._read_nginx_hosts)
        top_n = int(self.cfg.get("top_n", 5))
        entries = [{"host": h, "count": c} for h, c in counts.most_common(top_n) if c > 0]
        payload = {
            "enabled": True,
            "window_minutes": int(self.cfg.get("window_minutes", 60)),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": entries,
            "total_requests": total,
        }
        self._persist(payload)
        self._refreshed = True
        return payload

    # -- helpers --------------------------------------------

    def _read_nginx_hosts(self) -> tuple[collections.Counter, int]:
        log_dir = Path(self.cfg.get("log_dir", DEFAULT_LOG_DIR))
        window = int(self.cfg.get("window_minutes", 60))
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        counts: collections.Counter = collections.Counter()
        total = 0
        try:
            files = sorted(log_dir.glob("*_access.log"))
        except Exception as e:  # noqa: BLE001
            log.warning("cannot list %s: %s", log_dir, e)
            return counts, 0
        for f in files:
            try:
                size = f.stat().st_size
                if size == 0:
                    continue
                host = f.name[: -len("_access.log")]
                with open(f, "rb") as fh:
                    if size > TAIL_BYTES:
                        fh.seek(size - TAIL_BYTES)
                        fh.readline()  # drop the partial first line
                    blob = fh.read().decode("utf-8", errors="replace")
            except PermissionError:
                log.warning("no read permission on %s (add service user to 'adm')", f)
                continue
            except Exception as e:  # noqa: BLE001
                log.warning("read %s failed: %s", f, e)
                continue
            for line in blob.splitlines():
                m = TS_RE.search(line)
                if not m:
                    continue
                try:
                    ts = datetime.strptime(m.group(1), TS_FMT)
                except ValueError:
                    continue
                if ts >= cutoff:
                    counts[host] += 1
                    total += 1
        return counts, total

    def _persist(self, payload: dict) -> None:
        try:
            CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = CACHE_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload))
            tmp.replace(CACHE_PATH)
        except Exception as e:  # noqa: BLE001
            log.warning("persist failed: %s", e)

    def _disabled_payload(self) -> dict:
        return {
            "enabled": False,
            "window_minutes": int(self.cfg.get("window_minutes", 60)),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": [],
            "total_requests": 0,
        }
