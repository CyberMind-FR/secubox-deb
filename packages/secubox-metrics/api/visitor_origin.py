# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: VisitorOrigin aggregator
Polls the secubox_metrics seen_src nft set, resolves ASNs via MaxMind GeoLite2,
threshold-gates the rollup, and exposes a sanitized payload. Raw IPs never
leave the local scope.
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from collections import Counter
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path
from typing import Optional

try:
    import maxminddb
except ImportError:
    maxminddb = None  # type: ignore[assignment]


log = logging.getLogger("secubox.visitor_origin")

CACHE_PATH = Path("/var/cache/secubox/metrics/visitor-origin.json")


class VisitorOriginAggregator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._payload: dict = {"enabled": False, "entries": []}
        self._refreshed = False
        self._mmdb = None
        self._mmdb_mtime: float = 0.0

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
        if not Path(self.cfg["asn_db_path"]).exists() or maxminddb is None:
            self._refreshed = True
            return self._disabled_payload()
        ips = await asyncio.to_thread(self._read_nft_set)
        entries = self._aggregate(ips)
        payload = {
            "enabled": True,
            "window_minutes": self.cfg["window_minutes"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": entries,
        }
        self._persist(payload)
        self._refreshed = True
        return payload

    # -- pure helpers ---------------------------------------

    def _aggregate(self, ips: list[IPv4Address]) -> list[dict]:
        counter: Counter[tuple[int, str]] = Counter()
        seen: set[IPv4Address] = set()
        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)
            asn = self._lookup_asn(ip)
            if asn is None:
                continue
            counter[asn] += 1
        groups = [
            {"asn": asn, "org": org, "count": cnt}
            for (asn, org), cnt in counter.items()
            if cnt >= self.cfg["min_count"]
        ]
        groups.sort(key=lambda e: (-e["count"], e["asn"]))
        return groups[: self.cfg["top_n"]]

    def _lookup_asn(self, ip: IPv4Address) -> Optional[tuple[int, str]]:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return None
        try:
            current_mtime = Path(self.cfg["asn_db_path"]).stat().st_mtime
        except OSError:
            current_mtime = 0.0
        if self._mmdb is not None and current_mtime != self._mmdb_mtime:
            try:
                self._mmdb.close()
            except Exception:
                pass
            self._mmdb = None
        if self._mmdb is None:
            try:
                self._mmdb = maxminddb.open_database(self.cfg["asn_db_path"])
                self._mmdb_mtime = current_mtime
            except Exception as e:
                log.warning("mmdb open failed: %s", e)
                return None
        try:
            rec = self._mmdb.get(str(ip))
        except Exception:
            return None
        if not rec:
            return None
        asn = rec.get("autonomous_system_number")
        org = rec.get("autonomous_system_organization") or ""
        if asn is None:
            return None
        return (int(asn), str(org))

    def _read_nft_set(self) -> list[IPv4Address]:
        cmd = [
            "nft", "-j", "list", "set",
            self.cfg["nft_family"], self.cfg["nft_table"], self.cfg["nft_set"],
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return []
            doc = json.loads(res.stdout)
        except Exception:
            return []
        ips: list[IPv4Address] = []
        for obj in doc.get("nftables", []):
            elem = obj.get("set", {}).get("elem")
            if not elem:
                continue
            for e in elem:
                # nftables JSON can wrap addresses in dicts when flags are set
                raw = (
                    e["elem"]["val"]
                    if isinstance(e, dict) and isinstance(e.get("elem"), dict)
                    else e
                )
                if isinstance(raw, dict):
                    raw = raw.get("val", "")
                try:
                    ips.append(IPv4Address(str(raw)))
                except Exception:
                    continue
        return ips

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
