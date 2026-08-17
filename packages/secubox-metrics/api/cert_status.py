# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: CertStatus aggregator
Scans /etc/letsencrypt/live/*/cert.pem, parses each cert via cryptography,
and emits a rollup of {valid, expiring_soon, expiring_critical, expired}
plus the soonest-renewing non-expired host.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509


log = logging.getLogger("secubox.cert_status")

CACHE_PATH = Path("/var/cache/secubox/metrics/cert-status.json")


class CertStatusAggregator:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._payload: dict = {"enabled": False, "summary": {}, "warnings": []}

    # -- public ---------------------------------------------

    def current(self) -> dict:
        if self._payload.get("summary"):
            return dict(self._payload)
        if CACHE_PATH.exists():
            try:
                return json.loads(CACHE_PATH.read_text())
            except Exception:
                pass
        return {"enabled": False, "summary": {}, "warnings": []}

    async def run_forever(self) -> None:
        while True:
            try:
                self._payload = await self.refresh_once()
            except Exception as e:
                log.warning("refresh_once raised: %s", e)
            await asyncio.sleep(60)

    async def refresh_once(self) -> dict:
        if not self.cfg.get("enabled"):
            return self._disabled_payload()
        live = Path(self.cfg["letsencrypt_live_dir"])
        if not live.is_dir():
            return self._disabled_payload()
        # #740 — x509 parsing is synchronous CPU; run it OFF the event loop so a
        # large cert set never freezes the shared metrics loop (502 windows on
        # /metrics/* + HealthBanner). The endpoint serves the cached payload.
        infos = await asyncio.to_thread(self._scan_certs, live)
        if not infos:
            return self._disabled_payload()
        payload = self._summarize(infos)
        self._persist(payload)
        return payload

    # -- helpers --------------------------------------------

    def _scan_certs(self, live: Path) -> list[dict]:
        out: list[dict] = []
        now = datetime.now(timezone.utc)
        for host_dir in sorted(live.iterdir()):
            if not host_dir.is_dir():
                continue
            cert_path = host_dir / "cert.pem"
            if not cert_path.exists():
                continue
            try:
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                not_after = cert.not_valid_after_utc
            except Exception as e:
                log.warning("parse failed for %s: %s", host_dir.name, e)
                continue
            days = math.ceil((not_after - now).total_seconds() / 86400)
            out.append({"host": host_dir.name, "days": days, "state": self._classify(days)})
        return out

    def _classify(self, days: int) -> str:
        if days <= 0:
            return "expired"
        if days <= self.cfg["critical_days"]:
            return "expiring_critical"
        if days <= self.cfg["warn_days"]:
            return "expiring_soon"
        return "valid"

    def _summarize(self, infos: list[dict]) -> dict:
        buckets = {"valid": 0, "expiring_soon": 0, "expiring_critical": 0, "expired": 0}
        for i in infos:
            buckets[i["state"]] += 1
        non_expired = sorted(
            (i for i in infos if i["state"] != "expired"),
            key=lambda x: x["days"],
        )
        next_renewal = (
            {"host": non_expired[0]["host"], "days": non_expired[0]["days"]}
            if non_expired
            else None
        )
        warnings = sorted(
            (i for i in infos if i["state"] in ("expiring_soon", "expiring_critical", "expired")),
            key=lambda x: x["days"],
        )
        return {
            "enabled": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {"total": len(infos), **buckets, "failed_renewal": 0},
            "next_renewal": next_renewal,
            "warnings": warnings,
        }

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
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {},
            "warnings": [],
        }
