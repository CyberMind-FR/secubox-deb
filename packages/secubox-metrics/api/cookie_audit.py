# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: CookieAuditAggregator
Reconciles the mitmproxy Set-Cookie ledger (server) with browser snapshots
(client) and produces a per-vhost RGPD / ePrivacy compliance report.

Sources:
  - "http" : seen in mitmproxy ledger, not in any browser snapshot.
  - "js"   : seen in a browser snapshot but NEVER in a Set-Cookie response
             header. Posed by client-side JavaScript → requires prior consent
             unless strictly necessary (LCEN art. 82 / ePrivacy).
  - "both" : seen in both — classification still drives the verdict.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("secubox.cookie_audit")

DEFAULT_CACHE_PATH = Path("/var/cache/secubox/metrics/cookie-audit.json")
DEFAULT_LEDGER = "/var/log/secubox/cookie-audit/server.jsonl"
DEFAULT_INGEST_DIR = "/var/lib/secubox/cookie-audit/ingest"


class Classifier:
    """Maps a cookie name to a RGPD category via regex patterns.

    Categories are checked in the order:
    strictly_necessary → functional → analytics → marketing.
    First match wins; unmatched names get the ``unclassified`` label.
    """

    CATEGORIES = ("strictly_necessary", "functional", "analytics", "marketing")

    def __init__(self, rules: dict):
        self._compiled: dict = {}
        for cat in self.CATEGORIES:
            patterns = rules.get(cat, []) or []
            self._compiled[cat] = [re.compile(p) for p in patterns]

    def classify(self, name: str) -> str:
        for cat in self.CATEGORIES:
            for rx in self._compiled[cat]:
                if rx.search(name):
                    return cat
        return "unclassified"


def classify_cookie(name: str, rules: dict) -> str:
    return Classifier(rules).classify(name)


class CookieAuditAggregator:
    def __init__(self, cfg: dict, cache_path: Optional[Path] = None):
        self.cfg = cfg
        self.cache_path = Path(cache_path) if cache_path else DEFAULT_CACHE_PATH
        self._payload: dict = {"enabled": False, "hosts": []}

    def current(self) -> dict:
        if self._payload.get("hosts") or self._payload.get("enabled"):
            return dict(self._payload)
        if self.cache_path.exists():
            try:
                return json.loads(self.cache_path.read_text())
            except Exception:
                pass
        return {"enabled": False, "hosts": []}

    async def run_forever(self) -> None:
        while True:
            try:
                self._payload = await self.refresh_once()
            except Exception as e:
                log.warning("refresh_once raised: %s", e)
            await asyncio.sleep(60)

    async def refresh_once(self) -> dict:
        if not self.cfg.get("enabled"):
            self._payload = {"enabled": False, "hosts": []}
            self._persist(self._payload)
            return self._payload
        ledger_path = Path(self.cfg.get("ledger_path", DEFAULT_LEDGER))
        ingest_dir = Path(self.cfg.get("ingest_dir", DEFAULT_INGEST_DIR))
        classifier = Classifier(self.cfg.get("classifier", {}))
        server = self._read_ledger(ledger_path)
        browser = self._read_ingest(ingest_dir)
        hosts = self._reconcile(server, browser, classifier)
        payload = {
            "enabled": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hosts": hosts,
            "summary": self._summarize(hosts),
        }
        self._persist(payload)
        self._payload = payload
        return payload

    def _read_ledger(self, path: Path) -> dict:
        """Return {vhost: {cookie_name: latest server record}}."""
        out: dict = {}
        if not path.exists():
            return out
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                vhost = (rec.get("vhost") or "").strip()
                name = (rec.get("name") or "").strip()
                if not vhost or not name:
                    continue
                bucket = out.setdefault(vhost, {})
                bucket[name] = rec
        except Exception as e:
            log.warning("ledger read failed: %s", e)
        return out

    def _read_ingest(self, ingest_dir: Path) -> dict:
        """Return {vhost: {cookie_name: set(value_hash)}} across all snapshots."""
        out: dict = {}
        if not ingest_dir.exists():
            return out
        for f in ingest_dir.glob("*.jsonl"):
            try:
                for line in f.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    host = (rec.get("host") or "").strip()
                    if not host:
                        continue
                    bucket = out.setdefault(host, {})
                    for c in rec.get("cookies", []) or []:
                        n = (c.get("name") or "").strip()
                        if not n:
                            continue
                        bucket.setdefault(n, set()).add(c.get("value_hash") or "")
            except Exception as e:
                log.warning("ingest read failed for %s: %s", f, e)
        return out

    def _reconcile(self, server: dict, browser: dict, classifier: Classifier) -> list:
        all_hosts = sorted(set(server) | set(browser))
        out: list = []
        for vhost in all_hosts:
            srv = server.get(vhost, {})
            brw = browser.get(vhost, {})
            names = sorted(set(srv) | set(brw))
            cookies = []
            for n in names:
                s_rec = srv.get(n)
                b_hashes = brw.get(n)
                if s_rec and b_hashes:
                    source = "both"
                elif s_rec:
                    source = "http"
                else:
                    source = "js"
                cat = classifier.classify(n)
                violation = (source == "js" and cat != "strictly_necessary")
                cookies.append({
                    "name": n,
                    "source": source,
                    "category": cat,
                    "secure": bool(s_rec.get("secure")) if s_rec else None,
                    "httponly": bool(s_rec.get("httponly")) if s_rec else None,
                    "samesite": (s_rec.get("samesite") if s_rec else None),
                    "rgpd_violation": violation,
                })
            out.append({
                "vhost": vhost,
                "cookies": cookies,
                "violation_count": sum(1 for c in cookies if c["rgpd_violation"]),
            })
        return out

    def _summarize(self, hosts: list) -> dict:
        by_cat = {c: 0 for c in (*Classifier.CATEGORIES, "unclassified")}
        violations = 0
        hosts_with_violations = 0
        for h in hosts:
            local_violation = False
            for c in h["cookies"]:
                by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
                if c["rgpd_violation"]:
                    violations += 1
                    local_violation = True
            if local_violation:
                hosts_with_violations += 1
        return {
            "host_count": len(hosts),
            "hosts_with_violations": hosts_with_violations,
            "violation_count": violations,
            "by_category": by_cat,
        }

    def _persist(self, payload: dict) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(payload, separators=(",", ":")))
        except Exception as e:
            log.warning("persist failed: %s", e)
