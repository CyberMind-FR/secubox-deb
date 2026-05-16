# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: cookie_audit
Mitmproxy addon that appends every Set-Cookie observed in transit to a JSONL
ledger for RGPD / ePrivacy compliance auditing on operator-owned vhosts.

Cookie values are sha256-hashed in-process — the raw value never leaves the
addon. Companion to the browser-side ``cookie-inventory.js`` and the
``CookieAuditAggregator`` in secubox-metrics, which reconciles both streams.
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("secubox.cookie_audit")

DEFAULT_LEDGER = "/var/log/secubox/cookie-audit/server.jsonl"


def parse_set_cookie(raw: str) -> dict:
    """Parse a Set-Cookie header into a structured record.

    Returns an empty dict if ``raw`` lacks an ``name=value`` pair. Unknown
    attributes are ignored — we only record the RGPD-relevant ones.
    """
    if not raw or "=" not in raw.split(";", 1)[0]:
        return {}
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    name = name.strip()
    if not name:
        return {}
    rec = {
        "name": name,
        "value_hash": hashlib.sha256(
            value.strip().encode("utf-8", errors="replace")
        ).hexdigest(),
        "domain": None,
        "path": None,
        "expires": None,
        "max_age": None,
        "secure": False,
        "httponly": False,
        "samesite": None,
    }
    for attr in parts[1:]:
        if not attr:
            continue
        k, _, v = attr.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "domain":
            rec["domain"] = v.lstrip(".") or None
        elif k == "path":
            rec["path"] = v or None
        elif k == "expires":
            rec["expires"] = v or None
        elif k == "max-age":
            try:
                rec["max_age"] = int(v)
            except (ValueError, TypeError):
                pass
        elif k == "secure":
            rec["secure"] = True
        elif k == "httponly":
            rec["httponly"] = True
        elif k == "samesite":
            rec["samesite"] = v or None
    return rec


class CookieAudit:
    """Mitmproxy addon — log every Set-Cookie response header to JSONL."""

    def __init__(self, ledger_path: str = DEFAULT_LEDGER):
        self.ledger_path = Path(ledger_path)
        self._lock = threading.Lock()

    def response(self, flow) -> None:
        try:
            resp = getattr(flow, "response", None)
            if resp is None:
                return
            headers = getattr(resp, "headers", None)
            if headers is None or not hasattr(headers, "get_all"):
                return
            set_cookies = headers.get_all("Set-Cookie")
            if not set_cookies:
                return
            req = getattr(flow, "request", None)
            host = ""
            path = ""
            referer = ""
            if req is not None:
                host = getattr(req, "host", "") or ""
                path = getattr(req, "path", "") or ""
                try:
                    rhdrs = getattr(req, "headers", None)
                    if rhdrs is not None and hasattr(rhdrs, "get"):
                        referer = rhdrs.get("Referer", "") or ""
                except Exception:
                    referer = ""
            for raw in set_cookies:
                parsed = parse_set_cookie(raw)
                if not parsed:
                    continue
                rec = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "vhost": host,
                    "path": path,
                    "request_referer": referer,
                    **parsed,
                }
                self._append(rec)
        except Exception as e:
            log.warning("cookie_audit response hook failed: %s", e)

    def _append(self, rec: dict) -> None:
        with self._lock:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with self.ledger_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")


addons = [CookieAudit()]
