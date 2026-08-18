# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Pending-TOTP-enrollment store. JSON-backed, TTL'd."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional


class PendingStore:
    def __init__(self, path: Path, ttl_seconds: int = 900):
        self.path = Path(path)
        self.ttl = ttl_seconds
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("{}")

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except Exception:
            return {}

    def _save(self, doc: dict) -> None:
        fd, tmp = tempfile.mkstemp(prefix=".pending.", dir=str(self.path.parent))
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f)
        os.replace(tmp, self.path)

    def put(self, key: str, secret: str) -> None:
        doc = self._load()
        doc[key] = {"secret": secret, "expires_at": int(time.time()) + self.ttl}
        self._save(doc)

    def get(self, key: str) -> Optional[str]:
        doc = self._load()
        entry = doc.get(key)
        if not entry:
            return None
        if entry.get("expires_at", 0) < int(time.time()):
            self.delete(key)
            return None
        return entry.get("secret")

    def delete(self, key: str) -> None:
        doc = self._load()
        if key in doc:
            del doc[key]
            self._save(doc)
