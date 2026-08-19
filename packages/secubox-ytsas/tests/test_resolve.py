# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from fastapi.testclient import TestClient
import os, sys, pathlib, tempfile

# main.py creates DOWNLOAD_DIR (default /data/ytsas) and opens a sqlite DB
# under it at import time. Point it at a throwaway dir so the import doesn't
# require /data to exist / be writable on a dev box.
os.environ.setdefault("YTSAS_DOWNLOAD_DIR", tempfile.mkdtemp())

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
import main

class FakeLib:
    def __init__(self, rows): self._rows = rows
    def list(self): return self._rows

class FakeEngine:
    def __init__(self): self.added = []
    async def add(self, url): self.added.append(url); return {"id": "dQw4w9WgXcQ", "status": "queued"}

def _client(rows):
    main.library = FakeLib(rows)
    main.engine = FakeEngine()
    return TestClient(main.app), main.engine

def test_mirror():
    c, _ = _client([{"id": "dQw4w9WgXcQ", "complete": 1, "peertube_url": "https://peertube.gk2/w/xy"}])
    r = c.get("/api/v1/ytsas/resolve", params={"url": "https://youtu.be/dQw4w9WgXcQ"})
    assert r.json()["state"] == "mirror"
    assert r.json()["peertube_url"] == "https://peertube.gk2/w/xy"

def test_cache():
    c, _ = _client([{"id": "dQw4w9WgXcQ", "complete": 1, "peertube_url": None}])
    j = c.get("/api/v1/ytsas/resolve", params={"url": "https://youtu.be/dQw4w9WgXcQ"}).json()
    assert j["state"] == "cache" and j["stream_url"].endswith("/dQw4w9WgXcQ")

def test_pending_enqueues():
    c, eng = _client([])
    j = c.get("/api/v1/ytsas/resolve", params={"url": "https://youtu.be/dQw4w9WgXcQ"}).json()
    assert j["state"] == "pending"
    assert eng.added == ["https://youtu.be/dQw4w9WgXcQ"]

def test_unsupported():
    c, _ = _client([])
    assert c.get("/api/v1/ytsas/resolve", params={"url": "https://vimeo.com/1"}).json()["state"] == "unsupported"
