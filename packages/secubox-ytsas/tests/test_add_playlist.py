# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1099 — coller une URL de playlist ajoute TOUTES ses vidéos (bornées), pas
seulement la première. On vérifie l'aiguillage de /add et la logique
d'énumération→enfilement de l'engine (sans jamais lancer yt-dlp)."""
import asyncio
import os
import sys
import pathlib
import tempfile

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("YTSAS_DOWNLOAD_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
import main  # noqa: E402
from engine import Engine  # noqa: E402

PLAYLIST = "https://www.youtube.com/playlist?list=PLxxxxxxxxxxxxxxxx"
VIDEO = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"


# ── aiguillage de /add ───────────────────────────────────────────────────────
class RoutingEngine:
    def __init__(self):
        self.added = []
        self.playlists = []

    async def add(self, url):
        self.added.append(url)
        return {"id": "dQw4w9WgXcQ", "status": "downloading"}

    async def add_playlist(self, url, limit=100):
        self.playlists.append((url, limit))
        return {"playlist": True, "count": 2, "items": []}


def _client():
    main.engine = RoutingEngine()
    return TestClient(main.app), main.engine


def test_add_playlist_url_routes_to_add_playlist():
    c, eng = _client()
    r = c.post("/api/v1/ytsas/add", json={"url": PLAYLIST})
    assert r.status_code == 200 and r.json()["playlist"] is True
    assert eng.playlists and eng.playlists[0][0] == PLAYLIST
    assert eng.added == []                      # NE tombe PAS dans l'add simple


def test_add_video_url_routes_to_add():
    c, eng = _client()
    r = c.post("/api/v1/ytsas/add", json={"url": VIDEO})
    assert r.status_code == 200
    assert eng.added == [VIDEO] and eng.playlists == []


# ── engine.add_playlist ──────────────────────────────────────────────────────
class FakeLib:
    def __init__(self, rows=None):
        self.rows = {r["id"]: r for r in (rows or [])}
        self.added = []

    def add(self, id, url, title, path):
        self.added.append((id, title))
        self.rows.setdefault(id, {"id": id, "url": url, "title": title})

    def get(self, id):
        return self.rows.get(id)


def _engine_with(lib, entries, monkeypatch):
    eng = Engine("/tmp/ytsas-test", lib, cookie_path=None)

    async def fake_enum(url, limit=50):
        return entries[:limit]

    downloaded = []

    async def fake_dl(vid, url, item_dir):
        downloaded.append(vid)

    monkeypatch.setattr(eng, "enumerate_playlist", fake_enum)
    monkeypatch.setattr(eng, "_download", fake_dl)
    monkeypatch.setattr("engine.os.makedirs", lambda *a, **k: None)
    return eng, downloaded


ENTRIES = [
    {"id": "aaaaaaaaaaa", "url": "https://www.youtube.com/watch?v=aaaaaaaaaaa", "title": "A"},
    {"id": "bbbbbbbbbbb", "url": "https://www.youtube.com/watch?v=bbbbbbbbbbb", "title": "B"},
    {"id": "ccccccccccc", "url": "https://www.youtube.com/watch?v=ccccccccccc", "title": "C"},
]


@pytest.mark.asyncio
async def test_add_playlist_enqueues_every_entry(monkeypatch):
    lib = FakeLib()
    eng, _ = _engine_with(lib, ENTRIES, monkeypatch)
    out = await eng.add_playlist(PLAYLIST, limit=100)
    await asyncio.sleep(0)                           # laisse les tâches de fond démarrer
    assert out["playlist"] is True and out["count"] == 3
    assert {a[0] for a in lib.added} == {"aaaaaaaaaaa", "bbbbbbbbbbb", "ccccccccccc"}
    assert all(i["status"] == "downloading" for i in out["items"])


@pytest.mark.asyncio
async def test_add_playlist_skips_already_complete(monkeypatch):
    lib = FakeLib(rows=[{"id": "aaaaaaaaaaa", "complete": 1, "title": "A"}])
    eng, _ = _engine_with(lib, ENTRIES, monkeypatch)
    out = await eng.add_playlist(PLAYLIST, limit=100)
    await asyncio.sleep(0)
    assert out["count"] == 3                         # 3 reportés…
    done = [i for i in out["items"] if i["status"] == "complete"]
    assert [i["id"] for i in done] == ["aaaaaaaaaaa"]
    # …et le complet n'est PAS ré-inséré (donc pas re-téléchargé).
    assert {a[0] for a in lib.added} == {"bbbbbbbbbbb", "ccccccccccc"}


@pytest.mark.asyncio
async def test_add_playlist_bound_is_passed_to_enumeration(monkeypatch):
    lib = FakeLib()
    eng, _ = _engine_with(lib, ENTRIES, monkeypatch)
    seen = {}

    async def capture_enum(url, limit=50):
        seen["limit"] = limit
        return ENTRIES[:limit]

    monkeypatch.setattr(eng, "enumerate_playlist", capture_enum)
    out = await eng.add_playlist(PLAYLIST, limit=2)
    await asyncio.sleep(0)
    assert seen["limit"] == 2
    assert out["count"] == 2 and len(lib.added) == 2   # borne respectée
