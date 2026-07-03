# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Test the DPI /media_types endpoint — fail-empty + populated (ref #785)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # make api importable
from fastapi.testclient import TestClient  # noqa: E402
from api.main import app  # noqa: E402


def test_media_types_fail_empty(tmp_path, monkeypatch):
    from secubox_core import media_catch
    monkeypatch.setattr(media_catch, "MEDIA_CATCH_PATH", str(tmp_path / "absent.jsonl"))
    r = TestClient(app).get("/media_types")
    assert r.status_code == 200
    assert r.json()["present"] is False


def test_media_types_populated(tmp_path, monkeypatch):
    p = tmp_path / "media-catch.jsonl"
    p.write_text(json.dumps({"client": "aa", "host": "v", "kind": "video",
                             "ctype": "video/mp4", "bytes": 10}) + "\n")
    from secubox_core import media_catch
    monkeypatch.setattr(media_catch, "MEDIA_CATCH_PATH", str(p))
    r = TestClient(app).get("/media_types")
    body = r.json()
    assert body["present"] is True
    assert any(k["label"] == "video" for k in body["kinds"])
