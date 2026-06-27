# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Tests for POST /__toolbox/sw-candidate (ref #753)."""
import asyncio
from secubox_toolbox import api


class _Req:
    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload


def test_sw_candidate_appends_and_dedupes(tmp_path, monkeypatch):
    f = tmp_path / "sw-neuter-candidates.txt"
    monkeypatch.setattr(api, "SW_CANDIDATES_FILE", f)
    r1 = asyncio.run(api.toolbox_sw_candidate(_Req({"hosts": ["www.cnn.com", "leparisien.fr"]})))
    assert r1.status_code == 204
    asyncio.run(api.toolbox_sw_candidate(_Req({"hosts": ["www.cnn.com", "20minutes.fr"]})))
    lines = [l.strip() for l in f.read_text().splitlines() if l.strip()]
    assert sorted(lines) == ["20minutes.fr", "leparisien.fr", "www.cnn.com"]  # deduped


def test_sw_candidate_ignores_bad_payload(tmp_path, monkeypatch):
    f = tmp_path / "sw-neuter-candidates.txt"
    monkeypatch.setattr(api, "SW_CANDIDATES_FILE", f)
    r = asyncio.run(api.toolbox_sw_candidate(_Req({"hosts": [None, 123, ""]})))
    assert r.status_code == 204
    assert not f.exists() or f.read_text().strip() == ""
