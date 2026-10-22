# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3036 — un yt-dlp qui dépasse le délai est TUÉ (plus d'orphelin sur pipe_write) ; les incomplets reprennent au démarrage."""
import asyncio
import os
import pathlib
import sys
import tempfile
import time

import pytest

os.environ.setdefault("YTSAS_DOWNLOAD_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
import engine as moteur  # noqa: E402
from engine import Engine, EngineError, PlaylistTimeout  # noqa: E402

LENT = "#!/bin/sh\necho $$ > \"$(dirname \"$0\")/pid\"\nsleep 30\n"


class FauxLibrary:
    def __init__(self, incomplets=()):
        self._inc = list(incomplets)
        self.ajouts = []

    def incomplete(self):
        return list(self._inc)

    def get(self, vid):
        return next((r for r in self._inc if r["id"] == vid), None)

    def add(self, **kw):
        self.ajouts.append(kw)

    def set_complete(self, *a, **k):
        pass


def _moteur(tmp_path, lib=None):
    faux = tmp_path / "yt-dlp"
    faux.write_text(LENT)
    faux.chmod(0o755)
    return Engine(str(tmp_path / "dl"), lib or FauxLibrary(), str(tmp_path / "cookies.txt"), ytdlp_bin=str(faux)), tmp_path / "pid"


def _vivant(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _attend_mort(pid, delai=5):
    fin = time.time() + delai
    while time.time() < fin and _vivant(pid):
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        time.sleep(0.05)
    return not _vivant(pid)


def test_la_sonde_tue_le_processus_au_dela_du_delai(tmp_path, monkeypatch):
    monkeypatch.setattr(moteur, "DELAI_SONDE", 0.5)
    eng, pidf = _moteur(tmp_path)
    with pytest.raises(EngineError):
        asyncio.run(eng._probe("https://www.youtube.com/channel/UCx"))
    pid = int(pidf.read_text())
    assert _attend_mort(pid), "yt-dlp a survécu au dépassement de délai"


def test_l_enumeration_de_playlist_tue_aussi(tmp_path, monkeypatch):
    monkeypatch.setattr(moteur, "DELAI_PLAYLIST", 0.5)
    eng, pidf = _moteur(tmp_path)
    with pytest.raises(PlaylistTimeout):
        asyncio.run(eng.enumerate_playlist("https://www.youtube.com/playlist?list=PLx", 5))
    assert _attend_mort(int(pidf.read_text()))


def test_les_incomplets_reprennent_au_demarrage(tmp_path, monkeypatch):
    lib = FauxLibrary([{"id": "aaa", "url": "https://www.youtube.com/watch?v=aaa", "title": "A", "complete": 0},
                       {"id": "bbb", "url": None, "title": "sans url", "complete": 0},
                       {"id": "ccc", "url": "https://www.youtube.com/watch?v=ccc", "title": "C", "complete": 0}])
    eng, _ = _moteur(tmp_path, lib)
    relances = []
    monkeypatch.setattr(eng, "add_prefetched", lambda vid, url, title: relances.append(vid) or {"id": vid, "status": "downloading"})
    eng.jobs["ccc"] = {"status": "downloading"}          # déjà en cours : pas de doublon
    assert eng.reprend_incomplets() == 1
    assert relances == ["aaa"]
