# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#4055 — un refus d'authentification est mis en cache : pas de yt-dlp au 2e appel, levé par de nouveaux cookies ;
au délai, yt-dlp ET ses enfants (deno) sont tués en groupe."""
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
from engine import AuthRequired, Engine  # noqa: E402

URL = "https://www.youtube.com/watch?v=7AzimrAgWbA"
# Faux yt-dlp : compte ses lancements, répond le refus « not a bot » de YouTube.
REFUS = ("#!/bin/sh\necho x >> \"$(dirname \"$0\")/appels\"\n"
         "echo \"ERROR: [youtube] x: Sign in to confirm you're not a bot. Use --cookies\" >&2\nexit 1\n")


class Lib:
    def add(self, **kw):
        pass


def _moteur(tmp_path, script=REFUS):
    faux = tmp_path / "yt-dlp"
    faux.write_text(script)
    faux.chmod(0o755)
    cookies = tmp_path / "cookies.txt"
    cookies.write_text("# Netscape\n")
    return Engine(str(tmp_path / "dl"), Lib(), str(cookies), ytdlp_bin=str(faux)), tmp_path / "appels", cookies


def _appels(f):
    return len(f.read_text().splitlines()) if f.exists() else 0


def test_refus_en_cache_pas_de_sous_processus_au_second_appel(tmp_path):
    e, appels, _ = _moteur(tmp_path)
    with pytest.raises(AuthRequired) as a:
        asyncio.run(e.add(URL))
    assert _appels(appels) == 1 and "cookies périmés" in str(a.value)
    with pytest.raises(AuthRequired) as b:
        asyncio.run(e.add(URL))
    assert _appels(appels) == 1, "le refus mis en cache ne doit pas relancer yt-dlp"
    assert str(b.value) == str(a.value)


def test_nouveaux_cookies_levent_le_cache(tmp_path):
    e, appels, cookies = _moteur(tmp_path)
    with pytest.raises(AuthRequired):
        asyncio.run(e.add(URL))
    cookies.write_text("# Netscape\n# neufs, plus longs\n")
    os.utime(cookies, ns=(time.time_ns() + 10**9, time.time_ns() + 10**9))
    with pytest.raises(AuthRequired):
        asyncio.run(e.add(URL))
    assert _appels(appels) == 2, "un coffre changé lève le cache : yt-dlp est relancé"


def test_oublie_refus_au_depot(tmp_path):
    e, appels, _ = _moteur(tmp_path)
    with pytest.raises(AuthRequired):
        asyncio.run(e.add(URL))
    e.oublie_refus()
    with pytest.raises(AuthRequired):
        asyncio.run(e.add(URL))
    assert _appels(appels) == 2


def test_cache_expire_au_delai(tmp_path, monkeypatch):
    e, appels, _ = _moteur(tmp_path)
    with pytest.raises(AuthRequired):
        asyncio.run(e.add(URL))
    monkeypatch.setattr(moteur.time, "time", lambda: 10**12)
    with pytest.raises(AuthRequired):
        asyncio.run(e.add(URL))
    assert _appels(appels) == 2


def test_autre_adresse_non_bloquee(tmp_path):
    e, appels, _ = _moteur(tmp_path)
    with pytest.raises(AuthRequired):
        asyncio.run(e.add(URL))
    with pytest.raises(AuthRequired):
        asyncio.run(e.add("https://www.youtube.com/watch?v=0MYN8mAEKUo"))
    assert _appels(appels) == 2


def test_route_add_rend_cookies_a_renouveler(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import main
    e, appels, _ = _moteur(tmp_path)
    monkeypatch.setattr(main, "engine", e)
    c = TestClient(main.app)
    for _ in range(3):
        r = c.post(main.API + "/add", json={"url": URL})
        assert r.status_code == 401
        d = r.json()
        assert d["auth_required"] is True and d["cookies_a_renouveler"] is True
    assert _appels(appels) == 1


# yt-dlp qui lance un enfant (comme deno) puis dort : au délai, le GROUPE meurt.
ENFANT = ("#!/bin/sh\nd=\"$(dirname \"$0\")\"\nsleep 30 &\necho $! > \"$d/enfant\"\nsleep 30\n")


def test_delai_tue_aussi_les_enfants(tmp_path, monkeypatch):
    e, _, _ = _moteur(tmp_path, ENFANT)
    monkeypatch.setattr(moteur, "DELAI_SONDE", 1)
    with pytest.raises(moteur.EngineError):
        asyncio.run(e.add(URL))
    pid = int((tmp_path / "enfant").read_text())
    fin = time.time() + 5
    while time.time() < fin:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        time.sleep(0.1)
    else:
        os.kill(pid, 9)
        pytest.fail("l'enfant de yt-dlp (deno) a survécu au délai : orphelin")
