# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3618 — case « via Tor » : proxy validé, jamais de cookies par Tor, refus clair sans Tor, booléen strict à l'API."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lxc" / "app"))

from engine import Engine, EngineError  # noqa: E402

PROXY = "socks5h://192.168.1.200:9050"


class Lib:
    def add(self, **kw):
        pass

    def get(self, vid):
        return None


def _eng(tmp_path, proxy=PROXY, cookies=True):
    c = tmp_path / "cookies.txt"
    if cookies:
        c.write_text("# Netscape\n")
    return Engine(str(tmp_path), Lib(), str(c), tor_proxy=proxy)


@pytest.mark.parametrize("douteux", ["socks5://192.168.1.200:9050", "socks5h://exemple.org:9050",
                                     "socks5h://1.2.3.4:9050 --exec x", "http://1.2.3.4:8080", ""])
def test_proxy_douteux_ignore(tmp_path, douteux):
    assert _eng(tmp_path, douteux).tor_proxy is None


def test_sans_tor_refus_clair(tmp_path):
    with pytest.raises(EngineError, match="Tor n'est pas disponible"):
        _eng(tmp_path, None)._tor_args(True)
    assert _eng(tmp_path, None)._tor_args(False) == []


def _argv_de_la_sonde(tmp_path, monkeypatch, tor):
    eng = _eng(tmp_path)
    vu = {}

    async def faux_exec(*argv, **kw):
        vu["argv"] = argv
        raise FileNotFoundError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", faux_exec)
    with pytest.raises(EngineError):
        asyncio.run(eng._probe("https://www.youtube.com/watch?v=X7qsiab6KtE", tor))
    return vu["argv"]


def test_sonde_par_tor_avec_proxy_et_sans_cookies(tmp_path, monkeypatch):
    argv = _argv_de_la_sonde(tmp_path, monkeypatch, True)
    assert "--proxy" in argv and argv[argv.index("--proxy") + 1] == PROXY
    assert "--cookies" not in argv


def test_sonde_directe_garde_les_cookies_et_pas_de_proxy(tmp_path, monkeypatch):
    argv = _argv_de_la_sonde(tmp_path, monkeypatch, False)
    assert "--proxy" not in argv and "--cookies" in argv


def test_telechargement_par_tor_sans_cookies(tmp_path, monkeypatch):
    eng = _eng(tmp_path)
    eng.jobs["v"] = {"progress": 0.0, "status": "downloading", "title": "t", "error": None}
    vus = []

    async def faux_exec(*argv, **kw):
        vus.append(argv)
        raise FileNotFoundError

    monkeypatch.setattr(asyncio, "create_subprocess_exec", faux_exec)
    asyncio.run(eng._download("v", "https://www.youtube.com/watch?v=v", str(tmp_path), True))
    assert vus and all("--cookies" not in a for a in vus)
    assert all(a[a.index("--proxy") + 1] == PROXY for a in vus)


def test_l_api_n_accepte_qu_un_vrai_booleen():
    src = (Path(__file__).resolve().parents[1] / "lxc" / "app" / "main.py").read_text()
    assert 'tor = b.get("tor") is True' in src and "engine.add(url, tor=tor)" in src
