# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 16 (#4058) : hebdomadaire du lundi — synthèse d'abord, seuil, et JAMAIS de publication."""
import asyncio
import os
import time

import httpx

from conftest import PAQUET
from emissions import hebdo

M, N = {"marquant": True}, {"marquant": False}
SUJETS = {"campagne/a": [M, M, M], "campagne/b": [M, N], "acteur/c": [], "acteur/d": [M, M, M, N]}


def test_synthese_d_abord():
    p = hebdo.planifier_semaine(SUJETS)
    assert p[0] == {"format": "synthese", "sources": ["campagne/a", "campagne/b", "acteur/d"]}
    assert all(x["format"] == "sujet" for x in p[1:])


def test_seuil():
    assert [x["sources"] for x in hebdo.planifier_semaine(SUJETS)[1:]] == [["campagne/a"], ["acteur/d"]]
    assert [x["sources"] for x in hebdo.planifier_semaine(SUJETS, seuil=4)[1:]] == []
    assert hebdo.planifier_semaine({"acteur/c": []}) == []                 # rien n'a changé : rien à produire


def test_hebdo_ne_publie_jamais(tmp_path):
    vues = []

    def repondre(req):
        vues.append((req.method, req.url.path))
        if req.url.path == "/evolutions":
            return httpx.Response(200, json={"sujets": SUJETS})
        if req.url.path == "/reglages":
            return httpx.Response(200, json={"seuil": 3, "mp4_jours": 14})
        if req.url.path == "/produire":
            return httpx.Response(200, json={"id": "e20261130060000-abcdef"})
        return httpx.Response(404)
    notes = []

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(repondre), base_url="http://e") as c:
            return await hebdo.executer(c, notifier=notes.append, base=tmp_path)
    ids = asyncio.run(go())
    assert len(ids) == 3 and [m for m, p in vues if p == "/produire"] == ["POST"] * 3
    assert not any("publier" in p for _, p in vues)
    assert notes and "3 brouillon" in notes[0]
    assert "/publier" not in (PAQUET / "emissions/hebdo.py").read_text()      # aucun chemin vers la publication


def test_purge_mp4_locaux(tmp_path):
    d = tmp_path / "brouillons" / "e20261101000000-abcdef"
    d.mkdir(parents=True)
    vieux, neuf, mp3 = d / "emission.mp4", tmp_path / "brouillons" / "e20261128000000-abcdef" / "emission.mp4", d / "emission.mp3"
    neuf.parent.mkdir()
    for f in (vieux, neuf, mp3):
        f.write_bytes(b"x")
    ancien = time.time() - 20 * 86400
    os.utime(vieux, (ancien, ancien))
    os.utime(mp3, (ancien, ancien))
    assert hebdo.purger_mp4(tmp_path, 14) == 1
    assert not vieux.exists() and neuf.exists() and mp3.exists()


def test_minuterie_lundi_6h():
    t = (PAQUET / "systemd/secubox-ai-emissions-hebdo-gk0.timer").read_text()
    assert "OnCalendar=Mon *-*-* 06:00:00" in t and "Persistent=true" in t
