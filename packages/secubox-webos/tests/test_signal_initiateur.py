# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1434 — seul l'initiateur de l'appairage Signal reçoit l'accès."""
import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sp = pytest.importorskip("api.signal_pont")


@pytest.fixture
def banc(monkeypatch):
    poses = []
    etat = {"state": "pending"}

    async def appel(qui, methode, chemin, corps=None, exige_acces=True):
        return {"ok": True, "data": dict(etat)}
    monkeypatch.setattr(sp, "_appel", appel)
    monkeypatch.setattr(sp.acces, "a_acces", lambda qui, svc: any(p == qui for p in poses))
    monkeypatch.setattr(sp.acces, "pose_manuel", lambda qui, svc, compte, secret: poses.append(qui))
    sp._APPAIRAGE.clear()
    return poses, etat


def test_seul_l_initiateur_obtient_l_acces(banc):
    poses, etat = banc
    asyncio.run(sp.lier("alice"))
    etat["state"] = "linked"
    asyncio.run(sp.lier_etat("mallory"))          # un autre utilisateur du Hall
    assert poses == []
    asyncio.run(sp.lier_etat("alice"))
    assert poses == ["alice"]
    asyncio.run(sp.lier_etat("mallory"))          # après coup non plus
    assert poses == ["alice"]


def test_sans_appairage_lance_personne(banc):
    poses, etat = banc
    etat["state"] = "linked"
    asyncio.run(sp.lier_etat("alice"))
    assert poses == []
