# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 9 (#4058) : Gemma suspendu le temps de la voix, relance garantie, relais en 503 pendant ce temps."""
import asyncio
import json
import sys

import pytest

from conftest import PAQUET
from emissions.gpu import VerrouGPU

if str(PAQUET / "relais") not in sys.path:
    sys.path.insert(0, str(PAQUET / "relais"))


class Faux:
    def __init__(self):
        self.arrets = self.relances = 0

    async def arreter(self):
        self.arrets += 1

    async def relancer(self):
        self.relances += 1


def test_gpu_relance_meme_en_echec(tmp_path):
    f = Faux()
    v = VerrouGPU(tmp_path / "voix.verrou", f.arreter, f.relancer)

    async def corps():
        async with v.voix():
            assert v.fichier.exists()
            raise RuntimeError("worker coupé")

    with pytest.raises(RuntimeError):
        asyncio.run(corps())
    assert (f.arrets, f.relances) == (1, 1)
    assert not v.fichier.exists()


def test_gpu_relance_si_annulee(tmp_path):
    # SIGTERM sous uvicorn = annulation de la tâche : même garantie
    f = Faux()
    v = VerrouGPU(tmp_path / "voix.verrou", f.arreter, f.relancer)

    async def corps():
        async with v.voix():
            await asyncio.sleep(10)

    async def scenario():
        t = asyncio.create_task(corps())
        await asyncio.sleep(0.05)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

    asyncio.run(scenario())
    assert f.relances == 1 and not v.fichier.exists()


def test_reparer_au_demarrage(tmp_path):
    f = Faux()
    fichier = tmp_path / "voix.verrou"
    fichier.write_text(json.dumps({"pid": 2 ** 22 + 12345, "quand": 0, "cle": "x"}))   # pid mort
    v = VerrouGPU(fichier, f.arreter, f.relancer)
    assert asyncio.run(v.reparer()) is True
    assert f.relances == 1 and not fichier.exists()
    assert asyncio.run(v.reparer()) is False      # plus rien à réparer
    assert f.relances == 1


def test_relais_503_voix_en_cours(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import emissions_relais
    fichier = tmp_path / "voix.verrou"
    monkeypatch.setattr(emissions_relais, "VERROU", fichier)
    app = FastAPI()

    @app.post("/v1/chat/completions")
    def chat():
        return {"ok": True}

    @app.post("/api/v1/ai/moteur/demarrer")
    def demarrer():
        return {"ok": True}

    @app.get("/api/v1/ai/etat")
    def etat():
        return {"ok": True}

    emissions_relais.brancher(app, None)
    c = TestClient(app)
    assert c.post("/v1/chat/completions").status_code == 200
    fichier.write_text(json.dumps({"pid": 1, "cle": "secret-du-verrou"}))
    assert emissions_relais.voix_en_cours()
    r = c.post("/v1/chat/completions")
    assert r.status_code == 503 and r.json() == {"detail": "voix en cours"}
    assert c.post("/api/v1/ai/moteur/demarrer").status_code == 503
    assert c.post("/api/v1/ai/moteur/demarrer", headers={"X-Emissions-Cle": "secret-du-verrou"}).status_code == 200
    assert c.get("/api/v1/ai/etat").status_code == 200
    fichier.unlink()
    assert c.post("/v1/chat/completions").status_code == 200
