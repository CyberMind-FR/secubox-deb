# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#4037 : précache des lectures en double tampon de l'agrégateur (stale-while-revalidate).

Les âges sont simulés en reculant `fin` de l'entrée : aucune attente fixe, aucun seuil de temps réel."""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from aggregator import cache as c
from aggregator import main as agg


class _Module:
    """Sous-application témoin : compte ses calculs, peut échouer ou traîner sur commande."""

    def __init__(self):
        self.n = 0
        self.echec = False
        self.refus = False
        self.retard: asyncio.Event | None = None
        self.app = FastAPI()

        @self.app.get("/api/v1/demo/rapports")
        async def rapports(request: Request):
            self.n += 1
            if self.retard is not None:
                await self.retard.wait()
            if self.refus:
                return JSONResponse({"detail": "non"}, status_code=401)
            if self.echec:
                return JSONResponse({"detail": "panne"}, status_code=500)
            return {"n": self.n, "qui": request.headers.get("authorization", "")}

        @self.app.post("/api/v1/demo/ban")
        async def ban():
            return {"ok": True}

        @self.app.get("/api/v1/demo/events")
        async def events():
            self.n += 1
            return {"n": self.n}

        @self.app.get("/api/v1/demo/direct")
        async def flux():
            async def gen():
                yield b"data: 1\n\n"
            return StreamingResponse(gen(), media_type="text/event-stream")


async def _appel(app, chemin: str, methode: str = "GET", jeton: str = "A", entetes=()):
    scope = {"type": "http", "method": methode, "path": chemin, "raw_path": chemin.encode(), "query_string": b"",
             "headers": [(b"host", b"box"), (b"authorization", f"Bearer {jeton}".encode()), *entetes],
             "http_version": "1.1", "scheme": "http", "root_path": "", "client": ("127.0.0.1", 1),
             "server": ("box", 80), "state": {}}
    recu = {"statut": 0, "entetes": {}, "corps": b""}
    envoye = False

    async def receive():
        nonlocal envoye
        if not envoye:
            envoye = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)

    async def send(m):
        if m["type"] == "http.response.start":
            recu["statut"] = m["status"]
            recu["entetes"] = {bytes(k).decode().lower(): bytes(v).decode() for k, v in m["headers"]}
        elif m["type"] == "http.response.body":
            recu["corps"] += m.get("body", b"")

    await app(scope, receive, send)
    return recu


def _etat(r) -> str:
    return r["entetes"].get("x-sbx-cache", "").split(";")[0]


def _n(r) -> int:
    return json.loads(r["corps"])["n"]


def _vieillir(cache: c.CacheLecture, secondes: float) -> None:
    for e in cache._entrees.values():
        e.fin -= secondes


async def _attendre_recalculs(cache: c.CacheLecture) -> None:
    while cache._en_cours:
        await asyncio.gather(*cache._en_cours.values(), return_exceptions=True)


def _banc(**reglages):
    m = _Module()
    cache = c.CacheLecture(m.app, c.Reglages(**reglages))
    return m, cache


def test_absente_puis_fraiche():
    async def scenario():
        m, cache = _banc()
        r1 = await _appel(cache, "/api/v1/demo/rapports")
        assert _etat(r1) == "absent" and _n(r1) == 1
        r2 = await _appel(cache, "/api/v1/demo/rapports")
        assert _etat(r2) == "frais" and _n(r2) == 1 and m.n == 1
        assert "x-sbx-cache-age" in r2["entetes"] and "x-sbx-cache-date" in r2["entetes"]
    asyncio.run(scenario())


def test_perimee_servie_aussitot_puis_recalculee():
    async def scenario():
        m, cache = _banc()
        await _appel(cache, "/api/v1/demo/rapports")
        _vieillir(cache, 61)  # TTL de « rapports » = 60 s
        m.retard = asyncio.Event()
        r = await _appel(cache, "/api/v1/demo/rapports")
        assert _etat(r) == "perime" and _n(r) == 1      # servie sans attendre le calcul bloqué
        assert r["entetes"]["x-sbx-cache"].startswith("perime; age=")
        m.retard.set()
        await _attendre_recalculs(cache)
        r = await _appel(cache, "/api/v1/demo/rapports")
        assert _etat(r) == "frais" and _n(r) == 2
    asyncio.run(scenario())


def test_un_seul_recalcul_concurrent_par_cle():
    async def scenario():
        m, cache = _banc()
        await _appel(cache, "/api/v1/demo/rapports")
        _vieillir(cache, 61)
        m.retard = asyncio.Event()
        for _ in range(5):
            assert _etat(await _appel(cache, "/api/v1/demo/rapports")) == "perime"
        await asyncio.sleep(0)
        assert len(cache._en_cours) == 1
        m.retard.set()
        await _attendre_recalculs(cache)
        assert m.n == 2  # 1 calcul initial + 1 seul recalcul
    asyncio.run(scenario())


def test_isolation_par_identite():
    async def scenario():
        m, cache = _banc()
        ra = await _appel(cache, "/api/v1/demo/rapports", jeton="A")
        rb = await _appel(cache, "/api/v1/demo/rapports", jeton="B")
        assert _etat(rb) == "absent" and json.loads(rb["corps"])["qui"] == "Bearer B"
        assert json.loads(ra["corps"])["qui"] == "Bearer A"
        # Même jeton, autre adresse cliente (zones LAN/maillage) : autre clé.
        rc = await _appel(cache, "/api/v1/demo/rapports", jeton="A", entetes=[(b"x-real-ip", b"10.0.0.9")])
        assert _etat(rc) == "absent"
        assert len(cache._entrees) == 3
    asyncio.run(scenario())


def test_erreur_n_ecrase_pas_la_bonne_reponse():
    async def scenario():
        m, cache = _banc()
        await _appel(cache, "/api/v1/demo/rapports")
        _vieillir(cache, 61)
        m.echec = True
        assert _etat(await _appel(cache, "/api/v1/demo/rapports")) == "perime"
        await _attendre_recalculs(cache)
        r = await _appel(cache, "/api/v1/demo/rapports")
        assert r["statut"] == 200 and _n(r) == 1   # toujours la bonne, toujours périmée
        assert _etat(r) == "perime"
    asyncio.run(scenario())


def test_refus_401_au_recalcul_retire_l_entree():
    async def scenario():
        m, cache = _banc()
        await _appel(cache, "/api/v1/demo/rapports")
        _vieillir(cache, 61)
        m.refus = True
        await _appel(cache, "/api/v1/demo/rapports")
        await _attendre_recalculs(cache)
        assert not cache._entrees
        r = await _appel(cache, "/api/v1/demo/rapports")
        assert r["statut"] == 401
    asyncio.run(scenario())


def test_ecriture_invalide_le_module():
    async def scenario():
        m, cache = _banc()
        await _appel(cache, "/api/v1/demo/rapports")
        r = await _appel(cache, "/api/v1/demo/ban", methode="POST")
        assert r["statut"] == 200 and "x-sbx-cache" not in r["entetes"]
        r = await _appel(cache, "/api/v1/demo/rapports")
        assert _etat(r) == "frais" and _n(r) == 2   # recalculé dans le délai synchrone
    asyncio.run(scenario())


def test_invalidee_et_calcul_trop_long_sert_la_vieille():
    async def scenario():
        m, cache = _banc(delai_synchrone=0.01)
        await _appel(cache, "/api/v1/demo/rapports")
        cache.invalider_module("demo")
        m.retard = asyncio.Event()
        r = await _appel(cache, "/api/v1/demo/rapports")
        assert _etat(r) == "perime" and _n(r) == 1
        m.retard.set()
        await _attendre_recalculs(cache)
        assert _n(await _appel(cache, "/api/v1/demo/rapports")) == 2
    asyncio.run(scenario())


def test_recalcul_d_avant_l_ecriture_n_est_pas_range():
    async def scenario():
        m, cache = _banc()
        await _appel(cache, "/api/v1/demo/rapports")
        _vieillir(cache, 61)
        m.retard = asyncio.Event()
        await _appel(cache, "/api/v1/demo/rapports")   # recalcul lancé, bloqué
        await _appel(cache, "/api/v1/demo/ban", methode="POST")
        m.retard.set()
        await _attendre_recalculs(cache)
        assert all(e.invalide for e in cache._entrees.values())
    asyncio.run(scenario())


def test_exclusions_par_defaut_et_toml():
    async def scenario():
        m, cache = _banc(exclus=["demo/rapports"])
        await _appel(cache, "/api/v1/demo/rapports")
        await _appel(cache, "/api/v1/demo/events")
        r = await _appel(cache, "/api/v1/demo/direct")   # flux SSE non déclaré : relayé tel quel, jamais gardé
        assert r["corps"] == b"data: 1\n\n" and r["entetes"]["content-type"].startswith("text/event-stream")
        assert not cache._entrees
    asyncio.run(scenario())
    cache = c.CacheLecture(None, c.Reglages.depuis_toml({"ttl": {"waf": 30, "waf/categories": 0}}))
    assert cache.ttl_pour("waf", "categories") == 0
    assert cache.ttl_pour("waf", "status") == 30
    assert cache.ttl_pour("auth", "users") == 0
    assert cache.ttl_pour("metrics", "health") == 0
    assert cache.ttl_pour("hub", "status") == 5
    assert cache.ttl_pour("hub", "x") == 15


def test_reponse_non_json_ou_cookie_jamais_gardee():
    async def scenario():
        m = _Module()

        @m.app.get("/api/v1/demo/page")
        async def page():
            r = JSONResponse({"n": 1})
            r.set_cookie("s", "x")
            return r

        cache = c.CacheLecture(m.app, c.Reglages())
        await _appel(cache, "/api/v1/demo/page")
        assert not cache._entrees
    asyncio.run(scenario())


def test_borne_lru():
    async def scenario():
        m, cache = _banc(entrees_max=3)
        for j in "ABCDE":
            await _appel(cache, "/api/v1/demo/rapports", jeton=j)
        assert len(cache._entrees) == 3
        await _appel(cache, "/api/v1/demo/rapports", jeton="C")      # C redevient récente
        await _appel(cache, "/api/v1/demo/rapports", jeton="F")
        restes = [json.loads(e.corps)["qui"] for e in cache._entrees.values()]
        assert "Bearer C" in restes and "Bearer D" not in restes
        assert cache._octets == sum(cache._poids(e) for e in cache._entrees.values())
        _m, petit = _banc(octets_max=600)
        for j in "ABCDE":
            await _appel(petit, "/api/v1/demo/rapports", jeton=j)
        assert petit._octets <= 600
    asyncio.run(scenario())


def test_plafond_de_recalculs():
    async def scenario():
        m, cache = _banc(recalculs_max=1)
        for j in "AB":
            await _appel(cache, "/api/v1/demo/rapports", jeton=j)
        _vieillir(cache, 61)
        m.retard = asyncio.Event()
        assert _etat(await _appel(cache, "/api/v1/demo/rapports", jeton="A")) == "perime"
        assert _etat(await _appel(cache, "/api/v1/demo/rapports", jeton="B")) == "perime"
        assert cache.compteurs["recalculs_refuses"] == 1
        m.retard.set()
        await _attendre_recalculs(cache)
        await cache.fermer()
    asyncio.run(scenario())


def test_contournement_et_desactivation():
    async def scenario():
        m, cache = _banc()
        await _appel(cache, "/api/v1/demo/rapports")
        r = await _appel(cache, "/api/v1/demo/rapports", entetes=[(b"x-sbx-cache", b"contourner")])
        assert _n(r) == 2
        _m, inactif = _banc(actif=False)
        await _appel(inactif, "/api/v1/demo/rapports")
        assert not inactif._entrees
    asyncio.run(scenario())


def test_agregateur_monte_le_cache(tmp_path, monkeypatch):
    toml = tmp_path / "aggregator.toml"
    toml.write_text('modules = []\n[cache]\nttl_defaut = 7\n[cache.ttl]\n"waf/categories" = 120\n')
    monkeypatch.setattr(agg, "CONFIG_FILE", toml)
    app = agg._build_app()
    app.build_middleware_stack()
    assert c.INSTANCE is not None and c.INSTANCE.r.ttl_defaut == 7
    assert c.INSTANCE.ttl_pour("waf", "categories") == 120


@pytest.fixture(autouse=True)
def _remise():
    yield
    c.INSTANCE = None
