# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Application FastAPI du canal : identité, cloisonnement, bornes, protocole du client Go (#3126)."""
import asyncio
import json

import httpx
import pytest

from api.canal import creer_app_canal
from pilotage.files import Files
from pilotage.identite import Box
from pilotage.stockage import StockageMemoire

GK5 = Box("gk5", "10.10.0.10", "maillage", None, None)
LGM = Box("lgm-10.64.0.9", "10.64.0.9", "autoload", "lgm", "actif")
CONNUES = {GK5.adresse: GK5, LGM.adresse: LGM}


def monter(**kw):
    audits = []
    files = kw.pop("files", None) or Files()
    stock = StockageMemoire()
    app = creer_app_canal(files, CONNUES.get, stock, lambda ev, champs: audits.append((ev, champs)), **kw)
    return app, files, stock, audits


def client(app, ip="10.10.0.10", **kw):
    h = {"X-Real-IP": ip} if ip else {}
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://m", headers=h, **kw)


def run(coro):
    return asyncio.run(coro)


def test_canal_refuse_une_adresse_inconnue():
    async def cas():
        app, _, stock, audits = monter()
        async with client(app, "10.10.0.200") as c:
            r = await c.get("/canal/v1/requetes?attente=0")
            assert r.status_code == 403
            assert (await c.post("/canal/v1/bonjour", json={})).status_code == 403
        assert audits[0] == ("pilotage_identite_refusee", {"adresse": "10.10.0.200"})
        assert len(audits) == 2 and stock.vus == []
    run(cas())


def test_canal_identite_seulement_par_x_real_ip():
    async def cas():
        app, _, _, audits = monter()
        # sans en-tête : le pair de la socket ne compte pour rien
        async with client(app, None) as c:
            assert (await c.get("/canal/v1/requetes?attente=0")).status_code == 403
        # en-tête en double
        async with client(app, None) as c:
            h = [("X-Real-IP", "10.10.0.10"), ("X-Real-IP", "10.64.0.9")]
            assert (await c.get("/canal/v1/requetes?attente=0", headers=h)).status_code == 403
        # adresse invalide, avec bourrage
        async with client(app, "10.10.0.10, 1.2.3.4") as c:
            assert (await c.get("/canal/v1/requetes?attente=0")).status_code == 403
        async with client(app, "x" * 500) as c:
            assert (await c.get("/canal/v1/requetes?attente=0")).status_code == 403
        assert len(audits) == 4
        assert all(ev == "pilotage_identite_refusee" for ev, _ in audits)
        assert all(len(ch.get("adresse", "")) <= 64 for _, ch in audits)
        assert set(audits[0][1]) == {"adresse"}
    run(cas())


def test_canal_cloisonne_les_files():
    async def cas():
        app, files, stock, _ = monter(attente_max=0.05)
        fut = files.deposer(GK5.cle, {"type": "GET", "body": {"paths": ["Device."]}})
        async with client(app, "10.64.0.9") as lgm, client(app, "10.10.0.10") as gk5:
            assert (await lgm.get("/canal/v1/requetes?attente=1")).status_code == 204
            r = await gk5.get("/canal/v1/requetes?attente=1")
            assert r.status_code == 200
            [rq] = r.json()
            assert set(rq) == {"msg_id", "type", "body"} and rq["body"] == {"paths": ["Device."]}
            rep = [{"msg_id": rq["msg_id"], "type": "GET_RESP", "body": {"results": []}}]
            r = await lgm.post("/canal/v1/reponses", json=rep)
            assert r.status_code == 200 and r.json() == {"ignore": 1}
            assert not fut.done() and stock.resultats == []
            r = await gk5.post("/canal/v1/reponses", json=rep)
            assert r.status_code == 200 and r.json() == {"ignore": 0}
        assert (await fut)["type"] == "GET_RESP"
        assert stock.resultats == [(GK5, rq["msg_id"], rep[0])]
    run(cas())


def test_canal_ignore_une_reponse_inconnue():
    async def cas():
        app, _, stock, _ = monter()
        async with client(app) as c:
            r = await c.post("/canal/v1/reponses", json=[{"msg_id": "0123456789abcdef", "type": "GET_RESP", "body": {}}])
            assert r.status_code == 200 and r.json() == {"ignore": 1}
            # formes bancales : jamais 500
            for corps in ([42, None, "x", {"msg_id": 7}, {"msg_id": "0123456789abcdef", "type": "PAGE", "body": {}}], []):
                r = await c.post("/canal/v1/reponses", json=corps)
                assert r.status_code == 200
            assert (await c.post("/canal/v1/reponses", content=b"{pas du json")).status_code == 400
            assert (await c.post("/canal/v1/reponses", json={"msg_id": "a"})).status_code == 400
        assert stock.resultats == []
    run(cas())


def test_canal_attente_longue_rend_204():
    async def cas():
        app, _, stock, _ = monter(attente_max=0.1)
        async with client(app) as c:
            t0 = asyncio.get_running_loop().time()
            r = await c.get("/canal/v1/requetes?attente=3600")  # borné à attente_max
            assert r.status_code == 204 and r.content == b""
            assert asyncio.get_running_loop().time() - t0 < 2
            assert (await c.get("/canal/v1/requetes?attente=abc")).status_code == 204
            assert (await c.get("/canal/v1/requetes?attente=-5")).status_code == 204
        assert len(stock.vus) == 3  # chaque sondage est un signe de vie
    run(cas())


def test_canal_borne_par_defaut_a_25_s():
    async def cas():
        from api import canal
        assert canal.ATTENTE_MAX_S == 25 and canal.TAILLE_MAX == 256 << 10
    run(cas())


def test_canal_refuse_un_corps_trop_gros():
    async def cas():
        app, _, stock, _ = monter()
        async with client(app) as c:
            gros = json.dumps([{"msg_id": "0123456789abcdef", "type": "GET_RESP", "body": {"x": "a" * (300 << 10)}}])
            assert (await c.post("/canal/v1/reponses", content=gros)).status_code == 413
            # sans Content-Length (flux découpé) : refusé en cours de lecture
            lus = []

            async def morceaux():
                for _ in range(100):
                    lus.append(1)
                    yield b"a" * 16384
            assert (await c.post("/canal/v1/notifs", content=morceaux())).status_code == 413
            assert len(lus) < 100
            ok = json.dumps([{"msg_id": "0123456789abcdef", "type": "GET_RESP", "body": {"x": "a" * (200 << 10)}}])
            assert (await c.post("/canal/v1/reponses", content=ok)).status_code == 200
        assert stock.vus == []
    run(cas())


def test_canal_rejoue_l_echange_du_client_go():
    async def cas():
        app, files, stock, _ = monter(attente_max=0.05)
        fut_get = files.deposer(GK5.cle, {"type": "GET", "body": {"paths": ["Device.DeviceInfo."]}})
        fut_dm = files.deposer(GK5.cle, {"type": "GET_SUPPORTED_DM", "body": {}})
        fut_op = files.deposer(GK5.cle, {"type": "OPERATE", "body": {"command": "Device.X_SECUBOX_Releve.Mesurer()", "args": {"duree_s": 60}}})
        async with client(app) as c:
            r = await c.post("/canal/v1/bonjour", json={
                "agent_version": "0.1.0", "boot_id": "b00t-1234", "modele": ["Device.DeviceInfo.", "Device.X_SECUBOX_Boot."]})
            assert r.status_code == 200
            r = await c.get("/canal/v1/requetes?attente=25")
            assert r.status_code == 200
            lus = r.json()
            assert [q["type"] for q in lus] == ["GET", "GET_SUPPORTED_DM", "OPERATE"]
            ids = [q["msg_id"] for q in lus]
            # corps de réponse tels que l'agent les produit (client.go)
            reps = [
                {"msg_id": ids[0], "type": "GET_RESP", "body": {"results": [
                    {"path": "Device.DeviceInfo.", "params": {"Device.DeviceInfo.SoftwareVersion": "1.2.3"}, "err": ""}], "tronque": True}},
                {"msg_id": ids[1], "type": "GET_SUPPORTED_DM_RESP", "body": {"paths": ["Device.DeviceInfo."]}},
                {"msg_id": ids[2], "type": "OPERATE_RESP", "body": {"output": {"duree_s": 60}}},
            ]
            r = await c.post("/canal/v1/reponses", content=json.dumps(reps, separators=(",", ":")))
            assert r.status_code == 200 and r.json() == {"ignore": 0}
            # un ERROR clôt aussi la requête
            fut_err = files.deposer(GK5.cle, {"type": "GET", "body": {"paths": ["x"]}})
            [q] = (await c.get("/canal/v1/requetes?attente=1")).json()
            r = await c.post("/canal/v1/reponses", json=[{"msg_id": q["msg_id"], "type": "ERROR", "body": {"err": "chemin invalide"}}])
            assert r.json() == {"ignore": 0}
            lot = [{"type": "NOTIFY", "body": {"event": {"path": "Device.X_SECUBOX_Boot.", "boot_id": "b00t-1234"}}}] * 16
            r = await c.post("/canal/v1/notifs", json=lot)
            assert r.status_code == 200 and r.json() == {"ignore": 0}
        assert (await fut_get)["body"]["tronque"] is True
        assert (await fut_dm)["type"] == "GET_SUPPORTED_DM_RESP"
        assert (await fut_op)["body"]["output"] == {"duree_s": 60}
        assert (await fut_err)["type"] == "ERROR"
        assert stock.vus[0][1]["agent_version"] == "0.1.0" and stock.vus[0][1]["boot_id"] == "b00t-1234"
        assert stock.vus[0][1]["modele"] == ["Device.DeviceInfo.", "Device.X_SECUBOX_Boot."]
        assert len(stock.notifications) == 16 and stock.notifications[0][0] == GK5
        assert stock.notifications[0][1] == {"path": "Device.X_SECUBOX_Boot.", "boot_id": "b00t-1234"}
    run(cas())


def test_canal_notifs_bornees_et_filtrees():
    async def cas():
        app, _, stock, _ = monter()
        async with client(app) as c:
            ev = {"type": "NOTIFY", "body": {"event": {"a": 1}}}
            assert (await c.post("/canal/v1/notifs", json=[ev] * 17)).status_code == 413
            r = await c.post("/canal/v1/notifs", json=[ev, {"type": "AUTRE"}, 7, {"type": "NOTIFY", "body": {"event": "x"}}])
            assert r.status_code == 200 and r.json() == {"ignore": 3}
            assert (await c.post("/canal/v1/notifs", json={"type": "NOTIFY"})).status_code == 400
        assert len(stock.notifications) == 1
    run(cas())


def test_canal_liste_de_reponses_bornee():
    async def cas():
        app, _, _, _ = monter()
        async with client(app) as c:
            rep = {"msg_id": "0123456789abcdef", "type": "GET_RESP", "body": {}}
            assert (await c.post("/canal/v1/reponses", json=[rep] * 65)).status_code == 413
    run(cas())


def test_canal_file_pleine_refus_propre_cote_depot():
    async def cas():
        files = Files(max_par_box=1)
        monter(files=files)
        files.deposer(GK5.cle, {"type": "GET", "body": {}})
        from pilotage.files import FileDeBoxPleine
        with pytest.raises(FileDeBoxPleine):
            files.deposer(GK5.cle, {"type": "GET", "body": {}})
    run(cas())


def test_canal_ne_prend_jamais_l_adresse_du_pair_socket():
    async def cas():
        app, _, _, audits = monter()
        # un client qui se dit 10.10.0.10 par le transport mais sans X-Real-IP reste refusé
        tr = httpx.ASGITransport(app=app, client=("10.10.0.10", 1234))
        async with httpx.AsyncClient(transport=tr, base_url="http://m") as c:
            assert (await c.get("/canal/v1/requetes?attente=0")).status_code == 403
        assert audits
    run(cas())


def test_canal_meme_nom_sur_deux_reseaux_ne_partage_rien():
    async def cas():
        gk5_auto = Box("gk5", "10.64.0.20", "autoload", "lgm", "actif")
        assert gk5_auto.cle == "autoload:gk5" and GK5.cle == "maillage:gk5"
        connues = {**CONNUES, gk5_auto.adresse: gk5_auto}
        files, stock = Files(), StockageMemoire()
        app = creer_app_canal(files, connues.get, stock, lambda *a: None, attente_max=0.05)
        fut = files.deposer(GK5.cle, {"type": "GET", "body": {"paths": ["Device."]}})
        async with client(app, "10.64.0.20") as auto, client(app, "10.10.0.10") as mesh:
            assert (await auto.get("/canal/v1/requetes?attente=1")).status_code == 204
            [rq] = (await mesh.get("/canal/v1/requetes?attente=1")).json()
            rep = [{"msg_id": rq["msg_id"], "type": "GET_RESP", "body": {}}]
            assert (await auto.post("/canal/v1/reponses", json=rep)).json() == {"ignore": 1}
            assert not fut.done() and stock.par_cle == {}
            assert (await mesh.post("/canal/v1/reponses", json=rep)).json() == {"ignore": 0}
        assert fut.done() and list(stock.par_cle) == ["maillage:gk5"]
    run(cas())
