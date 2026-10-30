# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""L5 tâche 3 (#3126) : message HTTP vers l'agent d'une box, réponse HTTP_RESP (contrôleur)."""
import asyncio
import base64
import json

import pytest

from pilotage.files import (AgentHorsLigne, AuditIndisponible, DelaiHTTPDepasse, DemandeHTTPInvalide, Files,
                            ReponseHTTPInvalide, demander_http, portee_permise)
from tests.test_canal import GK5, LGM, client, monter


def run(coro):
    return asyncio.run(coro)


def sortie(statut=200, corps=b'{"ok":true}', entetes=None):
    return {"statut": statut, "entetes": entetes or {"Content-Type": "application/json"},
            "corps_b64": base64.b64encode(corps).decode()}


async def sonder(c, attente=1):
    r = await c.get(f"/canal/v1/requetes?attente={attente}")
    return r.json() if r.status_code == 200 else []


async def en_ligne(files, cle):
    """Un sondage en cours : l'agent est en ligne (comme le client Go, toujours en attente longue)."""
    t = asyncio.create_task(files.attendre_requetes(cle, 0.01))
    await t


def demande(**kw):
    d = dict(methode="GET", chemin="/api/v1/system/status?x=1", acteur="admin", maitre="gk2", portee="admin")
    d.update(kw)
    return d


def test_canal_transporte_une_requete_http():
    async def cas():
        app, files, stock, _ = monter(attente_max=1)
        async with client(app) as agent:
            await en_ligne(files, GK5.cle)
            t = asyncio.create_task(demander_http(files, GK5.cle, **demande(methode="POST", chemin="/api/v1/system/regler",
                                                                            corps=b'{"a":1}', entetes={"Content-Type": "application/json",
                                                                                                       "Cookie": "x", "Authorization": "y"})))
            [rq] = await sonder(agent)
            assert rq["type"] == "HTTP" and len(rq["msg_id"]) == 16
            b = rq["body"]
            assert set(b) == {"methode", "chemin", "entetes", "corps_b64", "acteur", "maitre", "portee", "version_page"}
            assert b["methode"] == "POST" and b["chemin"] == "/api/v1/system/regler" and b["portee"] == "admin"
            assert base64.b64decode(b["corps_b64"]) == b'{"a":1}'
            # seuls les en-têtes que le relais transmet partent ; jamais Cookie ni Authorization
            assert b["entetes"] == {"Content-Type": "application/json"}
            r = await agent.post("/canal/v1/http", json={"msg_id": rq["msg_id"], "type": "HTTP_RESP", "body": sortie(201, b"fait")})
            assert r.status_code == 200 and r.json() == {"ignore": 0}
            rep = await asyncio.wait_for(t, 2)
        assert rep == {"statut": 201, "entetes": {"Content-Type": "application/json"}, "corps": b"fait"}
        assert stock.resultats == []          # un corps de page n'est jamais rangé en base
        assert files.en_attente(GK5.cle) == 0
    run(cas())


def test_http_acteur_maitre_portee_invalides_refuses():
    async def cas():
        files = Files()
        await en_ligne(files, GK5.cle)
        for kw in (dict(acteur="ad min"), dict(acteur=""), dict(acteur="Admin"), dict(acteur="a" * 65), dict(maitre="gk2.secubox.in"),
                   dict(maitre="gk_2"), dict(acteur="adKmin"), dict(portee="tout"), dict(methode="TRACE"),
                   dict(chemin="/admin"), dict(chemin="/api/v1/x/\n"), dict(chemin="/api/v1/" + "a" * 5000)):
            with pytest.raises(DemandeHTTPInvalide) as e:
                await demander_http(files, GK5.cle, **demande(**kw))
            assert e.value.statut == 400, kw
        assert files.en_attente(GK5.cle) == 0
    run(cas())


def test_http_corps_trop_gros_413():
    async def cas():
        files = Files()
        await en_ligne(files, GK5.cle)
        with pytest.raises(DemandeHTTPInvalide) as e:
            await demander_http(files, GK5.cle, **demande(methode="POST", corps=b"a" * ((4 << 20) + 1)))
        assert e.value.statut == 413 and files.en_attente(GK5.cle) == 0
        with pytest.raises(DemandeHTTPInvalide) as e:
            await demander_http(files, GK5.cle, **demande(methode="GET", corps=b"a"))
        assert e.value.statut == 400
    run(cas())


def test_http_agent_hors_ligne():
    async def cas():
        files = Files()
        with pytest.raises(AgentHorsLigne):
            await demander_http(files, GK5.cle, **demande())
        assert files.en_attente(GK5.cle) == 0
        # un sondage récent suffit ; trop ancien : hors ligne
        f2 = Files(en_ligne_s=0.05)
        await en_ligne(f2, GK5.cle)
        await asyncio.sleep(0.1)
        with pytest.raises(AgentHorsLigne):
            await demander_http(f2, GK5.cle, **demande())
    run(cas())


def test_http_delai_504_et_nettoyage():
    async def cas():
        files = Files()
        await en_ligne(files, GK5.cle)
        with pytest.raises(DelaiHTTPDepasse):
            await demander_http(files, GK5.cle, **demande(), delai=0.05)
        assert files.en_attente(GK5.cle) == 0
        # servie mais sans réponse : nettoyée aussi
        t = asyncio.create_task(demander_http(files, GK5.cle, **demande(), delai=0.1))
        await asyncio.sleep(0.01)
        assert len(await files.attendre_requetes(GK5.cle, 0.01)) == 1
        with pytest.raises(DelaiHTTPDepasse):
            await t
        assert files.en_attente(GK5.cle) == 0
        # appelant parti (page fermée) : la requête est retirée
        t = asyncio.create_task(demander_http(files, GK5.cle, **demande()))
        await asyncio.sleep(0.01)
        assert files.en_attente(GK5.cle) == 1
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        assert files.en_attente(GK5.cle) == 0
    run(cas())


def test_http_deux_requetes_entrelacees():
    async def cas():
        app, files, _, _ = monter(attente_max=1)
        async with client(app) as agent:
            await en_ligne(files, GK5.cle)
            t1 = asyncio.create_task(demander_http(files, GK5.cle, **demande(chemin="/api/v1/system/un")))
            t2 = asyncio.create_task(demander_http(files, GK5.cle, **demande(chemin="/api/v1/system/deux")))
            await asyncio.sleep(0.01)
            rqs = await sonder(agent)
            assert len(rqs) == 2 and rqs[0]["msg_id"] != rqs[1]["msg_id"]
            par_chemin = {rq["body"]["chemin"]: rq["msg_id"] for rq in rqs}
            # réponses dans l'ordre inverse, la seconde par la liste /reponses (petite)
            await agent.post("/canal/v1/http", json={"msg_id": par_chemin["/api/v1/system/deux"], "type": "HTTP_RESP", "body": sortie(200, b"2")})
            r = await agent.post("/canal/v1/reponses", json=[{"msg_id": par_chemin["/api/v1/system/un"], "type": "HTTP_RESP", "body": sortie(200, b"1")}])
            assert r.json() == {"ignore": 0}
            assert (await t1)["corps"] == b"1" and (await t2)["corps"] == b"2"
    run(cas())


def test_http_reponse_orpheline_ou_d_un_autre_type_ignoree():
    async def cas():
        app, files, stock, _ = monter(attente_max=1)
        async with client(app) as agent, client(app, "10.64.0.9") as autre:
            r = await agent.post("/canal/v1/http", json={"msg_id": "0123456789abcdef", "type": "HTTP_RESP", "body": sortie()})
            assert r.status_code == 200 and r.json() == {"ignore": 1}
            # HTTP_RESP sur une requête GET : ignorée ; GET_RESP sur une requête HTTP : ignorée
            await en_ligne(files, GK5.cle)
            fut = files.deposer(GK5.cle, {"type": "GET", "body": {"paths": ["Device."]}})
            t = asyncio.create_task(demander_http(files, GK5.cle, **demande(), delai=0.5))
            await asyncio.sleep(0.01)
            rqs = {rq["type"]: rq["msg_id"] for rq in await sonder(agent)}
            r = await agent.post("/canal/v1/http", json={"msg_id": rqs["GET"], "type": "HTTP_RESP", "body": sortie()})
            assert r.json() == {"ignore": 1} and not fut.done()
            r = await agent.post("/canal/v1/reponses", json=[{"msg_id": rqs["HTTP"], "type": "GET_RESP", "body": {"results": []}}])
            assert r.json() == {"ignore": 1}
            # une autre box ne répond pas à sa place
            r = await autre.post("/canal/v1/http", json={"msg_id": rqs["HTTP"], "type": "HTTP_RESP", "body": sortie()})
            assert r.json() == {"ignore": 1}
            # formes bancales : jamais 500 ; une HTTP_RESP de champs bancals est remise, l'appelant reçoit une erreur claire
            assert (await agent.post("/canal/v1/http", json=[1])).status_code == 400
            r = await agent.post("/canal/v1/http", json={"msg_id": rqs["HTTP"], "type": "HTTP_RESP", "body": {"statut": "x"}})
            assert r.status_code == 200
            with pytest.raises(ReponseHTTPInvalide):
                await t
            fut.cancel()
        assert stock.resultats == []
    run(cas())


def test_http_erreur_de_l_agent_502():
    """Un agent ancien (sans HTTP) rend ERROR « type de requête inconnu » : erreur claire, pas un délai."""
    async def cas():
        app, files, _, _ = monter(attente_max=1)
        async with client(app) as agent:
            await en_ligne(files, GK5.cle)
            t = asyncio.create_task(demander_http(files, GK5.cle, **demande()))
            [rq] = await sonder(agent)
            await agent.post("/canal/v1/reponses", json=[{"msg_id": rq["msg_id"], "type": "ERROR", "body": {"err": "type de requête inconnu"}}])
            with pytest.raises(ReponseHTTPInvalide) as e:
                await t
            assert "type de requête inconnu" in str(e.value)
    run(cas())


def test_http_corps_volumineux_par_le_canal():
    async def cas():
        app, files, _, _ = monter(attente_max=1)
        gros = b"z" * (4 << 20)
        async with client(app) as agent:
            await en_ligne(files, GK5.cle)
            t = asyncio.create_task(demander_http(files, GK5.cle, **demande()))
            [rq] = await sonder(agent)
            r = await agent.post("/canal/v1/http", json={"msg_id": rq["msg_id"], "type": "HTTP_RESP", "body": sortie(200, gros)})
            assert r.status_code == 200
            assert (await t)["corps"] == gros
            trop = json.dumps({"msg_id": "0123456789abcdef", "type": "HTTP_RESP", "body": {"x": "a" * (7 << 20)}})
            assert (await agent.post("/canal/v1/http", content=trop)).status_code == 413
            # /reponses garde son plafond de 256 Kio
            r = await agent.post("/canal/v1/reponses", json=[{"msg_id": "0123456789abcdef", "type": "HTTP_RESP", "body": sortie(200, gros)}])
            assert r.status_code == 413
    run(cas())


def test_http_lots_bornes_pour_l_agent():
    """Deux corps de 4 Mio ne partent jamais dans le même sondage (l'agent lit au plus ~5,8 Mo)."""
    async def cas():
        files = Files()
        await en_ligne(files, GK5.cle)
        for _ in range(2):
            asyncio.create_task(demander_http(files, GK5.cle, **demande(methode="POST", corps=b"a" * (4 << 20)), delai=1))
        await asyncio.sleep(0.01)
        lot1 = await files.attendre_requetes(GK5.cle, 0.01)
        lot2 = await files.attendre_requetes(GK5.cle, 0.01)
        assert len(lot1) == 1 and len(lot2) == 1
        assert len(json.dumps(lot1)) < 5_854_552
    run(cas())


def test_http_audit_des_ecritures():
    async def cas():
        lignes = []
        files = Files()
        await en_ligne(files, GK5.cle)
        t = asyncio.create_task(demander_http(files, GK5.cle, **demande(methode="POST", chemin="/api/v1/system/x?secret=1", corps=b"{}"),
                                              audit=lambda ev, ch: lignes.append((ev, ch)), delai=1))
        [rq] = await files.attendre_requetes(GK5.cle, 0.5)
        files.livrer_reponse(GK5.cle, {"msg_id": rq["msg_id"], "type": "HTTP_RESP", "body": sortie(423, b"{}")})
        assert (await t)["statut"] == 423
        assert [e for e, _ in lignes] == ["pilotage_http", "pilotage_http"]
        assert lignes[0][1] == {"box": GK5.cle, "methode": "POST", "chemin": "/api/v1/system/x", "acteur": "admin", "maitre": "gk2",
                                "portee": "admin", "etat": "demande"}
        assert lignes[1][1]["etat"] == "rendu" and lignes[1][1]["statut"] == 423
        assert "secret" not in json.dumps(lignes)
        # lecture : pas d'audit (une page en fait des dizaines)
        lignes.clear()
        t = asyncio.create_task(demander_http(files, GK5.cle, **demande(), audit=lambda ev, ch: lignes.append(ev), delai=1))
        [rq] = await files.attendre_requetes(GK5.cle, 0.5)
        files.livrer_reponse(GK5.cle, {"msg_id": rq["msg_id"], "type": "HTTP_RESP", "body": sortie()})
        await t
        assert lignes == []

        def panne(ev, ch):
            raise OSError("disque plein")
        with pytest.raises(AuditIndisponible):
            await demander_http(files, GK5.cle, **demande(methode="DELETE"), audit=panne)
        assert files.en_attente(GK5.cle) == 0
    run(cas())


def test_portee_permise_ne_fait_que_reduire():
    """Portée demandée = ce que la session du maître autorise ; le contrôleur réduit (mains liées, box cliente sans support),
    l'agent réduit encore."""
    assert portee_permise("maillage", False, False, "admin") == "admin"
    assert portee_permise("maillage", False, False, "lecture") == "lecture"
    assert portee_permise("maillage", True, False, "admin") == "lecture"
    assert portee_permise("maillage", None, False, "admin") == "lecture"       # inconnu : fermé
    assert portee_permise("autoload", False, False, "admin") == "lecture"
    assert portee_permise("autoload", False, True, "admin") == "admin"
    assert portee_permise("autoload", True, True, "admin") == "lecture"
    with pytest.raises(ValueError):
        portee_permise("maillage", False, False, "root")
    assert LGM.reseau == "autoload"


def test_lire_reponse_http_refuse_les_formes_bancales():
    from pilotage.files import lire_reponse_http
    for rep in ({"type": "HTTP_RESP", "body": {"statut": 200, "corps_b64": "!!"}},
                {"type": "HTTP_RESP", "body": {"statut": True}}, {"type": "HTTP_RESP", "body": {"statut": 99}},
                {"type": "HTTP_RESP", "body": {"statut": 200, "entetes": {"a": 1}}}, {"type": "HTTP_RESP", "body": []}):
        with pytest.raises(ReponseHTTPInvalide):
            lire_reponse_http(rep)


def test_gabarit_nginx_ouvre_6_mio_pour_http_seulement():
    """L5 : seule /canal/v1/http accepte une HTTP_RESP de 6 Mio ; le reste du canal garde 256 Kio."""
    from pathlib import Path
    t = (Path(__file__).resolve().parents[1] / "nginx/pilotage-canal.conf.tpl").read_text()
    bloc = t[t.index("location = /canal/v1/http {"):]
    bloc = bloc[:bloc.index("}")]
    assert "client_max_body_size 6m;" in bloc
    assert "proxy_pass http://unix:/run/secubox/pilotage-canal.sock;" in bloc
    # imbriquée dans /canal/v1/ : les en-têtes posés (X-Real-IP, marqueur du tunnel) sont hérités, jamais redéfinis
    parent = t[t.index("location /canal/v1/ {"):t.index("location = /canal/v1/http {")]
    assert "proxy_set_header X-SecuBox-Pilotage-Tunnel 1;" in parent and "proxy_set_header" not in bloc
    assert t.count("client_max_body_size 6m;") == 1
