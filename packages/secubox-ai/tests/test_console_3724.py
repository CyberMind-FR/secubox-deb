# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Onglets Dossier et Réponses de la console /ai/ (#3724) : routes du dossier, décisions humaines (redescendre,
analyser à nouveau, défaire), envoi de la levée par l'exécuteur, rendu de la page.

Aucun réseau : gk2 est le gk2 simulé de test_executeur_3723 (vraie garde ai-ban, vrais modèles Pydantic de gk2).
"""
import asyncio
import json
import re
import secrets
import shutil
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import Depends, HTTPException, Request

from secubox_core import compte_service as cs
from veille import base, correlation, decisions, dossiers, executeur
from veille.client import ROUTES_DEFAUT, ROUTES_GESTES, ClientGk2
from veille.regles import iso
from test_executeur_3723 import (G, TABLE, _action, _etat, _maintenant, _prop, _tour, banc)  # noqa: F401
from test_veille_correlation_3721 import T0, _auth, _waf

PAQUET = Path(__file__).resolve().parents[1]
PAGE = PAQUET / "www" / "ai" / "index.html"
A = "45.83.64.10"


@pytest.fixture
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from secubox_core.auth import require_jwt
    from api.main import app
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path))
    db = base.ouvrir(tmp_path / "veille.db")
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        yield TestClient(app), db
    finally:
        app.dependency_overrides.pop(require_jwt, None)
        db.close()


def _dossier_reel(db, ip=A):
    """Un vrai dossier d'acteur : WAF + authwatch = 2 couches → niveau contenir."""
    _waf(db, ip, T0 - timedelta(minutes=12), cat="scanners:x", sev="medium")
    _waf(db, ip, T0 - timedelta(minutes=10), cat="sqli:union", sev="high")
    _auth(db, ip, T0 - timedelta(minutes=5), "smtp")
    correlation.correler(db, T0)
    dossiers.construire(db, T0)
    db.commit()
    return db.execute("SELECT id FROM dossiers WHERE cle = ?", (ip,)).fetchone()[0]


def _action_faite(db, pid, geste, cible, id_gk2=None, fin=None):
    aid = secrets.token_hex(8)
    db.execute("INSERT INTO actions(id, proposition_id, geste, cible, mode, etat, jti, cle, code_http, id_gk2, fin_gk2, "
               "envoyee_le, repondue_le) VALUES (?, ?, ?, ?, 'auto', 'faite', ?, 'kid', 200, ?, ?, ?, ?)",
               (aid, pid, geste, cible, secrets.token_hex(8), id_gk2 or secrets.token_hex(16),
                fin if fin is not None else int(_maintenant().timestamp()) + 3600, iso(_maintenant()),
                iso(_maintenant())))
    db.execute("UPDATE propositions SET etat = 'faite' WHERE id = ?", (pid,))
    return aid


# ── routes gardées ──

ROUTES_3724 = {("GET", "/dossiers"), ("GET", "/dossiers/{did}"), ("POST", "/dossiers/{did}/redescendre"),
               ("POST", "/dossiers/{did}/analyser"), ("POST", "/actions/{aid}/defaire")}


def test_routes_declarees_et_gardees():
    from fastapi.routing import APIRoute
    from secubox_core.auth import require_jwt
    from api.main import app
    routes = {(m, r.path): r for r in app.routes if isinstance(r, APIRoute) for m in r.methods}
    assert ROUTES_3724 <= set(routes)
    for cle in ROUTES_3724:
        assert require_jwt in [d.call for d in routes[cle].dependant.dependencies], cle


def test_refus_sans_jeton():
    from fastapi.testclient import TestClient
    from api.main import app
    c = TestClient(app)
    for methode, chemin in (("GET", "/dossiers"), ("GET", "/dossiers/x"), ("POST", "/dossiers/x/redescendre"),
                            ("POST", "/dossiers/x/analyser"), ("POST", "/actions/x/defaire")):
        assert c.request(methode, chemin).status_code in (401, 403), chemin


def test_sans_veille_db_503_jamais_creee(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from secubox_core.auth import require_jwt
    from api.main import app
    monkeypatch.setenv("SECUBOX_AI_ETAT", str(tmp_path / "vide"))
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        c = TestClient(app)
        assert c.get("/dossiers").status_code == 503
        assert c.get("/dossiers/x").status_code == 503
        assert c.post("/actions/x/defaire").status_code == 503
        assert not (tmp_path / "vide" / "veille.db").exists()
    finally:
        app.dependency_overrides.pop(require_jwt, None)


# ── GET /dossiers : pagination ──

def test_liste_pagination_par_curseur_500_au_plus(api):
    c, db = api
    for i in range(7):
        h = iso(T0 - timedelta(minutes=i))
        db.execute("INSERT INTO dossiers(id, cle, type, gravite, premiere_vue, derniere_vue, maj_le, niveau) VALUES "
                   "(?, ?, 'acteur', 'high', ?, ?, ?, ?)", (f"d{i}", f"203.0.113.{i}", h, h, h,
                                                             "usager" if i % 2 else "observer"))
    db.commit()
    r = c.get("/dossiers", params={"limite": 3}).json()
    assert [d["id"] for d in r["dossiers"]] == ["d0", "d1", "d2"] and r["curseur"]
    r2 = c.get("/dossiers", params={"limite": 3, "curseur": r["curseur"]}).json()
    assert [d["id"] for d in r2["dossiers"]] == ["d3", "d4", "d5"]
    assert c.get("/dossiers", params={"limite": 3, "curseur": r2["curseur"]}).json()["curseur"] is None
    assert len(c.get("/dossiers").json()["dossiers"]) == 7                     # défaut : 100
    assert c.get("/dossiers", params={"limite": 500}).status_code == 200
    assert c.get("/dossiers", params={"limite": 501}).status_code == 422
    assert c.get("/dossiers", params={"limite": 0}).status_code == 422
    assert c.get("/dossiers", params={"curseur": "x'; DROP"}).status_code == 422
    assert [d["id"] for d in c.get("/dossiers", params={"niveau": "usager"}).json()["dossiers"]] == ["d1", "d3", "d5"]
    assert c.get("/dossiers", params={"niveau": "riposte"}).status_code == 422
    ligne = r["dossiers"][0]
    assert set(ligne) >= {"id", "cle", "type", "gravite", "niveau", "niveau_depuis", "premiere_vue", "derniere_vue"}


# ── GET /dossiers/{id} : vue complète ──

def test_detail_chronologie_etapes_niveau_analyse_gestes(api):
    c, db = api
    did = _dossier_reel(db)
    db.execute("INSERT INTO analyses(id, dossier_id, etat, version_prompt, moteur, resume, lecture, preuves_json, "
               "manques_json, cree_le) VALUES ('an1', ?, 'valide', 'analyste-v1', 'gk0', 'résumé', 'lecture', "
               "'[{\"id\": \"e\"}]', '[\"JA4\"]', ?)", (did, iso(T0)))
    ban = _prop(db, cible=A, dossier=did, mode="auto")
    aid = _action_faite(db, ban, "ban", A)
    db.commit()
    d = c.get(f"/dossiers/{did}").json()
    assert d["dossier"]["cle"] == A and d["dossier"]["niveau"] == "contenir" and d["dossier"]["adresses"] == [A]
    chrono = d["chronologie"]
    assert len(chrono) == 3 and [e["horodatage"] for e in chrono] == sorted(e["horodatage"] for e in chrono)
    assert {e["couche"] for e in chrono} == {"waf", "auth"}                     # couche calculée par le code
    assert all(re.fullmatch(r"[0-9a-f-]{8,64}", e["id"]) for e in chrono)
    assert any(e["etape"] == "exploitation" for e in chrono)
    etapes = {e["etape"]: e for e in d["etapes"]}
    assert list(etapes) == ["reperage", "essais", "exploitation", "persistance"]
    assert etapes["persistance"]["atteinte"] is False and etapes["exploitation"]["atteinte"] is True
    n = d["niveau"]
    assert n["niveau"] == "contenir" and n["signaux"]["couches"] == 2 and n["signaux"]["tentatives"] == 3
    assert n["seuils"] == {"n2_tentatives": 20, "n3_tentatives": 100}            # écrits par la veille
    assert [h["vers"] for h in n["historique"]] == ["contenir"] and n["redescente_en_attente"] is False
    a = d["analyse"]
    assert a["etat"] == "valide" and a["preuves"] == 1 and a["manques"] == ["JA4"] and a["moteur"] == "gk0"
    [g] = d["gestes"]
    assert g["proposition"]["id"] == ban and g["action"]["id"] == aid and g["action"]["code_http"] == 200
    assert g["action"]["effet"] is None                                          # jamais inventé
    assert g["defaire"] == {"possible": True, "action_id": aid, "raison": None, "partages": []}
    assert c.get("/dossiers/inconnu").status_code == 404


def test_prolongation_jamais_defaite_le_ban_prolonge_si(api):
    """Revue 1 : une prolongation n'a pas de « Défaire » (409 `prolongation`) ; le ban prolongé reste défaisable
    après sa fin d'origine (fin = la plus tardive de ses prolongations faites, comme l'exécuteur)."""
    c, db = api
    did = _dossier_reel(db)
    m = int(_maintenant().timestamp())
    ban = _prop(db, cible=A, dossier=did)
    aid = _action_faite(db, ban, "ban", A, fin=m - 10 * 3600)                  # ban 24 h posé il y a 34 h
    pro = _prop(db, geste="prolonger", cible=A, dossier=did, reference=ban, duree=4 * 86400)
    pid = _action_faite(db, pro, "prolonger", A, fin=m + 86 * 3600)            # prolongé à h20 de 4 j
    db.commit()
    gestes = {g["proposition"]["geste"]: g for g in c.get(f"/dossiers/{did}").json()["gestes"]}
    assert gestes["prolonger"]["defaire"] == {"possible": False, "action_id": None, "raison": "prolongation"}
    assert gestes["ban"]["defaire"]["possible"] is True and gestes["ban"]["defaire"]["action_id"] == aid
    r = c.post(f"/actions/{pid}/defaire")
    assert r.status_code == 409 and r.json()["detail"]["motif"] == "prolongation"
    assert c.post(f"/actions/{aid}/defaire").status_code == 200                # à h30 : gk2 le tient encore
    assert executeur._fin_ban is decisions.fin_geste                            # une seule règle, partagée


def test_ban_avec_partage_vivant_signale_jamais_retire_seul(api):
    """Revue 1 : lever un ban dont l'adresse a un indicateur partagé le SIGNALE ; le retrait est une seconde levée,
    seulement si l'administrateur la demande (deux levées vivantes de la même cible sont permises)."""
    c, db = api
    did = _dossier_reel(db)
    ban = _prop(db, cible=A, dossier=did)
    aid = _action_faite(db, ban, "ban", A)
    par = _prop(db, geste="partager", cible=A, dossier=did, duree=7 * 86400)
    paid = _action_faite(db, par, "partager", A)
    db.commit()
    g = next(x for x in c.get(f"/dossiers/{did}").json()["gestes"] if x["proposition"]["id"] == ban)
    assert g["defaire"]["partages"] == [{"action_id": paid, "cible": A}]
    lev = c.post(f"/actions/{aid}/defaire").json()["proposition"]
    assert db.execute("SELECT COUNT(*) FROM propositions WHERE geste = 'unban'").fetchone()[0] == 1   # rien de seul
    r = c.post(f"/actions/{paid}/defaire")
    assert r.status_code == 200, r.text
    refs = {x for (x,) in db.execute("SELECT reference FROM propositions WHERE geste = 'unban' AND etat = 'approuvee'")}
    assert refs == {ban, par} and lev


# ── POST /dossiers/{id}/redescendre : décision humaine, appliquée par la veille ──

def test_redescendre_ecrit_la_decision_la_veille_l_applique(api):
    c, db = api
    did = _dossier_reel(db)
    assert c.post("/dossiers/inconnu/redescendre").status_code == 404
    r = c.post(f"/dossiers/{did}/redescendre")
    assert r.status_code == 200 and r.json() == {"dossier": did, "etat": "en_attente"}
    assert c.post(f"/dossiers/{did}/redescendre").json()["detail"]["motif"] == "en_attente"
    # l'API n'a pas touché au niveau : elle n'écrit que la décision, auditée et relayée
    assert db.execute("SELECT niveau FROM dossiers WHERE id = ?", (did,)).fetchone()[0] == "contenir"
    op, acteur, det = db.execute("SELECT operation, acteur, details_json FROM audit_chaine WHERE operation = "
                                 "'dossier_redescendre'").fetchone()
    assert acteur == "admin" and json.loads(det)["relais"] is True
    assert executeur.RELAIS["dossier_redescendre"] == "ai-dossier-redescendre"
    assert c.get(f"/dossiers/{did}").json()["niveau"]["redescente_en_attente"] is True
    # la veille l'applique à sa passe suivante : observer, preuves antérieures soldées
    dossiers.construire(db, T0 + timedelta(minutes=1))
    db.commit()
    niveau, sig = db.execute("SELECT niveau, signaux_json FROM dossiers WHERE id = ?", (did,)).fetchone()
    assert niveau == "observer" and json.loads(sig)["plancher"]
    assert db.execute("SELECT appliquee_le FROM redescentes WHERE dossier_id = ?", (did,)).fetchone()[0]
    hist = c.get(f"/dossiers/{did}").json()["niveau"]["historique"]
    assert hist[-1]["vers"] == "observer" and hist[-1]["cible"] == "humain"
    # les anciennes preuves ne le font pas remonter ; déjà observer : rien à redescendre
    dossiers.construire(db, T0 + timedelta(minutes=2))
    assert db.execute("SELECT niveau FROM dossiers WHERE id = ?", (did,)).fetchone()[0] == "observer"
    assert c.post(f"/dossiers/{did}/redescendre").json()["detail"]["motif"] == "niveau"


# ── POST /dossiers/{id}/analyser ──

def test_analyser_a_nouveau_depose_un_travail_une_fois(api):
    c, db = api
    did = _dossier_reel(db)
    db.execute("DELETE FROM travaux")
    db.commit()
    assert c.post(f"/dossiers/{did}/analyser").json() == {"dossier": did, "etat": "en_file"}
    assert c.post(f"/dossiers/{did}/analyser").json() == {"dossier": did, "etat": "deja_en_file"}
    assert db.execute("SELECT COUNT(*) FROM travaux WHERE genre = 'analyser' AND objet_id = ? AND etat = 'attente'",
                      (did,)).fetchone()[0] == 1
    assert c.post("/dossiers/inconnu/analyser").status_code == 404
    assert c.get(f"/dossiers/{did}").json()["analyse_en_file"] is True
    assert executeur.RELAIS["dossier_analyser"] == "ai-dossier-analyser"


# ── POST /actions/{id}/defaire ──

def test_defaire_cree_la_levee_approuvee_reference_au_ban(api):
    c, db = api
    did = _dossier_reel(db)
    ban = _prop(db, cible=A, dossier=did)
    aid = _action_faite(db, ban, "ban", A)
    db.commit()
    r = c.post(f"/actions/{aid}/defaire")
    assert r.status_code == 200, r.text
    lev = r.json()["proposition"]
    p = db.execute("SELECT geste, cible, reference, etat, mode, dossier_id, politique FROM propositions WHERE id = ?",
                   (lev,)).fetchone()
    assert p == ("unban", A, ban, "approuvee", "clic", did, "gestes.unban")
    assert db.execute("SELECT acteur, decision FROM approbations WHERE proposition_id = ?", (lev,)).fetchone() == \
        ("admin", "approuver")
    det = json.loads(db.execute("SELECT details_json FROM audit_chaine WHERE operation = 'action_defaire'"
                                ).fetchone()[0])
    assert det["relais"] is True and det["action"] == aid and det["reference"] == ban
    assert executeur.RELAIS["action_defaire"] == "ai-action-defaire"
    assert c.post(f"/actions/{aid}/defaire").json()["detail"]["motif"] == "deja"        # une seule levée
    g = c.get(f"/dossiers/{did}").json()["gestes"]
    assert next(x for x in g if x["proposition"]["id"] == ban)["defaire"]["possible"] is False


def test_defaire_refuse_hors_v2_et_hors_etat(api):
    c, db = api
    assert c.post("/actions/inconnue/defaire").status_code == 404
    # action d'une autre source : aucun id de gk2 rendu à V2 → jamais levée par V2
    autre = _prop(db, cible="45.83.64.20")
    aid = _action_faite(db, autre, "ban", "45.83.64.20")
    db.execute("UPDATE actions SET id_gk2 = NULL WHERE id = ?", (aid,))
    # refusée par gk2 : rien n'a été posé
    refus = _prop(db, cible="45.83.64.21")
    rid = _action_faite(db, refus, "ban", "45.83.64.21")
    db.execute("UPDATE actions SET etat = 'refusee_gk2', code_http = 409 WHERE id = ?", (rid,))
    # déjà échu : rien à lever
    echu = _prop(db, cible="45.83.64.22")
    eid = _action_faite(db, echu, "ban", "45.83.64.22", fin=int(_maintenant().timestamp()) - 10)
    # une levée ne se défait pas, une prolongation se défait par son ban
    lev = _prop(db, geste="unban", cible="45.83.64.23", duree=None, reference=autre)
    lid = _action_faite(db, lev, "unban", "45.83.64.23")
    pro = _prop(db, geste="prolonger", cible="45.83.64.24", reference=refus)
    pid = _action_faite(db, pro, "prolonger", "45.83.64.24")
    db.commit()
    attendus = {aid: "source", rid: "etat", eid: "echu", lid: "geste", pid: "prolongation"}
    for ident, motif in attendus.items():
        r = c.post(f"/actions/{ident}/defaire")
        assert r.status_code == 409 and r.json()["detail"]["motif"] == motif, (ident, r.text)
    assert db.execute("SELECT COUNT(*) FROM propositions WHERE etat = 'approuvee'").fetchone()[0] == 0


# ── exécuteur : la levée part vers la bonne route de gk2 ──

def _ajouter_lever(b):
    async def lever(request: Request, user=Depends(cs.require_ai_ban)):
        corps = await request.body()
        geste = G.GesteLever.model_validate_json(corps)              # le VRAI contrat de gk2
        b.gk2.appels.append(("lever", json.loads(corps)))
        e = b.gk2.journal.get(geste.id)
        if e is None:
            raise HTTPException(404, detail={"motif": "inconnu"})
        if e["type"] != G.LEVABLES[geste.cible_geste]:
            raise HTTPException(409, detail={"motif": "geste"})
        e["annule"] = True
        return {"id": geste.id, "etat": "annule"}
    b.gk2.app.post("/ai/lever")(lever)
    table = dict(TABLE, ai_lever=("/ai/lever", "/ai/lever"))
    b.client = ClientGk2("http://gk2", "gk2", b.lec_prive, table, transport=b.transport, cle_ban=b.ban_prive)


def test_client_route_lever_au_catalogue():
    assert "ai_lever" in ROUTES_GESTES and ROUTES_DEFAUT["ai_lever"] == ("/waf/ai/lever", "/ai/lever")


@pytest.mark.parametrize("geste,cible,duree,route,attendu", [
    ("limiter", "2a01:4f8:c0c:1::1", 6 * 3600, "lever", {"geste": "lever", "cible_geste": "limiter"}),
    ("leurre", "45.83.64.11", 86400, "lever", {"geste": "lever", "cible_geste": "leurre"}),
    ("ban", "45.83.64.12", 86400, "unban", {"geste": "unban"}),
    ("partager", "45.83.65.12", 7 * 86400, "unban", {"geste": "unban"})])
def test_defaire_envoye_par_la_bonne_route(banc, geste, cible, duree, route, attendu):  # noqa: F811
    _ajouter_lever(banc)
    pid = _prop(banc.db, geste=geste, cible=cible, duree=duree)
    _tour(banc)
    assert _etat(banc.db, pid) == "faite"
    id_gk2 = _action(banc.db, pid)["id_gk2"]
    aid = banc.db.execute("SELECT id FROM actions WHERE proposition_id = ?", (pid,)).fetchone()[0]
    lev = decisions.demander_defaire(banc.db, aid, "admin", _maintenant())["proposition"]
    _tour(banc)
    nom, corps = banc.gk2.appels[-1]
    assert nom == route and corps == {**attendu, "id": id_gk2}
    assert _etat(banc.db, lev) == "faite" and banc.gk2.journal[id_gk2]["annule"]
    assert _action(banc.db, lev)["id_cible"] == id_gk2


@pytest.mark.parametrize("geste,cible,duree,liste", [("limiter", "45.83.64.11", 6 * 3600, "limites"),
                                                     ("leurre", "45.83.64.12", 86400, "leurres"),
                                                     ("partager", "45.83.64.13", 7 * 86400, "partages")])
def test_levee_perdue_rapprochee_sur_les_listes_de_gk2(banc, geste, cible, duree, liste):  # noqa: F811
    """Revue 1 : /ai/etat liste limites, leurres et partages (ensemble `tous` du rapprochement). Une levée restée en
    `envoi` n'est `faite` que si l'id a disparu de ces listes ; encore listé (rien n'est arrivé) : `echec`."""
    _ajouter_lever(banc)
    pid = _prop(banc.db, geste=geste, cible=cible, duree=duree)
    _tour(banc)
    id_gk2 = _action(banc.db, pid)["id_gk2"]
    assert any(e["id"] == id_gk2 for e in asyncio.run(banc.client.get("ai_etat"))[liste])
    aid = banc.db.execute("SELECT id FROM actions WHERE proposition_id = ?", (pid,)).fetchone()[0]
    lev = decisions.demander_defaire(banc.db, aid, "admin", _maintenant())["proposition"]
    banc.transport.couper = "avant"                       # rien n'arrive à gk2 : la levée reste en `envoi`
    _tour(banc)
    banc.transport.couper = None
    assert _action(banc.db, lev)["etat"] == "envoi"
    _tour(banc, maintenant=_maintenant() + timedelta(seconds=100))
    assert _action(banc.db, lev)["etat"] == "echec" and not banc.gk2.journal[id_gk2].get("annule")


def test_levee_revalidee_avant_signature(banc):  # noqa: F811
    _ajouter_lever(banc)
    lim = _prop(banc.db, geste="limiter", cible="45.83.64.11", duree=6 * 3600)
    _tour(banc)
    n = len(banc.gk2.appels)
    # levée forgée : cible différente de la limite visée → échec local, rien de signé
    fausse = _prop(banc.db, geste="unban", cible="45.83.64.99", duree=None, reference=lim, mode="clic",
                   etat="approuvee")
    _tour(banc)
    assert _etat(banc.db, fausse) == "echec" and len(banc.gk2.appels) == n


# ── veille/etat : indicateurs partagés, jamais un zéro inventé ──

def test_veille_etat_indicateurs_partages(api):
    c, db = api
    p = _prop(db, geste="partager", cible="45.83.64.30", duree=7 * 86400)
    _action_faite(db, p, "partager", "45.83.64.30")
    db.commit()
    e = c.get("/veille/etat").json()
    assert e["partages_7j"] == {"partages": 1, "revus": None, "contenus": None}


# ── page ──

@pytest.fixture(scope="module")
def html():
    return PAGE.read_text(encoding="utf-8")


def _script(html):
    [s] = re.findall(r"<script>(.*?)</script>", html, re.S)
    return s


def _bloc(html):
    s = _script(html)
    return s[s.index("// ---- Dossier et Réponses (#3724)"):s.index("// ---- fin Dossier et Réponses ----")]


def test_onglets_dossier_et_reponses_apres_la_chaine(html):
    declares = re.search(r"var ONGLETS\s*=\s*\[(.*?)\];", html, re.S).group(1)
    noms = re.findall(r"\['([a-z]+)',\s*'([^']+)'\]", declares)
    assert noms[1:5] == [("radar", "Radar"), ("chaine", "Chaîne"), ("dossier", "Dossier"), ("reponses", "Réponses")]
    sections = re.findall(r'<section data-o="([a-z]+)"', html)
    assert sections.index("dossier") == sections.index("chaine") + 1 and "reponses" in sections


def test_libelles_de_la_maquette(html):
    for texte in ("Redescendre le niveau", "Analyser à nouveau", "Chronologie multicouche", "Étapes atteintes",
                  "Outils", "Gestes appliqués et effet", "Pourquoi ce niveau",
                  "Fixé par le code sur ces chiffres, jamais par le modèle.", "Analyse IA", "Ce qui manque",
                  "le texte du modèle ne devient jamais un geste", "Défaire",
                  "gk2 décide et recontrôle chaque geste · la veille propose, signe et enregistre",
                  "Suspendre l'automatique", "À décider", "Actions et réponse de gk2", "Filtres WAF d'office",
                  "Plafonds restants (heure · jour)", "Indicateurs partagés (7 j)", "Suggestions d'empreintes",
                  "Jamais appliquées seules : à relire avant d'enrichir le catalogue.",
                  "3 refus « plafond » en 10 min ou un 503 de gk2 suspendent l'automatique, et c'est dit ici.",
                  "Approuver", "Refuser", "Confirmer", "relevé indisponible"):
        assert texte in html, texte


def test_routes_appelees_et_cibles_44px(html):
    b = _bloc(html)
    for route in ("'/dossiers", "'/veille/etat'", "'/propositions?etat=proposee", "'/actions?limite=",
                  "'/filtres'", "'/filtres/suggestions'", "/redescendre'", "/analyser'", "/defaire'",
                  "/approuver'", "/refuser'", "'/veille/suspendre'", "'/veille/reprendre'", "/confirmer'"):
        assert route in b, route
    css = html[html.index("/* Dossier et Réponses (#3724)"):html.index("</style>")]
    assert "min-height:44px" in css and "#0c1528" in css                     # palette sombre de la maquette
    assert "innerHTML" not in b and "confirm(" not in b and "alert(" not in b


def test_aucune_valeur_d_exemple_de_la_maquette(html):
    for exemple in ("ACT-1042", "ACT-1050", "134 (seuil", "seuil N3 : 100", "57/60", "391/400", "29/30", "99/100",
                    "398/400", "37 requêtes", "203.0.113.19", "2001:db8::7", "192.0.2.10", "plus aucune requête",
                    "13 min", "41 adresses", "33 adresses", "python-requests/2.x", "admin/admin123",
                    "ia-cve-2024", "7f3a", "91c0", "2d88", "c41e", "e019", "1 h 48", "42 min", "25 min",
                    "Trois adresses du même /24"):
        assert exemple not in html, exemple


def test_demonstration_annoncee_adresses_de_documentation(html):
    b = _bloc(html)
    demo = b[b.index("// démonstration (#3724)"):]
    ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", demo))
    assert ips and all(re.match(r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.", x) for x in ips), ips
    assert "api(" not in demo
    assert 'id="dzDemo"' in html and 'id="rsDemo"' in html


HARNAIS = r"""
var noeuds = {};
function Noeud(t) { this.tagName = t; this.children = []; this.textContent = ''; this.className = ''; this.style = {};
  this.dataset = {}; this.attrs = {}; this.hidden = false; this.disabled = false; this.value = ''; }
Noeud.prototype.appendChild = function (n) { this.children.push(n); return n; };
Noeud.prototype.removeChild = function (n) { this.children.splice(this.children.indexOf(n), 1); return n; };
Object.defineProperty(Noeud.prototype, 'firstChild', { get: function () { return this.children[0] || null; } });
Noeud.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); };
Noeud.prototype.addEventListener = function () {};
var document = { createElement: function (t) { return new Noeud(t); }, hidden: false,
  getElementById: function (i) { return noeuds[i] || (noeuds[i] = new Noeud('div')); } };
function $(i) { return document.getElementById(i); }
function el(t, c, x) { var e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; }
function vider(e) { while (e.firstChild) e.removeChild(e.firstChild); }
function rNombre(v) { return typeof v === 'number' && isFinite(v); }
function annoncer() {}
function setInterval() {}
var API = '/api/v1/ai', DEMO = true, q = { get: function () { return null; } };
function api() { throw new Error('aucun appel en démonstration'); }
function texte(n) { return [n.textContent].concat(n.children.map(texte)).join(' '); }
"""


def _node(html, tmp_path, corps):
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent")
    f = tmp_path / "t.js"
    f.write_text(HARNAIS + _bloc(html) + corps, encoding="utf-8")
    r = subprocess.run([node, str(f)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_rendu_demo_chiffres_venus_des_donnees(html, tmp_path):
    out = json.loads(_node(html, tmp_path, r"""
var d = dzDemoDossier(); dzRendre(d);
var r = rsDemo(); rsRendre(r);
console.log(JSON.stringify({ dz: Object.keys(noeuds).filter(function (k) { return k.slice(0, 2) === 'dz'; }).map(function (k) { return texte(noeuds[k]); }).join(' '),
  rs: Object.keys(noeuds).filter(function (k) { return k.slice(0, 2) === 'rs'; }).map(function (k) { return texte(noeuds[k]); }).join(' '),
  cle: d.dossier.cle, tent: d.niveau.signaux.tentatives, adecider: r.etat.a_decider }));
"""))
    assert out["cle"] in out["dz"] and str(out["tent"]) in out["dz"] and f"À décider ({out['adecider']})" in out["rs"]
    assert "Défaire" in out["dz"] and "Approuver" in out["rs"]


def test_rendu_a_vide_releve_indisponible_sans_aucun_chiffre(html, tmp_path):
    out = json.loads(_node(html, tmp_path, r"""
dzRendre({ dossier: { id: 'x', cle: 'k', type: 'acteur', gravite: null, niveau: null, niveau_depuis: null, premiere_vue: null, derniere_vue: null, adresses: [], adresses_total: null, blocs: [] },
  chronologie: [], etapes: [], outils: [], niveau: { niveau: null, depuis: null, signaux: {}, seuils: null, historique: [], redescente_en_attente: false },
  analyse: null, analyse_en_file: false, gestes: [] });
rsRendre({ etat: null, propositions: null, actions: null, filtres: null, suggestions: null });
console.log(JSON.stringify(Object.keys(noeuds).filter(function (k) { return /^(dz|rs)/.test(k); }).map(function (k) { return texte(noeuds[k]); }).join(' ')));
"""))
    assert "relevé indisponible" in out
    # aucun chiffre inventé (les noms des box, gk2 et gk3, ne sont pas des chiffres relevés)
    assert not re.search(r"\d", re.sub(r"\bgk[0-9]\b", "gk", out)), out


def test_page_revue_1(html, tmp_path):
    """Revue 1 : raison de la prolongation, partage proposé (jamais retiré seul), lecture directe de ?dossier=,
    confirmation ouverte jamais détruite par le rafraîchissement."""
    b = _bloc(html)
    assert "une prolongation ne se raccourcit pas ; défaire le ban ci-dessus" in b
    assert "Lever le ban seul" in b and "Lever le ban et retirer le partage" in b
    assert "!DZ.confirmation" in b and "DZ.confirmation = true" in b
    charger = b[b.index("function dzCharger("):b.index("$('dzChoix').addEventListener")]
    assert "ids.indexOf" not in charger                                    # plus de filtre sur les 100 plus récents
    out = _node(html, tmp_path, r"""
var d = dzDemoDossier(); dzRendre(d);
console.log(texte(noeuds['dzGestes']));
""")
    assert "une prolongation ne se raccourcit pas" in out and out.count("Défaire") == 2
