# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: messagerie — mur, privés, réponses, modération (#1446)."""
import importlib
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

ICI = Path(__file__).resolve().parent
sys.path[:0] = [str(ICI.parent / "api"), str(ICI.parents[2] / "common")]

ALICE = {"type": "sbx", "ref": "u-alice", "pseudo": "alice", "moderateur": False}
BOB = {"type": "sbx", "ref": "u-bob", "pseudo": "bob", "moderateur": False}
MODO = {"type": "sbx", "ref": "u-gandalf", "pseudo": "gandalf", "moderateur": True}
ANON = {"type": "anonyme", "ref": None, "pseudo": None, "moderateur": False}


@pytest.fixture
def m(tmp_path, monkeypatch):
    monkeypatch.setenv("MESSAGERIE_DB", str(tmp_path / "m.db"))
    mod = importlib.reload(importlib.import_module("main"))
    mod.__dict__["_QUI"] = ANON
    monkeypatch.setattr(mod, "qui", lambda r: mod._QUI)
    monkeypatch.setattr(mod, "_pseudos_sbx", lambda casse=False: {
        "alice": "u-alice", "bob": "u-bob", "gandalf": "u-gandalf"})
    monkeypatch.setattr(mod, "_radio_chat", lambda n=40: [
        {"id": "radio:7", "cree_le": 1, "auteur_type": "radio", "pseudo": "dj", "corps": "salut",
         "prive": 0, "source": "radio", "parent": None, "supprime": False}])
    mod._SURPOSTES = []
    monkeypatch.setattr(mod, "_surposte_radio", lambda q, p, c: mod._SURPOSTES.append((p, c)) or True)
    return mod


def req(ip="10.0.0.9", intention=True):
    h = [(b"x-real-ip", ip.encode())] + ([(b"x-sbx-messagerie", b"1")] if intention else [])
    return Request({"type": "http", "method": "POST", "path": "/", "headers": h, "client": (ip, 1)})


def ecrit(m, qui, **kw):
    m._QUI = qui
    rep = Response()
    return m.ecrit(m.Nouveau(**kw), req(), rep), rep


def test_mur_centralise_la_radio(m):
    ecrit(m, ALICE, corps="bonjour à tous")
    f = m.fil(req())["messages"]
    assert [x["pseudo"] for x in f] == ["dj", "alice"]


def test_visiteur_publie_d_emblee_et_recoit_un_cookie(m):
    r, rep = ecrit(m, ANON, corps="coucou", pseudo="Passant")
    assert "sbx_msg_v=" in rep.headers.get("set-cookie", "")
    assert any(x["pseudo"] == "Passant" for x in m.fil(req())["messages"])


def test_visiteur_ne_prend_pas_un_pseudo_de_la_box(m):
    with pytest.raises(HTTPException) as e:
        ecrit(m, ANON, corps="x", pseudo="Alice")
    assert e.value.status_code == 409


def test_visiteur_plafonne(m):
    for i in range(m.PLAFOND["visiteur"]):
        ecrit(m, ANON, corps=f"m{i}", pseudo="Passant")
    with pytest.raises(HTTPException) as e:
        ecrit(m, ANON, corps="de trop", pseudo="Passant")
    assert e.value.status_code == 429


def test_prive_ne_se_voit_que_des_deux(m):
    ecrit(m, ALICE, corps="secret", destinataire="u-bob")
    assert all(x["corps"] != "secret" for x in m.fil(req())["messages"])
    m._QUI = BOB
    assert [x["corps"] for x in m.prives(req())["messages"]] == ["secret"]
    m._QUI = MODO
    assert m.prives(req())["messages"] == []


def test_reponse_privee_ou_publique(m):
    r, _ = ecrit(m, ALICE, corps="question", destinataire="u-bob")
    r2, _ = ecrit(m, BOB, corps="réponse privée", parent=r["id"])
    assert r2["prive"]
    m._QUI = ALICE
    assert "réponse privée" in [x["corps"] for x in m.prives(req())["messages"]]
    r3, _ = ecrit(m, BOB, corps="réponse à tous", parent=r["id"], public=True)
    assert not r3["prive"]
    # un tiers ne peut pas répondre à un privé qui ne le concerne pas
    with pytest.raises(HTTPException) as e:
        ecrit(m, MODO, corps="intrus", parent=r["id"])
    assert e.value.status_code == 403


def test_repondre_a_la_radio_surposte(m):
    r, _ = ecrit(m, ALICE, corps="bien vu", parent="radio:7")
    assert not r["prive"] and m._SURPOSTES == [("alice", "bien vu")]


def test_suppression_auteur_ou_moderateur(m):
    r, _ = ecrit(m, ALICE, corps="à retirer")
    m._QUI = BOB
    with pytest.raises(HTTPException) as e:
        m.supprime(r["id"], req())
    assert e.value.status_code == 403
    m._QUI = MODO
    m.supprime(r["id"], req())
    v = [x for x in m.fil(req())["messages"] if x["id"] == r["id"]][0]
    assert v["supprime"] and v["corps"] == ""


def test_intention_exigee(m):
    m._QUI = ALICE
    with pytest.raises(HTTPException) as e:
        m.ecrit(m.Nouveau(corps="x"), req(intention=False), Response())
    assert e.value.status_code == 403


def test_destinataire_inconnu(m):
    with pytest.raises(HTTPException) as e:
        ecrit(m, ALICE, corps="x", destinataire="u-personne")
    assert e.value.status_code == 404


def test_visiteur_repond_en_prive_et_on_lui_repond(m):
    r, rep = ecrit(m, ANON, corps="bonjour alice", pseudo="Passant")
    cookie = rep.headers["set-cookie"].split("sbx_msg_v=")[1].split(";")[0]
    visiteur = {"type": "visiteur", "ref": m._ref_visiteur(cookie), "pseudo": None, "moderateur": False}
    r2, _ = ecrit(m, ALICE, corps="bonjour à vous", parent=r["id"], public=False)
    m._QUI = visiteur
    vus = m.prives(req())["messages"]
    assert [(x["pseudo"], x["dest_pseudo"], x["corps"]) for x in vus] == [("alice", "Passant", "bonjour à vous")]
    assert cookie not in str(vus)                 # l'empreinte circule, jamais le cookie


def test_on_n_ecrit_pas_a_un_visiteur_sans_repondre(m):
    with pytest.raises(HTTPException) as e:
        ecrit(m, ALICE, corps="x", destinataire="v:0123")
    assert e.value.status_code == 400
