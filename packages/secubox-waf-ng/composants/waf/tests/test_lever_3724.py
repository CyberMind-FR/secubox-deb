# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3724 : geste `lever` (défaire une limite ou un leurre posés par ai-ban), `POST /ai/lever`.

Corps `{geste: "lever", cible_geste: "limiter"|"leurre", id}` : seule une entrée du journal ai-ban, du type annoncé,
non annulée et non échue est levée (`wafctl limiter-lever` / `leurre-lever`) ; audit `ai-lever-demande` AVANT, puis
`ai-lever` ; plafonds 30/h et 100/j. Banc de #3716/#3723 (wafctl simulé, vraie garde ai-ban).
"""
from __future__ import annotations

import secrets
import time

import pytest

from .test_gestes_ia_3716 import _ban_journal, c  # noqa: F401  (fixture `c` réutilisée)
from .test_gestes_ia_3723 import _motif, gk2_simule  # noqa: F401  (fixture réutilisée)

IP4, IP6 = "198.51.100.7", "2001:db8:1::7"


@pytest.fixture
def g(gk2_simule):  # noqa: F811
    gk2_simule.faux.reponses["limiter-lever"] = (0, "[..] limiter-lever ok\n", "")
    gk2_simule.faux.reponses["leurre-lever"] = (0, "[..] leurre-lever ok\n", "")
    return gk2_simule


def _entree(type_, cible, at=None, fin=None):
    m = int(time.time())
    at = m - 60 if at is None else at
    geste = {"limite": "limiter", "leurre": "leurre", "partage": "partager"}[type_]
    return {"ts": "", "at": at, "type": type_, "geste": geste, "id": secrets.token_hex(16), "cible": cible,
            "fin": m + 3600 if fin is None else fin, "mode": "auto", "conseil": "c-0", "motif": "", "duree_s": 3600}


def _lever(g, ident, cible_geste="limiter", **extra):
    return g.c.post("/ai/lever", json={"geste": "lever", "cible_geste": cible_geste, "id": ident, **extra})


@pytest.mark.parametrize("type_,cible_geste,verbe,cible", [("limite", "limiter", "limiter-lever", IP6),
                                                           ("leurre", "leurre", "leurre-lever", IP4)])
def test_lever_retire_l_entree_ai_ban(g, type_, cible_geste, verbe, cible):
    e = _entree(type_, cible)
    g.journal(e)
    r = _lever(g, e["id"], cible_geste)
    assert r.status_code == 200, r.text
    assert r.json() == {"id": e["id"], "etat": "annule"}
    assert g.faux.appel(verbe)[:3] == ["sudo", "-n", "/usr/sbin/wafctl"] and g.faux.appel(verbe)[-2:] == [cible, str(e["fin"])]
    ligne = g.lignes_journal()[-1]
    assert ligne["type"] == "annule" and ligne["geste"] == "lever" and ligne["id"] == e["id"]
    assert ligne["cause"] == "lever"
    actions = [x["action"] for x in g.audit()]
    assert actions.index("ai-lever-demande") < actions.index("ai-lever")
    etat = g.c.get("/ai/etat").json()
    assert etat["limites"] == [] and etat["leurres"] == []
    # déjà levée : rien n'est relancé
    n = len(g.faux.appels)
    assert _lever(g, e["id"], cible_geste).json() == {"id": e["id"], "etat": "deja_annule"}
    assert len(g.faux.appels) == n


def test_lever_ne_touche_que_le_type_annonce(g):
    limite, leurre = _entree("limite", IP4), _entree("leurre", IP6)
    ban = _ban_journal("198.51.100.9", int(time.time()) - 60, int(time.time()) + 3600)
    partage = _entree("partage", "198.51.100.10")
    g.journal(limite, leurre, ban, partage)
    assert _lever(g, limite["id"], "leurre").status_code == 409
    assert _motif(_lever(g, leurre["id"], "limiter")) == "geste"
    assert _motif(_lever(g, ban["id"], "limiter")) == "geste"        # jamais un ban (route /ai/unban)
    assert _motif(_lever(g, partage["id"], "leurre")) == "geste"
    assert _lever(g, secrets.token_hex(16)).status_code == 404       # absente du journal ai-ban : jamais levée
    assert g.faux.appels == []


def test_lever_echu_ne_lance_rien(g):
    e = _entree("limite", IP4, at=int(time.time()) - 7200, fin=int(time.time()) - 10)
    g.journal(e)
    assert _lever(g, e["id"]).json() == {"id": e["id"], "etat": "echu"}
    assert g.faux.appels == []


@pytest.mark.parametrize("corps", [{"geste": "unban", "cible_geste": "limiter"}, {"geste": "lever", "cible_geste": "ban"},
                                   {"geste": "lever", "cible_geste": "partager"},
                                   {"geste": "lever", "cible_geste": "limiter", "cible": IP4},
                                   {"geste": "lever", "cible_geste": "limiter", "id": "X" * 32}])
def test_lever_forme_stricte_422(g, corps):
    corps = {"id": secrets.token_hex(16), **corps}
    assert g.c.post("/ai/lever", json=corps).status_code == 422
    assert g.faux.appels == []


def test_lever_plafonds_30_par_heure(g):
    m = int(time.time())
    entrees = [_entree("limite", f"198.51.100.{i}") for i in range(31)]
    levees = [{"ts": "", "at": m - 30, "type": "annule", "geste": "lever", "id": e["id"], "cible": e["cible"],
               "cause": "lever"} for e in entrees[:30]]
    g.journal(*entrees, *levees)
    r = _lever(g, entrees[30]["id"])
    assert r.status_code == 409 and _motif(r) == "plafond_heure"
    assert g.faux.appels == []


def test_lever_plafond_jour_100(g):
    m = int(time.time())
    entrees = [_entree("leurre", f"198.51.100.{i}", at=m - 7200) for i in range(101)]
    levees = [{"ts": "", "at": m - 5000, "type": "annule", "geste": "lever", "id": e["id"], "cible": e["cible"],
               "cause": "lever"} for e in entrees[:100]]
    g.journal(*entrees, *levees)
    assert _motif(_lever(g, entrees[100]["id"], "leurre")) == "plafond_jour"


def test_lever_sans_audit_de_demande_ne_fait_rien(g, monkeypatch):
    e = _entree("limite", IP4)
    g.journal(e)
    vrai = g.g._config["audit"]

    def audit(action, detail, user):
        if action == "ai-lever-demande":
            raise OSError("disque plein")
        vrai(action, detail, user)
    monkeypatch.setitem(g.g._config, "audit", audit)
    r = _lever(g, e["id"])
    assert r.status_code == 503 and _motif(r) == "audit"
    assert g.faux.appels == [] and g.lignes_journal()[-1]["type"] == "limite"


def test_lever_echec_wafctl_audite(g):
    e = _entree("leurre", IP4)
    g.journal(e)
    g.faux.reponses["leurre-lever"] = (1, "", "erreur")
    r = _lever(g, e["id"], "leurre")
    assert r.status_code == 503
    assert "ai-lever-echec" in [x["action"] for x in g.audit()]
    assert g.lignes_journal()[-1]["type"] == "leurre"                   # rien n'est clos


def test_lever_compte_ai_ban_exige(g):
    from secubox_core.compte_service import require_ai_ban
    g.waf.app.dependency_overrides.pop(require_ai_ban, None)
    r = g.c.post("/ai/lever", json={"geste": "lever", "cible_geste": "limiter", "id": secrets.token_hex(16)})
    assert r.status_code in (401, 403)


def test_lever_plafonds_propres_hors_plafonds_par_geste(g):
    # le plafond de la levée n'entre pas dans PLAFONDS_PAR_GESTE (relu par gk3 comme plafonds des gestes posés)
    assert g.g.PLAFONDS_LEVER == {"heure": 30, "jour": 100} and "lever" not in g.g.PLAFONDS_PAR_GESTE
