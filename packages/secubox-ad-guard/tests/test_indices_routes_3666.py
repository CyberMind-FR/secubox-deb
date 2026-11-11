# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3666 : interrupteurs et vue des indices du maillage (routes), état, branchement du moteur (runner)."""
import importlib.machinery
import importlib.util
import json
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv, dnstv_auto, dnstv_indices

IP = "192.168.1.95"
ETAT = {"actif": True, "clients": [{"ip": IP, "nom": "TV banc", "mode": "auto"}]}


@pytest.fixture
def banc(tmp_path, monkeypatch):
    from api import dnstv_indices_routes as L
    from api import dnstv_routes as r
    from secubox_core import auth
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    liv = tmp_path / "livraisons"
    monkeypatch.setattr(dnstv_indices, "LIVRAISONS", liv)
    monkeypatch.setattr(dnstv_indices, "PUBLICATION", tmp_path / "indices-publication.json")
    dnstv.ecrire_etat(ETAT, tmp_path)
    audits = []
    monkeypatch.setattr(r, "_ctl_entree", lambda action, entree: audits.append((action, json.loads(entree))))
    app = FastAPI()
    app.include_router(L.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    c = TestClient(app)
    c.tmp, c.liv, c.audits, c.app = tmp_path, liv, audits, app
    return c


def livrer(liv, producteurs):
    liv.mkdir(parents=True, exist_ok=True)
    idx = {}
    for i, (nom, indices, leg) in enumerate(producteurs):
        h = f"{i:032x}"
        idx[f"did:plc:{h}"] = {"nom": nom}
        (liv / f"{h}.json").write_text(json.dumps({"format": 1, "jeu": "tv-indices", "indices": indices, "legitimes": leg}))
    (liv / "index.json").write_text(json.dumps(idx))


def test_etat_ancien_valide_a_vrai_et_les_cles_sont_validees(tmp_path):
    e = dnstv.valider_etat({"actif": False, "clients": []})
    assert e["indices_publier"] is True and e["indices_recevoir"] is True
    assert dnstv.ETAT_DEFAUT["indices_publier"] is True and dnstv.ETAT_DEFAUT["indices_recevoir"] is True
    assert dnstv.valider_etat({"indices_recevoir": False})["indices_recevoir"] is False
    with pytest.raises(dnstv.ErreurTV):
        dnstv.valider_etat({"indices_publier": "oui"})


def test_get_sans_jeton_401(banc):
    banc.app.dependency_overrides.clear()
    assert banc.get("/adblock-tv/indices").status_code == 401
    assert banc.post("/adblock-tv/indices", json={"publier": False, "recevoir": False}).status_code == 401


def test_post_bascule_persiste_et_audite(banc):
    r = banc.post("/adblock-tv/indices", json={"publier": False, "recevoir": True})
    assert r.status_code == 200 and r.json() == {"publier": False, "recevoir": True}
    e, _ = dnstv.lire_etat(banc.tmp)
    assert e["indices_publier"] is False and e["indices_recevoir"] is True and e["clients"][0]["nom"] == "TV banc"
    assert banc.audits[-1] == ("audit-protection", {"acteur": "admin", "origine": "admin", "geste": "tv_indices_reglage", "cibles": ["indices"],
                                                    "minutes": None, "domaine": None, "type": "publier=non,recevoir=oui", "force": False})
    assert banc.get("/adblock-tv/indices").json()["publier"] is False
    assert banc.post("/adblock-tv/indices", json={"publier": "x"}).status_code == 422
    assert banc.post("/adblock-tv/indices", json={"publier": True, "recevoir": True, "x": 1}).status_code == 422


def test_audit_impossible_refuse_le_reglage(banc, monkeypatch):
    from fastapi import HTTPException
    from api import dnstv_routes as r

    def refus(a, e):
        raise HTTPException(502, "audit refusé")
    monkeypatch.setattr(r, "_ctl_entree", refus)
    assert banc.post("/adblock-tv/indices", json={"publier": False, "recevoir": False}).status_code == 502
    assert dnstv.lire_etat(banc.tmp)[0]["indices_publier"] is True


def test_geste_accepte_par_le_controleur_root():
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-tv"
    loader = importlib.machinery.SourceFileLoader("tv_ctl_3666", str(chemin))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader("tv_ctl_3666", loader))
    loader.exec_module(m)
    ok = {"acteur": "admin", "origine": "admin", "geste": "tv_indices_reglage", "cibles": ["indices"], "minutes": None, "domaine": None,
          "type": "publier=non,recevoir=oui", "force": False}
    assert m._enregistrement_protection(ok)
    assert not m._enregistrement_protection(dict(ok, type="publier=peut-etre"))
    assert not m._enregistrement_protection(dict(ok, domaine="x.example.com"))


def test_get_compte_les_producteurs(banc):
    assert banc.get("/adblock-tv/indices").json() == {"publier": True, "recevoir": True, "recus": 0, "producteurs": [], "publies": 0}
    livrer(banc.liv, [("gk1", {"a.example.com": "PUBLICITE", "b.example.com": "TRACKING"}, ["ok.example.com"]),
                      ("gk2", {"a.example.com": "PUBLICITE"}, [])])
    (banc.tmp / "indices-publication.json").write_text(json.dumps({"format": 1, "contenu": {"indices": {"z.example.com": "PUBLICITE", "y.example.com": "TRACKING"}}}))
    j = banc.get("/adblock-tv/indices").json()
    assert j["recus"] == 2 and j["publies"] == 2
    assert j["producteurs"] == [{"nom": "gk1", "indices": 2, "legitimes": 1}, {"nom": "gk2", "indices": 1, "legitimes": 0}]


# ── runner ────────────────────────────────────────────────────────────────────

def script(monkeypatch, tmp_path, etat):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", tmp_path / "listes")
    monkeypatch.setattr(dnstv_indices, "PUBLICATION", tmp_path / "indices-publication.json")
    monkeypatch.setattr(dnstv_indices, "LIVRAISONS", tmp_path / "livraisons")
    dnstv.ecrire_etat(etat, tmp_path)
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-auto"
    loader = importlib.machinery.SourceFileLoader("sbx_tv_auto_3666", str(chemin))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("sbx_tv_auto_3666", loader))
    loader.exec_module(mod)
    return mod


class Rep:
    returncode, stdout, stderr = 0, "", ""


def espion(monkeypatch):
    vus = []
    vrai = dnstv_auto.tick

    def tick(*a, **k):
        vus.append(k.get("indices"))
        return vrai(*a, **k)
    monkeypatch.setattr(dnstv_auto, "tick", tick)
    return vus


def test_runner_reception_coupee_passe_un_index_vide_lisible(monkeypatch, tmp_path):
    mod = script(monkeypatch, tmp_path, dict(ETAT, indices_recevoir=False))
    livrer(tmp_path / "livraisons", [("gk1", {"a.example.com": "PUBLICITE"}, [])])
    vus = espion(monkeypatch)
    assert mod.main(sudo=lambda: Rep(), maintenant=int(time.time())) == 0
    assert len(vus) == 1 and vus[0].lisible is True and vus[0].confirmes == {} and vus[0].legitimes == {}
    doc = json.loads((tmp_path / "indices-publication.json").read_text())
    assert doc["recevoir"] is False and doc["publier"] is True and doc["contenu"]["jeu"] == "tv-indices"


def test_runner_reception_active_charge_les_livraisons(monkeypatch, tmp_path):
    mod = script(monkeypatch, tmp_path, ETAT)
    livrer(tmp_path / "livraisons", [("gk1", {"a.example.com": "PUBLICITE"}, [])])
    vus = espion(monkeypatch)
    assert mod.main(sudo=lambda: Rep(), maintenant=int(time.time())) == 0
    assert vus[0].confirmateurs("a.example.com") == ["gk1"]


def test_runner_une_panne_des_indices_n_arrete_pas_le_passage(monkeypatch, tmp_path):
    mod = script(monkeypatch, tmp_path, ETAT)

    def boum(*a, **k):
        raise RuntimeError("boum")
    monkeypatch.setattr(dnstv_indices, "charger", boum)
    monkeypatch.setattr(dnstv_indices, "contenu", boum)
    vus = espion(monkeypatch)
    assert mod.main(sudo=lambda: Rep(), maintenant=int(time.time())) == 0
    assert vus[0].lisible is False and not (tmp_path / "indices-publication.json").exists()
