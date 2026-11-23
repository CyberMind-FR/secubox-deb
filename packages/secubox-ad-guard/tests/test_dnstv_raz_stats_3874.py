# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3874 : remise à zéro des statistiques TV Privacy depuis la webui (route administrateur, confirmée, auditée, sauvegardée)."""
import json
import sqlite3
import stat
from pathlib import Path

from api import dnstv
from test_dnstv_ctl_api import api, monde  # noqa: F401  (fixtures)

ICI = Path(__file__).resolve().parents[1]


def _remplir(etat: Path, n: int = 3) -> None:
    m = dnstv.Magasin(etat / "dnstv.db")
    evts = [(dnstv.Evenement(ts=1795400000 + i, client=f"192.168.1.{10 + i}", qname=f"pub{i}.exemple.test", qtype="A", rcode="NXDOMAIN",
                             decision="bloque"), "PUBLICITE") for i in range(n)]
    m.ajouter(evts)


def _comptes(etat: Path) -> dict:
    return dnstv.Magasin(etat / "dnstv.db").comptes()


def test_raz_vide_sauvegarde_et_audite(api, monde):
    _remplir(monde["etat"])
    (monde["etat"] / "pubs-bloquees.json").write_text("{}")
    r = api.post("/adblock-tv/stats/raz", json={"confirmer": True})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["ok"] is True and j["retirees"] == {"counts": 3, "clients": 3, "recents": 3}
    assert _comptes(monde["etat"]) == {"counts": 0, "clients": 0, "recents": 0}
    assert not (monde["etat"] / "pubs-bloquees.json").exists()
    sauvegarde = monde["etat"] / j["sauvegarde"]
    assert stat.S_IMODE(sauvegarde.stat().st_mode) == 0o640
    cx = sqlite3.connect(sauvegarde)
    assert cx.execute("SELECT COUNT(*) FROM dnstv_counts").fetchone()[0] == 3
    lignes = [json.loads(x) for x in (monde["tmp"] / "audit.log").read_text().splitlines()]
    raz = [x for x in lignes if x["action"] == "raz-stats"]
    assert raz and raz[-1]["acteur"] == "admin" and raz[-1]["lignes"]["counts"] == 3 and raz[-1]["sauvegarde"] == j["sauvegarde"]


def test_raz_sans_confirmation_refusee(api, monde):
    _remplir(monde["etat"])
    for corps in ({"confirmer": False}, {}, {"confirmer": True, "autre": 1}):
        assert api.post("/adblock-tv/stats/raz", json=corps).status_code == 422
    assert _comptes(monde["etat"])["counts"] == 3


def test_raz_audit_impossible_ne_vide_rien(api, monde, monkeypatch):
    from fastapi import HTTPException
    from api import dnstv_routes as r
    _remplir(monde["etat"])

    def refus(action, entree):
        raise HTTPException(502, "audit refusé")
    monkeypatch.setattr(r, "_ctl_entree", refus)
    assert api.post("/adblock-tv/stats/raz", json={"confirmer": True}).status_code == 502
    assert _comptes(monde["etat"])["counts"] == 3


def test_raz_garde_les_trois_dernieres_sauvegardes(api, monde):
    for i in range(5):
        (monde["etat"] / f"dnstv.db.avant-raz-{1000 + i}").write_text("x")
    _remplir(monde["etat"])
    assert api.post("/adblock-tv/stats/raz", json={"confirmer": True}).status_code == 200
    restantes = sorted(p.name for p in monde["etat"].glob("dnstv.db.avant-raz-*"))
    assert len(restantes) == 3 and "dnstv.db.avant-raz-1004" in restantes


def test_controleur_refuse_entree_malformee(monde):
    import importlib.machinery
    import importlib.util
    lo = importlib.machinery.SourceFileLoader("tv_ctl_raz", str(ICI / "sbin" / "secubox-adguard-tv"))
    m = importlib.util.module_from_spec(importlib.util.spec_from_loader("tv_ctl_raz", lo))
    lo.exec_module(m)
    bon = {"acteur": "admin", "lignes": {"counts": 1, "clients": 1, "recents": 1}, "sauvegarde": "dnstv.db.avant-raz-1795406542"}
    assert m.main(["x", "audit-raz-stats"], entree=json.dumps(bon)) == 0
    for mauvais in ({**bon, "sauvegarde": "../etat.json"}, {**bon, "acteur": "a b"}, {**bon, "lignes": {"counts": -1, "clients": 0, "recents": 0}},
                    {**bon, "lignes": {"counts": True, "clients": 0, "recents": 0}}, {**bon, "x": 1}, {**bon, "acteur": "admin\n"}, {**bon, "sauvegarde": "dnstv.db.avant-raz-1\n"}):
        assert m.main(["x", "audit-raz-stats"], entree=json.dumps(mauvais)) == 2


def test_sudoers_ouvre_le_verbe_sans_joker():
    ligne = [x for x in (ICI / "sudoers.d" / "secubox-adguard-tv").read_text().splitlines() if x.startswith("secubox ")][0]
    assert "/usr/sbin/secubox-adguard-tv audit-raz-stats" in ligne and "*" not in ligne


def test_page_porte_le_bouton_confirme():
    page = (ICI / "www" / "tv-privacy" / "index.html").read_text()
    assert 'id="raz-stats"' in page and "/stats/raz" in page and "confirmer:true" in page


def test_raz_sauvegarde_impossible_ne_vide_rien_ni_laisse_de_copie(api, monde, monkeypatch):
    _remplir(monde["etat"])

    vrai = sqlite3.connect

    class Source:                                       # la connexion source dont la copie échoue (disque plein)
        def __init__(self, cx):
            self.cx = cx

        def backup(self, dst):
            Path(f"{monde['etat']}/{next(monde['etat'].glob('dnstv.db.avant-raz-*')).name}-journal").write_text("x")
            raise sqlite3.OperationalError("database or disk is full")

        def close(self):
            self.cx.close()

    def connecter(chemin, *a, **k):
        cx = vrai(chemin, *a, **k)
        return Source(cx) if str(chemin).endswith("dnstv.db") and k.get("timeout") == 10 and connecter.copie else cx
    connecter.copie = False
    monkeypatch.setattr(dnstv.sqlite3, "connect", connecter)
    vrai_sauver = dnstv.Magasin.sauvegarder

    def sauver(self, destination):
        connecter.copie = True
        try:
            return vrai_sauver(self, destination)
        finally:
            connecter.copie = False
    monkeypatch.setattr(dnstv.Magasin, "sauvegarder", sauver)
    assert api.post("/adblock-tv/stats/raz", json={"confirmer": True}).status_code == 503
    assert _comptes(monde["etat"])["counts"] == 3
    assert not list(monde["etat"].glob("dnstv.db.avant-raz-*"))


def test_raz_place_insuffisante_507(api, monde, monkeypatch):
    import shutil
    from collections import namedtuple
    _remplir(monde["etat"])
    monkeypatch.setattr(shutil, "disk_usage", lambda p: namedtuple("u", "total used free")(1, 1, 1024))
    assert api.post("/adblock-tv/stats/raz", json={"confirmer": True}).status_code == 507
    assert _comptes(monde["etat"])["counts"] == 3


def test_raz_retire_la_marque_des_pubs(api, monde):
    _remplir(monde["etat"])
    (monde["etat"] / ".pubs-bloquees.passe").write_text("")
    j = api.post("/adblock-tv/stats/raz", json={"confirmer": True}).json()
    assert j["cache_pubs"] is True and not (monde["etat"] / ".pubs-bloquees.passe").exists()


def test_raz_exige_un_administrateur(monde):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api import dnstv_routes as r
    app = FastAPI()
    app.include_router(r.router)
    assert TestClient(app).post("/adblock-tv/stats/raz", json={"confirmer": True}).status_code in (401, 403)
