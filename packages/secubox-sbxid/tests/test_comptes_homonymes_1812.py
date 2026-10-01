# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Ouvrir les comptes d'une personne ne reprend pas le compte homonyme d'autrui ;
la suspension voit aussi les comptes courriel/Nextcloud ouverts ici (#1812)."""
import sqlite3
import time

import pytest

from secubox_core import sbxid as S
from api import comptes


@pytest.fixture
def base(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_WEBOS_ACCES", str(tmp_path / "coffre"))
    c = sqlite3.connect(":memory:", isolation_level=None)
    c.row_factory = sqlite3.Row
    S.initialise(c)
    c.execute("INSERT INTO sbx_users (user_uuid,pseudo,home_node,created_at) VALUES ('u1','zoe','did:plc:x',?)",
              (int(time.time()),))
    return c


def _helper(monkeypatch, existants=(), ambigu=()):
    appels = []

    def h(d):
        appels.append((d["service"], d["action"]))
        if d["action"] == "creer" and d["service"] in existants:
            return {"ok": False, "erreur": "user already exists"}
        if d["action"] == "creer" and d["service"] in ambigu:
            return {"ok": False, "erreur": "délai dépassé"}
        return {"ok": True}
    monkeypatch.setattr(comptes, "helper", h)
    return appels


def test_un_compte_homonyme_d_autrui_n_est_pas_repris(base, monkeypatch):
    appels = _helper(monkeypatch, existants={"nextcloud"})
    r = comptes.cree(base, "u1", ["email", "nextcloud"])
    assert r["services"]["email"] is True
    assert "existe déjà" in r["services"]["nextcloud"]
    assert ("nextcloud", "reinitialiser") not in appels, "jamais de mot de passe posé sur le compte d'autrui"
    assert "nextcloud" not in comptes.liens(base, "u1")


def test_une_tentative_precedente_pour_elle_se_reprend(base, monkeypatch):
    _helper(monkeypatch, ambigu={"nextcloud"})
    r = comptes.cree(base, "u1", ["nextcloud"])
    assert r["services"]["nextcloud"] != True                       # noqa: E712 — échec ambigu
    appels = _helper(monkeypatch, existants={"nextcloud"})          # entre-temps, le compte est né
    r = comptes.cree(base, "u1", ["nextcloud"])
    assert r["services"]["nextcloud"] is True and ("nextcloud", "reinitialiser") in appels


def test_la_suspension_voit_les_comptes_ouverts_ici(base, monkeypatch):
    _helper(monkeypatch)
    comptes.cree(base, "u1", ["email", "nextcloud"])
    # un compte relié (existant, mot de passe propre) n'est pas à elle de fermer
    base.execute("INSERT INTO sbx_app_links VALUES ('u1','peertube','zoe','zoe')")
    base.execute("INSERT INTO sbx_preferences VALUES ('u1','mdp_propre:peertube','1')")
    appels = _helper(monkeypatch)
    comptes.desactive_ouverts(base, "u1")
    assert sorted(s for s, a in appels if a == "desactiver") == ["email", "nextcloud"]


def test_les_liens_d_avant_la_marque_sont_reconnus(base, monkeypatch):
    # courriel ouvert avant #1812 : lié, sans marque, sans mot de passe propre
    base.execute("INSERT INTO sbx_app_links VALUES ('u1','email','zoe@secubox.in','zoe@secubox.in')")
    assert comptes._ouverts(base, "u1") == ["email"]
