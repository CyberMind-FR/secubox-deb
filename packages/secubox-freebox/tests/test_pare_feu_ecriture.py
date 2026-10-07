# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Réglage du pare-feu IPv6 de la Freebox : droit « settings » exigé, lecture avant/après, journal d'audit, aucune écriture inutile."""
import json

import pytest
from fastapi.testclient import TestClient

from api import client as c
from api import main
from tests.test_service_api import _svc, _session, VERSION  # noqa: F401


def ok(res):
    return (200, {"success": True, "result": res})


def _pret(tmp_path, reponses, droits=None):
    svc, f, _ = _svc(tmp_path, [VERSION] + _session(droits=droits if droits is not None else {"settings": True}) + reponses, app_token="T", autorise=True)
    journal = []
    svc.journal = journal.append
    return svc, f, journal


def test_sans_le_droit_settings_rien_n_est_ecrit(tmp_path):
    svc, f, journal = _pret(tmp_path, [], droits={"settings": False})
    with pytest.raises(c.DroitManquant):
        svc.regler_pare_feu_ipv6(True)
    assert not [a for a in f.appels if a[0] == "PUT"] and journal == []


def test_activation_ecrit_puis_relit_et_journalise(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"ipv6_enabled": True, "ipv6_firewall": False}), ok({"ipv6_firewall": True}), ok({"ipv6_firewall": True})])
    r = svc.regler_pare_feu_ipv6(True)
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert len(puts) == 1 and puts[0][1].endswith("connection/ipv6/config/") and json.loads(puts[0][3]) == {"ipv6_firewall": True}
    assert r["pare_feu_actif"] is True and r["change"] is True
    assert len(journal) == 1 and journal[0]["action"] == "pare_feu_ipv6" and journal[0]["avant"] is False and journal[0]["apres"] is True


def test_deja_dans_l_etat_voulu_n_ecrit_rien(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"ipv6_firewall": True})])
    r = svc.regler_pare_feu_ipv6(True)
    assert r["change"] is False and not [a for a in f.appels if a[0] == "PUT"]


def test_si_la_relecture_ne_confirme_pas_c_est_une_erreur(tmp_path):
    svc, f, journal = _pret(tmp_path, [ok({"ipv6_firewall": False}), ok({"ipv6_firewall": True}), ok({"ipv6_firewall": False})])
    with pytest.raises(c.ErreurFreebox):
        svc.regler_pare_feu_ipv6(True)


def test_la_route_exige_un_administrateur_et_une_confirmation(monkeypatch):
    t = TestClient(main.app)
    assert t.post("/pare-feu/ipv6", json={"actif": True, "confirme": True}).status_code in (401, 403)
    from secubox_core import auth
    main.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    try:
        assert t.post("/pare-feu/ipv6", json={"actif": True}).status_code == 400          # pas de confirmation explicite
        assert t.post("/pare-feu/ipv6", json={"confirme": True}).status_code == 400       # pas de valeur voulue
    finally:
        main.app.dependency_overrides.clear()
