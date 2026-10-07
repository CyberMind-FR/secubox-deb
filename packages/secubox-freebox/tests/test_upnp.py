# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""UPnP de la Freebox : lecture (état + ports ouverts automatiquement), réglage protégé comme le pare-feu."""
import json

import pytest
from fastapi.testclient import TestClient

from api import client as c
from api import main, normalise as N
from tests.test_pare_feu_ecriture import _pret, ok


def test_normalise_upnp_sans_redirection():
    assert N.upnp({"enabled": True, "version": 1}, None) == {"actif": True, "version": 1, "redirections": []}


def test_normalise_upnp_donne_des_redirections_lisibles():
    r = N.upnp({"enabled": True}, [{"enabled": True, "proto": "udp", "ext_port": 5060, "int_port": 5060, "int_ip": "192.168.1.200",
                                     "desc": "SIP", "src_ip": "0.0.0.0", "remaining": 600, "ts": 1}])
    assert r["redirections"] == [{"protocole": "udp", "port_externe": 5060, "port_local": 5060, "appareil_ip": "192.168.1.200", "description": "SIP"}]


def test_lecture_upnp(tmp_path):
    svc, f, _ = _pret(tmp_path, [ok({"enabled": True, "version": 1}), ok(None)])
    assert svc.upnp() == {"actif": True, "version": 1, "redirections": []}


def test_reglage_upnp_exige_settings_et_journalise(tmp_path):
    svc, f, j = _pret(tmp_path, [], droits={"settings": False})
    with pytest.raises(c.DroitManquant):
        svc.regler_upnp(False)
    svc, f, j = _pret(tmp_path, [ok({"enabled": True}), ok({"enabled": False}), ok({"enabled": False})])
    r = svc.regler_upnp(False)
    puts = [a for a in f.appels if a[0] == "PUT"]
    assert r == {"actif": False, "change": True} and json.loads(puts[0][3]) == {"enabled": False} and puts[0][1].endswith("upnpigd/config/")
    assert j[0]["action"] == "upnp" and j[0]["avant"] is True and j[0]["apres"] is False


def test_route_upnp_ecriture_confirmee_et_admin():
    t = TestClient(main.app)
    assert t.post("/upnp", json={"actif": False, "confirme": True}).status_code in (401, 403)
    from secubox_core import auth
    main.app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "a"}
    try:
        assert t.post("/upnp", json={"actif": False}).status_code == 400
    finally:
        main.app.dependency_overrides.clear()
