# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3154 — GET /public/ports : les ports publiés par les modules de la box (ports-publics.d), que le maître relaie."""
import json

from fastapi.testclient import TestClient

import api.main as m
from api import ports

MEET = {"module": "meet", "ports": [{"proto": "tcp", "port": 7881}, {"proto": "udp", "port": 7882},
                                    {"proto": "icmp", "port": 1}, {"proto": "tcp", "port": 22}]}


def test_public_ports_lit_le_dossier_et_filtre(tmp_path, monkeypatch):
    (tmp_path / "meet.json").write_text(json.dumps(MEET))
    (tmp_path / "x.json").write_text("{pas du json")
    monkeypatch.setattr(ports, "DOSSIER", tmp_path)
    assert ports.lire() == [{"proto": "tcp", "port": 7881, "module": "meet"}, {"proto": "udp", "port": 7882, "module": "meet"}]


def test_module_invalide_port_non_entier_et_dossier_absent(tmp_path, monkeypatch):
    (tmp_path / "a.json").write_text('{"module":"Mauvais Nom","ports":[{"proto":"tcp","port":5000}]}')
    (tmp_path / "b.json").write_text('{"module":"b","ports":[{"proto":"tcp","port":"5000"},{"proto":"tcp","port":true},{"proto":"udp","port":65536}]}')
    (tmp_path / "c.json").write_text('{"module":"c","ports":"x"}')
    (tmp_path / "d.json").write_text('[1,2]')
    monkeypatch.setattr(ports, "DOSSIER", tmp_path)
    assert ports.lire() == []
    monkeypatch.setattr(ports, "DOSSIER", tmp_path / "absent")
    assert ports.lire() == []


def test_au_plus_16_entrees_triees(tmp_path, monkeypatch):
    (tmp_path / "z.json").write_text(json.dumps({"module": "z", "ports": [{"proto": "udp", "port": 2000 + i} for i in range(20)]}))
    (tmp_path / "a.json").write_text(json.dumps({"module": "a", "ports": [{"proto": "tcp", "port": 9000}]}))
    monkeypatch.setattr(ports, "DOSSIER", tmp_path)
    r = ports.lire()
    assert len(r) == 16 and r[0] == {"proto": "tcp", "port": 9000, "module": "a"}
    assert r == sorted(r, key=lambda e: (e["proto"], e["port"]))


def test_route_publique_sans_jeton(tmp_path, monkeypatch):
    (tmp_path / "meet.json").write_text(json.dumps(MEET))
    monkeypatch.setattr(ports, "DOSSIER", tmp_path)
    monkeypatch.setattr(m, "domaine_box", lambda: "Box.Exemple.Test")
    r = TestClient(m.app).get("/public/ports")
    assert r.status_code == 200
    assert r.json() == {"domaine": "box.exemple.test", "ports": [
        {"proto": "tcp", "port": 7881, "module": "meet"}, {"proto": "udp", "port": 7882, "module": "meet"}]}
