# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""La trace des sessions déléguées n'est jamais silencieuse (#1720).

Vécu sur gk3 : un appel servi par un module durci (ProtectSystem=strict) ne
pouvait pas écrire /var/log/secubox/delegation.log, et disparaissait."""
import json
import sys
from types import SimpleNamespace


def _req():
    return SimpleNamespace(method="GET", url=SimpleNamespace(path="/boite"))


PAYLOAD = {"sub": "sonde.gk2", "delegation": {"centre": "did:plc:" + "0" * 32, "noeud": "gk2",
                                              "compte": "sonde", "session": "sess-1"}}


def test_trace_dans_le_fichier(tmp_path, monkeypatch):
    from secubox_core import auth
    f = tmp_path / "delegation.log"
    monkeypatch.setenv("SECUBOX_TRACE_DELEGATION", str(f))
    auth._trace_delegation(_req(), PAYLOAD)
    d = json.loads(f.read_text())
    assert (d["compte"], d["aidant"], d["noeud"], d["chemin"]) == ("sonde.gk2", "sonde", "gk2", "/boite")


def test_fichier_inaccessible_donc_journal_systeme(tmp_path, monkeypatch):
    from secubox_core import auth
    monkeypatch.setenv("SECUBOX_TRACE_DELEGATION", str(tmp_path / "absent" / "delegation.log"))
    lignes = []
    faux = SimpleNamespace(LOG_AUTH=32, LOG_NOTICE=5, openlog=lambda *a: None,
                           syslog=lambda prio, msg: lignes.append(msg))
    monkeypatch.setitem(sys.modules, "syslog", faux)
    auth._trace_delegation(_req(), PAYLOAD)
    assert len(lignes) == 1 and json.loads(lignes[0])["session"] == "sess-1"


def test_rien_hors_delegation(tmp_path, monkeypatch):
    from secubox_core import auth
    f = tmp_path / "delegation.log"
    monkeypatch.setenv("SECUBOX_TRACE_DELEGATION", str(f))
    auth._trace_delegation(_req(), {"sub": "admin"})
    assert not f.exists()
