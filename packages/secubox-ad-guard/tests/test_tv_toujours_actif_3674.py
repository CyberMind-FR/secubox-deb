# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3674 : SBX TV Privacy est toujours actif — activation à chaque configuration du paquet, jamais de réglage par
appareil touché, jamais d'état corrompu écrasé."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import dnstv  # noqa: E402


def _conf(monkeypatch, ajout):
    monkeypatch.setattr(dnstv, "_conf_paquet", lambda: {"adblock_tv": {"ajout_auto_initial": ajout}})


def test_etat_absent_ecrit_actif_avec_ajout_auto(tmp_path, monkeypatch):
    _conf(monkeypatch, True)
    assert dnstv.activer_toujours(tmp_path) is True
    e = dnstv.lire_etat(tmp_path)[0]
    assert e["actif"] is True and e["ajout_auto"] is True and e["mode_defaut"] == "auto"


def test_etat_d_usine_inactif_devient_actif_et_detecte(tmp_path, monkeypatch):
    _conf(monkeypatch, True)
    (tmp_path / "etat.json").write_text(json.dumps({"actif": False, "clients": [], "ajout_auto": False}))
    assert dnstv.activer_toujours(tmp_path) is True
    e = dnstv.lire_etat(tmp_path)[0]
    assert e["actif"] is True and e["ajout_auto"] is True


def test_reglages_par_appareil_jamais_touches(tmp_path, monkeypatch):
    _conf(monkeypatch, True)
    clients = [{"ip": "192.168.1.50", "nom": "TV", "mode": "observe"}]
    (tmp_path / "etat.json").write_text(json.dumps({"actif": False, "clients": clients, "ajout_auto": False}))
    assert dnstv.activer_toujours(tmp_path) is True
    e = dnstv.lire_etat(tmp_path)[0]
    assert e["actif"] is True and e["ajout_auto"] is False and e["clients"][0]["mode"] == "observe"
    assert dnstv.activer_toujours(tmp_path) is False                     # déjà actif : rien n'est réécrit


def test_etat_corrompu_jamais_ecrase(tmp_path, monkeypatch):
    _conf(monkeypatch, True)
    (tmp_path / "etat.json").write_text("{ pas du json")
    assert dnstv.activer_toujours(tmp_path) is False
    assert (tmp_path / "etat.json").read_text() == "{ pas du json"
