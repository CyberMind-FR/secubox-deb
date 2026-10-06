# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Contrôle de santé de l'antivirus à la demande : le sommeil est normal, une base périmée non (#1912)."""
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("checks_t", Path(__file__).resolve().parents[1] / "api" / "checks.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class R:
    def __init__(self, sortie):
        self.stdout = sortie


def _avec(monkeypatch, etat, present=True):
    monkeypatch.setattr(checks.Path, "exists", lambda self: present if str(self) == "/usr/sbin/clamavctl" else False)
    monkeypatch.setattr(checks, "_run", lambda *a, **k: R(json.dumps(etat)))


def test_lxc_endormi_et_base_a_jour_est_sain(monkeypatch):
    _avec(monkeypatch, {"lxc": "STOPPED", "clamd": False, "base_a_jour": True, "base_age_jours": {"daily": 0.4, "main": 3.0}})
    ok, d = checks.check_clamav()
    assert ok is True and d["veille_normale"] is True


def test_base_perimee_est_une_alerte_meme_si_tout_tourne(monkeypatch):
    _avec(monkeypatch, {"lxc": "RUNNING", "clamd": True, "base_a_jour": False, "base_age_jours": {"daily": 40.0, "main": 40.0}})
    ok, d = checks.check_clamav()
    assert ok is False and d["base_a_jour"] is False


def test_paquet_absent_rien_a_surveiller(monkeypatch):
    _avec(monkeypatch, {}, present=False)
    ok, d = checks.check_clamav()
    assert ok is True and d["skipped"] is True


def test_enregistre_dans_le_registre():
    assert "clamav" in checks.REGISTRY
