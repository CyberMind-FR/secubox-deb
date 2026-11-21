# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3850 — secubox-annuaire-noms recharge Unbound par fast_reload (le DNS répond pendant), reload seulement si refusé."""
import importlib.machinery
import importlib.util
import subprocess
from pathlib import Path
from types import SimpleNamespace

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-annuaire-noms"


def _module():
    loader = importlib.machinery.SourceFileLoader("annuaire_noms_3850", str(SCRIPT))
    spec = importlib.util.spec_from_loader("annuaire_noms_3850", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def _faux(monkeypatch, m, sortie_fast, code=0, delai=False):
    appels = []

    def run(args, **kw):
        appels.append(args[1])
        if args[1] == "fast_reload" and delai:
            raise subprocess.TimeoutExpired(args, 600)
        return SimpleNamespace(returncode=code if args[1] == "fast_reload" else 0, stdout=sortie_fast, stderr="")
    monkeypatch.setattr(m.subprocess, "run", run)
    return appels


def test_fast_reload_suffit(monkeypatch):
    m = _module()
    appels = _faux(monkeypatch, m, "ok\n")
    m._recharger_unbound()
    assert appels == ["fast_reload"]


def test_refus_repli_reload(monkeypatch):
    m = _module()
    appels = _faux(monkeypatch, m, "error not supported", code=1)
    m._recharger_unbound()
    assert appels == ["fast_reload", "reload"]


def test_delai_jamais_de_second_rechargement(monkeypatch):
    m = _module()
    appels = _faux(monkeypatch, m, "", delai=True)
    m._recharger_unbound()
    assert appels == ["fast_reload"]


def test_sortie_vide_est_un_succes(monkeypatch):
    m = _module()
    appels = _faux(monkeypatch, m, "")
    m._recharger_unbound()
    assert appels == ["fast_reload"]
