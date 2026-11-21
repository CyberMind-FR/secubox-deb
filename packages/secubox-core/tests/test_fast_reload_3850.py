# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3850 — rechargement d'Unbound par `fast_reload` (le DNS continue de répondre), repli sur `reload` seulement si Unbound
le refuse, jamais après un dépassement de délai."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "common"))
import secubox_unbound as U  # noqa: E402


@pytest.fixture
def systeme(tmp_path):
    class S(U.SystemeUnbound):
        AUDIT = str(tmp_path / "audit.log")
    return S()


def _faux(monkeypatch, reponses):
    vus = []

    def commande(args, delai):
        vus.append((args[1:], delai))
        return reponses[args[1]]
    monkeypatch.setattr(U, "commande", commande)
    return vus


def test_fast_reload_suffit(systeme, monkeypatch):
    vus = _faux(monkeypatch, {"fast_reload": (True, "ok")})
    systeme.recharger_unbound()
    assert vus == [(["fast_reload"], U.DELAI_FAST_RELOAD)]


def test_refus_repli_sur_reload_audite(systeme, monkeypatch, tmp_path):
    vus = _faux(monkeypatch, {"fast_reload": (False, "error fast_reload not supported"), "reload": (True, "ok")})
    systeme.recharger_unbound()
    assert [v[0] for v in vus] == [["fast_reload"], ["reload"]]
    assert "fast-reload-refuse" in (tmp_path / "audit.log").read_text(encoding="utf-8")


def test_reponse_inattendue_repli(systeme, monkeypatch):
    vus = _faux(monkeypatch, {"fast_reload": (True, "error: changes to some options cannot be applied"), "reload": (True, "ok")})
    systeme.recharger_unbound()
    assert [v[0] for v in vus] == [["fast_reload"], ["reload"]]


def test_delai_depasse_jamais_de_second_rechargement(systeme, monkeypatch):
    vus = _faux(monkeypatch, {"fast_reload": (False, "unbound-control : délai de 600 s dépassé")})
    with pytest.raises(U.ErreurUnbound):
        systeme.recharger_unbound()
    assert [v[0] for v in vus] == [["fast_reload"]]


def test_reload_en_echec_leve(systeme, monkeypatch):
    _faux(monkeypatch, {"fast_reload": (False, "refus"), "reload": (False, "boom")})
    with pytest.raises(U.ErreurUnbound):
        systeme.recharger_unbound()
