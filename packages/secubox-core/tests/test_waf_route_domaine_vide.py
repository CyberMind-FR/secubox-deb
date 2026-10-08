# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-waf-route : un domaine VIDE (celui de la box inconnu au moment du postinst) se dit clairement.

Quinze postinst appellent `secubox-waf-route "$(secubox-domaine <x>)" <port> || true`. Quand le domaine de la box est
inconnu, `secubox-domaine` ne rend rien et l'outil affichait « domaine invalide : » suivi de rien — sans dire quoi faire."""
import importlib.machinery
import importlib.util
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("waf_route_t", str(PKG / "usr" / "sbin" / "secubox-waf-route"))
spec = importlib.util.spec_from_loader("waf_route_t", loader)
w = importlib.util.module_from_spec(spec)
loader.exec_module(w)


def test_un_domaine_vide_dit_pourquoi_et_que_la_route_n_est_pas_posee(capsys):
    assert w.main(["secubox-waf-route", "", "9080"]) == 2
    err = capsys.readouterr().err
    assert "vide" in err and "secubox-domaine" in err and "non posée" in err


def test_un_domaine_malforme_garde_son_message(capsys):
    assert w.main(["secubox-waf-route", "pas un domaine!", "9080"]) == 2
    assert "domaine invalide : pas un domaine!" in capsys.readouterr().err
