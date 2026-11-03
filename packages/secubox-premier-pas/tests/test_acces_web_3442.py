# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#3442 : la page web dit où retrouver la box (navigateur externe), même quand elle change d'adresse."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import adresses as A  # noqa: E402

PAGE = (Path(__file__).resolve().parents[1] / "www" / "premier-pas" / "index.html").read_text()


def test_acces_lan_seulement_et_nom_local():
    a = A.acces("gk8", ["192.168.1.73", "203.0.113.7", "10.0.0.2"])
    assert a == {"noms": ["gk8.local"], "ips": ["192.168.1.73", "10.0.0.2"]}


def test_acces_nom_qualifie_garde_tel_quel():
    assert A.acces("gk8.secubox.in", [])["noms"] == ["gk8.secubox.in"]


def test_acces_sans_nom():
    assert A.acces("", ["192.168.1.5"]) == {"noms": [], "ips": ["192.168.1.5"]}


def test_etat_porte_les_acces(monkeypatch):
    from premier_pas import remplir as R
    monkeypatch.setattr(A, "acces", lambda: {"noms": ["gk8.local"], "ips": ["192.168.1.73"]})
    assert R.etat()["acces"]["ips"] == ["192.168.1.73"]


def test_page_affiche_les_adresses_et_ouvre_l_administration():
    assert "blocAcces(ETAT && ETAT.acces)" in PAGE and "blocAcces(ACCES, true)" in PAGE
    assert "Ouvrir l'administration" in PAGE and "Ouvrir le Hall" not in PAGE
