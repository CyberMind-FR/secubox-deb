# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Commandes courantes : grammaire partagée, repli sur whisper (#1656)."""
from pathlib import Path

from api import commandes

LISTE = Path(__file__).resolve().parents[1] / "conf" / "commandes.json"


def test_grammaire():
    l = commandes.charge_liste(LISTE)
    assert "mets la radio en pause" in l and "ouvre atelier" in l and "va dans sécurité" in l
    assert len(l) == len(set(l))


def test_sans_modele_rien_ne_bloque(monkeypatch):
    monkeypatch.setattr(commandes, "MODELE", Path("/nulle/part"))
    assert commandes.reconnait(b"audio") is None
