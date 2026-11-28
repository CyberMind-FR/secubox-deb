# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 4 (#4058) : magasin SQLite des lectures évolutives."""
from emissions.magasin import Magasin, empreinte


def _dossier(jour, bans=10):
    return {"sujet": {"genre": "campagne", "id": "c1", "nom": "C1"}, "genere_le": jour, "chiffres": {"bans_90j": bans}}


def _gardees():
    return [{"statut": "retenue", "texte": "La campagne compte 10 bans."},
            {"statut": "hypothese", "texte": "Elle semble revenir."}]


def test_retenir_puis_dernier(tmp_path):
    m = Magasin(tmp_path / "m.db")
    m.retenir("campagne/c1", _dossier("2026-11-20"), _gardees())
    m.retenir("campagne/c1", _dossier("2026-11-27", 14), _gardees())
    assert m.dernier_valide("campagne/c1")["genere_le"] == "2026-11-27"
    assert m.dernier_valide("acteur/inconnu") is None
    lues = m.interpretations("campagne/c1")
    assert len(lues) == 4 and {x["statut"] for x in lues} == {"verifiee", "hypothese"}


def test_amorcer_idempotent(tmp_path):
    m = Magasin(tmp_path / "m.db")
    rapports = [{"dossier": _dossier("2026-11-20"), "ia": {"etat": "fait", "perimee": False, "gardees": _gardees()}},
                {"dossier": _dossier("2026-11-21"), "ia": {"etat": "repli"}},
                {"dossier": _dossier("2026-11-22"), "ia": None}]
    assert m.amorcer(rapports) == 1
    assert m.amorcer(rapports) == 0


def test_empreinte_stable():
    assert empreinte({"a": 1, "b": 2}) == empreinte({"b": 2, "a": 1})
