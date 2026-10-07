# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1693 : « 0 ban actif » ne doit plus masquer des bans qui ne s'appliquent pas."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api.application import application, lire_etat  # noqa: E402

T = 1_790_000_000.0


def test_table_absente_est_une_panne_meme_si_sbxwaf_veille():
    v = application({"actif": True, "verifie": T}, table_absente=True, maintenant=T)
    assert v["etat"] == "table_absente" and v["ok"] is False


def test_etat_perime_veut_dire_waf_arrete():
    # Le cas gk3 : sbxwaf en boucle de redémarrage, l'état ne se renouvelle plus.
    v = application({"actif": True, "verifie": T - 600}, table_absente=False, maintenant=T)
    assert v["etat"] == "waf_arrete" and v["ok"] is False
    assert "10 min" in v["detail"]


def test_blocage_desactive_donne_la_cause():
    v = application({"actif": False, "verifie": T, "dernier_echec": "Operation not permitted"},
                    table_absente=False, maintenant=T)
    assert v["etat"] == "desactive" and "Operation not permitted" in v["detail"]


def test_applique_porte_les_reparations():
    v = application({"actif": True, "verifie": T - 20, "reparations": 2, "derniere_reparation": T - 100},
                    table_absente=False, maintenant=T)
    assert v["etat"] == "appliquee" and v["ok"] is True and v["reparations"] == 2


def test_sans_etat_publie_reste_inconnu():
    assert application(None, table_absente=False, maintenant=T)["etat"] == "inconnu"


def test_lire_etat_tolere_absent_et_illisible(tmp_path):
    assert lire_etat(tmp_path / "absent.json") is None
    f = tmp_path / "e.json"
    f.write_text("pas du json")
    assert lire_etat(f) is None
    f.write_text(json.dumps({"actif": True, "verifie": T}))
    assert lire_etat(f)["actif"] is True
