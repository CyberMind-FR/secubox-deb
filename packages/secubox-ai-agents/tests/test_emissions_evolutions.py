# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 5 (#4058) : évolutions d'un sujet entre deux lectures validées."""
import copy
import re
from datetime import datetime, timezone

from emissions.evolutions import GENRES, evolutions


def _t(jour):
    return datetime.fromisoformat(jour).replace(tzinfo=timezone.utc).timestamp()


def _dossier(genere_le, vagues, bans=900, operateurs=("OVH",), phases=("reconnaissance",)):
    return {"sujet": {"genre": "acteur", "id": "a1", "nom": "Acteur 198.51.100.4"},
            "genere_le": genere_le,
            "chiffres": {"bans_90j": bans, "vagues": len(vagues)},
            "vagues": [{"debut": d, "fin": f, "bans": 100} for d, f in vagues],
            "operateurs": [{"nom": o, "part": 50} for o in operateurs],
            "phases": [{"phase": p, "bans": 10} for p in phases]}


def test_premiere_lecture():
    d = _dossier("2026-11-20", [("2026-11-01", "2026-11-18")])
    f = evolutions(d, None, _t("2026-11-20"))
    assert [x["genre"] for x in f] == ["premiere_lecture"]


def test_sans_changement_vide():
    d = _dossier("2026-11-20", [("2026-11-01", "2026-11-18")])
    assert evolutions(d, d, _t("2026-11-20")) == []


def test_retour_acteur_premiere_classe():
    eteint = _dossier("2026-11-01", [("2026-09-01", "2026-10-10")])          # dernier ban il y a 22 jours
    reactive = _dossier("2026-11-28", [("2026-09-01", "2026-10-10"), ("2026-11-25", "2026-11-27")], bans=1000)
    f = evolutions(reactive, eteint, _t("2026-11-28"))
    retours = [x for x in f if x["genre"] == "retour_acteur"]
    assert len(retours) == 1 and retours[0]["marquant"] is True
    assert f[0]["genre"] == "retour_acteur"                                    # premier fait de la liste
    assert not [x for x in f if x["genre"] == "nouvelle_vague"]                # pas compté deux fois


def test_extinction():
    actif = _dossier("2026-11-10", [("2026-11-01", "2026-11-09")])
    calme = _dossier("2026-11-28", [("2026-11-01", "2026-11-09")])
    f = evolutions(calme, actif, _t("2026-11-28"))
    assert [x["genre"] for x in f] == ["extinction"] and f[0]["marquant"]


def test_nouvelle_vague_operateur_phase():
    avant = _dossier("2026-11-10", [("2026-11-01", "2026-11-09")])
    apres = _dossier("2026-11-28", [("2026-11-01", "2026-11-09"), ("2026-11-20", "2026-11-27")],
                     operateurs=("OVH", "Hetzner"), phases=("reconnaissance", "exploitation"))
    genres = {x["genre"] for x in evolutions(apres, avant, _t("2026-11-28"))}
    assert {"nouvelle_vague", "operateur_nouveau", "phase"} <= genres


def test_chiffre_marquant_a_25_pct():
    avant = _dossier("2026-11-10", [("2026-11-01", "2026-11-09")], bans=1000)
    petit = copy.deepcopy(avant)
    petit["chiffres"]["bans_90j"] = 1100
    gros = copy.deepcopy(avant)
    gros["chiffres"]["bans_90j"] = 1250
    (p,) = [x for x in evolutions(petit, avant, _t("2026-11-10")) if x["genre"] == "chiffre"]
    (g,) = [x for x in evolutions(gros, avant, _t("2026-11-10")) if x["genre"] == "chiffre"]
    assert p["marquant"] is False and g["marquant"] is True


def test_aucune_adresse_et_genres_connus():
    avant = _dossier("2026-11-10", [("2026-11-01", "2026-11-09")], operateurs=("OVH",))
    apres = _dossier("2026-11-28", [("2026-11-01", "2026-11-09"), ("2026-11-20", "2026-11-27")],
                     operateurs=("OVH", "AS 203.0.113.7", "2001:db8::1"), bans=5000)
    faits = evolutions(apres, avant, _t("2026-11-28")) + evolutions(apres, None, _t("2026-11-28"))
    for x in faits:
        assert x["genre"] in GENRES | {"premiere_lecture"}
        assert not re.search(r"\d{1,3}(\.\d{1,3}){3}", x["texte"]) and "2001:db8" not in x["texte"]
