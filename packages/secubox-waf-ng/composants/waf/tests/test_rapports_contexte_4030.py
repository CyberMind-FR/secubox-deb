# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# See LICENCE-CMSD-1.0.md for terms.
"""#4030 : contrôles de contexte du vérificateur, pas de rédaction sans ban."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api import rapports as R  # noqa: E402
from api import verif_rapport as V  # noqa: E402

D = {"sujet": {"genre": "acteur", "id": "ACT-0088", "nom": "ACT-0088"}, "genere_le": "2026-11-27",
     "periode": {"debut": "2026-08-30", "fin": "2026-11-27", "jours": 90},
     "chiffres": {"bans_90j": 12, "adresses_90j": 6, "blocs24_90j": 5, "jours_actifs": 2, "vagues": 1},
     "operateurs": [{"nom": "Amazon.com, Inc.", "part": 50}], "acteur": {"level": "LOW", "priority": 36},
     "vagues": [{"debut": "2026-10-11", "fin": "2026-10-12", "bans": 12}]}


def statut(phrase):
    return V.verifier(phrase, D)["gardees"]


def test_bloc_24_heures_retire():
    assert not statut("Le nombre de blocs 24 heures a atteint 5 durant la période.")


def test_niveau_contraire_retire_et_juste_garde():
    assert not statut("La priorité attribuée à cet acteur est de 36, indiquant un risque modéré.")
    assert statut("La priorité de cet acteur est de 36, avec un risque faible.")


def test_fenetre_seule_retiree():
    assert not statut("La période d'observation s'étend du 30 août 2026 au 27 novembre 2026, couvrant 90 jours.")
    assert not statut("L'acteur ACT-0088 a été identifié le 27 novembre 2026.")


def test_fait_reel_garde():
    assert statut("La vague du 11 octobre 2026 compte 12 bans.")
    assert statut("Amazon.com, Inc. porte 50 % des bans de l'acteur ACT-0088.")


def test_pas_de_redaction_sans_ban():
    d = {**D, "chiffres": {**D["chiffres"], "bans_90j": 0}}
    r = asyncio.run(R.rediger("acteur:ACT-0088", d, ["http://127.0.0.1:1"]))
    assert r["etat"] == "repli" and "aucun ban" in r["motif"]



# #4042
D2 = {**D, "lecture": [{"code": "x", "texte": "18 723 bans de repérage, 22 000 bans au total."}],
      "chiffres": {**D["chiffres"], "bans_90j": 22000, "blocs24_90j": 1144}}


def test_nombre_de_la_lecture_garde_son_unite():
    assert not V.verifier("Au total, 22 000 blocs 24 ont été bloqués.", D2)["gardees"]
    assert V.verifier("Au total, 22 000 bans ont été posés.", D2)["gardees"]
    assert V.verifier("La campagne touche 1144 blocs 24.", D2)["gardees"]


def test_fenetre_lue_comme_duree():
    assert not statut("La phase de repérage a duré 90 jours, avec 12 bans.")
    assert not statut("La vague compte 12 bans et 90 jours d'activité.")


def test_suggerant_hypothese():
    g = V.verifier("La vague du 11 octobre 2026 compte 12 bans, suggérant une activité stable.", D)["gardees"]
    assert g and g[0]["statut"] == "hypothese"
