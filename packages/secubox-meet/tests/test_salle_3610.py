# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3610 — créer une salle Meet depuis l'administration : garde, validation, argv exact, audit dans meetctl."""
import json
import subprocess
from pathlib import Path

import test_api

from api import main as M

cli = test_api.cli
CTL = Path(__file__).resolve().parent.parent / "sbin" / "meetctl"


def test_creer_salle_reservee_a_l_administrateur_et_validee(cli):
    corps = {"nom": "", "acces": "trusted", "proprietaire": "abc-123"}
    assert cli.post("/salles", json=corps, jwt=False).status_code == 401
    for mauvais in ({**corps, "nom": "gk-public"}, {**corps, "nom": "x" * 101}, {**corps, "nom": "abc-defg-hi1"},
                    {**corps, "proprietaire": "../x"}, {**corps, "acces": "ouvert"}):
        assert cli.post("/salles", json=mauvais, jwt=True).status_code in (400, 422), mauvais
    assert not cli.appels
    r = cli.post("/salles", json=corps, jwt=True)
    assert r.status_code == 200
    assert cli.appels[-1] == ("salle-creer", "-", "trusted", "abc-123", "admin")            # code généré
    assert cli.post("/salles", json={**corps, "nom": "Abc-Defg-Hij"}, jwt=True).status_code == 200
    assert cli.appels[-1][1] == "abc-defg-hij"


def test_echec_du_controleur_remonte(cli, monkeypatch):
    monkeypatch.setattr(M, "_run_ctl", lambda *a, timeout=30: (1, json.dumps(
        {"success": False, "error": "une salle porte déjà cette adresse"}), ""))
    r = cli.post("/salles", json={"nom": "", "acces": "public", "proprietaire": "s"}, jwt=True)
    assert r.status_code == 502 and "déjà" in r.json()["detail"]


def test_comptes(cli):
    cli.sorties["comptes"] = json.dumps([{"sub": "s1", "pseudo": "Gandalf"}, {"pseudo": "sans sub"}])
    assert cli.get("/comptes", jwt=False).status_code == 401
    assert cli.get("/comptes", jwt=True).json() == {"comptes": [{"sub": "s1", "pseudo": "Gandalf"}]}


def _ctl(*args):
    return subprocess.run(["bash", str(CTL), "salle-creer", *args], capture_output=True, text=True, timeout=20)


def test_meetctl_refuse_les_arguments_douteux_avant_le_conteneur():
    for args in ((), ("-", "ouvert", "sub"), ("-", "public", "../sub"), ("gk-public", "public", "s"),
                 ("abc-defg-hi1", "public", "s"), ("-", "public", "s", "acteur avec espace")):
        r = _ctl(*args)
        assert r.returncode != 0 and "usage" in r.stdout, args


def test_valeurs_jamais_dans_le_code_python():
    t = CTL.read_text()
    assert "json.load(sys.stdin)" in t and 'shell -c "$PY_SALLE"' in t
    assert "audit salle-creer " in t and "audit salle-creer-echec" in t


def test_code_genere_au_format_de_meet():
    t = CTL.read_text()
    assert 'return s(3) + "-" + s(4) + "-" + s(3)' in t and "secrets.choice(string.ascii_lowercase)" in t
