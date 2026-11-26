# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3970 : la page de veille d'un module à la demande est une réponse voulue, reconnue par sa marque, jamais une panne."""
import ast
from pathlib import Path

RACINE = Path(__file__).resolve().parents[2]
SRC = (Path(__file__).resolve().parents[1] / "src" / "prober.py").read_text()
ns: dict = {}
arbre = ast.parse(SRC)
exec(compile(ast.Module([n for n in arbre.body if (isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "MARQUES_VEILLE" for t in n.targets))
                         or (isinstance(n, ast.FunctionDef) and n.name == "est_veille")], []), "prober", "exec"), ns)


def test_marques_des_pages_du_waker():
    waking = (RACINE / "secubox-profiles" / "templates" / "waking.html").read_text()
    waker = (RACINE / "secubox-profiles" / "api" / "waker.py").read_text()
    assert ns["est_veille"](503, waking)
    assert ns["est_veille"](503, waker[waker.index("<title>Module desactive"):])


def test_un_503_ordinaire_reste_une_panne():
    assert not ns["est_veille"](503, "<h1>503 Service Unavailable</h1>")
    assert not ns["est_veille"](200, "SecuBox — réveil du service")
    assert 'result["status"] = "veille"' in SRC and 'results["veille"]' in SRC
