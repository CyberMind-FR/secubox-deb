# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3919, tâche 8 — liste « Campagnes » de la page Actor : cartes lisibles avec les repères partagés du Radar.

Lecture statique du HTML ; le rendu (cible hostile, repli, lien vers les populations) est essayé sous node
avec un DOM factice (actor_campagnes_3919.test.mjs)."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]
PAGE = RACINE / "www" / "actor" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")
TEST_MJS = Path(__file__).with_name("actor_campagnes_3919.test.mjs")


def _fonction(nom):
    debut = HTML.index("function " + nom + "(")
    i, p = HTML.index("{", debut), 0
    while True:
        if HTML[i] == "{":
            p += 1
        elif HTML[i] == "}":
            p -= 1
            if p == 0:
                return HTML[debut:i + 1]
        i += 1


def _bloc():
    return HTML[HTML.index("// ---- Cartes de campagne (#3919"):HTML.index("// ---- Fin des cartes de campagne")]


def test_reperes_charge():
    m = re.search(r'<script src="reperes\.js"></script>', HTML)
    assert m, "reperes.js non chargé"
    principal = HTML.index("<script>")
    assert m.start() < principal, "reperes.js doit précéder le script principal"
    assert (RACINE / "www" / "actor" / "reperes.js").is_file()


def test_rend_campagnes_utilise_reperes():
    bloc = _bloc()
    assert "SbxReperes" in _fonction("rendCampagnes")
    assert "R.nomCarte" in bloc and "R.CLASSES" in bloc and "R.FAMILLES" in bloc and "R.ETATS" in bloc
    carte = _fonction("carteCampagne")
    # la signature n'est plus le titre : elle n'apparaît que dans le détail
    titre = re.search(r"h\('h3'[^;]*", carte).group(0)
    assert "signature" not in titre and "nomCarte" in titre
    assert "'Signature'" in carte or "Signature :" in carte
    assert "<details" not in carte and "'details'" in carte


def test_bloc_sans_injection_de_balisage():
    bloc = _bloc()
    for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "DOMParser"):
        assert interdit not in bloc, interdit


def test_repli_et_lien_populations():
    bloc = _bloc()
    assert "Autres campagnes" in bloc and "86400" in bloc
    assert "/api/v1/waf/populations" in HTML and "campagne_actord" in bloc
    assert "même population que « " in bloc and "dans le Radar" in bloc
    # lecture discrète : une route absente ou refusée ne déclenche aucun bandeau de session
    assert re.search(r"jget\('/api/v1/waf/populations',\s*true\)", HTML)


def test_demo_enrichie():
    demo = _fonction("demoCampagnes")
    for champ in ("famille:", "classes:", "pays_top:", "une:", "le3:", "rotation:", "cibles_noms:"):
        assert champ in demo, champ
    assert "{code:'" in demo                       # pays_top en objets, comme actord
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", demo)   # aucune adresse IP
    asn = [int(x) for x in re.findall(r"AS(\d+)", demo)]
    assert all(64496 <= a <= 64511 for a in asn)
    for hote in re.findall(r"'([a-z0-9.-]+\.[a-z]+)'", demo):
        assert hote.endswith(".example.test"), hote
    assert "campagne_actord" in _fonction("demoPopulations")


def test_rendu_node_cible_hostile_inerte():
    if not shutil.which("node"):
        pytest.skip("node absent")
    r = subprocess.run(["node", "--test", str(TEST_MJS)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
