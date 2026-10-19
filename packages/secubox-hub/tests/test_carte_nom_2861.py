# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2861 — le pied et le sous-titre du hub disent le NOM de la carte, jamais « [object Object] ».

/hub/dashboard renvoie `board` en OBJET (model, board, hostname, …) ; la page le posait tel quel en texte. Le mode démonstration envoyait une chaîne et masquait le défaut :
ce test sert la page avec la FORME RÉELLE de l'API."""
import json
from pathlib import Path

import pytest

playwright = pytest.importorskip("playwright.sync_api")
PAGE = Path(__file__).resolve().parents[1] / "www" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def _ouvre(navigateur, board):
    ctx = navigateur.new_context(viewport={"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif chemin in ("", "index.html"):
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/hub", 1)[1].split("?")[0]
        corps = {"/dashboard": {"board": board, "cpu_percent": 10, "memory_percent": 20, "disk_percent": 30, "load_avg": [0.1, 0.1, 0.1], "build_info": {"version": "dev"}},
                 "/menu": {"total_active": 1, "total_installed": 1, "categories": []}}.get(chemin)
        r.fulfill(status=200 if corps is not None else 404, content_type="application/json", body=json.dumps(corps if corps is not None else {}))
    p.route("http://sbx.test/api/v1/hub/**", api)
    p.goto("http://sbx.test/")
    p.wait_for_function("document.getElementById('pCarte').textContent !== '—'")
    return ctx, p, erreurs


REEL = {"model": "Globalscale Marvell MOCHAbin Board", "board": "mochabin", "hostname": "gk2", "uptime_sec": 5, "cpu_count": 4, "mem_total_mb": 7923, "mem_free_mb": 800}


def test_la_carte_reelle_est_nommee_par_son_modele(navigateur):
    ctx, p, err = _ouvre(navigateur, REEL)
    assert p.inner_text("#pCarte") == "Globalscale Marvell MOCHAbin Board"
    assert "[object Object]" not in p.inner_text("body") and "Globalscale Marvell MOCHAbin Board" in p.inner_text("#subline")
    assert err == []
    ctx.close()


def test_modele_inconnu_retombe_sur_le_nom_de_carte(navigateur):
    ctx, p, _ = _ouvre(navigateur, {**REEL, "model": "unknown"})
    assert p.inner_text("#pCarte") == "mochabin" and "[object Object]" not in p.inner_text("body")
    ctx.close()


def test_une_simple_chaine_reste_acceptee(navigateur):
    ctx, p, _ = _ouvre(navigateur, "carte-exemple")
    assert p.inner_text("#pCarte") == "carte-exemple" and "carte-exemple" in p.inner_text("#subline")
    ctx.close()


def test_le_mode_demo_envoie_la_forme_reelle():
    assert "case '/dashboard': return r({ board: { model:" in SRC          # le démo doit imiter l'API (objet), sinon il masque le défaut
