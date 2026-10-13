# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2556 — /hardening/ au profil Aurora : pages statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "hardening" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    assert "googleapis" not in SRC and "/shared/crt-engine.js" not in SRC and "hybrid-dark" not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'hardening'" in SRC and "demo" in SRC.lower() and "embed" in SRC


def test_routes_d_ecriture_identiques_et_lectures():
    # Même appel qu'avant : POST sans corps sur /apply et /benchmark ; /install n'était pas appelée.
    assert "ecrire('/apply')" in SRC and "ecrire('/benchmark')" in SRC and "/install" not in SRC
    assert "method: 'POST'" in SRC and "body: JSON" not in SRC
    for lecture in ("'/status'", "'/components'", "'/wan-guard'"):
        assert lecture in SRC
    assert "sbx_token" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


STATUS = {"version": "2.0.0", "sysctl_applied": True, "modprobe_applied": False, "passed": 6, "total": 7, "score": 85, "checks": [
    {"id": "aslr", "name": "ASLR", "status": "pass"},
    {"id": "rp_filter", "name": "<b>Reverse Path</b>", "status": "fail", "current": "2"}]}
COMP = {"components": [{"name": "sysctl", "description": "Kernel parameter hardening", "installed": True, "path": "/etc/sysctl.d/99-secubox-hardening.conf"},
                       {"name": "modprobe", "description": "Module blacklist", "installed": False, "path": "/etc/modprobe.d/x.conf"}]}
GARDE = {"livree": True, "interface": "eth2", "ports_gardes": [8080, 9000], "ports_gardes_en_ecoute": [9000],
         "ports_non_gardes": [{"port": 8888, "adresse": "192.0.2.10"}]}
API = {("GET", "/status"): (200, STATUS), ("GET", "/components"): (200, COMP), ("GET", "/wan-guard"): (200, GARDE),
       ("POST", "/apply"): (200, {"success": True, "output": "\x1b[0;32m[OK]\x1b[0m Sysctl settings applied", "error": None}),
       ("POST", "/benchmark"): (200, {"success": True, "output": "Score: 5/6", "error": None})}


def ouvre(navigateur, url, routes, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "hardening":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        chemin = r.request.url.split("/api/v1/hardening", 1)[1].split("?")[0]
        appels.append((r.request.method, chemin, r.request.post_data))
        statut, corps = routes.get((r.request.method, chemin), (404, {}))
        r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
    p.route("http://sbx.test/api/v1/hardening/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_et_tableaux_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/hardening/", API)
    p.wait_for_selector("#bComp tr td.mono", state="attached")
    assert [p.inner_text(i) for i in ("#tScore", "#tPasses", "#tSysctl", "#tModprobe", "#tGarde")] == ["85 %", "6 / 7", "Appliqué", "Absente", "1"]
    assert p.inner_text("#etat") == "DURCI"
    # le nom d'un contrôle est du texte, jamais du HTML
    assert "<b>Reverse Path</b>" in p.inner_text("#checks") and p.locator("#checks b b").count() == 0
    assert "Valeur actuelle : 2" in p.inner_text("#checks")
    assert "8888 (192.0.2.10)" in p.inner_text("#kNon") and p.inner_text("#kIface") == "eth2"
    assert "INSTALLÉ" in p.inner_text("#bComp") and "ABSENT" in p.inner_text("#bComp")
    assert err == []
    ctx.close()


def test_etat_sans_checks_n_est_pas_un_score_zero(navigateur):
    # L'API rend 200 {success:false} quand hardeningctl échoue : pas de « 0 % ».
    routes = {**API, ("GET", "/status"): (200, {"success": False, "error": "boom"})}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/hardening/", routes)
    p.wait_for_selector("#erreur:not([hidden])")
    assert p.inner_text("#tScore") == "—" and "boom" in p.inner_text("#erreur") and p.inner_text("#etat") == "ÉTAT INCONNU"
    assert err == []
    ctx.close()


def test_appliquer_demande_confirmation_puis_poste_sans_corps(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/hardening/", API)
    p.wait_for_selector("#actions button")
    p.get_by_role("button", name="Appliquer le durcissement").click()
    assert not [a for a in appels if a[0] == "POST"]
    p.get_by_role("button", name="Confirmer").click()
    p.wait_for_function("document.getElementById('rAct').textContent.includes('appliqué')")
    assert ("POST", "/apply", None) in appels
    assert "\x1b" not in p.inner_text("#sortie") and "Sysctl settings applied" in p.inner_text("#sortie")
    ctx.close()


def test_succes_false_n_est_pas_annonce_comme_reussi(navigateur):
    routes = {**API, ("POST", "/benchmark"): (200, {"success": False, "output": "", "error": "sysctl absent"})}
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/hardening/", routes)
    p.wait_for_selector("#actions button")
    p.get_by_role("button", name="Lancer le test").click()
    p.wait_for_function("document.getElementById('rAct').textContent.includes('Échec')")
    assert "sysctl absent" in p.inner_text("#rAct") and ("POST", "/benchmark", None) in appels
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    refus = {k: (401, {"detail": "jeton requis"}) for k in API}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/hardening/", refus)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tScore", "#tPasses", "#tSysctl", "#tModprobe", "#tGarde")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/hardening/?demo=1", {})
    p.wait_for_selector("#bComp tr td.mono", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.get_by_role("button", name="Lancer le test").click()
    p.wait_for_function("document.getElementById('rAct').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/hardening/?embed=1", API, taille={"width": 420, "height": 800})
    p.wait_for_selector("#bComp tr td.mono", state="attached")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
