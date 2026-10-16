# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2571 — /appstore/ au profil Aurora : page statique + vrai navigateur, API simulée."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "appstore" / "index.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_page_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["/shared/sidebar.js"]
    for ancien in ("/shared/crt-engine.js", "hybrid-dark", "crt-light", "design-tokens", "Cinzel", "JetBrains"):
        assert ancien not in SRC
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick=", "insertAdjacentHTML"):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'appstore'" in SRC and "demo" in SRC.lower() and "embed" in SRC
    assert "sbx_token" in SRC and "Authorization" in SRC


def test_routes_d_ecriture_a_l_identique():
    # mêmes appels que l'ancienne page : action de module, config, installation fédérée
    assert "'/module/' + encodeURIComponent(nom) + '/action/' + verbe" in SRC and "'POST'" in SRC
    assert "'PUT', '/module/' + encodeURIComponent(CUR) + '/config', { content:" in SRC
    assert "ecrire(FED, 'POST', '/install', { id: o.id, nom })" in SRC
    for r in ("/categories", "/catalog", "/groupes", "/metapaquets", "/mesh-catalog"):
        assert r in SRC
    assert "/api/v1/appstore" in SRC and "'/api/appstore'" in SRC
    # écritures : ces trois appels + l'installation à distance (#2808 : accepter/refuser par remoteAgir, et demander)
    assert len(re.findall(r"ecrire\(", SRC)) == 6   # définition + 3 appels d'origine + remoteAgir + demander


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def mod(name, cat, tier, state, desc="", version=None):
    inst = state in ("running", "installed")
    return {"name": name, "category": cat, "tier": tier, "state": state, "description": desc, "version": version,
            "installed": inst, "running": state == "running", "depends": ["secubox-core"]}


CATS = {"categories": [{"name": "media", "count": 2}, {"name": "network", "count": 1}], "board_tier": "standard"}
CATALOG = {"modules": [mod("secubox-radio", "media", "standard", "running", "Radio", "1.4.0"),
                       mod("secubox-galerie", "media", "pro", "tier-locked", "Galerie"),
                       mod("secubox-dns", "network", "lite", "installed", "DNS", "2.1.3"),
                       mod("secubox-relais", "network", "standard", "available", "Relais"),
                       mod("secubox-coffre", "network", "pro", "unpublished", "Coffre")], "count": 5, "total": 5}
# L'API compte « installés » = membres connus du catalogue : ici elle mentionne 2/2, la page doit recalculer 1/2
GROUPES = {"groupes": [{"id": "ecouter", "label": "Écouter", "description": "d", "membres": [{"name": "secubox-radio", "installed": True}, {"name": "secubox-galerie", "installed": True}], "installes": 2, "total": 2}]}
MP = {"disponible": True, "noeuds": [{"meta": "secubox", "label": "SecuBox", "niveau": "racine", "description": "socle", "requiert": ["secubox-dns"], "recommande": [], "suggere": [],
                                      "installe": True, "compte": {"requis": {"installes": 1, "total": 1}}}],
      "paquets": {"secubox-dns": {"paquet": "secubox-dns", "version": "2.1.3", "installe": True, "resume": "DNS", "depends": [{"nom": "unbound", "installe": True}], "recommends": [], "suggests": []}}}
MESH = {"catalog": [{"name": "tor-socks", "kind": "socks", "endpoint": "http://192.0.2.10:9050", "channel": "mesh", "provider_node": "sat-a", "provider_mesh_ip": "10.10.0.2"},
                    {"name": "piege", "kind": "http", "endpoint": "javascript:alert(1)", "channel": "x", "provider_node": "sat-b"}], "node_count": 2}
FEDC = {"objets": [{"id": "mb-1", "type": "metablog", "name": "Carnet", "description": "j", "author": "Atelier", "license": "MIT", "version": "1.0", "channel": "stable", "certifie": True, "verrouille": False},
                   {"id": "mb-2", "type": "metablog", "name": "<img src=x onerror=window.PWNED=1>", "description": "", "author": "x", "license": "MIT", "version": "1", "channel": "stable",
                    "certifie": False, "verrouille": False, "motif": "inconnu"}], "canaux_ouverts": ["stable"]}
LECTURES = {"/categories": CATS, "/catalog": CATALOG, "/groupes": GROUPES, "/metapaquets": MP, "/mesh-catalog": MESH}


def ouvre(navigateur, url, statut_lecture=200, ecritures=None, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1400, "height": 900})
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("shared/"):
            r.fulfill(status=200, content_type="text/css" if chemin.endswith(".css") else "application/javascript", body="")
        elif chemin.rstrip("/") == "appstore":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        m = r.request.method
        appels.append((m, u, r.request.post_data, r.request.headers.get("authorization")))
        if m == "GET":
            if statut_lecture != 200:
                return r.fulfill(status=statut_lecture, content_type="application/json", body='{"detail":"jeton requis"}')
            corps = FEDC if u == "/api/appstore/catalog" else LECTURES.get(u.replace("/api/v1/appstore", ""), None)
            if u.endswith("/config"):
                corps = {"path": "/etc/secubox/radio.toml", "exists": True, "readable": True, "content": "port = 1\n"}
            return r.fulfill(status=200 if corps is not None else 404, content_type="application/json", body=json.dumps(corps or {}))
        st, c = (ecritures or {}).get(u, (200, {"status": "ok"}))
        r.fulfill(status=st, content_type="application/json", body=json.dumps(c))
    p.route("http://sbx.test/api/**", api)
    p.goto(url)
    return ctx, p, erreurs, appels


def test_tuiles_cartes_et_groupes_viennent_de_l_api(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/appstore/")
    p.wait_for_selector("#grille .carte")
    assert [p.inner_text(i) for i in ("#tTotal", "#tInst", "#tRun", "#tDispo", "#tTier")] == ["5", "2", "1", "1", "standard"]
    assert p.inner_text("#etat") == "EN LIGNE" and p.locator("#grille .carte").count() == 5
    # le compte du groupe est recalculé d'après l'état réel (1 installé sur 2), pas le « 2/2 » de l'API
    assert p.inner_text("#groupes .groupe .n") == "1/2"
    p.fill("#q", "dns")
    assert p.locator("#grille .carte").count() == 1
    p.fill("#q", ""); p.select_option("#fEtat", "unpublished")
    assert p.locator("#grille .carte").count() == 1 and "NON PUBLIÉ" in p.inner_text("#grille")
    p.select_option("#fEtat", ""); p.click("#groupes .groupe")
    assert p.locator("#grille .carte").count() == 2
    assert "SecuBox" in p.inner_text("#arbre") and "tor-socks" in p.inner_text("#bMesh")
    assert err == []
    ctx.close()


def test_donnees_d_api_jamais_interpretees_en_html(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/appstore/")
    p.wait_for_selector("#fGrille .carte")
    p.click("#fPuces >> text=Métablogs")
    assert "<img src=x" in p.inner_text("#fGrille") and p.evaluate("window.PWNED === undefined")
    # un point d'accès non http(s) n'est pas un lien
    assert p.locator("#bMesh a").count() == 1 and "javascript:" in p.inner_text("#bMesh")
    assert err == []
    ctx.close()


def test_arreter_un_module_demande_confirmation_et_envoie_le_jeton(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/appstore/")
    p.add_init_script("localStorage.setItem('sbx_token','jwt-test')"); p.reload()
    p.wait_for_selector("#grille .carte")
    carte = p.locator("#grille .carte", has_text="radio")
    carte.get_by_text("Arrêter").click()
    assert not [a for a in appels if a[0] == "POST"]                   # pas encore : il faut confirmer
    assert "Arrêter radio ?" in p.inner_text("#grille")
    carte.get_by_text("Confirmer").click()
    p.wait_for_function("document.getElementById('rMod').textContent.includes('effectué')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/api/v1/appstore/module/secubox-radio/action/stop" and post[2] is None and post[3] == "Bearer jwt-test"
    ctx.close()


def test_redemarrer_sans_confirmation_et_refus_affiche(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/appstore/", ecritures={"/api/v1/appstore/module/secubox-radio/action/restart": (409, {"detail": "verrou dpkg"})})
    p.wait_for_selector("#grille .carte")
    p.locator("#grille .carte", has_text="radio").get_by_text("Redémarrer").click()
    p.wait_for_function("document.getElementById('rMod').textContent.includes('verrou dpkg')")
    ctx.close()


def test_config_enregistre_avec_le_meme_corps_apres_confirmation(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/appstore/")
    p.wait_for_selector("#grille .carte")
    p.locator("#grille .carte", has_text="radio").get_by_text("Config").click()
    p.wait_for_function("document.getElementById('cfgTexte').value.includes('port')")
    p.fill("#cfgTexte", "port = 2\n")
    p.click("#cfgActs >> text=Enregistrer")
    assert not [a for a in appels if a[0] == "PUT"]
    p.click("#cfgActs >> text=Confirmer")
    p.wait_for_function("document.getElementById('cfgMsg').textContent.includes('enregistré')")
    put = [a for a in appels if a[0] == "PUT"][0]
    assert put[1] == "/api/v1/appstore/module/secubox-radio/config" and json.loads(put[2]) == {"content": "port = 2\n"}
    assert err == []
    ctx.close()


def test_installation_federee_confirmee_dans_la_page(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "http://sbx.test/appstore/", ecritures={"/api/appstore/install": (200, {"nom": "Carnet-copie", "suite": "à publier"})})
    p.wait_for_selector("#fGrille .carte")
    p.locator("#fGrille .carte", has_text="Carnet").get_by_text("Installer").click()
    assert not [a for a in appels if a[0] == "POST"]
    assert p.input_value("#fGrille input") == "Carnet-copie"
    p.fill("#fGrille input", "mon-site")
    p.click("text=Confirmer l’installation")
    p.wait_for_function("document.getElementById('rFed').textContent.includes('Installé')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "/api/appstore/install" and json.loads(post[2]) == {"id": "mb-1", "nom": "mon-site"}
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/appstore/", statut_lecture=401)
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tTotal", "#tInst", "#tRun", "#tDispo", "#tTier")] == ["—"] * 5 and err == []
    ctx.close()


def test_demonstration_annoncee_et_actions_inertes(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/appstore/?demo=1")
    p.wait_for_selector("#grille .carte")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    p.locator("#grille .carte", has_text="dns").get_by_text("Redémarrer").click()
    p.wait_for_function("document.getElementById('rMod').textContent.includes('inerte')")
    assert appels == [] and err == []
    ctx.close()


def test_telephone_sans_debordement_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/appstore/?embed=1&demo=1", taille={"width": 420, "height": 800})
    p.wait_for_selector("#grille .carte")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert not p.is_visible("#sidebar") and err == []
    ctx.close()
