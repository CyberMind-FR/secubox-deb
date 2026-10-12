# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Webui NAC au profil Aurora (#2378) : contrôles statiques, sans navigateur."""
import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "www" / "nac" / "index.html"
HTML = PAGE.read_text(encoding="utf-8")


def test_spdx():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in HTML[:600]


def test_hauteur_et_demo():
    assert "sbxVue" in HTML and "onglet:'nac'" in HTML
    assert "demo" in HTML and "embed" in HTML
    assert "min-height:100vh" not in HTML and "scrollHeight" not in HTML


def test_aucun_script_externe():
    # seul le menu latéral commun est injecté par le script (hors embed et démo)
    assert not re.search(r"<script[^>]+src=", HTML)
    assert "http://" not in HTML and "https://" not in HTML.replace("https://secubox.in", "")


def test_pas_de_lorem_ni_secret():
    low = HTML.lower()
    assert "lorem" not in low
    for mot in ("password", "passwd", "secret", "private key"):
        assert mot not in low


def test_pas_de_dialogue_navigateur():
    assert not re.search(r"(?<![\w.])(confirm|alert|prompt)\(", HTML)


def test_routes_lecture():
    for r in ("/api/v1/nac", "/status", "/clients", "/quarantine", "/policy", "/history"):
        assert r in HTML


def test_routes_ecriture_identiques_a_l_ancienne_page():
    # ancienne page : POST /quarantine et /unquarantine, corps JSON {mac}, jeton sbx_token, credentials include
    assert "api('/quarantine',{method:'POST'" in HTML
    assert "api('/unquarantine',{method:'POST'" in HTML
    assert "JSON.stringify({mac:r.mac})" in HTML
    assert "'Content-Type':'application/json'" in HTML
    assert "sbx_token" in HTML and "credentials:'include'" in HTML


def test_mesure_absente_en_tiret():
    assert "'—'" in HTML


def test_menu_lateral_hors_embed():
    assert "/shared/sidebar.js" in HTML and "EMB" in HTML


def test_conteneurs_lxc_isoles_de_la_liste_des_appareils_2410():
    """#2410 : les conteneurs LXC ont leur panneau ; ils ne sont ni dans la liste, ni dans les tuiles et répartitions."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1] / "www" / "nac" / "index.html").read_text(encoding="utf-8")
    assert 'id="lxc"' in src and "Conteneurs LXC" in src
    assert "LISTE=TOUS.filter(function(r){return !r.lxc;})" in src   # appareils = hors conteneurs
    assert "LXC=TOUS.filter(function(r){return r.lxc;})" in src
    assert "var r=TOUS[Number(b.getAttribute('data-ok'))]" in src     # l'action retrouve l'appareil par son indice d'origine
    assert "ct-exemple" in src and "exemple" in src                    # démonstration : noms fictifs


def test_nac_administrable_zones_autoriser_bloquer_et_comportements_2417():
    """#2417 : affecter une zone, autoriser, bloquer (avec confirmation intégrée) et voir le comportement réel des zones."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1] / "www" / "nac" / "index.html").read_text(encoding="utf-8")
    assert "api('/add_to_zone'" in src and "api('/allow/'" in src and "api('/deny/'" in src
    assert 'data-act="zone:' in src and 'data-act="allow"' in src and 'data-act="deny"' in src
    assert "jget('/zone_behaviors')" in src and 'id="comport"' in src
    assert "Non disponible dans cette version" in src
    assert "confirm(" not in src and "alert(" not in src       # la confirmation est intégrée à la page


def test_tuiles_de_synthese_sont_des_boutons_de_filtre_2421():
    """#2421 : cliquer une tuile filtre la liste ; re-cliquer retire le filtre ; « Appareils » remet tout à zéro. Test dans un vrai navigateur."""
    import pathlib
    import pytest
    sync_api = pytest.importorskip("playwright.sync_api")
    page = pathlib.Path(__file__).resolve().parents[1] / "www" / "nac" / "index.html"
    erreurs = []
    with sync_api.sync_playwright() as p:
        try:
            nav = p.chromium.launch()
        except Exception as e:
            pytest.skip(f"chromium indisponible : {e}")
        pg = nav.new_page()
        pg.on("pageerror", lambda e: erreurs.append(str(e)))
        pg.goto("file://" + str(page) + "?demo=1")
        pg.wait_for_timeout(500)
        total = pg.evaluate("document.querySelectorAll('#rang .app-c').length")
        assert pg.evaluate("document.querySelectorAll('#tuiles button.tuile[data-f]').length") == 6
        pg.click('#tuiles [data-f="fe:quarantaine"]')
        quarantaine = pg.evaluate("document.querySelectorAll('#rang .app-c').length")
        assert 0 < quarantaine < total
        assert pg.evaluate("document.querySelector('#tuiles [data-f=\"fe:quarantaine\"]').getAttribute('aria-pressed')") == "true"
        assert pg.evaluate("document.querySelector('#fe').value") == "quarantaine"      # cohérent avec la liste déroulante
        pg.click('#tuiles [data-f="fe:quarantaine"]')                                      # re-clic : filtre retiré
        assert pg.evaluate("document.querySelectorAll('#rang .app-c').length") == total
        pg.click('#tuiles [data-f="fc:on"]')
        pg.click('#tuiles [data-f="reset"]')
        assert pg.evaluate("document.querySelectorAll('#rang .app-c').length") == total
        nav.close()
    assert erreurs == [], erreurs


def test_clients_reels_jonction_par_preuves_2423():
    """#2423 : les identités se regroupent par preuve (clé NAC, puis même adresse de tunnel annoncée comme déduite) ; sans preuve, rien n'est deviné."""
    import pathlib
    import pytest
    sync_api = pytest.importorskip("playwright.sync_api")
    page = pathlib.Path(__file__).resolve().parents[1] / "www" / "nac" / "index.html"
    erreurs = []
    with sync_api.sync_playwright() as p:
        try:
            nav = p.chromium.launch()
        except Exception as e:
            pytest.skip(f"chromium indisponible : {e}")
        pg = nav.new_page()
        pg.on("pageerror", lambda e: erreurs.append(str(e)))
        pg.goto("file://" + str(page) + "?demo=1")
        pg.wait_for_timeout(400)
        r = pg.evaluate("""() => {
          const U = n => ({name:n, bytes:100});
          const d = (id, nom, b) => ({device:id, name:nom, bytes:b, up_bytes:b/2, down_bytes:b/2, flows:1, usages:[U('cloud')], top_dst:[], countries:[]});
          const tb = [{mac_hash:'h1', appareil_cle:'K1'}, {mac_hash:'h2', appareil_cle:''}, {mac_hash:'h3', appareil_cle:''}, {mac_hash:'h4', appareil_cle:''}, {mac_hash:'h5', appareil_cle:''}];
          const dpi = [d('h1','iPhone · .75',300), d('h2','Android · .75',200), d('h3','Linux · .9',50), d('h4','Linux · .9',40), d('h5','Seul · .5',10)];
          const A = window.sbxReels.agreger([{cle:'K1', nom:'tel', fab:'Apple', os:'iOS', type:'phone', lxc:false}, {cle:'K2', nom:'conteneur', lxc:true}], tb, dpi);
          return A.clients.map(c => [c.preuve, c.ids.length, c.bytes, c.nom]);
        }""")
        nav.close()
    assert erreurs == [], erreurs
    assert ["nac", 2, 500, "tel"] in r            # h1 relié au NAC par sa clé ; h2 partage son adresse .75 : même appareil
    assert ["adresse", 2, 90, "Appareil · .9"] in r   # deux identités sur la même adresse, sans appareil NAC : déduit
    assert ["aucune", 1, 10, "Seul · .5"] in r         # aucune preuve : identité seule, rien de deviné
    assert len(r) == 3


def test_filtre_web_par_appareil_dans_la_carte_2430():
    """#2430 : la carte d'un appareil montre son profil de filtrage de contenus et ses requêtes classées (7 j) ; ad-guard est dit ; sans données, rien."""
    import pathlib
    import pytest
    sync_api = pytest.importorskip("playwright.sync_api")
    page = pathlib.Path(__file__).resolve().parents[1] / "www" / "nac" / "index.html"
    erreurs = []
    with sync_api.sync_playwright() as p:
        try:
            nav = p.chromium.launch()
        except Exception as e:
            pytest.skip(f"chromium indisponible : {e}")
        pg = nav.new_page()
        pg.on("pageerror", lambda e: erreurs.append(str(e)))
        pg.goto("file://" + str(page) + "?demo=1")
        pg.wait_for_timeout(500)
        lignes = pg.evaluate("[...document.querySelectorAll('#rang .app-c')].map(c => [c.querySelector('b').textContent, (c.textContent.match(/Filtre web[^A-Z]*/) || [''])[0]])")
        pg.evaluate("window.sbxWf = null")
        nav.close()
    assert erreurs == [], erreurs
    par_nom = {n: t for n, t in lignes}
    assert "profil enfants" in par_nom["iphone-bob"] and "75 bloquées / 80 classées" in par_nom["iphone-bob"]
    assert "géré par ad-guard" in par_nom["cam-entree"]
    assert par_nom["nas-atelier"] == ""                                   # aucun profil ni requête : rien d'affiché, jamais « 0 »
