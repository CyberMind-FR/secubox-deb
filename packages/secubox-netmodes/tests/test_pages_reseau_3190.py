# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3190 — panneau Réseau : hôte à onglets (index.html), Cartographie (carte.html) et Liens du maillage (maillage.html).

Tests statiques (§ 11.1 du profil Aurora) puis vrai navigateur si Playwright est installé : démonstration à 1400 et 420 px,
aucun débordement ni erreur JS, bascule des onglets (src et hauteur de l'iframe), et sources en panne (file://, 401, 503)
affichées comme des pannes, jamais comme « aucun »."""
import concurrent.futures
import ipaddress
import json
import re
import time
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parents[1]
WWW = ICI / "www" / "netmodes"
PAGES = {"index": WWW / "index.html", "carte": WWW / "carte.html", "maillage": WWW / "maillage.html"}
SRC = {k: p.read_text(encoding="utf-8") for k, p in PAGES.items()}
DOC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

ROUTES = {
    "carte": ["/api/v1/netmodes/reseau/carte", "/api/v1/netmodes/reseau/ports", "/api/v1/netmodes/reseau/clients",
              "/api/v1/netmodes/routeur/etat", "/api/v1/p2p/peers", "/api/v1/wireguard/peers/status", "/api/v1/wireguard/summary"],
    "maillage": ["/api/v1/p2p/peers", "/api/v1/wireguard/peers/status", "/api/v1/wireguard/summary"],
}
# Identifiants de l'ancienne page que tests/test_page_aurora_2457.py et son script utilisent : tous conservés.
ANCIENS_IDS = ["sMode", "sModeS", "sWan", "sWanS", "sIf", "sDet", "sDetS", "sLast", "inconnu", "interfaces", "dialogue", "resultat",
               "detection", "aperc", "aperN", "yaml", "modes", "pastille", "subline", "heure", "btn-refresh", "demo", "btnValider", "btnRestaurer"]


def _code(s):
    """Le script sans commentaires ; la sonde XSS de la démonstration héritée est retirée."""
    return re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", s, flags=re.S)).replace("onerror=alert(1)", "")


# ── Statique ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("k", list(PAGES))
def test_page_autonome_sans_dependance_ni_boite_native(k):
    s = SRC[k]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s
    assert re.findall(r"<script[^>]*\bsrc=", s) == []                       # aucun script externe écrit dans la page
    assert re.findall(r"\.src\s*=\s*['\"]([^'\"]+)['\"]", s) == ["/shared/sidebar.js"]   # le menu commun, seul, chargé par le script
    assert re.search(r"if \(EMB \|\| DEMO\)", s)                             # … hors ?embed=1 et hors démonstration
    for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "fonts.googleapis", "hybrid-skin", "Math.random"):
        assert interdit not in s, interdit
    code = _code(s)
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f
    assert "lorem" not in s.lower()
    assert "@container a" in s and "container-type:inline-size" in s
    # hauteur : le cadre, jamais le document
    assert "sbxVue" in s and "getBoundingClientRect().bottom" in s and "location.origin" in s
    assert "scrollHeight" not in s and "100vh" not in s
    # jeton : sbx_token en Bearer, lecture protégée, jamais écrit
    assert "localStorage.getItem('sbx_token')" in s or 'localStorage.getItem("sbx_token")' in s
    assert "setItem" not in s and "Bearer " in s


@pytest.mark.parametrize("k", list(PAGES))
def test_demo_avec_adresses_de_documentation_seulement(k):
    s = SRC[k]
    assert "demo" in s and "DÉMONSTRATION" in s
    for ip in re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", s):
        assert any(ipaddress.ip_address(ip) in n for n in DOC), ip
    assert "gk2.secubox" not in s and "secubox.in" not in s


@pytest.mark.parametrize("k", ["carte", "maillage"])
def test_onglet_lecture_seule_routes_citees(k):
    s = SRC[k]
    for r in ROUTES[k]:
        assert r in s, r
    for m in ("'POST'", '"POST"', "'PUT'", '"PUT"', "'DELETE'", '"DELETE"', "'PATCH'", '"PATCH"', "JSON.stringify"):
        assert m not in s, m
    assert 'method: "GET"' in s and s.count("fetch(") == 1
    assert ('var ONGLET = "%s";' % k) in s and "onglet: ONGLET" in s
    assert "full_key" in s and '"wg-mesh"' in s                               # jointure p2p × WireGuard par clé complète
    assert "session requise" in s and "source en panne" in s


def test_hote_onglets_iframe_et_hauteur_verifiee():
    s = SRC["index"]
    assert 'role="tablist"' in s and s.count('role="tab"') == 6 and len(re.findall(r'<button[^>]*aria-selected="true"', s)) == 1
    assert re.search(r'id="onglet-carte"[^>]*aria-selected="true"', s)
    vues = re.findall(r'data-vue="([^"]+)"', s)
    assert vues == ["carte.html", "switch.html", "clients.html", "maillage.html", "routeur.html"]
    assert "page + '?embed=1' + (DEMO ? '&demo=1' : '')" in s                  # ?embed=1 toujours, ?demo=1 propagé
    assert s.count("<iframe") == 1
    assert "e.origin !== location.origin" in s and "e.source !== vue.contentWindow" in s and "e.data.onglet !== courant" in s
    assert "Math.min(4000, Math.max(300," in s
    assert "/routeur/etat" in s and "Passer au mode routeur durable" in s and "LAN temporaire" in s
    assert "focus-visible" in s and "ArrowRight" in s


def test_hote_garde_l_ancienne_page_et_ses_ecritures_a_l_identique():
    s = SRC["index"]
    for i in ANCIENS_IDS:
        assert s.count('id="%s"' % i) == 1, i
    assert 'id="ecran-modes" role="tabpanel"' in s and 'data-onglet="modes"' in s
    # les deux seules écritures sont celles de l'ancienne page, appel identique
    assert "appeler('/apply_mode', 'POST', { mode: m.id })" in s and "appeler('/rollback', 'POST')" in s
    assert s.count("'POST'") == 2
    for r in ("/get_available_modes", "/status", "/detect", "/preview_changes?mode=", "/validate_config"):
        assert r in s
    assert "/interfaces'" not in s and "/current_mode'" not in s


def test_menu_reseau_en_francais():
    m = json.loads((ICI / "menu.d" / "30-netmodes.json").read_text(encoding="utf-8"))
    assert m["name"] == "Réseau" and m["path"] == "/netmodes/" and m["id"] == "netmodes"
    assert "maillage" in m["description"] and "routeur" in m["description"] and "Network" not in json.dumps(m)


# ── Navigateur ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def _avec_navigateur(scenario):
    sync_api = pytest.importorskip("playwright.sync_api")

    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:      # navigateur absent : test sauté, pas en échec
                return ("skip", str(e))
            try:
                return ("ok", scenario(nav))
            finally:
                nav.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=240)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1]


def _page(nav, api=None, taille=(1400, 900)):
    """Pages servies par une origine http fictive (postMessage exige une vraie origine), API simulée par `api`."""
    ctx = nav.new_context(viewport={"width": taille[0], "height": taille[1]})
    pg = ctx.new_page()
    j = {"erreurs": [], "natifs": [], "appels": []}
    pg.on("pageerror", lambda e: j["erreurs"].append(str(e)))
    pg.on("dialog", lambda d: (j["natifs"].append(d.type), d.dismiss()))

    def servir(r):
        chemin = r.request.url.split("http://t.test/", 1)[1].split("?")[0].split("#")[0]
        if chemin.startswith("api/"):
            j["appels"].append((r.request.method, chemin))
            st, corps = (api or {}).get(chemin[len("api/v1/"):], (404, {"detail": "absent"}))
            return r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
        if chemin.startswith("netmodes/"):
            f = WWW / (chemin.split("/", 1)[1] or "index.html")
            if f.is_file():
                return r.fulfill(status=200, content_type="text/html", body=f.read_text(encoding="utf-8"))
        r.fulfill(status=404, content_type="text/plain", body="absent")
    pg.route("http://t.test/**", servir)
    return ctx, pg, j


def _cadre(pg):
    return pg.query_selector("#vue").content_frame()


def _sans_debordement(page_ou_cadre):
    return page_ou_cadre.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")


def test_demo_hote_bascule_les_onglets_src_et_hauteur_sans_appel_ni_erreur():
    def scenario(nav):
        ctx, pg, j = _page(nav)
        pg.goto("http://t.test/netmodes/?demo=1")
        pg.wait_for_function("document.getElementById('vue').style.height !== '1000px'", timeout=8000)
        r = {"defaut": pg.evaluate("document.querySelector('[aria-selected=true]').dataset.onglet"),
             "src": pg.get_attribute("#vue", "src"), "h": pg.evaluate("parseInt(document.getElementById('vue').style.height)"),
             "bandeau": pg.inner_text("#bandeauLan"), "demo": pg.is_visible("#demo"), "onglets": {}}
        for o in ("switch", "clients", "maillage", "routeur", "carte", "modes"):
            pg.click("#onglet-" + o)
            pg.wait_for_timeout(150)
            if o in ("maillage", "carte"):
                pg.wait_for_function("document.getElementById('vue').style.height !== '1000px'", timeout=8000)
            r["onglets"][o] = (pg.evaluate("document.querySelector('[aria-selected=true]').dataset.onglet"), pg.get_attribute("#vue", "src"),
                               pg.evaluate("parseInt(document.getElementById('vue').style.height)"), pg.is_visible("#vue"),
                               pg.is_visible("#ecran-modes"), pg.evaluate("location.hash"))
        r["modes"] = pg.locator(".mode").count()
        pg.click("#onglet-carte")
        pg.click("#versRouteur")
        r["vers"] = pg.get_attribute("#vue", "src")
        r["deb"] = _sans_debordement(pg)
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["defaut"] == "carte" and r["src"] == "carte.html?embed=1&demo=1" and 300 <= r["h"] <= 4000 and r["h"] != 1000
    assert r["demo"] and "LAN temporaire" in r["bandeau"] and "198.51.100.1/24" in r["bandeau"]
    for o in ("switch", "clients", "routeur"):
        sel, src, _h, vue, modes, ancre = r["onglets"][o]
        assert sel == o and src == o + ".html?embed=1&demo=1" and vue and not modes and ancre == "#" + o
    sel, src, h, vue, modes, _ = r["onglets"]["maillage"]
    assert sel == "maillage" and src == "maillage.html?embed=1&demo=1" and 300 <= h <= 4000 and h != 1000
    sel, _src, _h, vue, modes, ancre = r["onglets"]["modes"]
    assert sel == "modes" and not vue and modes and ancre == "#modes" and r["modes"] == 5
    assert r["vers"] == "routeur.html?embed=1&demo=1" and r["deb"]
    assert j["erreurs"] == [] and j["natifs"] == [] and j["appels"] == []   # démonstration : aucune requête, donc aucune écriture


def test_hauteur_refusee_hors_de_l_iframe_ou_d_un_autre_onglet():
    def scenario(nav):
        ctx, pg, j = _page(nav)
        pg.goto("http://t.test/netmodes/?demo=1")
        pg.wait_for_function("document.getElementById('vue').style.height !== '1000px'", timeout=8000)
        pg.wait_for_timeout(400)

        def h():
            return pg.evaluate("document.getElementById('vue').style.height")
        pg.evaluate("window.postMessage({sbxVue: 2222, onglet: 'carte'}, location.origin)")          # source : l'hôte lui-même
        pg.wait_for_timeout(200)
        a = h()
        _cadre(pg).evaluate("parent.postMessage({sbxVue: 3333, onglet: 'switch'}, location.origin)")  # mauvais onglet
        pg.wait_for_timeout(200)
        b = h()
        _cadre(pg).evaluate("parent.postMessage({sbxVue: 9999, onglet: 'carte'}, location.origin)")  # borné à 4000
        pg.wait_for_function("document.getElementById('vue').style.height === '4000px'", timeout=3000)
        ctx.close()
        return a, b, j
    a, b, j = _avec_navigateur(scenario)
    assert a != "2226px" and b != "3337px" and j["erreurs"] == []


@pytest.mark.parametrize("page", ["index.html?demo=1#carte", "index.html?demo=1#maillage", "index.html?demo=1#modes", "carte.html?demo=1", "maillage.html?demo=1"])
def test_demo_420_px_sans_defilement_horizontal(page):
    def scenario(nav):
        ctx, pg, j = _page(nav, taille=(420, 900))
        pg.goto("http://t.test/netmodes/" + page)
        pg.wait_for_timeout(900)
        dedans = True
        if page.startswith("index") and "#modes" not in page:
            dedans = _sans_debordement(_cadre(pg))
        r = (_sans_debordement(pg), dedans)
        ctx.close()
        return r, j
    (page_ok, cadre_ok), j = _avec_navigateur(scenario)
    assert page_ok and cadre_ok and j["erreurs"] == [] and j["appels"] == []


def test_lien_direct_modes_herite_garde_confirmation_integree_et_demo_inerte():
    """Les comportements de l'ancienne page (#2457), dans l'onglet « Modes (hérité) »."""
    def scenario(nav):
        ctx, pg, j = _page(nav)
        pg.goto("http://t.test/netmodes/index.html?demo=1#modes")
        pg.wait_for_selector(".mode")
        n, mode, wan, ifs = pg.locator(".mode").count(), pg.inner_text("#sMode"), pg.inner_text("#sWan"), pg.inner_text("#sIf")
        xss = pg.locator("#interfaces img").count()
        pg.click(".mode:nth-child(2) .btn.danger")
        pg.wait_for_selector("#dialogue:not([hidden])")
        grave, m = pg.evaluate("document.getElementById('dialogue').classList.contains('grave')"), pg.inner_text("#dialogue")
        pg.click("#dialogue .btn:not(.danger)")
        pg.wait_for_selector("#dialogue[hidden]", state="attached")
        annule = pg.inner_text("#resultat")
        pg.click(".mode:nth-child(1) .btn.danger")
        pg.wait_for_selector("#dialogue:not([hidden])")
        pg.click("#dialogue .btn.danger")
        pg.wait_for_function("document.getElementById('resultat').textContent.includes('inerte')")
        ctx.close()
        return (n, mode, wan, ifs, xss, grave, m, annule), j
    (n, mode, wan, ifs, xss, grave, m, annule), j = _avec_navigateur(scenario)
    assert n == 5 and mode == "Routeur" and wan == "eth2" and ifs == "2 / 3" and xss == 0
    assert grave and "netplan apply" in m and "Sniffer Inline" in m and annule == ""
    assert j["erreurs"] == [] and j["natifs"] == [] and j["appels"] == []


def test_modes_herite_mode_non_enregistre_affiche_inconnu():
    api = {"netmodes/get_available_modes": (200, [{"id": "router", "name": "Routeur", "desc": "d"}]),
           "netmodes/status": (200, {"mode_connu": False, "current_mode": None, "last_change": None, "wan": {"interface": None, "passerelle": None}, "interfaces": []}),
           "netmodes/routeur/etat": (200, {"etat": "actif", "bascule_en_cours": False, "adresses_pont": ["198.51.100.1/24"]})}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/index.html#modes")
        pg.wait_for_function("document.getElementById('sMode').textContent !== '—'")
        r = (pg.inner_text("#sMode"), pg.is_visible("#inconnu"), pg.inner_text("#sWan"), pg.locator(".mode.cur").count(),
             pg.inner_text("#pastilleRouteur"), pg.is_visible("#bandeauLan"))
        ctx.close()
        return r, j
    (mode, bandeau, wan, cur, pastille, lan), j = _avec_navigateur(scenario)
    assert mode == "Inconnu" and bandeau and wan == "aucune" and cur == 0
    assert pastille == "MODE ROUTEUR ACTIF" and not lan                     # « actif » : aucun bandeau LAN temporaire
    assert j["erreurs"] == [] and ("GET", "api/v1/netmodes/detect") in j["appels"]
    assert not any(m != "GET" for m, _ in j["appels"])


def test_bandeau_a_confirmer_compte_jusqu_a_l_echeance_reelle():
    ech = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 150))
    api = {"netmodes/routeur/etat": (200, {"etat": "en_attente", "depuis": "2000-01-01T00:00:00Z", "echeance": ech, "bascule_en_cours": False,
                                           "adresses_pont": ["198.51.100.1/24"], "dhcp_actif": True})}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/")
        pg.wait_for_selector("#bandeauLan:not([hidden])")
        r = (pg.inner_text("#pastilleRouteur"), pg.inner_text("#bandeauLan"))
        ctx.close()
        return r, j
    (pastille, bandeau), j = _avec_navigateur(scenario)
    assert pastille == "MODE ROUTEUR À CONFIRMER" and "retour automatique" in bandeau
    assert re.search(r"dans (2 min|1 min 5\d s|2 min 0\d s|2 min 1\d s|2 min 2\d s|2 min 30 s)", bandeau), bandeau   # échéance réelle, jamais depuis + 180
    assert j["erreurs"] == []


def test_sans_session_sous_file_les_sources_sont_en_panne_jamais_vides():
    """fetch() refusé sous file:// : c'est le cas « sans session » du profil Aurora (§ 11.3)."""
    def scenario(nav):
        ctx = nav.new_context(viewport={"width": 1400, "height": 900})
        pg = ctx.new_page()
        erreurs = []
        pg.on("pageerror", lambda e: erreurs.append(str(e)))
        r = {}
        pg.goto("file://" + str(PAGES["carte"]))
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        r["carte"] = (pg.inner_text("#etatSources"), pg.locator(".src.panne").count(), pg.locator(".src").count(),
                      pg.evaluate("document.getElementById('schema').textContent"))
        pg.goto("file://" + str(PAGES["maillage"]))
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        r["maillage"] = (pg.inner_text("#pairs"), pg.inner_text("#tunnels"), pg.inner_text("#tPairs"), pg.inner_text("#tActifs"), pg.inner_text("#tRetirer"))
        pg.goto("file://" + str(PAGES["index"]))
        pg.wait_for_function("document.getElementById('pastilleRouteur').textContent !== 'LECTURE…'")
        r["index"] = (pg.inner_text("#pastilleRouteur"), pg.is_visible("#bandeauLan"), pg.get_attribute("#vue", "src"))
        ctx.close()
        return r, erreurs
    r, erreurs = _avec_navigateur(scenario)
    etat, pannes, total, schema = r["carte"]
    assert "EN PANNE" in etat and pannes == total == 7
    assert "Maillage illisible" in schema and "aucun pair" not in schema and "aucun autre tunnel" not in schema and "aucun appareil" not in schema
    assert "source en panne" in schema
    pairs, tunnels, n, actifs, retirer = r["maillage"]
    assert "Maillage illisible" in pairs and "Aucun pair" not in pairs and "Aucun autre tunnel" not in tunnels and "source en panne" in tunnels
    assert n == actifs == retirer == "—"
    pastille, bandeau, src = r["index"]
    assert pastille == "ÉTAT DU ROUTEUR ILLISIBLE" and not bandeau and src == "carte.html?embed=1"
    assert erreurs == []


CLE = {i: "K%02d" % i + "x" * 41 for i in range(1, 6)}
P2P = {"peers": [
    {"id": "gk1-demo", "name": "gk1-demo", "address": "203.0.113.8", "public_key": CLE[1], "status": "online", "latency": None, "last_seen": None},
    {"id": "ebin-demo", "name": "ebin-demo", "address": "203.0.113.7", "public_key": CLE[2], "status": "offline", "latency": None, "last_seen": None},
    {"id": "203.0.113.2", "name": "203.0.113.2", "address": "203.0.113.2", "public_key": CLE[3], "status": "offline", "latency": None, "last_seen": None},
    {"id": "x", "name": "<img src=x onerror=alert(1)>", "address": "203.0.113.9", "public_key": CLE[4], "status": "offline", "latency": None, "last_seen": None}],
    "count": 4}


def _wg(cle, iface="wg-mesh", st="offline", s=None, rx=0, ips=None):
    return {"interface": iface, "public_key": cle[:16] + "...", "full_key": cle, "status": st, "endpoint": None, "allowed_ips": ips or [],
            "last_handshake": None, "seconds_since_handshake": s, "rx_bytes": rx, "tx_bytes": 0, "persistent_keepalive": None}


WG = {"peers": [_wg(CLE[1], st="online", s=6, rx=int(4.5 * 1024 ** 3)), _wg(CLE[2]), _wg(CLE[3], s=40 * 86400, rx=1024),
                _wg(CLE[4]), _wg(CLE[5], ips=["203.0.113.66/32"]), _wg("AUTRE" + "y" * 39, iface="wg-toolbox", st="online", s=3)],
      "total": 6, "online": 2, "offline": 4}
SUM = {"interfaces": [{"name": "wg-mesh", "listen_port": 51822, "peers": 5, "online": 1, "rx_bytes": 1, "tx_bytes": 1},
                      {"name": "wg-toolbox", "listen_port": 51820, "peers": 8, "online": 1, "rx_bytes": 2048, "tx_bytes": 0}], "totals": {}}


def test_maillage_jointure_par_cle_a_retirer_et_valeurs_en_texte_brut():
    api = {"p2p/peers": (200, P2P), "wireguard/peers/status": (200, WG), "wireguard/summary": (200, SUM)}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/maillage.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        lignes = pg.evaluate("[...document.querySelectorAll('#pairs tr')].map(tr => [...tr.cells].map(td => td.textContent.trim()))")
        r = (lignes, pg.inner_text("#tunnels"), pg.inner_text("#meshNote"), pg.locator("#pairs img").count(),
             [pg.inner_text(i) for i in ("#tPairs", "#tActifs", "#tMuets", "#tRetirer")], pg.inner_text("#etatSources"))
        ctx.close()
        return r, j
    (lignes, tunnels, note, imgs, tuiles, etat), j = _avec_navigateur(scenario)
    par_ip = {ligne[1]: ligne for ligne in lignes}
    assert par_ip["203.0.113.8"][0].startswith("gk1-demo") and par_ip["203.0.113.8"][2] == "il y a 6 s" and par_ip["203.0.113.8"][3] == "4,5 Go" and par_ip["203.0.113.8"][4] == "actif"
    assert par_ip["203.0.113.7"][2] == "jamais" and par_ip["203.0.113.7"][4] == "muet"
    assert par_ip["203.0.113.2"][0].startswith("sans nom") and par_ip["203.0.113.2"][4] == "à retirer ?"   # nom = adresse : sans nom
    assert par_ip["203.0.113.66"][0].startswith("sans nom") and par_ip["203.0.113.66"][4] == "à retirer ?"  # sur wg-mesh, absent du registre
    assert par_ip["203.0.113.9"][0].startswith("<img src=x onerror=alert(1)>") and imgs == 0
    assert len(lignes) == 5 and not any(ligne[0].startswith("AUTRE") for ligne in lignes)                    # wg-toolbox n'est pas le maillage
    assert "wg-toolbox" in tunnels and "51820" in tunnels and "1 en ligne" in tunnels and "wg-mesh" not in tunnels
    assert note == "wg-mesh · UDP 51822" and tuiles == ["5", "1", "2", "2"] and etat == "TOUTES LES SOURCES LUES"
    assert j["erreurs"] == [] and j["natifs"] == [] and all(m == "GET" for m, _ in j["appels"])


def test_wireguard_503_et_401_affiches_en_panne_jamais_aucun_pair():
    api = {"p2p/peers": (200, P2P), "wireguard/peers/status": (503, {"detail": "wgctl dump en échec : délai"}),
           "wireguard/summary": (401, {"detail": "Not authenticated"}),
           "netmodes/reseau/carte": (200, {"carte": {"wan": {"interface": "eth2", "adresse": "192.0.2.200/24", "passerelle": "192.0.2.254", "nb_voisins": 2},
                                                     "lxc": {"pont": "br-lxc", "actifs": 3}, "tunnels": [{"nom": "wg-mesh", "etat": "up"}, {"nom": "wg-toolbox", "etat": "up"}]}, "pannes": []}),
           "netmodes/reseau/ports": (200, {"ports": [{"nom": "lan0", "role": "lan", "porteuse": True, "vitesse_mbps": 1000, "etat_admin": "up", "maitre": "br-lan",
                                                      "nb_appareils": 1, "plusieurs_appareils": False, "coupe": False}], "pannes": []}),
           "netmodes/reseau/clients": (401, {"detail": "Not authenticated"}),
           "netmodes/routeur/etat": (200, {"etat": "actif", "bascule_en_cours": False, "adresses_pont": ["198.51.100.1/24"]})}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/maillage.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        m = (pg.inner_text("#meshPannes"), pg.inner_text("#pairs"), pg.inner_text("#tunnels"), pg.is_visible("#session"),
             pg.evaluate("[...document.querySelectorAll('.src')].map(e => e.className)"), pg.inner_text("#tActifsS"),
             pg.evaluate("[...document.querySelectorAll('#pairs tr')].map(tr => tr.cells[3].textContent)"))
        pg.goto("http://t.test/netmodes/carte.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        c = (pg.evaluate("document.getElementById('schema').textContent"), pg.inner_text("#sessionTexte"))
        ctx.close()
        return m, c, j
    m, c, j = _avec_navigateur(scenario)
    pannes, pairs, tunnels, session, classes, actifs_s, recus = m
    assert "WireGuard" in pannes and "source en panne" in pannes and "wgctl dump en échec" in pannes
    assert "gk1-demo" in pairs and "Aucun pair" not in pairs and set(recus) == {"—"}                # noms lus, volumes inconnus
    assert "session requise" in tunnels and "Aucun autre tunnel" not in tunnels
    assert session and classes == ["src ok", "src panne", "src session"] and actifs_s == "selon le registre p2p"
    schema, session_txt = c
    assert "état et volumes : WireGuard, source en panne" in schema and "ports et pairs : WireGuard, session requise" in schema
    assert "wg-toolbox" in schema and "aucun pair" not in schema and "aucun autre tunnel" not in schema
    assert "2 voisins · adresses : session requise" in schema and "nom : session requise" in schema
    assert "2 sources" in session_txt                                        # clients et tunnels en 401 ; pairs WireGuard en 503
    assert j["erreurs"] == [] and all(meth == "GET" for meth, _ in j["appels"])


# ── Valeurs absentes ou d'un autre format : « — », jamais « null », « aucun » ni « NaN » (revue de la tâche 5) ──────────────────
SUM_NULL = {"interfaces": [{"name": "wg-x", "listen_port": 51999, "peers": None, "online": None, "rx_bytes": None, "tx_bytes": None},
                           {"name": "wg-zero", "listen_port": 51998, "peers": 3, "online": 0, "rx_bytes": 0, "tx_bytes": 0}], "totals": {}}


def test_tunnels_pairs_et_en_ligne_absents_affiches_tiret_seul_un_vrai_zero_dit_aucun_lien():
    api = {"p2p/peers": (200, {"peers": [], "count": 0}), "wireguard/peers/status": (200, {"peers": [], "total": 0, "online": 0, "offline": 0}),
           "wireguard/summary": (200, SUM_NULL),
           "netmodes/reseau/carte": (200, {"carte": {"wan": None, "lxc": {"pont": "br-lxc", "actifs": None}, "tunnels": None}, "pannes": ["wan_addr", "liens_wg"]})}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/maillage.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        lignes = pg.evaluate("[...document.querySelectorAll('#tunnels tr')].map(tr => [...tr.cells].map(td => td.textContent.trim()))")
        pg.goto("http://t.test/netmodes/carte.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        schema = pg.evaluate("[...document.querySelectorAll('#schema text')].map(t => t.textContent)")
        ctx.close()
        return lignes, schema, j
    lignes, schema, j = _avec_navigateur(scenario)
    par_nom = {ligne[0]: ligne for ligne in lignes}
    assert par_nom["wg-x"] == ["wg-x", "51999", "—", "—", "—", "—"]                     # pairs, reçu, émis, état : absents
    assert par_nom["wg-zero"][2] == "3" and par_nom["wg-zero"][5] == "aucun lien"          # 0 en ligne mesuré : « aucun lien »
    x = [t for t in schema if t.startswith("wg-x")]
    z = [t for t in schema if t.startswith("wg-zero")]
    assert x == ["wg-x · UDP 51999 · pairs — · liens —"] and z == ["wg-zero · UDP 51998 · 3 pairs · aucun lien"]
    assert "conteneurs actifs —" in schema and not any("null" in t or "NaN" in t or "undefined" in t for t in schema)
    assert j["erreurs"] == []


def test_dernier_echange_p2p_iso_ou_illisible_jamais_nan():
    """WireGuard en panne : le dernier échange vient du registre p2p, dont `last_seen` est un epoch, un ISO 8601 naïf en UTC
    (peers.json hérité, datetime.utcnow().isoformat()) ou n'importe quoi."""
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 125)) + ".123456"
    p2p = {"peers": [
        {"id": "a", "name": "iso-demo", "address": "203.0.113.21", "public_key": "KA", "status": "online", "last_seen": iso},
        {"id": "b", "name": "epoch-demo", "address": "203.0.113.22", "public_key": "KB", "status": "online", "last_seen": int(time.time()) - 30},
        {"id": "c", "name": "texte-demo", "address": "203.0.113.23", "public_key": "KC", "status": "offline", "last_seen": "hier"},
        {"id": "d", "name": "jamais-demo", "address": "203.0.113.24", "public_key": "KD", "status": "offline", "last_seen": None}], "count": 4}
    api = {"p2p/peers": (200, p2p), "wireguard/peers/status": (503, {"detail": "wgctl dump en échec"}), "wireguard/summary": (503, {"detail": "wgctl dump en échec"})}

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/maillage.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        lignes = pg.evaluate("[...document.querySelectorAll('#pairs tr')].map(tr => [...tr.cells].map(td => td.textContent.trim()))")
        pg.goto("http://t.test/netmodes/carte.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        schema = pg.evaluate("document.getElementById('schema').textContent")
        ctx.close()
        return lignes, schema, j
    lignes, schema, j = _avec_navigateur(scenario)
    par_ip = {ligne[1]: ligne for ligne in lignes}
    assert par_ip["203.0.113.21"][2] in ("il y a 2 min", "il y a 3 min") and par_ip["203.0.113.21"][4] == "actif"
    assert re.fullmatch(r"il y a (29|3\d) s", par_ip["203.0.113.22"][2])
    assert par_ip["203.0.113.23"][2] == "—" and par_ip["203.0.113.23"][4] == "muet"        # illisible : inconnu, pas « jamais »
    assert par_ip["203.0.113.24"][2] == "jamais"
    assert not any("NaN" in c for ligne in lignes for c in ligne) and "NaN" not in schema
    assert "iso-demo" in schema and j["erreurs"] == []
