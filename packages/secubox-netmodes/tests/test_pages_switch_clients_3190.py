# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3190 — onglets Switch (switch.html) et Clients LAN (clients.html) du panneau Réseau.

Tests statiques (§ 11.1 du profil Aurora) puis vrai navigateur si Playwright est installé : démonstration à 1400 et 420 px, aucun
débordement ni erreur JS, confirmation intégrée inerte en démonstration, 409 affiché tel quel, sources en panne affichées comme des
pannes (file://, 401, NAC en panne), jointure NAC par adresse MAC."""
import ipaddress
import json
import re
import time
from pathlib import Path

import pytest

from test_pages_reseau_3190 import _avec_navigateur, _page, _sans_debordement, _code  # noqa: F401  (outillage commun)

ICI = Path(__file__).resolve().parents[1]
WWW = ICI / "www" / "netmodes"
PAGES = {"switch": WWW / "switch.html", "clients": WWW / "clients.html"}
SRC = {k: p.read_text(encoding="utf-8") for k, p in PAGES.items()}
DOC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
ROUTES = {"switch": ["/api/v1/netmodes/reseau/ports", "/api/v1/netmodes/reseau/clients", "/api/v1/netmodes/routeur/etat"],
          "clients": ["/api/v1/netmodes/reseau/clients", "/api/v1/netmodes/reseau/ports", "/api/v1/nac/clients"]}


def _port(nom, role="lan", porteuse=True, v=1000, macs=None, multi=False, coupe=False, maitre="br-lan"):
    return {"nom": nom, "role": role, "porteuse": porteuse, "vitesse_mbps": v, "etat_admin": "up", "maitre": maitre,
            "macs": macs or [], "plusieurs_appareils": multi, "coupe": coupe}


PORTS = {"ports": [_port("eth2", "wan", maitre=None), _port("eth1", "conduit", v=2500, maitre=None), _port("eth0", "sfp", porteuse=False, v=None, maitre=None),
                   _port("lan0", macs=["00:00:5e:00:53:c0"]), _port("lan1", porteuse=False, v=None), _port("lan2", macs=["00:00:5e:00:53:a1", "00:00:5e:00:53:a2"], multi=True),
                   _port("lan3", macs=["00:00:5e:00:53:bf"])], "pannes": []}
CLIENTS = {"clients": [
    {"mac": "00:00:5e:00:53:c0", "ip": "198.51.100.192", "nom": "pc-demo", "port": "lan0", "source": "bail", "expire": 1},
    {"mac": "00:00:5e:00:53:a1", "ip": "198.51.100.150", "nom": "<img src=x onerror=alert(1)>", "port": "lan2", "source": "bail", "expire": 1},
    {"mac": "00:00:5e:00:53:a2", "ip": "198.51.100.151", "nom": "", "port": "lan2", "source": "voisin", "expire": None},
    {"mac": "00:00:5e:00:53:bf", "ip": "198.51.100.191", "nom": "rpi-demo", "port": "lan3", "source": "bail", "expire": 1}], "pannes": []}
NAC = {"clients": [{"mac": "00:00:5E:00:53:C0", "ip": "198.51.100.192", "hostname": "pc-demo", "zone": "lan", "zone_name": "LAN", "allow_state": "allowed"},
                   {"mac": "00:00:5e:00:53:bf", "ip": "198.51.100.191", "hostname": "rpi-demo", "zone": "guest", "zone_name": "Invités", "allow_state": "unknown"}],
       "count": 2, "by_zone": {}}
ROUTEUR = {"etat": "actif", "ports_coupes": [], "bascule_en_cours": False}


# ── Statique ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("k", list(PAGES))
def test_page_autonome_sans_dependance_ni_boite_native(k):
    s = SRC[k]
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in s
    assert re.findall(r"<script[^>]*\bsrc=", s) == []
    assert re.findall(r"\.src\s*=\s*['\"]([^'\"]+)['\"]", s) == ["/shared/sidebar.js"]
    assert re.search(r"if \(EMB \|\| DEMO\)", s)
    for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "fonts.googleapis", "hybrid-skin", "Math.random"):
        assert interdit not in s, interdit
    code = _code(s)
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f
    assert "lorem" not in s.lower()
    assert "@container a" in s and "container-type:inline-size" in s
    assert "sbxVue" in s and "getBoundingClientRect().bottom" in s and "location.origin" in s
    assert "scrollHeight" not in s and "100vh" not in s
    assert ('var ONGLET = "%s";' % k) in s and "onglet: ONGLET" in s
    assert "localStorage.getItem(\"sbx_token\")" in s and "setItem" not in s and "Bearer " in s
    assert "!document.hidden" in s


@pytest.mark.parametrize("k", list(PAGES))
def test_demo_avec_adresses_de_documentation_seulement(k):
    s = SRC[k]
    assert "DEMO" in s and "DÉMONSTRATION" in s
    for ip in re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", s):
        assert any(ipaddress.ip_address(ip) in n for n in DOC), ip
    assert "gk2.secubox" not in s and "secubox.in" not in s


@pytest.mark.parametrize("k", list(PAGES))
def test_routes_citees(k):
    for r in ROUTES[k]:
        assert r in SRC[k], r


def test_clients_lecture_seule():
    s = SRC["clients"]
    for m in ("'POST'", '"POST"', '"PUT"', '"DELETE"', '"PATCH"', "JSON.stringify"):
        assert m not in s, m
    assert "NAC indisponible" in s and "à classer" in s and "Hubs et switchs détectés" in s and "unknown" in s


def test_switch_une_seule_ecriture_ports_lan_seulement():
    s = SRC["switch"]
    assert s.count('method: "POST"') == 1 and s.count("fetch(") == 2
    assert '"/api/v1/netmodes/ports/" + port + "/" + verbe' in s and "JSON.stringify({ confirmer: port })" in s
    assert "var LAN_RE = /^lan[0-3]$/;" in s
    assert re.search(r"if \(DEMO\) \{ fermer\(\); resultat\(\"Démonstration : action inerte", s)       # la démo ne mène jamais au fetch
    assert 'iso.disabled = true; iso.title = "livraison 3"' in s
    for t in ("jamais ponté", "jamais relancé à distance", "plusieurs appareils derrière ce port (switch, hub ou point d'accès)", "Couper…", "Rétablir…"):
        assert t in s, t
    assert not re.search(r"bouton\([^)]*eth[012]", s)


# ── Navigateur ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("page", ["switch", "clients"])
@pytest.mark.parametrize("largeur", [1400, 420])
def test_demo_sans_debordement_ni_erreur_ni_appel(page, largeur):
    def scenario(nav):
        ctx, pg, j = _page(nav, taille=(largeur, 900))
        pg.goto("http://t.test/netmodes/%s.html?demo=1" % page)
        pg.wait_for_function("document.getElementById('heure').textContent !== '—'")
        pg.wait_for_timeout(300)
        r = (_sans_debordement(pg), pg.is_visible("#demo"), pg.inner_text("#etatSources"), pg.locator("#sources .src.demo").count())
        pg.screenshot(path=str(CAPT / ("%s-%d.png" % (page, largeur))), full_page=True)
        ctx.close()
        return r, j
    (deb, demo, etat, nsrc), j = _avec_navigateur(scenario)
    assert deb and demo and etat == "DÉMONSTRATION" and nsrc == 3
    assert j["erreurs"] == [] and j["natifs"] == [] and j["appels"] == []


CAPT = Path("/tmp/claude-1000/-home-reepost-CyberMindStudio-secubox-deb-secubox-deb/dd6762e6-f034-4417-bd75-e92d1336483e/scratchpad/captures-reseau")
CAPT.mkdir(parents=True, exist_ok=True)


def test_switch_demo_facade_tableau_et_confirmation_inerte():
    def scenario(nav):
        ctx, pg, j = _page(nav)
        pg.goto("http://t.test/netmodes/switch.html?demo=1&embed=1")
        pg.wait_for_selector("#ports tr")
        lignes = pg.evaluate("Object.fromEntries([...document.querySelectorAll('#ports tr')].map(tr => [tr.cells[0].textContent, [...tr.cells].map(td => td.textContent.trim())]))")
        r = {"lignes": lignes, "ports_facade": pg.locator("#facade .port").count(),
             "iso": pg.evaluate("[...document.querySelectorAll('#ports button')].filter(b => b.textContent.startsWith('Isoler')).map(b => [b.disabled, b.title])"),
             "boutons_eth": pg.evaluate("[...document.querySelectorAll('#ports tr')].filter(tr => /^eth/.test(tr.cells[0].textContent)).map(tr => tr.cells[5].querySelectorAll('button').length)"),
             "multi": pg.inner_text("#ports tr:nth-child(5)")}
        pg.click("button[data-port=lan0][data-verbe=couper]")
        r["ouverte"] = pg.is_visible("#confirm")
        r["ok_avant"] = pg.is_disabled("#confirmOk")
        pg.fill("#confirmSaisie", "lan1")
        r["ok_faux"] = pg.is_disabled("#confirmOk")
        pg.fill("#confirmSaisie", "lan0")
        r["ok_juste"] = pg.is_disabled("#confirmOk")
        pg.click("#confirmOk")
        r["res"] = pg.inner_text("#resultat")
        r["ferme"] = not pg.is_visible("#confirm")
        pg.click("button[data-port=lan3][data-verbe=couper]")
        pg.click("#confirmAnnule")
        r["annule"] = not pg.is_visible("#confirm")
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["ports_facade"] == 6 and all(d and t == "livraison 3" for d, t in r["iso"]) and len(r["iso"]) == 4
    assert r["boutons_eth"] == [0, 0, 0]
    assert r["lignes"]["eth2"][5] == "jamais relancé à distance" and r["lignes"]["eth1"][5] == "jamais ponté"
    assert "plusieurs appareils derrière ce port (switch, hub ou point d'accès)" in r["lignes"]["lan2"][4]
    assert r["lignes"]["lan0"][4].startswith("1 appareil · pc-demo") and r["lignes"]["lan1"][2] == "aucun"
    assert r["ouverte"] and r["ok_avant"] and r["ok_faux"] and not r["ok_juste"]
    assert "action inerte" in r["res"] and r["ferme"] and r["annule"]
    assert j["erreurs"] == [] and j["natifs"] == [] and j["appels"] == []


def _api(**sur):
    base = {"netmodes/reseau/ports": (200, PORTS), "netmodes/reseau/clients": (200, CLIENTS), "netmodes/routeur/etat": (200, ROUTEUR), "nac/clients": (200, NAC)}
    base.update(sur)
    return base


def test_switch_couper_envoie_le_corps_confirme_et_affiche_le_409_tel_quel():
    refus = "vous couperiez votre propre accès (votre poste est derrière lan3)"
    api = _api()
    api["netmodes/ports/lan3/couper"] = (409, {"detail": refus})

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        corps = []
        pg.on("request", lambda rq: corps.append((rq.method, rq.url.split("t.test/")[1], rq.post_data)) if rq.method == "POST" else None)
        pg.goto("http://t.test/netmodes/switch.html")
        pg.wait_for_selector("button[data-port=lan3]")
        pg.click("button[data-port=lan3][data-verbe=couper]")
        pg.fill("#confirmSaisie", "lan3")
        pg.click("#confirmOk")
        pg.wait_for_function("!document.getElementById('resultat').hidden")
        r = (pg.inner_text("#resultat"), pg.get_attribute("#resultat", "class"), pg.is_visible("#confirm"), corps, pg.locator("#resultat img").count())
        pg.screenshot(path=str(CAPT / "switch-409-1400.png"), full_page=True)
        ctx.close()
        return r, j
    (res, cls, ouverte, corps, imgs), j = _avec_navigateur(scenario)
    assert refus in res and "409" in res and "ko" in cls and ouverte                  # le refus reste affiché, la confirmation reste ouverte
    assert corps == [("POST", "api/v1/netmodes/ports/lan3/couper", '{"confirmer":"lan3"}')]
    assert j["erreurs"] == [] and j["natifs"] == []


def test_switch_retablir_un_port_coupe_puis_relecture():
    coupe = json.loads(json.dumps(PORTS))
    for p in coupe["ports"]:
        if p["nom"] == "lan1":
            p["coupe"], p["etat_admin"] = True, "down"
    api = _api(**{"netmodes/reseau/ports": (200, coupe), "netmodes/ports/lan1/retablir": (200, ROUTEUR)})

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/switch.html")
        pg.wait_for_selector("button[data-port=lan1]")
        r = {"verbe": pg.get_attribute("button[data-port=lan1]", "data-verbe"), "texte": pg.inner_text("button[data-port=lan1]"), "tuile": pg.inner_text("#tCoupe"),
             "lien": pg.inner_text("#ports tr:nth-child(4) td:nth-child(3)")}
        pg.click("button[data-port=lan1]")
        pg.fill("#confirmSaisie", "lan1")
        pg.click("#confirmOk")
        pg.wait_for_function("document.getElementById('resultat').textContent.includes('rétabli')")
        r["res"] = pg.inner_text("#resultat")
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["verbe"] == "retablir" and r["texte"] == "Rétablir…" and r["tuile"] == "1" and r["lien"] == "coupé" and "lan1 rétabli" in r["res"]
    assert ("POST", "api/v1/netmodes/ports/lan1/retablir") in j["appels"] and j["natifs"] == []


def test_switch_champ_illisible_jamais_faux_et_valeurs_en_texte_brut():
    illisible = json.loads(json.dumps(PORTS))
    for p in illisible["ports"]:
        if p["nom"] == "lan2":
            p.update(coupe=None, macs=None, plusieurs_appareils=None)
    illisible["pannes"] = ["coupes", "fdb"]
    api = _api(**{"netmodes/reseau/ports": (200, illisible), "netmodes/reseau/clients": (401, {"detail": "Not authenticated"}), "netmodes/routeur/etat": (503, {"detail": "contrôleur en échec"})})

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/switch.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        r = {"lan2": pg.evaluate("[...document.querySelectorAll('#ports tr')][4].cells[4].textContent"), "act": pg.evaluate("[...document.querySelectorAll('#ports tr')][4].cells[5].textContent"),
             "lan0": pg.evaluate("[...document.querySelectorAll('#ports tr')][2].cells[4].textContent"), "alertes": pg.inner_text("#portsPannes"),
             "etat": pg.inner_text("#etatSources"), "tCoupe": pg.inner_text("#tCoupe"), "multi": pg.locator(".multi").count(),
             "classes": pg.evaluate("[...document.querySelectorAll('.src')].map(e => e.className)")}
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["lan2"] == "—" and "illisible" in r["act"] and r["multi"] == 0 and r["tCoupe"] == "—"
    assert "noms : session requise" in r["lan0"] and "coupes, fdb" in r["alertes"] and "Mode routeur et ports coupés : source en panne" in r["alertes"]
    assert r["classes"] == ["src panne", "src session", "src panne"] and "EN PANNE" in r["etat"]
    assert j["erreurs"] == [] and all(m == "GET" for m, _ in j["appels"])


def test_switch_pas_de_rafraichissement_pendant_une_confirmation_ni_onglet_cache():
    def scenario(nav):
        ctx, pg, j = _page(nav, _api())
        pg.add_init_script("window.__cb = []; const si = window.setInterval; window.setInterval = (f, t) => { window.__cb.push(f); return 0; };")
        pg.goto("http://t.test/netmodes/switch.html")
        pg.wait_for_selector("button[data-port=lan0]")
        n0 = len(j["appels"])
        pg.click("button[data-port=lan0]")
        pg.evaluate("window.__cb.forEach(f => f())")
        pg.wait_for_timeout(300)
        n1 = len(j["appels"])
        pg.click("#confirmAnnule")
        pg.evaluate("window.__cb.forEach(f => f())")
        pg.wait_for_timeout(300)
        n2 = len(j["appels"])
        ctx.close()
        return (n0, n1, n2), j
    (n0, n1, n2), j = _avec_navigateur(scenario)
    assert n1 == n0 and n2 == n0 + 3                        # rien pendant la confirmation, trois lectures après


def test_clients_jointure_nac_par_mac_sans_casse_a_classer_et_texte_brut():
    def scenario(nav):
        ctx, pg, j = _page(nav, _api())
        pg.goto("http://t.test/netmodes/clients.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        r = {"lignes": pg.evaluate("[...document.querySelectorAll('#clients tr')].map(tr => [...tr.cells].map(td => td.textContent.trim()))"),
             "imgs": pg.locator("#clients img").count(), "tuiles": [pg.inner_text(i) for i in ("#tNb", "#tCl", "#tSp", "#tHub")], "hubs": pg.inner_text("#hubs"),
             "etat": pg.inner_text("#etatSources")}
        pg.screenshot(path=str(CAPT / "clients-nac-1400.png"), full_page=True)
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    par_ip = {ligne[1]: ligne for ligne in r["lignes"]}
    assert par_ip["198.51.100.192"][3] == "LAN" and par_ip["198.51.100.192"][0].startswith("pc-demo")      # MAC en majuscules côté NAC
    assert par_ip["198.51.100.191"][3] == "à classer"                                                      # allow_state « unknown »
    assert par_ip["198.51.100.150"][3] == "à classer" and par_ip["198.51.100.151"][0].startswith("sans nom")   # absent du NAC
    assert par_ip["198.51.100.150"][0].startswith("<img src=x onerror=alert(1)>") and r["imgs"] == 0
    assert r["tuiles"] == ["4", "3", "0", "1"] and "lan2" in r["hubs"] and "2 appareils" in r["hubs"] and r["etat"] == "TOUTES LES SOURCES LUES"
    assert j["erreurs"] == [] and all(m == "GET" for m, _ in j["appels"])


def test_clients_nac_en_panne_et_session_requise_jamais_vides():
    def scenario(nav):
        ctx, pg, j = _page(nav, _api(**{"nac/clients": (503, {"detail": "nac arrêté"})}))
        pg.goto("http://t.test/netmodes/clients.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        a = {"zones": pg.evaluate("[...document.querySelectorAll('#clients tr')].map(tr => tr.cells[3].textContent.trim())"), "alertes": pg.inner_text("#clientsPannes"),
             "tCl": pg.inner_text("#tCl"), "etat": pg.inner_text("#etatSources")}
        pg.screenshot(path=str(CAPT / "clients-panne-nac-1400.png"), full_page=True)
        ctx.close()
        ctx, pg, j2 = _page(nav, _api(**{"netmodes/reseau/clients": (401, {"detail": "x"}), "nac/clients": (401, {"detail": "x"})}))
        pg.goto("http://t.test/netmodes/clients.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        b = {"corps": pg.inner_text("#clients"), "tNb": pg.inner_text("#tNb"), "session": pg.is_visible("#session"), "hubs": pg.inner_text("#hubs")}
        ctx.close()
        return (a, b), j
    (a, b), j = _avec_navigateur(scenario)
    assert set(a["zones"]) == {"NAC indisponible"} and "Zones NAC" in a["alertes"] and "source en panne" in a["alertes"] and a["tCl"] == "—"
    assert "à classer" not in " ".join(a["zones"]) and "EN PANNE" in a["etat"]
    assert "Appareils illisibles : session requise" in b["corps"] and "Aucun appareil" not in b["corps"] and b["tNb"] == "—" and b["session"]
    assert "1 appareil" not in b["hubs"] and "lan2" in b["hubs"]                      # les ports restent lus : le hub reste détecté
    assert j["erreurs"] == []


def test_ports_en_panne_hubs_illisibles_jamais_aucun():
    def scenario(nav):
        ctx, pg, j = _page(nav, _api(**{"netmodes/reseau/ports": (503, {"detail": "ip en échec"})}))
        pg.goto("http://t.test/netmodes/clients.html")
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        r = (pg.inner_text("#hubs"), pg.inner_text("#tHub"))
        ctx.close()
        return r, j
    (hubs, t), j = _avec_navigateur(scenario)
    assert "Détection illisible" in hubs and "Aucun" not in hubs and t == "—"


@pytest.mark.parametrize("page", ["switch", "clients"])
def test_sans_session_sous_file_les_sources_sont_en_panne(page):
    def scenario(nav):
        ctx = nav.new_context(viewport={"width": 1400, "height": 900})
        pg = ctx.new_page()
        erreurs = []
        pg.on("pageerror", lambda e: erreurs.append(str(e)))
        pg.goto("file://" + str(PAGES[page]))
        pg.wait_for_function("document.getElementById('etatSources').textContent !== 'LECTURE…'")
        r = (pg.inner_text("#etatSources"), pg.locator(".src.panne").count(), pg.inner_text("#" + ("ports" if page == "switch" else "clients")),
             pg.inner_text("#tLien" if page == "switch" else "#tNb"), _sans_debordement(pg))
        pg.screenshot(path=str(CAPT / ("panne-%s-1400.png" % page)), full_page=True)
        pg.set_viewport_size({"width": 420, "height": 900})
        pg.wait_for_timeout(200)
        r += (_sans_debordement(pg),)
        pg.screenshot(path=str(CAPT / ("panne-%s-420.png" % page)), full_page=True)
        ctx.close()
        return r, erreurs
    (etat, pannes, corps, tuile, d1, d2), erreurs = _avec_navigateur(scenario)
    assert "EN PANNE" in etat and pannes == 3 and "illisibles : source en panne" in corps and "Aucun" not in corps and tuile == "—"
    assert d1 and d2 and erreurs == []


# ── Relecture finale I3 : la relecture après une action n'est jamais sautée ─────────────────────────────────────────────────────
from test_page_routeur_3190 import _attendre, _page as _page_tenue  # noqa: E402  (réponses retenues par le scénario)


def test_switch_relecture_enchainee_et_lecture_d_avant_l_action_jetee_dans_le_code():
    code = _code(SRC["switch"])
    assert "suite = lecture.then(" in code and "if (g !== generation) { return; }" in code and "enCours" not in code
    assert code.count("generation++") == 3                  # avant l'envoi, à la réponse, à l'échec réseau de l'action


def test_switch_action_pendant_une_lecture_en_vol_relit_apres_elle():
    """Une lecture en vol quand Rétablir réussit revient APRÈS lui avec l'état d'avant (lan1 coupé) : elle est jetée (le
    tableau n'est pas redessiné), et la relecture part dès sa fin, jamais sautée ; elle montre lan1 rétabli."""
    coupe = json.loads(json.dumps(PORTS))
    for p in coupe["ports"]:
        if p["nom"] == "lan1":
            p["coupe"], p["etat_admin"] = True, "down"
    box = {"garder": 0, "retabli": False}

    def ports(_m, _c):
        if box["garder"]:
            box["garder"] -= 1
            return None                                     # réponse retenue, donnée par le scénario
        return 200, (PORTS if box["retabli"] else coupe)

    def retablir(_m, _c):
        box["retabli"] = True
        return 200, ROUTEUR
    api = {"netmodes/reseau/ports": ports, "netmodes/reseau/clients": (200, CLIENTS), "netmodes/routeur/etat": (200, ROUTEUR),
           "netmodes/ports/lan1/retablir": retablir}

    def scenario(nav):
        ctx, pg, j = _page_tenue(nav, api)
        pg.goto("http://t.test/netmodes/switch.html")
        pg.wait_for_selector("button[data-port=lan1][data-verbe=retablir]")
        box["garder"] = 1
        pg.click("#rafraichir")
        _attendre(pg, lambda: len(j["gardees"]) == 1)                       # une lecture en vol
        pg.click("button[data-port=lan1]")
        pg.fill("#confirmSaisie", "lan1")
        pg.click("#confirmOk")
        pg.wait_for_function("document.getElementById('resultat').textContent.includes('rétabli')")
        box["garder"] = 1                                                   # retient aussi la relecture enchaînée
        pg.evaluate("document.querySelector('button[data-port=lan1]').closest('tr').dataset.marque = 'avant'")
        lache = time.time()
        j["gardees"][0].fulfill(status=200, content_type="application/json", body=json.dumps(coupe))   # l'état d'avant, en retard
        try:
            _attendre(pg, lambda: len(j["gardees"]) == 2, 2.0)
        except AssertionError:
            pass
        pg.wait_for_timeout(300)
        lectures = [c[3] for c in j["appels"] if c[1].endswith("reseau/ports")]
        r = {"enchainee": len(j["gardees"]) == 2, "delai": lectures[-1] - lache,
             "jetee": pg.evaluate("!!document.querySelector('#ports tr[data-marque=avant]')")}
        if r["enchainee"]:
            j["gardees"][1].fulfill(status=200, content_type="application/json", body=json.dumps(PORTS))
            try:
                pg.wait_for_function("document.querySelector('button[data-port=lan1]').dataset.verbe === 'couper'", timeout=3000)
            except Exception:                               # l'assertion qui suit dit ce qui est affiché
                pass
        r.update(verbe=pg.get_attribute("button[data-port=lan1]", "data-verbe"), tuile=pg.inner_text("#tCoupe"), res=pg.inner_text("#resultat"))
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["enchainee"], "aucune relecture après l'action : sautée parce qu'une lecture était en vol"
    assert 0 <= r["delai"] < 1.0, r["delai"]                                 # dès la fin de la lecture en vol
    assert r["jetee"], "la lecture partie avant l'action a été rendue"
    assert r["verbe"] == "couper" and r["tuile"] == "0" and "lan1 rétabli" in r["res"]
    assert j["erreurs"] == [] and j["natifs"] == []


# ── Relecture finale I1 : rétablir est permis en tout mode (arbitrage, contrôleur) ───────────────────────────────────────────────
def _ports_lan1_coupe():
    coupe = json.loads(json.dumps(PORTS))
    for p in coupe["ports"]:
        if p["nom"] == "lan1":
            p.update(coupe=True, etat_admin="down", porteuse=False, vitesse_mbps=None, maitre=None)
    return coupe


def test_switch_rien_ne_dit_que_retablir_exige_le_mode_routeur():
    s = SRC["switch"]
    assert "couper ou rétablir un port exige" not in s
    assert "« Rétablir » le relance : seuls lan0 à lan3, en mode routeur actif" not in s
    assert "le relance en tout mode" in s and "hors du pont" in s


def test_switch_mode_inactif_port_coupe_retablir_propose_hors_du_pont():
    """Mode routeur inactif, lan1 coupé : bandeau limité à Couper, Rétablir proposé, son texte dit « hors du pont » (jamais
    « dans le pont br-lan »), et l'action part (le contrôleur la permet en tout mode). Captures à 1400 et 420 px."""
    inactif = {"etat": "inactif", "depuis": None, "config": None, "ports_coupes": ["lan1"], "bascule_en_cours": False}
    api = _api(**{"netmodes/reseau/ports": (200, _ports_lan1_coupe()), "netmodes/routeur/etat": (200, inactif),
                  "netmodes/ports/lan1/retablir": (200, inactif)})

    def scenario(nav):
        r = {}
        for largeur in (1400, 420):
            ctx, pg, j = _page(nav, api, taille=(largeur, 900))
            pg.goto("http://t.test/netmodes/switch.html")
            pg.wait_for_selector("button[data-port=lan1]")
            r["bandeau"] = pg.inner_text("#portsPannes")
            r["verbe"], r["texte"] = pg.get_attribute("button[data-port=lan1]", "data-verbe"), pg.inner_text("button[data-port=lan1]")
            r["lien"] = pg.inner_text("#ports tr:nth-child(4) td:nth-child(3)")
            pg.click("button[data-port=lan1]")
            r["confirm"] = pg.inner_text("#confirmTexte")
            r["deb_%d" % largeur] = _sans_debordement(pg)
            pg.screenshot(path=str(CAPT / ("switch-inactif-coupe-%d.png" % largeur)), full_page=True)
            if largeur == 1400:
                pg.fill("#confirmSaisie", "lan1")
                pg.click("#confirmOk")
                pg.wait_for_function("document.getElementById('resultat').textContent.includes('rétabli')")
                r["res"], r["appels"] = pg.inner_text("#resultat"), list(j["appels"])
            r["erreurs_%d" % largeur], r["natifs_%d" % largeur] = j["erreurs"], j["natifs"]
            ctx.close()
        return r, None
    r, _ = _avec_navigateur(scenario)
    b = r["bandeau"]
    assert "Mode routeur « inactif » : couper un port exige le mode routeur actif" in b, b
    assert "Rétablir un port coupé reste possible en tout mode" in b and "couper ou rétablir" not in b, b
    assert r["verbe"] == "retablir" and r["texte"] == "Rétablir…" and r["lien"] == "coupé"
    c = r["confirm"]
    assert "Rétablir lan1 remonte le port hors du pont" in c and "« inactif »" in c and "remet dans le pont" not in c, c
    assert ("POST", "api/v1/netmodes/ports/lan1/retablir") in r["appels"] and "lan1 rétabli" in r["res"]
    assert r["deb_1400"] and r["deb_420"]
    assert r["erreurs_1400"] == r["erreurs_420"] == [] and r["natifs_1400"] == r["natifs_420"] == []


@pytest.mark.parametrize("routeur,attendu,absent", [
    ((200, {"etat": "actif", "config": {"ports": ["lan0", "lan1", "lan2", "lan3"]}, "ports_coupes": ["lan1"]}),
     "Rétablir lan1 relance le port et le remet dans le pont br-lan", "hors du pont"),
    ((200, {"etat": "actif", "config": {"ports": ["lan0", "lan2"]}, "ports_coupes": ["lan1"]}),
     "Rétablir lan1 remonte le port hors du pont : lan1 n'est pas un port configuré du mode routeur", "remet dans le pont"),
    ((200, {"etat": "en_attente", "config": {"ports": ["lan0", "lan1"]}, "ports_coupes": ["lan1"]}),
     "Rétablir lan1 remonte le port hors du pont : le mode routeur est « en_attente »", "remet dans le pont"),
    ((503, {"detail": "contrôleur en échec"}),
     "dans le pont br-lan si le mode routeur est actif et le port configuré, sinon hors du pont", "remet dans le pont"),
], ids=["actif_configure", "actif_non_configure", "en_attente", "illisible"])
def test_switch_texte_de_retablir_suit_le_controleur(routeur, attendu, absent):
    api = _api(**{"netmodes/reseau/ports": (200, _ports_lan1_coupe()), "netmodes/routeur/etat": routeur})

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto("http://t.test/netmodes/switch.html")
        pg.wait_for_selector("button[data-port=lan1][data-verbe=retablir]")
        pg.click("button[data-port=lan1]")
        t = pg.inner_text("#confirmTexte")
        ctx.close()
        return t, j
    t, j = _avec_navigateur(scenario)
    assert attendu in t and absent not in t, t
    assert j["erreurs"] == [] and all(m == "GET" for m, _ in j["appels"])
