# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3201 — onglet Switch : « Isoler… » et « Rendre au LAN… ».

Statique (textContent seulement, chemins, libellés exacts, note), puis vrai navigateur si Playwright est installé : démonstration
(lan2 isolé, aucune écriture, pas de défilement à 420 px), texte des confirmations, corps envoyé, 409 affiché tel quel,
fermeture de la confirmation quand l'état du port ne permet plus le verbe."""
import json
import re
from pathlib import Path

from test_pages_reseau_3190 import _avec_navigateur, _page, _sans_debordement, _code  # noqa: F401  (outillage commun)
from test_pages_switch_clients_3190 import PORTS, CLIENTS, ROUTEUR, _api

SRC = (Path(__file__).resolve().parents[1] / "www" / "netmodes" / "switch.html").read_text(encoding="utf-8")
URL = "http://t.test/netmodes/switch.html"

TEXTE_ISOLER = ("Isoler lan1 : il sort du pont et reçoit son propre réseau 192.168.249.0/24 (DHCP et DNS de la box). Les appareils branchés "
                "n'auront accès qu'à Internet : ni au LAN, ni à la Freebox, ni à l'administration. Ceux déjà branchés changent d'adresse au "
                "renouvellement de leur bail (débrancher puis rebrancher pour l'immédiat).")
TEXTE_RATTACHER = ("Rendre lan2 au LAN : il rejoint le pont br-lan si le mode routeur est actif. Les appareils branchés reprennent une "
                   "adresse du LAN au renouvellement de leur bail.")


def _ports(isole=None, coupes=()):
    """PORTS du test 3190 avec le champ isole : {nom: True/False/None}, absent = False sur lan0 à lan3."""
    d = json.loads(json.dumps(PORTS))
    for p in d["ports"]:
        if p["nom"].startswith("lan"):
            v = (isole or {}).get(p["nom"], False)
            p["isole"], p["reseau_isole"] = v, ("192.168.%d.0/24" % (248 + int(p["nom"][3])) if v else None)
            if p["nom"] in coupes:
                p["coupe"], p["etat_admin"] = True, "down"
    return d


def test_statique_chemins_libelles_et_note():
    code = _code(SRC)
    assert "innerHTML" not in SRC and "insertAdjacentHTML" not in SRC
    assert '"Isoler…"' in SRC and '"Rendre au LAN…"' in SRC
    assert '"isoler"' in code and '"rattacher"' in code
    assert "/api/v1/netmodes/ports/" in SRC                                  # le même fetch construit /isoler et /rattacher
    assert "VLAN (livraison 3)" not in SRC and "livraison 3" not in SRC
    note = re.search(r'<p class="note">(.*?)</p>', SRC, re.S).group(1)
    assert ("« Isoler » sort un port du pont : son propre réseau (192.168.248.0/24 pour lan0 … 192.168.251.0/24 pour lan3), DHCP et DNS de la box, "
            "Internet seul ; en mode routeur actif seulement, jamais sur le port de votre poste. « Rendre au LAN » le rattache en tout mode.") in note
    for f in ("confirm(", "alert(", "prompt("):
        assert not re.search(r"(?<![A-Za-z.])" + re.escape(f), code), f
    assert "isole === true" in SRC and "isole === false" in SRC


def test_demo_lan2_isole_sans_ecriture_ni_debordement():
    def scenario(nav):
        out = {}
        for larg in (1400, 420):
            ctx, pg, j = _page(nav, taille=(larg, 900))
            pg.goto(URL + "?demo=1&embed=1")
            pg.wait_for_selector("#ports tr")
            pg.wait_for_function("document.getElementById('heure').textContent !== '—'")
            r = {"lan2": pg.evaluate("[...document.querySelectorAll('#ports tr')].find(tr => tr.cells[0].textContent === 'lan2').textContent"),
                 "pill": pg.evaluate("[...document.querySelectorAll('#ports .pill')].filter(p => p.textContent === 'isolé').map(p => p.title)"),
                 "boutons": pg.evaluate("Object.fromEntries([...document.querySelectorAll('#ports button')].map(b => [b.dataset.port + '/' + b.dataset.verbe, b.textContent]))"),
                 "facade": pg.inner_text("#facade"), "deb": _sans_debordement(pg)}
            pg.click("button[data-port=lan2][data-verbe=rattacher]")
            pg.fill("#confirmSaisie", "lan2")
            pg.click("#confirmOk")
            r["res"] = pg.inner_text("#resultat")
            out[larg] = (r, j)
            ctx.close()
        return out
    out = _avec_navigateur(scenario)
    for larg, (r, j) in out.items():
        assert "isolé" in r["lan2"] and r["pill"] == ["Internet seul — 192.168.250.0/24"]
        assert r["boutons"]["lan2/rattacher"] == "Rendre au LAN…" and "lan2/couper" not in r["boutons"] and "lan2/isoler" not in r["boutons"]
        assert r["boutons"]["lan0/isoler"] == "Isoler…" and r["boutons"]["lan0/couper"] == "Couper…"
        assert "lan2 · isolé" in r["facade"] or "isolé" in r["facade"]
        assert "action inerte" in r["res"]
        assert r["deb"], larg
        assert j["erreurs"] == [] and j["natifs"] == [] and j["appels"] == [], larg


def test_textes_de_confirmation_exacts():
    api = _api(**{"netmodes/reseau/ports": (200, _ports({"lan2": True}))})

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto(URL)
        pg.wait_for_selector("button[data-port=lan1][data-verbe=isoler]")
        pg.click("button[data-port=lan1][data-verbe=isoler]")
        r = {"iso": pg.inner_text("#confirmTexte"), "ok_iso": pg.inner_text("#confirmOk"), "grave": pg.get_attribute("#confirm", "class")}
        pg.click("#confirmAnnule")
        pg.click("button[data-port=lan2][data-verbe=rattacher]")
        r["rat"] = pg.inner_text("#confirmTexte")
        r["ok_rat"] = pg.inner_text("#confirmOk")
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r["iso"] == TEXTE_ISOLER and r["rat"] == TEXTE_RATTACHER, r
    assert "lan1" in r["ok_iso"] and "lan2" in r["ok_rat"]
    assert j["erreurs"] == [] and j["natifs"] == []


def test_isole_null_aucun_bouton_isoler_mais_couper_reste():
    api = _api(**{"netmodes/reseau/ports": (200, _ports({"lan1": None}))})

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto(URL)
        pg.wait_for_selector("button[data-port=lan0]")
        r = pg.evaluate("[...document.querySelectorAll('#ports button')].map(b => b.dataset.port + '/' + b.dataset.verbe)")
        ctx.close()
        return r
    r = _avec_navigateur(scenario)
    assert "lan1/isoler" not in r and "lan1/couper" in r and "lan0/isoler" in r


def test_isoler_envoie_le_corps_confirme_et_le_409_s_affiche_tel_quel():
    refus = "votre poste est derrière lan1 : isolement refusé"
    api = _api(**{"netmodes/reseau/ports": (200, _ports()), "netmodes/ports/lan1/isoler": (409, {"detail": refus})})

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        corps = []
        pg.on("request", lambda rq: corps.append((rq.method, rq.url.split("t.test/")[1], rq.post_data)) if rq.method == "POST" else None)
        pg.goto(URL)
        pg.wait_for_selector("button[data-port=lan1][data-verbe=isoler]")
        pg.click("button[data-port=lan1][data-verbe=isoler]")
        pg.fill("#confirmSaisie", "lan1")
        pg.click("#confirmOk")
        pg.wait_for_function("!document.getElementById('resultat').hidden")
        r = (pg.inner_text("#resultat"), pg.get_attribute("#resultat", "class"), pg.is_visible("#confirm"), corps)
        ctx.close()
        return r, j
    (res, cls, ouverte, corps), j = _avec_navigateur(scenario)
    assert refus in res and "409" in res and "ko" in cls and ouverte
    assert corps == [("POST", "api/v1/netmodes/ports/lan1/isoler", '{"confirmer":"lan1"}')]
    assert j["erreurs"] == [] and j["natifs"] == []


def test_rattacher_puis_relecture_dit_le_resultat():
    api = _api(**{"netmodes/reseau/ports": (200, _ports({"lan2": True})), "netmodes/ports/lan2/rattacher": (200, {"ok": True})})

    def scenario(nav):
        ctx, pg, j = _page(nav, api)
        pg.goto(URL)
        pg.wait_for_selector("button[data-port=lan2][data-verbe=rattacher]")
        pg.click("button[data-port=lan2][data-verbe=rattacher]")
        pg.fill("#confirmSaisie", "lan2")
        pg.click("#confirmOk")
        pg.wait_for_function("!document.getElementById('resultat').hidden")
        r = pg.inner_text("#resultat")
        ctx.close()
        return r, j
    r, j = _avec_navigateur(scenario)
    assert r.startswith("lan2 rendu au LAN") and ("POST", "api/v1/netmodes/ports/lan2/rattacher") in j["appels"]


def test_confirmation_ouverte_se_ferme_si_l_etat_ne_permet_plus_le_verbe():
    """Une lecture partie avant l'ouverture arrive pendant la confirmation : si le port n'admet plus le verbe, elle se ferme."""
    cas = [("lan1", "isoler", {"lan1": True}, ()), ("lan1", "couper", {"lan1": True}, ()), ("lan1", "isoler", {}, ("lan1",)),
           ("lan2", "rattacher", {}, ()), ("lan1", "retablir", {}, ())]
    ports_depart = {"isoler": _ports(), "couper": _ports(), "rattacher": _ports({"lan2": True}), "retablir": _ports(coupes=("lan1",))}

    def scenario(nav):
        sorties = []
        for port, verbe, apres, coupes in cas:
            api = _api(**{"netmodes/reseau/ports": (200, ports_depart[verbe])})
            ctx, pg, j = _page(nav, api)
            pg.goto(URL)
            pg.wait_for_selector("button[data-port=%s][data-verbe=%s]" % (port, verbe))
            tenue = []
            pg.route("**/api/v1/netmodes/reseau/ports", lambda rt: tenue.append(rt))
            pg.click("#rafraichir")
            pg.wait_for_timeout(200)
            pg.click("button[data-port=%s][data-verbe=%s]" % (port, verbe))
            ouverte = pg.is_visible("#confirm")
            tenue[0].fulfill(status=200, content_type="application/json", body=json.dumps(_ports(apres, coupes)))
            pg.wait_for_timeout(300)
            sorties.append((verbe, ouverte, pg.is_visible("#confirm")))
            ctx.close()
        # même état renvoyé : la confirmation reste ouverte
        api = _api(**{"netmodes/reseau/ports": (200, _ports())})
        ctx, pg, j = _page(nav, api)
        pg.goto(URL)
        pg.wait_for_selector("button[data-port=lan1][data-verbe=isoler]")
        tenue = []
        pg.route("**/api/v1/netmodes/reseau/ports", lambda rt: tenue.append(rt))
        pg.click("#rafraichir")
        pg.wait_for_timeout(200)
        pg.click("button[data-port=lan1][data-verbe=isoler]")
        tenue[0].fulfill(status=200, content_type="application/json", body=json.dumps(_ports()))
        pg.wait_for_timeout(300)
        sorties.append(("inchange", True, pg.is_visible("#confirm")))
        ctx.close()
        return sorties
    sorties = _avec_navigateur(scenario)
    assert sorties == [("isoler", True, False), ("couper", True, False), ("isoler", True, False), ("rattacher", True, False),
                       ("retablir", True, False), ("inchange", True, True)], sorties


def test_changelog_1_6_0():
    ch = (Path(__file__).resolve().parents[1] / "debian" / "changelog").read_text(encoding="utf-8")
    assert ch.startswith("secubox-netmodes (1.6.0-1~trixie1) trixie; urgency=medium")
    tete = ch.split("\n -- ", 1)
    assert "(ref #3201)" in tete[0] and "192.168.248.0/22" in tete[0] and "Unbound" in tete[0]
    assert tete[1].startswith("Gérald Kerma <devel@cybermind.fr>  Tue, 27 Oct 2026 12:00:00 +0100")
