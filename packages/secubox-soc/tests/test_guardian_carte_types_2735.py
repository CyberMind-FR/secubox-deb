# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2735 : la carte des attaques du Guardian colorise les types de menace agrégés (couleur + forme), légende filtrante, infobulle.

Même modèle que la vue d'ensemble du WAF (#2703) : les pages Aurora sont autonomes, le code de la carte est porté, pas partagé. Les halos rouges
uniformes disparaissent : un pays est un anneau réparti entre les types observés, le type dominant porte sa forme au centre."""
import json
import re
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "www" / "soc" / "guardian.html"
SRC = PAGE.read_text(encoding="utf-8")


def test_source_sans_balisage_injecte_pour_les_nouvelles_donnees():
    bloc = SRC[SRC.index("function famille("):SRC.index("function courbe(")]
    assert "innerHTML" not in bloc and "createElementNS" in bloc and "textContent" in bloc
    assert "alerts?limit=500" in SRC and "alerts?limit=8" not in SRC      # même route /alerts, aucune route nouvelle
    assert not re.search(r"(src|href)=[\"']https?://|@import", SRC)


def test_au_moins_sept_types_aux_couleurs_et_formes_distinctes():
    t = re.findall(r"\{id:'(\w+)',nom:'([^']+)',coul:'(#[0-9a-f]{6})',forme:'(\w+)'", SRC)
    assert len(t) >= 7
    assert len({x[2] for x in t}) == len(t) and len({x[3] for x in t}) == len(t)


def test_les_types_sont_les_memes_que_ceux_de_la_vue_du_waf():
    """Une même couleur garde le même sens dans toutes les pages (AURORA-REFERENCE §2) : on compare à la source de référence."""
    waf = (Path(__file__).resolve().parents[2] / "secubox-waf-ng" / "composants" / "waf" / "www" / "waf" / "vue.html").read_text(encoding="utf-8")
    motif = r"\{id:'(\w+)',nom:'([^']+)',coul:'(#[0-9a-f]{6})',forme:'(\w+)',re:/([^/]+)/i\}"
    assert re.findall(motif, SRC) == re.findall(motif, waf)


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def al(pays, cat, n):
    return [{"timestamp": "2026-10-10T14:00:00", "client_ip": "203.0.113.%d" % (i + 1), "country": pays, "category": cat,
             "host": "h", "path": "/", "severity": "high", "action": "banned"} for i in range(n)]


STATS = {"total_threats": 100, "observed_threats": 90, "by_severity": {"high": 3}, "by_category": {"sqli": 3, "xss": 1, "scan-ports": 4, "robots": 9},
         "top_countries": {"US": 40, "DE": 20, "FR": 10, "CN": 5}}
ALERTES = {"alerts": al("US", "sql.injection", 6) + al("US", "xss", 2) + al("DE", "scan-ports", 4) + al("FR", "honeypot leurre", 3) + al("DE", "robots", 1)
           + al("US", "path traversal", 1) + al("US", "brute-force ssh", 1)}
REP = {"/api/v1/waf/stats": STATS, "/api/v1/waf/alerts": ALERTES}


def ouvre(nav, reponses, url="http://g.test/soc/guardian.html", taille=None, appels=None):
    ctx = nav.new_context(viewport=taille or {"width": 1400, "height": 1000})
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def api(r):
        if appels is not None:
            appels.append(r.request.url)
        corps = reponses.get(r.request.url.split("?")[0].split("g.test")[1])
        r.fulfill(status=200 if corps is not None else 401, content_type="application/json", body=json.dumps(corps if corps is not None else {}))
    p.route("http://g.test/api/**", api)
    p.route("http://g.test/soc/guardian.html*", lambda r: r.fulfill(status=200, content_type="text/html", body=SRC))
    p.goto(url)
    p.wait_for_selector("#monde g.pt, #pays .vide", state="attached")
    return ctx, p, erreurs


def test_couleur_du_type_dominant_par_pays(nav):
    ctx, p, err = ouvre(nav, REP)
    dom = {a: p.get_attribute('#monde g.pt[data-pays="%s"]' % a, "data-dom") for a in ("US", "DE", "FR", "CN")}
    assert dom == {"US": "inj", "DE": "scan", "FR": "leurre", "CN": ""}
    cs = p.eval_on_selector_all('#monde g.pt[data-pays="US"] path[data-type]', "e=>e.map(x=>x.getAttribute('fill'))")
    assert "#ff4d5e" in cs and "#ff9f1c" in cs and len(set(cs)) == 4          # injection rouge, script orange, traversée, accès
    assert p.get_attribute('#pays [data-pays="DE"]', "data-dom") == "scan" and p.get_attribute('#pays [data-pays="CN"]', "data-dom") == ""
    assert p.locator("#pays svg").count() == 4 and err == []
    ctx.close()


def test_plus_aucun_halo_rouge_uniforme(nav):
    """L'ancienne carte peignait tout en rouge (dégradé « lueur ») : un pays sans type connu est un anneau gris, pas un halo rouge."""
    ctx, p, _ = ouvre(nav, REP)
    assert p.locator("#lueur, radialGradient").count() == 0
    cn = p.eval_on_selector('#monde g.pt[data-pays="CN"] circle', "e=>e.getAttribute('fill')+'|'+e.getAttribute('stroke')")
    assert "#ff4d5e" not in cn
    ctx.close()


def test_legende_comptes_et_filtre_accessible(nav):
    ctx, p, _ = ouvre(nav, REP)
    b = p.locator("#legT button")
    assert b.count() == 7 and p.get_attribute("#legT", "role") == "group"
    assert all(b.nth(i).get_attribute("aria-pressed") == "false" for i in range(b.count()))
    inj = p.locator('#legT button[data-type="inj"]')
    assert "Injection" in inj.inner_text() and inj.inner_text().split()[-1] == "6"
    inj.click()
    assert p.get_attribute('#legT button[data-type="inj"]', "aria-pressed") == "true"
    assert "att" in p.get_attribute('#monde g.pt[data-pays="DE"]', "class") and "att" not in p.get_attribute('#monde g.pt[data-pays="US"]', "class")
    p.locator('#legT button[data-type="inj"]').click()
    assert "att" not in p.get_attribute('#monde g.pt[data-pays="DE"]', "class")
    ctx.close()


def test_infobulle_repartition_et_pays_sans_type(nav):
    ctx, p, _ = ouvre(nav, REP)
    p.hover('#monde g.pt[data-pays="US"] circle.hal', force=True)
    t = p.inner_text("#tip")
    assert "US" in t and "40 événements" in t and "Injection" in t and "6 (60 %)" in t and "sur 10 alertes récentes" in t
    p.mouse.move(2, 2)
    assert not p.is_visible("#tip")
    p.focus('#monde g.pt[data-pays="CN"]')
    assert "Type inconnu" in p.inner_text("#tip") and "type inconnu" in p.get_attribute('#monde g.pt[data-pays="CN"]', "aria-label")
    ctx.close()


def test_sans_alerte_aucun_type_invente(nav):
    ctx, p, err = ouvre(nav, {**REP, "/api/v1/waf/alerts": {"alerts": []}})
    assert "—" in p.inner_text("#legT") and p.locator("#legT button").count() == 0
    assert p.locator("#monde g.pt").count() == 4 and all(d == "" for d in p.eval_on_selector_all("#monde g.pt", "e=>e.map(x=>x.dataset.dom)"))
    assert err == []
    ctx.close()


def test_categorie_hostile_en_texte(nav):
    mal = {"alerts": al("US", "<img src=x onerror=window.pwn=1>", 2)}
    ctx, p, _ = ouvre(nav, {**REP, "/api/v1/waf/alerts": mal})
    assert p.evaluate("window.pwn") is None and p.get_attribute('#monde g.pt[data-pays="US"]', "data-dom") == "autre"
    ctx.close()


def test_le_tableau_des_derniers_evenements_garde_ses_six_lignes_malgre_les_500_alertes(nav):
    ctx, p, _ = ouvre(nav, {**REP, "/api/v1/waf/alerts": {"alerts": al("US", "robots", 40)}})
    assert p.locator("#events tr").count() == 6
    ctx.close()


def test_on_demande_500_alertes_et_aucune_route_nouvelle(nav):
    appels = []
    ctx, p, _ = ouvre(nav, REP, appels=appels)
    assert any(a.endswith("/api/v1/waf/alerts?limit=500") for a in appels) and not any("limit=8" in a for a in appels)
    ctx.close()


def test_demo_types_varies_et_annonce(nav):
    ctx, p, err = ouvre(nav, {}, "http://g.test/soc/guardian.html?demo=1")
    assert p.is_visible("#demo") and p.locator("#legT button").count() >= 6
    assert len(set(p.eval_on_selector_all("#monde g.pt", "e=>e.map(x=>x.dataset.dom)"))) >= 4 and err == []
    ctx.close()


@pytest.mark.parametrize("larg", [420, 700, 1400])
def test_pas_de_debordement_et_legende_qui_passe_a_la_ligne(nav, larg):
    ctx, p, err = ouvre(nav, {}, "http://g.test/soc/guardian.html?demo=1", {"width": larg, "height": 900})
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth") and err == []
    assert p.evaluate("(()=>{const e=document.querySelector('.legT');return e.scrollWidth<=e.clientWidth+1})()")
    ctx.close()
