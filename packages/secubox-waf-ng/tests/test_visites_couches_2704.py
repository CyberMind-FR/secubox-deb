# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2704 — Visites : couches superposées et lecture dans le temps. Statique + navigateur, API simulée."""
import json
import re
import time
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "composants/waf/www/waf/visites.html"
SRC = PAGE.read_text(encoding="utf-8")
BLOC = SRC[SRC.index("#2704 : couches superposées"):SRC.index("el('heure').textContent")]


def test_statique_bloc_neuf_sans_innerhtml_ni_dialogue():
    assert "innerHTML" not in BLOC
    for interdit in ("confirm(", "alert(", "prompt(", "Math.random"):
        assert interdit not in SRC
    assert "createElementNS" in BLOC and "prefers-reduced-motion" in SRC
    assert 'type="range"' in SRC and 'aria-label="Position de la fenêtre' in SRC
    assert "historique insuffisant" in BLOC and "/api/v1/waf/history" in SRC and "sbx_token" in SRC


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def maintenant_h():
    return int(time.time() // 3600)


def stock(jours, h0=None):
    """Heures mesurées : valeur(idx) = 100 + 10*(heure UTC) + 1000*jours_en_arrière (3600 s couvertes)."""
    n = maintenant_h()
    h = {}
    for i in range(n - 24 * jours + 1, n + 1):
        h[str(i)] = [100 + 10 * (i % 24) + 1000 * ((n - i) // 24), 3600]
    return {"last": None, "h": h}


def valeur(i):
    n = maintenant_h()
    return 100 + 10 * (i % 24) + 1000 * ((n - i) // 24)


def ouvre(navigateur, url, visits=None, history=None, store=None, taille=None, reduit=False):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900},
                                 reduced_motion="reduce" if reduit else "no-preference")
    if store is not None:
        ctx.add_init_script("localStorage.setItem('sbx_visites_horaire_v1', %s);localStorage.setItem('sbx_token','tok-test')" % json.dumps(json.dumps(store)))
    p = ctx.new_page()
    err, appels = [], []
    p.on("pageerror", lambda e: err.append(str(e)))

    def fichier(r, *_):
        ch = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if ch.startswith("shared/"):
            r.fulfill(status=200, content_type="application/javascript", body="")
        elif ch.rstrip("/") == "visites":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        appels.append((r.request.url, r.request.headers.get("authorization")))
        if r.request.url.endswith("/visits"):
            c = visits
        else:
            c = history
        if c is None:
            r.fulfill(status=401, content_type="application/json", body="{}")
        else:
            r.fulfill(status=200, content_type="application/json", body=json.dumps(c))
    p.route("http://sbx.test/api/v1/waf/**", api)
    p.goto(url)
    return ctx, p, err, appels


VISITS = {"available": True, "total": 5000, "updated_unix": int(time.time()), "by_client_type": {"browser": 10},
          "by_os": {}, "by_status": {"2xx": 10}, "by_vhost": {}, "top_countries": {}}


def titres(p, sel):
    return p.evaluate("(s)=>Array.from(document.querySelectorAll(s+' title')).map(t=>t.textContent)", sel)


def test_couches_activables_et_valeurs_agregees(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/visites/", VISITS, {"jours": {}}, stock(10))
    p.wait_for_selector("#legH button")
    assert p.locator("#legH button").count() == 4
    assert all(p.get_attribute(f"#legH button >> nth={i}", "aria-pressed") == "true" for i in range(4))
    n = maintenant_h()
    # heure du dernier créneau (x=23) : fenêtre courante = n, hier = n-24, J-7 = n-168, moyenne des 7 jours précédents
    t = re.sub(r"(?<=\d)[\s\u202f\xa0](?=\d{3})", "", titres(p, "#chH")[23])
    assert f"Aujourd’hui : {round(valeur(n))} visites/h" in t
    assert f"Il y a 24 h : {valeur(n - 24)} visites/h" in t
    assert f"Il y a 7 jours : {valeur(n - 168)} visites/h" in t
    moy = sum(valeur(n - 24 * k) for k in range(1, 8)) / 7
    assert f"Moyenne des 7 jours précédents : {round(moy)} visites/h (7 jours)" in t.replace("\xa0", " ").replace(" ", " ")
    # désactiver une couche : elle disparaît de l'infobulle
    p.click("#legH button >> nth=1")
    assert p.get_attribute("#legH button >> nth=1", "aria-pressed") == "false"
    assert "Il y a 24 h" not in titres(p, "#chH")[23]
    assert p.locator("#chH path").count() >= 3
    assert ("Bearer tok-test" in [a[1] for a in appels if a[1]])
    assert err == []
    ctx.close()


def test_couche_a_historique_insuffisant_grisee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/visites/", VISITS, {"jours": {}}, stock(3))
    p.wait_for_selector("#legH button")
    assert p.is_enabled("#legH button >> nth=0") and p.is_enabled("#legH button >> nth=1")
    j7 = p.locator("#legH button >> nth=2")
    assert j7.is_disabled() and "historique insuffisant (3 jours disponibles)" in j7.inner_text()
    assert p.get_attribute("#legH button >> nth=2", "aria-pressed") == "false"
    men = p.locator("#legD button >> nth=1")
    assert men.is_disabled() and "historique insuffisant (0 jour disponible)" in men.inner_text()
    assert err == []
    ctx.close()


def test_menaces_journalieres_reelles(navigateur):
    d0 = int(time.time() // 86400)
    jours = {time.strftime("%Y-%m-%d", time.gmtime((d0 - k) * 86400)): {"total": 100 * (k + 1)} for k in range(5)}
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/visites/", VISITS, {"jours": jours}, stock(10))
    p.wait_for_function("!document.querySelector('#legD button:nth-child(2)').disabled")
    t = titres(p, "#chD")
    assert "Menaces détectées par jour : 100" in t[-1]          # aujourd'hui = k=0
    assert "Menaces détectées par jour : 500" in t[-5]
    assert "Menaces détectées par jour : —" in t[-6]            # jour absent des journaux : pas comblé
    assert "Moyenne mobile 7 jours (menaces) : 300" in t[-1] or "Moyenne mobile 7 jours (menaces) : 150" in t[-1] or "Moyenne mobile" in t[-1]
    ctx.close()


def test_curseur_lecture_vitesse_et_debut(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/visites/", VISITS, {"jours": {}}, stock(10))
    p.wait_for_selector("#curseur:not([disabled])")
    mx, mn = int(p.get_attribute("#curseur", "max")), int(p.get_attribute("#curseur", "min"))
    assert mx - mn == 239 and p.get_attribute("#curseur", "aria-label")
    avant = titres(p, "#chH")[23]
    p.fill("#curseur", str(mx - 30))
    assert titres(p, "#chH")[23] != avant and "(la plus récente)" not in p.inner_text("#lapseT")
    assert str(mx - 30 - mx) not in p.inner_text("#lapseT")
    p.click("#bDebut")
    assert int(p.input_value("#curseur")) == mn
    p.click("[data-v='4']")
    assert p.get_attribute("[data-v='4']", "aria-pressed") == "true" and p.get_attribute("[data-v='1']", "aria-pressed") == "false"
    p.click("#bPlay")
    assert "Pause" in p.inner_text("#bPlay")
    p.wait_for_function("+document.getElementById('curseur').value > %d + 5" % mn)
    p.click("#bPlay")
    v = p.input_value("#curseur")
    time.sleep(.5)
    assert p.input_value("#curseur") == v                         # pause : plus d'avance
    assert err == []
    ctx.close()


def test_reduced_motion_pas_de_lecture_auto(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/visites/?demo=1", reduit=True)
    p.wait_for_selector("#curseur:not([disabled])")
    assert p.is_disabled("#bPlay") and "réduire les animations" in p.get_attribute("#bPlay", "title")
    v = p.input_value("#curseur")
    time.sleep(.6)
    assert p.input_value("#curseur") == v
    p.fill("#curseur", str(int(v) - 50))                           # le curseur manuel reste utilisable
    assert p.input_value("#curseur") == str(int(v) - 50) and err == []
    ctx.close()


def test_demonstration_sans_requete(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "http://sbx.test/visites/?demo=1")
    p.wait_for_selector("#curseur:not([disabled])")
    assert "fictives" in p.inner_text("#demo") and p.is_visible("#demo")
    assert p.locator("#legH button:enabled").count() == 4 and p.locator("#legD button:enabled").count() == 3
    p.click("#bPlay")
    p.wait_for_function("document.getElementById('bPlay').textContent.includes('Pause')")
    p.click("#bPlay")
    assert appels == [] and err == []
    ctx.close()


def test_sans_session_tirets_et_aucune_erreur(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/visites/", None, None)
    p.wait_for_selector("#session:not([hidden])")
    assert p.locator("#legH button:disabled").count() == 4
    assert "historique insuffisant" in p.inner_text("#legH")
    assert "—" in p.inner_text("#tuilesC") and p.is_disabled("#curseur") and err == []
    ctx.close()


def test_echantillonnage_du_compteur_cumule(navigateur):
    t = int(time.time())
    st = {"last": {"t": t - 720, "n": 1000}, "h": {}}
    v = dict(VISITS, total=1144, updated_unix=t)
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/visites/", v, {"jours": {}}, st)
    p.wait_for_function("document.querySelector('#tuilesC .v').textContent !== '—'")
    assert p.inner_text("#tuilesC .v") == "720"                    # 144 visites en 720 s = 720 visites/h
    ctx.close()


def test_telephone_sans_debordement_et_embed(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "http://sbx.test/visites/?demo=1&embed=1", taille={"width": 420, "height": 900})
    p.wait_for_selector("#curseur:not([disabled])")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert p.evaluate("document.getElementById('chH').getBoundingClientRect().right <= innerWidth")
    assert err == []
    ctx.close()
