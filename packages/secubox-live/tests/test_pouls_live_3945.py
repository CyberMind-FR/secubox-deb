# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Page publique vivante (#3945) : location exacte, version, contraste, et au navigateur (CSP de production) recul daté,
ancien etat.json, relevé ancien, pouls.js absent. Le composant lui-même est testé dans secubox-hub."""
import re
import time

import pytest
from test_page_3933 import etat, lire, navigateur, ouvrir, serveur  # noqa: F401 — mêmes fixtures que la page


def test_location_exacte_version_et_paquet():
    conf, html = lire("nginx/live.vhost.conf.in"), lire("www/live/index.html")
    assert "location = /pouls.js     { limit_except GET HEAD { deny all; } try_files /pouls.js =404; }" in conf
    v = re.match(r"secubox-live \((\d+\.\d+\.\d+)-", lire("debian/changelog")).group(1)
    assert f'src="/pouls.js?v={v}"' in html and "script-src 'self'; style-src 'self'" in conf
    assert "www/live/*.js" in lire("debian/rules")


def _lum(h):
    c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= .03928 else ((x + .055) / 1.055) ** 2.4 for x in c]
    return .2126 * c[0] + .7152 * c[1] + .0722 * c[2]


def test_contraste_des_dates():
    css = lire("www/live/live.css")
    nuit, jour = css.split(':root[data-ambiance="jour"]', 1)

    def var(bloc, nom):
        return re.search(rf"--{nom}:(#[0-9a-f]{{6}})", bloc).group(1)
    for bloc, fonds in ((nuit, ["#0a0714", "#140e28"]), (jour, ["#f3f7ff", "#ffffff"])):
        for nom in ("sbxp-direct", "ambre-texte", "cyan-texte"):
            for fond in fonds:
                a, b = sorted((_lum(var(bloc, nom)), _lum(fond)), reverse=True)
                assert (a + .05) / (b + .05) >= 4.5, (nom, fond)


def passe(n=12):
    t = int(time.time())
    return [{"genere_le": t - 600 * (n - i), "attaques": [{"code": "FR", "n": 100 + i}, {"code": "US", "n": 50}] if i != 4 else None,
             "visiteurs": [{"code": "FR", "n": 3}], "tuiles": {"requetes_24h": 100 * i, "menaces_24h": 1, "bloquees_24h": 1, "bans_actifs": i}} for i in range(n)]


def donnees(**c):
    e = etat(**c)
    e["genere_le"] = int(time.time())
    return e


def avancer(pg, sel, motif, tours=600):
    for _ in range(tours):
        t = pg.evaluate("s=>document.querySelector(s).textContent", sel)
        if re.search(motif, t):
            return t
        pg.clock.run_for(60)
    raise AssertionError((sel, motif, t))


def test_nav_carte_recule_date_et_revient(ouvrir):  # noqa: F811
    pg, _ = ouvrir(donnees(cartes_passe=passe()))
    pg.evaluate("document.getElementById('monde').scrollIntoView({block:'center'})")
    pg.wait_for_timeout(200)
    avancer(pg, "#monde-quand", r"^● maintenant$")
    avancer(pg, "#monde-quand", r"^◀ il y a 1 h \d\d$")
    assert pg.evaluate("document.querySelectorAll('#monde .onde').length") == 0        # remplacées par celles du composant
    avancer(pg, "#monde-quand", r"^● maintenant$")
    assert pg.evaluate("[...document.querySelectorAll('#top em')].every(e=>e.textContent==='')")
    assert pg.erreurs == []


def test_nav_releve_pendant_le_recul_ne_relance_pas(ouvrir):  # noqa: F811
    pg, boite = ouvrir(donnees(cartes_passe=passe()))
    pg.evaluate("document.getElementById('monde').scrollIntoView({block:'center'})")
    pg.wait_for_timeout(200)
    avancer(pg, "#monde-quand", r"^◀ il y a 1 h \d\d$")
    boite["e"] = donnees(cartes_passe=passe())
    avant = pg.evaluate("document.getElementById('monde-quand').textContent")
    pg.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
    pg.wait_for_timeout(200)
    assert avant.startswith("◀") and pg.evaluate("document.querySelectorAll('svg[data-sbxp=carte]').length") == 1
    assert pg.evaluate("document.getElementById('monde-quand').textContent").startswith("◀")


def test_nav_ancien_etat_sans_passe(ouvrir):  # noqa: F811
    pg, _ = ouvrir(donnees())
    assert pg.evaluate("document.getElementById('monde-quand').textContent") == ""
    assert pg.evaluate("document.querySelectorAll('#monde .onde').length") > 0          # les ondes d'avant demeurent
    assert pg.evaluate("document.getElementById('t-requetes').textContent").strip() != ""
    assert pg.erreurs == []


def test_nav_releve_ancien_jamais_maintenant(ouvrir):  # noqa: F811
    e = donnees(cartes_passe=passe())
    e["genere_le"] -= 3600
    for x in e["cartes_passe"]:
        x["genere_le"] -= 3600
    pg, _ = ouvrir(e)
    assert pg.evaluate("document.getElementById('monde-quand').textContent") == "● au relevé"
    assert pg.evaluate("[...document.querySelectorAll('[data-sbxp=quand]')].every(x=>!/maintenant/.test(x.textContent))")
    pg.evaluate("document.getElementById('heure').scrollIntoView({block:'center'})")
    pg.wait_for_timeout(200)
    avancer(pg, "#heure-quand", r"^◀ \d+ min avant le relevé : ")


def test_nav_fixe_arrete_la_pluie(ouvrir):  # noqa: F811
    pg, _ = ouvrir(donnees())
    pg.evaluate("()=>{window.dispatchEvent(new StorageEvent('storage',{key:'sbx-pouls',newValue:'fixe'}));window.n=0;const x=CanvasRenderingContext2D.prototype,f=x.clearRect;x.clearRect=function(){window.n++;return f.apply(this,arguments)}}")
    pg.clock.run_for(1500)
    assert pg.evaluate("window.n") == 0
    pg.evaluate("window.dispatchEvent(new StorageEvent('storage',{key:'sbx-pouls',newValue:'vivant'}))")
    pg.clock.run_for(1500)
    assert pg.evaluate("window.n") > 5


def test_nav_sans_pouls_la_page_reste_entiere(navigateur, serveur):  # noqa: F811
    import json
    c = navigateur.new_context()
    pg = c.new_page()
    err = []
    pg.on("pageerror", lambda x: err.append(str(x)))
    pg.route("**/pouls.js*", lambda r: r.fulfill(status=404))
    pg.route("**/etat.json", lambda r: r.fulfill(status=200, content_type="application/json", body=json.dumps(donnees(cartes_passe=passe()))))
    pg.goto(serveur)
    pg.wait_for_timeout(600)
    assert pg.evaluate("[document.querySelectorAll('#monde .point').length>0,document.querySelectorAll('#monde .onde').length>0]") == [True, True]
    assert pg.locator("[data-sbxp]").count() == 0 and err == []
    c.close()


@pytest.mark.parametrize("sale", [{"cartes_passe": "x"}, {"cartes_passe": [None, 3, {"genere_le": "hier"}, {"genere_le": 1764000000, "attaques": [{"code": "<i>", "n": 1}], "tuiles": 4}]}])
def test_nav_passe_hostile(ouvrir, sale):  # noqa: F811
    pg, _ = ouvrir(donnees(**sale))
    pg.clock.run_for(4000)
    assert pg.erreurs == [] and not re.search(r"NaN|undefined", pg.evaluate("document.body.innerText"))
