# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2473 — portail /billets/ au profil Aurora : stats réelles du blog, « — » sans mesure, liens sûrs, valeurs en texte brut, aucune écriture."""
import concurrent.futures
import json
import pathlib
import re

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
PAGE = pathlib.Path(__file__).resolve().parents[1] / "www" / "billets" / "index.html"
CORS = {"access-control-allow-origin": "*"}


def _nav(scenario, query="?demo=1", stats=None):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e), [], [])
            pg = nav.new_page()
            erreurs, natifs = [], []
            pg.on("pageerror", lambda e: erreurs.append(str(e)))
            pg.on("dialog", lambda d: (natifs.append(d.type), d.dismiss()))
            if stats is not None:
                def route(r):
                    u = r.request.url
                    if u.endswith("/page"):
                        return r.fulfill(status=200, content_type="text/html", body=PAGE.read_text(encoding="utf-8"))
                    if u.endswith("/stats.json"):
                        return stats(r)
                    return r.fulfill(status=404, body="")
                pg.route("**/*", route)
                pg.goto("https://admin.exemple.test/page")
            else:
                pg.goto("file://" + str(PAGE) + query)
            pg.wait_for_timeout(500)
            r = scenario(pg)
            nav.close()
            return ("ok", r, erreurs, natifs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1], res[2], res[3]


def test_aucune_boite_native_ni_ecriture():
    src = PAGE.read_text(encoding="utf-8")
    code = re.sub(r"//[^\n]*", "", re.sub(r"<!--.*?-->", "", src, flags=re.S)).replace("onerror=alert(1)", "").replace("javascript:alert(1)", "")
    for f in ("confirm", "alert", "prompt"):
        assert not re.search(r"(?<![A-Za-z.])" + f + r"\(", code), f
    assert "POST" not in src and "method:" not in code


def test_demo_tuiles_reactions_et_derniers_billets():
    def sc(pg):
        return ([pg.inner_text(f".tuile .v[data-k='{k}']") for k in ("billets_published", "billets_drafts", "comments_approved", "reactions_total")],
                pg.locator("#reacts .chip").count(), pg.inner_text("#reacts .chip:first-child"), pg.locator("#latest .item").count(),
                pg.evaluate("document.getElementById('latest').textContent.includes('<img src=x onerror=alert(1)>')"), pg.locator("#latest img").count(),
                pg.is_visible("#demo"))
    (t, n, premier, billets, texte, imgs, demo), erreurs, natifs = _nav(sc)
    assert t[0] == "42" and t[1] == "3" and t[2] == "117" and t[3] == "560" and n == 6 and "👍" in premier and "210" in premier
    assert billets == 3 and texte and imgs == 0 and demo and erreurs == [] and natifs == []


def test_lien_javascript_n_est_jamais_pose():
    def sc(pg):
        return pg.evaluate("[...document.querySelectorAll('#latest .item')].map(a => a.getAttribute('href'))")
    hrefs, erreurs, _ = _nav(sc)
    assert len(hrefs) == 3 and not any((h or "").startswith("javascript:") for h in hrefs) and erreurs == []


def test_blog_injoignable_donne_des_tirets_et_le_dit():
    def stats(r):
        r.fulfill(status=500, body="{}", headers=CORS)

    def sc(pg):
        return [pg.inner_text(f".tuile .v[data-k='{k}']") for k in ("billets_published", "billets_drafts", "comments_approved", "reactions_total")], pg.inner_text("#pastille"), pg.inner_text("#latest")
    (vals, pastille, latest), erreurs, _ = _nav(sc, stats=stats)
    assert vals == ["—"] * 4 and pastille == "BLOG INJOIGNABLE" and "injoignable" in latest and erreurs == []


def test_stats_reelles_du_blog_lues_depuis_l_origine_billets():
    corps = {"site_url": "https://billets.exemple.test/", "billets_published": 7, "billets_drafts": 1, "comments_approved": 9, "reactions_total": 30, "reactions_by": {"👍": 30}, "latest": [{"title": "Salut", "url": "/b/9", "date": "2026-10-12"}]}

    def stats(r):
        r.fulfill(status=200, content_type="application/json", headers=CORS, body=json.dumps(corps))

    def sc(pg):
        return (pg.inner_text(".tuile .v[data-k='billets_published']"), pg.inner_text("#pastille"), pg.get_attribute("#latest .item", "href"), pg.get_attribute("#a-new", "href"),
                pg.inner_text("#reacts .chip:nth-child(2)"))
    (pub, pastille, href, nouveau, chip2), erreurs, _ = _nav(sc, stats=stats)
    assert pub == "7" and pastille == "BLOG EN LIGNE · 7 PUBLIÉS" and href == "https://billets.exemple.test/b/9" and nouveau == "https://billets.exemple.test/admin/billets/new"
    assert chip2.replace("\n", "") .startswith("❤️") and chip2.endswith("0") and erreurs == []
