# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2516 — le détecteur d'anti-adblock du thème Foxiz (zataz) ne doit plus voir son appât masqué par la feuille cosmétique de surf.

Le détecteur crée #rb-adcheck > #google_ads_iframe_test (300x250) et déclare « bloqueur » si l'appât est masqué ou de taille nulle. La logique
de mesure est celle de Foxiz (checkBaitElement), appliquée à la VRAIE feuille injectée par surf."""
import concurrent.futures
import re
import sys
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from surf import relais  # noqa: E402

MESURE = """
() => {
  const c = document.createElement('div');
  c.id = 'rb-adcheck'; c.setAttribute('aria-hidden', 'true');
  c.style.cssText = 'position:absolute;bottom:0;left:0;z-index:-1;pointer-events:none;overflow:hidden;';
  const i = document.createElement('div');
  i.id = 'google_ads_iframe_test';
  i.className = 'adsbygoogle ad-slot adbanner ads-banner banner_ad ad-placeholder pub_300x250 textads adsbox';
  i.setAttribute('data-ad-slot', 'test');
  i.style.cssText = 'width:300px;height:250px;background:transparent;';
  c.appendChild(i); document.body.appendChild(c);
  const s = getComputedStyle(i), r = i.getBoundingClientRect();
  return r.height < 1 || r.width < 1 || s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) === 0 || i.offsetParent === null;
}
"""


def _style():
    m = re.search(r'<style id="sbx-surf">.*?</style>', relais._INJECTION, re.S)
    assert m
    return m.group(0)


def _bloque_selon_foxiz(style):
    def tache():
        with sync_api.sync_playwright() as p:
            try:
                nav = p.chromium.launch()
            except Exception as e:
                return ("skip", str(e))
            pg = nav.new_page()
            pg.set_content("<!doctype html><html><head>" + style + "</head><body><p>article</p></body></html>")
            r = pg.evaluate(MESURE)
            nav.close()
            return ("ok", r)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        res = ex.submit(tache).result(timeout=60)
    if res[0] == "skip":
        pytest.skip(res[1])
    return res[1]


def test_la_mesure_detecte_bien_un_appat_masque():
    """Garde-fou du test : sans la protection, la feuille de surf masque l'appât (c'était le défaut)."""
    sans = re.sub(r"/\* APPAT.*?\*/.*?(?=</style>)", "", _style(), flags=re.S)
    sans = re.sub(r"#rb-adcheck.*?\}\s*", "", sans, flags=re.S)
    assert _bloque_selon_foxiz(sans) is True


def test_l_appat_reste_visible_et_mesurable_sous_la_feuille_de_surf():
    assert _bloque_selon_foxiz(_style()) is False
