# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3960 — « Bannir cet acteur » dans la fiche : vrai navigateur, API simulée."""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
playwright = pytest.importorskip("playwright.sync_api")

from test_actor_details_3936 import Banc, nav  # noqa: E402,F401
import json  # noqa: E402

ID = "a" * 32


class BancBan(Banc):
    def __init__(self, nav, **k):  # noqa: F811
        self.posts, self.gestes, self.code, self.expire, self.etat_ko, self.ici = [], [], 200, 300, False, True
        super().__init__(nav, **k)

    def _sert(self, r, *_):
        u = r.request.url.split("http://sbx.test", 1)[1]
        if not u.startswith("/api/v1/waf/acteurs/"):
            return super()._sert(r)
        code, now = 200, int(time.time())
        if r.request.method == "POST":
            self.posts.append((u, r.request.post_data_json))
            code = self.code
        if code != 200:
            d = {"detail": {"motif": "protegee_inconnue"}}
        elif u.endswith("/etat"):
            code = 403 if self.etat_ko else 200
            d = {"vues_48h": 10, "bannies": 4 + 2 * len(self.gestes), "partiel": True, "gestes": self.gestes}
        elif u.endswith("/apercu"):
            d = {"apercu": ID, "expire": now + self.expire, "a_bannir": [{"ip": "198.51.100.7", "vu": now}, {"ip": "198.51.100.8", "vu": now}],
                 "deja_bannies": 4, "reste": 30, "partiel": False,
                 "epargnees": [{"ip": "x", "motif": "robot"}, {"ip": "y", "motif": "robot"}, {"ip": "z", "motif": "<img src=x>"}]}
        elif u.endswith("/bannir"):
            self.gestes = [{"id": ID, "at": now, "fin": now + 86400, "nombre": 2, "par": "gk2", "ici": self.ici}]
            d = {"id": ID, "posees": 2, "presentes": 0, "refusees": [], "fin": now + 86400}
        else:
            self.gestes = []
            d = {"id": ID, "levees": 1, "gardees": 1}
        return r.fulfill(status=code, content_type="application/json", body=json.dumps(d))


def test_apercu_confirmation_puis_levee(nav):  # noqa: F811
    b = BancBan(nav)
    b.p.wait_for_function("document.querySelector('.ban').textContent.includes('Bloqué maintenant : 4 sur 10')")
    assert b.p.get_by_role("button", name="Bannir ces").count() == 0          # jamais sans aperçu
    b.p.click(".ban button:has-text('Voir ce qui serait banni')")
    b.p.wait_for_selector(".ban .banl")
    t = b.p.inner_text(".ban").replace(" ", " ").replace(" ", " ")
    assert "À bannir 24 h : 2 adresses, puis 30 au geste suivant" in t and "2 robot vérifié, 1 <img src=x>" in t
    assert b.posts == [] and b.p.locator(".ban img").count() == 0
    b.p.click("#rafraichir")                                                  # la relecture ne perd pas l'aperçu
    b.p.wait_for_timeout(400)
    b.p.click(".ban button.rouge")
    b.p.wait_for_selector(".ban button:has-text('Lever ce ban')")
    assert b.posts == [("/api/v1/waf/acteurs/ACT-0000/bannir", {"apercu": ID})]
    assert "2 adresses bannies jusqu" in b.p.inner_text(".ban")
    b.p.click(".ban button:has-text('Lever ce ban')")
    b.p.wait_for_function("document.querySelector('.ban').textContent.includes('1 adresse levée')")
    assert b.posts[1][0].endswith(f"/gestes/{ID}/lever") and b.p.locator(".ban button:has-text('Lever')").count() == 0
    b.fin()


def test_refus_dit_et_apercu_expire(nav):  # noqa: F811
    b = BancBan(nav)
    b.code = 503
    b.p.click(".ban button:has-text('Voir ce qui serait banni')")
    b.p.click(".ban button.rouge")
    b.p.wait_for_selector(".ban p.err")
    assert "rien n’est banni" in b.p.inner_text(".ban p.err") and b.p.locator(".ban button.rouge").count() == 0
    b.expire = 3
    b.p.click(".ban button:has-text('Voir ce qui serait banni')")
    b.p.wait_for_selector(".ban button.rouge")
    b.p.wait_for_function("!document.querySelector('.ban button.rouge')", timeout=15000)
    assert len(b.posts) == 1
    b.fin()


def test_annuler_et_session_refusee(nav):  # noqa: F811
    b = BancBan(nav, taille={"width": 400, "height": 800})
    b.p.evaluate("montreProfil()")
    b.p.click(".ban button:has-text('Voir ce qui serait banni')")
    b.p.click(".ban button:has-text('Annuler')")
    assert b.p.locator(".ban button.rouge").count() == 0 and b.posts == []
    assert b.p.evaluate("document.documentElement.scrollWidth<=innerWidth")
    b.fin()


def test_demonstration_sans_geste(nav):  # noqa: F811
    b = Banc(nav, url="?demo=1")
    if b.p.locator("#demo:not([hidden])").count():
        assert b.p.locator(".ban button").count() == 0 and not [u for u in b.appels if "waf/acteurs" in u]
    b.ctx.close()


def test_geste_d_une_autre_fiche_a_part_et_levable(nav):  # noqa: F811
    b = BancBan(nav)
    b.ici = False
    b.p.click(".ban button:has-text('Voir ce qui serait banni')")
    b.p.click(".ban button.rouge")
    b.p.wait_for_selector(".ban details:has-text('Autres gestes en cours')")
    assert b.p.locator(".ban > .bang button:has-text('Lever')").count() == 0
    b.p.click(".ban summary:has-text('Autres gestes en cours')")
    b.p.click(".ban button:has-text('Lever ce ban')")
    b.p.wait_for_function("document.querySelector('.ban').textContent.includes('1 adresse levée')")
    b.fin()
