# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2647 — SBX OS au profil Aurora : coquille statique + vrai navigateur, box simulée (données factices)."""
import json
import mimetypes
import re
from pathlib import Path

import pytest

WWW = Path(__file__).resolve().parents[1] / "www"
SRC = (WWW / "index.html").read_text(encoding="utf-8")
CSS = (WWW / "ui" / "styles.css").read_text(encoding="utf-8")


def test_coquille_sans_dialogue_natif_ni_dependance():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    assert re.findall(r'<script[^>]+src="([^"]+)"', SRC) == []
    assert "https://fonts" not in SRC and "https://fonts" not in CSS
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "onclick="):
        assert interdit not in SRC
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'sbxos'" in SRC and "demo" in SRC and "embed" in SRC


def test_memes_appels_reseau_qu_avant():
    for r in ("/api/v1/acces/session/etat", "/acces/appareil.js", "./mine/manifeste.json", "ouvreSiAdmis", "cloneDuHall({ profil })"):
        assert r in SRC
    assert "./offline/sw.js" in SRC
    assert "'sbxos-v8'" in (WWW / "offline" / "sw.js").read_text(encoding="utf-8")
    assert "--sbx-fond:#070C1C" in CSS and "--accent:var(--sbx-accent-2)" in CSS


playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


CURATION = (WWW / "mine" / "curation.json").read_text(encoding="utf-8")


def ouvre(navigateur, query="", api=None, manifeste=True, taille=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1300, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif"), d.dismiss()))
    p.add_init_script("window.__msgs=[];addEventListener('message',e=>__msgs.push(e.data));")

    def fichier(r, *_):
        url = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        appels.append(url)
        if url.startswith("/api/"):
            statut, corps = (api or {}).get(url, (404, {}))
            r.fulfill(status=statut, content_type="application/json", body=json.dumps(corps))
            return
        if not url.startswith("/sbxos/"):
            r.fulfill(status=404, body="")
            return
        rel = url[len("/sbxos/"):] or "index.html"
        f = WWW / rel
        if not manifeste and rel.startswith("mine/") and rel.endswith(".json"):
            r.fulfill(status=404, body="")
        elif f.is_file():
            r.fulfill(status=200, content_type=mimetypes.guess_type(f.name)[0] or "text/plain", body=f.read_bytes())
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)
    p.goto("http://sbx.test/sbxos/" + query)
    return ctx, p, erreurs, appels


def test_demonstration_annoncee_hors_reseau_et_sans_stockage(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "?demo=1")
    p.wait_for_selector("sbx-carlette", state="attached")
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    assert [p.inner_text(i) for i in ("#tProfil", "#tAutorises", "#tAffiches", "#tFavoris")] == ["user", "6", "6", "0"]
    assert [a for a in appels if a.startswith("/api/") or a.startswith("/acces/") or a.endswith("manifeste.json") or a.endswith("curation.json")] == []
    # ouvrir un lieu fictif : rien n'est chargé
    p.locator("sbx-carlette").first.click()
    p.wait_for_selector("#theatre:not([hidden])")
    assert "fictif" in p.inner_text("#theatre-note") and p.get_attribute("#theatre-cadre", "src") in (None, "")
    p.click("#theatre-fav")
    assert p.evaluate("localStorage.getItem('sbxos.hall')") is None and p.evaluate("localStorage.getItem('sbxos.manifeste')") is None
    assert err == []
    ctx.close()


def test_les_tuiles_portent_une_definition_et_viennent_du_bureau(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "", api={"/api/v1/acces/session/etat": (200, {"session": True})})
    p.wait_for_function("document.getElementById('tAutorises').textContent !== '—'")
    assert not p.is_visible("#demo")
    n = int(p.inner_text("#tAutorises"))
    assert n > 0 and p.inner_text("#tProfil") == "user" and int(p.inner_text("#tAffiches")) <= n
    assert p.evaluate("[...document.querySelectorAll('.tuile')].every(t => t.title.length > 20)")
    assert err == []
    ctx.close()


def test_sans_acces_bandeau_session_requise(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "", api={"/api/v1/acces/session/etat": (200, {"session": False})})
    p.wait_for_selector("#note.info")
    assert "session requise" in p.inner_text("#note") and p.locator("#note a").get_attribute("href") == "/acces/"
    assert err == []
    ctx.close()


def test_box_injoignable_tirets_et_message(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "", manifeste=False)
    p.wait_for_function("document.getElementById('note').textContent.includes('injoignable')")
    assert [p.inner_text(i) for i in ("#tProfil", "#tAutorises", "#tAffiches", "#tFavoris")] == ["—"] * 4
    assert err == []
    ctx.close()


def test_encadre_masque_la_marque_annonce_sa_hauteur_et_tient_sur_420px(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "?embed=1&demo=1", taille={"width": 420, "height": 800})
    p.wait_for_selector("sbx-carlette", state="attached")
    assert not p.is_visible(".mast .marque")
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    for ecran in ("favoris", "reglages"):
        p.click(f"#barre button[data-ecran={ecran}]")
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    msgs = [m for m in p.evaluate("__msgs") if isinstance(m, dict) and m.get("onglet") == "sbxos"]
    assert msgs and all(isinstance(m["sbxVue"], int) and m["sbxVue"] > 100 for m in msgs)
    assert err == []
    ctx.close()


def test_reglages_et_ecrans_fonctionnent_toujours(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "?demo=1")
    p.wait_for_selector("sbx-carlette", state="attached")
    p.click("#barre button[data-ecran=reglages]")
    assert p.is_visible("#ecran-reglages") and not p.is_visible("#ecran-hall")
    p.select_option("#choix-densite", "large")
    assert p.get_attribute("#damier", "densite") == "large"
    p.select_option("#choix-theme", "clair")
    assert p.get_attribute("html", "data-theme") == "light"
    p.click("#barre button[data-ecran=hall]")
    assert p.is_visible("#ecran-hall") and err == []
    ctx.close()
