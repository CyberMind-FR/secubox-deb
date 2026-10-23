# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 1bis) — <sbx-dice> : le dé SecuBox de 3d.<domaine>, extrait en composant, dans la topbar v2.

Pas d'iframe, pas de bibliothèque, pas de fetch distant : moteur canvas 2D servi par le Hall, textures en fichiers.
Au quart de vitesse sous prefers-reduced-motion (figé par localStorage sbx_de=fige, #3068), en pause hors écran, 30 i/s si le dessin dépasse 8 ms. Le thème Plymouth
secubox-cube reprend les mêmes six faces.
"""
import mimetypes
import re
import struct
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
RACINE = PKG.parents[1]
HALL_DIR = PKG / "www" / "hall"
JS = (HALL_DIR / "sbx-dice.js").read_text(encoding="utf-8")
COQUE_JS = (HALL_DIR / "hall-v2.js").read_text(encoding="utf-8")
SRC = (HALL_DIR / "index.html").read_text(encoding="utf-8")
RULES = (PKG / "debian" / "rules").read_text(encoding="utf-8")
PLY = RACINE / "image" / "plymouth" / "secubox-cube"


def test_composant_livre_sous_licence_et_route():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in JS
    assert "www/hall/sbx-dice.js $(CURDIR)/debian/secubox-webos/usr/share/secubox/www/hall/sbx-dice.js" in RULES
    assert "www/hall/dice/*.jpg $(CURDIR)/debian/secubox-webos/usr/share/secubox/www/hall/dice/" in RULES
    for conf in ("nginx/hall-racine.conf", "nginx/webos.conf"):
        c = (PKG / conf).read_text(encoding="utf-8")
        assert "location = /sbx-dice.js" in c and "location ^~ /dice/" in c, conf


def test_budget_et_interdits():
    sans_commentaires = re.sub(r"/\*.*?\*/", "", JS, flags=re.S)
    assert len(re.sub(r"\s+", " ", sans_commentaires).encode()) <= 8 * 1024
    for interdit in ("eval(", "new Function", "fetch(", "http://", "https://", "importScripts", "<script"):
        assert interdit not in JS, interdit
    assert "customElements.define('sbx-dice'" in JS
    assert "prefers-reduced-motion: reduce" in JS and "visibilitychange" in JS and "IntersectionObserver" in JS
    # le Hall v1 ne charge pas le composant : seule la coque v2 l'injecte
    assert "sbx-dice" not in SRC
    assert "s.src='/sbx-dice.js'" in COQUE_JS


def test_six_textures_jpeg_320_decodees_pas_de_base64():
    assert "base64" not in JS
    for i in range(6):
        f = HALL_DIR / "dice" / f"face-{i}.jpg"
        b = f.read_bytes()
        assert b[:2] == b"\xff\xd8", f
        # SOF0/SOF2 : hauteur, largeur
        j = 2
        while j < len(b) - 9:
            if b[j] == 0xFF and b[j + 1] in (0xC0, 0xC2):
                h, w = struct.unpack(">HH", b[j + 5:j + 9])
                assert (w, h) == (320, 320), (f, w, h)
                break
            j += 1
        else:
            pytest.fail(f"pas de SOF dans {f}")


def test_plymouth_reprend_les_six_faces():
    script = (PLY / "secubox-cube.script").read_text(encoding="utf-8")
    for i in range(6):
        assert (PLY / f"face-{i}.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
        assert f'Image("face-{i}.png")' in script, i
    assert 'Image("face-5.png");   /* Front' in script
    assert 'cp "${CUBE_SRC}"/face-*.png "${PLYMOUTH_DIR}/"' in (RACINE / "image" / "build-rpi-usb.sh").read_text(encoding="utf-8")


# ── Rendu ──────────────────────────────────────────────────────────────────

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, largeur, reduced=False, fige=False):
    ctx = nav.new_context(viewport={"width": largeur, "height": 900}, color_scheme="dark",
                          reduced_motion="reduce" if reduced else "no-preference")
    if fige:
        ctx.add_init_script("try{localStorage.setItem('sbx_de','fige')}catch(e){}")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.15.0-1", "en_ligne": true}')
        if u.startswith("/api/"):
            return r.fulfill(status=401, content_type="application/json", body="{}")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.goto("http://sbx.test/?hall=v2")
    p.wait_for_selector(".logo sbx-dice canvas", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def pixels_opaques(p):
    return p.evaluate("""(()=>{const c=document.querySelector('.logo sbx-dice canvas');const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data;
      let n=0;for(let i=3;i<d.length;i+=4) if(d[i]>0) n++;return n;})()""")


def test_le_de_remplace_le_medaillon_et_tourne(nav):
    ctx, p, erreurs = ouvre(nav, 1440)
    assert p.evaluate("!document.querySelector('.logo .medaillon')")
    assert p.evaluate("document.querySelector('.logo sbx-dice').getAttribute('size')") == "36"
    assert p.evaluate("document.querySelector('.logo sbx-dice canvas').getAttribute('aria-hidden')") == "true"
    assert p.evaluate("getComputedStyle(document.querySelector('.logo sbx-dice canvas')).width") == "36px"
    p.wait_for_function("document.querySelector('.logo sbx-dice canvas').getContext('2d').getImageData(0,0,4,4)")
    a = pixels_opaques(p)
    assert a > 200
    avant = p.evaluate("document.querySelector('.logo sbx-dice canvas').toDataURL()")
    p.wait_for_timeout(250)
    assert p.evaluate("document.querySelector('.logo sbx-dice canvas').toDataURL()") != avant
    # mesure : moyenne du coût de dessin sur 60 images, exposée sur l'élément
    p.wait_for_function("document.querySelector('.logo sbx-dice').hasAttribute('data-raf-ms')", timeout=15000)
    ms = p.evaluate("document.querySelector('.logo sbx-dice').mesure()")
    print(f"\n[sbx-dice] dessin moyen 36 px : {ms:.2f} ms/image")
    assert 0 < ms < 8
    # le logo reste le label accessible, et le texte SbX est intact
    assert "SbX" in p.inner_text(".logo")
    assert erreurs == []
    ctx.close()


def test_survol_accelere_et_le_clic_reste_l_accueil(nav):
    ctx, p, _ = ouvre(nav, 1440)
    p.hover(".logo")
    assert p.evaluate("document.querySelector('.logo sbx-dice').getAttribute('speed')") == "12"
    p.mouse.move(700, 600)
    assert p.evaluate("document.querySelector('.logo sbx-dice').getAttribute('speed')") == "4"
    p.evaluate("showView('systeme')")
    p.click(".logo")
    assert not p.evaluate("document.getElementById('view-accueil').classList.contains('hidden')")
    ctx.close()


def test_reduced_motion_tourne_au_quart_de_vitesse_au_lieu_de_se_figer(nav):
    """#3068 — une préférence « réduire les animations » posée sur un poste de bureau laissait le dé immobile, sans
    explication, alors qu'il tournait sur tablette : il tourne maintenant, calmement (data-etat=calme)."""
    ctx, p, erreurs = ouvre(nav, 1440, reduced=True)
    p.wait_for_function("document.querySelector('.logo sbx-dice').getAttribute('data-etat')==='calme'")
    avant = p.evaluate("document.querySelector('.logo sbx-dice canvas').toDataURL()")
    p.wait_for_timeout(1500)
    assert p.evaluate("document.querySelector('.logo sbx-dice canvas').toDataURL()") != avant, "le dé doit tourner"
    assert erreurs == []
    ctx.close()


def test_sbx_de_fige_fige_la_face_secubox_sans_boucle(nav):
    ctx, p, erreurs = ouvre(nav, 1440, reduced=True, fige=True)
    p.wait_for_function("document.querySelector('.logo sbx-dice').getAttribute('data-etat')==='fige'")
    avant = p.evaluate("document.querySelector('.logo sbx-dice canvas').toDataURL()")
    p.wait_for_timeout(400)
    assert p.evaluate("document.querySelector('.logo sbx-dice canvas').toDataURL()") == avant
    assert not p.evaluate("document.querySelector('.logo sbx-dice').hasAttribute('data-raf-ms')")
    assert erreurs == []
    ctx.close()


def test_mobile_30_px(nav):
    ctx, p, erreurs = ouvre(nav, 390)
    assert p.evaluate("document.querySelector('.logo sbx-dice').getAttribute('size')") == "30"
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    assert erreurs == []
    ctx.close()
