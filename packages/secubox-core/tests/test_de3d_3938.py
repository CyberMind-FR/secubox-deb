# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3938 — accueil de nœud : dé holographique en 3D réelle (WebGL 2, www/noeud/de3d.js), repli <sbx-dice>.

Vérifié : le moteur (licence, budget, rien d'extérieur, replis de période sans dérive), la page rendue par Chromium en GL
logiciel (SwiftShader) sous la CSP réelle du vhost (canvas exactement dans le cercle de la mire, contraste du texte, nom long,
rotation sans arrêt, motifs lisibles à douze poses), les replis (pas de WebGL 2, shader refusé, image absente, moteur absent,
contexte perdu) et la régénération du vhost déjà posé, sans nouvelle exposition."""
import io
import math
import os
import random
import re
from pathlib import Path

import pytest

from banc_noeud import DE3D, DOM, HALL, PAGE, PKG, POLICES, audits, box_noeud, charger, conf, table  # noqa: F401

JS = DE3D.read_text(encoding="utf-8")


# ── Le moteur ────────────────────────────────────────────────────────────────────────────────────────────────

def test_moteur_licence_budget_et_interdits():
    assert JS.startswith("/* SPDX-License-Identifier: LicenseRef-CMSD-1.0")
    sans = re.sub(r"/\*.*?\*/", "", JS, flags=re.S)
    sans = re.sub(r"\s//[^\n]*", "", sans)
    assert len(re.sub(r"\s+", " ", sans).encode()) <= 20 * 1024
    for interdit in ("http://", "https://", "fetch(", "XMLHttpRequest", "WebSocket", "eval(", "new Function", "innerHTML",
                     "new Worker", "blob:", "data:", "importScripts", "localStorage.setItem"):
        assert interdit not in JS, interdit
    for voulu in ("powerPreference:'low-power'", "webglcontextlost", "webglcontextrestored", "preventDefault()", "visibilitychange",
                  "IntersectionObserver", "prefers-reduced-motion: reduce", "(hover: hover) and (pointer: fine)", "SRGB8_ALPHA8",
                  "sbx_de')==='fige'"):
        assert voulu in JS, voulu
    # smoothstep à bornes inversées : résultat indéfini en GLSL (Mali, V3D)
    for a, b in re.findall(r"smoothstep\((-?[\d.]+),(-?[\d.]+),", JS):
        assert float(a) < float(b), (a, b)


def test_aucune_derive_le_temps_est_replie_sur_sa_periode():
    assert "T=(T+pas/1000)%100" in JS and "%9" in JS and "%TAU" in JS
    # chaque facteur de T donné à irise (période 1) fait un nombre entier de tours en 100 s ; le sinus aussi
    facteurs = re.findall(r"T\*(\.\d+)", JS)
    assert len(facteurs) >= 6
    for f in facteurs:
        tours = float(f) * 100 / (2 * math.pi) if f == ".8796459" else float(f) * 100
        assert abs(tours - round(tours)) < 1e-4, f


# ── Le vhost déjà posé sur une box ───────────────────────────────────────────────────────────────────────────

def _ancien(texte):
    """Le vhost de 1.8.43 : sans le dé 3D ni les polices."""
    return re.sub(r"    # Le dé holographique 3D.*?(?=    # Le moteur 2D du repli)", "", texte, flags=re.S).replace(" font-src 'self';", "")


def test_mise_a_jour_le_vhost_en_place_gagne_les_emplacements(box):
    assert box.appliquer() == 0
    nouveau = conf(box)
    vieux = _ancien(nouveau)
    assert "de3d" not in vieux and "font-src" not in vieux and vieux != nouveau
    Path(box.CONF).write_text(vieux)
    avant_route = table(box)
    box.appels.clear()
    assert box.appliquer() == 0                                  # ce que lance le postinst à chaque configuration
    assert conf(box) == nouveau and table(box) == avant_route
    assert box.appels == [["nginx", "-t"], ["systemctl", "reload", "nginx"]]   # ni route, ni HAProxy
    assert audits(box)[-1]["action"] == "vhost" and audits(box)[-1]["result"] == "regenere"
    # nginx refuse : l'ancien fichier revient, rien n'est rechargé
    Path(box.CONF).write_text(vieux)
    box.nginx_ok = False
    box.appels.clear()
    assert box.appliquer() == 1 and conf(box) == vieux
    assert ["systemctl", "reload", "nginx"] not in box.appels


def test_mise_a_jour_n_expose_jamais_une_box_non_exposee(box, monkeypatch):
    monkeypatch.setattr(box, "mot_de_passe_change", lambda: False)
    assert box.appliquer() == 0
    Path(box.CONF).write_text(_ancien(conf(box)))
    box.appels.clear()
    assert box.appliquer() == 0 and "location = /_noeud/de3d.js {" in conf(box)
    assert DOM not in table(box) and not any(a[0] in ("secubox-waf-route", "haproxyctl") for a in box.appels)
    # sans WAF, et accueil coupé : rien n'est exposé non plus
    Path(box.ROUTES).unlink()
    monkeypatch.setattr(box, "mot_de_passe_change", lambda: True)
    Path(box.CONF).write_text(_ancien(conf(box)))
    box.appels.clear()
    assert box.appliquer() == 0 and not any(a[0] in ("secubox-waf-route", "haproxyctl") for a in box.appels)
    Path(box.REGLAGES).write_text("[noeud]\naccueil = false\n")
    assert box.appliquer() == 0 and conf(box) is None


# ── La page rendue ───────────────────────────────────────────────────────────────────────────────────────────

playwright = pytest.importorskip("playwright.sync_api")
Image = pytest.importorskip("PIL.Image")

SANS_GL = ("HTMLCanvasElement.prototype.getContext=(o=>function(t,...a){return t==='webgl2'?null:o.call(this,t,...a)})"
           "(HTMLCanvasElement.prototype.getContext);")
FIGE = "try{localStorage.setItem('sbx_de','fige')}catch(e){}"


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch(args=["--use-gl=angle", "--use-angle=swiftshader", "--enable-unsafe-swiftshader"])
        yield b
        b.close()


def fichiers():
    f = {"/": (PAGE, "text/html"), "/_noeud/de3d.js": (DE3D, "application/javascript"),
         "/_noeud/sbx-dice.js": (HALL / "sbx-dice.js", "application/javascript")}
    for p in ("unbounded", "jetbrains-mono"):
        f[f"/_noeud/polices/{p}-latin.woff2"] = (POLICES / f"{p}-latin.woff2", "font/woff2")
    for i in range(6):
        f[f"/_noeud/dice/face-{i}.jpg"] = (HALL / f"dice/face-{i}.jpg", "image/jpeg")
    return f


class Ouverte:
    def __init__(self, nav, largeur=700, hauteur=700, init="", absents=(), hote=DOM, pret=True, **ctx):
        csp = re.search(r'Content-Security-Policy "([^"]+)"', charger().rendre(DOM, None, False)).group(1)
        self.ctx = nav.new_context(viewport={"width": largeur, "height": hauteur}, **ctx)
        self.p = self.ctx.new_page()
        self.erreurs, self.demandes = [], []
        connus = fichiers()

        def servir(route):
            chemin = route.request.url.split(hote, 1)[1].split("?")[0] if hote in route.request.url else route.request.url
            self.demandes.append(chemin)
            if chemin not in connus or chemin in absents:
                return route.fulfill(status=404, body="")
            f, t = connus[chemin]
            route.fulfill(status=200, body=f.read_bytes(), headers={"Content-Type": t, "Content-Security-Policy": csp})
        self.p.on("pageerror", lambda e: self.erreurs.append(str(e)))
        self.p.on("console", lambda m: "Content Security Policy" in m.text and self.erreurs.append(m.text))
        if init:
            self.p.add_init_script(init)
        self.p.route("**/*", servir)
        self.p.goto(f"http://{hote}/")
        if pret:
            attend(self.p, "!!document.querySelector('#de3d.pret,#scene.repli')", 60)
            raison = self.p.get_attribute("#scene", "data-repli")
            if raison in ("rendu trop lent", "WebGL 2 absent"):     # machine d'essai sans GL ou débordée, pas un défaut de la page
                self.ctx.close()
                pytest.skip(f"GL logiciel : {raison}")
            assert raison is None, raison

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.ctx.close()

    def image(self, **kw):
        return Image.open(io.BytesIO(self.p.screenshot(timeout=90000, **kw))).convert("RGB")

    def repli(self):
        self.p.wait_for_selector("#scene.repli sbx-dice canvas", timeout=60000)
        assert self.p.is_hidden("#de3d")
        assert self.p.evaluate("customElements.get('sbx-dice')!==undefined && document.querySelectorAll('sbx-dice').length") == 1
        assert self.p.get_attribute("sbx-dice", "role") == "img"
        return self.p.get_attribute("#scene", "data-repli")


def attend(p, condition, secondes):
    # pas wait_for_function : il évalue du texte dans la page, que la CSP du vhost refuse (pas d'unsafe-eval)
    for _ in range(int(secondes * 10)):
        if p.evaluate(condition):
            return
        p.wait_for_timeout(100)
    raise AssertionError(f"jamais vrai : {condition}")


def pixels(im):
    b = im.tobytes()
    return [tuple(b[i:i + 3]) for i in range(0, len(b), 3)]


def cadre(p):
    return p.evaluate("""(()=>{const c=document.getElementById('de3d').getBoundingClientRect(),
      m=document.getElementById('rond').getScreenCTM(), d=document.documentElement;
      return {x:c.left+c.width/2, y:c.top+c.height/2, w:c.width, h:c.height, cx:600*m.a+m.e, cy:400*m.d+m.f, d:700*m.a,
              sw:d.scrollWidth, sh:d.scrollHeight, etroit:d.classList.contains('etroit')}})()""")


@pytest.mark.parametrize("lg,h", [(1280, 900), (800, 360), (568, 320), (1024, 768), (768, 1024), (700, 700), (2560, 1080),
                                 (2560, 1440), (1920, 1080), (320, 320)])
def test_le_canvas_remplit_exactement_le_cercle_de_la_mire(nav, lg, h):
    with Ouverte(nav, lg, h, init=FIGE, pret=False) as o:
        c = cadre(o.p)
        assert not c["etroit"]
        assert abs(c["w"] - c["d"]) < 1 and abs(c["h"] - c["d"]) < 1
        assert abs(c["x"] - c["cx"]) < 1 and abs(c["y"] - c["cy"]) < 1
        assert c["sw"] <= lg and c["sh"] <= h
        o.p.set_viewport_size({"width": 900, "height": 600})      # suit un redimensionnement
        attend(o.p, "innerWidth===900&&Math.abs(document.getElementById('scene').offsetWidth-525)<2", 5)
        c = cadre(o.p)
        assert abs(c["w"] - c["d"]) < 1 and abs(c["y"] - c["cy"]) < 1


@pytest.mark.parametrize("lg,h", [(320, 568), (400, 850), (360, 640), (412, 915), (600, 960)])
def test_ecran_etroit_le_de_est_agrandi(nav, lg, h):
    with Ouverte(nav, lg, h, init=FIGE, pret=False) as o:
        c = cadre(o.p)
        assert c["etroit"] and c["w"] > c["d"] * 1.3 and c["w"] <= lg and c["sw"] <= lg and c["sh"] <= h
        assert o.p.evaluate("getComputedStyle(document.querySelector('.rond')).display") == "none"
        r = o.p.evaluate("""['.nom','.marque'].map(s=>{const r=document.querySelector(s).getBoundingClientRect();return [r.top,r.bottom,r.left,r.right]})""")
        assert r[0][0] >= c["y"] + c["w"] / 2 - 1 and r[0][1] <= r[1][0] and r[0][2] >= 0 and r[0][3] <= lg and r[1][1] <= h


def _lum(rgb):
    v = [x / 255 / 12.92 if x / 255 <= .03928 else ((x / 255 + .055) / 1.055) ** 2.4 for x in rgb]
    return .2126 * v[0] + .7152 * v[1] + .0722 * v[2]


@pytest.mark.parametrize("lg,h", [(1280, 900), (400, 850), (800, 360), (320, 568), (568, 320), (2560, 1440), (768, 1024)])
def test_textes_lisibles_contraste_et_place(nav, lg, h):
    """Contraste mesuré sur le rendu : le fond le plus CLAIR sous le texte contre la teinte la plus SOMBRE du texte."""
    with Ouverte(nav, lg, h, init=FIGE) as o:
        o.p.wait_for_timeout(1200)
        rects = o.p.evaluate("""['h1','.zone','.marque'].map(s=>{const g=document.createRange();g.selectNodeContents(document.querySelector(s));
          const r=g.getBoundingClientRect();return [r.left,r.top,r.right,r.bottom]})""")
        o.p.evaluate("""(()=>{document.querySelector('h1').style.visibility='hidden';
          document.querySelectorAll('.zone,.marque,.marque b').forEach(e=>e.style.color='transparent')})()""")
        im = o.image()
        # teinte la plus sombre : dégradé du titre (#b9a3ff, #ff9be0), pastille, signature
        for r, sombre in zip(rects, ((0xb9, 0xa3, 0xff), (0xd9, 0xec, 0xff), (0x9f, 0xb3, 0xd6))):
            assert r[0] >= 0 and r[2] <= lg + .5 and r[1] >= 0 and r[3] <= h + .5, r
            zone = im.crop([int(x) for x in r])
            lums = sorted(_lum(px) for px in pixels(zone))
            fond = lums[int(len(lums) * .995) - 1]                # hors quelques pixels de liseré
            assert (_lum(sombre) + .05) / (fond + .05) >= 4.5, (r, fond)
        assert rects[1][3] <= rects[2][1] + 1                     # l'adresse au-dessus de la signature
        sortie = os.environ.get("SBX_NOEUD_CAPTURES")
        if sortie:
            im.save(f"{sortie}/fond-{lg}x{h}.png")


@pytest.mark.parametrize("lg,h", [(320, 568), (320, 320), (800, 360), (1280, 900)])
def test_nom_de_quarante_caracteres(nav, lg, h):
    nom = "a-noeud-au-nom-vraiment-tres-long-wmwm40"
    assert len(nom) == 40
    with Ouverte(nav, lg, h, init=FIGE, hote=f"{nom}.secubox.in", pret=False) as o:
        o.p.evaluate("document.fonts.ready")
        assert o.p.inner_text("h1") == nom
        r = o.p.evaluate("""(()=>{const b=[];for(const s of ['h1','.zone']){const e=document.querySelector(s),r=e.getBoundingClientRect();
          b.push([r.left,r.top,r.right,r.bottom,e.scrollWidth-e.clientWidth])}b.push([document.documentElement.scrollWidth,document.documentElement.scrollHeight]);return b})()""")
        for x in r[:2]:
            assert x[0] >= 0 and x[2] <= lg and x[1] >= 0 and x[3] <= h and x[4] <= 0, r
        assert r[2][0] <= lg and r[2][1] <= h


def test_le_de_3d_tourne_sans_fin_et_sans_erreur(nav):
    with Ouverte(nav, 500, 500) as o:
        o.p.wait_for_timeout(700)
        assert o.p.get_attribute("#de3d", "role") == "img" and o.p.get_attribute("#de3d", "aria-label")
        assert o.p.evaluate("document.querySelector('sbx-dice')===null") and "/_noeud/sbx-dice.js" not in o.demandes
        c = cadre(o.p)
        im = o.image(clip={"x": c["x"] - c["w"] * .3, "y": c["y"] - c["w"] * .3, "width": c["w"] * .6, "height": c["w"] * .6})
        assert len(set(pixels(im))) > 2000                       # canvas non vide : échiquier, dé, reflets
        # ni le rebond (toutes les 9 s) ni des semaines d'animation n'arrêtent ou n'emballent la rotation
        for saut in (5300, 600, 400, 300, 3_000_000_000):
            o.p.evaluate("ms=>sbxDe3d.avance(ms)", saut)
            a = o.p.evaluate("sbxDe3d.etat()")
            o.p.wait_for_timeout(450)
            b = o.p.evaluate("sbxDe3d.etat()")
            assert b["marche"] and all(0 <= x < 2 * math.pi for x in b["angles"]) and 0 <= b["T"] < 100 and 0 <= b["rebond"] < 9
            for i, v in enumerate((.93, 1.41, .57)):
                d = (b["angles"][i] - a["angles"][i]) % (2 * math.pi)
                assert 0.02 < d < v * 3, (saut, i, d)
        assert o.erreurs == [] and all(x.startswith("/") for x in o.demandes)
        # onglet caché : pause
        o.p.evaluate("Object.defineProperty(document,'hidden',{get:()=>true,configurable:true});document.dispatchEvent(new Event('visibilitychange'))")
        assert o.p.evaluate("sbxDe3d.etat().marche") is False
        o.p.evaluate("delete document.hidden;document.dispatchEvent(new Event('visibilitychange'))")
        assert o.p.evaluate("sbxDe3d.etat().marche") is True


def test_mouvement_reduit_lent_et_fige(nav):
    with Ouverte(nav, 400, 400, reduced_motion="reduce") as o:
        a, t = o.p.evaluate("[sbxDe3d.etat(),performance.now()]")
        o.p.mouse.move(10, 10)
        o.p.wait_for_timeout(900)
        b, t2 = o.p.evaluate("[sbxDe3d.etat(),performance.now()]")
        d = (b["angles"][1] - a["angles"][1]) % (2 * math.pi)
        assert 0 < d <= .00047 * .75 * (t2 - t + 120) and b["T"] == a["T"] and b["rebond"] == a["rebond"]
        assert o.p.evaluate("getComputedStyle(document.querySelector('h1')).animationName") == "none"
    with Ouverte(nav, 400, 400, init=FIGE) as o:
        o.p.wait_for_timeout(300)
        e = o.p.evaluate("sbxDe3d.etat()")
        assert e["angles"] == [0, 0, 0] and e["marche"] is False


# ── Motifs lisibles ──────────────────────────────────────────────────────────────────────────────────────────

FACES3D = {0: ((0, 0, -1), (-1, 0, 0), (0, -1, 0)), 5: ((0, 0, 1), (1, 0, 0), (0, -1, 0)),
           1: ((0, 1, 0), (1, 0, 0), (0, 0, 1)), 3: ((0, -1, 0), (-1, 0, 0), (0, 0, 1)),
           2: ((1, 0, 0), (0, 0, -1), (0, 1, 0)), 4: ((-1, 0, 0), (0, 0, -1), (0, 1, 0))}


def _rot(ax, ay, az):
    cx, sx, cy, sy, cz, sz = math.cos(ax), math.sin(ax), math.cos(ay), math.sin(ay), math.cos(az), math.sin(az)
    return [[cz * cy, cz * sy * sx - sz * cx, cz * sy * cx + sz * sx], [sz * cy, sz * sy * sx + cz * cx, sz * sy * cx - cz * sx],
            [-sy, cy * sx, cy * cx]]


def _sc(a, b):
    return sum(x * y for x, y in zip(a, b))


def _unit(a):
    n = math.sqrt(_sc(a, a))
    return [x / n for x in a]


def _vect(a, b):
    return [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]]


def test_motifs_lisibles_a_douze_poses_aucune_face_blanche(nav):
    """Pour chaque face vue d'assez près de face : le motif (pixels colorés de l'image source) se distingue de son fond, et la
    face n'est pas lavée de blanc. Géométrie : même caméra que le shader."""
    alea = random.Random(3938)
    textures = {k: Image.open(HALL / f"dice/face-{k}.jpg").convert("RGB") for k in range(6)}
    oeil, vise = [0, 4.25, -6.6], [0, .78, .15]
    f = _unit([vise[i] - oeil[i] for i in range(3)])
    x = _unit(_vect([0, 1, 0], f))
    y = _vect(f, x)
    vues = 0
    with Ouverte(nav, 700, 700) as o:
        o.p.evaluate("document.querySelector('.nom').style.display='none'")
        c = cadre(o.p)
        for n in range(14):
            pose = [(0, -math.pi / 2, 0), (0, math.pi / 2, 0)][n] if n < 2 else [alea.uniform(0, 2 * math.pi) for _ in range(3)]
            o.p.evaluate("a=>sbxDe3d.pose(...a)", list(pose))
            o.p.wait_for_timeout(700)
            im = o.image()
            m = _rot(*pose)
            centre = [0, sum(abs(v) for v in m[1]) * .63 + .17 + .62, 0]
            for k, (nn, tu, tv) in FACES3D.items():
                def monde(v):
                    return [_sc(ligne, (v[0], -v[1], v[2])) for ligne in m]
                nw = monde(nn)
                pc = [centre[i] + .8 * nw[i] for i in range(3)]
                if -_sc(nw, _unit([pc[i] - oeil[i] for i in range(3)])) < .45:
                    continue
                vues += 1
                motif, fond, blancs, total = [], [], 0, 0
                for i in range(40):
                    for j in range(40):
                        u, v = -.72 + 1.44 * i / 39, -.72 + 1.44 * j / 39
                        pt = [.8 * (nn[a] + u * tu[a] + v * tv[a]) for a in range(3)]
                        pw = monde(pt)
                        d = [centre[a] + pw[a] - oeil[a] for a in range(3)]
                        z = _sc(d, f)
                        px = c["x"] + 2.35 * _sc(d, x) / z * c["w"] / 2
                        py = c["y"] - 2.35 * _sc(d, y) / z * c["w"] / 2
                        rgb = im.getpixel((int(px), int(py)))
                        total += 1
                        blancs += min(rgb) > 215
                        # profondeur du motif (parallaxe) : même décalage que le shader
                        vw = [_sc(_unit(d), [m[0][a], m[1][a], m[2][a]]) for a in range(3)]
                        vw = [vw[0], -vw[1], vw[2]]
                        g = max(.28, -_sc(vw, nn))
                        uu, vv = u + .11 * _sc(vw, tu) / g, v + .11 * _sc(vw, tv) / g
                        t = textures[k].getpixel((max(0, min(319, int((uu + 1) * 160))), max(0, min(319, int((vv + 1) * 160)))))
                        (motif if max(t) - min(t) > 40 else fond).append(rgb)
                assert blancs / total < .08, (n, k, blancs / total)
                assert len(motif) > 30 and len(fond) > 30
                if os.environ.get("SBX_NOEUD_CAPTURES"):
                    print(n, k, round(math.dist(*[[sum(p[a] for p in lot) / len(lot) for a in range(3)] for lot in (motif, fond)])), round(blancs / total, 3))
                moy = [[sum(p[a] for p in lot) / len(lot) for a in range(3)] for lot in (motif, fond)]
                assert math.dist(*moy) > 18, (n, k, moy)
    assert vues >= 14


# ── Replis ───────────────────────────────────────────────────────────────────────────────────────────────────

SHADER_KO = ("const s=WebGL2RenderingContext.prototype.shaderSource;WebGL2RenderingContext.prototype.shaderSource="
             "function(h,x){return s.call(this,h,x.includes('main')&&x.includes('irise')?x+'erreur':x)};")
LENT = ("let z=performance.now.bind(performance),n=0;const f=WebGL2RenderingContext.prototype.getSyncParameter,t=new WeakMap();"
        "WebGL2RenderingContext.prototype.getSyncParameter=function(s,p){if(!t.has(s))t.set(s,z());"
        "return z()-t.get(s)<200?this.UNSIGNALED:f.call(this,s,p)};")


@pytest.mark.parametrize("init,absents,raison", [
    (SANS_GL, (), "WebGL 2"), (SHADER_KO, (), "shader"), ("", ("/_noeud/dice/face-3.jpg",), "image"),
    ("", ("/_noeud/de3d.js",), "moteur"), (LENT, (), "lent")])
def test_repli_sur_le_de_du_hall(nav, init, absents, raison):
    with Ouverte(nav, 900, 600, init=init, absents=absents, pret=False) as o:
        assert raison in o.repli()
        assert o.erreurs == []
        assert o.p.inner_text("h1") == "gk2" and o.p.evaluate("document.documentElement.scrollHeight") <= 600
        assert not o.p.evaluate("document.documentElement.classList.contains('vif')")
        a = o.p.evaluate("document.querySelector('sbx-dice')._ay")
        o.p.wait_for_timeout(400)
        assert absents == ("/_noeud/dice/face-3.jpg",) or o.p.evaluate("document.querySelector('sbx-dice')._ay") > a


def test_contexte_perdu_rendu_puis_perdu_pour_de_bon(nav):
    with Ouverte(nav, 500, 500) as o:
        o.p.evaluate("window.x=document.getElementById('de3d').getContext('webgl2').getExtension('WEBGL_lose_context');x.loseContext()")
        attend(o.p, "sbxDe3d.etat().marche===false", 5)
        o.p.wait_for_timeout(300)
        o.p.evaluate("x.restoreContext()")
        attend(o.p, "sbxDe3d.etat().marche===true", 30)
        o.p.wait_for_timeout(800)
        assert o.p.evaluate("document.querySelector('sbx-dice')") is None
        c = cadre(o.p)
        im = o.image(clip={"x": c["x"] - 80, "y": c["y"] - 80, "width": 160, "height": 160})
        assert len(set(pixels(im))) > 500                        # textures reconstruites
        o.p.evaluate("x.loseContext()")
        assert "contexte perdu" in o.repli()
        assert o.erreurs == []


def test_resolution_adaptative_descend_puis_remonte_sans_osciller(nav):
    """La boucle jouée sur une horloge fausse : lente à pleine résolution, fluide un cran dessous. Elle descend, remonte après une
    longue période fluide, puis de plus en plus rarement."""
    horloge = ("""
window.__f=null; window.__t=0; window.requestAnimationFrame=f=>{window.__f=f;return 1}; window.cancelAnimationFrame=()=>{window.__f=null};
window.__joue=(n,lent)=>{const s=[];for(let i=0;i<n;i++){const f=window.__f;if(!f)break;
  window.__t+=lent(sbxDe3d.echelle())?50:16.67;f(window.__t);const e=sbxDe3d.echelle();if(!s.length||s[s.length-1][1]!==e)s.push([Math.round(window.__t/1000),e]);}return s};
WebGL2RenderingContext.prototype.drawArrays=function(){};
""")
    with Ouverte(nav, 300, 300, init=horloge, pret=False) as o:
        attend(o.p, "!!window.sbxDe3d&&sbxDe3d.etat().marche", 60)
        suite = o.p.evaluate("__joue(60000,e=>e>.9)")               # 1000 s environ
        niveaux = [e for _, e in suite]
        assert min(niveaux) >= .82 and niveaux[-1] in (1, .82)
        montees = [t for t, e in suite if e == 1][1:] if niveaux[0] == 1 else [t for t, e in suite if e == 1]
        assert 1 <= len(montees) <= 8, suite                       # quelques essais, espacés
        ecarts = [b - a for a, b in zip(montees, montees[1:])]
        assert all(b >= a * 1.3 for a, b in zip(ecarts, ecarts[1:])), suite
        assert o.p.evaluate("__joue(4000,e=>true)")[-1][1] >= .45 and o.p.evaluate("sbxDe3d.etat().fini") is False
        o.p.evaluate("__joue(20000,e=>false)")
        # tout redevient fluide : la résolution finit par remonter
        assert o.p.evaluate("__joue(150000,e=>false)")[-1][1] >= .67


def test_paquet_et_readme():
    rules = (PKG / "debian/rules").read_text()
    assert "www/noeud/de3d.js debian/secubox-core/usr/share/secubox/www/noeud/de3d.js" in rules
    assert "de3d.js" in (PKG / "README.md").read_text()
