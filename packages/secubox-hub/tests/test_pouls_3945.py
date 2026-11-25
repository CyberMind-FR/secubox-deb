# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Composant partagé « pouls » (#3945) : fichier sûr et borné, copie identique pour la page publique, fonctions pures (node),
comportement au navigateur sous CSP stricte (sauté sans Playwright) : date écrite, une mesure à la fois, survol, mise à jour
sans relance, hors écran, mouvement réduit, bouton retenu, données absentes ou hostiles."""
import http.server
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent.parent
SRC = ICI / "www/shared/pouls.js"
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'"


def test_fichier_sur_et_borne():
    js = SRC.read_text(encoding="utf-8")
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in js[:120]
    assert len(js.encode()) < 17_500
    for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "cssText", "new Function", "fetch(", "XMLHttp",
                     "aria-live", "setInterval", "createElement('style')", "adoptedStyleSheets"):
        assert interdit not in js, interdit
    assert not re.search(r"setAttribute\(\s*'style'", js) and "{style:" not in js
    assert "http" not in js.replace("http://www.w3.org/2000/svg", "")
    # Écouteurs posés une fois pour toutes (page), jamais par mesure : rien à fuir quand la page refait ses éléments.
    assert js.count("addEventListener('") == 4


def test_copie_de_la_page_publique_identique():
    assert (ICI.parent / "secubox-live/www/live/pouls.js").read_bytes() == SRC.read_bytes()


def test_fonctions_pures():
    node = shutil.which("node")
    if not node:
        pytest.skip("node absent")
    r = subprocess.run([node, "--test", str(Path(__file__).with_name("pouls_3945.test.mjs"))], capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-1000:]


# ------------------------------------------------------------------------------------------------ navigateur

PAGE = """<!doctype html><html lang="fr"><head><meta charset="utf-8"><script src="/compte.js"></script><script src="/pouls.js"></script></head><body>
<div id="outils"></div>
<section id="za"><h3 id="qa"></h3><svg id="a" viewBox="0 0 120 60" width="480" height="240"></svg><b id="nfr"></b></section>
<section id="zb"><span id="qb"></span><b id="b">4 514</b><svg id="sb" viewBox="0 0 200 44" width="200" height="44"></svg></section>
<section id="zc"><span id="qc"></span><svg id="c" viewBox="0 0 520 190" width="520" height="190"></svg></section>
<script src="/essai.js"></script></body></html>"""
COMPTE = """if(!sessionStorage.getItem('sbx-pouls-auto')&&!/auto/.test(location.search))sessionStorage.setItem('sbx-pouls-auto','non');window.RAF=0;const _r=window.requestAnimationFrame.bind(window);window.requestAnimationFrame=f=>{window.RAF++;return _r(f)};
window.MUT=0;document.addEventListener('DOMContentLoaded',()=>{new MutationObserver(l=>{window.MUT+=l.length}).observe(document.body,{subtree:true,childList:true,attributes:true,characterData:true})});"""
ESSAI = """const $=i=>document.getElementById(i),T=1764000000,C={FR:[46,2],US:[38,-97],CN:[35,103]};
window.I=n=>Array.from({length:n},(_,i)=>({t:T-600*(n-1-i),pays:[{code:'FR',n:100+10*i},{code:'US',n:50},{code:'CN',n:7+i}]}));
window.carte=o=>SbxPouls.carte($('a'),Object.assign({cle:'m',instantanes:I(13),centres:C,liste:{FR:$('nfr')},quand:$('qa'),zone:$('za')},o));
window.compteur=o=>SbxPouls.compteur($('b'),Object.assign({cle:'k',valeurs:[10,20,30,40],libelles:['le 1','le 2','le 3','le 4'],svg:$('sb'),quand:$('qb'),zone:$('zb')},o));
window.barres=o=>SbxPouls.barres($('c'),Object.assign({cle:'h',valeurs:[1,null,3,4],libelles:i=>'n'+i,quand:$('qc'),zone:$('zc')},o));
window.dates=()=>['qa','qb','qc'].map(i=>$(i).textContent);"""


@pytest.fixture(scope="module")
def serveur():
    corps = {"/": (PAGE, "text/html"), "/compte.js": (COMPTE, "text/javascript"), "/essai.js": (ESSAI, "text/javascript"),
             "/pouls.js": (SRC.read_text(encoding="utf-8"), "text/javascript")}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            c = corps.get(self.path.split("?")[0])
            self.send_response(200 if c else 404)
            self.send_header("Content-Security-Policy", CSP)
            if c:
                self.send_header("Content-Type", c[1] + "; charset=utf-8")
            self.end_headers()
            if c:
                self.wfile.write(c[0].encode())

        def log_message(self, *a):
            pass
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_address[1]}/"
    s.shutdown()


@pytest.fixture(scope="module")
def navigateur():
    api = pytest.importorskip("playwright.sync_api")
    with api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as e:  # noqa: BLE001 — navigateur absent de la machine
            pytest.skip(f"chromium absent : {e}")
        yield b
        b.close()


@pytest.fixture
def page(navigateur, serveur):
    ouverts = []

    def _p(**ctx):
        c = navigateur.new_context(viewport={"width": 900, "height": 900}, locale="fr-FR", **ctx)
        pg = c.new_page()
        pg.erreurs = []
        pg.on("console", lambda m: pg.erreurs.append(m.text) if m.type in ("error", "warning") and "favicon" not in str(m.location) else None)
        pg.on("pageerror", lambda e: pg.erreurs.append(str(e)))
        pg.goto(serveur)
        ouverts.append((c, pg))
        return pg
    yield _p
    for c, pg in ouverts:
        assert pg.erreurs == []
        c.close()


def attendre(pg, expr, timeout=20000):
    """Sans wait_for_function : il évalue du texte dans la page, ce que la CSP refuse."""
    fin = time.monotonic() + timeout / 1000
    while not pg.evaluate(expr):
        assert time.monotonic() < fin, (expr, pg.evaluate("dates()"))
        pg.wait_for_timeout(15)


def recul(pg, i=0):
    attendre(pg, f"/^◀ (il y a|le|n)/.test(dates()[{i}])")


def test_nav_recul_date_et_retour(page):
    pg = page()
    pg.evaluate("carte()")
    assert pg.evaluate("dates()[0]") == "● maintenant" and pg.locator("#qa [data-sbxp=quand]").get_attribute("aria-hidden") == "true"
    assert pg.locator("#za svg[data-sbxp=carte]").get_attribute("aria-hidden") == "true"
    attendre(pg, "dates()[0] === '◀ il y a 2 h 00'", timeout=15000)
    assert float(pg.locator("#nfr").inner_text()) < 115                         # 100 au plus ancien, 110 au suivant
    attendre(pg, "dates()[0] === '● maintenant'", timeout=15000)
    assert pg.locator("#nfr").inner_text() == "220"


def test_nav_une_seule_mesure_a_la_fois_et_rythme_borne(page):
    pg = page()
    r = pg.evaluate("""async()=>{carte();compteur();barres();const vus=new Set();let max=0,r0=RAF,t0=performance.now();
      while(performance.now()-t0<22000){const p=dates().map((x,i)=>x.startsWith('◀')?i:-1).filter(i=>i>=0);max=Math.max(max,p.length);p.forEach(i=>vus.add(i));await new Promise(f=>setTimeout(f,40))}
      return{max,vus:[...vus].sort(),ips:(RAF-r0)/22}}""")
    assert r["max"] == 1 and r["vus"] == [0, 1, 2] and r["ips"] <= 16


def test_nav_survol_fige_sur_une_mesure_reelle(page):
    pg = page()
    pg.evaluate("carte()")
    recul(pg)
    pg.hover("#nfr")
    pg.hover("#qa")
    pg.wait_for_timeout(200)
    a = pg.evaluate("[dates()[0], $('nfr').textContent]")
    pg.wait_for_timeout(900)
    assert a == pg.evaluate("[dates()[0], $('nfr').textContent]")
    n = int(a[1])
    assert n % 10 == 0 and 100 <= n <= 220                                      # un relevé réel, jamais une valeur intermédiaire
    if a[0] != "● maintenant":
        assert pg.evaluate("[...document.querySelectorAll('#za title')].map(x=>x.textContent)")[0].startswith("FR : %d · " % n)
    pg.mouse.move(890, 890)
    attendre(pg, "dates()[0] === '● maintenant'", timeout=15000)
    assert pg.locator("#za title").count() == 0


def test_nav_focus_clavier_ramene_au_present(page):
    pg = page()
    pg.evaluate("$('za').appendChild(Object.assign(document.createElement('button'),{id:'bt',textContent:'x'}));carte()")
    recul(pg)
    pg.keyboard.press("Tab")
    pg.wait_for_timeout(300)
    assert pg.evaluate("document.activeElement.id") == "bt" and pg.evaluate("dates()[0]") == "● maintenant"


def test_nav_mise_a_jour_sans_relance(page):
    pg = page()
    pg.evaluate("compteur()")
    attendre(pg, "/^◀ le [12]/.test(dates()[1])")
    r = pg.evaluate("""()=>{const av=dates()[1];
      // la page refait tout son bloc, comme à chaque relevé : même clé, la position demeure
      $('zb').textContent='';[['span','qb'],['b','b']].forEach(([t,i])=>{const e=document.createElement(t);e.id=i;$('zb').appendChild(e)});
      const s=document.createElementNS('http://www.w3.org/2000/svg','svg');s.id='sb';s.setAttribute('viewBox','0 0 200 44');$('zb').appendChild(s);
      $('b').textContent='50';compteur({valeurs:[20,30,40,50]});return[av,dates()[1],$('b').textContent,$('zb').querySelectorAll('[data-sbxp=barres]').length]}""")
    assert r[1].startswith("◀") and r[2] != "50" and r[3] == 1
    attendre(pg, "dates()[1] === '● maintenant'", timeout=15000)
    assert pg.evaluate("$('b').textContent") == "50" and pg.evaluate("$('b').hasAttribute('role')") is False
    # cent mises à jour : un seul groupe, une seule date, une seule boucle
    r = pg.evaluate("""async()=>{const m=carte();for(let i=0;i<100;i++){carte();compteur();m.maj({})}const r0=RAF;await new Promise(f=>setTimeout(f,2000));
      return[(RAF-r0)/2,document.querySelectorAll('#za svg[data-sbxp=carte]').length,document.querySelectorAll('#qa > span').length,document.querySelectorAll('#b > i').length]}""")
    assert r[0] <= 16 and r[1:] == [1, 1, 1]


@pytest.mark.parametrize("n", [0, 1])
def test_nav_sans_historique_rien_ne_bouge(page, n):
    pg = page()
    r = pg.evaluate("async n=>{carte({instantanes:I(n)});compteur({valeurs:n?[7]:[]});barres({valeurs:[null,n||null,null]});await new Promise(f=>setTimeout(f,200));const a=[MUT,RAF];await new Promise(f=>setTimeout(f,3500));return[MUT-a[0],RAF-a[1],dates(),$('b').textContent]}", n)
    assert r == [0, 0, ["", "", ""], "4 514"]


def test_nav_mouvement_reduit_halos_fixes(page):
    pg = page(reduced_motion="reduce")
    r = pg.evaluate("async()=>{carte();compteur();barres();await new Promise(f=>setTimeout(f,200));const a=[MUT,RAF];await new Promise(f=>setTimeout(f,3500));return[MUT-a[0],RAF-a[1],dates(),Number($('za').querySelector('circle').getAttribute('r'))>0]}")
    assert r == [0, 0, ["● maintenant"] * 3, True]


def test_nav_hors_ecran_et_masque_rien_ne_tourne(page):
    pg = page()
    r = pg.evaluate("async()=>{$('za').style.marginTop='3000px';carte();compteur();await new Promise(f=>setTimeout(f,400));const a=[MUT,RAF];await new Promise(f=>setTimeout(f,2500));return[MUT-a[0],RAF-a[1]]}")
    assert r == [0, 0]
    pg.evaluate("$('za').style.marginTop='0'")
    recul(pg)
    pg.evaluate("$('za').style.marginTop='3000px'")
    attendre(pg, "dates()[0] === '● maintenant'", timeout=1500)           # sorti de l'écran : présent, tout de suite


def test_nav_bouton_retenu(page, serveur):
    pg = page()
    pg.evaluate("SbxPouls.bouton($('outils'));SbxPouls.bouton($('outils'));carte()")
    b = pg.locator("#outils button")
    assert b.count() == 1 and b.inner_text() == "💓 vivant" and b.bounding_box()["height"] >= 40
    recul(pg)
    b.click()
    assert b.inner_text() == "⏸ fixe" and b.get_attribute("aria-pressed") == "false" and pg.evaluate("dates()[0]") == "● maintenant"
    pg.goto(serveur)
    r = pg.evaluate("async()=>{SbxPouls.bouton($('outils'));carte();await new Promise(f=>setTimeout(f,300));const a=[MUT,RAF];await new Promise(f=>setTimeout(f,2500));return[MUT-a[0],RAF-a[1]]}")
    assert r == [0, 0] and b.inner_text() == "⏸ fixe"
    b.click()
    recul(pg)


def test_nav_donnees_nulles_et_hostiles(page):
    pg = page()
    hostile = [{"t": 1764000000, "pays": [{"code": "<img src=x onerror=alert(1)>", "n": 1}, {"code": "FR", "n": 1e308}, {"code": "US", "n": -4}, {"code": "constructor", "n": 3}]},
               {"t": 1764000600, "pays": None}, {"t": 1764001200, "pays": [{"code": "FR", "n": 5}, {"code": "ZZ", "n": 5}]}, "x", None, {"t": "demain"}]
    pg.evaluate("h=>{carte({instantanes:h});compteur({valeurs:[null,NaN,'9',1e300,3,null],libelles:['<b>x</b>'],total:true});barres({valeurs:[null,null,2,null,0],libelles:null});SbxPouls.carte($('a'),null);SbxPouls.memoire('x',{t:'y'})}", hostile)
    pg.evaluate("h=>carte({instantanes:h})", hostile)
    attendre(pg, "dates()[0].includes('non mesuré')", timeout=25000)      # le relevé absent se dit, il ne s'invente pas
    assert pg.evaluate("document.querySelectorAll('img').length") == 0
    assert not re.search(r"NaN|undefined|Infinity", pg.content())


def test_nav_null_jamais_rendu_zero_par_le_format_de_la_page(page):
    pg = page()
    pg.evaluate("""()=>{const z=v=>String(Math.round(Number(v)||0));const l=I(6).map((s,i)=>i<3?{t:s.t,pays:[{code:'US',n:5}]}:s);window.vus=new Set();
      new MutationObserver(()=>vus.add($('nfr').textContent+'|'+$('b').textContent)).observe(document.body,{subtree:true,childList:true,characterData:true});
      carte({instantanes:l,format:z});compteur({valeurs:[null,null,30,40],format:z})}""")
    attendre(pg, "[...vus].some(x=>x.startsWith('—'))")
    attendre(pg, "[...vus].some(x=>x.endsWith('|—'))")
    assert not pg.evaluate("[...vus].some(x=>x.split('|').includes('0'))")


def test_nav_memoire_d_onglet_bornee(page):
    pg = page()
    r = pg.evaluate("""()=>{let l;for(let i=0;i<500;i++)l=SbxPouls.memoire('e',{t:1764000000+15*i,pays:[{code:'FR',n:i}]});
      const d=l.map((s,i)=>i?s.t-l[i-1].t:0).slice(1,-1);sessionStorage.setItem('sbx-pouls:f','{pas du json');
      return{n:l.length,min:Math.min(...d),der:l[l.length-1].pays,age:l[l.length-1].t-l[0].t,garde:JSON.parse(sessionStorage.getItem('sbx-pouls:e')).length,f:SbxPouls.memoire('f',{t:1764000000,pays:[]}).length}}""")
    assert r["n"] <= 13 and r["garde"] <= 12 and r["min"] >= 60 and r["age"] <= 10800 and r["der"] == [{"code": "FR", "n": 499}] and r["f"] == 1


def test_nav_fixe_n_altere_pas_les_barres_de_la_page(page):
    pg = page(reduced_motion="reduce")
    pg.evaluate("()=>{$('c').innerHTML='<rect/><rect/><rect/><rect/>';barres({barres:$('c').children})}")
    assert pg.evaluate("[...$('c').children].every(e=>!e.style.opacity&&!e.style.filter)")


def test_nav_sans_halo_au_recul_et_battement_par_calque(page):
    pg = page()
    pg.evaluate("carte();window.R0=0;new MutationObserver(l=>{window.R0+=l.filter(x=>x.attributeName==='r').length}).observe($('za'),{subtree:true,attributes:true})")
    pg.wait_for_timeout(900)
    assert pg.evaluate("window.R0") == 0
    assert pg.locator("#za svg[data-sbxp=battement] g").count() == 1 and pg.locator("#za svg[data-sbxp=battement] circle").count() <= 12
    recul(pg)
    assert pg.evaluate("[$('za').querySelector('svg[data-sbxp=carte] > g').style.opacity,$('za').querySelector('svg[data-sbxp=battement]').style.opacity]") == ["0", "0"]


def test_nav_souris_immobile_ne_bloque_pas_et_infobulle_suit(page):
    pg = page()
    pg.evaluate("carte();compteur()")
    recul(pg)
    pg.hover("#qa")
    attendre(pg, "document.querySelectorAll('#za title').length > 0", 3000)
    avant = pg.evaluate("document.querySelector('#za title').textContent")
    pg.evaluate("carte({instantanes:I(13).map(s=>({t:s.t,pays:s.pays.map(p=>({code:p.code,n:p.n+1000}))}))})")
    assert pg.evaluate("document.querySelector('#za title').textContent") != avant
    attendre(pg, "dates()[0] === '● maintenant' && dates()[1].startsWith('◀')", 16000)


@pytest.mark.parametrize("requete,reglage", [("?auto&kiosk=1", ""), ("?auto", "Object.defineProperty(navigator,'hardwareConcurrency',{get:()=>2})"), ("?auto", "Object.defineProperty(navigator,'deviceMemory',{get:()=>2})")])
def test_nav_fixe_par_defaut_machine_modeste(page, serveur, requete, reglage):
    pg = page()
    pg.evaluate("sessionStorage.clear()")
    if reglage:
        pg.add_init_script(reglage)
    pg.goto(serveur + requete)
    pg.evaluate("SbxPouls.bouton($('outils'));carte()")
    b = pg.locator("#outils button")
    assert b.inner_text() == "⏸ fixe (auto)" and pg.evaluate("SbxPouls.vivant()") is False
    b.click()
    assert b.inner_text() == "💓 vivant" and pg.evaluate("localStorage.getItem('sbx-pouls')") is None
    recul(pg)


def test_nav_repli_automatique_machine_lente(page, serveur):
    pg = page()
    pg.evaluate("sessionStorage.clear()")
    pg.add_init_script("for(const [k,v] of [['hardwareConcurrency',8],['deviceMemory',8]])Object.defineProperty(navigator,k,{get:()=>v})")
    pg.goto(serveur + "?auto")
    pg.evaluate("SbxPouls.bouton($('outils'));carte();window.r0=window.requestAnimationFrame;window.requestAnimationFrame=f=>r0(t=>{const z=performance.now();while(performance.now()-z<90);f(t)});0")
    attendre(pg, "$('outils').textContent === '⏸ fixe (auto)'")
    assert pg.evaluate("[sessionStorage.getItem('sbx-pouls-auto'),localStorage.getItem('sbx-pouls')]") == ["fixe", None]
    assert pg.evaluate("dates()[0]") == "● maintenant"
    pg.evaluate("()=>{window.requestAnimationFrame=window.r0}")
    pg.locator("#outils button").click()
    pg.wait_for_timeout(4000)
    assert pg.locator("#outils button").inner_text() == "💓 vivant"


def test_documentation_de_l_api():
    doc = (ICI / "README.md").read_text(encoding="utf-8")
    for f in re.findall(r"^A\.(\w+)=", SRC.read_text(encoding="utf-8"), re.M):
        assert f == "pur" or f"SbxPouls.{f}" in doc, f
