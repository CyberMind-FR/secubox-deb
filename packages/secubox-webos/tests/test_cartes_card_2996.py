# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 4, suite) — migration des cartes de l'accueil vers `Card`, dans l'ordre du prompt.

En v2, une carte migrée (`.fcard[data-embed]` dont l'id figure dans MIGREES) est HABILLÉE en `Card` sur place :
en-tête (icône SVG, titre, pastille de statut, action ›), corps (le cardlet existant, intact), pied (« Relevé »).
L'ancien rendu n'est pas retiré : la carte garde `.fcard`, `data-embed`, sa poignée ⠿, son étoile ★ et son aide ?,
donc le glisser, les favoris et l'auto-guide continuent de la trouver. Les cartes non migrées gardent le pied v2
de la phase 3 ; le Hall v1 ne change pas.
"""
import json
import mimetypes
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
HALL_DIR = PKG / "www" / "hall"
JS = (HALL_DIR / "hall-v2.js").read_text(encoding="utf-8")
COMPOSANTS = (HALL_DIR / "composants.js").read_text(encoding="utf-8")
CSS = (HALL_DIR / "hall-v2.css").read_text(encoding="utf-8")

# Ordre du prompt (dossier §2, phase 4) : Sécurité, DNS, Réseau, État système (= Hero), Appareils, Notifications,
# Accès rapide, Mes modules (= mosaïque), Flux d'actualités, Radio dock, Mur de discussion, Actor + Radar, Éphéméride,
# Zigbee, DevWatch, ZIA, Mes comptes, Lyrion, Freebox TV, L'écoute, YTSaS. Sur les cartes réelles du Hall :
# Sécurité = securite + acteurs + radar ; DNS et Appareils = guardian ; Réseau = dpi + ipv6guard ; Notifications = activite ;
# Flux d'actualités = metanews + ytflux + billets ; Mur = bbs ; L'écoute = mood.
PREMIER_LOT = ["securite", "acteurs", "radar", "guardian", "dpi", "ipv6guard", "activite",
               "metanews", "ytflux", "billets", "radio", "bbs", "ephemeride", "zigbee", "devwatch", "zia", "comptes",
               "lyrion", "freeboxtv", "mood", "ytsas"]
INDEX = (HALL_DIR / "index.html").read_text(encoding="utf-8")

# Les cartes de curation portent des ids à elles (securite, guardian, acteurs, radar, activite) : leur statut est celui
# du MODULE qui les sert dans le registre (waf, ad-guard, actor, sbxid) — SOURCE_STATUT de hall-v2.js.
SERVICES = {"services": [
    {"id": "waf", "name": "WAF", "category": "wall", "status": "active", "health": {"state": "online"}},
    {"id": "ad-guard", "name": "Ad Guard", "category": "wall", "status": "idle", "health": {"state": "online"}},
    {"id": "dpi", "name": "DPI", "category": "mesh", "status": "offline", "health": {"state": "offline"}},
    {"id": "radio", "name": "Radio", "category": "mind", "status": "active", "health": {"state": "online"}},
], "computed_at": time.time(), "releve": "2026-10-22T07:10:52+00:00", "intervalle_s": 15}


def test_le_premier_lot_est_declare_dans_l_ordre_du_prompt():
    m = re.search(r"var MIGREES\s*=\s*\[([^\]]*)\]", JS)
    assert m, "hall-v2.js doit déclarer MIGREES (cartes habillées en Card)"
    ids = re.findall(r"'([a-z0-9-]+)'", m.group(1))
    assert ids == PREMIER_LOT
    m = re.search(r"var SOURCE_STATUT\s*=\s*\{([^}]*)\}", JS)
    assert m and dict(re.findall(r"([a-z]+):'([a-z-]+)'", m.group(1))) == {
        "securite": "waf", "acteurs": "actor", "radar": "actor", "guardian": "ad-guard", "activite": "sbxid",
        "ytflux": "ytsas", "comptes": "sbxid", "mood": "sbxos-audio-mood", "freeboxtv": "freebox"}
    # chaque id du lot est une carte réelle de la curation, et porte une icône SVG connue des composants
    icones = dict(re.findall(r"([a-z0-9]+):'([a-z]+)'", re.search(r"var ICO_CARTE\s*=\s*\{([^}]*)\}", JS).group(1)))
    connues = set(re.findall(r"^\s*([a-z]+):'<", COMPOSANTS, re.M)) | set(re.findall(r"\s([a-z]+):'<", COMPOSANTS))
    for i in ids:
        assert re.search(r'\{id:"%s"' % i, INDEX), i
        assert icones.get(i) in connues, (i, icones.get(i))
    # Card accepte un hôte : l'article existant est habillé, jamais remplacé.
    assert "o.hote" in COMPOSANTS
    # Les commandes de carte (poignée, étoile, aide) restent à l'article, hors du corps.
    assert "cl-grip" in COMPOSANTS and "cl-vedette" in COMPOSANTS and "cl-aide" in COMPOSANTS
    # Le corps d'une carte habillée ne rajoute pas de marge autour du cardlet ; cible tactile de l'action à 44 px au téléphone.
    assert re.search(r"\.fcard\.sbx-card\s+\.sbx-card-corps\{[^}]*padding:0", CSS)
    assert re.search(r"@media\s*\(max-width:\s*720px\)[^@]*\.fcard\.sbx-card\s+\.sbx-card-action\{[^}]*(width|min-width):44px", CSS, re.S)


# ── Rendu ──────────────────────────────────────────────────────────────────

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def nav():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(nav, largeur=1440, v2=True):
    ctx = nav.new_context(viewport={"width": largeur, "height": 900}, color_scheme="dark")
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))

    def sert(r):
        u = r.request.url.split("http://sbx.test", 1)[1].split("?")[0]
        if u == "/api/v1/webos/public/services":
            # relevé frais à chaque réponse : un relevé plus vieux que 2 × l'intervalle est « périmé » (phase 3)
            return r.fulfill(status=200, content_type="application/json", body=json.dumps(dict(SERVICES, computed_at=time.time())))
        if u == "/api/v1/webos/public/etat":
            return r.fulfill(status=200, content_type="application/json", body='{"hall_v2": false, "version": "1.19.11-1", "en_ligne": true}')
        if u.startswith("/api/"):
            return r.fulfill(status=404, content_type="application/json", body="{}")
        if u.startswith("/cardlets/") or u.startswith("/guardian/") or u.startswith("/dpi-vue/") or u.startswith("/actor-intelligence/"):
            return r.fulfill(status=200, content_type="text/html", body="<p>cardlet</p>")
        f = HALL_DIR / ("index.html" if u == "/" else u.lstrip("/"))
        if f.is_file():
            return r.fulfill(status=200, content_type=mimetypes.guess_type(str(f))[0] or "text/plain", body=f.read_bytes())
        r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", sert)
    p.route("https://**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>x</p>"))
    p.goto("http://sbx.test/" + ("?hall=v2" if v2 else ""))
    p.wait_for_selector(".fcard[data-embed]", state="attached")
    if v2:
        p.wait_for_selector(".fcard[data-embed='securite'].sbx-card .sbx-releve", state="attached")
    p.evaluate("document.querySelectorAll('.bienv-scrim').forEach(e=>e.classList.add('hidden'))")
    return ctx, p, erreurs


def test_la_carte_securite_est_habillee_en_card_sans_perdre_l_ancienne(nav):
    ctx, p, erreurs = ouvre(nav)
    sel = ".fcard[data-embed='securite']"
    assert p.evaluate("document.querySelectorAll(\"%s\").length" % sel) == 1
    c = sel + ".sbx-card"
    assert p.evaluate("document.querySelector(\"%s header.sbx-card-tete svg.sbx-ico\")" % c) is not None
    assert p.inner_text(c + " .sbx-card-titre") == "Sécurité"
    assert p.evaluate("document.querySelector(\"%s .sbx-card-statut\").textContent" % c) == "actif"
    assert p.evaluate("document.querySelector(\"%s\").getAttribute('data-status')" % c) == "active"
    # l'action › ouvre le service embarqué par la délégation du Hall (data-open), en vrai bouton
    a = p.evaluate("(()=>{const a=document.querySelector(\"%s .sbx-card-action\");return [a.tagName,a.type,a.getAttribute('data-open'),a.getAttribute('data-mode'),a.getAttribute('aria-label')]})()" % c)
    assert a == ["BUTTON", "button", "securite", "embed", "Ouvrir Sécurité"]
    # le cardlet d'origine vit dans le corps, intact (src conservé)
    assert p.evaluate("document.querySelector(\"%s .sbx-card-corps iframe.fcard-cadre\").getAttribute('src')" % c).startswith("/cardlets/cumul.html?groupe=securite")
    assert p.evaluate("getComputedStyle(document.querySelector(\"%s .sbx-card-corps\")).paddingTop" % c) == "0px"
    # pied : source (hôte) à gauche, relevé à droite ; plus de pied v2 de la phase 3
    assert p.inner_text(c + " .sbx-card-pied .sbx-source") == p.evaluate("document.querySelector(\"%s\").getAttribute('data-host')" % c)
    assert p.inner_text(c + " .sbx-releve").startswith("Relevé ")
    assert p.evaluate("document.querySelector(\"%s .sbx-fcard-pied\")" % c) is None
    # les commandes de la carte sont toujours là, une seule fois, hors du corps
    for cmd in ("cl-grip", "cl-vedette", "cl-aide"):
        assert p.evaluate("document.querySelectorAll(\"%s > .%s\").length" % (c, cmd)) == 1, cmd
    # les commandes ne mangent pas le titre : elles descendent dans la bande du pied, le titre n'est pas tronqué
    pied = p.evaluate("(()=>{const r=document.querySelector(\"%s .sbx-card-pied\").getBoundingClientRect();return [r.top,r.bottom]})()" % c)
    grip = p.evaluate("(()=>{const r=document.querySelector(\"%s > .cl-grip\").getBoundingClientRect();return [r.top,r.bottom]})()" % c)
    assert pied[0] - 1 <= grip[0] and grip[1] <= pied[1] + 1
    assert p.evaluate("(()=>{const h=document.querySelector(\"%s .sbx-card-titre\");return h.scrollWidth<=h.clientWidth})()" % c)
    assert erreurs == []
    ctx.close()


def test_seules_les_cartes_du_lot_sont_habillees_les_autres_gardent_le_pied_v2(nav):
    ctx, p, erreurs = ouvre(nav)
    ids = p.evaluate("[...document.querySelectorAll('.fcard.sbx-card')].map(c=>c.getAttribute('data-embed'))")
    assert ids and set(ids) <= set(PREMIER_LOT), ids
    assert "securite" in ids and "dpi" in ids and "radio" in ids and "metanews" in ids
    autre = ".fcard[data-embed='peertube']"   # hors lot : la carte générique garde le pied v2
    assert p.evaluate("document.querySelector(\"%s\").classList.contains('sbx-card')" % autre) is False
    assert p.evaluate("document.querySelector(\"%s .sbx-fcard-pied\")" % autre) is not None
    assert p.evaluate("document.querySelector(\"%s .sbx-card-tete\")" % autre) is None
    # le dock radio reste un nœud unique : une seule carte radio, son cadre intact dans le corps
    assert p.evaluate("document.querySelectorAll(\".fcard[data-embed='radio']\").length") == 1
    assert p.evaluate("document.querySelector(\".fcard[data-embed='radio'].sbx-card .sbx-card-corps iframe\")") is not None
    assert erreurs == []
    ctx.close()


def test_le_statut_du_registre_pilote_la_pastille_et_la_veille(nav):
    ctx, p, erreurs = ouvre(nav)
    g = ".fcard[data-embed='guardian'].sbx-card"
    assert p.evaluate("document.querySelector(\"%s .sbx-card-statut\").textContent" % g) == "en veille"
    assert p.evaluate("document.querySelector(\"%s\").getAttribute('data-status')" % g) == "idle"
    # en veille : aucune requête (src retiré), la note de veille est dans le corps
    assert p.evaluate("document.querySelector(\"%s .sbx-card-corps iframe\").getAttribute('src')" % g) is None
    assert p.evaluate("document.querySelector(\"%s .sbx-card-corps .sbx-veille\")" % g) is not None
    d = ".fcard[data-embed='dpi'].sbx-card"
    assert p.evaluate("document.querySelector(\"%s .sbx-card-statut\").textContent" % d) == "hors ligne"
    assert float(p.evaluate("getComputedStyle(document.querySelector(\"%s\")).opacity" % d)) < 1
    assert erreurs == []
    ctx.close()


def test_mobile_390_une_colonne_sans_debordement_et_action_tactile(nav):
    ctx, p, erreurs = ouvre(nav, 390)
    assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
    c = ".fcard[data-embed='securite'].sbx-card"
    larg = p.evaluate("document.querySelector(\"%s\").getBoundingClientRect().width" % c)
    assert 300 <= larg <= 390
    act = p.evaluate("(()=>{const r=document.querySelector(\"%s .sbx-card-action\").getBoundingClientRect();return [r.width,r.height]})()" % c)
    assert min(act) >= 44
    assert erreurs == []
    ctx.close()


def test_le_hall_v1_ne_porte_aucune_card(nav):
    ctx, p, erreurs = ouvre(nav, v2=False)
    assert p.evaluate("document.querySelector('#featgrid .sbx-card, #favbande .sbx-card')") is None
    assert erreurs == []
    ctx.close()
