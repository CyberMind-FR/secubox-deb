# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2638 — carte « Flux YouTube » du Hall au profil Aurora : page statique, nginx dédié, vrai navigateur (API simulée)."""
import json
import re
import time
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
CARTE_PATH = PKG / "www" / "hall" / "cardlets" / "ytflux.html"
SRC = CARTE_PATH.read_text(encoding="utf-8")
VHOST = (PKG / "nginx" / "hall.vhost.conf").read_text(encoding="utf-8")
ROUTES_YTSAS = (PKG.parent / "secubox-ytsas" / "nginx" / "ytsas-routes.conf").read_text(encoding="utf-8")


# ───────────────────────── statique : la page ─────────────────────────

def test_page_aurora_autonome_sans_dialogue_natif():
    assert "SPDX-License-Identifier: LicenseRef-CMSD-1.0" in SRC
    # seul script externe : la sonde du Hall (même origine, contrat des cartes)
    assert re.findall(r'<script src="([^"]+)"', SRC) == ["../sonde.js"]
    assert "--fond:#060d1b" in SRC and "container-type:inline-size" in SRC and "container-name:a" in SRC
    assert "data-theme" not in SRC and "prefers-color-scheme" not in SRC       # thème unique sombre
    for interdit in ("confirm(", "alert(", "prompt(", "innerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "onclick="):
        assert interdit not in SRC, interdit
    assert "lorem" not in SRC.lower()
    assert "sbxVue" in SRC and "onglet: 'ytflux'" in SRC and "location.origin" in SRC
    assert "demo" in SRC and "embed" in SRC


def test_la_demonstration_n_ecrit_rien():
    # les écritures (SAS, favoris) sont gardées par DEMO
    assert re.search(r"function ajouter\([^)]*\)\{\s*if\(DEMO\)", SRC)
    assert re.search(r"function basculerFavori\([^)]*\)\{\s*if\(DEMO\)", SRC)


# ───────────────────────── statique : nginx ─────────────────────────

def _corps(debut):
    i = VHOST.index(debut)
    return VHOST[i:VHOST.index("\n    }", i)]


def test_location_dediee_de_la_carte_precede_le_prefixe_cardlets():
    assert VHOST.index("location = /cardlets/ytflux.html {") < VHOST.index("location /cardlets/ {")


def test_csp_de_la_carte_est_la_csp_generique_avec_un_cadrage_borne():
    ded = _corps("location = /cardlets/ytflux.html {")
    gen = _corps("location /cardlets/ {")
    def csp(c):
        return re.search(r'add_header Content-Security-Policy "([^"]*)" always;', c).group(1)
    d, g = csp(ded), csp(gen)
    # identique à la générique, à la seule directive frame-ancestors près
    assert d.replace(re.search(r"frame-ancestors [^;]*", d).group(0), "X") == g.replace(re.search(r"frame-ancestors [^;]*", g).group(0), "X")
    fa = re.search(r"frame-ancestors ([^;]*)", d).group(1).split()
    assert fa[0] == "'self'" and "$sbx_admin_du_hall" in fa
    for src in fa:
        assert src != "*" and src != "https:" and src != "http:" and not re.fullmatch(r"https?://\*\.?", src), src
        assert src in ("'self'", "$sbx_admin_du_hall"), src
    assert "'none'" not in fa
    assert 'add_header X-Content-Type-Options "nosniff" always;' in ded
    assert 'add_header Cache-Control "no-cache" always;' in ded
    assert "try_files $uri =404;" in ded


def test_admin_deduit_du_domaine_du_hall_et_jamais_un_joker_nu():
    m = re.search(r"map \$host \$sbx_admin_du_hall \{(.*?)\n\}", VHOST, re.S)
    assert m, "map $sbx_admin_du_hall absente"
    corps = m.group(1)
    assert re.search(r'~\^hall\\\.\(\?<\w+>\.\+\)\$\s+"https://admin\.\$\w+";', corps)
    assert "default" in corps and re.search(r'default\s+"";', corps)
    assert "*" not in re.sub(r"#.*", "", corps).replace(".+", "")


def test_la_route_flux_du_hall_reste_authentifiee_et_en_lecture():
    corps = _corps('location ~ "^/api/v1/ytsas/flux')
    assert "auth_request /__sbx_verifie_secubox;" in corps
    assert "limit_except GET { deny all; }" in corps


def test_la_route_flux_n_est_pas_ouverte_sur_le_vhost_admin():
    assert "flux" not in ROUTES_YTSAS


# ───────────────────────── vrai navigateur ─────────────────────────

playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


NOW = int(time.time())
PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360000002000001e221bc330000000049454e44ae426082")


def video(i, titre=None, chaine="Chaîne test", duree=213):
    vid = ("abcdefghi%02d" % i)
    return {"id": vid, "titre": titre or f"Vidéo numéro {i}", "chaine": chaine, "duree": duree,
            "url": f"https://www.youtube.com/watch?v={vid}", "vignette": f"/api/v1/ytsas/flux/vignette/{vid}"}


def liste(type_, n=3, **kw):
    return {"type": type_, "items": [video(i) for i in range(n)], "en_cache": False, "perime": False, "date": NOW - 120, **kw}


FLUX_OK = {t: (200, liste(t, 3 if t != "historique" else 2)) for t in ("envie", "propositions", "abonnements", "historique")}


def ouvre(navigateur, query, flux, taille=None, permissions=None):
    ctx = navigateur.new_context(viewport=taille or {"width": 1400, "height": 900}, permissions=permissions or [])
    p = ctx.new_page()
    erreurs, appels = [], []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("dialog", lambda d: (erreurs.append("dialogue natif : " + d.message), d.dismiss()))
    # http://sbx.test n'est pas un contexte sûr : le presse-papiers y est absent, on le remplace par un témoin
    p.add_init_script("window.__msgs=[];addEventListener('message',e=>__msgs.push(e.data));"
                      "Object.defineProperty(navigator,'clipboard',{value:{writeText:t=>{window.__copie=t;return Promise.resolve();}}});")

    def fichier(r, *_):
        chemin = r.request.url.split("http://sbx.test/", 1)[1].split("?")[0]
        if chemin == "cardlets/ytflux.html":
            r.fulfill(status=200, content_type="text/html", body=SRC)
        elif chemin == "sonde.js":
            r.fulfill(status=200, content_type="application/javascript", body="")
        else:
            r.fulfill(status=404, body="")
    p.route("http://sbx.test/**", fichier)

    def api(r, *_):
        url = r.request.url
        chemin = url.split("/api/v1/ytsas/", 1)[1]
        appels.append((r.request.method, chemin, r.request.post_data))
        if chemin.startswith("flux/vignette/"):
            r.fulfill(status=200, content_type="image/png", body=PNG)
        elif chemin.startswith("flux?"):
            t = re.search(r"type=([a-z]+)", chemin).group(1)
            st, corps = flux.get(t, (404, {}))
            r.fulfill(status=st, content_type="application/json", body=json.dumps(corps))
        else:
            r.fulfill(status=200, content_type="application/json", body="{}")
    p.route("http://sbx.test/api/v1/ytsas/**", api)
    p.goto("http://sbx.test/cardlets/ytflux.html" + query)
    return ctx, p, erreurs, appels


def attend_liste(p):
    p.wait_for_selector("#grille .video", state="attached")


def test_quatre_listes_et_actions_de_chaque_video(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "", FLUX_OK)
    attend_liste(p)
    assert p.locator("#onglets [role=tab]").all_inner_texts() == ["À regarder plus tard", "Proposées", "Abonnements", "Historique", "Mes chaînes", "Playlists", "Favoris"]   # #2708 : trois onglets ajoutés
    assert p.get_attribute("#onglets [data-type=envie]", "aria-selected") == "true"
    assert p.locator("#grille .video").count() == 3
    v = p.locator("#grille .video").first
    assert "Vidéo numéro 0" in v.inner_text() and "Chaîne test" in v.inner_text() and "3:33" in v.inner_text()
    assert v.locator("img").get_attribute("src") == "/api/v1/ytsas/flux/vignette/abcdefghi00"
    assert [b.inner_text() for b in v.locator(".act").all()] == ["▶ YouTube", "⬇ SAS", "⧉", "☆", "🧭", "📡"]   # #2708 : 📡 ajouté en dernier
    lien = v.locator("a.act")
    assert lien.get_attribute("href") == "https://www.youtube.com/watch?v=abcdefghi00" and lien.get_attribute("rel") == "noopener noreferrer"
    assert p.inner_text("#tVideos") == "3" and p.inner_text("#etat") == "À JOUR"
    for type_, n in (("propositions", 3), ("abonnements", 3), ("historique", 2)):
        p.click(f"#onglets [data-type={type_}]")
        p.wait_for_function(f"document.querySelectorAll('#grille .video').length === {n} && document.querySelector('#onglets [data-type={type_}]').getAttribute('aria-selected') === 'true'")
    assert [a[1] for a in appels if a[1].startswith("flux?")] == [f"flux?type={t}&limite=24" for t in ("envie", "propositions", "abonnements", "historique")]
    assert err == []
    ctx.close()


def test_ajouter_au_sas_poste_la_meme_requete(navigateur):
    ctx, p, _, appels = ouvre(navigateur, "", FLUX_OK)
    attend_liste(p)
    p.locator("#grille .video").first.get_by_text("⬇ SAS").click()
    p.wait_for_function("document.querySelector('#grille .video .act:nth-child(2)').textContent.includes('Au SAS')")
    post = [a for a in appels if a[0] == "POST"][0]
    assert post[1] == "add" and json.loads(post[2]) == {"url": "https://www.youtube.com/watch?v=abcdefghi00"}
    ctx.close()


def test_favori_ecrit_sbx_favoris_et_copier_ecrit_le_presse_papier(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "", FLUX_OK)
    attend_liste(p)
    v = p.locator("#grille .video").first
    u = "https://www.youtube.com/watch?v=abcdefghi00"
    v.locator("button[aria-label=Favori]").click()
    assert json.loads(p.evaluate("localStorage.getItem('sbx_favoris')")) == [u]
    assert v.locator("button[aria-label=Favori]").inner_text() == "★"
    v.locator("button[aria-label=Favori]").click()
    assert json.loads(p.evaluate("localStorage.getItem('sbx_favoris')")) == []
    v.get_by_label("Copier le lien").click()
    p.wait_for_function("document.querySelector('#grille .video button[aria-label=\"Copier le lien\"]').textContent === '✓'")
    assert p.evaluate("window.__copie") == u
    # Surf : message 'surf' adressé à l'origine du parent
    v.get_by_label("Voir dans Surf").click()
    p.wait_for_function("__msgs.some(m => m.sbx === 'surf')")
    assert {"sbx": "surf", "url": u} in p.evaluate("__msgs")
    assert err == []
    ctx.close()


def test_cause_cookies_et_autres_pannes_sont_dites(navigateur):
    def perime(cause):
        return {"envie": (200, liste("envie", 2, en_cache=True, perime=True, cause=cause))}
    ctx, p, err, _ = ouvre(navigateur, "", perime("cookies"))
    attend_liste(p)
    assert "cookies YouTube périmés" in p.inner_text("#lecture") and "cookies.txt" in p.inner_text("#lecture")
    assert "PÉRIMÉES" in p.inner_text("#etat") and p.inner_text("#tDonnees") == "Périmées" and p.inner_text("#tCache") == "Oui"
    ctx.close()
    ctx, p, _, _ = ouvre(navigateur, "", perime("youtube"))
    attend_liste(p)
    assert "n’a pas répondu" in p.inner_text("#lecture") and "cookies YouTube périmés" not in p.inner_text("#lecture")
    ctx.close()
    ctx, p, _, _ = ouvre(navigateur, "", {"envie": (502, {"error": "YouTube n'a pas rendu ce flux", "detail": "délai"})})
    p.wait_for_selector("#msg:not([hidden])")
    assert "n’a pas répondu (délai)" in p.inner_text("#msg") and "Réessayer" in p.inner_text("#msg")
    assert p.inner_text("#etat") == "HORS LIGNE" and p.inner_text("#tVideos") == "—"
    ctx.close()
    ctx, p, _, _ = ouvre(navigateur, "", {"envie": (401, {"error": "auth requise", "cookies_perimes": True})})
    p.wait_for_selector("#msg:not([hidden])")
    assert "cookies sont périmés" in p.inner_text("#msg")
    ctx.close()


def test_sans_session_bandeau_et_tirets(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "", {"envie": (401, {"detail": "jeton requis"})})
    p.wait_for_selector("#session:not([hidden])")
    assert "session requise" in p.inner_text("#session") and p.inner_text("#etat") == "SESSION REQUISE"
    assert [p.inner_text(i) for i in ("#tVideos", "#tLecture", "#tCache", "#tDonnees")] == ["—"] * 4
    assert "Connexion requise" in p.inner_text("#msg") and err == []
    ctx.close()


def test_liste_vide_dit_rien_et_garde_les_tirets(navigateur):
    ctx, p, _, _ = ouvre(navigateur, "", {"envie": (200, liste("envie", 0))})
    p.wait_for_selector("#msg:not([hidden])")
    assert "Rien dans cette liste" in p.inner_text("#msg") and p.inner_text("#tVideos") == "0"
    ctx.close()


def test_demonstration_annoncee_et_aucune_ecriture(navigateur):
    ctx, p, err, appels = ouvre(navigateur, "?demo=1", {})
    attend_liste(p)
    assert p.is_visible("#demo") and "DÉMONSTRATION" in p.inner_text("#demo")
    for t in ("propositions", "abonnements", "historique"):
        p.click(f"#onglets [data-type={t}]")
        p.wait_for_selector("#grille .video", state="attached")
    v = p.locator("#grille .video").first
    for nom in ("⬇ SAS",):
        v.get_by_text(nom).click()
    v.locator("button[aria-label=Favori]").click()
    v.get_by_label("Copier le lien").click()
    v.get_by_label("Voir dans Surf").click()
    assert "inerte" in p.inner_text("#retour")
    assert p.evaluate("localStorage.getItem('sbx_favoris')") is None
    p.wait_for_timeout(200)
    assert [m for m in p.evaluate("__msgs") if "sbx" in m] == []
    assert appels == [] and err == []
    ctx.close()


def test_embed_sans_chrome_superflu_et_hauteur_annoncee(navigateur):
    ctx, p, err, _ = ouvre(navigateur, "?embed=1", FLUX_OK, taille={"width": 700, "height": 600})
    attend_liste(p)
    assert not p.is_visible("#tuiles") and not p.is_visible(".marque")
    assert not p.locator("#grille .video").first.get_by_label("Voir dans Surf").is_visible()      # le parent n'est pas le Hall
    p.wait_for_function("__msgs.some(m => m.sbxVue)")
    m = [x for x in p.evaluate("__msgs") if x.get("sbxVue")][-1]
    assert m["onglet"] == "ytflux" and 300 <= m["sbxVue"] <= 4000
    h = p.evaluate("Math.ceil(document.querySelector('.cadre').getBoundingClientRect().bottom + scrollY)")
    assert abs(m["sbxVue"] - h) <= 2
    assert p.evaluate("document.documentElement.scrollHeight") >= m["sbxVue"] - 2
    assert err == []
    ctx.close()


def test_telephone_420_sans_debordement(navigateur):
    for q in ("", "?embed=1", "?demo=1"):
        ctx, p, err, _ = ouvre(navigateur, q, FLUX_OK, taille={"width": 420, "height": 800})
        attend_liste(p)
        assert p.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"), q
        # aucun bouton ni titre ne dépasse son carreau
        assert p.evaluate("[...document.querySelectorAll('.video')].every(v => [...v.querySelectorAll('.act')].every(a => a.getBoundingClientRect().right <= v.getBoundingClientRect().right + 1))"), q
        assert err == []
        ctx.close()
