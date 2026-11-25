# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox-live (#3933) : refonte de la page publique — CSP, polices, rien d'intégré, nuit par défaut, données absentes ou
hostiles, mise à jour d'un vhost déjà exposé. Les essais au navigateur sont sautés sans Playwright."""
import functools
import http.server
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent.parent
WWW = ICI / "www/live"


def lire(rel: str) -> str:
    return (ICI / rel).read_text(encoding="utf-8")


def csp() -> str:
    return re.search(r'Content-Security-Policy "([^"]*)"', lire("nginx/live.vhost.conf.in")).group(1)


# ------------------------------------------------------------------------------------------------ statique

def test_rien_d_integre_ni_d_externe():
    html, js, css = lire("www/live/index.html"), lire("www/live/live.js"), lire("www/live/live.css")
    assert "style=" not in html and "<style" not in html and not re.search(r"\son[a-z]+=", html)
    for src in re.findall(r'(?:src|href)="([^"]+)"', html):
        if src.startswith("https://"):
            assert src in ("https://secubox.in", "https://github.com/CyberMind-FR/secubox-deb"), src   # liens, pas des ressources
        else:
            assert src.startswith("/") or src.startswith("data:image/svg+xml,"), src
    assert not re.search(r"<(script|link|img|iframe)[^>]+(?:src|href)=\"(?:https?:)?//", html)
    for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "cssText", "new Function"):
        assert interdit not in js, interdit
    assert not re.search(r"setAttribute\(\s*['\"]style", js) and not re.search(r"[{,]\s*['\"]?style['\"]?\s*:", js)
    assert "http" not in re.sub(r"http://www\.w3\.org/2000/svg", "", js)
    assert "@import" not in css and "http" not in css
    assert "maquette" not in html.lower()


def test_polices_hebergees_licence_et_locations_exactes():
    conf, css = lire("nginx/live.vhost.conf.in"), lire("www/live/live.css")
    assert "font-src 'self'" in csp() and "unsafe" not in csp() and "default-src 'none'" in csp()
    urls = re.findall(r"url\(([^)]+)\)", css)
    assert sorted(urls) == ["/polices/jetbrains-mono-latin.woff2", "/polices/unbounded-latin.woff2"]
    assert css.count("font-display:swap") == 2
    for u in urls:
        assert (WWW / u.lstrip("/")).read_bytes()[:4] == b"wOF2" and f"location = {u} " in conf
        assert (WWW / u.lstrip("/")).stat().st_size < 80_000
    for nom in ("unbounded", "jetbrains-mono"):
        assert "SIL Open Font License, Version 1.1" in lire(f"www/live/polices/OFL-{nom}.txt")
        assert f"location = /polices/OFL-{nom}.txt " in conf
    assert "location /polices" not in conf and "autoindex" not in conf
    assert "polices/*.woff2" in lire("debian/rules") and "OFL-*.txt" in lire("debian/rules")


def test_version_du_paquet_dans_la_page():
    v = re.match(r"secubox-live \((\d+\.\d+\.\d+)-", lire("debian/changelog")).group(1)
    html = lire("www/live/index.html")
    assert f'href="/live.css?v={v}"' in html and f'src="/live.js?v={v}"' in html


def test_nuit_par_defaut_quel_que_soit_le_systeme():
    html, js, css = lire("www/live/index.html"), lire("www/live/live.js"), lire("www/live/live.css")
    assert "data-ambiance" not in html and "prefers-color-scheme" not in css + js + html
    assert "color-scheme:dark" in css and ':root[data-ambiance="jour"]' in css
    assert js.count("localStorage") == 2 and len(re.findall(r"try \{ (?:return )?localStorage", js)) == 2


def test_mouvement_reduit_et_page_cachee():
    css, js = lire("www/live/live.css"), lire("www/live/live.js")
    bloc = css[css.index("prefers-reduced-motion"):]
    for c in (".pouls s", ".onde", ".flotte", ".averse"):
        assert c in bloc and "animation:none!important" in bloc, c
    assert "document.hidden || calme.matches" in js and "prefers-reduced-motion" in js


def _lum(c):
    c = [x / 255 for x in c]
    c = [x / 12.92 if x <= .03928 else ((x + .055) / 1.055) ** 2.4 for x in c]
    return .2126 * c[0] + .7152 * c[1] + .0722 * c[2]


def _contraste(a, b):
    x, y = sorted((_lum(a), _lum(b)), reverse=True)
    return (x + .05) / (y + .05)


def _couleur(v, fond=(0, 0, 0)):
    if v.startswith("#"):
        return tuple(int(v[i:i + 2], 16) for i in (1, 3, 5))
    r, g, b, a = (float(x) for x in re.match(r"rgba\(([^)]+)\)", v).group(1).split(","))
    return tuple(a * c + (1 - a) * f for c, f in zip((r, g, b), fond))


def _mel(a, b, t):
    return tuple(x + (y - x) * t for x, y in zip(a, b))


@pytest.mark.parametrize("ambiance", ["nuit", "jour"])
def test_contraste_du_texte(ambiance):
    css = lire("www/live/live.css")
    blocs = {"nuit": re.search(r":root\{(.*?)\}", css, re.S).group(1),
             "jour": re.search(r':root\[data-ambiance="jour"\]\{(.*?)\}', css, re.S).group(1)}
    v = dict(re.findall(r"--([a-z0-9-]+):([^;}]+)", blocs["nuit"]))
    if ambiance == "jour":
        v.update(re.findall(r"--([a-z0-9-]+):([^;}]+)", blocs["jour"]))
    nuit = _couleur(v["nuit"])
    ciel1, ciel2 = _couleur(v["ciel1"]), _couleur(v["ciel2"])
    bas = _mel(ciel1, ciel2, 38 / 56)                                     # bas de la ville (dégradé 62 % → 118 %)
    sol = _mel(bas, nuit, .86)                                            # bande du sol
    ciel = [_mel(nuit, ciel1, t) for t in (0, .5, .9)]                    # le titre est dans le haut du dégradé
    nappes = [_couleur(v["nappe"], f) for f in [nuit] + ciel]
    # grille du fond : trait --plan posé sur la nuit
    fonds = [nuit, _couleur(v["plan"], nuit)] + nappes
    for nom, sur in (("texte", fonds + ciel + [sol]), ("doux", fonds + [sol]), ("cyan-texte", fonds + ciel[:2]), ("ambre-texte", [nuit]),
                     ("rose", [nuit]), ("sur-rose", [_couleur(v["rose"])])):
        for f in sur:
            assert _contraste(_couleur(v[nom]), f) >= 4.5, (ambiance, nom, f, _contraste(_couleur(v[nom]), f))


# ------------------------------------------------------------------------------------------------ exposeur

def _banc(tmp_path, domaine="live.secubox.in", retenu="live.secubox.in", expose=True, nginx_ok=True, reload_ok=True, nginx_suite=""):
    """Copie de l'exposeur, chemins ramenés dans tmp_path ; nginx, systemctl… remplacés par des témoins."""
    b = tmp_path / "bin"
    for d in (b, tmp_path / "etc/nginx/sites-available", tmp_path / "etc/nginx/sites-enabled", tmp_path / "lib"):
        d.mkdir(parents=True)
    (tmp_path / "live.toml").write_text(f'domaine = "{domaine}"\n')
    (tmp_path / "profils").write_text("/usr/sbin/secubox-live-collecte (enforce)\n")
    site, lien = tmp_path / "etc/nginx/sites-available/live.conf", tmp_path / "etc/nginx/sites-enabled/live.conf"
    if expose:
        site.write_text("ancien vhost\n")
        os.symlink("../sites-available/live.conf", lien)
    if retenu:
        (tmp_path / "lib/domaine").write_text(retenu + "\n")
    s = lire("sbin/secubox-live-exposer")
    for a, c in (("/etc/secubox/live.toml", tmp_path / "live.toml"), ("/etc/secubox/haproxy.toml", tmp_path / "absent"),
                 ("/usr/share/secubox/live/live.vhost.conf.in", ICI / "nginx/live.vhost.conf.in"),
                 ("/etc/nginx/", str(tmp_path / "etc/nginx") + "/"), ("/var/lib/secubox-live", tmp_path / "lib"),
                 ("/run/secubox-live-exposer.lock", tmp_path / "verrou"),
                 ("/sys/kernel/security/apparmor/profiles", tmp_path / "profils"), ("/data/haproxy/certs", tmp_path / "certs")):
        assert a in s, a
        s = s.replace(a, str(c))
    # pid du script, pour les essais d'interruption ($PPID désigne le sous-shell de la substitution de commande)
    s = s.replace("set -euo pipefail\n", f"set -euo pipefail\necho $$ > {tmp_path}/pid\n", 1)
    (b / "exposer").write_text(s)
    for nom, code in (("nginx", 0 if nginx_ok else 1), ("systemctl", 0 if reload_ok else 1), ("logger", 0), ("secubox-waf-route", 0), ("haproxyctl", 0), ("certbot", 1)):
        suite = nginx_suite if nom == "nginx" else ""
        (b / nom).write_text(f'#!/bin/sh\necho "{nom} $*" >> {tmp_path}/appels\n{suite}\nexit {code}\n')
        (b / nom).chmod(0o755)

    def lancer(*args):
        r = subprocess.run(["bash", str(b / "exposer"), *args], capture_output=True, text=True, timeout=30,
                           env={"PATH": f"{b}:/usr/bin:/bin"})
        appels = (tmp_path / "appels").read_text().splitlines() if (tmp_path / "appels").exists() else []
        return r, appels
    return lancer, site, lien


def test_maj_rend_de_nouveau_un_vhost_expose(tmp_path):
    lancer, site, lien = _banc(tmp_path)
    r, appels = lancer("--mise-a-jour")
    assert r.returncode == 0, r.stderr
    assert "font-src 'self'" in site.read_text() and "server_name live.secubox.in;" in site.read_text()
    assert appels[:2] == ["nginx -t", "systemctl reload nginx"]
    assert not any(a.startswith(("secubox-waf-route", "haproxyctl", "certbot")) for a in appels)      # rien d'autre
    assert [p.name for p in site.parent.iterdir()] == ["live.conf"]                                    # aucun reste
    n = len(appels)
    r, appels = lancer("--mise-a-jour")
    assert r.returncode == 0 and len(appels) == n                                                      # identique : aucun rechargement


@pytest.mark.parametrize("cas", [dict(expose=False), dict(retenu=""), dict(domaine=""), dict(retenu="live.autre.secubox.in"),
                                 dict(expose=False, retenu="")])
def test_maj_n_expose_jamais_une_box_non_exposee(tmp_path, cas):
    lancer, site, lien = _banc(tmp_path, **cas)
    avant = site.read_text() if site.exists() else None
    r, appels = lancer("--mise-a-jour")
    assert r.returncode == 0 and appels == []
    assert (site.read_text() if site.exists() else None) == avant and lien.exists() is cas.get("expose", True)


def test_maj_nginx_refuse_garde_le_vhost_precedent(tmp_path):
    lancer, site, lien = _banc(tmp_path, nginx_ok=False)
    for args in (("--mise-a-jour",), ()):                                  # à la main non plus, la page servie n'est pas retirée
        r, appels = lancer(*args)
        assert r.returncode == 1 and "précédent remis en place" in r.stderr
        assert site.read_text() == "ancien vhost\n" and lien.is_symlink()
        assert not any("reload" in a for a in appels)
        assert [p.name for p in site.parent.iterdir()] == ["live.conf"]


def test_maj_sans_apparmor_ne_touche_a_rien(tmp_path):
    lancer, site, _ = _banc(tmp_path)
    (tmp_path / "profils").write_text("")
    r, appels = lancer("--mise-a-jour")
    assert r.returncode == 1 and appels == [] and site.read_text() == "ancien vhost\n"


def test_rechargement_en_echec_remet_le_precedent(tmp_path):
    lancer, site, lien = _banc(tmp_path, reload_ok=False)
    for args in (("--mise-a-jour",), ("--mise-a-jour",), ()):              # jamais « déjà à jour » tant que nginx ne l'a pas pris
        r, appels = lancer(*args)
        assert r.returncode == 1 and "rechargement" in r.stderr and "déjà à jour" not in r.stdout
        assert site.read_text() == "ancien vhost\n" and lien.is_symlink()
        assert not any(a.startswith(("logger", "secubox-waf-route", "haproxyctl")) for a in appels)
        assert [p.name for p in site.parent.iterdir()] == ["live.conf"]


def test_premiere_exposition_rechargement_en_echec_rien_d_expose(tmp_path):
    lancer, site, lien = _banc(tmp_path, expose=False, retenu="", reload_ok=False)
    r, appels = lancer()
    assert r.returncode == 1 and not lien.is_symlink() and not any(a.startswith("secubox-waf-route") for a in appels)
    assert not (tmp_path / "lib/domaine").exists()


@pytest.mark.parametrize("signal", ["TERM", "INT", "HUP"])
def test_interruption_entre_la_pose_et_la_validation(tmp_path, signal):
    coupe = 'kill -%s "$(cat %s/pid)"; sleep 0.3'
    lancer, site, lien = _banc(tmp_path, nginx_suite=coupe % (signal, tmp_path))
    r, appels = lancer("--mise-a-jour")
    code = {"HUP": 129, "INT": 130, "TERM": 143}[signal]
    assert r.returncode == code and site.read_text() == "ancien vhost\n" and lien.is_symlink()
    assert not any("reload" in a for a in appels) and [p.name for p in site.parent.iterdir()] == ["live.conf"]
    (tmp_path / "n").mkdir()
    lancer, site, lien = _banc(tmp_path / "n", expose=False, retenu="", nginx_suite=coupe % (signal, tmp_path / "n"))
    r, _ = lancer()
    assert r.returncode == code and not lien.is_symlink() and not site.exists()


def test_verrou_un_seul_exposeur_a_la_fois(tmp_path):
    import fcntl
    lancer, site, _ = _banc(tmp_path)
    s = (tmp_path / "bin/exposer").read_text()
    assert "flock -w 60 9" in s
    (tmp_path / "bin/exposer").write_text(s.replace("flock -w 60 9", "flock -w 0 9"))
    with open(tmp_path / "verrou", "w") as v:
        fcntl.flock(v, fcntl.LOCK_EX)
        r, appels = lancer("--mise-a-jour")
        assert r.returncode == 1 and "déjà en cours" in r.stderr and appels == [] and site.read_text() == "ancien vhost\n"
    r, _ = lancer("--mise-a-jour")
    assert r.returncode == 0 and "font-src" in site.read_text()


@pytest.mark.parametrize("retenu", ["", "live.secubox.in"])
@pytest.mark.parametrize("forme", ["lien_ailleurs", "fichier", "site_lien"])
def test_lien_qui_n_est_pas_le_notre_jamais_remplace(tmp_path, forme, retenu):
    lancer, site, lien = _banc(tmp_path, expose=False, retenu=retenu)
    autre = tmp_path / "etc/nginx/sites-available/autre.conf"
    autre.write_text("autre vhost\n")
    if forme == "lien_ailleurs":
        os.symlink("../sites-available/autre.conf", lien)
    elif forme == "fichier":
        lien.write_text("posé à la main\n")
    else:                                                                    # notre fichier est lui-même un lien vers ailleurs
        os.symlink("autre.conf", site)
        os.symlink("../sites-available/live.conf", lien)
    for args, code in ((("--mise-a-jour",), 0), ((), 1)):
        r, appels = lancer(*args)
        assert r.returncode == code and appels == [], (args, r.stderr)
        assert autre.read_text() == "autre vhost\n" and lien.read_text() == ("posé à la main\n" if forme == "fichier" else "autre vhost\n")
        assert site.is_symlink() is (forme == "site_lien") and site.exists() is (forme == "site_lien")


def test_exposition_manuelle_et_argument_inconnu(tmp_path):
    lancer, site, lien = _banc(tmp_path, expose=False, retenu="")
    r, appels = lancer("--autre")
    assert r.returncode == 2 and appels == [] and not site.exists()
    r, appels = lancer()
    assert r.returncode == 0 and lien.is_symlink() and "secubox-waf-route live.secubox.in 9080" in appels
    assert (tmp_path / "lib/domaine").read_text() == "live.secubox.in\n"


def test_postinst_mise_a_jour_seulement_rafraichit():
    p = lire("debian/postinst")
    maj = p[p.index('if [ -n "$2" ]'):p.index("    else\n")]
    assert "secubox-live-exposer --mise-a-jour" in maj and maj.count("secubox-live-exposer") == 1


# ------------------------------------------------------------------------------------------------ navigateur

PAYS = [{"code": c, "n": n} for c, n in (("BE", 900), ("US", 800), ("FR", 70), ("DE", 5))]


def etat(**champs):
    e = {"version": 1, "genere_le": int(time.time()) - 30, "etat_global": "degrade",
         "production": {"depuis": "2026-05-04", "historique_depuis": "2026-08-20"},
         "tuiles": {"noeuds_en_ligne": 1, "noeuds_total": 2, "requetes_24h": 9747, "menaces_24h": 32489, "bloquees_24h": 12955,
                    "bans_actifs": 17118, "disponibilite_30j": None, "sites_publies": 132},
         "noeuds": [{"nom": "gk2", "etat": "en ligne", "cpu": 91.4, "memoire": 85, "role": "maître", "materiel": "MOCHAbin", "marche": "x"},
                    {"nom": "gk4", "etat": "hors ligne", "cpu": 43.5, "memoire": 60, "role": "banc", "materiel": "Pi", "marche": "en marche depuis 4 jours"}],
         "waf_heure": [{"rang": i, "bloquees": i % 7} for i in range(60)], "menaces": [{"categorie": "host_anomaly", "n": 17998}],
         "cartes": {"attaques": PAYS, "visiteurs": PAYS[::-1]},
         "histo": [{"jour": f"2026-{m:02d}-{j:02d}", "visites": None if m < 10 else j, "attaques": 3 * j, "bans": j} for m in (9, 10, 11) for j in range(1, 29)],
         "dev": {"fusions_7j": 83, "issues_ouvertes": 740, "ci_master": "success", "dernieres": [{"num": 1, "titre": "feat(x): essai (ref #2)", "le": None}]},
         "feuille_de_route": None}
    e.update(champs)
    return e


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


@pytest.fixture(scope="module")
def serveur():
    class H(http.server.SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header("Content-Security-Policy", csp())            # la CSP de production
            super().end_headers()

        def log_message(self, *a):
            pass
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(H, directory=str(WWW)))
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_address[1]}/"
    s.shutdown()


@pytest.fixture
def ouvrir(navigateur, serveur):
    contextes = []

    def _o(donnees, larg=1280, **ctx):
        """`donnees` : objet (modifiable ensuite par boite['e']), texte brut, ou None (relevé injoignable)."""
        c = navigateur.new_context(viewport={"width": larg, "height": 900}, locale="fr-FR", timezone_id="America/New_York", **ctx)
        contextes.append(c)
        pg, boite = c.new_page(), {"e": donnees}
        pg.erreurs = []
        pg.on("console", lambda m: pg.erreurs.append(m.text) if m.type in ("error", "warning") else None)
        pg.on("pageerror", lambda e: pg.erreurs.append(str(e)))

        def repondre(r):
            e = boite["e"]
            if e is None:
                r.abort()
            else:
                r.fulfill(status=200, content_type="application/json", body=e if isinstance(e, str) else json.dumps(e))
        pg.route("**/etat.json", repondre)
        pg.clock.install()
        pg.goto(serveur)
        pg.wait_for_function("document.getElementById('releve').textContent !== 'relevé en cours…'")
        return pg, boite
    yield _o
    for c in contextes:
        c.close()


def relire(pg):
    with pg.expect_request("**/etat.json"):
        pg.clock.run_for(20500)
    pg.wait_for_timeout(150)


def test_nav_page_complete_sans_erreur_csp(ouvrir):
    for larg in (1280, 400):
        pg, _ = ouvrir(etat(), larg, color_scheme="light")
        assert pg.evaluate("document.documentElement.getAttribute('data-ambiance')") is None         # nuit, même si le système est clair
        assert pg.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(10, 7, 20)"
        assert re.sub(r"\s", "", pg.inner_text("#h-stop")) == "12955"
        assert pg.locator(".tour").count() == 2 and pg.locator("h1").count() == 1
        assert pg.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        assert pg.evaluate("document.fonts.ready.then(() => [...document.fonts].filter(f => f.status === 'loaded').length)") >= 1
        assert pg.erreurs == []
    z = pg.evaluate("(z => [z.scrollLeft, z.scrollWidth - z.clientWidth])(document.getElementById('frise'))")
    assert z[1] > 0 and z[0] >= z[1] - 2                                                             # l'histoire commence à aujourd'hui


def test_nav_hors_ligne_sans_chiffre(ouvrir):
    pg, _ = ouvrir(etat())
    t = pg.locator(".tour[data-k=gk4]")
    for txt in (t.text_content(), t.get_attribute("data-b"), t.get_attribute("aria-label")):
        assert "%" not in txt and "43" not in txt and "60" not in txt and "depuis" not in txt, txt
    assert t.locator("rect[fill='var(--ambre)'], rect[fill='var(--cyan)']").count() == 0
    assert "91 %" in pg.locator(".tour[data-k=gk2]").get_attribute("data-b")


def test_nav_ambiance_retenue(ouvrir, serveur):
    pg, _ = ouvrir(etat())
    pg.click("#ambiance")
    assert pg.inner_text("#ambiance").endswith("Passer à la nuit")
    pg.reload()
    assert pg.evaluate("document.documentElement.getAttribute('data-ambiance')") == "jour"
    pg.click("#ambiance")
    assert pg.evaluate("localStorage.getItem('live-ambiance')") == "nuit"


def test_nav_releve_en_place(ouvrir):
    pg, boite = ouvrir(etat(), 400)
    pg.evaluate("document.getElementById('frise').scrollLeft = 120")
    pg.click("#m-vis")
    pg.evaluate("document.querySelector('.point[data-k=FR]').focus()")
    assert "France" in pg.inner_text("#bulle") and "70" in pg.inner_text("#bulle")
    pg.evaluate("window.ref = document.querySelector('.point[data-k=FR]'); window.t = document.querySelector('.tour[data-k=gk2]')")
    e = etat()
    e["cartes"]["visiteurs"] = [{"code": "JP", "n": 5000}, {"code": "FR", "n": 4321}, {"code": "BE", "n": 4}]   # l'ordre change
    e["tuiles"]["bloquees_24h"] = 13000
    boite["e"] = e
    relire(pg)
    assert re.sub(r"\s", "", pg.inner_text("#h-stop")) == "13000"
    assert pg.evaluate("document.activeElement === window.ref && window.ref.isConnected && window.t.isConnected")
    assert pg.is_visible("#bulle") and "321" in pg.inner_text("#bulle")
    assert pg.get_attribute("#m-vis", "aria-pressed") == "true"
    assert pg.evaluate("document.getElementById('frise').scrollLeft") == 120
    pg.keyboard.press("ArrowRight")
    assert pg.evaluate("document.activeElement.classList.contains('point') && document.activeElement !== window.ref")
    pg.keyboard.press("Escape")
    assert not pg.is_visible("#bulle")
    assert pg.erreurs == []


def test_nav_toucher_ouvre_l_infobulle(ouvrir):
    pg, _ = ouvrir(etat(), 400, has_touch=True, is_mobile=True)
    pg.locator(".tour[data-k=gk2]").tap()
    assert "gk2" in pg.inner_text("#bulle")
    pg.locator("h2").first.tap()
    assert not pg.is_visible("#bulle")


def test_nav_donnees_absentes(ouvrir):
    for e in (dict.fromkeys(etat()), {}, {"tuiles": [], "noeuds": "x", "cartes": 3, "histo": {}, "dev": [], "genere_le": "hier"}):
        pg, _ = ouvrir(e)
        assert pg.inner_text("#h-suite") == "Le compteur fait une pause" and not pg.is_visible("#h-stop")
        assert [pg.inner_text(f"#t-{i}") for i in ("sites", "requetes", "menaces", "bans", "noeuds")] == ["—"] * 5
        assert pg.inner_text("#releve") == "heure du relevé inconnue" and "inconnu" in pg.inner_text("#h-etat")
        for i in ("ville-note", "monde-note", "portes-note", "heure-vide", "term-note", "histo-vide"):
            assert pg.is_visible("#" + i) and pg.inner_text("#" + i), i
        assert not re.search(r"\d", pg.inner_text("#cumuls")) and not re.search(r"\b0\b", pg.inner_text(".billets"))
        assert not pg.is_visible("#bloc-route") and pg.erreurs == []


def test_nav_jour_non_mesure_et_date_utc(ouvrir):
    pg, _ = ouvrir(etat())
    j = pg.locator(".jour[data-k='2026-09-01']").get_attribute("data-b")
    assert j == "1 septembre · visites non mesuré · attaques 3 · bans 1"                              # fuseau à l'ouest : le bon jour
    assert pg.locator(".jour[data-k='2026-09-01'] rect").first.get_attribute("fill") == "var(--trait)"


def test_nav_valeurs_hostiles(ouvrir):
    e = etat(feuille_de_route=[{"nom": "<b>Alpha</b>", "etat": "bientôt"}])
    e["tuiles"].update(bloquees_24h=1e24, menaces_24h=-5, requetes_24h="12", bans_actifs=0)
    e["noeuds"] = [{"nom": "<img src=x onerror=alert(1)>" if i == 0 else f"n{i}", "etat": ("en ligne", "???", None, 42)[i % 4],
                    "cpu": (1e9, -1, "x", None)[i % 4], "memoire": (None, 900, [], 5)[i % 4]} for i in range(20)]
    e["cartes"]["attaques"] = [{"code": "<b>", "n": 9}, {"code": "fr", "n": 1}, {"code": "__proto__", "n": 1}, {"code": "FR", "n": 1e21}, {"code": "ZZ", "n": 2}, None, 3]
    e["menaces"] = [{"categorie": c, "n": 0} for c in ("__proto__", "constructor", "nouvelle_categorie", None)] + [None]
    e["waf_heure"] = [{"bloquees": 0}] * 30 + [{"bloquees": None}]
    e["histo"] = [{"jour": "?", "visites": 0, "attaques": None, "bans": 0}]
    for larg in (1280, 400):
        pg, boite = ouvrir(e, larg)
        assert pg.locator(".tour").count() == 20 and pg.locator("main img").count() == 0 and pg.locator("main b b").count() == 0
        assert pg.locator(".point").count() == 1 and pg.locator("#top li").count() == 2
        assert pg.inner_text("#t-menaces") == "—" and pg.inner_text("#t-requetes") == "—" and pg.inner_text("#t-bans") == "0"
        assert "nouvelle categorie" in pg.inner_text("#portes") and pg.is_visible("#bloc-route")
        assert pg.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        assert pg.locator("[width^='-'], [height^='-'], [r^='-']").count() == 0 and "NaN" not in pg.content()
        boite["e"] = etat(noeuds=[], menaces=[], waf_heure=[], histo=[], cartes={"attaques": [], "visiteurs": []})
        relire(pg)
        assert pg.inner_text("#ville-note") == "Aucun boîtier publié." and pg.inner_text("#monde-note") == "Aucune attaque géolocalisée."
        assert pg.erreurs == []


def test_nav_releve_ancien_et_panne(ouvrir):
    pg, boite = ouvrir(etat(genere_le=int(time.time()) - 5400))
    assert "relevé ancien (90 min)" in pg.inner_text("#releve") and "alerte" in pg.get_attribute("#releve", "class")
    boite["e"] = etat()
    relire(pg)
    assert pg.inner_text("#releve").startswith("relevé du ")
    for panne in (None, "pas du json", "[]", "null"):
        boite["e"] = panne
        relire(pg)
        assert "données momentanément indisponibles · dernier relevé du" in pg.inner_text("#releve"), panne
        assert re.sub(r"\s", "", pg.inner_text("#h-stop")) == "12955"                                 # le dernier relevé reste affiché
    pg, _ = ouvrir(None)
    assert pg.inner_text("#h-suite") == "Le relevé ne répond pas" and pg.inner_text("#term-note") == "Données indisponibles."


def test_nav_mouvement_reduit(ouvrir):
    pg, _ = ouvrir(etat(), reduced_motion="reduce")
    assert pg.evaluate("document.getAnimations().length") == 0
    pg.evaluate("""() => { window.n = 0; const p = CanvasRenderingContext2D.prototype, o = p.clearRect;
                           p.clearRect = function () { window.n++; return o.apply(this, arguments); }; }""")
    pg.clock.run_for(2000)
    assert pg.evaluate("window.n") == 0


def test_nav_pluie_une_seule_boucle(ouvrir):
    pg, _ = ouvrir(etat())
    pg.evaluate("""() => { window.file = new Map(); let n = 0;
        window.requestAnimationFrame = f => { window.file.set(++n, f); return n; };
        window.cancelAnimationFrame = i => window.file.delete(i);
        window.vue = h => { Object.defineProperty(document, 'hidden', { value: h, configurable: true }); document.dispatchEvent(new Event('visibilitychange')); }; }""")
    pg.clock.run_for(300)                                                                             # images en attente
    for _ in range(4):
        pg.evaluate("() => { window.vue(true); window.vue(false); }")
        pg.clock.run_for(300)
        assert pg.evaluate("window.file.size") == 1
    pg.evaluate("window.vue(true)")
    assert pg.evaluate("window.file.size") == 0
