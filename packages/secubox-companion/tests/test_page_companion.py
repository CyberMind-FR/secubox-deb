# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Page /companion/ dans un vrai navigateur : box simulée par routes Playwright, version.json factice."""
import json
import mimetypes
from pathlib import Path
from urllib.parse import urlparse

import pytest

WWW = Path(__file__).resolve().parents[1] / "www/companion"
playwright = pytest.importorskip("playwright.sync_api")

SHA = "ab" * 32
VERSION = {"version": "2.0", "version_code": 7, "sha256": SHA, "taille": 3133544, "fichier": "secubox-companion.apk"}
LIEN = "secubox://associer?box=https%3A%2F%2Fadmin.gk12.secubox.in"


@pytest.fixture(scope="module")
def navigateur():
    with playwright.sync_playwright() as pw:
        b = pw.chromium.launch()
        yield b
        b.close()


def ouvre(navigateur, url, version=VERSION, largeur=420, ua=None):
    options = {"user_agent": ua} if ua else {}
    ctx = navigateur.new_context(viewport={"width": largeur, "height": 800}, ignore_https_errors=True, **options)
    p = ctx.new_page()
    erreurs = []
    p.on("pageerror", lambda e: erreurs.append(str(e)))
    p.on("console", lambda m: erreurs.append(m.text) if m.type == "error" else None)

    def sert(route):
        chemin = urlparse(route.request.url).path
        if chemin.startswith("/shared/"):                      # menu latéral de l'hôte : hors sujet ici
            return route.fulfill(status=200, content_type="text/plain", body="")
        nom = chemin.removeprefix("/companion/") or "index.html"
        if nom == "version.json":
            if version is None:
                return route.fulfill(status=404, body="")
            return route.fulfill(status=200, content_type="application/json", body=json.dumps(version))
        f = WWW / nom
        if not f.is_file():
            return route.fulfill(status=404, body="")
        return route.fulfill(status=200, content_type=mimetypes.guess_type(nom)[0] or "text/plain", body=f.read_bytes())
    p.route("**/*", sert)
    p.goto(url)
    p.wait_for_load_state("networkidle")
    return ctx, p, erreurs


def test_https_nomme_lien_qr_version_et_telechargement(navigateur):
    ctx, p, err = ouvre(navigateur, "https://admin.gk12.secubox.in/companion/?embed=1")
    assert p.get_attribute("#ouvrir", "href") == LIEN
    assert p.locator("#qr svg rect").count() > 100
    assert p.is_visible("#qr svg")
    texte = p.inner_text("#infos")
    assert "2.0" in texte and SHA in texte and "3,0 Mo" in texte.replace(" ", " ").replace("\xa0", " ")
    assert p.get_attribute("#telecharger", "href") == "secubox-companion.apk"
    assert p.eval_on_selector("#telecharger", "a => new URL(a.href).pathname") == "/companion/secubox-companion.apk"
    assert p.is_hidden("#adresseRequise")
    assert p.evaluate("document.documentElement.scrollWidth") <= 420
    assert not err
    ctx.close()


def test_adresse_ip_en_http_sans_lien(navigateur):
    ctx, p, err = ouvre(navigateur, "http://192.168.1.200/companion/")
    assert p.locator("a[href^='secubox://']").count() == 0
    assert p.is_hidden("#associer") and p.is_visible("#adresseRequise")
    assert "adresse https de la box" in p.inner_text("#adresseRequise")
    assert p.locator("#qr svg").count() == 0
    assert p.evaluate("document.documentElement.scrollWidth") <= 420
    ctx.close()


def test_adresse_ip_en_https_sans_lien(navigateur):
    ctx, p, _ = ouvre(navigateur, "https://192.168.1.200/companion/")
    assert p.locator("a[href^='secubox://']").count() == 0 and p.is_visible("#adresseRequise")
    ctx.close()


def test_version_json_absent_dit_indisponible(navigateur):
    ctx, p, _ = ouvre(navigateur, "https://admin.gk12.secubox.in/companion/", version=None)
    assert "indisponibles" in p.inner_text("#etatVersion")
    assert p.get_attribute("#ouvrir", "href") == LIEN          # le lien ne dépend pas de version.json
    ctx.close()


def test_empreinte_invalide_non_affichee(navigateur):
    ctx, p, _ = ouvre(navigateur, "https://admin.gk12.secubox.in/companion/", version=dict(VERSION, sha256="<b>x</b>"))
    assert p.locator("#infos b").count() == 0
    ctx.close()


def test_pas_d_innerhtml_ni_donnee_en_html():
    for f in ("index.html", "qrcode.js"):
        src = (WWW / f).read_text(encoding="utf-8")
        for interdit in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
            assert interdit not in src.replace("jamais par innerHTML", ""), (f, interdit)


def test_page_complete_sans_embed_tient_dans_420_px(navigateur):
    # Sans ?embed=1 : le menu latéral de l'hôte n'est pas chargé ici (/shared/ vide), seul le cadre de la page est rendu.
    ctx, p, _ = ouvre(navigateur, "https://admin.gk12.secubox.in/companion/")
    assert not p.evaluate("document.body.classList.contains('emb')")
    assert p.evaluate("document.documentElement.scrollWidth") <= 420
    ctx.close()


@pytest.mark.parametrize("hote", ["localhost", "box.local", "admin.gk12.local", "intranet", "[::1]"])
def test_noms_locaux_sans_lien(navigateur, hote):
    ctx, p, _ = ouvre(navigateur, "https://%s/companion/" % hote)
    assert p.locator("a[href^='secubox://']").count() == 0 and p.is_visible("#adresseRequise")
    assert p.locator("#qr svg").count() == 0
    ctx.close()


def test_nom_de_domaine_avec_point_a_un_lien(navigateur):
    ctx, p, _ = ouvre(navigateur, "https://gk12.secubox.in/companion/")
    assert p.get_attribute("#ouvrir", "href") == "secubox://associer?box=https%3A%2F%2Fgk12.secubox.in"
    ctx.close()


def test_dans_l_appli_ni_telechargement_ni_association(navigateur):
    ctx, p, err = ouvre(navigateur, "https://admin.gk12.secubox.in/companion/",
                        ua="Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36 SecuBoxCompanion/2.0")
    assert p.is_hidden("#telecharger") and p.is_hidden("#ouvrir") and p.is_hidden("#associer") and p.is_hidden("#adresseRequise")
    assert p.locator("#qr svg").count() == 0
    assert "Vous êtes dans l'appli. Pour la mettre à jour, ouvrez cette page dans le navigateur du téléphone." in p.inner_text("#dansAppli")
    assert "2.0" in p.inner_text("#infos")                  # la version reste affichée
    assert not err
    ctx.close()


def test_hors_appli_le_message_est_cache(navigateur):
    ctx, p, _ = ouvre(navigateur, "https://admin.gk12.secubox.in/companion/")
    assert p.is_hidden("#dansAppli") and p.is_visible("#telecharger")
    ctx.close()
