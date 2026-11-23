# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3885 : toutes les pages d'erreur sortent de scripts/pages-erreur.py (la mire). Pages à jour, errorfile HAProxy sous le tampon,
marqueurs et espaces réservés de sbxwaf présents, aucune ressource externe ni JavaScript, et la 404 jamais posée sur un vhost
qui intercepte les erreurs d'API."""
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[2]
SCRIPT = RACINE / "scripts" / "pages-erreur.py"
PACKAGES = RACINE / "packages"
HUB = PACKAGES / "secubox-hub"
WAF = PACKAGES / "secubox-toolbox-ng" / "cmd" / "sbxwaf" / "templates"

_spec = importlib.util.spec_from_file_location("pages_erreur", SCRIPT)
pe = importlib.util.module_from_spec(_spec)
sys.modules["pages_erreur"] = pe   # dataclasses exige le module enregistré
_spec.loader.exec_module(pe)

PAGES = [RACINE / p.chemin for p in pe.PAGES]
# HAProxy refuse un errorfile plus grand que tune.bufsize (16384 par défaut, non réglé dans haproxyctl) moins la réserve
# de réécriture (tune.maxrewrite, 1024) : on garde une large marge.
LIMITE_HTTP = 12 * 1024


def test_les_pages_du_depot_sont_celles_du_modele():
    r = subprocess.run([sys.executable, str(SCRIPT), "--verifier"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_verifier_detecte_une_page_modifiee_ou_absente(tmp_path):
    assert subprocess.run([sys.executable, str(SCRIPT), "--racine", str(tmp_path)], capture_output=True).returncode == 0
    page = tmp_path / pe.PAGES[0].chemin
    page.write_text(page.read_text() + " ")
    (tmp_path / pe.PAGES[1].chemin).unlink()
    r = subprocess.run([sys.executable, str(SCRIPT), "--verifier", "--racine", str(tmp_path)], capture_output=True, text=True)
    assert r.returncode == 1
    assert pe.PAGES[0].chemin in r.stderr and pe.PAGES[1].chemin in r.stderr


def test_toutes_les_sorties_attendues():
    attendus = {f"packages/secubox-hub/errorpages/{c}.html" for c in (404, 421, 500, 502, 503, 504)}
    attendus |= {f"packages/secubox-haproxy/errors/{c}.http" for c in (400, 403, 408, 500, 502, 503, 504)}
    attendus |= {f"packages/secubox-toolbox-ng/cmd/sbxwaf/templates/{n}.html"
                 for n in ("error-502", "error-503", "error-504", "waf-avertissement", "waf-banni")}
    assert {p.chemin for p in pe.PAGES} == attendus


def test_haproxy_ne_regle_pas_le_tampon():
    assert "bufsize" not in (PACKAGES / "secubox-haproxy" / "sbin" / "haproxyctl").read_text()


@pytest.mark.parametrize("page", [p for p in PAGES if p.suffix == ".http"], ids=lambda p: p.name)
def test_errorfile_haproxy_sous_le_tampon_et_en_tetes(page):
    brut = page.read_bytes()
    assert len(brut) < LIMITE_HTTP
    entetes, _, corps = brut.decode().partition("\n\n")
    lignes = entetes.split("\n")
    assert re.fullmatch(rf"HTTP/1\.1 {page.stem} [A-Za-z ]+", lignes[0])
    assert "Connection: close" in lignes and "Content-Type: text/html; charset=utf-8" in lignes
    assert any(ligne.startswith("Cache-Control: no-store") for ligne in lignes)
    assert corps.startswith("<!DOCTYPE html>")


@pytest.mark.parametrize("page", PAGES, ids=lambda p: str(p.relative_to(PACKAGES)))
def test_page_autonome_accessible(page):
    t = page.read_text()
    assert '<html lang="fr">' in t
    assert 'role="img"' in t and '<title id="t">' in t and '<desc id="d">' in t
    assert '<p class="tech">' in t                     # l'explication est du vrai texte HTML
    assert not re.search(r"\son[a-z]+\s*=", t)          # aucun gestionnaire d'événement en ligne
    assert "<script" not in t.lower()
    assert not re.search(r"""(?:src|href)\s*=\s*["']?\s*(?:https?:)?//""", t, re.I)
    assert "@import" not in t and "url(" not in t
    code = re.search(r'class="code"[^>]*>(\d{3}) · ', t)
    assert code, "ligne du code absente de la mire"


@pytest.mark.parametrize("p", pe.PAGES, ids=lambda p: p.chemin.rsplit("/", 1)[-1])
def test_la_ligne_du_code_tient_dans_le_cercle(p):
    texte = f"{p.erreur.code} · {p.erreur.phrase.upper()}"
    taille = pe.taille_police(texte)
    assert len(texte) * (0.6 * taille + 2) <= pe.LARGEUR_MAX


def test_503_se_rafraichit_toutes_les_15_secondes():
    assert '<meta http-equiv="refresh" content="15">' in (HUB / "errorpages" / "503.html").read_text()


def test_sbxwaf_espaces_reserves_et_marqueurs():
    for n in ("error-502", "error-503", "error-504"):
        t = (WAF / f"{n}.html").read_text()
        assert "{host}" in t and "{time}" in t and n[-3:] in t
    avert = (WAF / "waf-avertissement.html").read_text()
    banni = (WAF / "waf-banni.html").read_text()
    assert "<!-- sbxwaf-warning -->" in avert and "{categorie}" in avert and "sbxwaf-banned" not in avert
    assert "<!-- sbxwaf-banned -->" in banni and "sbxwaf-warning" not in banni


def test_le_paquet_hub_installe_toutes_les_pages_html():
    regles = (HUB / "debian" / "rules").read_text()
    assert "install -m 0644 errorpages/*.html debian/secubox-hub/etc/secubox/errorpages/" in regles
    assert (HUB / "errorpages" / "404.html").is_file()


def _code_nginx(f: Path) -> str:
    return "\n".join(ligne.split("#", 1)[0] for ligne in f.read_text(errors="replace").splitlines())


def test_le_snippet_commun_ne_porte_pas_la_404():
    """Le snippet commun est inclus là où les erreurs d'API sont interceptées : une 404 y remplacerait leur JSON."""
    t = _code_nginx(HUB / "nginx" / "snippets" / "secubox-errorpages.conf")
    assert not re.search(r"error_page[^;]*\b404\b", t)
    assert "/_sbx_404.html" in _code_nginx(HUB / "nginx" / "snippets" / "secubox-errorpages-404.conf")


def test_la_404_jamais_sur_un_vhost_qui_intercepte():
    fautifs = []
    for f in [*PACKAGES.rglob("*.conf"), *PACKAGES.rglob("*.tpl"), *PACKAGES.rglob("*.py"), *(RACINE / "deploy").rglob("*.conf")]:
        if set(f.parts) & {"_gocache", "_gopath", "vendor", "node_modules", "tests"} or f.name == "secubox-errorpages-404.conf":
            continue
        t = _code_nginx(f) if f.suffix != ".py" else f.read_text(errors="replace")
        if "secubox-errorpages-404.conf" not in t:
            continue
        if re.search(r"proxy_intercept_errors\s+on", t) or "secubox-waking.conf" in t or "secubox-routes.d" in t:
            fautifs.append(str(f.relative_to(RACINE)))
    assert not fautifs, f"404 HTML posée sur un vhost qui intercepte les erreurs amont : {fautifs}"
