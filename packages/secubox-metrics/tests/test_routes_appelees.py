# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Chaque route qu'une page appelle existe-t-elle dans l'application ? (#1777)

POURQUOI CE FICHIER EXISTE

La fusion 7ebe27403a (branche health-banner perimee) a ecrase main.py avec une
version ancienne : /api/v1/metrics/summary, que la barre laterale de la page
/metrics/ appelle, et les trois routes /api/v1/cookie-audit/* que le bandeau,
sbxwaf, le portail et cookie-inventory.js appellent, ont disparu. Aucun test
n'a proteste : les tests existants construisaient leurs objets eux-memes et ne
lisaient jamais la liste des routes. Ils ont repondu 404 pendant six semaines.

Ce fichier lit les APPELANTS (pages, bandeau, injecteur) et exige que chaque
chemin qu'ils visent soit une route de l'application, avec la bonne methode.
Il fige aussi la garde de chaque route restauree.
"""

import importlib
import re
import sys
from pathlib import Path

import pytest

ICI = Path(__file__).resolve().parent
PAQUET = ICI.parent
DEPOT = PAQUET.parents[1]
WWW = PAQUET / "www" / "metrics"
PAR_PAGE = {
    "index.html": WWW / "index.html",
    "vhosts.html": WWW / "vhosts.html",
}


# ── Import de l'application, hors de toute configuration de la machine ───────

@pytest.fixture(scope="module")
def main(tmp_path_factory):
    """main.py importe avec une configuration jetable.

    Sans cela, `get_*_config()` lirait /etc/secubox/secubox.conf de la machine
    qui lance les tests (illisible sur un poste, absent en CI).
    """
    import secubox_core.config as cfg
    conf = tmp_path_factory.mktemp("conf") / "secubox.conf"
    conf.write_text("[global]\nhostname = 'test'\n")
    anciens = (cfg._CONF_PATHS, cfg._CONFIG)
    cfg._CONF_PATHS = [conf]
    cfg._CONFIG = None
    sys.modules.pop("main", None)
    try:
        yield importlib.import_module("main")
    finally:
        cfg._CONF_PATHS, cfg._CONFIG = anciens
        sys.modules.pop("main", None)


def _routes(app):
    """{(METHODE, motif compile)} des routes de l'application."""
    out = []
    for r in app.routes:
        # Les routeurs inclus (analyse des journaux, /logs) n'ont pas de
        # `path` propre dans les FastAPI recents ; aucune page ne les vise ici.
        if not hasattr(r, "path"):
            continue
        methodes = getattr(r, "methods", None) or set()
        motif = "^" + re.sub(r"\{[^}/]+\}", "[^/]+", r.path) + "$"
        out.append((set(methodes), re.compile(motif), r.path))
    return out


def _existe(app, methode, chemin):
    return any(methode in m and rx.match(chemin) for m, rx, _ in _routes(app))


# ── Ce que les pages appellent ────────────────────────────────────────────────

def _normaliser(brut, api):
    """`${API}/x/${nom}?q=${v}` -> `/api/v1/metrics/x/X`."""
    brut = brut.replace("${API}", api)
    brut = re.sub(r"\$\{[^}]*\}", "X", brut)
    return brut.split("?", 1)[0]


def _appels_de_page(html):
    """[(methode, chemin)] des appels d'API d'une page de metrics."""
    m = re.search(r"const\s+API\s*=\s*['\"]([^'\"]+)['\"]", html)
    assert m, "la page ne declare plus `const API` : adapter ce test"
    api = m.group(1)
    appels = []
    # api('/x') · api(`/x/${y}`, {method: "POST"})
    for lit, suite in re.findall(
            r"\bapi\(\s*(['\"`][^'\"`]+['\"`])\s*(,\s*\{[^}]*\})?\)", html):
        methode = "POST" if re.search(r"method:\s*['\"]POST", suite or "") else "GET"
        appels.append((methode, api + _normaliser(lit[1:-1], api)))
    # fetch(`${API}/x`, {method: "POST", ...})
    for lit, suite in re.findall(
            r"\bfetch\(\s*(`\$\{API\}[^`]+`)\s*(,\s*\{[^}]*\})?", html):
        methode = "POST" if re.search(r"method:\s*['\"]POST", suite or "") else "GET"
        appels.append((methode, _normaliser(lit[1:-1], api)))
    return appels


@pytest.mark.parametrize("page", sorted(PAR_PAGE))
def test_chaque_route_appelee_par_la_page_existe(main, page):
    html = PAR_PAGE[page].read_text(encoding="utf-8")
    appels = _appels_de_page(html)
    assert appels, f"{page} : aucun appel d'API reconnu, l'analyse est a revoir"
    manquants = [(m, c) for m, c in appels if not _existe(main.app, m, c)]
    assert not manquants, f"{page} appelle des routes absentes : {manquants}"


def test_le_widget_de_la_barre_laterale_a_sa_route(main):
    """sidebar.js affiche cpu/mem/load sur /metrics/ via /api/v1/metrics/summary."""
    js = (DEPOT / "packages" / "secubox-hub" / "www" / "shared" / "sidebar.js")
    if not js.is_file():
        pytest.skip("arbre partiel : sidebar.js absent")
    m = re.search(r"'/metrics/'\s*:\s*\{[^}]*api:\s*'([^']+)'", js.read_text(encoding="utf-8"))
    assert m, "sidebar.js ne declare plus d'API pour /metrics/"
    assert _existe(main.app, "GET", m.group(1)), f"{m.group(1)} absente de l'app"


# ── Ce que le bandeau, l'injecteur, le portail et l'inventaire appellent ─────

def _chemins_servis_par_metrics(texte):
    """Chemins /api/v1/metrics/... et /api/v1/cookie-audit/... cites en dur."""
    return sorted(set(re.findall(
        r"/api/v1/(?:metrics|cookie-audit)/[A-Za-z0-9_/-]*[A-Za-z0-9_]", texte)))


APPELANTS = {
    "health-banner.js": ("packages/secubox-hub/www/shared/health-banner.js", "GET"),
    "sbxwaf injectwidget.go": ("packages/secubox-toolbox-ng/cmd/sbxwaf/injectwidget.go", "GET"),
    "portail": ("packages/secubox-portal/www/portal/index.html", "GET"),
    "cookie-inventory.js": ("packages/secubox-hub/www/shared/cookie-inventory.js", "POST"),
}


@pytest.mark.parametrize("nom", sorted(APPELANTS))
def test_les_routes_des_appelants_externes_existent(main, nom):
    rel, methode = APPELANTS[nom]
    f = DEPOT / rel
    if not f.is_file():
        pytest.skip(f"arbre partiel : {rel} absent")
    chemins = _chemins_servis_par_metrics(f.read_text(encoding="utf-8"))
    assert chemins, f"{nom} : aucun chemin metrics reconnu"
    manquants = [c for c in chemins if not _existe(main.app, methode, c)]
    assert not manquants, f"{nom} appelle des routes absentes : {manquants}"


def test_nginx_relaie_les_routes_cookie_audit():
    """Hors de /api/v1/metrics/, nginx envoyait /api/v1/cookie-audit/ a
    l'agregateur, qui ne les connait pas : la route doit etre livree."""
    conf = (PAQUET / "nginx" / "metrics-cookie-audit.conf").read_text(encoding="utf-8")
    assert "location /api/v1/cookie-audit/" in conf
    assert "metrics.sock:/api/v1/cookie-audit/" in conf
    assert "secubox-proxy.conf" in conf, "sans le snippet, pas de verdict LAN"
    rules = (PAQUET / "debian" / "rules").read_text(encoding="utf-8")
    assert "etc/nginx/secubox-routes.d/metrics-cookie-audit.conf" in rules


# ── Gardes des routes restaurees ──────────────────────────────────────────────

def _gardes(app, chemin, methode):
    for r in app.routes:
        if getattr(r, "path", None) == chemin and methode in (getattr(r, "methods", None) or ()):
            vues, pile = set(), list(r.dependant.dependencies)
            while pile:
                d = pile.pop()
                vues.add(getattr(d.call, "__name__", ""))
                pile.extend(d.dependencies)
            return vues
    raise AssertionError(f"{methode} {chemin} absente")


@pytest.mark.parametrize("methode,chemin,garde", [
    ("POST", "/api/v1/cookie-audit/ingest", "require_lecture"),
    ("GET", "/api/v1/cookie-audit/report", "require_jwt"),
    ("GET", "/api/v1/cookie-audit/summary", "require_lecture"),
    ("GET", "/api/v1/metrics/summary", "require_jwt"),
])
def test_chaque_route_restauree_porte_sa_garde(main, methode, chemin, garde):
    assert garde in _gardes(main.app, chemin, methode)


# ── Comportement ──────────────────────────────────────────────────────────────

@pytest.fixture
def client(main):
    from fastapi.testclient import TestClient
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def test_anonyme_hors_lan_ne_peut_ni_ecrire_ni_lire(main):
    """Le harnais (conftest racine) joue un tableau de bord LAN ; ici on retire
    la marque LAN pour jouer un visiteur d'Internet sans jeton."""
    from fastapi.testclient import TestClient
    from secubox_core.auth import ENTETE_LAN
    client = TestClient(main.app, headers={ENTETE_LAN: "0"})
    assert client.post("/api/v1/cookie-audit/ingest",
                       json={"host": "a.fr", "cookies": []}).status_code == 401
    assert client.get("/api/v1/cookie-audit/summary").status_code == 401
    assert client.get("/api/v1/cookie-audit/report").status_code == 401
    assert client.get("/api/v1/metrics/summary").status_code == 401


def test_un_lecteur_lan_n_obtient_pas_le_detail(main, client):
    """require_lecture satisfait (tableau de bord LAN) : le resume oui, le
    rapport detaille non — il reste reserve a l'administrateur."""
    from secubox_core.auth import require_lecture
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": None, "tableau_de_bord": True}
    r = client.get("/api/v1/cookie-audit/summary")
    assert r.status_code == 200
    assert set(r.json()) == {"enabled", "generated_at", "summary"}, "le resume ne doit citer aucun hote"
    assert client.get("/api/v1/cookie-audit/report").status_code == 401


def test_ingest_ecrit_des_empreintes_bornees(main, client, tmp_path, monkeypatch):
    from secubox_core.auth import require_lecture
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": None, "tableau_de_bord": True}
    monkeypatch.setattr(main, "get_cookie_audit_config",
                        lambda: {"enabled": True, "ingest_dir": str(tmp_path)})
    r = client.post("/api/v1/cookie-audit/ingest", json={
        "host": "blog.example.org", "ua": "x" * 5000,
        "cookies": [{"name": "_ga", "value_hash": "ab" * 32}] * 300})
    assert r.status_code == 200 and r.json()["stored"] == 200
    lignes = (tmp_path / "blog.example.org.jsonl").read_text().splitlines()
    assert len(lignes) == 1 and len(lignes[0]) < 20_000

    for mauvais in ("../etc/passwd", "a/b", "a..b", "", "-x.fr", "a b"):
        r = client.post("/api/v1/cookie-audit/ingest", json={"host": mauvais, "cookies": []})
        assert r.status_code == 400, mauvais


def test_ingest_desactive_par_defaut(main, client, monkeypatch):
    from secubox_core.auth import require_lecture
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": None}
    monkeypatch.setattr(main, "get_cookie_audit_config", lambda: {"enabled": False})
    r = client.post("/api/v1/cookie-audit/ingest", json={"host": "a.fr", "cookies": []})
    assert r.status_code == 403


def test_ingest_plafonne_par_hote(main, client, tmp_path, monkeypatch):
    from secubox_core.auth import require_lecture
    main.app.dependency_overrides[require_lecture] = lambda: {"sub": None}
    monkeypatch.setattr(main, "get_cookie_audit_config",
                        lambda: {"enabled": True, "ingest_dir": str(tmp_path)})
    (tmp_path / "a.fr.jsonl").write_bytes(b"x" * main.MAX_INGEST_FILE_BYTES)
    r = client.post("/api/v1/cookie-audit/ingest", json={"host": "a.fr", "cookies": []})
    assert r.status_code == 429


def test_le_resume_systeme_ne_lance_aucun_sous_processus(main, client, monkeypatch):
    """Cache perime : /summary lit /proc, jamais lxc-info/systemctl — il doit
    repondre bien avant le delai d'inactivite de HAProxy."""
    from secubox_core.auth import require_jwt
    main.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(main, "cache_is_fresh", lambda: False)

    # On NOTE les appels au lieu de lever : run_cmd() avale les exceptions, un
    # `raise` ici passerait inapercu.
    lances = []
    monkeypatch.setattr(main.subprocess, "run", lambda *a, **k: lances.append(a))
    r = client.get("/api/v1/metrics/summary")
    assert r.status_code == 200
    assert not lances, f"sous-processus lances par /summary : {lances}"
    d = r.json()
    assert {"cpu", "mem", "load", "_freshness"} <= set(d)
    assert isinstance(d["load"], str)


def test_l_apercu_expose_cpu_pct(main, monkeypatch):
    monkeypatch.setattr(main, "run_cmd", lambda *a, **k: "")
    assert "cpu_pct" in main.build_overview()
