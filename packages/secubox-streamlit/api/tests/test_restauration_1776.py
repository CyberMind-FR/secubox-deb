# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Gardes posées par la restauration #1776 (ref #1748).

Trois fusions du 2026-08-17 ont remplacé `api/main.py`, `sbin/streamlitctl`
et `www/streamlit/index.html` par des copies de branche périmées : le mur
Mosaïque appelait `/apps/audit`, `/recapture` et `/screenshot` qui
n'existaient plus, et personne ne l'a vu. Ce fichier pose ce qui aurait
dû protester :

  - toute route appelée par la page existe dans l'application, et la page
    appelle bien les routes dont le mur a besoin (une page périmée
    re-fusionnée échoue ici aussi) ;
  - le réveil ne bloque ni la boucle d'événements (handler `def`) ni la
    requête au-delà de 25 s (vérification de vivacité bornée, sans
    `git describe` par appli) ;
  - un nom d'appli malformé n'atteint jamais `sudo streamlitctl` ;
  - l'échec d'un réveil de fond est rendu une fois au sondage suivant (504,
    ou 404 pour le code 2 de streamlitctl), puis un clic retente ;
  - l'intégration metoblizer purgée par be25628c7 ne revient pas.
"""
import inspect
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from starlette.routing import Match

from api import main as api_main
from api.main import app
from secubox_core.auth import require_jwt

PAGE = Path(__file__).resolve().parents[2] / "www" / "streamlit" / "index.html"


# ─────────────────────────────────────────────────────────────────────────
# La page et l'application parlent des mêmes routes
# ─────────────────────────────────────────────────────────────────────────

def _premier_argument(src: str, debut: int) -> tuple[str, int]:
    """Expression du premier argument d'un appel dont la parenthèse
    ouvrante précède `debut` ; rend (expression, index après elle)."""
    prof, i, quote = 0, debut, None
    while i < len(src):
        c = src[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            prof += 1
        elif c in ")]}":
            if prof == 0:
                return src[debut:i], i
            prof -= 1
        elif c == "," and prof == 0:
            return src[debut:i], i
        i += 1
    raise AssertionError("appel non refermé dans la page")


def _gabarit(expr: str) -> str | None:
    """Chemin d'une expression JS de chemin : littéraux gardés, parties
    dynamiques remplacées par « x », chaîne de requête retirée. None si
    l'expression ne commence pas par un littéral (ex. `API + path`)."""
    expr = expr.strip()
    if expr.startswith("API"):
        expr = expr[3:].lstrip().lstrip("+").lstrip()
    if not expr or expr[0] not in "'`":
        return None
    morceaux = []
    for m in re.finditer(r"'([^']*)'|`([^`]*)`|([^+'`]+)", expr):
        simple, gabarit, dyn = m.groups()
        if simple is not None:
            morceaux.append(simple)
        elif gabarit is not None:
            morceaux.append(re.sub(r"\$\{[^}]*\}", "x", gabarit))
        elif dyn.strip():
            morceaux.append("x")
    return "".join(morceaux).split("?", 1)[0]


def _appels_de_la_page() -> set[tuple[str, str]]:
    src = PAGE.read_text(encoding="utf-8")
    appels = set()
    for m in re.finditer(r"\b(api|fetch)\(", src):
        expr, fin = _premier_argument(src, m.end())
        chemin = _gabarit(expr)
        if chemin is None or (m.group(1) == "fetch" and not expr.strip().startswith("API")):
            continue
        suite, _ = _premier_argument(src, fin + 1) if src[fin] == "," else ("", fin)
        methode = re.search(r"method:\s*'([A-Z]+)'", suite)
        appels.add(((methode.group(1) if methode else "GET"), chemin))
    # Les vignettes : <img src="' + API + '/apps/' + … + '/screenshot?t=…">
    for m in re.finditer(r"API \+ ('/apps/' \+ encodeURIComponent\(\w+\) \+\s*'/screenshot[^']*')", src):
        appels.add(("GET", _gabarit(m.group(1))))
    return appels


def _route_existe(methode: str, chemin: str) -> bool:
    scope = {"type": "http", "method": methode, "path": chemin, "root_path": ""}
    return any(r.matches(scope)[0] == Match.FULL for r in app.routes)


def test_every_route_the_page_calls_exists_in_the_app():
    appels = _appels_de_la_page()
    assert len(appels) >= 15, f"extraction suspecte, trop peu d'appels : {sorted(appels)}"
    absentes = sorted(f"{m} {p}" for m, p in appels if not _route_existe(m, p))
    assert not absentes, f"la page appelle des routes que l'API ne sert pas : {absentes}"


def test_the_page_still_drives_the_mosaic_routes():
    """Une page périmée re-fusionnée (celle du 2026-08-17 n'avait ni
    vignettes ni recapture) passerait le test précédent sans rien dire :
    on exige aussi que la page APPELLE ce dont le mur a besoin."""
    appels = _appels_de_la_page()
    for attendu in [("GET", "/apps/audit"), ("POST", "/apps/x/wake"),
                    ("POST", "/apps/x/recapture"), ("GET", "/apps/x/screenshot")]:
        assert attendu in appels, f"la page n'appelle plus {attendu}"
    # Réveil non bloquant côté serveur ⇒ la page doit re-sonder tant que la
    # réponse n'est pas "running" (la version périmée lisait UNE réponse).
    page = PAGE.read_text(encoding="utf-8")
    assert "pollWakeUntilRunning" in page
    assert "r.status === 'running'" in page


# ─────────────────────────────────────────────────────────────────────────
# Réveil : hors de la boucle d'événements, borné, existence déléguée
# ─────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_path, monkeypatch):
    fake_ctl = tmp_path / "streamlitctl"
    fake_ctl.write_text("#!/bin/sh\nexit 0\n")
    fake_ctl.chmod(0o755)
    monkeypatch.setattr(api_main, "CTL", str(fake_ctl))
    spawned = []
    monkeypatch.setattr(api_main, "_spawn_shotter",
                         lambda name, force: spawned.append((name, force)))
    api_main._WAKE_IN_PROGRESS.clear()
    api_main._WAKE_ECHECS.clear()
    app.dependency_overrides[require_jwt] = lambda: {"sub": "tester"}
    try:
        yield TestClient(app), spawned
    finally:
        app.dependency_overrides.clear()
        api_main._WAKE_IN_PROGRESS.clear()
        api_main._WAKE_ECHECS.clear()


def test_wake_and_capture_handlers_never_run_on_the_event_loop():
    """La version perdue du réveil était `async def` et appelait
    `_get_apps()` (sudo + lxc-attach) SUR la boucle partagée par
    l'agrégateur. `def` : Starlette les sert depuis son threadpool."""
    for handler in (api_main.wake_app, api_main.app_recapture, api_main.app_screenshot):
        assert not inspect.iscoroutinefunction(handler), handler.__name__


def test_wake_liveness_check_is_bounded_and_skips_git_enrichment(client):
    test_client, _ = client
    vu = {}

    def fake_get_apps(**kw):
        vu.update(kw)
        return [{"name": "foo", "running": True}]

    with patch.object(api_main, "_get_apps", side_effect=fake_get_apps):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 200, r.text
    assert vu.get("enrichir") is False, "pas de git describe par appli sur le chemin du réveil"
    assert vu.get("strict") is True, "un ctl muet ne doit jamais se lire « aucune appli »"
    assert 0 < vu["timeout"] <= 25, "la réponse doit partir avant la coupure HAProxy de 30 s"


def test_recapture_target_resolution_is_bounded(client):
    test_client, _ = client
    vu = {}

    def fake_run_ctl(*args, **kw):
        vu["args"], vu["kw"] = args, kw
        return {"ok": True, "url": "http://10.0.0.5:8501/", "source": "/x"}

    with patch.object(api_main, "_run_ctl", side_effect=fake_run_ctl):
        r = test_client.post("/apps/demo/recapture")

    assert r.status_code == 200, r.text
    assert vu["args"] == ("app", "shot-target", "demo")
    assert 0 < vu["kw"]["timeout"] <= 25


def test_unavailable_liveness_check_delegates_existence_to_app_wake(client):
    """`app list` trop lent ou en échec : ni faux 404 ni faux "running" —
    le réveil est confié à `app wake`, seul juge de l'existence (#959)."""
    test_client, _ = client
    planifie = []

    def fake_add_task(self, func, *a, **kw):
        planifie.append((func, a))

    with patch.object(api_main, "_get_apps", side_effect=RuntimeError("timeout")), \
         patch("starlette.background.BackgroundTasks.add_task", fake_add_task):
        r = test_client.post("/apps/foo/wake")

    assert r.status_code == 200, r.text
    assert r.json()["status"] == "waking"
    assert planifie == [(api_main._do_wake_in_background, ("foo",))]


def _fake_run(rc: int, stderr: bytes):
    def run(cmd, **kw):
        if "wake" in cmd:
            return MagicMock(returncode=rc, stdout=b"", stderr=stderr)
        raise AssertionError(f"appel inattendu : {cmd}")
    return run


def test_background_failure_is_reported_once_then_a_new_wake_is_allowed(client):
    test_client, spawned = client
    endormie = [{"name": "foo", "running": False}]
    with patch.object(api_main, "_get_apps", return_value=endormie), \
         patch("api.main.subprocess.run", side_effect=_fake_run(1, b"wake: foo did not come up within 300s\n")):
        r1 = test_client.post("/apps/foo/wake")   # déclenche ; échoue en fond
        r2 = test_client.post("/apps/foo/wake")   # sondage suivant : l'échec
        r3 = test_client.post("/apps/foo/wake")   # nouveau clic : nouvel essai

    assert r1.status_code == 200 and r1.json()["status"] == "waking"
    assert r2.status_code == 504, r2.text
    assert "did not come up" in r2.json()["detail"]
    assert r3.status_code == 200 and r3.json()["status"] == "waking"
    assert spawned == []


def test_rc2_of_a_background_wake_becomes_the_404_of_the_next_poll(client):
    """Existence déléguée à streamlitctl (#959) : son code 2 est un 404,
    même quand il n'arrive qu'en tâche de fond (liste indisponible)."""
    test_client, _ = client
    with patch.object(api_main, "_get_apps", side_effect=RuntimeError("timeout")), \
         patch("api.main.subprocess.run", side_effect=_fake_run(2, b"App not found: ghost\n")):
        r1 = test_client.post("/apps/ghost/wake")
        r2 = test_client.post("/apps/ghost/wake")

    assert r1.status_code == 200 and r1.json()["status"] == "waking"
    assert r2.status_code == 404, r2.text


def test_a_stale_background_failure_is_forgotten(client, monkeypatch):
    test_client, _ = client
    monkeypatch.setattr(api_main, "WAKE_ECHEC_TTL_S", -1)
    endormie = [{"name": "foo", "running": False}]
    with patch.object(api_main, "_get_apps", return_value=endormie), \
         patch("api.main.subprocess.run", side_effect=_fake_run(1, b"boom\n")):
        test_client.post("/apps/foo/wake")
        r = test_client.post("/apps/foo/wake")
    assert r.status_code == 200 and r.json()["status"] == "waking"


def test_a_running_app_clears_a_pending_failure(client):
    """Réveil lent noté en échec, mais l'appli a fini par monter : le
    sondage suivant dit "running", jamais un 504 périmé."""
    test_client, _ = client
    api_main._wake_noter_echec("foo", 504, "wake failed: trop lent")
    with patch.object(api_main, "_get_apps", return_value=[{"name": "foo", "running": True}]):
        r = test_client.post("/apps/foo/wake")
    assert r.status_code == 200 and r.json()["status"] == "running"
    assert "foo" not in api_main._WAKE_ECHECS


# ─────────────────────────────────────────────────────────────────────────
# Aucun nom malformé n'atteint `sudo streamlitctl`
# ─────────────────────────────────────────────────────────────────────────

NOMS_REFUSES = ["-rf", "--help", ".hidden", "..", "a b", "a;b", "a$(id)", "é", "x" * 129]
NOMS_DE_LA_BOARD = ["yijing", "yijing-360", "yijing.bak.rolledback.20260101",
                    "Photo_cloud_streamlit_main", "fanzine_gk2_lumiere_1", "x" * 128]


@pytest.mark.parametrize("nom", NOMS_REFUSES)
def test_malformed_names_are_refused_before_sudo(client, nom):
    test_client, spawned = client
    with patch("api.main.subprocess.run") as run, \
         patch("api.main.subprocess.Popen") as popen:
        for methode, gabarit in [("POST", "/apps/{}/wake"), ("POST", "/apps/{}/recapture"),
                                 ("POST", "/app/{}/start"), ("POST", "/app/{}/stop"),
                                 ("DELETE", "/app/{}"), ("GET", "/app/{}/logs"),
                                 ("POST", "/instance/{}/start"), ("POST", "/gitea/push/{}")]:
            # Encodage explicite : le client HTTP ne doit pas normaliser
            # « .. » avant qu'il n'atteigne la route.
            chemin = gabarit.format("".join(f"%{b:02X}" for b in nom.encode()))
            r = test_client.request(methode, chemin)
            assert r.status_code == 400, (methode, chemin, r.status_code)
    run.assert_not_called()
    popen.assert_not_called()
    assert spawned == []


@pytest.mark.parametrize("nom", NOMS_DE_LA_BOARD)
def test_real_board_app_names_still_pass(client, nom):
    test_client, _ = client
    with patch.object(api_main, "_get_apps", return_value=[{"name": nom, "running": True}]):
        r = test_client.post(f"/apps/{nom}/wake")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "running"


# ─────────────────────────────────────────────────────────────────────────
# Metoblizer : purgé par be25628c7, il ne revient pas
# ─────────────────────────────────────────────────────────────────────────

def test_presence_events_never_post_to_metoblizer(monkeypatch):
    """Même avec d'anciennes clés `metoblizer_*` dans streamlit.toml, aucun
    événement de présence ne part vers localhost:9300 — ni `urlopen`
    bloquant, ni clé de configuration relayée."""
    monkeypatch.setattr(api_main, "get_config", lambda _m: {"power": {
        "presence_events": False,
        "metoblizer_log": True,
        "metoblizer_endpoint": "http://localhost:9300/api/v1/metoblizer/ingest",
    }})
    with patch("urllib.request.urlopen") as urlopen:
        api_main._emit_presence_event("wake", {"x": 1})
    urlopen.assert_not_called()
    assert not any("metoblizer" in k for k in api_main._cfg())
