# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests secubox-waker (activator : splash + one-wake lock + budget)
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import json
import time

from fastapi.testclient import TestClient


def test_waker_up_backend_signals_proxy(monkeypatch, tmp_path):
    import api.waker as waker
    from api.observe import Actual
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n[portal]\ndomain="demo.gk2"\n')
    monkeypatch.setattr(waker, "_observe_one", lambda m: Actual(enabled=True, active=True))
    c = TestClient(waker.app)
    r = c.get("/_wake/demo.gk2")
    assert r.status_code == 200 and r.headers.get("X-Sbx-Wake") == "up"


def test_waker_down_backend_serves_splash_and_fires_one_wake(monkeypatch, tmp_path):
    import api.waker as waker
    from api.observe import Actual
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n[portal]\ndomain="demo.gk2"\n')
    monkeypatch.setattr(waker, "_observe_one", lambda m: Actual(enabled=False, active=False))
    fired = []
    monkeypatch.setattr(waker, "_fire_wake", lambda mid: fired.append(mid))
    c = TestClient(waker.app)
    r = c.get("/_wake/demo.gk2")
    assert r.status_code == 503
    assert "Retry-After" in r.headers and r.headers["Cache-Control"] == "no-store"
    assert fired == ["demo"]                 # exactly one wake fired


def test_waker_unknown_vhost_serves_a_page(monkeypatch, tmp_path):
    """L'invariant a CHANGE en #999, deliberement.

    Le 404 remontait a nginx comme une page brute — c'est ce que voyait
    l'utilisateur sur les vhosts tombes apres un redemarrage. Ce qui reste
    garanti, et que verifie
    test_undeclared_vhost_gets_the_splash_not_a_404, c'est qu'aucun reveil
    n'est declenche pour un module inconnu."""
    import api.waker as waker
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    c = TestClient(waker.app)
    assert c.get("/_wake/nope.gk2").status_code == 503


def test_wake_writes_active_state_file(monkeypatch, tmp_path):
    """The waker must persist its in-memory `_last_wake` set to
    /run/secubox/waker-active.json on each wake it fires, so the sleeper
    (api.sleeper._read_wake_locked, WAKE_LOCK_FILE = same path) can honor an
    in-flight wake and never race-stop a module that was just woken."""
    import api.waker as waker
    from api.observe import Actual
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["demo.service"]\nlifecycle="on-demand"\n[portal]\ndomain="demo.gk2"\n')
    monkeypatch.setattr(waker, "_observe_one", lambda m: Actual(enabled=False, active=False))
    monkeypatch.setattr(waker, "_fire_wake", lambda mid: None)
    active_path = tmp_path / "waker-active.json"
    monkeypatch.setattr(waker, "_WAKE_ACTIVE_PATH", active_path)
    waker._last_wake.clear()

    c = TestClient(waker.app)
    r = c.get("/_wake/demo.gk2")

    assert r.status_code == 503
    assert json.loads(active_path.read_text(encoding="utf-8")) == ["demo"]


def test_wake_active_file_prunes_stale_entries(monkeypatch, tmp_path):
    """An entry older than _WAKE_ACTIVE_TTL_S must not survive into the
    written file (nor linger in _last_wake) — the sleeper must not be told
    a long-gone wake is still in flight."""
    import api.waker as waker
    active_path = tmp_path / "waker-active.json"
    monkeypatch.setattr(waker, "_WAKE_ACTIVE_PATH", active_path)
    monkeypatch.setattr(waker, "_WAKE_ACTIVE_TTL_S", 60.0)
    waker._last_wake.clear()
    now = time.monotonic()
    waker._last_wake["stale"] = now - 120.0
    waker._last_wake["fresh"] = now

    waker._write_wake_active()

    assert json.loads(active_path.read_text(encoding="utf-8")) == ["fresh"]
    assert "stale" not in waker._last_wake


def test_fire_wake_reaps_child_no_zombie(monkeypatch):
    """`_fire_wake` must not leak a <defunct> zombie: without a `.wait()`
    somewhere, the child process it Popen()s is never reaped. This asserts
    the reaper daemon thread is built with target=<popen>.wait, started, and
    that invoking that target actually reaps (via a fake Popen whose .wait()
    flips a flag) — real coverage of the fix, not just an argv assertion."""
    import api.waker as waker

    class FakePopen:
        def __init__(self):
            self.waited = False

        def wait(self):
            self.waited = True

    fake = FakePopen()
    monkeypatch.setattr(waker.subprocess, "Popen", lambda *a, **k: fake)

    started: dict = {}

    class FakeThread:
        def __init__(self, target=None, daemon=None):
            started["target"] = target
            started["daemon"] = daemon

        def start(self):
            started["started"] = True
            started["target"]()  # simulate the reaper thread running

    monkeypatch.setattr(waker.threading, "Thread", FakeThread)

    waker._fire_wake("demo")

    assert started["target"] == fake.wait
    assert started["daemon"] is True
    assert started["started"] is True
    assert fake.waited is True  # reaped — no zombie left behind


def test_fire_wake_wraps_in_systemd_run_fire_and_forget(monkeypatch):
    """The waker runs under ProtectSystem=strict; a plain `sudo` child would
    inherit that sandbox and secubox-wakectl (which writes the 4R snapshot +
    audit and drives systemd/LXC) would see everything outside
    /run/secubox as read-only (EROFS) — the systemd-run caveat from
    MODULE-COMPLIANCE.md. _fire_wake must wrap the call in
    `systemd-run --collect --quiet` (escapes the sandbox into PID 1's
    context) and must NOT use --wait/--pipe: the waker is fire-and-forget,
    it never blocks an HTTP request on the wake's outcome. The sudoers grant
    matches this exact fixed prefix."""
    import api.waker as waker

    captured: dict = {}

    class FakePopen:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv

        def wait(self):
            pass

    monkeypatch.setattr(waker.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(waker.threading, "Thread",
                        lambda target=None, daemon=None: type(
                            "T", (), {"start": lambda self: None})())

    waker._fire_wake("demo")

    argv = captured["argv"]
    assert argv == ["sudo", "-n", "/usr/bin/systemd-run", "--collect", "--quiet",
                    "/usr/sbin/secubox-wakectl", "wake", "demo", "--json"]
    assert "--wait" not in argv
    assert "--pipe" not in argv



# ── 5xx -> reveil, et une page dans tous les cas (#999) ─────────────────────

def test_undeclared_vhost_gets_the_splash_not_a_404(monkeypatch, tmp_path):
    """Un 404 remontait a nginx comme une page brute.

    C'est ce que voyait l'utilisateur sur les vhosts tombes apres un
    redemarrage. On rend la page d'attente — sans reveiller quoi que ce soit :
    wake() refuse les modules inconnus, et c'est une garde voulue."""
    import api.waker as waker
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    fired = []
    monkeypatch.setattr(waker, "_fire_wake", lambda mid: fired.append(mid))
    c = TestClient(waker.app)
    r = c.get("/_wake/inconnu.gk2")
    assert r.status_code == 503, "page d'attente attendue, pas 404"
    assert "text/html" in r.headers.get("content-type", "")
    assert r.headers.get("Retry-After")
    # La garde reste entiere : un 5xx n'est pas un droit de demarrer un
    # service arbitraire.
    assert fired == [], "aucun reveil ne doit partir pour un vhost inconnu"


def test_always_on_vhost_still_reports_a_real_failure(monkeypatch, tmp_path):
    """Un backend cense tourner en permanence n'est pas un endormi : lui servir
    une page d'attente ferait croire a un reveil que personne ne declenchera."""
    import api.waker as waker
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["demo.service"]\nlifecycle="always-on"\n[portal]\ndomain="demo.gk2"\n')
    c = TestClient(waker.app)
    assert c.get("/_wake/demo.gk2").status_code == 502


def test_nginx_snippet_routes_errors_to_the_waker():
    """Le fragment servait un fichier statique : une belle page, et rien
    derriere. Le reveil n'avait lieu que pour les vhosts deja connus."""
    from pathlib import Path
    conf = (Path(__file__).resolve().parents[1] / "nginx"
            / "secubox-waking.conf").read_text()
    assert "error_page 502 503 504 = @sbx_wake;" in conf
    assert "waker.sock" in conf, "l'erreur doit atteindre le waker"
    # Volontairement PAS d'error_page dans @sbx_wake : il interceptait aussi
    # les 502 DELIBERES du waker (panne reelle d'un always-on) et jetait leur
    # corps — l'utilisateur recevait la page brute de nginx, exactement ce que
    # ce fragment existe pour supprimer.
    wake = conf[conf.index("location @sbx_wake"):]
    wake = wake[:wake.index("\n}")]
    # LES COMMENTAIRES SONT ECARTES AVANT DE CONCLURE. Le premier jet cherchait
    # la chaine dans le bloc entier — et le commentaire qui EXPLIQUE l'absence
    # de `error_page` contient forcement le mot. Le test echouait donc sur la
    # documentation de ce qu'il verifiait, et le faire passer aurait demande de
    # retirer l'explication : exactement le mauvais mouvement.
    directives = [l.strip() for l in wake.splitlines()
                  if l.strip() and not l.strip().startswith("#")]
    assert not any("error_page" in d for d in directives), (
        "une directive error_page dans @sbx_wake intercepterait les 502 "
        "DELIBERES du waker et jetterait leur corps")


def test_always_on_failure_returns_a_page_not_an_empty_502(monkeypatch, tmp_path):
    """Un 502 nu s'affiche comme une page brute cote navigateur.

    C'est ce que voyait l'utilisateur sur zigbee : un corps VIDE, aucune
    explication. Le raisonnement etait pourtant juste — un module always-on
    qui ne repond pas ne sera reveille par personne, et lui servir la page
    d'attente ferait esperer un reveil qui n'arriverait jamais. Il manquait
    simplement la troisieme page."""
    import api.waker as waker
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "demo.toml").write_text(
        'id="demo"\ncategory="infra"\nruntime="native"\nexposure="public"\n'
        'units=["demo.service"]\nlifecycle="always-on"\n[portal]\ndomain="demo.gk2"\n')
    c = TestClient(waker.app)
    r = c.get("/_wake/demo.gk2")
    assert r.status_code == 502
    assert len(r.content) > 200, "un corps vide n'explique rien"
    assert "text/html" in r.headers.get("content-type", "")


def test_le_gabarit_de_panne_porte_les_emplacements_contextuels():
    """Le texte n'est plus fige : il est rempli selon l'etat constate.

    Le premier jet affirmait des phrases en dur, dont « rien ne va le relever
    tout seul » — ce qui etait FAUX pour un service qui se relance en boucle,
    et c'est precisement le cas qu'on avait sous les yeux (4050 redemarrages).
    Le gabarit doit donc porter des emplacements, pas des conclusions.
    """
    from pathlib import Path as _P
    import api.waker as waker
    txt = (_P(waker.__file__).resolve().parent.parent / "templates"
           / "down.html").read_text()
    for marque in ("__TITRE__", "__EXPLICATION__", "__ACTION__"):
        assert marque in txt, f"emplacement {marque} absent du gabarit"


def test_un_service_qui_boucle_ne_dit_pas_d_attendre():
    """Inviter a patienter devant une boucle de redemarrage est un contresens.

    Le service a deja echoue des milliers de fois de facon reproductible :
    attendre ne change rien, et `Retry-After` ferait insister le navigateur sur
    une panne qui consomme deja du processeur en continu.
    """
    from api.etat_panne import qualifie, ETAT_BATTEMENT
    import api.etat_panne as ep

    ep._systemctl = lambda u, p, conteneur=None: {
        "SubState": "auto-restart", "ActiveState": "activating",
        "NRestarts": "4050"}.get(p, "")
    p = qualifie("zigbee2mqtt")
    assert p.etat == ETAT_BATTEMENT
    assert p.reessayer is None, "un service qui boucle ne doit pas inviter a reessayer"
    assert "4050" in p.explication, "le nombre de tentatives doit etre dit"


def test_un_service_qui_demarre_invite_a_patienter():
    from api.etat_panne import qualifie, ETAT_DEMARRE
    import api.etat_panne as ep

    ep._systemctl = lambda u, p, conteneur=None: {
        "SubState": "start", "ActiveState": "activating", "NRestarts": "0"}.get(p, "")
    p = qualifie("secubox-x")
    assert p.etat == ETAT_DEMARRE
    assert p.reessayer and p.reessayer > 0


def test_un_504_est_traite_avant_toute_lecture_de_systemd():
    """Le service TOURNE : systemd dirait « active » et ferait conclure a tort.

    Un 504 est une panne de lenteur, pas d'absence. La distinguer evite de
    proposer un redemarrage qui masquerait la cause.
    """
    from api.etat_panne import qualifie, ETAT_LENT
    import api.etat_panne as ep

    ep._systemctl = lambda u, p, conteneur=None: (_ for _ in ()).throw(
        AssertionError("systemd ne doit pas etre interroge pour un 504"))
    p = qualifie("secubox-x", statut_amont=504)
    assert p.etat == ETAT_LENT
    assert "lenteur" in p.explication.lower()


def test_un_service_franchement_arrete_ne_promet_aucun_reveil():
    from api.etat_panne import qualifie, ETAT_ARRETE
    import api.etat_panne as ep

    ep._systemctl = lambda u, p, conteneur=None: {
        "SubState": "dead", "ActiveState": "inactive", "NRestarts": "0"}.get(p, "")
    p = qualifie("secubox-x")
    assert p.etat == ETAT_ARRETE
    assert p.reessayer is None
