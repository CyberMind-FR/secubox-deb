# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Les épingles 'off' sont RESPECTÉES, pas seulement enregistrées (#1028)."""
import pytest

from api.diff import Change, changements_epingles
from api.state import OFF, ON


def ch(mid, action="stop"):
    return Change(id=mid, action=action, reason="", priority=0)


def test_seuls_les_epingles_off_sont_retenus():
    plan = [ch("glances"), ch("appstore"), ch("vault")]
    pins = {"glances": OFF, "vault": OFF}  # appstore : absent du profil, pas épinglé
    gardes = [c.id for c in changements_epingles(plan, pins, OFF)]
    assert gardes == ["glances", "vault"]


def test_un_epingle_on_n_est_pas_emporte():
    # ALLUMER n'est jamais fait par une minuterie : démarrer des services sur
    # une board dont on ne sait rien de la charge reste une décision manuelle.
    plan = [ch("billets", "start"), ch("glances", "stop")]
    pins = {"billets": ON, "glances": OFF}
    assert [c.id for c in changements_epingles(plan, pins, OFF)] == ["glances"]


def test_sans_epingle_rien_n_est_retenu():
    assert changements_epingles([ch("a"), ch("b")], {}, OFF) == []


def test_le_filtre_ne_replanifie_pas():
    # On filtre le plan produit par plan_changes, on n'en fabrique pas un
    # second : un planificateur parallèle finirait par diverger sur la
    # protection des modules ou sur l'ordre.
    plan = [ch("a"), ch("b"), ch("c")]
    out = changements_epingles(plan, {"a": OFF, "c": OFF}, OFF)
    assert all(c in plan for c in out)
    assert [c.id for c in out] == ["a", "c"]


# ── Le waker ─────────────────────────────────────────────────────────────

def test_le_waker_refuse_de_reveiller_un_epingle(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "profiles").mkdir(parents=True)
    (tmp_path / "profiles" / "pins.toml").write_text('"glances" = "off"\n')
    from api import waker
    assert waker._epingle_off("glances") is True
    assert waker._epingle_off("billets") is False


def test_un_pins_illisible_ne_bloque_pas_tous_les_reveils(tmp_path, monkeypatch):
    # Transformer une erreur de syntaxe en panne générale serait un remède
    # pire que le mal : on ne sait pas, donc on laisse le comportement d'avant.
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    (tmp_path / "profiles").mkdir(parents=True)
    (tmp_path / "profiles" / "pins.toml").write_text("ceci n'est pas du toml [[[")
    from api import waker
    assert waker._epingle_off("glances") is False


def test_la_reponse_dit_que_c_est_voulu(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    from api import waker
    r = waker._reponse_epingle("glances")
    corps = bytes(r.body).decode()
    assert r.status_code == 503
    assert "glances" in corps
    # Le point essentiel : ne PAS faire patienter pour un réveil qui n'aura
    # pas lieu. Une page d'attente mentirait.
    assert "pas une panne" in corps and "ne se rallumera pas" in corps


# ── Le cas qui échappait au plan ─────────────────────────────────────────

def test_un_epingle_arrete_mais_encore_active_est_vu():
    """`is_on` vaut `enabled ET active` : un module arrêté à la main mais resté
    `enabled` passait pour déjà éteint, et revenait au prochain démarrage."""
    from api.diff import epingles_encore_activees
    from api.manifest import Manifest
    from api.observe import Actual

    manifests = {"glances": Manifest(id="glances", category="x", runtime="systemd", exposure="lan",
                             units=("secubox-glances",))}
    actuals = {"glances": Actual(enabled=True, active=False)}
    out = epingles_encore_activees(manifests, {"glances": OFF}, actuals)
    assert [c.id for c in out] == ["glances"]
    assert "encore activé" in out[0].reason


def test_un_epingle_deja_desactive_n_est_pas_repris():
    from api.diff import epingles_encore_activees
    from api.manifest import Manifest
    from api.observe import Actual
    manifests = {"g": Manifest(id="g", category="x", runtime="systemd", exposure="lan", units=("u",))}
    actuals = {"g": Actual(enabled=False, active=False)}
    assert epingles_encore_activees(manifests, {"g": OFF}, actuals) == []


def test_un_epingle_encore_allume_est_laisse_au_plan():
    # Le plan normal s'en charge : le reprendre ici le mettrait deux fois.
    from api.diff import epingles_encore_activees
    from api.manifest import Manifest
    from api.observe import Actual
    manifests = {"g": Manifest(id="g", category="x", runtime="systemd", exposure="lan", units=("u",))}
    actuals = {"g": Actual(enabled=True, active=True)}
    assert epingles_encore_activees(manifests, {"g": OFF}, actuals) == []


def test_un_module_protege_n_est_jamais_repris():
    from api.diff import epingles_encore_activees
    from api.manifest import Manifest
    from api.observe import Actual
    manifests = {"auth": Manifest(id="auth", category="x", runtime="systemd", exposure="lan",
                          units=("u",), protected=True)}
    actuals = {"auth": Actual(enabled=True, active=False)}
    assert epingles_encore_activees(manifests, {"auth": OFF}, actuals) == []
