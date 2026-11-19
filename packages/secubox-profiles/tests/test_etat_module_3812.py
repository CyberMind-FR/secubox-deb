# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Fiche d'état d'UN module pour le bouton d'état des pages (#3812).

systemctl est remplacé par une sortie `systemctl show` écrite à la main : on
vérifie la forme de la fiche, la raison d'un « HORS LIGNE » (jamais « endormi »
sans sleep_state ni sur une sonde muette), les gardes et la validation de l'id.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "common"))

from fastapi.testclient import TestClient  # noqa: E402

import api.etat_module as em  # noqa: E402
import api.web as web  # noqa: E402

MANIFESTES = {
    "mail": """id = "mail"
category = "media"
runtime = "native"
exposure = "lan"
units = ["secubox-mail.service", "secubox-mail-sync.service"]
lifecycle = "on-demand"
needs = ["vault", "fantome"]
""",
    "vault": """id = "vault"
category = "security"
runtime = "native"
exposure = "internal"
units = ["secubox-vault.service"]
""",
    "radio": """id = "radio"
category = "media"
runtime = "native"
exposure = "lan"
units = ["secubox-radio.service"]
lifecycle = "eager"
needs = ["mail"]
""",
    "fixe": """id = "fixe"
category = "infra"
runtime = "native"
exposure = "lan"
units = ["secubox-fixe.service"]
""",
}


def _bloc(unit, active="active", sub="running", result="success", ufs="enabled", load="loaded"):
    return (f"Id={unit}\nLoadState={load}\nActiveState={active}\nSubState={sub}\n"
            f"Result={result}\nUnitFileState={ufs}\nMainPID=0\n")


def _faux_systemctl(etats: dict):
    """etats : unité -> dict des propriétés à surcharger ; absente = inconnue de systemd."""
    appels = []

    def run(argv):
        appels.append(argv)
        if argv[:2] == ["lxc-ls", "-f"]:
            return 0, ""
        units = [a for a in argv[2:] if a.endswith(".service")]
        blocs = [_bloc(u, **etats[u]) for u in units if u in etats]
        return 0, "\n".join(blocs)
    run.appels = appels
    return run


@pytest.fixture()
def root(tmp_path, monkeypatch):
    d = tmp_path / "modules.d"
    d.mkdir()
    for mid, txt in MANIFESTES.items():
        (d / f"{mid}.toml").write_text(txt)
    (tmp_path / "profiles").mkdir()
    monkeypatch.setenv("SECUBOX_PROFILES_ROOT", str(tmp_path))
    web._module_cache.clear()
    return tmp_path


def _client(monkeypatch, etats):
    monkeypatch.setattr(em, "_run_batch", _faux_systemctl(etats))
    c = TestClient(web.app)
    c.app.dependency_overrides[web.require_jwt] = lambda: {"sub": "admin"}
    return c


def _tous_actifs():
    return {u: {} for u in ("secubox-mail.service", "secubox-mail-sync.service",
                            "secubox-vault.service", "secubox-radio.service", "secubox-fixe.service")}


def test_garde_jwt_reelle(root):
    c = TestClient(web.app)
    c.app.dependency_overrides.clear()
    assert c.get("/api/v1/profiles/module/mail").status_code == 401


@pytest.mark.parametrize("mauvais", ["MAIL", "-mail", "mail_x", "a" * 65, "mail.toml", "..", "m%2Fx"])
def test_id_invalide_422_sans_sonde(root, monkeypatch, mauvais):
    c = _client(monkeypatch, _tous_actifs())
    r = c.get(f"/api/v1/profiles/module/{mauvais}")
    assert r.status_code in (404, 422)  # « / » encodé peut ne pas atteindre la route
    assert em._run_batch.appels == []


def test_id_inconnu_404(root, monkeypatch):
    c = _client(monkeypatch, _tous_actifs())
    assert c.get("/api/v1/profiles/module/inconnu").status_code == 404


def test_forme_module_eveille(root, monkeypatch):
    c = _client(monkeypatch, _tous_actifs())
    r = c.get("/api/v1/profiles/module/mail")
    assert r.status_code == 200
    f = r.json()
    for cle in ("id", "lifecycle", "sleep_state", "sleepable", "etat", "etat_global", "unites",
                "dependances", "raison", "wake_budget_s", "cached_at", "age_s"):
        assert cle in f, cle
    assert f["etat"] == "eveille" and f["sleep_state"] == "up" and f["sleepable"] is True
    assert [u["unite"] for u in f["unites"]] == ["secubox-mail.service", "secubox-mail-sync.service"]
    assert all(u["etat"] == "actif" for u in f["unites"])
    deps = {d["id"]: d for d in f["dependances"]}
    assert deps["vault"]["etat"] == "eveille" and deps["vault"]["connue"] is True
    assert deps["fantome"]["connue"] is False and deps["fantome"]["etat"] == "absente"
    # Dépendance sans manifeste = panne déclarée, pas « endormie ».
    assert f["raison"] == {"code": "dependance_en_panne", "dependance": "fantome"}
    assert f["etat_global"] == "dependance"


def test_module_endormi(root, monkeypatch):
    e = _tous_actifs()
    e["secubox-mail.service"] = {"active": "inactive", "sub": "dead", "ufs": "disabled"}
    e["secubox-mail-sync.service"] = {"active": "inactive", "sub": "dead"}
    f = _client(monkeypatch, e).get("/api/v1/profiles/module/mail").json()
    assert f["sleep_state"] == "asleep"
    assert f["etat"] == "endormi" and f["raison"] == {"code": "endormi"}


def test_echec_prime_sur_le_sommeil(root, monkeypatch):
    e = _tous_actifs()
    e["secubox-mail.service"] = {"active": "inactive", "sub": "dead", "ufs": "disabled"}
    e["secubox-mail-sync.service"] = {"active": "failed", "sub": "failed", "result": "exit-code"}
    f = _client(monkeypatch, e).get("/api/v1/profiles/module/mail").json()
    assert f["sleep_state"] == "asleep"
    assert f["etat"] == "echec"
    assert f["raison"] == {"code": "echec", "unite": "secubox-mail-sync.service"}
    assert f["unites"][1]["result"] == "exit-code"


def test_sonde_muette_jamais_endormi(root, monkeypatch):
    # systemctl ne répond pas : la fiche dit « inconnu », jamais « endormi ».
    monkeypatch.setattr(em, "_run_batch", lambda argv: (None, ""))
    c = TestClient(web.app)
    c.app.dependency_overrides[web.require_jwt] = lambda: {"sub": "admin"}
    f = c.get("/api/v1/profiles/module/radio").json()
    assert f["etat"] == "inconnu"
    assert f["raison"]["code"] != "endormi"
    assert all(u["etat"] == "inconnu" for u in f["unites"])


def test_module_permanent_arrete(root, monkeypatch):
    e = _tous_actifs()
    e["secubox-fixe.service"] = {"active": "inactive", "sub": "dead"}
    f = _client(monkeypatch, e).get("/api/v1/profiles/module/fixe").json()
    assert f["sleep_state"] == "n/a" and f["sleepable"] is False
    assert f["etat"] == "arrete" and f["raison"] == {"code": "arrete"}


def test_dependance_endormie(root, monkeypatch):
    e = _tous_actifs()
    e["secubox-mail.service"] = {"active": "inactive", "sub": "dead"}
    e["secubox-mail-sync.service"] = {"active": "inactive", "sub": "dead"}
    f = _client(monkeypatch, e).get("/api/v1/profiles/module/radio").json()
    assert f["etat"] == "eveille" and f["etat_global"] == "dependance"
    assert f["raison"] == {"code": "dependance_endormie", "dependance": "mail"}
    assert f["dependances"][0]["sleepable"] is True


def test_unite_absente(root, monkeypatch):
    e = _tous_actifs()
    e["secubox-fixe.service"] = {"load": "not-found", "active": "inactive", "sub": "dead"}
    f = _client(monkeypatch, e).get("/api/v1/profiles/module/fixe").json()
    assert f["unites"][0]["etat"] == "absente"


def test_une_seule_sonde_systemctl_et_cache(root, monkeypatch):
    c = _client(monkeypatch, _tous_actifs())
    c.get("/api/v1/profiles/module/mail")
    n = len(em._run_batch.appels)
    # observe_all (1re unité) + une seule commande détaillée pour toutes les unités.
    assert n == 2
    detail = em._run_batch.appels[1]
    assert detail[:2] == ["systemctl", "show"] and "secubox-vault.service" in detail
    c.get("/api/v1/profiles/module/mail")
    assert len(em._run_batch.appels) == n  # servi par le cache


def test_reveil_vide_le_cache_de_la_fiche(root, monkeypatch):
    c = _client(monkeypatch, _tous_actifs())
    c.get("/api/v1/profiles/module/mail")
    assert any(k[1] == "mail" for k in web._module_cache)

    class P:
        returncode = 0
        stdout = '{"status":"woken","module":"mail"}'
        stderr = ""
    monkeypatch.setattr(web, "_ctl_run", lambda argv, **kw: P())
    c.app.dependency_overrides[web.require_session] = lambda: {"sub": "admin"}
    assert c.post("/api/v1/profiles/wake", json={"module": "mail"}).status_code == 200
    assert not any(k[1] == "mail" for k in web._module_cache)


def test_etat_unite_classes():
    assert em.etat_unite(None) == "inconnu"
    assert em.etat_unite({"ActiveState": "activating"}) == "demarrage"
    assert em.etat_unite({"ActiveState": "deactivating"}) == "arret"
    assert em.etat_unite({"ActiveState": "reloading"}) == "actif"
    assert em.etat_unite({"ActiveState": "bizarre"}) == "inconnu"
