# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2476 — SÉCURITÉ : plus aucune route de maillage « locale » sans authentification.

`invite-local` rendait un jeton de jonction (auto-approuvé par défaut) à TOUTE requête : `is_local_request` jugeait local un client sans adresse (socket unix, le chemin
de nginx), et un X-Real-IP / X-Forwarded-For n'est pas une preuve de provenance (le proxy amont ne transmet pas l'adresse du visiteur). Le jeton suffit à /master-link/join
(sans authentification) pour être approuvé et recevoir une identité WireGuard du maillage."""
import pytest
from fastapi.testclient import TestClient

from api import main


@pytest.fixture
def client(monkeypatch):
    main.app.dependency_overrides.clear()                         # pas de contournement : les routes doivent se défendre seules
    appels = []
    monkeypatch.setattr(main, "ml_token_generate", lambda *a, **k: appels.append("jeton") or {"token": "x", "token_hash": "h", "expires": "e", "ttl": 1})
    monkeypatch.setattr(main, "ml_cleanup_tokens", lambda: appels.append("nettoyage") or {"cleaned": 0})
    main._appels_test = appels
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


@pytest.mark.parametrize("entetes", [{}, {"X-Real-IP": "127.0.0.1"}, {"X-Real-IP": "203.0.113.9"}, {"X-Forwarded-For": "127.0.0.1"}])
def test_invite_local_exige_une_authentification_quelle_que_soit_la_provenance_annoncee(client, entetes):
    r = client.post("/master-link/invite-local?ttl=1&auto_approve=true", headers=entetes)
    assert r.status_code in (401, 403) and main._appels_test == []          # aucun jeton n'a été fabriqué


@pytest.mark.parametrize("entetes", [{}, {"X-Real-IP": "127.0.0.1"}, {"X-Forwarded-For": "127.0.0.1"}])
def test_cleanup_local_exige_une_authentification(client, entetes):
    r = client.post("/master-link/cleanup-local", headers=entetes)
    assert r.status_code in (401, 403) and main._appels_test == []


def test_la_confiance_dans_la_provenance_n_existe_plus():
    assert not hasattr(main, "is_local_request")


def test_invite_authentifiee_fonctionne_toujours(client, monkeypatch):
    async def jwt():
        return {"sub": "admin"}
    main.app.dependency_overrides[main.require_jwt] = jwt
    monkeypatch.setattr(main, "get_ml_config", lambda: {"role": "master", "fingerprint": "fp"})
    r = client.post("/master-link/invite-local?ttl=1&auto_approve=false")
    assert r.status_code == 200 and r.json()["token"] == "x" and main._appels_test == ["jeton"]


def test_la_page_d_administration_envoie_le_jwt():
    import pathlib
    h = (pathlib.Path(__file__).resolve().parents[1] / "www" / "master-link" / "admin.html").read_text(encoding="utf-8")
    assert "'Authorization': 'Bearer ' + t" in h and "sbx_token" in h
