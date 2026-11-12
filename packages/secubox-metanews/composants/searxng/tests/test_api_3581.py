# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — routes de l'API : gardes, validation de q, sortie bornée et nettoyée, /reload par sudo à argv exact."""
import io
import json
import socket
import subprocess
import urllib.error

import pytest
from fastapi.testclient import TestClient

from sbx_searxng import recherche as R


class Reponse(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def ouvreur(donnees=None, erreur=None, appels=None):
    def ouvrir(req, timeout):
        if appels is not None:
            appels.append((req.full_url, timeout))
        if erreur is not None:
            raise erreur
        return Reponse(donnees if isinstance(donnees, bytes) else json.dumps(donnees).encode())
    return ouvrir


@pytest.fixture
def client(api_mod, monkeypatch, tmp_path):
    from secubox_core.auth import require_jwt, require_lecture

    monkeypatch.setattr(api_mod, "CONFIG", str(tmp_path / "absent.toml"))   # défauts
    api_mod.app.dependency_overrides[require_jwt] = lambda: {"sub": "alice"}
    api_mod.app.dependency_overrides[require_lecture] = lambda: {"sub": "alice"}
    yield TestClient(api_mod.app)
    api_mod.app.dependency_overrides.clear()


def test_health_publique(api_mod):
    r = TestClient(api_mod.app).get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok", "module": "searxng"}


def test_rechercher_et_reload_exigent_un_administrateur(api_mod):
    c = TestClient(api_mod.app)
    assert c.get("/rechercher", params={"q": "x"}).status_code in (401, 403)
    assert c.post("/reload").status_code in (401, 403)


def test_gardes_declarees():
    import ast
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text(encoding="utf-8")
    gardes = {}
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.FunctionDef):
            for d in n.decorator_list:
                if isinstance(d, ast.Call) and getattr(d.func, "attr", "") in ("get", "post"):
                    gardes[d.args[0].value] = ast.unparse(n)
    assert set(gardes) == {"/health", "/status", "/components", "/engines", "/rechercher", "/reload"}
    for route in ("/status", "/components", "/engines"):
        assert "require_lecture" in gardes[route] and "require_jwt" not in gardes[route]
    for route in ("/rechercher", "/reload"):
        assert "Depends(require_jwt)" in gardes[route]


@pytest.mark.parametrize("q", ["", "   ", "x" * 257, "a\x00b", "a\nb"])
def test_q_refusee(client, q):
    assert client.get("/rechercher", params={"q": q}).status_code == 422


@pytest.mark.parametrize("page", [0, 51, "x"])
def test_page_refusee(client, page):
    assert client.get("/rechercher", params={"q": "ok", "page": page}).status_code == 422


def test_resultats_bornes_et_nettoyes(client, monkeypatch):
    resultats = [{"title": f"T{i}", "url": f"https://ex.example/{i}", "content": "c" * 5000, "engine": "mojeek"} for i in range(40)]
    resultats[0:0] = [{"title": "piège", "url": "javascript:alert(1)"}, {"title": "data", "url": "data:text/html,x"},
                      {"title": "rel", "url": "/relative"}, {"title": "ftp", "url": "ftp://ex.example/f"}, "pas un objet",
                      {"title": "<b>gras</b>", "url": "http://ex.example/gras", "engine": "bing"}]
    appels = []
    monkeypatch.setattr(R, "_OUVREUR", type("O", (), {"open": staticmethod(ouvreur(
        {"results": resultats, "unresponsive_engines": [["brave", "too many requests"]]}, appels=appels))}))
    r = client.get("/rechercher", params={"q": "  été 2026 ", "page": 2})
    assert r.status_code == 200
    d = r.json()
    assert d["nombre"] == 20 and len(d["resultats"]) == 20 and d["ecartes"] == 5
    assert all(set(x) == {"titre", "url", "extrait", "moteur"} for x in d["resultats"])
    assert all(x["url"].startswith(("http://", "https://")) for x in d["resultats"])
    assert d["resultats"][0] == {"titre": "<b>gras</b>", "url": "http://ex.example/gras", "extrait": "", "moteur": "bing"}
    assert all(len(x["extrait"]) <= 600 for x in d["resultats"])
    assert d["moteurs_sans_reponse"] == [{"moteur": "brave", "raison": "too many requests"}]
    url, delai = appels[0]
    assert url.startswith("http://10.100.0.85:8888/search?") and "format=json" in url and "language=fr" in url
    assert "pageno=2" in url and "q=%C3%A9t%C3%A9+2026" in url and delai == 8.0


@pytest.mark.parametrize("erreur,code", [
    (urllib.error.URLError(socket.timeout("timed out")), 504),
    (TimeoutError(), 504),
    (urllib.error.URLError(ConnectionRefusedError()), 503),
    (OSError("no route"), 503),
    (urllib.error.HTTPError("u", 429, "Too Many", {}, None), 502),
])
def test_erreurs_de_searxng_jamais_500(client, monkeypatch, erreur, code):
    monkeypatch.setattr(R, "_OUVREUR", type("O", (), {"open": staticmethod(ouvreur(erreur=erreur))}))
    r = client.get("/rechercher", params={"q": "x"})
    assert r.status_code == code and r.json()["detail"]


@pytest.mark.parametrize("corps", [b"<html>", b'{"results": "x"}', b"[1,2]"])
def test_reponse_invalide_502(client, monkeypatch, corps):
    monkeypatch.setattr(R, "_OUVREUR", type("O", (), {"open": staticmethod(ouvreur(corps))}))
    assert client.get("/rechercher", params={"q": "x"}).status_code == 502


def test_moteurs_de_searxng_puis_repli(client, monkeypatch, api_mod, tmp_path):
    from sbx_searxng import sondes as S

    monkeypatch.setattr(api_mod, "MOTEURS", S.Cache(None, ttl=60))
    config = {"engines": [{"name": "wikipedia", "enabled": True, "categories": ["general"]},
                          {"name": "brave", "enabled": False}, {"name": "bing", "enabled": True}]}
    monkeypatch.setattr(R, "_OUVREUR", type("O", (), {"open": staticmethod(ouvreur(config))}))
    d = client.get("/engines").json()
    assert d["source"] == "searxng" and [m["nom"] for m in d["actifs"]] == ["bing", "wikipedia"]
    monkeypatch.setattr(api_mod, "MOTEURS", S.Cache(None, ttl=60))
    monkeypatch.setattr(R, "_OUVREUR", type("O", (), {"open": staticmethod(ouvreur(erreur=OSError()))}))
    d = client.get("/engines").json()
    assert d["source"] == "configuration" and d["actifs"] is None and d["desactives"] == []


# ── /reload ──

def test_argv_identique_au_sudoers(api_mod):
    from pathlib import Path

    ligne = [x for x in (Path(__file__).resolve().parents[1] / "sudoers.d" / "secubox-searxng").read_text().splitlines()
             if x and not x.startswith("#")]
    assert len(ligne) == 1
    assert ligne[0] == "secubox-searxng ALL=(root) NOPASSWD: " + " ".join(api_mod.ARGV_RELOAD[2:])
    assert api_mod.ARGV_RELOAD[:2] == ["sudo", "-n"]


def _faux_run(code=0, sortie="", exc=None, appels=None):
    def run(argv, **kw):
        if appels is not None:
            appels.append((argv, kw))
        if exc is not None:
            raise exc
        if code:
            raise subprocess.CalledProcessError(code, argv, output=sortie, stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout=sortie, stderr="")
    return run


def test_reload_applique(client, api_mod, monkeypatch):
    appels = []
    monkeypatch.setattr(api_mod.subprocess, "run", _faux_run(sortie='{"issue": "applique", "sha256": "ab"}\n', appels=appels))
    r = client.post("/reload")
    assert r.status_code == 200 and r.json()["issue"] == "applique"
    argv, kw = appels[0]
    assert argv == api_mod.ARGV_RELOAD and kw["timeout"] == api_mod.DELAI_RELOAD and kw["check"] is True
    assert json.loads(kw["input"]) == {"acteur": "alice"}


@pytest.mark.parametrize("code,issue,attendu", [(3, "retour-arriere", 409), (3, "refuse", 409), (4, "conteneur-arrete", 409),
                                                (5, "occupe", 409), (1, "echec", 502)])
def test_reload_issues(client, api_mod, monkeypatch, code, issue, attendu):
    monkeypatch.setattr(api_mod.subprocess, "run", _faux_run(code, json.dumps({"issue": issue, "detail": "d"})))
    r = client.post("/reload")
    assert r.status_code == attendu and r.json()["detail"]["issue"] == issue


def test_reload_delai_depasse_504(client, api_mod, monkeypatch):
    monkeypatch.setattr(api_mod.subprocess, "run", _faux_run(exc=subprocess.TimeoutExpired(["sudo"], 120)))
    assert client.post("/reload").status_code == 504


def test_reload_sans_sudo_503(client, api_mod, monkeypatch):
    monkeypatch.setattr(api_mod.subprocess, "run", _faux_run(exc=FileNotFoundError("sudo")))
    assert client.post("/reload").status_code == 503


def test_reload_acteur_non_conforme_neutralise(api_mod, monkeypatch, tmp_path):
    from secubox_core.auth import require_jwt

    appels = []
    monkeypatch.setattr(api_mod, "CONFIG", str(tmp_path / "absent.toml"))
    monkeypatch.setattr(api_mod.subprocess, "run", _faux_run(sortie='{"issue": "applique"}', appels=appels))
    api_mod.app.dependency_overrides[require_jwt] = lambda: {"sub": "x\n;reboot"}
    try:
        TestClient(api_mod.app).post("/reload")
    finally:
        api_mod.app.dependency_overrides.clear()
    assert json.loads(appels[0][1]["input"]) == {"acteur": "?"}
