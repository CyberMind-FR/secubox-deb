# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3581 — routes de l'API : gardes, validation de q, sortie bornée et nettoyée, /reload par fichier de demande (aucun sudo,
aucun sous-processus)."""
import io
import json
import socket
import urllib.error
from pathlib import Path

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


# ── /reload : dépôt d'une demande, résultat posé par le contrôleur root ──

@pytest.fixture
def depot(api_mod, monkeypatch, tmp_path):
    d, r = tmp_path / "searxng-reload", tmp_path / "searxng-reload-resultats"
    d.mkdir()
    r.mkdir()
    monkeypatch.setattr(api_mod, "DEMANDES", d)
    monkeypatch.setattr(api_mod, "RESULTATS", r)
    return d, r


def controleur(api_mod, monkeypatch, depot, code=0, resultat=None, vues=None):
    """Joue secubox-searxng-reload.service à la première attente de l'API : consomme la demande, pose le résultat."""
    d, r = depot

    def dormir(_pause):
        for f in sorted(d.glob("*.demande")):
            if vues is not None:
                vues.append((f.name, json.loads(f.read_text())))
            f.unlink()
            (r / (f.name[: -len(".demande")] + ".json")).write_text(json.dumps({"code": code, "resultat": resultat}))
    monkeypatch.setattr(api_mod, "_dormir", dormir)


def test_api_sans_sudo_ni_sous_processus():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text(encoding="utf-8")
    code = "\n".join(x for x in src.splitlines() if not x.lstrip().startswith("#"))
    assert "subprocess" not in code and "sudo" not in code.replace("pseudo", "") and "systemd-run" not in code
    assert not (Path(__file__).resolve().parents[1] / "sudoers.d").exists()


def test_reload_applique(client, api_mod, monkeypatch, depot):
    vues = []
    controleur(api_mod, monkeypatch, depot, 0, {"issue": "applique", "sha256": "ab"}, vues)
    r = client.post("/reload")
    assert r.status_code == 200 and r.json()["issue"] == "applique"
    assert len(vues) == 1 and vues[0][1] == {"acteur": "alice"}
    assert api_mod._NOM_DEMANDE.fullmatch(vues[0][0])
    assert list(depot[0].iterdir()) == []                      # aucun temporaire laissé
    assert api_mod.DELAI_RELOAD == 30.0


@pytest.mark.parametrize("code,issue,attendu", [(3, "retour-arriere", 409), (3, "refuse", 409), (4, "conteneur-arrete", 409),
                                                (5, "occupe", 409), (1, "echec", 502), (2, "refuse", 502)])
def test_reload_issues(client, api_mod, monkeypatch, depot, code, issue, attendu):
    controleur(api_mod, monkeypatch, depot, code, {"issue": issue, "detail": "d"})
    r = client.post("/reload")
    assert r.status_code == attendu and r.json()["detail"]["issue"] == issue


def test_reload_sans_resultat_dans_le_delai_202(client, api_mod, monkeypatch, depot):
    monkeypatch.setattr(api_mod, "DELAI_RELOAD", 0.05)
    monkeypatch.setattr(api_mod, "_dormir", lambda _p: None)
    r = client.post("/reload")
    assert r.status_code == 202
    d = r.json()
    assert d["issue"] == "en-cours" and "audit" in d["detail"] and (depot[0] / f"{d['demande']}.demande").is_file()


def test_reload_deja_demande_409(client, api_mod, depot):
    (depot[0] / ("0" * 16 + ".demande")).write_text('{"acteur": "bob"}')
    r = client.post("/reload")
    assert r.status_code == 409 and r.json()["detail"]["issue"] == "occupe"
    assert [x.name for x in depot[0].iterdir()] == ["0" * 16 + ".demande"]


def test_reload_sans_depot_503(client, api_mod, monkeypatch, tmp_path):
    monkeypatch.setattr(api_mod, "DEMANDES", tmp_path / "absent")
    r = client.post("/reload")
    assert r.status_code == 503 and "secubox-searxng-reload.path" in r.json()["detail"]["detail"]


def test_reload_resultat_lien_ignore(client, api_mod, monkeypatch, depot, tmp_path):
    d, r = depot
    leurre = tmp_path / "leurre.json"
    leurre.write_text(json.dumps({"code": 0, "resultat": {"issue": "applique"}}))

    def dormir(_pause):
        for f in d.glob("*.demande"):
            lien = r / (f.name[: -len(".demande")] + ".json")
            if not lien.is_symlink():
                lien.symlink_to(leurre)
    monkeypatch.setattr(api_mod, "_dormir", dormir)
    monkeypatch.setattr(api_mod, "DELAI_RELOAD", 0.05)
    assert client.post("/reload").status_code == 202


@pytest.mark.parametrize("sub", ["x\n;reboot", "alice\n", "a b", ""])
def test_reload_acteur_non_conforme_neutralise(api_mod, monkeypatch, depot, tmp_path, sub):
    from secubox_core.auth import require_jwt

    vues = []
    monkeypatch.setattr(api_mod, "CONFIG", str(tmp_path / "absent.toml"))
    controleur(api_mod, monkeypatch, depot, 0, {"issue": "applique"}, vues)
    api_mod.app.dependency_overrides[require_jwt] = lambda: {"sub": sub}
    try:
        TestClient(api_mod.app).post("/reload")
    finally:
        api_mod.app.dependency_overrides.clear()
    assert vues[0][1] == {"acteur": "?"}
