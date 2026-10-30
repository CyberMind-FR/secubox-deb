# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3126, L5 tâche 1 : le porteur DÉLÉGUÉ du pilotage dans `secubox_core.auth`.

Sur une box légère, les pages d'administration sont servies par le maître ; leurs appels `/api/v1/…` arrivent par le
canal, puis le relais local `sbx-pilotage-relais` frappe un jeton de 60 s (HS256, secret de la box, `aud` = nom de
la box, `sub` = `pilotage:<admin>@<maître>`, réclamation `pilotage = {acteur, maitre, portee}`) et appelle la socket
du module en posant `X-SecuBox-Pilotage-Relais`.

Ce jeton n'est PAS une session : il n'est jamais dans le registre des sessions, il est reconnu par sa forme, et
seulement quand la requête arrive par une socket Unix de module, avec l'en-tête du relais (que nginx, HAProxy et
l'agrégateur effacent). Il n'ouvre jamais une route qui crée ou modifie des comptes, des secrets ou des sessions.
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from pathlib import Path

import httpx
import jwt
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from starlette.requests import Request

from secubox_core import auth

SECRET = "secret-de-la-box-gk5"
BOX = "gk5"
ENTETE = "X-SecuBox-Pilotage-Relais"
REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def box(monkeypatch, tmp_path):
    """Une box `gk5`, son secret, aucun compte local nommé `pilotage:…`, AUCUNE session vivante, trace en fichier."""
    monkeypatch.setattr(auth, "_secret", lambda: SECRET)
    monkeypatch.setattr(auth, "nom_box_locale", lambda: BOX, raising=False)
    monkeypatch.setattr(auth, "_session_validator", lambda jti: False)
    monkeypatch.setattr(auth.user_store, "is_enabled", lambda s: s == "gk2")
    monkeypatch.setattr(auth.user_store, "get_user",
                        lambda s: {"role": "admin", "enabled": True} if s == "gk2" else None)
    monkeypatch.setattr(auth.appareils, "est_admis", lambda s: False)
    trace = tmp_path / "delegation.log"
    monkeypatch.setenv("SECUBOX_TRACE_DELEGATION", str(trace))
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    return trace


def frappe(portee="admin", aud=BOX, duree=60, sub="pilotage:gerald@gk2", reclamation=None, secret=SECRET,
           iat=None, sans=()):
    """Ce que frappe le relais (tâche 2)."""
    maintenant = int(time.time()) if iat is None else iat
    p = {"sub": sub, "aud": aud, "iat": maintenant, "exp": maintenant + duree,
         "pilotage": reclamation if reclamation is not None else {"acteur": "gerald", "maitre": "gk2", "portee": portee}}
    for k in sans:
        p.pop(k, None)
    return jwt.encode(p, secret, algorithm="HS256")


def requete(methode="GET", chemin="/status", relais=True, serveur=("/run/secubox/demo.sock", None), cookies=None,
            entetes=None):
    h = dict(entetes or {})
    if relais:
        h[ENTETE] = "1"
    brut = [(k.lower().encode(), str(v).encode()) for k, v in h.items()]
    if cookies:
        brut.append((b"cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()).encode()))
    return Request({"type": "http", "method": methode, "path": chemin, "raw_path": chemin.encode(),
                    "query_string": b"", "headers": brut, "server": serveur, "client": None, "scheme": "http",
                    "root_path": ""})


def _cred(jeton):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=jeton)


def garde(nom, req, jeton):
    """Rend (statut, payload) : 200 si la garde passe, sinon le code de l'HTTPException."""
    try:
        p = asyncio.run(getattr(auth, nom)(req, _cred(jeton) if jeton else None))
        return 200, p
    except HTTPException as e:
        return e.status_code, None


def lignes(trace: Path):
    return [json.loads(x) for x in trace.read_text(encoding="utf-8").splitlines()] if trace.exists() else []


# ── Le chemin nominal, sur une VRAIE socket Unix servie par uvicorn ────────────────────────────────────────────────
def _app():
    app = FastAPI()

    @app.get("/status")
    def lire(p=Depends(auth.require_jwt)):
        return {"sub": p["sub"]}

    @app.post("/regler")
    def regler(p=Depends(auth.require_jwt)):
        return {"sub": p["sub"]}

    return app


@pytest.fixture
def socket_du_module(monkeypatch):
    """Le module `demo` servi par uvicorn sur `<dossier>/demo.sock` (le dossier des sockets du module, ici court :
    un chemin AF_UNIX est borné à 108 octets)."""
    import tempfile

    import uvicorn
    dossier = Path(tempfile.mkdtemp(prefix="sbx3126-"))
    monkeypatch.setattr(auth, "DOSSIER_SOCKETS", str(dossier), raising=False)
    chemin = dossier / "demo.sock"
    serveur = uvicorn.Server(uvicorn.Config(_app(), uds=str(chemin), log_level="warning", lifespan="off"))
    t = threading.Thread(target=serveur.run, daemon=True)
    t.start()
    for _ in range(200):
        if serveur.started:
            break
        time.sleep(0.02)
    try:
        yield httpx.Client(transport=httpx.HTTPTransport(uds=str(chemin)), base_url="http://localhost")
    finally:
        serveur.should_exit = True
        t.join(5)
        chemin.unlink(missing_ok=True)
        dossier.rmdir()


def test_jeton_pilotage_accepte_par_la_socket_du_relais(socket_du_module):
    client = socket_du_module
    h = {"Authorization": f"Bearer {frappe()}", ENTETE: "1"}
    r = client.get("/status", headers=h)
    assert r.status_code == 200, r.text
    assert r.json() == {"sub": "pilotage:gerald@gk2"}
    assert client.post("/regler", headers=h).status_code == 200       # portée admin : l'écriture passe
    # sans l'en-tête du relais, le même jeton n'est rien
    assert client.get("/status", headers={"Authorization": f"Bearer {frappe()}"}).status_code == 401


def test_jeton_pilotage_valide_au_niveau_du_predicat():
    p = jwt.decode(frappe(), SECRET, algorithms=["HS256"], audience=BOX)
    assert auth.jeton_pilotage_valide(p, requete()) is True
    assert auth.jeton_pilotage_valide(p, requete(relais=False)) is False
    assert auth.jeton_pilotage_valide(p, requete(serveur=("127.0.0.1", 8000))) is False


# ── L'en-tête forgé ────────────────────────────────────────────────────────────────────────────────────────────────
def test_entete_relais_forge_refuse():
    jeton = frappe()
    # par TCP (nginx en écoute réseau, un service ouvert par erreur) : jamais
    for serveur in (("127.0.0.1", 8000), ("testserver", 80), ("::1", 9080), None):
        assert garde("require_jwt", requete(serveur=serveur), jeton)[0] == 401, serveur
    # socket Unix hors du dossier des sockets de modules, ou qui n'est pas une socket de module
    for chemin in ("/tmp/demo.sock", "/run/secubox/../demo.sock", "/run/secubox/sous/demo.sock",
                   "/run/secubox/demo", "/run/secubox/.sock"):
        assert garde("require_jwt", requete(serveur=(chemin, None)), jeton)[0] == 401, chemin
    # en-tête vide (c'est ce que pose nginx : `proxy_set_header … ""`)
    assert garde("require_jwt", requete(relais=False, entetes={ENTETE: ""}), jeton)[0] == 401
    # le jeton délégué dans le COOKIE : jamais (le relais le porte en Bearer ; le cookie suit le navigateur)
    st, _ = garde("require_jwt", requete(cookies={auth.SESSION_COOKIE: jeton}), None)
    assert st == 401
    # l'en-tête seul, avec un jeton ordinaire d'une AUTRE box ou d'un autre secret : rien
    assert garde("require_jwt", requete(), frappe(secret="autre-secret")) [0] == 401


def test_nginx_commun_vide_l_entete_du_relais():
    snippet = (REPO / "common" / "nginx" / "secubox-proxy.conf").read_text(encoding="utf-8")
    assert f'proxy_set_header   {ENTETE} "";' in snippet


def test_jeton_pilotage_jamais_accepte_par_verify():
    """L'`auth_request` de nginx (vhosts protégés) n'est pas un chemin du relais : le jeton délégué y est refusé."""
    from fastapi.testclient import TestClient as TC
    app = FastAPI()
    app.include_router(auth.router)
    r = TC(app).get("/verify", headers={"Authorization": f"Bearer {frappe()}", ENTETE: "1"})
    assert r.status_code == 401


# ── Validation du jeton : tout est requis, échec fermé ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("jeton", [
    pytest.param(frappe(duree=61), id="61s"),
    pytest.param(frappe(duree=3600), id="1h"),
    pytest.param(frappe(iat=int(time.time()) - 120, duree=60), id="expire"),
    pytest.param(frappe(iat=int(time.time()) + 3600, duree=60), id="iat-futur"),
    pytest.param(frappe(aud="gk4"), id="autre-box"),
    pytest.param(frappe(aud=["gk5", "gk4"]), id="aud-liste"),
    pytest.param(frappe(sans=("aud",)), id="sans-aud"),
    pytest.param(frappe(sans=("iat",)), id="sans-iat"),
    pytest.param(frappe(sans=("exp",)), id="sans-exp"),
    pytest.param(frappe(sub="gk2"), id="sub-compte-local"),
    pytest.param(frappe(sub="pilotage:"), id="sub-vide"),
    pytest.param(frappe(sub="xpilotage:gerald@gk2"), id="sub-prefixe"),
    pytest.param(frappe(reclamation={}), id="reclamation-vide"),
    pytest.param(frappe(reclamation={"acteur": "gerald", "maitre": "gk2"}), id="sans-portee"),
    pytest.param(frappe(reclamation={"acteur": "", "maitre": "gk2", "portee": "admin"}), id="acteur-vide"),
    pytest.param(frappe(reclamation={"acteur": "gerald", "portee": "admin"}), id="sans-maitre"),
    pytest.param(frappe(portee="root"), id="portee-inconnue"),
    pytest.param(frappe(reclamation="admin"), id="reclamation-chaine"),
    pytest.param(frappe(secret="autre"), id="autre-secret"),
    pytest.param(jwt.encode({"sub": "pilotage:g@gk2", "aud": BOX, "iat": int(time.time()), "exp": int(time.time()) + 30,
                             "pilotage": {"acteur": "g", "maitre": "gk2", "portee": "admin"}},
                            SECRET, algorithm="HS512"), id="hs512"),
])
def test_jeton_pilotage_trop_long_refuse(jeton):
    assert garde("require_jwt", requete(), jeton)[0] == 401
    assert garde("require_lecture", requete(), jeton)[0] == 401


def test_jeton_alg_none_refuse():
    maintenant = int(time.time())
    jeton = jwt.encode({"sub": "pilotage:g@gk2", "aud": BOX, "iat": maintenant, "exp": maintenant + 30,
                        "pilotage": {"acteur": "g", "maitre": "gk2", "portee": "admin"}}, None, algorithm="none")
    assert garde("require_jwt", requete(), jeton)[0] == 401


def test_nom_de_box_inconnu_ferme(monkeypatch):
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "", raising=False)
    assert garde("require_jwt", requete(), frappe(aud=""))[0] == 401
    assert garde("require_jwt", requete(), frappe())[0] == 401


def test_nom_box_locale_est_le_nom_court_de_l_hote(monkeypatch):
    monkeypatch.undo()
    monkeypatch.setattr(socket, "gethostname", lambda: "GK5.secubox.in")
    assert auth.nom_box_locale() == "gk5"
    monkeypatch.setattr(socket, "gethostname", lambda: "")
    assert auth.nom_box_locale() == ""


# ── Portée ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_portee_lecture_refuse_l_ecriture():
    lecture = frappe(portee="lecture")
    assert garde("require_lecture", requete("GET"), lecture)[0] == 200
    assert garde("require_lecture", requete("HEAD"), lecture)[0] == 200
    assert garde("require_jwt", requete("GET"), lecture)[0] == 200
    assert garde("require_jwt", requete("HEAD"), lecture)[0] == 200
    for m in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        assert garde("require_jwt", requete(m), lecture)[0] == 403, m
        assert garde("require_session", requete(m), lecture)[0] == 403, m
        assert garde("require_lecture", requete(m), lecture)[0] == 403, m
    # la portée admin écrit
    for m in ("POST", "PUT", "PATCH", "DELETE"):
        assert garde("require_jwt", requete(m), frappe(portee="admin"))[0] == 200, m


def test_coherence_est_admin_reel_et_session_toujours_admin():
    admin = jwt.decode(frappe(portee="admin"), SECRET, algorithms=["HS256"], audience=BOX)
    lecture = jwt.decode(frappe(portee="lecture"), SECRET, algorithms=["HS256"], audience=BOX)
    assert auth.est_admin_reel(admin) is True
    assert auth.session_toujours_admin(admin) is True
    assert auth.est_admin_reel(lecture) is False
    assert auth.session_toujours_admin(lecture) is False
    echu = dict(admin, exp=int(time.time()) - 1)
    assert auth.est_admin_reel(echu) is False and auth.session_toujours_admin(echu) is False
    trop_long = dict(admin, exp=admin["iat"] + 61)
    assert auth.est_admin_reel(trop_long) is False and auth.session_toujours_admin(trop_long) is False
    autre_box = dict(admin, aud="gk4")
    assert auth.est_admin_reel(autre_box) is False
    # jamais une personne (route d'usager : diffuser, parler sous son nom)
    assert auth.est_personne(admin) is False


def test_jeton_pilotage_n_est_pas_une_session(monkeypatch):
    vus = []
    monkeypatch.setattr(auth._sessions, "muter", lambda f: vus.append(f))
    monkeypatch.setattr(auth, "_session_validator", lambda jti: vus.append(jti) or True)
    assert auth._validate_token(frappe()) is None            # le chemin des sessions ne le reconnaît pas
    jeton = jwt.encode({**jwt.decode(frappe(), SECRET, algorithms=["HS256"], audience=BOX), "jti": "abc"},
                       SECRET, algorithm="HS256")
    assert auth._validate_token(jeton) is None               # même avec un jti, jamais une session
    assert garde("require_jwt", requete(), frappe())[0] == 200
    assert vus == []                                         # registre jamais lu, jamais écrit


# ── Exclusions : comptes, secrets, sessions ────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("module", sorted(auth.MODULES_EXCLUS_PILOTAGE) if hasattr(auth, "MODULES_EXCLUS_PILOTAGE")
                         else ["auth"])
def test_module_exclu_refuse_le_jeton_delegue(module):
    req = requete("GET", "/status", serveur=(f"/run/secubox/{module}.sock", None))
    assert garde("require_jwt", req, frappe())[0] == 403
    assert garde("require_lecture", req, frappe(portee="lecture"))[0] == 403


def test_liste_des_modules_exclus():
    attendus = {"auth", "vault", "portal", "assist", "premier-pas", "users", "aggregator", "pilotage", "pilotage-agent",
                "pilotage-canal", "pilotage-relais"}
    assert attendus <= set(getattr(auth, "MODULES_EXCLUS_PILOTAGE", ()))


@pytest.mark.parametrize("chemin", [
    "/api/v1/auth/login", "/api/v1/vault/etat", "/api/v1/portal/login", "/api/v1/users/list",
    "/users", "/users/gk2", "/user/add", "/comptes", "/compte/gk2/role", "/sessions", "/session",
    "/secrets", "/secret/rotate", "/password", "/mot-de-passe", "/totp/enroll", "/mfa", "/2fa",
    "/jeton", "/jetons", "/token", "/tokens", "/api-keys", "/cles", "/keys/rotate", "/passkeys",
    "/webauthn/register", "/coffre", "/delegation", "/Users", "/%75sers", "/x/../users",
])
def test_chemin_exclu_refuse_le_jeton_delegue(chemin):
    for m in ("GET", "POST"):
        assert garde("require_jwt", requete(m, chemin), frappe())[0] == 403, (m, chemin)


@pytest.mark.parametrize("chemin", ["/status", "/api/v1/demo/status", "/rules", "/services/redemarrer"])
def test_chemin_ordinaire_accepte(chemin):
    assert garde("require_jwt", requete("POST", chemin), frappe())[0] == 200


# ── Traçage ────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_trace_avec_acteur(box):
    jeton = frappe(portee="admin")
    assert garde("require_jwt", requete("POST", "/services/redemarrer"), jeton)[0] == 200
    assert garde("require_lecture", requete("GET", "/status"), frappe(portee="lecture"))[0] == 200
    t = lignes(box)
    assert len(t) == 2, t
    assert t[0]["acteur"] == "gerald" and t[0]["maitre"] == "gk2" and t[0]["portee"] == "admin"
    assert t[0]["methode"] == "POST" and t[0]["chemin"] == "/services/redemarrer"
    assert t[0]["compte"] == "pilotage:gerald@gk2" and t[0]["type"] == "pilotage" and t[0]["verdict"] == "accepte"
    assert t[1]["portee"] == "lecture" and t[1]["methode"] == "GET"
    texte = box.read_text(encoding="utf-8")
    assert jeton not in texte and jeton.split(".")[2] not in texte      # jamais le jeton, ni sa signature


def test_trace_des_refus(box):
    garde("require_jwt", requete("POST", "/status"), frappe(portee="lecture"))
    garde("require_jwt", requete("GET", "/users", serveur=("/run/secubox/demo.sock", None)), frappe())
    t = lignes(box)
    assert [x["verdict"] for x in t] == ["refuse", "refuse"], t
    assert all(x["acteur"] == "gerald" for x in t)


def test_trace_impossible_ne_bloque_pas(monkeypatch):
    monkeypatch.setenv("SECUBOX_TRACE_DELEGATION", "/proc/interdit/delegation.log")
    assert garde("require_jwt", requete(), frappe())[0] == 200


# ── Rien ne change pour un jeton ordinaire ─────────────────────────────────────────────────────────────────────────
def test_jeton_ordinaire_inchange(monkeypatch, box):
    monkeypatch.setattr(auth, "_session_validator", lambda jti: True)
    ordinaire = auth.create_token("gk2", jti="s1")
    for relais in (True, False):
        st, p = garde("require_jwt", requete("POST", "/users", relais=relais, serveur=("127.0.0.1", 80)), ordinaire)
        assert st == 200 and p["sub"] == "gk2"
    assert lignes(box) == []                                   # un jeton ordinaire n'est pas tracé comme délégué


def test_tcp_testclient_jeton_ordinaire(monkeypatch):
    monkeypatch.setattr(auth, "_session_validator", lambda jti: True)
    r = TestClient(_app()).post("/regler", headers={"Authorization": f"Bearer {auth.create_token('gk2')}", ENTETE: "1"})
    assert r.status_code == 200
