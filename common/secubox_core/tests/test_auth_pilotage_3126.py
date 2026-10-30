# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3126, L5 tâche 1 : le porteur DÉLÉGUÉ du pilotage dans `secubox_core.auth`.

Sur une box légère, les pages d'administration sont servies par le maître ; leurs appels `/api/v1/…` arrivent par le
canal, puis le relais local `sbx-pilotage-relais` frappe un jeton de 60 s et appelle la socket du module en posant
`X-SecuBox-Pilotage-Relais`.

R-L5-9 (déroge aux Global Constraints « HS256 + jwt_secret ») : le jeton est signé en Ed25519 (EdDSA) par la clé
PRIVÉE du seul relais ; les modules le vérifient avec la clé PUBLIQUE `/etc/secubox/pilotage/relais.pub`. Les sockets
étant souvent en 0666 et `jwt_secret` lu par tous les modules, un module compromis ne doit pas pouvoir en frapper un.
La réclamation `cible` nomme le module visé, comparée à l'identité du module courant (le fichier source de la route
servie, sous `/usr/lib/secubox/<module>/`). La preuve par la socket (`scope["server"]`) n'est qu'un contrôle de plus :
uvicorn 0.32 (Debian) n'y met rien pour une socket Unix.

Ce jeton n'est PAS une session. Il n'ouvre jamais une route de comptes, de secrets ou de sessions (R-L5-10).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import threading
import time
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from starlette.requests import Request

from secubox_core import auth

SECRET = "secret-de-la-box-gk5-assez-long-pour-hs256"
BOX = "gk5"
ENTETE = "X-SecuBox-Pilotage-Relais"
REPO = Path(__file__).resolve().parents[3]
CLE = Ed25519PrivateKey.generate()          # celle du relais
AUTRE_CLE = Ed25519PrivateKey.generate()    # une autre (autre box, attaquant)
_DEFAUT = object()
#: Ce que le paquet du module `demo` déclarerait ouvert à l'écriture déléguée (R-L5-12).
DECLARATION_DEMO = """
[[routes]]
methodes = ["POST", "PUT", "PATCH", "DELETE"]
chemins = ["^/status$", "^/regler$", "^/services/redemarrer$", "^/rules$", "^/etat$"]
"""


def _pem_publique(cle) -> bytes:
    return cle.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture(autouse=True)
def box(monkeypatch, tmp_path):
    """Une box `gk5`, son secret JWT, la clé publique du relais, aucun compte `pilotage:…`, AUCUNE session vivante,
    trace et audit en fichiers temporaires."""
    monkeypatch.setattr(auth, "_secret", lambda: SECRET)
    monkeypatch.setattr(auth, "nom_box_locale", lambda: BOX, raising=False)
    monkeypatch.setattr(auth, "_session_validator", lambda jti: False)
    monkeypatch.setattr(auth.user_store, "is_enabled", lambda s: s == "gk2")
    monkeypatch.setattr(auth.user_store, "get_user",
                        lambda s: {"role": "admin", "enabled": True} if s == "gk2" else None)
    monkeypatch.setattr(auth.appareils, "est_admis", lambda s: False)
    monkeypatch.setattr(auth, "UID_ROOT", os.getuid(), raising=False)
    cles = tmp_path / "etc-secubox-pilotage"
    cles.mkdir(mode=0o755)
    (cles / "relais.pub").write_bytes(_pem_publique(CLE))
    os.chmod(cles / "relais.pub", 0o644)
    monkeypatch.setattr(auth, "DOSSIER_CLE_RELAIS", str(cles), raising=False)
    routes = tmp_path / "routes-ouvertes.d"
    routes.mkdir(mode=0o755)
    (routes / "demo.toml").write_text(DECLARATION_DEMO, encoding="utf-8")
    os.chmod(routes / "demo.toml", 0o644)
    monkeypatch.setattr(auth, "DOSSIER_ROUTES_OUVERTES", str(routes), raising=False)
    if hasattr(auth, "_invalides"):
        auth._invalides.update(nombre=0, depuis=0.0)
    monkeypatch.setattr(auth, "AUDIT_PILOTAGE", str(tmp_path / "audit.log"), raising=False)
    trace = tmp_path / "delegation.log"
    monkeypatch.setenv("SECUBOX_TRACE_DELEGATION", str(trace))
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    return trace


def frappe(portee="admin", aud=BOX, duree=60, sub="pilotage:gerald@gk2", reclamation=None, cle=CLE, alg="EdDSA",
           iat=None, sans=(), cible="demo"):
    """Ce que frappe le relais (tâche 2)."""
    maintenant = int(time.time()) if iat is None else iat
    p = {"sub": sub, "aud": aud, "iat": maintenant, "exp": maintenant + duree, "cible": cible,
         "pilotage": reclamation if reclamation is not None else {"acteur": "gerald", "maitre": "gk2", "portee": portee}}
    for k in sans:
        p.pop(k, None)
    if alg.startswith("HS"):
        return jwt.encode(p, SECRET, algorithm=alg)
    return jwt.encode(p, cle, algorithm=alg)


def _endpoint(module: str):
    """Une fonction de route dont le source est `/usr/lib/secubox/<module>/api/main.py` (le chemin d'installation)."""
    ns: dict = {}
    exec(compile("def route():\n    return None\n", f"/usr/lib/secubox/{module}/api/main.py", "exec"), ns)
    return ns["route"]


def requete(methode="GET", chemin="/status", relais=True, serveur=_DEFAUT, cookies=None, entetes=None, module="demo",
            endpoint=_DEFAUT):
    h = dict(entetes or {})
    if relais:
        h[ENTETE] = "1"
    brut = [(k.lower().encode(), str(v).encode()) for k, v in h.items()]
    if cookies:
        brut.append((b"cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()).encode()))
    scope = {"type": "http", "method": methode, "path": chemin, "raw_path": chemin.encode("utf-8"),
             "query_string": b"", "headers": brut,
             "server": (f"/run/secubox/{module}.sock", None) if serveur is _DEFAUT else serveur,
             "client": None, "scheme": "http", "root_path": ""}
    ep = _endpoint(module) if endpoint is _DEFAUT else endpoint
    if ep is not None:
        scope["endpoint"] = ep
    return Request(scope)


def _cred(jeton):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=jeton)


def garde(nom, req, jeton):
    """Rend (statut, payload) : 200 si la garde passe, sinon le code de l'HTTPException."""
    try:
        p = asyncio.run(getattr(auth, nom)(req, _cred(jeton) if jeton else None))
        return 200, p
    except HTTPException as e:
        return e.status_code, None


def lignes(fichier: Path):
    return [json.loads(x) for x in fichier.read_text(encoding="utf-8").splitlines()] if fichier.exists() else []


# ── Le chemin nominal, sur une VRAIE socket Unix servie par uvicorn ────────────────────────────────────────────────
_SOURCE_APP = '''
from fastapi import Depends, FastAPI
from secubox_core import auth

app = FastAPI()


@app.get("/status")
def lire(p=Depends(auth.require_jwt)):
    return {"sub": p["sub"], "admin": auth.est_admin_reel(p)}


@app.post("/regler")
def regler(p=Depends(auth.require_jwt)):
    return {"sub": p["sub"]}
'''


def _app_du_module(module="demo"):
    """L'application d'un module tel qu'installé : son source sous `/usr/lib/secubox/<module>/api/main.py`."""
    ns: dict = {}
    exec(compile(_SOURCE_APP, f"/usr/lib/secubox/{module}/api/main.py", "exec"), ns)
    return ns["app"]


@pytest.fixture
def socket_du_module(monkeypatch):
    """Le module `demo` servi par uvicorn sur `<dossier>/demo.sock` (dossier court : AF_UNIX borne à 108 octets)."""
    import tempfile

    import uvicorn
    dossier = Path(tempfile.mkdtemp(prefix="sbx3126-"))
    monkeypatch.setattr(auth, "DOSSIER_SOCKETS", str(dossier), raising=False)
    chemin = dossier / "demo.sock"
    serveur = uvicorn.Server(uvicorn.Config(_app_du_module(), uds=str(chemin), log_level="warning", lifespan="off"))
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
    assert r.json() == {"sub": "pilotage:gerald@gk2", "admin": True}
    assert client.post("/regler", headers=h).status_code == 200       # portée admin : l'écriture passe
    # sans l'en-tête du relais, le même jeton n'est rien
    assert client.get("/status", headers={"Authorization": f"Bearer {frappe()}"}).status_code == 401
    # un jeton visant un autre module, sur cette socket : rien
    assert client.get("/status", headers={"Authorization": f"Bearer {frappe(cible='system')}", ENTETE: "1"}
                      ).status_code == 401


def test_server_absent_accepte_si_signature_et_cible_bonnes():
    """uvicorn 0.32 (Debian trixie) rend `scope["server"] = None` sur une socket Unix : on ne refuse pas pour autant."""
    assert garde("require_jwt", requete(serveur=None), frappe())[0] == 200
    assert garde("require_jwt", requete(serveur=None), frappe(cible="system"))[0] == 401
    assert garde("require_jwt", requete(serveur=None), frappe(cle=AUTRE_CLE))[0] == 401


def test_jeton_pilotage_valide_au_niveau_du_predicat():
    p = jwt.decode(frappe(), _pem_publique(CLE), algorithms=["EdDSA"], audience=BOX)
    assert auth.jeton_pilotage_valide(p, requete()) is True
    assert auth.jeton_pilotage_valide(p, requete(serveur=None)) is True
    assert auth.jeton_pilotage_valide(p, requete(relais=False)) is False
    assert auth.jeton_pilotage_valide(p, requete(serveur=("127.0.0.1", 8000))) is False
    assert auth.jeton_pilotage_valide(p, requete(module="system")) is False


# ── Signature (R-L5-9) ─────────────────────────────────────────────────────────────────────────────────────────────
def test_jeton_hs256_signe_avec_jwt_secret_refuse():
    """Ce que frapperait un module compromis : il lit `jwt_secret`, jamais la clé privée du relais."""
    for alg in ("HS256", "HS384", "HS512"):
        assert garde("require_jwt", requete(), frappe(alg=alg))[0] == 401, alg
        assert garde("require_lecture", requete(), frappe(alg=alg, portee="lecture"))[0] == 401, alg


def test_jeton_hs256_signe_avec_la_cle_publique_refuse(box):
    """Confusion d'algorithme : la clé publique (lisible par tous) employée comme secret HMAC."""
    pem = _pem_publique(CLE)
    maintenant = int(time.time())
    p = {"sub": "pilotage:gerald@gk2", "aud": BOX, "iat": maintenant, "exp": maintenant + 30, "cible": "demo",
         "pilotage": {"acteur": "gerald", "maitre": "gk2", "portee": "admin"}}
    import hashlib
    import hmac
    import base64
    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")
    tete = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    corps = b64(json.dumps(p).encode())
    sig = b64(hmac.new(pem, tete + b"." + corps, hashlib.sha256).digest())
    assert garde("require_jwt", requete(), (tete + b"." + corps + b"." + sig).decode())[0] == 401


def test_ed25519_autre_cle_refuse():
    assert garde("require_jwt", requete(), frappe(cle=AUTRE_CLE))[0] == 401


def test_cible_differente_du_module_refuse():
    assert garde("require_jwt", requete(module="demo"), frappe(cible="system"))[0] == 401
    # le nom de la socket ne fait pas l'identité : socket « system », route servie par « demo »
    assert garde("require_jwt", requete(module="demo", serveur=("/run/secubox/system.sock", None)),
                 frappe(cible="system"))[0] == 401


@pytest.mark.parametrize("cible", [None, "", "Demo", "../demo", "demo/x", 42])
def test_cible_absente_ou_invalide_refuse(cible):
    jeton = frappe(sans=("cible",)) if cible is None else frappe(cible=cible)
    assert garde("require_jwt", requete(), jeton)[0] == 401


@pytest.mark.parametrize("endpoint", [
    None,                                                                    # aucune route résolue
    pytest.param("secubox_core", id="route-du-coeur"),                       # route de secubox_core (auth/login…)
    pytest.param("relatif", id="chemin-relatif"),
])
def test_identite_du_module_inconnue_refuse(endpoint):
    if endpoint == "secubox_core":
        ep = auth.verify
    elif endpoint == "relatif":
        ns: dict = {}
        exec(compile("def route():\n    return None\n", "demo/api/main.py", "exec"), ns)
        ep = ns["route"]
    else:
        ep = None
    assert garde("require_jwt", requete(endpoint=ep), frappe())[0] == 401


def test_identite_du_module_par_le_fichier_de_la_route():
    assert auth.module_courant(requete(module="wireguard")) == "wireguard"
    assert auth.module_courant(requete(endpoint=None)) == ""


def test_cle_publique_absente_refuse(monkeypatch, tmp_path):
    (tmp_path / "etc-secubox-pilotage" / "relais.pub").unlink()
    assert garde("require_jwt", requete(), frappe())[0] == 401


@pytest.mark.parametrize("contenu", [
    b"", b"pas une cle",
    pytest.param(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), id="rsa"),
    pytest.param(b"x" * 100_000, id="trop-gros"),
])
def test_cle_publique_invalide_refuse(monkeypatch, tmp_path, contenu):
    f = tmp_path / "etc-secubox-pilotage" / "relais.pub"
    f.write_bytes(contenu)
    assert garde("require_jwt", requete(), frappe())[0] == 401


def test_cle_publique_jamais_lue_depuis_la_requete(monkeypatch, tmp_path):
    """Aucun en-tête, aucune réclamation (`jku`, `jwk`, `kid`) ne choisit la clé."""
    pirate = tmp_path / "pirate.pub"
    pirate.write_bytes(_pem_publique(AUTRE_CLE))
    maintenant = int(time.time())
    p = {"sub": "pilotage:gerald@gk2", "aud": BOX, "iat": maintenant, "exp": maintenant + 30, "cible": "demo",
         "pilotage": {"acteur": "gerald", "maitre": "gk2", "portee": "admin"}}
    jeton = jwt.encode(p, AUTRE_CLE, algorithm="EdDSA", headers={"kid": str(pirate), "jku": f"file://{pirate}"})
    assert garde("require_jwt", requete(entetes={"X-SecuBox-Cle": str(pirate)}), jeton)[0] == 401


# ── L'en-tête forgé ────────────────────────────────────────────────────────────────────────────────────────────────
def test_entete_relais_forge_refuse():
    jeton = frappe()
    # par TCP (nginx en écoute réseau, un service ouvert par erreur) : jamais
    for serveur in (("127.0.0.1", 8000), ("testserver", 80), ("::1", 9080)):
        assert garde("require_jwt", requete(serveur=serveur), jeton)[0] == 401, serveur
    # socket Unix fournie mais hors du dossier des sockets de modules, ou pas celle du module
    for chemin in ("/tmp/demo.sock", "/run/secubox/../demo.sock", "/run/secubox/sous/demo.sock",
                   "/run/secubox/demo", "/run/secubox/.sock", "/run/secubox/system.sock"):
        assert garde("require_jwt", requete(serveur=(chemin, None)), jeton)[0] == 401, chemin
    # en-tête vide (c'est ce que pose nginx : `proxy_set_header … ""`)
    assert garde("require_jwt", requete(relais=False, entetes={ENTETE: ""}), jeton)[0] == 401
    # le jeton délégué dans le COOKIE : jamais (le relais le porte en Bearer ; le cookie suit le navigateur)
    assert garde("require_jwt", requete(cookies={auth.SESSION_COOKIE: jeton}), None)[0] == 401


def test_nginx_commun_vide_l_entete_du_relais():
    snippet = (REPO / "common" / "nginx" / "secubox-proxy.conf").read_text(encoding="utf-8")
    assert f'proxy_set_header   {ENTETE} "";' in snippet


def test_jeton_pilotage_jamais_accepte_par_verify():
    """L'`auth_request` de nginx (vhosts protégés) n'est pas un chemin du relais : le jeton délégué y est refusé."""
    app = FastAPI()
    app.include_router(auth.router)
    for jeton in (frappe(), frappe(alg="HS256")):
        r = TestClient(app).get("/verify", headers={"Authorization": f"Bearer {jeton}", ENTETE: "1"})
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
    pytest.param(frappe(sub="pilotage:Gerald@gk2"), id="sub-majuscule"),
    pytest.param(frappe(sub="pilotage:gerald@gk2.secubox.in"), id="sub-maitre-fqdn"),
    pytest.param(frappe(sub="pilotage:gérald@gk2"), id="sub-non-ascii"),
    pytest.param(frappe(sub="pilotage:gerald@gk2\n"), id="sub-saut-de-ligne"),
    pytest.param(frappe(sub="pilotage:" + "a" * 65 + "@gk2"), id="sub-trop-long"),
    pytest.param(frappe(sub="pilotage:alice@gk2"), id="sub-autre-que-acteur"),
    pytest.param(frappe(reclamation={}), id="reclamation-vide"),
    pytest.param(frappe(reclamation={"acteur": "gerald", "maitre": "gk2"}), id="sans-portee"),
    pytest.param(frappe(reclamation={"acteur": "", "maitre": "gk2", "portee": "admin"}), id="acteur-vide"),
    pytest.param(frappe(reclamation={"acteur": "gerald", "portee": "admin"}), id="sans-maitre"),
    pytest.param(frappe(reclamation={"acteur": "Gérald", "maitre": "gk2", "portee": "admin"}), id="acteur-motif"),
    pytest.param(frappe(reclamation={"acteur": "gerald", "maitre": "gk2.lan", "portee": "admin"}), id="maitre-motif"),
    pytest.param(frappe(portee="root"), id="portee-inconnue"),
    pytest.param(frappe(reclamation="admin"), id="reclamation-chaine"),
])
def test_jeton_pilotage_trop_long_refuse(jeton):
    assert garde("require_jwt", requete(), jeton)[0] == 401
    assert garde("require_lecture", requete(), jeton)[0] == 401


def test_jeton_alg_none_refuse():
    maintenant = int(time.time())
    jeton = jwt.encode({"sub": "pilotage:gerald@gk2", "aud": BOX, "iat": maintenant, "exp": maintenant + 30,
                        "cible": "demo", "pilotage": {"acteur": "gerald", "maitre": "gk2", "portee": "admin"}},
                       None, algorithm="none")
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
    for m in ("POST", "PUT", "PATCH", "DELETE"):
        assert garde("require_jwt", requete(m), frappe(portee="admin"))[0] == 200, m


def test_est_admin_reel_exige_la_marque_de_la_garde():
    """Un payload délégué n'est administrateur que s'il SORT de la garde : le même contenu décodé ailleurs, non."""
    jeton = frappe(portee="admin")
    brut = jwt.decode(jeton, _pem_publique(CLE), algorithms=["EdDSA"], audience=BOX)
    assert auth.est_admin_reel(brut) is False
    assert auth.session_toujours_admin(brut) is False
    req = requete()
    st, p = garde("require_jwt", req, jeton)
    assert st == 200
    assert auth.est_admin_reel(p) is True and auth.session_toujours_admin(p) is True
    assert req.state.pilotage is p                           # la garde pose sa marque sur la requête
    assert auth.est_admin_reel(dict(p)) is False             # une copie perd la marque
    assert json.loads(json.dumps(p))["sub"] == "pilotage:gerald@gk2"   # reste sérialisable (routes qui rendent `user`)


def test_coherence_est_admin_reel_et_session_toujours_admin():
    _, admin = garde("require_jwt", requete(), frappe(portee="admin"))
    _, lecture = garde("require_jwt", requete(), frappe(portee="lecture"))
    assert auth.est_admin_reel(admin) is True and auth.session_toujours_admin(admin) is True
    assert auth.est_admin_reel(lecture) is False and auth.session_toujours_admin(lecture) is False
    admin["exp"] = int(time.time()) - 1                      # échu depuis : plus administrateur
    assert auth.est_admin_reel(admin) is False and auth.session_toujours_admin(admin) is False
    _, admin2 = garde("require_jwt", requete(), frappe(portee="admin"))
    assert auth.est_personne(admin2) is False                # jamais une personne


def test_jeton_pilotage_n_est_pas_une_session(monkeypatch):
    vus = []
    monkeypatch.setattr(auth._sessions, "muter", lambda f: vus.append(f))
    monkeypatch.setattr(auth, "_session_validator", lambda jti: vus.append(jti) or True)
    assert auth._validate_token(frappe()) is None            # le chemin des sessions ne le reconnaît pas
    assert auth._validate_token(frappe(alg="HS256")) is None
    assert garde("require_jwt", requete(), frappe())[0] == 200
    assert vus == []                                         # registre jamais lu, jamais écrit


# ── Exclusions : comptes, secrets, sessions (R-L5-10) ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("module", sorted(auth.MODULES_EXCLUS_PILOTAGE) if hasattr(auth, "MODULES_EXCLUS_PILOTAGE")
                         else ["auth"])
def test_module_exclu_refuse_le_jeton_delegue(module):
    req = requete("GET", "/status", module=module)
    assert garde("require_jwt", req, frappe(cible=module))[0] == 403
    assert garde("require_lecture", req, frappe(portee="lecture", cible=module))[0] == 403


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
    # R-L5-10 : morceaux de segments, mots ajoutés
    "/reset-password", "/set-password", "/set_password", "/api_key", "/api-key", "/api.key", "/user_tokens",
    "/new-session", "/credential", "/credentials", "/identifiants", "/private", "/privkey", "/private_key",
    "/psk", "/wg-psk", "/restore", "/config/restore/sauvegarde-1", "/backup.restore",
])
def test_chemin_exclu_refuse_le_jeton_delegue(chemin):
    for m in ("GET", "POST"):
        assert garde("require_jwt", requete(m, chemin), frappe())[0] == 403, (m, chemin)


@pytest.mark.parametrize("module,methode,chemin", [
    ("wireguard", "GET", "/peer/alice/config"),
    ("wireguard", "GET", "/peer/alice/qr"),
    ("wireguard", "GET", "/peer/alice/config/"),
    ("wireguard", "GET", "/export/peers"),
    ("wireguard", "GET", "/export"),
    ("wireguard", "GET", "/api/v1/wireguard/peer/alice/config"),
    ("wireguard", "GET", "/api/v1/wireguard/export/peers"),
    ("turn", "GET", "/credentials"),
    ("turn", "POST", "/credentials"),
    ("haproxy", "POST", "/config/restore/sauvegarde-1"),
])
@pytest.mark.parametrize("portee", ["lecture", "admin"])
def test_routes_reelles_de_secrets_refusees(module, methode, chemin, portee):
    st, _ = garde("require_jwt", requete(methode, chemin, module=module), frappe(portee=portee, cible=module))
    assert st == 403, (module, methode, chemin, portee)
    if methode == "GET":
        st, _ = garde("require_lecture", requete(methode, chemin, module=module), frappe(portee=portee, cible=module))
        assert st == 403


@pytest.mark.parametrize("module,chemin", [
    ("demo", "/status"), ("demo", "/api/v1/demo/status"), ("demo", "/rules"), ("demo", "/services/redemarrer"),
    ("wireguard", "/peers"), ("wireguard", "/peers/status"), ("dpi", "/export_flows"), ("ad-guard", "/export"),
    ("haproxy", "/config"),
])
def test_chemin_ordinaire_accepte(module, chemin):
    for portee in ("lecture", "admin"):
        assert garde("require_jwt", requete("GET", chemin, module=module), frappe(cible=module, portee=portee))[0] == 200


# ── Traçage ────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_trace_avec_acteur(box):
    jeton = frappe(portee="admin")
    assert garde("require_jwt", requete("POST", "/services/redemarrer"), jeton)[0] == 200
    assert garde("require_lecture", requete("GET", "/status"), frappe(portee="lecture"))[0] == 200
    t = lignes(box)
    assert len(t) == 2, t
    assert t[0]["acteur"] == "gerald" and t[0]["maitre"] == "gk2" and t[0]["portee"] == "admin"
    assert t[0]["methode"] == "POST" and t[0]["chemin"] == "/services/redemarrer" and t[0]["module"] == "demo"
    assert t[0]["compte"] == "pilotage:gerald@gk2" and t[0]["type"] == "pilotage" and t[0]["verdict"] == "accepte"
    assert t[1]["portee"] == "lecture" and t[1]["methode"] == "GET"
    texte = box.read_text(encoding="utf-8")
    assert jeton not in texte and jeton.split(".")[2] not in texte      # jamais le jeton, ni sa signature


def test_trace_en_ascii(box):
    """Le chemin vient du client : rien que de l'ASCII au journal (ensure_ascii), sauts de ligne échappés."""
    assert garde("require_jwt", requete("GET", "/état\nfaux"), frappe())[0] == 200
    brut = box.read_bytes()
    assert brut.isascii() and brut.count(b"\n") == 1
    assert lignes(box)[0]["chemin"] == "/état\nfaux"


def test_trace_des_refus(box, tmp_path):
    garde("require_jwt", requete("POST", "/status"), frappe(portee="lecture"))
    garde("require_jwt", requete("GET", "/users"), frappe())
    t = lignes(box)
    assert [x["verdict"] for x in t] == ["refuse", "refuse"], t
    assert all(x["acteur"] == "gerald" for x in t)
    audit = lignes(tmp_path / "audit.log")
    assert [x["verdict"] for x in audit] == ["refuse", "refuse"]
    assert all(x["evenement"] == "pilotage_delegue" and x["module"] == "demo" for x in audit)


@pytest.mark.parametrize("jeton", [
    pytest.param(frappe(alg="HS256"), id="hs256"),
    pytest.param(frappe(cle=AUTRE_CLE), id="autre-cle"),
    pytest.param("xxxx.yyyy.zzzz", id="illisible"),
])
def test_jeton_non_signe_par_le_relais_compte_pas_audite(box, tmp_path, monkeypatch, jeton):
    """M1 : un jeton dont la signature n'est pas vérifiée n'est PAS audité (n'importe qui peut en envoyer) ; il est
    compté, et le compte part au journal au plus une fois par minute."""
    horloge = [1000.0]
    monkeypatch.setattr(auth, "_horloge", lambda: horloge[0], raising=False)
    for _ in range(5):
        assert garde("require_jwt", requete("GET", "/status"), jeton)[0] == 401
    assert lignes(tmp_path / "audit.log") == []
    t = lignes(box)
    assert len(t) == 1 and t[0]["verdict"] == "refuse" and t[0]["nombre"] == 1 and "signature" in t[0]["motif"], t
    horloge[0] += 61
    assert garde("require_jwt", requete("GET", "/status"), jeton)[0] == 401
    t = lignes(box)
    assert len(t) == 2 and t[1]["nombre"] == 5, t                 # les 4 suivants + celui-ci
    texte = box.read_text(encoding="utf-8")
    assert jeton not in texte and jeton.split(".")[-1] not in texte


@pytest.mark.parametrize("jeton,motif", [
    pytest.param(frappe(duree=3600), "forme", id="trop-long"),
    pytest.param(frappe(cible="system"), "cible", id="cible"),
    pytest.param(frappe(aud="gk4"), "forme", id="autre-box"),
])
def test_jeton_signe_refuse_est_audite(box, tmp_path, jeton, motif):
    """Signature vérifiée, jeton refusé : tracé ET audité, avec l'acteur, jamais le jeton."""
    assert garde("require_jwt", requete("GET", "/status"), jeton)[0] == 401
    for f in (box, tmp_path / "audit.log"):
        t = lignes(f)
        assert len(t) == 1 and t[0]["verdict"] == "refuse" and motif in t[0]["motif"] and t[0]["acteur"] == "gerald"
        assert jeton not in f.read_text(encoding="utf-8")


def test_pas_de_trace_sans_l_entete(box, tmp_path):
    """Un Bearer périmé sans l'en-tête du relais (le cas courant) n'est pas un usage du pilotage."""
    garde("require_jwt", requete(relais=False), "xxxx.yyyy.zzzz")
    garde("require_jwt", requete(relais=False), frappe(cle=AUTRE_CLE))
    assert lignes(box) == [] and lignes(tmp_path / "audit.log") == []


def test_journal_cite_les_valeurs_du_client_en_repr():
    vu = []

    class _H(logging.Handler):
        def emit(self, record):
            vu.append(record)

    h = _H()
    logging.getLogger("secubox.auth").addHandler(h)
    try:
        garde("require_jwt", requete("GET", "/users\nfaux"), frappe())
    finally:
        logging.getLogger("secubox.auth").removeHandler(h)
    assert vu and "%r" in vu[-1].msg and "%s" not in vu[-1].msg
    assert "'/users\\nfaux'" in vu[-1].getMessage()


def test_trace_impossible_ne_bloque_pas(monkeypatch):
    monkeypatch.setenv("SECUBOX_TRACE_DELEGATION", "/proc/interdit/delegation.log")
    monkeypatch.setattr(auth, "AUDIT_PILOTAGE", "/proc/interdit/audit.log", raising=False)
    assert garde("require_jwt", requete(), frappe())[0] == 200
    assert garde("require_jwt", requete("GET", "/users"), frappe())[0] == 403


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
    r = TestClient(_app_du_module()).post(
        "/regler", headers={"Authorization": f"Bearer {auth.create_token('gk2')}", ENTETE: "1"})
    assert r.status_code == 200


# ── R-L5-12 : écriture FERMÉE par défaut, ouverte route par route par le paquet du module ──────────────────────────
@pytest.mark.parametrize("module,chemin", [("dpi", "/export_flows"), ("wireguard", "/peers"), ("ad-guard", "/export"),
                                           ("haproxy", "/config"), ("system", "/reboot")])
def test_ecriture_sur_un_module_non_declare_refusee(box, tmp_path, module, chemin):
    for m in ("POST", "PUT", "PATCH", "DELETE"):
        assert garde("require_jwt", requete(m, chemin, module=module), frappe(cible=module))[0] == 403, (m, module)
    audit = lignes(tmp_path / "audit.log")
    assert audit and all("declare" in x["motif"] for x in audit)


def test_ecriture_hors_declaration_refusee():
    # module déclaré, route non déclarée ; puis route déclarée, méthode non déclarée
    assert garde("require_jwt", requete("POST", "/autre"), frappe())[0] == 403
    assert garde("require_jwt", requete("POST", "/status/x"), frappe())[0] == 403     # ancré : pas de préfixe


def test_ecriture_route_declaree_acceptee():
    for m in ("POST", "PUT", "PATCH", "DELETE"):
        assert garde("require_jwt", requete(m, "/regler"), frappe())[0] == 200, m
    assert garde("require_jwt", requete("POST", "/api/v1/demo/regler"), frappe())[0] == 200      # préfixe du module
    # la liste de refus reste devant : déclarée ou non, une route de secrets est refusée
    assert garde("require_jwt", requete("POST", "/users"), frappe())[0] == 403


def test_lecture_jamais_soumise_a_la_declaration(tmp_path):
    (tmp_path / "routes-ouvertes.d" / "demo.toml").unlink()
    assert garde("require_jwt", requete("GET", "/status"), frappe())[0] == 200
    assert garde("require_jwt", requete("POST", "/status"), frappe())[0] == 403


@pytest.mark.parametrize("texte", [
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["/regler$"]', id="non-ancre-debut"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/regler"]', id="non-ancre-fin"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/.*$"]', id="point-etoile"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a/.+$"]', id="point-plus"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a.b$"]', id="point-nu"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a$|^/b"]', id="alternative-nue"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a/[^x]+$"]', id="classe-sans-barre"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a/\\\\S+$"]', id="classe-echappee"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a/(?:x)$"]', id="groupe-special"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a/(x|.*)$"]', id="groupe-ouvert"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a/x*$"]', id="etoile"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a/[$"]', id="motif-invalide"),
    pytest.param('[[routes]]\nmethodes = ["GET"]\nchemins = ["^/a$"]', id="methode-lecture"),
    pytest.param('[[routes]]\nmethodes = ["post"]\nchemins = ["^/a$"]', id="methode-minuscule"),
    pytest.param('[[routes]]\nmethodes = []\nchemins = ["^/a$"]', id="methodes-vides"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = []', id="chemins-vides"),
    pytest.param('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/a$"]\nportee = "x"', id="cle-inconnue"),
    pytest.param('autre = 1', id="sans-routes"),
    pytest.param('[[routes]]\nmethodes = "POST"\nchemins = ["^/a$"]', id="methodes-chaine"),
    pytest.param('[[routes', id="toml-invalide"),
])
def test_validateur_refuse_un_fichier_invalide(texte):
    with pytest.raises(ValueError):
        auth.valider_routes_ouvertes(texte)


def test_validateur_accepte_les_motifs_bornes():
    r = auth.valider_routes_ouvertes(
        '[[routes]]\nmethodes = ["POST", "DELETE"]\n'
        'chemins = ["^/a$", "^/allow/[0-9A-Fa-f:]{17}$", "^/x/[^/]+/(essayer|rejeter)$", "^/pare-feu/ipv6$", '
        '"^/f\\\\.json$"]\n')
    assert len(r) == 1 and r[0][0] == frozenset({"POST", "DELETE"}) and len(r[0][1]) == 5


@pytest.mark.parametrize("cas", ["fichier-non-root", "dossier-non-root", "fichier-groupe", "dossier-autres",
                                 "fichier-lien", "invalide"])
def test_declaration_douteuse_ignoree(box, tmp_path, monkeypatch, cas):
    routes = tmp_path / "routes-ouvertes.d"
    f = routes / "demo.toml"
    if cas == "fichier-non-root" or cas == "dossier-non-root":
        monkeypatch.setattr(auth, "UID_ROOT", 0, raising=False)
        cles = tmp_path / "etc-secubox-pilotage"            # la clé reste « root » pour ce test : on l'en distingue
        monkeypatch.setattr(auth, "_proprietaire_attendu", lambda chemin: os.getuid() if str(cles) in chemin else 0,
                            raising=False)
    elif cas == "fichier-groupe":
        os.chmod(f, 0o664)
    elif cas == "dossier-autres":
        os.chmod(routes, 0o757)
    elif cas == "fichier-lien":
        vrai = tmp_path / "ailleurs.toml"
        vrai.write_text(DECLARATION_DEMO, encoding="utf-8")
        f.unlink()
        f.symlink_to(vrai)
    else:
        f.write_text('[[routes]]\nmethodes = ["POST"]\nchemins = ["^/.*$"]\n', encoding="utf-8")
    assert garde("require_jwt", requete("POST", "/regler"), frappe())[0] == 403
    assert garde("require_jwt", requete("GET", "/status"), frappe())[0] == 200


@pytest.mark.parametrize("module", ["system", "nac", "ad-guard", "freebox"])
def test_declarations_livrees_valides_et_reelles(module):
    """Les 4 modules du banc livrent leur déclaration ; elle est valide, chaque motif vise une route d'écriture qui
    existe dans l'API du module, et le paquet l'installe."""
    import itertools
    import re as _re
    paquet = REPO / "packages" / f"secubox-{module}"
    decl = paquet / "pilotage" / "routes-ouvertes.d" / f"{module}.toml"
    routes = auth.valider_routes_ouvertes(decl.read_text(encoding="utf-8"))
    reelles = []                                   # (méthode, motif de la route réelle, paramètres → [^/]+)
    for py in (paquet / "api").rglob("*.py"):
        source = py.read_text(encoding="utf-8")
        prefixes = dict(_re.findall(r"(\w+)\s*=\s*APIRouter\([^)]*prefix=\"([^\"]+)\"", source))
        for objet, methode, chemin in _re.findall(r"@(\w+)\.(post|put|patch|delete)\(\s*\"([^\"]+)\"", source):
            gabarit = _re.sub(r"\\\{[^}]+\\\}", "[^/]+", _re.escape(prefixes.get(objet, "") + chemin))
            reelles.append((methode.upper(), _re.compile(gabarit)))

    def exemples(motif: str):
        """Toutes les chaînes que désigne un motif déclaré (une par alternative), paramètres remplacés."""
        corps = motif[1:-1].replace("[^/]+", "x").replace("[0-9A-Fa-f:]{17}", "aa:bb:cc:dd:ee:ff").replace("\\.", ".")
        morceaux = _re.split(r"\(([^)]*)\)", corps)
        choix = [[m] if k % 2 == 0 else m.split("|") for k, m in enumerate(morceaux)]
        return ["".join(c) for c in itertools.product(*choix)]

    for methodes, motifs in routes:
        for motif in motifs:
            for exemple in exemples(motif.pattern):
                assert motif.fullmatch(exemple), (module, motif.pattern, exemple)
                for m in methodes:
                    assert any(mm == m and r.fullmatch(exemple) for mm, r in reelles), (module, m, exemple)
    regles = " ".join((paquet / "debian" / f).read_text(encoding="utf-8")
                      for f in ("rules", f"secubox-{module}.install") if (paquet / "debian" / f).exists())
    assert "routes-ouvertes.d" in regles


# ── R-L5-13 : la clé publique, dans un arbre root ──────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("cas", ["dossier-non-root", "fichier-non-root", "dossier-groupe", "fichier-autres",
                                 "fichier-lien", "dossier-lien"])
def test_cle_hors_arbre_root_refusee(box, tmp_path, monkeypatch, cas):
    cles = tmp_path / "etc-secubox-pilotage"
    pub = cles / "relais.pub"
    if cas == "dossier-non-root":
        monkeypatch.setattr(auth, "_proprietaire_attendu",
                            lambda chemin: 0 if chemin == str(cles) else os.getuid(), raising=False)
    elif cas == "fichier-non-root":
        monkeypatch.setattr(auth, "_proprietaire_attendu",
                            lambda chemin: 0 if chemin.endswith("relais.pub") else os.getuid(), raising=False)
    elif cas == "dossier-groupe":
        os.chmod(cles, 0o775)
    elif cas == "fichier-autres":
        os.chmod(pub, 0o646)
    elif cas == "fichier-lien":
        vrai = tmp_path / "vraie.pub"
        vrai.write_bytes(_pem_publique(CLE))
        pub.unlink()
        pub.symlink_to(vrai)
    else:
        autre = tmp_path / "autre-dossier"
        cles.rename(autre)
        cles.symlink_to(autre)
    assert garde("require_jwt", requete(), frappe())[0] == 401


def test_chemin_par_defaut_de_la_cle(monkeypatch):
    monkeypatch.undo()
    assert auth.DOSSIER_CLE_RELAIS == "/etc/secubox-pilotage" and auth.NOM_CLE_RELAIS == "relais.pub"


# ── M2, M3 ─────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_cle_refusee_avertie_une_fois_par_empreinte(tmp_path):
    vu = []

    class _H(logging.Handler):
        def emit(self, record):
            vu.append(record.getMessage())

    (tmp_path / "etc-secubox-pilotage" / "relais.pub").write_bytes(b"pas une cle")
    h = _H()
    logging.getLogger("secubox.auth").addHandler(h)
    try:
        for _ in range(3):
            garde("require_jwt", requete(), frappe())
    finally:
        logging.getLogger("secubox.auth").removeHandler(h)
    cle = [m for m in vu if m.startswith("cle publique du relais")]
    assert len(cle) == 1, vu


def test_module_courant_en_cache(monkeypatch):
    appels = []
    vrai = os.path.realpath
    monkeypatch.setattr(auth.os.path, "realpath", lambda p: appels.append(p) or vrai(p))
    req = requete(module="cachetest")
    assert auth.module_courant(req) == "cachetest"
    n = len(appels)
    assert auth.module_courant(req) == "cachetest" and len(appels) == n


# ── R-L5-15 : les verbes du ctl L2 (Operate) ne sont JAMAIS ouverts au jeton délégué ───────────────────────────────
#: Routes d'API qui recouvrent un verbe de `secubox-pilotagectl` (reboot, maj-paquets, service
#: demarrer|arreter|redemarrer, renommer, renouveler-secrets) : elles passent par les actions du pilotage (accord du
#: détenteur, confirmation forte, une opération longue à la fois), jamais par une page relayée.
ROUTES_OPERATE_L2 = {
    "system": ["/reboot", "/shutdown", "/apply_updates", "/settings", "/save_settings", "/service_control",
               "/service_action", "/restart_services"],
    "nac": [],
    "ad-guard": ["/maintenance/reload"],
    "freebox": ["/autoriser", "/revoquer"],
}
_VERBES_L2 = ("reboot", "shutdown", "poweroff", "halt", "apply_updates", "upgrade", "maj", "renommer", "rename",
              "hostname", "renouveler", "rotate", "service_control", "service_action", "restart_services")


@pytest.mark.parametrize("module", sorted(ROUTES_OPERATE_L2))
def test_aucune_declaration_n_ouvre_un_verbe_du_ctl_l2(module):
    decl = REPO / "packages" / f"secubox-{module}" / "pilotage" / "routes-ouvertes.d" / f"{module}.toml"
    routes = auth.valider_routes_ouvertes(decl.read_text(encoding="utf-8"))
    for methodes, motifs in routes:
        for motif in motifs:
            for chemin in ROUTES_OPERATE_L2[module]:
                assert not motif.fullmatch(chemin), (module, motif.pattern, chemin)
            for verbe in _VERBES_L2:
                assert verbe not in motif.pattern.lower(), (module, motif.pattern, verbe)


def test_page_systeme_appelle_ces_routes_le_relais_les_refusera(tmp_path, monkeypatch):
    """Les routes Operate restent appelées par la page système : avec le jeton délégué, 403 (la page doit renvoyer
    vers les actions du pilotage, tâche 7)."""
    routes = tmp_path / "routes-ouvertes.d"
    (routes / "system.toml").write_bytes((REPO / "packages" / "secubox-system" / "pilotage" / "routes-ouvertes.d"
                                          / "system.toml").read_bytes())
    os.chmod(routes / "system.toml", 0o644)
    for chemin in ROUTES_OPERATE_L2["system"]:
        assert garde("require_jwt", requete("POST", chemin, module="system"), frappe(cible="system"))[0] == 403, chemin
    assert garde("require_jwt", requete("POST", "/clear_cache", module="system"), frappe(cible="system"))[0] == 200
