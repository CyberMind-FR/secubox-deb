# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3126, L5 tâche 2 : le jeton FRAPPÉ PAR LE RELAIS Go (`sbx-pilotage-relais`) passe le vrai vérificateur Python.

Deux sources :
- le vecteur versionné `packages/secubox-pilotage-agent/internal/relais/testdata/vecteur-python.json`, que le test Go
  `TestVecteurFige` garantit identique à ce que frappe le code (Ed25519 est déterministe ; iat fixe, l'horloge est
  donc figée ici) ;
- un jeton frappé MAINTENANT par `go test -run TestVecteurVivant` quand `go` est installé (vérification complète de
  PyJWT, échéance comprise).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from starlette.requests import Request

from secubox_core import auth

REPO = Path(__file__).resolve().parents[3]
PAQUET = REPO / "packages" / "secubox-pilotage-agent"
VECTEUR = PAQUET / "internal" / "relais" / "testdata" / "vecteur-python.json"


def _endpoint(module: str):
    """Une fonction de route dont le source est `/usr/lib/secubox/<module>/api/main.py` (le chemin d'installation)."""
    ns: dict = {}
    exec(compile("def route():\n    return None\n", f"/usr/lib/secubox/{module}/api/main.py", "exec"), ns)
    return ns["route"]


def _requete(module: str, methode: str = "GET", chemin: str = "/status") -> Request:
    scope = {"type": "http", "method": methode, "path": chemin, "raw_path": chemin.encode(), "query_string": b"",
             "headers": [(b"x-secubox-pilotage-relais", b"sbx-pilotage-relais")],
             "server": (f"/run/secubox/{module}.sock", None), "client": None, "scheme": "http", "root_path": "",
             "endpoint": _endpoint(module)}
    return Request(scope)


@pytest.fixture
def poser_cle(monkeypatch, tmp_path):
    """Pose la clé publique du vecteur là où `_cle_publique_relais` la lit (propriétaire = le compte du test)."""
    def poser(v: dict) -> None:
        d = tmp_path / "etc-secubox-pilotage"
        d.mkdir(mode=0o755)
        (d / "relais.pub").write_text(v["pub_pem"], encoding="ascii")
        os.chmod(d / "relais.pub", 0o644)
        monkeypatch.setattr(auth, "DOSSIER_CLE_RELAIS", str(d))
        monkeypatch.setattr(auth, "UID_ROOT", os.getuid())
        monkeypatch.setattr(auth, "nom_box_locale", lambda: v["box"])
        monkeypatch.setattr(auth, "AUDIT_PILOTAGE", str(tmp_path / "audit.log"))
        monkeypatch.setenv("SECUBOX_TRACE_DELEGATION", str(tmp_path / "delegation.log"))
        monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    return poser


def _verifier(v: dict, payload: dict) -> None:
    r = auth._forme_pilotage(payload)
    assert r == {"acteur": "gerald", "maitre": "gk2", "portee": "admin"}   # « Gerald » / « GK2 » normalisés
    assert set(payload) == {"sub", "aud", "iat", "exp", "cible", "pilotage"}
    assert payload["exp"] - payload["iat"] == 30
    assert payload["sub"] == "pilotage:gerald@gk2" and payload["aud"] == v["box"] and payload["cible"] == v["cible"]
    en_tete = jwt.get_unverified_header(v["jeton"])
    assert en_tete == {"alg": "EdDSA", "typ": "JWT"}


def test_vecteur_fige_accepte_par_le_verificateur(monkeypatch, poser_cle):
    v = json.loads(VECTEUR.read_text(encoding="utf-8"))
    poser_cle(v)
    monkeypatch.setattr(time, "time", lambda: v["iat"] + 1)   # l'horloge du vecteur (iat fixe)
    cle = load_pem_public_key(v["pub_pem"].encode())
    payload = jwt.decode(v["jeton"], cle, algorithms=["EdDSA"],
                         options={"verify_exp": False, "verify_aud": False, "verify_iat": False, "verify_nbf": False})
    _verifier(v, payload)
    # Le chemin complet de la garde : signature (clé publique posée), forme, cible = module servi, socket.
    req = _requete(v["cible"])
    assert auth._porteur_pilotage(req, v["jeton"]) == payload
    assert auth.jeton_pilotage_valide(payload, req)
    # Échu 31 s après iat : refusé.
    monkeypatch.setattr(time, "time", lambda: v["iat"] + 31)
    assert auth._forme_pilotage(payload) is None


def test_vecteur_fige_refuse_pour_un_autre_module_ou_une_autre_box(monkeypatch, poser_cle):
    v = json.loads(VECTEUR.read_text(encoding="utf-8"))
    poser_cle(v)
    monkeypatch.setattr(time, "time", lambda: v["iat"] + 1)
    assert auth._porteur_pilotage(_requete("system"), v["jeton"]) is None    # cible = demo
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk4")
    assert auth._porteur_pilotage(_requete(v["cible"]), v["jeton"]) is None


def test_vecteur_altere_refuse(monkeypatch, poser_cle):
    v = json.loads(VECTEUR.read_text(encoding="utf-8"))
    poser_cle(v)
    monkeypatch.setattr(time, "time", lambda: v["iat"] + 1)
    t, c, s = v["jeton"].split(".")
    altere = ".".join((t, c, ("A" if s[0] != "A" else "B") + s[1:]))
    assert auth._porteur_pilotage(_requete(v["cible"]), altere) is None


@pytest.mark.skipif(shutil.which("go") is None, reason="go absent : seul le vecteur versionné est vérifié")
def test_jeton_frappe_maintenant_par_le_relais_go(tmp_path, poser_cle):
    sortie = tmp_path / "vecteur.json"
    env = {**os.environ, "SBX_VECTEUR_SORTIE": str(sortie), "GOFLAGS": "-mod=mod", "GOPROXY": "off",
           "GOTOOLCHAIN": "local", "CGO_ENABLED": "0"}
    subprocess.run(["go", "test", "-count=1", "-run", "^TestVecteurVivant$", "./internal/relais/"], cwd=PAQUET,
                   env=env, check=True, timeout=300, capture_output=True, text=True)
    v = json.loads(sortie.read_text(encoding="utf-8"))
    poser_cle(v)
    cle = load_pem_public_key(v["pub_pem"].encode())
    # Vérification COMPLÈTE de PyJWT (signature, échéance, audience) puis la forme du vérificateur.
    payload = jwt.decode(v["jeton"], cle, algorithms=["EdDSA"], audience=v["box"])
    _verifier(v, payload)
    assert auth._porteur_pilotage(_requete(v["cible"]), v["jeton"]) == payload
