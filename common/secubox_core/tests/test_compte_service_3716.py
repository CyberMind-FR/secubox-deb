# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#3716, tâche 3 : `secubox_core.compte_service`, l'identité de service « ai-ban ».

Une clé privée Ed25519 sur la box de l'IA signe un jeton à usage unique, de 60 s au plus, lié au corps exact de la
requête ; gk2 ne garde que la clé publique (arbre root) et la vérifie par `require_ai_ban`. Ce jeton n'est JAMAIS une
session : `require_jwt`, `require_session`, `require_lecture`, `require_personne` le refusent, et `require_ai_ban`
refuse une session d'administrateur.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from collections import namedtuple

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from secubox_core import auth
from secubox_core import compte_service as _cs

T = 1_800_000_000.0
SECRET = "secret-de-la-box-gk2-assez-long-pour-hs256"
Cle = namedtuple("Cle", "prive kid objet pem_publique")


def _pem_prive(cle) -> bytes:
    return cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _pem_public(cle) -> bytes:
    return cle.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def _nouvelle_cle() -> Cle:
    objet = Ed25519PrivateKey.generate()
    pem = _pem_public(objet)
    return Cle(_pem_prive(objet), _cs.empreinte(pem), objet, pem)


def _poser(dossier, cle: Cle, nom=None, mode=0o644):
    f = dossier / (nom or f"{cle.kid}.pub")
    f.write_bytes(cle.pem_publique)
    os.chmod(f, mode)
    return f


@pytest.fixture
def cs(monkeypatch, tmp_path):
    """Le module, sur une box `gk2` dont l'arbre des comptes de service est dans `tmp_path`, au compte courant ;
    état (rejeu, cache, audit) neuf à chaque test."""
    monkeypatch.setattr(_cs, "DOSSIER_COMPTES_SERVICE", str(tmp_path))
    monkeypatch.setattr(auth, "_proprietaire_attendu", lambda chemin: os.getuid())
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    monkeypatch.setattr(auth, "AUDIT_PILOTAGE", str(tmp_path / "audit.log"))
    monkeypatch.setattr(auth, "_secret", lambda: SECRET)
    monkeypatch.setattr(_cs, "_rejeu", _cs._Rejeu())
    monkeypatch.setattr(_cs, "_cache_cles", {})
    monkeypatch.setattr(_cs, "_derniers_refus", {})
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    return _cs


@pytest.fixture
def cle(cs, tmp_path):
    """Une paire Ed25519 ; la clé publique posée en `tmp_path/ai-ban/<kid>.pub` (0755 / 0644)."""
    dossier = tmp_path / "ai-ban"
    dossier.mkdir(mode=0o755)
    os.chmod(dossier, 0o755)
    c = _nouvelle_cle()
    _poser(dossier, c)
    return c


def _jeton(cle: Cle, brut=b"", maintenant=T, alg="EdDSA", kid=None, cle_signature=None, entetes=None, **modif):
    """Un jeton construit à la main : les réclamations de `frapper_jeton`, modifiables une à une."""
    iat = int(maintenant)
    p = {"sub": "ai-ban", "aud": "gk2", "portee": "waf-ban", "iat": iat, "exp": iat + 30,
         "jti": secrets.token_hex(16), "corps": hashlib.sha256(brut).hexdigest()}
    for k, v in modif.items():
        if v is _SANS:
            p.pop(k, None)
        else:
            p[k] = v
    h = {"kid": cle.kid if kid is None else kid}
    h.update(entetes or {})
    if alg.startswith("HS"):
        return jwt.encode(p, SECRET, algorithm=alg, headers=h)
    return jwt.encode(p, cle_signature or cle.objet, algorithm=alg, headers=h)


_SANS = object()


# ── Le chemin nominal ──────────────────────────────────────────────────
def test_jeton_valide_rend_le_compte(cs, cle):
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b'{"x":1}', T)
    p = cs.verifier_jeton("ai-ban", j, b'{"x":1}', T + 1)
    assert p["sub"] == "ai-ban" and p["compte_service"] == "ai-ban" and p["cle"] == cle.kid
    assert set(p) == {"sub", "compte_service", "jti", "cle"} and len(p["jti"]) == 32


def test_empreinte_est_le_sha256_du_der(cs, cle):
    der = cle.objet.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    assert cs.empreinte(cle.pem_publique) == hashlib.sha256(der).hexdigest()
    with pytest.raises(ValueError):
        cs.empreinte(b"pas une cle")


def test_frapper_borne_la_duree_et_le_compte(cs, cle):
    with pytest.raises(ValueError):
        cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T, duree_s=61)
    with pytest.raises(ValueError):
        cs.frapper_jeton(cle.prive, "autre", "gk2", b"", T)


# ── Les refus ──────────────────────────────────────────────────────────
_CAS = {
    "aud_autre_box": (lambda c: _jeton(c, aud="gk3"), b"", "audience"),
    "portee": (lambda c: _jeton(c, portee="admin"), b"", "portee"),
    "duree_61s": (lambda c: _jeton(c, exp=int(T) + 61), b"", "duree"),
    "iat_futur_6s": (lambda c: _jeton(c, iat=int(T) + 6, exp=int(T) + 36), b"", "iat_futur"),
    "echu": (lambda c: _jeton(c, iat=int(T) - 100, exp=int(T) - 40), b"", "echu"),
    "kid_inconnu": (lambda c: (lambda a: _jeton(a))(_nouvelle_cle()), b"", "cle_inconnue"),
    "corps_modifie": (lambda c: _jeton(c, brut=b'{"cible":"203.0.113.0/24"}'), b'{"cible":"203.0.113.1"}',
                      "corps"),
    "alg_hs256": (lambda c: _jeton(c, alg="HS256"), b"", "algorithme"),
    "sub_autre": (lambda c: _jeton(c, sub="admin"), b"", "sujet"),
    "jti_court": (lambda c: _jeton(c, jti="abcd"), b"", "jti"),
}


@pytest.mark.parametrize("cas,statut", [("aud_autre_box", 403), ("portee", 403), ("duree_61s", 401),
    ("iat_futur_6s", 401), ("echu", 401), ("kid_inconnu", 401), ("corps_modifie", 401), ("alg_hs256", 401),
    ("sub_autre", 403), ("jti_court", 401)])
def test_refus(cs, cle, cas, statut):
    fabrique, corps, motif = _CAS[cas]
    with pytest.raises(cs.RefusCompteService) as e:
        cs.verifier_jeton("ai-ban", fabrique(cle), corps, T)
    assert e.value.statut == statut and e.value.motif == motif


@pytest.mark.parametrize("fabrique,statut,motif", [
    (lambda c: _jeton(c, cle_signature=Ed25519PrivateKey.generate()), 401, "signature"),
    (lambda c: _jeton(c, aud=["gk2"]), 403, "audience"),
    (lambda c: _jeton(c, aud=_SANS), 401, "reclamations"),
    (lambda c: _jeton(c, jti=_SANS), 401, "reclamations"),
    (lambda c: _jeton(c, corps=_SANS), 401, "reclamations"),
    (lambda c: _jeton(c, portee=_SANS), 403, "portee"),
    (lambda c: _jeton(c, iat=True), 401, "reclamations"),
    (lambda c: _jeton(c, exp=int(T) - 1, iat=int(T)), 401, "duree"),
    (lambda c: _jeton(c, jti="A" * 32), 401, "jti"),
    (lambda c: _jeton(c, nbf=int(T) + 30), 401, "iat_futur"),
    (lambda c: _jeton(c, kid="0" * 63), 401, "cle_inconnue"),
    (lambda c: _jeton(c, entetes={"jwk": {"kty": "OKP"}}), 401, "entete"),
    (lambda c: "x" * 9000, 401, "illisible"),
    (lambda c: "pas.un.jeton", 401, "illisible"),
])
def test_refus_supplementaires(cs, cle, fabrique, statut, motif):
    with pytest.raises(cs.RefusCompteService) as e:
        cs.verifier_jeton("ai-ban", fabrique(cle), b"", T)
    assert (e.value.statut, e.value.motif) == (statut, motif)


def test_derive_de_5_s_toleree(cs, cle):
    cs.verifier_jeton("ai-ban", _jeton(cle, iat=int(T) + 5, exp=int(T) + 35), b"", T)
    cs.verifier_jeton("ai-ban", _jeton(cle, iat=int(T) - 60, exp=int(T) - 4), b"", T)


def test_box_sans_nom_refuse_en_503(cs, cle, monkeypatch):
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "")
    with pytest.raises(cs.RefusCompteService) as e:
        cs.verifier_jeton("ai-ban", _jeton(cle), b"", T)
    assert e.value.statut == 503


# ── Usage unique ───────────────────────────────────────────────────────
def test_refus_rejeu_meme_jti(cs, cle):
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T)
    cs.verifier_jeton("ai-ban", j, b"", T)
    with pytest.raises(cs.RefusCompteService) as e:
        cs.verifier_jeton("ai-ban", j, b"", T + 1)
    assert e.value.statut == 401 and e.value.motif == "rejeu"


def test_corps_refuse_ne_brule_pas_le_jti(cs, cle):
    """Un tiers qui rejoue un jeton capturé avec un AUTRE corps ne consomme pas le geste légitime."""
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b'{"id":"a"}', T)
    with pytest.raises(cs.RefusCompteService):
        cs.verifier_jeton("ai-ban", j, b'{"id":"b"}', T)
    cs.verifier_jeton("ai-ban", j, b'{"id":"a"}', T)


def test_rejeu_plein_refuse_en_503_sans_oublier(cs, cle, monkeypatch):
    monkeypatch.setattr(cs, "REJEU_MAX", 2)
    j1, j2 = (cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T) for _ in range(2))
    cs.verifier_jeton("ai-ban", j1, b"", T)
    cs.verifier_jeton("ai-ban", j2, b"", T)
    with pytest.raises(cs.RefusCompteService) as e:
        cs.verifier_jeton("ai-ban", cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T), b"", T)
    assert e.value.statut == 503 and e.value.motif == "rejeu_plein"
    with pytest.raises(cs.RefusCompteService) as e:   # j1 n'a pas été oublié pour faire de la place
        cs.verifier_jeton("ai-ban", j1, b"", T)
    assert e.value.motif == "rejeu"
    # passé l'échéance (+ dérive), la place se libère
    cs.verifier_jeton("ai-ban", cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T + 40), b"", T + 40)


def test_jti_oublie_jamais_rejoue_meme_si_l_horloge_recule(cs, cle):
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T)
    cs.verifier_jeton("ai-ban", j, b"", T)
    cs.verifier_jeton("ai-ban", cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T + 100), b"", T + 100)  # purge
    assert len(cs._rejeu) == 1
    with pytest.raises(cs.RefusCompteService) as e:   # horloge revenue à T : le jti oublié reste refusé
        cs.verifier_jeton("ai-ban", j, b"", T + 1)
    assert e.value.statut == 401


# ── Les clés publiques ────────────────────────────────────────────────
def test_dossier_inscriptible_par_le_groupe_aucune_cle(cs, cle, tmp_path):
    os.chmod(tmp_path / "ai-ban", 0o775)
    assert cs.cles_publiques("ai-ban") == {}
    with pytest.raises(cs.RefusCompteService) as e:
        cs.verifier_jeton("ai-ban", _jeton(cle), b"", T)
    assert e.value.statut == 401


def test_racine_inscriptible_par_les_autres_aucune_cle(cs, cle, tmp_path):
    os.chmod(tmp_path, 0o757)
    try:
        assert cs.cles_publiques("ai-ban") == {}
    finally:
        os.chmod(tmp_path, 0o700)


def test_dossier_lien_symbolique_aucune_cle(cs, cle, tmp_path):
    (tmp_path / "ai-ban").rename(tmp_path / "vrai")
    (tmp_path / "ai-ban").symlink_to(tmp_path / "vrai")
    assert cs.cles_publiques("ai-ban") == {}


def test_fichiers_douteux_ignores(cs, cle, tmp_path):
    d = tmp_path / "ai-ban"
    autre = _nouvelle_cle()
    _poser(d, autre, nom="0" * 64 + ".pub")            # nom ≠ empreinte réelle
    (d / "lien.pub").symlink_to(d / f"{cle.kid}.pub")   # nom hors format
    ailleurs = _nouvelle_cle()
    _poser(tmp_path, ailleurs)
    (d / f"{ailleurs.kid}.pub").symlink_to(tmp_path / f"{ailleurs.kid}.pub")   # bon nom, mais un lien
    (d / "LISEZMOI").write_text("rien", encoding="utf-8")
    assert set(cs.cles_publiques("ai-ban")) == {cle.kid}
    os.chmod(d / f"{cle.kid}.pub", 0o664)               # inscriptible par le groupe
    assert cs.cles_publiques("ai-ban") == {}


def test_deux_cles_au_plus(cs, cle, tmp_path):
    d = tmp_path / "ai-ban"
    deuxieme = _nouvelle_cle()
    _poser(d, deuxieme)
    assert set(cs.cles_publiques("ai-ban")) == {cle.kid, deuxieme.kid}
    _poser(d, _nouvelle_cle())
    assert cs.cles_publiques("ai-ban") == {}


def test_cle_retiree_refus_immediat(cs, cle, tmp_path):
    cs.verifier_jeton("ai-ban", cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T), b"", T)
    (tmp_path / "ai-ban" / f"{cle.kid}.pub").unlink()
    with pytest.raises(cs.RefusCompteService) as e:
        cs.verifier_jeton("ai-ban", cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", T), b"", T)
    assert e.value.statut == 401 and e.value.motif == "cle_inconnue"


def test_cle_ajoutee_prise_sans_redemarrage(cs, cle, tmp_path):
    assert set(cs.cles_publiques("ai-ban")) == {cle.kid}
    nouvelle = _nouvelle_cle()
    _poser(tmp_path / "ai-ban", nouvelle)
    cs.verifier_jeton("ai-ban", cs.frapper_jeton(nouvelle.prive, "ai-ban", "gk2", b"", T), b"", T)


def test_compte_hors_liste_refuse(cs, cle):
    with pytest.raises(ValueError):
        cs.garde_compte_service("autre")
    with pytest.raises(cs.RefusCompteService) as e:
        cs.verifier_jeton("autre", _jeton(cle), b"", T)
    assert e.value.statut == 401


# ── Les gardes : jamais une session, jamais une session à la place ────
def _app_gardes(cs):
    app = FastAPI()
    for nom, garde in (("jwt", auth.require_jwt), ("session", auth.require_session),
                       ("lecture", auth.require_lecture), ("personne", auth.require_personne),
                       ("ai", cs.require_ai_ban)):
        def route(p=Depends(garde)):
            return {"sub": p.get("sub")}
        app.add_api_route(f"/{nom}", route, methods=["GET", "POST"])
    return app


def test_jeton_ai_ban_refuse_par_require_jwt_session_lecture(cs, cle, monkeypatch, tmp_path):
    monkeypatch.setattr(auth.user_store, "is_enabled", lambda s: True)
    monkeypatch.setattr(auth.user_store, "get_user", lambda s: {"role": "admin", "enabled": True})
    monkeypatch.setattr(auth, "_session_validator", lambda jti: True)
    # Pire cas : la clé du relais du pilotage serait celle d'ai-ban — le jeton reste refusé (forme, `sub`, `cible`).
    relais = tmp_path / "pilotage"
    relais.mkdir(mode=0o755)
    _poser(relais, cle, nom="relais.pub")
    monkeypatch.setattr(auth, "DOSSIER_CLE_RELAIS", str(relais))
    monkeypatch.setattr(auth, "UID_ROOT", os.getuid())
    monkeypatch.setenv("SECUBOX_TRACE_DELEGATION", str(tmp_path / "delegation.log"))
    auth._invalides.update(nombre=0, depuis=0.0)
    client = TestClient(_app_gardes(cs))
    for garde in ("jwt", "session", "lecture", "personne"):
        for methode in ("GET", "POST"):
            for relais in ({}, {auth.ENTETE_PILOTAGE_RELAIS: "1"}):
                j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", time.time())
                r = client.request(methode, f"/{garde}", headers={"Authorization": f"Bearer {j}", **relais})
                assert r.status_code == 401, (garde, methode, relais, r.status_code)
    with pytest.raises(auth.HTTPException) as e:   # ni par /auth/verify (auth_request de nginx)
        auth._decode_token(cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b"", time.time()))
    assert e.value.status_code == 401


def test_session_admin_refusee_par_require_ai_ban(cs, cle, monkeypatch):
    monkeypatch.setattr(auth.user_store, "is_enabled", lambda s: True)
    monkeypatch.setattr(auth.user_store, "get_user", lambda s: {"role": "admin", "enabled": True})
    monkeypatch.setattr(auth, "_session_validator", lambda jti: True)
    client = TestClient(_app_gardes(cs))
    jeton = auth.create_token("admin")
    assert client.get("/jwt", headers={"Authorization": f"Bearer {jeton}"}).status_code == 200   # témoin
    assert client.post("/ai", headers={"Authorization": f"Bearer {jeton}"}).status_code == 401
    client.cookies.set(auth.SESSION_COOKIE, jeton)
    assert client.post("/ai").status_code == 401
    # même une session HS256 qui imiterait les réclamations ai-ban
    faux = jwt.encode({"sub": "ai-ban", "aud": "gk2", "portee": "waf-ban", "iat": int(time.time()),
                       "exp": int(time.time()) + 30, "jti": secrets.token_hex(16),
                       "corps": hashlib.sha256(b"").hexdigest()}, SECRET, algorithm="HS256",
                      headers={"kid": cle.kid})
    assert client.post("/ai", headers={"Authorization": f"Bearer {faux}"}).status_code == 401


def test_require_ai_ban_accepte_le_corps_exact(cs, cle):
    client = TestClient(_app_gardes(cs))
    corps = b'{"cible": "203.0.113.0/24", "duree_s": 86400}'
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", corps, time.time())
    r = client.post("/ai", content=corps, headers={"Authorization": f"Bearer {j}",
                                                   "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json() == {"sub": "ai-ban"}
    r = client.post("/ai", content=corps, headers={"Authorization": f"Bearer {j}"})
    assert r.status_code == 401 and "rejeu" in r.json()["detail"]
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", corps, time.time())
    r = client.post("/ai", content=corps + b" ", headers={"Authorization": f"Bearer {j}"})
    assert r.status_code == 401
    assert client.post("/ai", content=corps).status_code == 401          # sans jeton
    assert client.post("/ai", content=corps).headers.get("www-authenticate") == "Bearer"


def test_refus_audite_sans_le_jeton(cs, cle, tmp_path):
    client = TestClient(_app_gardes(cs))
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", b'{"a":1}', time.time())
    for _ in range(3):   # même (compte, motif) : une ligne en 10 s
        assert client.post("/ai", content=b'{"a":2}', headers={"Authorization": f"Bearer {j}",
                                                                "X-Forwarded-For": "198.51.100.7"}).status_code == 401
    texte = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert j not in texte and j.split(".")[2] not in texte
    lignes = [json.loads(x) for x in texte.splitlines()]
    assert len(lignes) == 1
    ligne = lignes[0]
    assert {k: ligne[k] for k in ("module", "action", "compte", "motif", "ip")} == {
        "module": "compte-service", "action": "refus", "compte": "ai-ban", "motif": "corps", "ip": "198.51.100.7"}
    client.post("/ai")   # autre motif : sa propre ligne
    assert len((tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()) == 2


def test_audit_relance_apres_10_s(cs, cle, tmp_path, monkeypatch):
    horloge = [1000.0]
    monkeypatch.setattr(cs, "_horloge", lambda: horloge[0])
    client = TestClient(_app_gardes(cs))
    client.post("/ai")
    horloge[0] += 5
    client.post("/ai")
    horloge[0] += 6
    client.post("/ai")
    lignes = [json.loads(x) for x in (tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()]
    assert len(lignes) == 2 and lignes[1]["nombre"] == 2


class _Geste(BaseModel):
    cible: str
    duree_s: int


def test_require_ai_ban_avec_un_modele_de_corps(cs, cle):
    """La route lit son modèle Pydantic ET la garde le corps brut (mis en cache par Starlette) : forme de la tâche 4."""
    app = FastAPI()

    @app.post("/ai/ban")
    def ban(geste: _Geste, p=Depends(cs.require_ai_ban)):
        return {"cible": geste.cible, "jti": p["jti"]}

    corps = json.dumps({"cible": "203.0.113.0/24", "duree_s": 3600}).encode()
    j = cs.frapper_jeton(cle.prive, "ai-ban", "gk2", corps, time.time())
    r = TestClient(app).post("/ai/ban", content=corps, headers={"Authorization": f"Bearer {j}",
                                                                 "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json()["cible"] == "203.0.113.0/24" and len(r.json()["jti"]) == 32
