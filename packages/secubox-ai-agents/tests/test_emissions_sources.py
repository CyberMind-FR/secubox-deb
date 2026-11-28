# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 6 (#4058) : lecture SEULE des dossiers de gk2 ; #4063 : un jeton ai-lecture frappé par requête."""
import asyncio
import os
import sys
import time
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_COMMON = Path(__file__).resolve().parents[3] / "common"
if str(_COMMON) not in sys.path:
    sys.path.insert(0, str(_COMMON))

from secubox_core import auth, compte_service  # noqa: E402
from emissions import sources as src  # noqa: E402
from emissions.sources import Sources, jeton_ai_lecture, jeton_fichier, lire_cle  # noqa: E402


def _paire(tmp_path):
    cle = Ed25519PrivateKey.generate()
    f = tmp_path / "ai-lecture.key"
    f.write_bytes(cle.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    f.chmod(0o600)
    pub = cle.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return f, cle.public_key(), compte_service.empreinte(pub)


@pytest.fixture
def gk2(monkeypatch):
    """Garde de gk2 simulée avec le VRAI compte_service : box « gk2 », clé publique de test, rejeu neuf."""
    cles = {}
    monkeypatch.setattr(compte_service, "cles_publiques", lambda compte: dict(cles) if compte == "ai-lecture" else {})
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    monkeypatch.setattr(compte_service, "_DEMARRAGE", time.time() - 3600)
    monkeypatch.setattr(compte_service, "_rejeu", compte_service._Rejeu())
    return cles


def _client(vues):
    def gerer(req: httpx.Request) -> httpx.Response:
        vues.append(req)
        if req.url.path.endswith("/rapports"):
            return httpx.Response(200, json={"disponible": True, "sujets": [{"genre": "campagne", "id": "c1"}]})
        return httpx.Response(200, json={"cle": "campagne/c1", "dossier": {"sujet": {"id": "c1"}}})
    return httpx.AsyncClient(transport=httpx.MockTransport(gerer))


def test_genre_inconnu_refuse():
    s = Sources("http://127.0.0.1:1", lambda c: "j", client=_client([]))
    for genre, ident in (("ban", "x"), ("campagne", "../etc"), ("acteur", "a/b"), ("acteur", "")):
        with pytest.raises(ValueError):
            asyncio.run(s.dossier(genre, ident))


def test_get_seulement():
    vues = []
    s = Sources("http://127.0.0.1:9/api/v1/waf/", lambda c: "jeton-lecture", client=_client(vues))

    async def tout():
        assert (await s.lister())[0]["id"] == "c1"
        assert (await s.dossier("campagne", "c1"))["cle"] == "campagne/c1"
        assert (await s.dossier("acteur", "ACT-12"))["cle"]
    asyncio.run(tout())
    assert vues and all(r.method == "GET" for r in vues)
    assert [r.url.path for r in vues] == ["/api/v1/waf/rapports", "/api/v1/waf/rapports/campagne/c1",
                                         "/api/v1/waf/rapports/acteur/ACT-12"]
    assert all(r.headers["authorization"] == "Bearer jeton-lecture" for r in vues)
    assert not [n for n in dir(Sources) if n.startswith(("rediger", "ecrire", "post", "put", "supprimer"))]


def test_erreur_http_remonte():
    s = Sources("http://127.0.0.1:9", lambda c: "j",
                client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403))))
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(s.lister())


def test_lister_sujets_absents():
    s = Sources("http://127.0.0.1:9", lambda c: "j",
                client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"disponible": False}))))
    assert asyncio.run(s.lister()) == []


def test_jeton_fichier_0600(tmp_path):
    f = tmp_path / "lecture-gk2"
    f.write_text("abc\n")
    f.chmod(0o644)
    with pytest.raises(PermissionError):
        jeton_fichier(f)()
    f.chmod(0o600)
    assert jeton_fichier(f)() == "abc"
    assert os.stat(f).st_mode & 0o777 == 0o600


def test_jeton_frappe_verifie_par_compte_service(tmp_path, gk2):
    f, pub, kid = _paire(tmp_path)
    gk2[kid] = pub
    vues = []
    s = Sources("http://127.0.0.1:9/api/v1/waf", jeton_ai_lecture("gk2", cle=lambda: lire_cle(f)), client=_client(vues))

    async def tout():
        await s.lister()
        await s.dossier("campagne", "c1")
    asyncio.run(tout())
    jetons = [r.headers["authorization"].removeprefix("Bearer ") for r in vues]
    assert len(set(jetons)) == 2                                   # un jeton NEUF par requête
    for j, chemin in zip(jetons, ("/rapports", "/rapports/campagne/c1")):
        e = jwt.get_unverified_header(j)
        assert e["alg"] == "EdDSA" and e["kid"] == kid
        p = jwt.decode(j, options={"verify_signature": False})
        assert (p["sub"], p["portee"], p["aud"], p["methode"], p["chemin"]) == \
            ("ai-lecture", "waf-lecture", "gk2", "GET", chemin)
        assert 0 < p["exp"] - p["iat"] <= compte_service.DUREE_MAX_S
        v = compte_service.verifier_jeton("ai-lecture", j, b"", time.time(), "GET", chemin)
        assert v["cle"] == kid
        with pytest.raises(compte_service.RefusCompteService):  # jti à usage unique
            compte_service.verifier_jeton("ai-lecture", j, b"", time.time(), "GET", chemin)


def test_jeton_refuse_ailleurs(tmp_path, gk2):
    f, pub, kid = _paire(tmp_path)
    gk2[kid] = pub
    j = jeton_ai_lecture("gk2", cle=lambda: lire_cle(f))("/rapports")
    with pytest.raises(compte_service.RefusCompteService) as e:   # autre chemin
        compte_service.verifier_jeton("ai-lecture", j, b"", time.time(), "GET", "/bans")
    assert e.value.motif == "chemin"
    autre = jeton_ai_lecture("gk6", cle=lambda: lire_cle(f))("/rapports")
    with pytest.raises(compte_service.RefusCompteService) as e:   # autre box
        compte_service.verifier_jeton("ai-lecture", autre, b"", time.time(), "GET", "/rapports")
    assert (e.value.statut, e.value.motif) == (403, "audience")
    gk2.clear()
    j = jeton_ai_lecture("gk2", cle=lambda: lire_cle(f))("/rapports")
    with pytest.raises(compte_service.RefusCompteService) as e:   # clé non déposée sur gk2
        compte_service.verifier_jeton("ai-lecture", j, b"", time.time(), "GET", "/rapports")
    assert e.value.motif == "cle_inconnue"


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660])
def test_cle_lisible_par_dautres_refusee(tmp_path, mode):
    f, _, _ = _paire(tmp_path)
    f.chmod(mode)
    with pytest.raises(PermissionError):
        lire_cle(f)
    with pytest.raises(PermissionError):
        jeton_ai_lecture("gk2", cle=lambda: lire_cle(f))("/rapports")


def test_cle_lien_refuse(tmp_path):
    f, _, _ = _paire(tmp_path)
    lien = tmp_path / "lien.key"
    lien.symlink_to(f)
    with pytest.raises(OSError):
        lire_cle(lien)


def test_audience_invalide_refusee():
    for aud in ("", "gk2 gk3", "a/b", None):
        with pytest.raises(ValueError):
            jeton_ai_lecture(aud)


def test_aucune_methode_ecriture():
    noms = [n for n in dir(Sources) if not n.startswith("__")]
    assert set(noms) == {"_get", "lister", "dossier"}
    assert "post" not in open(src.__file__, encoding="utf-8").read().replace("POST …/rediger", "")
    assert not hasattr(src, "JETON_DEFAUT")                        # plus de jeton fixe pour gk2
