# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3795 — veille V2 : /etat et /historique lisibles par le compte `ai-lecture` (contenu complet), anonyme du LAN
inchangé (chiffres seulement), autre porteur 401. Jeton signé sur le chemin COMPLET (nginx garde le préfixe)."""
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient  # noqa: E402

from api import main  # noqa: E402
from test_api_3794 import env  # noqa: E402,F401


@pytest.fixture
def v(env, monkeypatch, tmp_path):  # noqa: F811
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from secubox_core import auth
    from secubox_core import compte_service as cs
    main.app.dependency_overrides.clear()
    monkeypatch.setattr(cs, "DOSSIER_COMPTES_SERVICE", str(tmp_path / "comptes"))
    monkeypatch.setattr(auth, "_proprietaire_attendu", lambda chemin: os.getuid())
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    monkeypatch.setattr(auth, "AUDIT_PILOTAGE", str(tmp_path / "audit-garde.log"))
    monkeypatch.setattr(auth, "_secret", lambda: "secret-de-la-box-gk2-assez-long-pour-hs256")
    monkeypatch.setattr(cs, "_rejeu", cs._Rejeu())
    monkeypatch.setattr(cs, "_cache_cles", {})
    monkeypatch.setattr(cs, "_derniers_refus", {})
    monkeypatch.setattr(cs, "_minuterie", {"active": None})
    monkeypatch.setattr(cs, "_armer_minuterie", lambda: None)
    monkeypatch.setattr(cs, "_DEMARRAGE", 0.0)
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "1")
    objet = Ed25519PrivateKey.generate()
    pub = objet.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    dossier = tmp_path / "comptes" / "ai-lecture"
    dossier.mkdir(parents=True)
    os.chmod(tmp_path / "comptes", 0o755)
    os.chmod(dossier, 0o755)
    f = dossier / f"{cs.empreinte(pub)}.pub"
    f.write_bytes(pub)
    os.chmod(f, 0o644)
    prive = objet.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())

    class V:
        c = TestClient(main.app)

        def get(self, chemin, params=None, signe=None):
            j = cs.frapper_jeton(prive, "ai-lecture", "gk2", b"", time.time(), methode="GET", chemin=signe or chemin)
            return self.c.get(chemin, params=params, headers={"Authorization": f"Bearer {j}"})
    try:
        yield V()
    finally:
        main.app.dependency_overrides.clear()


def test_ai_lecture_contenu_complet(v):
    r = v.get("/api/v1/garde/etat")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["session_requise"] is False and "192.168.1.95" in json.dumps(d["actives"])
    r = v.get("/api/v1/garde/historique", params={"heures": 48})
    assert r.status_code == 200, r.text
    assert r.json()["lignes"] and "session_requise" not in r.json()


def test_chemin_lie_au_jeton(v):
    # Signé sans le préfixe (chemin vu par nginx retiré) ou sur une autre route : refusé.
    assert v.get("/api/v1/garde/etat", signe="/etat").status_code == 401
    assert v.get("/api/v1/garde/historique", signe="/api/v1/garde/etat").status_code == 401


def test_bornes_422(v):
    for p in ({"heures": 0}, {"heures": 721}, {"heures": "x"}):
        assert v.get("/api/v1/garde/historique", params=p).status_code == 422, p


def test_anonyme_lan_inchange_et_autre_porteur_401(v, monkeypatch):
    from secubox_core import auth
    c = TestClient(main.app)
    r = c.get("/api/v1/garde/etat", headers={auth.ENTETE_LAN: "1"})
    assert r.status_code == 200, r.text
    t = json.dumps(r.json())
    assert r.json()["session_requise"] is True and "192.168.1.95" not in t and "TV salon" not in t
    h = c.get("/api/v1/garde/historique", headers={auth.ENTETE_LAN: "1"}).json()
    assert h["lignes"] == [] and h["session_requise"] is True
    # Porteur HS256 quelconque (non session) : 401, jamais de repli anonyme.
    import jwt
    autre = jwt.encode({"sub": "inconnu", "exp": int(time.time()) + 60}, "x" * 40, algorithm="HS256")
    for chemin in ("/api/v1/garde/etat", "/api/v1/garde/historique"):
        assert c.get(chemin, headers={"Authorization": f"Bearer {autre}"}).status_code == 401, chemin
    # Jeton d'un autre compte de service (clé inconnue de ai-lecture) : 401.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from secubox_core import compte_service as cs
    pk = Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption())
    j = cs.frapper_jeton(pk, "ai-lecture", "gk2", b"", time.time(), methode="GET", chemin="/api/v1/garde/etat")
    assert c.get("/api/v1/garde/etat", headers={"Authorization": f"Bearer {j}"}).status_code == 401
