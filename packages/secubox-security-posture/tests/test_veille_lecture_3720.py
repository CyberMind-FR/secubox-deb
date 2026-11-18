# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3720 — veille V2 : /overview lisible par le compte `ai-lecture`, signé sur `/overview` (nginx retire le préfixe
/api/v1/security-posture), anonyme du LAN inchangé, autre porteur 401."""
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from api import main  # noqa: E402


@pytest.fixture
def v(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from secubox_core import auth
    from secubox_core import compte_service as cs
    main.app.dependency_overrides.clear()
    monkeypatch.setattr(cs, "DOSSIER_COMPTES_SERVICE", str(tmp_path / "comptes"))
    monkeypatch.setattr(auth, "_proprietaire_attendu", lambda chemin: os.getuid())
    monkeypatch.setattr(auth, "nom_box_locale", lambda: "gk2")
    monkeypatch.setattr(auth, "AUDIT_PILOTAGE", str(tmp_path / "audit.log"))
    monkeypatch.setattr(auth, "_secret", lambda: "secret-de-la-box-gk2-assez-long-pour-hs256")
    monkeypatch.setattr(cs, "_rejeu", cs._Rejeu())
    monkeypatch.setattr(cs, "_cache_cles", {})
    monkeypatch.setattr(cs, "_derniers_refus", {})
    monkeypatch.setattr(cs, "_minuterie", {"active": None})
    monkeypatch.setattr(cs, "_armer_minuterie", lambda: None)
    monkeypatch.setattr(cs, "_DEMARRAGE", 0.0)
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "1")
    monkeypatch.setitem(main._state, "snapshot", {"overall": {"name": "Bonne", "score": 78}})
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

        def get(self, chemin, signe=None):
            j = cs.frapper_jeton(prive, "ai-lecture", "gk2", b"", time.time(), methode="GET", chemin=signe or chemin)
            return self.c.get(chemin, headers={"Authorization": f"Bearer {j}"})
    try:
        yield V()
    finally:
        main.app.dependency_overrides.clear()


def test_ai_lecture_overview(v):
    r = v.get("/overview")
    assert r.status_code == 200, r.text
    assert r.json()["overall"]["score"] == 78


def test_chemin_lie_au_jeton(v):
    assert v.get("/overview", signe="/api/v1/security-posture/overview").status_code == 401
    assert v.get("/overview", signe="/defcon").status_code == 401


def test_anonyme_lan_inchange_et_autre_porteur_401(v):
    import jwt
    from secubox_core import auth
    c = TestClient(main.app)
    assert c.get("/overview", headers={auth.ENTETE_LAN: "1"}).status_code == 200
    autre = jwt.encode({"sub": "inconnu", "exp": int(time.time()) + 60}, "x" * 40, algorithm="HS256")
    assert c.get("/overview", headers={"Authorization": f"Bearer {autre}"}).status_code == 401
