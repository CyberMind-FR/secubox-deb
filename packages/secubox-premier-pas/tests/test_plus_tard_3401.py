# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 : « Plus tard » à l'étape admin — le mot de passe par défaut reste, la box se configure quand même."""
import tomllib
from pathlib import Path

from premier_pas import moteur as M
from premier_pas import profil as P
from premier_pas import remplir as R

EXEMPLE = Path(__file__).resolve().parents[1] / "exemples" / "profil.toml"
PAGE = (Path(__file__).resolve().parents[1] / "www" / "premier-pas" / "index.html").read_text()


def test_plus_tard_est_une_reponse_complete():
    ex = P.examine({"admin": {"mot_de_passe": "plus_tard"}})
    assert "admin" not in ex.manquantes and "admin" not in ex.erreurs


def test_plus_tard_enregistre_sans_mot_de_passe(tmp_path, monkeypatch):
    monkeypatch.setattr(M, "MARQUEUR", tmp_path / "fait")
    monkeypatch.setenv("PREMIER_PAS_DIR", str(tmp_path))
    monkeypatch.setattr(R, "profil_path", lambda: tmp_path / "profil.toml")
    R.enregistre("admin", {"plus_tard": True})
    assert R.lit()["admin"]["mot_de_passe"] == "plus_tard"
    assert R.vue(R.lit())["admin"]["mot_de_passe"] == "plus_tard"


def test_le_plan_garde_le_defaut_et_ne_pose_aucune_empreinte():
    profil = tomllib.loads(EXEMPLE.read_text())
    profil["admin"]["mot_de_passe"] = "plus_tard"
    assert P.examine(profil, ["full", "lite"]).complet
    admin = [a for a in M.plan(profil) if a.etape == "admin"]
    assert any(a.fn is M._garde_mot_de_passe_defaut for a in admin)
    assert not any("empreinte" in a.quoi for a in admin)


def test_garde_marque_a_changer_et_audite(tmp_path, monkeypatch):
    import json
    import sys
    import types
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"users": [{"username": "admin", "password_hash": "$argon2id$x", "must_change_password": False}]}))

    class Engine:
        def __init__(self, users_path):
            self.p = users_path

        def _load(self):
            return json.loads(Path(self.p).read_text())

        def _find(self, doc, n):
            return next((u for u in doc["users"] if u["username"] == n), None)

        def _save(self, doc):
            Path(self.p).write_text(json.dumps(doc))
    api = types.ModuleType("api")
    api.engine = types.SimpleNamespace(Engine=Engine)
    monkeypatch.setitem(sys.modules, "api", api)
    monkeypatch.setattr(M, "USERS_FILE", users)
    monkeypatch.setenv("SECUBOX_AUDIT_LOG", str(tmp_path / "audit.log"))
    M._garde_mot_de_passe_defaut()
    assert not list(tmp_path.glob("**/plus-tard"))          # arbitrage : aucun marqueur persistant
    u = json.loads(users.read_text())["users"][0]
    assert u["must_change_password"] is True and u["password_hash"] == "$argon2id$x"
    assert "premier_pas_plus_tard" in (tmp_path / "audit.log").read_text()


def test_page_offre_plus_tard_et_explique_l_encadrement():
    assert 'id="plustard"' in PAGE and "({plus_tard: true})" in PAGE
    assert "réseau local ou le maillage seulement" in PAGE and "redemandé à chaque connexion" in PAGE and "SSH par mot de passe refusé" in PAGE


def test_moteur_users_absent_message_clair(monkeypatch):
    import builtins
    vrai = builtins.__import__

    def faux(nom, *a, **k):
        if nom == "api":
            raise ImportError("absent")
        return vrai(nom, *a, **k)
    monkeypatch.setattr(builtins, "__import__", faux)
    import pytest
    with pytest.raises(RuntimeError, match="secubox-auth"):
        M._garde_mot_de_passe_defaut()
