# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2745 — régler le second facteur PAR COMPTE : moteur (`set_otp_mode`) et route `PUT /user/{nom}/otp-mode`.

`jamais` sur un ADMINISTRATEUR l'ouvre depuis internet avec le seul mot de passe : confirmation explicite, journal (qui, quel compte, ancien et nouveau mode). Le secret TOTP est conservé :
réactiver ne demande pas de ré-enrôlement. Aucun secret dans les réponses."""
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT / "common"))
sys.path.insert(0, str(ROOT / "packages" / "secubox-auth" / "composants" / "users"))

from api import engine, totp  # noqa: E402


# ---------- moteur ----------

@pytest.fixture
def store(tmp_path: Path):
    p = tmp_path / "users.json"
    p.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    eng = engine.Engine(users_path=p)
    eng.create_user("alice", email="a@b.c", role="admin")
    eng.create_user("bob", email="b@b.c", role="viewer")
    return eng


@pytest.mark.parametrize("mode", ["hors_lan", "toujours", "jamais"])
def test_set_otp_mode_enregistre_le_mode(store, mode):
    store.set_otp_mode("alice", mode)
    assert store.get_user("alice")["otp_mode"] == mode


def test_defaut_retire_le_champ_pour_garder_users_json_propre(store):
    store.set_otp_mode("alice", "jamais")
    store.set_otp_mode("alice", "defaut")
    assert "otp_mode" not in store.get_user("alice")


@pytest.mark.parametrize("mauvais", ["", "off", "JAMAIS", "toujours ", None, 1, "hors-lan"])
def test_un_mode_inconnu_est_refuse(store, mauvais):
    with pytest.raises(engine.EngineError):
        store.set_otp_mode("alice", mauvais)
    assert "otp_mode" not in store.get_user("alice")


def test_un_compte_inconnu_est_refuse(store):
    with pytest.raises(engine.EngineError, match="not found"):
        store.set_otp_mode("personne", "jamais")


def test_le_secret_totp_est_conserve_quand_le_second_facteur_est_desactive(store):
    secret = totp.generate_secret()
    store.enroll_totp("alice", secret)
    store.set_otp_mode("alice", "jamais")
    u = store.get_user("alice")
    assert u["totp"]["enabled"] is True and u["totp"]["secret"] == secret, "réactiver ne doit pas demander de ré-enrôlement"
    store.set_otp_mode("alice", "toujours")
    assert store.get_user("alice")["totp"]["secret"] == secret


def test_reinitialiser_le_2fa_ne_touche_pas_au_mode(store):
    store.enroll_totp("alice", totp.generate_secret())
    store.set_otp_mode("alice", "hors_lan")
    store.disable_totp("alice")
    assert store.get_user("alice")["otp_mode"] == "hors_lan" and store.get_user("alice")["totp"] is None


def test_le_changement_est_journalise_avec_l_ancien_et_le_nouveau_mode(store, tmp_path, monkeypatch):
    evenements = []
    monkeypatch.setattr(store, "_audit", lambda ev, user, details=None: evenements.append((ev, user, details or {})))
    store.set_otp_mode("alice", "jamais")
    store.set_otp_mode("alice", "hors_lan")
    assert evenements[0] == ("otp_mode_change", "alice", {"ancien": "defaut", "nouveau": "jamais"})
    assert evenements[1] == ("otp_mode_change", "alice", {"ancien": "jamais", "nouveau": "hors_lan"})


def test_un_mode_inchange_n_ecrit_pas_et_ne_journalise_pas(store, monkeypatch):
    evenements = []
    monkeypatch.setattr(store, "_audit", lambda ev, user, details=None: evenements.append(ev))
    store.set_otp_mode("alice", "defaut")
    assert evenements == []


# ---------- API ----------

def _noop_jwt():
    return {"sub": "root-admin"}


@pytest.fixture
def ctx(tmp_path: Path, monkeypatch):
    from fastapi.testclient import TestClient
    users_path = tmp_path / "users.json"
    users_path.write_text(json.dumps({"version": 2, "users": [], "groups": []}))
    monkeypatch.setenv("USERS_FILE", str(users_path))
    # api.main lit /etc/secubox/secubox.conf à l'import : on l'isole (sans cela l'import échoue sur toute machine où ce fichier n'est pas lisible).
    from secubox_core import config as sbx_config
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    import api.main as users_main
    importlib.reload(users_main)
    users_main.app.dependency_overrides[users_main.require_jwt] = _noop_jwt
    users_main.app.dependency_overrides[users_main.require_session] = _noop_jwt          # la garde de permission exige une SESSION, pas seulement un jeton
    monkeypatch.setattr(users_main, "user_has_permission", lambda *_a, **_kw: True)
    eng = users_main._engine
    eng.create_user("root-admin", email="r@b.c", role="admin")          # l'appelant : la garde ne laisse un compte administrateur qu'à un administrateur
    eng.create_user("alice", email="a@b.c", role="admin")
    eng.create_user("bob", email="b@b.c", role="viewer")
    eng.enroll_totp("alice", totp.generate_secret())
    return TestClient(users_main.app), users_path, users_main


def mode(users_path, nom):
    return next(u for u in json.loads(users_path.read_text())["users"] if u["username"] == nom).get("otp_mode")


@pytest.mark.parametrize("m", ["hors_lan", "toujours", "defaut"])
def test_regler_un_mode_sans_risque(ctx, m):
    c, p, _ = ctx
    r = c.put("/user/alice/otp-mode", json={"mode": m})
    assert r.status_code == 200 and r.json() == {"ok": True, "otp_mode": m}
    assert mode(p, "alice") == (None if m == "defaut" else m)


def test_desactiver_le_second_facteur_d_un_administrateur_exige_une_confirmation_explicite(ctx):
    c, p, _ = ctx
    r = c.put("/user/alice/otp-mode", json={"mode": "jamais"})
    assert r.status_code == 400 and "confirmation" in r.json()["detail"].lower() and mode(p, "alice") is None
    for faux in (False, "true", 1, "oui", None):
        assert c.put("/user/alice/otp-mode", json={"mode": "jamais", "confirmer": faux}).status_code == 400, faux
    r = c.put("/user/alice/otp-mode", json={"mode": "jamais", "confirmer": True})
    assert r.status_code == 200 and mode(p, "alice") == "jamais"


def test_desactiver_pour_un_utilisateur_ordinaire_ne_demande_pas_de_confirmation(ctx):
    c, p, _ = ctx
    assert c.put("/user/bob/otp-mode", json={"mode": "jamais"}).status_code == 200 and mode(p, "bob") == "jamais"


def test_mode_inconnu_400_compte_inconnu_404(ctx):
    c, _, _ = ctx
    assert c.put("/user/alice/otp-mode", json={"mode": "off"}).status_code == 400
    assert c.put("/user/alice/otp-mode", json={}).status_code == 400
    assert c.put("/user/personne/otp-mode", json={"mode": "toujours"}).status_code == 404


def test_la_liste_expose_le_mode_et_jamais_un_secret(ctx):
    c, _, _ = ctx
    c.put("/user/alice/otp-mode", json={"mode": "hors_lan"})
    u = {x["username"]: x for x in c.get("/users").json()["users"]}
    assert u["alice"]["otp_mode"] == "hors_lan" and u["alice"]["totp_enabled"] is True and "otp_mode" not in u["bob"]
    texte = json.dumps(c.get("/users").json())
    assert "password_hash" not in texte and '"secret"' not in texte and "backup_codes" not in texte


def test_la_permission_users_edit_est_exigee(ctx, monkeypatch):
    c, p, m = ctx
    monkeypatch.setattr(m, "user_has_permission", lambda *_a, **_kw: False)
    r = c.put("/user/bob/otp-mode", json={"mode": "toujours"})
    assert r.status_code == 403 and mode(p, "bob") is None


def test_le_changement_est_journalise_avec_le_nom_de_l_appelant_et_la_confirmation(ctx, monkeypatch):
    c, _, m = ctx
    evenements = []
    monkeypatch.setattr(m._engine, "_audit", lambda ev, user, details=None: evenements.append((ev, user, details or {})))
    monkeypatch.setattr(m, "_journal_action", lambda *a, **k: evenements.append(("journal", a, k)), raising=False)
    c.put("/user/alice/otp-mode", json={"mode": "jamais", "confirmer": True})
    ev = [e for e in evenements if e[0] == "otp_mode_change"]
    assert ev and ev[0][1] == "alice" and ev[0][2]["nouveau"] == "jamais" and ev[0][2]["par"] == "root-admin" and ev[0][2]["confirme"] is True


def test_une_valeur_sans_confirmation_n_est_jamais_enregistree_a_moitie(ctx):
    c, p, _ = ctx
    c.put("/user/alice/otp-mode", json={"mode": "toujours"})
    c.put("/user/alice/otp-mode", json={"mode": "jamais"})            # refusé
    assert mode(p, "alice") == "toujours"
