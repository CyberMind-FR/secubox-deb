# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1720 — côté BOX AIDÉE : un compte d'un autre nœud entre en administrateur
tant que la box l'a autorisé, et plus du tout ensuite ; jamais par mot de passe."""
import importlib
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ANNUAIRE = str(Path(__file__).resolve().parents[2] / "secubox-annuaire")
sys.path.append(ANNUAIRE)  # après l'auth : l'annuaire a aussi un paquet « api »
from annuaire.crypto import did_from_pubkey, generate_keypair, public_from_private  # noqa: E402
from annuaire.delegation import emettre  # noqa: E402


def _cle():
    priv, _ = generate_keypair()
    pub = public_from_private(priv)
    return priv, pub.hex(), did_from_pubkey(pub)


def _rfc(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    box_priv, box_pub, box = _cle()
    ctr_priv, ctr_pub, centre = _cle()
    t = time.time()
    journal = [
        {"op": "genesis", "author": centre, "payload_type": "Identity", "payload": {"did": centre, "pubkey": ctr_pub}},
        {"op": "node_publish", "author": centre, "payload": {"did": centre, "boxname": "gk2", "ddns": "gk2.secubox.in"}},
        {"op": "assist_session_open", "author": box, "payload": {"issued_by": box, "session_id": "s1", "center_did": centre, "expires_ts": _rfc(t + 7200)}},
        {"op": "assist_console_grant", "author": box, "payload": {"issued_by": box, "session_id": "s1", "expires_ts": _rfc(t + 3600)}},
    ]
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "groups": [], "users": []}))
    (tmp_path / "sessions.json").write_text("[]")
    (tmp_path / "totp-pending.json").write_text("{}")
    for k, v in {"USERS_FILE": users, "SECUBOX_AUTH_DATA_DIR": tmp_path,
                 "SECUBOX_AUTH_SESSIONS": tmp_path / "sessions.json", "SECUBOX_AUTH_AUDIT": tmp_path / "audit.log",
                 "SECUBOX_AUTH_TOTP_PENDING": tmp_path / "totp-pending.json",
                 "SECUBOX_AUTH_REGLAGES": tmp_path / "reglages.json",
                 "SECUBOX_AUTH_DELEGUES": tmp_path / "delegues.json",
                 "SECUBOX_TRACE_DELEGATION": tmp_path / "delegation.log"}.items():
        monkeypatch.setenv(k, str(v))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret-de-trente-deux-octets!!")
    from secubox_core import config as sbx_config, user_store
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    monkeypatch.setattr(user_store, "USERS_PATH", users)
    from api import delegation as D
    monkeypatch.setattr(D, "ANNUAIRE_LIB", ANNUAIRE)
    monkeypatch.setattr(D, "entrees", lambda journal_path=None: journal)
    monkeypatch.setattr(D, "did_du_noeud", lambda chemin=None: box)
    from api import main as auth_main
    importlib.reload(auth_main)
    monkeypatch.setattr(auth_main._deleg, "entrees", lambda journal_path=None: journal)
    monkeypatch.setattr(auth_main._deleg, "did_du_noeud", lambda chemin=None: box)
    return {"c": TestClient(auth_main.app), "main": auth_main, "journal": journal, "box": box,
            "ctr_priv": ctr_priv, "tmp": tmp_path, "users": users}


def test_le_centre_entre_en_administrateur_et_chaque_appel_est_trace(env):
    c, m = env["c"], env["main"]
    a = emettre(env["ctr_priv"], env["box"], "gk2", "s1")
    r = c.get("/delegation/entrer", params={"a": a})
    assert r.status_code == 200, r.text
    jeton = r.text.split("localStorage.setItem('sbx_token',")[1].split(")")[0].strip().strip('"')
    u = next(u for u in json.loads(env["users"].read_text())["users"] if u["username"] == "gk2.gk2")
    assert u["role"] == "admin" and u["password_hash"] and u["must_change_password"] is False
    # Administrateur réel (require_jwt) : /sessions répond.
    assert c.get("/sessions", headers={"Authorization": "Bearer " + jeton}).status_code == 200
    trace = (env["tmp"] / "delegation.log").read_text().strip().splitlines()
    assert trace and json.loads(trace[-1])["aidant"] == "gk2" and json.loads(trace[-1])["chemin"] == "/sessions"


def test_une_assertion_ne_sert_qu_une_fois(env):
    c = env["c"]
    a = emettre(env["ctr_priv"], env["box"], "gk2", "s1")
    assert c.get("/delegation/entrer", params={"a": a}).status_code == 200
    assert c.get("/delegation/entrer", params={"a": a}).status_code == 403


def test_sans_autorisation_rien_ne_s_ouvre(env):
    env["journal"].pop()  # retire l'accord de console
    a = emettre(env["ctr_priv"], env["box"], "gk2", "s1")
    assert env["c"].get("/delegation/entrer", params={"a": a}).status_code == 403


def test_un_autre_noeud_non_autorise_est_refuse(env):
    autre_priv, _, _ = _cle()
    a = emettre(autre_priv, env["box"], "gk2", "s1")
    assert env["c"].get("/delegation/entrer", params={"a": a}).status_code == 403


def test_autorisation_retiree_la_veille_ferme_les_sessions(env):
    c, m = env["c"], env["main"]
    a = emettre(env["ctr_priv"], env["box"], "gk2", "s1")
    jeton = c.get("/delegation/entrer", params={"a": a}).text.split("sbx_token',")[1].split(")")[0].strip().strip('"')
    env["journal"].append({"op": "assist_console_revoke", "author": env["box"],
                           "payload": {"issued_by": env["box"], "session_id": "s1"}})
    m._veille_delegations_une_fois()
    assert c.get("/sessions", headers={"Authorization": "Bearer " + jeton}).status_code == 401


def test_le_compte_delegue_n_entre_jamais_par_mot_de_passe(env):
    c = env["c"]
    a = emettre(env["ctr_priv"], env["box"], "gk2", "s1")
    c.get("/delegation/entrer", params={"a": a})
    r = c.post("/login", json={"username": "gk2.gk2", "password": ""}, headers={"X-SecuBox-LAN": "1"})
    assert r.status_code == 401
