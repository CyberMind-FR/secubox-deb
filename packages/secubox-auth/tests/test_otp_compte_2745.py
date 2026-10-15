# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2745 — le second facteur se règle PAR COMPTE : `otp_mode` ∈ defaut | hors_lan | toujours | jamais.

Demande du mainteneur : « activer ou désactiver l'OTP sur les comptes SBX OS ; admin par défaut OTP hors LAN seulement, ou full disable ». Avant : un seul réglage GLOBAL (`otp_lan`, #1699).
- `defaut` (champ absent ou inconnu) : suit le réglage global — facultatif sur le LAN, c'est-à-dire « hors LAN seulement » ;
- `hors_lan` : exigé hors du LAN seulement ;  `toujours` : exigé partout, LAN compris ;
- `jamais` : jamais exigé, même depuis internet, même pour un compte enrôlé (le secret est conservé).
Garde-fou : une connexion depuis le WAN SANS second facteur n'ouvre JAMAIS le coffre (il s'ouvre avec le mot de passe)."""
import importlib
import json
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

MDP = "GoodPass!42xyz"
MODES = ("defaut", "hors_lan", "toujours", "jamais")


def _compte(nom, role, otp, mode=None):
    c = {"username": nom, "email": None, "role": role, "enabled": True,
         "password_hash": PasswordHasher().hash(MDP), "must_change_password": False,
         "totp": ({"secret": "JBSWY3DPEHPK3PXP", "enabled": True, "enrolled_at": "2026-09-01T00:00:00+00:00",
                   "last_step": None, "backup_codes": []} if otp else None),
         "google": None, "services": [], "created": "2026-09-01T00:00:00+00:00", "last_login": None}
    if mode is not None:
        c["otp_mode"] = mode
    return c


def comptes():
    out = []
    for mode in MODES:
        out += [_compte(f"enrole-{mode}", "admin", True, mode), _compte(f"neuf-{mode}", "admin", False, mode), _compte(f"lect-{mode}", "user", True, mode)]
    out += [_compte("enrole-absent", "admin", True), _compte("neuf-absent", "admin", False), _compte("enrole-inconnu", "admin", True, "n'importe-quoi")]
    return out


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "groups": [], "users": comptes()}))
    (tmp_path / "sessions.json").write_text("[]")
    (tmp_path / "totp-pending.json").write_text("{}")
    for k, v in {"USERS_FILE": users, "SECUBOX_AUTH_DATA_DIR": tmp_path, "SECUBOX_AUTH_SESSIONS": tmp_path / "sessions.json",
                 "SECUBOX_AUTH_AUDIT": tmp_path / "audit.log", "SECUBOX_AUTH_TOTP_PENDING": tmp_path / "totp-pending.json",
                 "SECUBOX_AUTH_REGLAGES": tmp_path / "reglages.json"}.items():
        monkeypatch.setenv(k, str(v))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret-de-trente-deux-octets!!")
    from secubox_core import config as sbx_config, user_store
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    monkeypatch.setattr(user_store, "USERS_PATH", users)
    from api import main as auth_main
    importlib.reload(auth_main)
    return TestClient(auth_main.app), tmp_path, auth_main


def login(c, nom, lan):
    # « 0 » explicite pour le WAN : secubox_core.testing fait poser X-SecuBox-LAN: 1 par défaut à tout TestClient du parc.
    return c.post("/login", json={"username": nom, "password": MDP}, headers={"X-SecuBox-LAN": "1" if lan else "0"}).json()


def issue(r):
    return "jeton" if r.get("access_token") else "mfa" if r.get("mfa_required") else "enrolement" if r.get("enrollment_required") else str(r)


# (mode, compte enrôlé ?, LAN ?) -> ce que la connexion rend. « defaut » = réglage global « facultatif » (LAN : mot de passe suffit).
MATRICE = [
    ("defaut", True, False, "mfa"), ("defaut", True, True, "jeton"), ("defaut", False, False, "enrolement"), ("defaut", False, True, "jeton"),
    ("hors_lan", True, False, "mfa"), ("hors_lan", True, True, "jeton"), ("hors_lan", False, False, "enrolement"), ("hors_lan", False, True, "jeton"),
    ("toujours", True, False, "mfa"), ("toujours", True, True, "mfa"), ("toujours", False, False, "enrolement"), ("toujours", False, True, "enrolement"),
    ("jamais", True, False, "jeton"), ("jamais", True, True, "jeton"), ("jamais", False, False, "jeton"), ("jamais", False, True, "jeton"),
]


@pytest.mark.parametrize("mode,enrole,lan,attendu", MATRICE)
def test_matrice_mode_reseau_enrolement(env, mode, enrole, lan, attendu):
    c, _, _ = env
    nom = f"{'enrole' if enrole else 'neuf'}-{mode}"
    assert issue(login(c, nom, lan)) == attendu, (mode, enrole, lan)


def test_un_compte_sans_champ_ou_avec_une_valeur_inconnue_suit_le_reglage_global(env):
    c, _, _ = env
    assert issue(login(c, "enrole-absent", False)) == "mfa" and issue(login(c, "enrole-absent", True)) == "jeton"
    assert issue(login(c, "enrole-inconnu", False)) == "mfa" and issue(login(c, "enrole-inconnu", True)) == "jeton"


def test_le_reglage_global_obligatoire_ne_s_applique_qu_aux_comptes_par_defaut(env):
    c, tmp, _ = env
    (tmp / "reglages.json").write_text(json.dumps({"otp_lan": "obligatoire"}))
    assert issue(login(c, "enrole-defaut", True)) == "mfa"          # suit le global
    assert issue(login(c, "enrole-hors_lan", True)) == "jeton"      # le compte l'emporte
    assert issue(login(c, "enrole-jamais", False)) == "jeton"
    assert issue(login(c, "enrole-toujours", True)) == "mfa"


def test_les_utilisateurs_ordinaires_suivent_la_meme_regle(env):
    c, _, _ = env
    assert issue(login(c, "lect-jamais", False)) == "jeton" and issue(login(c, "lect-toujours", True)) == "mfa"
    assert issue(login(c, "lect-hors_lan", False)) == "mfa" and issue(login(c, "lect-hors_lan", True)) == "jeton"


def test_le_verdict_lan_reste_celui_de_nginx_pas_l_adresse(env):
    """`hors_lan` : un client sans verdict (ou avec une valeur autre que « 1 ») est le WAN."""
    c, _, _ = env
    for v in ("0", "", "true", "yes"):
        r = c.post("/login", json={"username": "enrole-hors_lan", "password": MDP}, headers={"X-SecuBox-LAN": v}).json()
        assert issue(r) == "mfa", v


# ---------- le journal dit pourquoi ----------

def raisons(tmp):
    return [json.loads(ligne).get("otp") for ligne in (tmp / "audit.log").read_text().splitlines() if '"login_success"' in ligne]


def test_le_journal_distingue_le_compte_desactive_du_lan_facultatif(env):
    c, tmp, _ = env
    login(c, "enrole-jamais", False)
    login(c, "enrole-defaut", True)
    r = raisons(tmp)
    assert "désactivé (compte)" in r and "facultatif (LAN)" in r


# ---------- le coffre ----------

@pytest.fixture
def coffre(env, monkeypatch):
    c, tmp, m = env
    appels = []
    monkeypatch.setattr(m._coffre, "preparer", lambda u, p: "TICKET")
    monkeypatch.setattr(m._coffre, "confirmer", lambda ticket, distante: appels.append((ticket, distante)) or False)
    monkeypatch.setattr(m._coffre, "garder", lambda *a, **k: None)
    return c, appels


def test_depuis_le_wan_sans_second_facteur_le_coffre_ne_s_ouvre_jamais(coffre):
    c, appels = coffre
    assert issue(login(c, "enrole-jamais", False)) == "jeton"
    assert appels == [(None, True)], "WAN sans second facteur : aucun ticket ne part vers le coffre"


def test_depuis_le_lan_sans_second_facteur_le_coffre_s_ouvre_comme_avant(coffre):
    c, appels = coffre
    assert issue(login(c, "enrole-jamais", True)) == "jeton"
    assert appels == [("TICKET", False)]
    appels.clear()
    assert issue(login(c, "enrole-defaut", True)) == "jeton" and appels == [("TICKET", False)]


def test_un_compte_defaut_ou_toujours_ne_change_rien_pour_le_coffre(coffre):
    c, appels = coffre
    login(c, "enrole-toujours", True)                # défi : rien n'est confirmé avant le second facteur
    assert appels == []


# ---------- le défi MFA reste celui d'avant ----------

def test_le_defi_mfa_d_un_compte_toujours_se_resout_comme_avant(env, monkeypatch):
    c, _, m = env
    r = login(c, "enrole-toujours", True)
    assert r.get("mfa_required") and r.get("mfa_token") and "access_token" not in r
