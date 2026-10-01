# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Le second facteur hors de secubox-auth, aux MÊMES règles (#1827)."""
import json
import time

import pyotp
import pytest
from starlette.requests import Request

from secubox_core import second_facteur as SF

SECRET = pyotp.random_base32()


@pytest.fixture
def banc(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUBOX_TOTP_REPLAY_PATH", str(tmp_path / "totp-replay.json"))
    monkeypatch.setenv("SECUBOX_AUTH_REGLAGES", str(tmp_path / "reglages.json"))
    comptes = {"gk2": {"role": "admin", "enabled": True, "totp": {"enabled": True, "secret": SECRET}},
               "nu": {"role": "admin", "enabled": True},
               "op": {"role": "operator", "enabled": True},
               "ferme": {"role": "admin", "enabled": False},
               "repli": {"role": "admin", "enabled": True, "_fallback": True}}
    monkeypatch.setattr(SF.user_store, "get_user", lambda u: comptes.get(u))
    monkeypatch.setattr(SF, "get_config", lambda section: {})
    return tmp_path


def _req(lan):
    h = [(b"x-secubox-lan", b"1")] if lan else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": h})


def test_hors_lan_toujours_exige(banc):
    assert SF.otp_exige(_req(False)) is True
    assert SF.otp_exige(_req(True)) is False                   # LAN, « facultatif » par défaut


def test_otp_lan_lit_la_meme_source_qu_auth(banc, monkeypatch):
    (banc / "reglages.json").write_text(json.dumps({"otp_lan": "obligatoire"}))
    assert SF.otp_exige(_req(True)) is True
    (banc / "reglages.json").write_text(json.dumps({"otp_lan": "nimporte"}))  # inconnu : ignoré
    monkeypatch.setattr(SF, "get_config", lambda section: {"otp_lan": "obligatoire"})
    assert SF.otp_lan() == "obligatoire"


def test_un_code_ne_sert_qu_une_fois(banc):
    code = pyotp.TOTP(SECRET).now()
    assert SF.verifie_totp("gk2", code) is True
    assert SF.verifie_totp("gk2", code) is False


def test_le_plancher_est_partage_avec_le_moteur_users(banc):
    """Un pas déjà consommé par la page de connexion (plancher écrit par le
    moteur secubox-users) ne sert pas ici."""
    pas = int(time.time()) // 30
    (banc / "totp-replay.json").write_text(json.dumps({"gk2": pas + 1}))
    assert SF.verifie_totp("gk2", pyotp.TOTP(SECRET).now()) is False


def test_le_last_step_herite_compte_aussi(banc, monkeypatch):
    pas = int(time.time()) // 30
    compte = {"role": "admin", "enabled": True, "totp": {"enabled": True, "secret": SECRET, "last_step": pas + 1}}
    monkeypatch.setattr(SF.user_store, "get_user", lambda u: compte)
    assert SF.verifie_totp("gk2", pyotp.TOTP(SECRET).now()) is False


@pytest.mark.parametrize("code", ["", "12345", "1234567", "abcdef", None])
def test_formes_refusees(banc, code):
    assert SF.verifie_totp("gk2", code) is False


def test_compte_sans_totp_ou_inconnu(banc):
    assert SF.totp_actif("nu") is False and SF.verifie_totp("nu", "123456") is False
    assert SF.verifie_totp("personne", "123456") is False


def test_compte_admin_actif(banc):
    assert SF.compte_admin_actif("gk2") and SF.compte_admin_actif("nu")
    for c in ("op", "ferme", "repli", "personne", None, ""):
        assert not SF.compte_admin_actif(c)
