# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: users — les secrets ne doivent jamais quitter le processus.

users.json contient le hash argon2id du mot de passe, le SECRET TOTP et les
hashes des codes de secours. Les routes qui renvoient un utilisateur sont
gardées par `require_jwt` — donc n'importe quel compte authentifié, pas
seulement un admin. Un enregistrement non expurgé transforme le compte le moins
privilégié en moissonneuse d'identifiants.
"""
from api.redact import redact_user

# La forme réelle observée dans /etc/secubox/users.json sur la board.
REAL_SHAPE = {
    "username": "admin",
    "email": "gandalf@gk2.net",
    "role": "admin",
    "enabled": True,
    "created": "2026-05-09T11:14:11.719355",
    "last_login": "2026-07-17T09:01:36.952678+00:00",
    "must_change_password": False,
    "google": None,
    "services": [],
    "password_hash": "$argon2id$v=19$m=1024,t=1,p=1$c2FsdA$hash",
    "totp": {
        "enabled": True,
        "enrolled_at": "2026-05-09T11:20:00",
        "secret": "JBSWY3DPEHPK3PXP",
        "last_step": 59475852,
        "backup_codes": [{"hash": "$argon2id$v=19$m=65536,t=3,p=4$abc$def"}],
    },
}


def _flat(obj) -> str:
    """Sérialisation grossière : un secret imbriqué reste détectable."""
    import json
    return json.dumps(obj)


def test_password_hash_never_leaves():
    assert "password_hash" not in redact_user(REAL_SHAPE)


def test_totp_secret_never_leaves():
    # Le pire des trois : le secret TOTP seul permet de forger des codes à 6
    # chiffres indéfiniment — un contournement complet du MFA.
    out = redact_user(REAL_SHAPE)
    assert "secret" not in out["totp"]
    assert "JBSWY3DPEHPK3PXP" not in _flat(out)


def test_backup_code_hashes_never_leave():
    out = redact_user(REAL_SHAPE)
    assert "backup_codes" not in out["totp"]
    assert "argon2id" not in _flat(out)


def test_no_argon2_hash_survives_anywhere():
    # Filet global : attrape tout futur champ portant un hash.
    assert "$argon2" not in _flat(redact_user(REAL_SHAPE))


def test_fields_the_panel_needs_are_preserved():
    out = redact_user(REAL_SHAPE)
    for k in ("username", "email", "role", "enabled", "created",
              "last_login", "must_change_password", "services"):
        assert k in out, f"le panel a besoin de {k}"


def test_totp_presence_is_preserved_for_the_mfa_badge():
    # Le panel décide du badge MFA par simple véracité
    # (`u.totp_enabled || u.totp || u.mfa_enabled`) : supprimer la clé
    # éteindrait le badge en silence.
    out = redact_user(REAL_SHAPE)
    assert out["totp"]            # truthy
    assert out["totp"]["enabled"] is True
    assert out["totp_enabled"] is True


def test_user_without_totp_does_not_gain_a_badge():
    # Symétrique : ne jamais allumer le badge d'un utilisateur non enrôlé.
    out = redact_user({"username": "gk2", "password_hash": "$argon2id$x"})
    assert out.get("totp") is None
    assert out["totp_enabled"] is False


def test_totp_present_but_disabled_reports_not_enabled():
    out = redact_user({"username": "u", "totp": {"enabled": False, "secret": "S"}})
    assert out["totp_enabled"] is False
    assert "secret" not in out["totp"]


def test_redaction_does_not_mutate_the_stored_record():
    # redact_user reçoit l'objet chargé depuis users.json ; le muter
    # corromprait la base au prochain save.
    import copy
    original = copy.deepcopy(REAL_SHAPE)
    redact_user(REAL_SHAPE)
    assert REAL_SHAPE == original
