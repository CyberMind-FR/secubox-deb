"""L'anti-rejeu TOTP ne doit pas exiger d'ecrire dans le magasin d'utilisateurs (#990).

Panne mesuree sur la board : /etc/secubox est root:root 0755, secubox-auth
tourne en `secubox`, donc l'ecriture du fichier temporaire de `_save` est
refusee. Et comme `_save` n'est appele QUE dans la branche de succes — pour
enregistrer `last_step` —, le symptome est asymetrique et deroutant :

  - mauvais code -> False -> 401 propre
  - BON code     -> PermissionError -> 500

L'utilisateur qui saisit le bon code est rejete ; s'il se trompe, il recoit un
message coherent. De quoi croire longtemps que son authentificateur derive.

`last_step` est de l'etat d'execution, pas de la configuration : il n'a rien a
faire dans /etc. Ces tests epinglent qu'il vit ailleurs, et que la migration ne
rouvre pas de fenetre de rejeu.
"""
import json
import os
import time

import pytest

pyotp = pytest.importorskip("pyotp")

from api.engine import Engine  # noqa: E402


def _store(tmp_path, secret, last_step=None):
    totp = {"enabled": True, "secret": secret}
    if last_step is not None:
        totp["last_step"] = last_step
    doc = {"version": 2, "groups": [],
           "users": [{"username": "gk2", "enabled": True, "totp": totp}]}
    p = tmp_path / "users.json"
    p.write_text(json.dumps(doc))
    return p


def test_valid_code_succeeds_when_the_store_directory_is_read_only(tmp_path):
    """Le coeur du defaut : repertoire du magasin non inscriptible."""
    secret = pyotp.random_base32()
    d = tmp_path / "etc"; d.mkdir()
    users = _store(d, secret)
    replay = tmp_path / "var" / "totp-replay.json"

    eng = Engine(users, replay_path=replay)
    code = pyotp.TOTP(secret).now()

    os.chmod(d, 0o555)  # lecture + traversee seulement, comme /etc/secubox
    try:
        assert eng.verify_totp_for_user("gk2", code) is True, (
            "un code valide doit etre accepte sans ecrire dans le magasin"
        )
    finally:
        os.chmod(d, 0o755)


def test_replay_of_the_same_code_is_refused(tmp_path):
    """L'anti-rejeu doit rester effectif : c'est sa seule raison d'etre."""
    secret = pyotp.random_base32()
    users = _store(tmp_path, secret)
    replay = tmp_path / "totp-replay.json"
    eng = Engine(users, replay_path=replay)
    code = pyotp.TOTP(secret).now()

    assert eng.verify_totp_for_user("gk2", code) is True
    assert eng.verify_totp_for_user("gk2", code) is False, (
        "le meme code ne doit jamais passer deux fois"
    )


def test_last_step_already_in_users_json_still_acts_as_a_floor(tmp_path):
    """Compatibilite : un last_step herite du magasin doit continuer de faire
    plancher, sinon la migration rouvrirait une fenetre de rejeu sur les codes
    deja consommes."""
    secret = pyotp.random_base32()
    current = int(time.time()) // 30
    users = _store(tmp_path, secret, last_step=current)
    replay = tmp_path / "totp-replay.json"
    eng = Engine(users, replay_path=replay)

    code = pyotp.TOTP(secret).now()
    assert eng.verify_totp_for_user("gk2", code) is False, (
        "un code deja consomme selon users.json doit rester refuse"
    )


def test_users_json_is_never_written_by_verification(tmp_path):
    secret = pyotp.random_base32()
    users = _store(tmp_path, secret)
    replay = tmp_path / "totp-replay.json"
    before = users.read_bytes()

    eng = Engine(users, replay_path=replay)
    assert eng.verify_totp_for_user("gk2", pyotp.TOTP(secret).now()) is True
    assert users.read_bytes() == before, (
        "la verification est un chemin de LECTURE : elle ne doit pas muter le "
        "magasin appartenant a root"
    )
    assert replay.exists(), "l'etat d'anti-rejeu doit etre persiste ailleurs"
