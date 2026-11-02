# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 : l'indicateur unique « mot de passe par défaut actif »."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from argon2 import PasswordHasher

from secubox_core import mot_de_passe_defaut as D


def _users(tmp_path, mdp):
    f = tmp_path / "users.json"
    f.write_text(json.dumps({"version": 2, "users": [
        {"username": "admin", "password_hash": PasswordHasher().hash(mdp) if mdp else None}]}))
    return f


def test_actif_quand_l_empreinte_est_celle_du_defaut(tmp_path):
    assert D.verdict(users=_users(tmp_path, "secubox")) == D.ACTIF
    assert D.garde_requise(users=_users(tmp_path, "secubox"))


def test_inactif_apres_changement(tmp_path):
    f = _users(tmp_path, "une phrase longue et choisie")
    assert D.verdict(users=f) == D.INACTIF and not D.garde_requise(users=f)


def test_sans_mot_de_passe_le_defaut_n_est_pas_actif(tmp_path):
    assert D.verdict(users=_users(tmp_path, None)) == D.INACTIF


@pytest.mark.parametrize("contenu", [None, "{pas du json", '{"users": "x"}', '{"users": [{"username": "bob"}]}',
                                     '{"users": [{"username": "admin", "password_hash": "$argon2id$casse"}]}'])
def test_fail_closed_tout_doute_est_inconnu_et_garde(tmp_path, contenu):
    f = tmp_path / "users.json"
    if contenu is not None:
        f.write_text(contenu)
    assert D.verdict(users=f) == D.INCONNU and D.garde_requise(users=f)
    assert D.etat(users=f)["inconnu"] is True


def test_cli_codes_sans_importer_le_paquet(tmp_path):
    src = Path(D.__file__)
    env = {"SECUBOX_USERS_JSON": str(_users(tmp_path, "secubox")), "PATH": "/usr/bin:/bin"}
    r = subprocess.run([sys.executable, str(src)], env=env, cwd="/", capture_output=True, timeout=30, check=False)
    assert r.returncode == 0, r.stderr
    env["SECUBOX_USERS_JSON"] = str(_users(tmp_path, "autre phrase bien longue"))
    assert subprocess.run([sys.executable, str(src)], env=env, cwd="/", timeout=30, check=False).returncode == 10
    env["SECUBOX_USERS_JSON"] = str(tmp_path / "absent")
    assert subprocess.run([sys.executable, str(src)], env=env, cwd="/", timeout=30, check=False).returncode == 2
    # Le module ne tire ni FastAPI ni le paquet secubox_core.
    assert "import fastapi" not in src.read_text() and "from secubox_core" not in src.read_text()


def test_etat_donne_message_et_lien_sans_le_clair(tmp_path):
    e = D.etat(users=_users(tmp_path, "secubox"))
    assert e["actif"] and e["lien"] and "secubox" not in json.dumps(e).replace("SecuBox", "")


def test_est_le_defaut():
    assert D.est_le_defaut("secubox") and not D.est_le_defaut("Secubox")


def test_audit_en_ajout_sans_mot_de_passe(tmp_path):
    log = tmp_path / "audit.log"
    D.audit("connexion", {"ip": "192.168.1.2"}, chemin=log)
    D.audit("leve", {}, chemin=log)
    lignes = log.read_text().splitlines()
    assert len(lignes) == 2 and json.loads(lignes[0])["evenement"] == "connexion"
    assert "secubox\"" not in log.read_text() and oct(log.stat().st_mode & 0o777) == "0o640"



def test_maillage_zone_de_confiance():
    assert D.adresse_du_maillage("10.10.0.7") and D.adresse_du_maillage("10.64.3.2")
    assert not D.adresse_du_maillage("10.11.0.7") and not D.adresse_du_maillage("203.0.113.5")
    assert not D.adresse_du_maillage("pas-une-ip")


def test_aucun_marqueur_persistant():
    src = Path(D.__file__).read_text()
    assert "MARQUEUR_PLUS_TARD" not in src and "plus_tard_choisi" not in src
