# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3401 : l'indicateur unique « mot de passe par défaut actif »."""
import json

from argon2 import PasswordHasher

from secubox_core import mot_de_passe_defaut as D


def _users(tmp_path, mdp):
    f = tmp_path / "users.json"
    f.write_text(json.dumps({"version": 2, "users": [
        {"username": "admin", "password_hash": PasswordHasher().hash(mdp) if mdp else None}]}))
    return f


def test_actif_quand_l_empreinte_est_celle_du_defaut(tmp_path):
    assert D.actif(users=_users(tmp_path, "secubox")) is True


def test_inactif_apres_changement(tmp_path):
    assert D.actif(users=_users(tmp_path, "une phrase longue et choisie")) is False


def test_inactif_sans_empreinte_ou_fichier(tmp_path):
    assert D.actif(users=_users(tmp_path, None)) is False
    assert D.actif(users=tmp_path / "absent.json") is False


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
