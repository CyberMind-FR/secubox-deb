# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3708 : un compte admin semé et jamais configuré ne reste pas revendicable (moteur, usersctl, postinst)."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from api.engine import Engine, EngineError

ROOT = Path(__file__).resolve().parents[5]
USERS = ROOT / "packages" / "secubox-auth" / "composants" / "users"
CHOISI = PasswordHasher().hash("une phrase longue et choisie")
DEFAUT = PasswordHasher().hash("secubox")


def compte(nom, h=None, role="admin", enabled=True, **k):
    return {"username": nom, "email": None, "role": role, "enabled": enabled, "password_hash": h,
            "must_change_password": h is None, "totp": None, "google": None, "services": [],
            "created": "2026-09-01T00:00:00+00:00", "last_login": None, **k}


class Box:
    def __init__(self, d: Path):
        self.d, self.users, self.journal = d, d / "users.json", d / "audit.log"
        self.env = {"PATH": os.environ["PATH"], "USERS_FILE": str(self.users), "SECUBOX_AUDIT_LOG": str(self.journal),
                    "SECUBOX_CONF": str(d / "secubox.conf"), "SECUBOX_AUTH_DELEGUES": str(d / "delegues.json"),
                    "SECUBOX_AUTH_SESSIONS": str(d / "sessions.json"), "PYTHONPATH": f"{ROOT / 'common'}:{USERS}"}

    def pose(self, *comptes):
        self.users.write_text(json.dumps({"version": 2, "groups": [], "users": list(comptes)}))

    def etat(self):
        return {u["username"]: u["enabled"] for u in json.loads(self.users.read_text())["users"]}

    def audit(self):
        return [json.loads(x) for x in self.journal.read_text().splitlines()] if self.journal.exists() else []

    def ctl(self, *args):
        return subprocess.run([sys.executable, str(USERS / "sbin" / "usersctl"), *args], env=self.env, cwd="/",
                              capture_output=True, text=True, timeout=60, check=False)

    @property
    def e(self):
        return Engine(users_path=self.users)


@pytest.fixture
def box(tmp_path, monkeypatch):
    b = Box(tmp_path)
    for k in ("SECUBOX_AUDIT_LOG", "SECUBOX_CONF", "SECUBOX_AUTH_DELEGUES"):
        monkeypatch.setenv(k, b.env[k])
    return b


# ── 1. Semis ──────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_box_vierge_seme_comme_avant(box):
    assert box.e.semer_comptes("boite") == ["admin", "boite"]
    assert box.etat() == {"admin": True, "boite": True}
    assert box.e.semer_comptes("boite") == []
    assert box.e.desactiver_admins_sans_mot_de_passe() == [] and box.audit() == []


@pytest.mark.parametrize("h", [CHOISI, DEFAUT])
def test_plus_de_compte_machine_des_qu_un_admin_a_un_mot_de_passe(box, h):
    box.pose(compte("admin", h))
    assert box.e.semer_comptes("boite") == [] and box.etat() == {"admin": True}


@pytest.mark.parametrize("autre", [
    compte("chef", CHOISI, enabled=False), compte("chef", CHOISI, role="operator"), compte("console", CHOISI),
    compte("chef", hashlib.sha256(b"x").hexdigest())])
def test_un_mot_de_passe_qui_n_ouvre_pas_l_administration_ne_compte_pas(box, autre):
    box.pose(compte("admin"), autre)
    assert box.e.semer_comptes("boite") == ["boite"]


def test_le_nom_d_un_compte_de_service_n_est_jamais_seme(box):
    box.pose(compte("admin"))
    assert box.e.semer_comptes("console") == []


# ── 2. Migration ──────────────────────────────────────────────────────────────────────────────────────────────────────

def test_box_aux_deux_orphelins(box):
    box.pose(compte("chef", CHOISI), compte("runnervm0000"), compte("secubox-rpi"), compte("usager", role="viewer"))
    assert box.e.desactiver_admins_sans_mot_de_passe("postinst") == ["runnervm0000", "secubox-rpi"]
    assert box.etat() == {"chef": True, "runnervm0000": False, "secubox-rpi": False, "usager": True}
    assert [(a["evenement"], a["compte"], a["origine"]) for a in box.audit()] == [
        ("admin_sans_mot_de_passe_desactive", n, "postinst") for n in ("runnervm0000", "secubox-rpi")]
    avant = box.users.read_bytes()
    assert box.e.desactiver_admins_sans_mot_de_passe("postinst") == []
    assert box.users.read_bytes() == avant and len(box.audit()) == 2


@pytest.mark.parametrize("autre", [
    compte("chef", DEFAUT), compte("chef", CHOISI, enabled=False), compte("chef", CHOISI, role="viewer"),
    compte("console", CHOISI), compte("chef", hashlib.sha256(b"x").hexdigest()), compte("chef", "$argon2id$casse"),
    compte("aide.autre-noeud", CHOISI)])
def test_sans_autre_admin_configure_rien_ne_bouge(box, autre):
    box.pose(compte("admin"), autre)
    assert box.e.desactiver_admins_sans_mot_de_passe() == [] and box.etat()["admin"] is True


def test_comptes_jamais_touches(box):
    (box.d / "secubox.conf").write_text('[console]\ncompte = "ecran"\n')
    (box.d / "delegues.json").write_text(json.dumps({"aide.noeud": {}}))
    gardes = [compte(n) for n in ("console", "kiosk", "ai", "webhooks", "ecran", "aide.noeud")]
    gardes += [compte("vieux", hashlib.sha256(b"x").hexdigest()), compte("defaut", DEFAUT), compte("op", role="operator")]
    box.pose(compte("chef", CHOISI), *gardes)
    assert box.e.desactiver_admins_sans_mot_de_passe() == [] and all(box.etat().values())


def test_audit_impossible_rien_n_est_desactive(box):
    box.journal.mkdir()
    box.pose(compte("chef", CHOISI), compte("orphelin"))
    with pytest.raises(EngineError):
        box.e.desactiver_admins_sans_mot_de_passe()
    assert box.etat()["orphelin"] is True


def test_audit_par_lien_refuse(box):
    cible = box.d / "ailleurs"
    cible.write_text("")
    box.journal.symlink_to(cible)
    box.pose(compte("chef", CHOISI), compte("orphelin"))
    with pytest.raises(EngineError):
        box.e.desactiver_admins_sans_mot_de_passe()
    assert cible.read_text() == "" and box.etat()["orphelin"] is True


def test_reversible_par_usersctl(box):
    box.pose(compte("chef", CHOISI), compte("orphelin"))
    (box.d / "sessions.json").write_text(json.dumps([{"id": "a", "username": "orphelin"}, {"id": "b", "username": "chef"}]))
    r = box.ctl("desactiver-admins-sans-mot-de-passe", "--origine=postinst")
    assert r.returncode == 0 and "usersctl enable orphelin" in r.stdout, r.stderr
    assert [s["id"] for s in json.loads((box.d / "sessions.json").read_text())] == ["b"]
    box.e.set_password("orphelin", "autre phrase bien longue")
    assert box.ctl("enable", "orphelin").returncode == 0
    assert box.ctl("desactiver-admins-sans-mot-de-passe").stdout == "" and box.etat()["orphelin"] is True


def test_un_compte_rouvert_sans_mot_de_passe_se_referme(box):
    box.pose(compte("chef", CHOISI), compte("orphelin"))
    for _ in range(2):
        box.ctl("enable", "orphelin")
        box.ctl("desactiver-admins-sans-mot-de-passe")
    assert box.etat()["orphelin"] is False


def test_postinst_seme_puis_referme_sans_avaler_les_droits():
    t = (USERS / "debian" / "postinst").read_text()
    assert t.index("usersctl semer --machine=") < t.index("usersctl desactiver-admins-sans-mot-de-passe") \
        < t.index("chown root:secubox /etc/secubox/users.json")
    assert "create_user" not in t and "ischroot" in t


def test_les_composants_ne_sont_configures_qu_une_fois():
    assert (ROOT / "packages/secubox-auth/debian/postinst").read_text().count("maintscripts/*.postinst") == 1


def test_un_admin_reseme_sur_une_box_configuree_est_aussitot_referme(box):
    box.pose(compte("chef", CHOISI))
    assert box.ctl("semer", "--machine=boite").returncode == 0
    assert box.ctl("desactiver-admins-sans-mot-de-passe").returncode == 0
    assert box.etat() == {"chef": True, "admin": False}


# ── 3. Renommage de la box ────────────────────────────────────────────────────────────────────────────────────────────

def test_renommage_box_configuree_desactive_l_ancien(box):
    box.pose(compte("chef", CHOISI), compte("ancien"))
    assert box.ctl("renommer-compte-machine", "--acteur", "chef", "ancien", "neuf").stdout.strip() == "desactive"
    assert box.etat() == {"chef": True, "ancien": False} and box.audit()[0]["acteur"] == "chef"


@pytest.mark.parametrize("admin", [compte("admin"), compte("admin", DEFAUT)])
def test_renommage_box_vierge_renomme_le_compte(box, admin):
    box.pose(admin, compte("ancien"))
    assert box.e.renommer_compte_machine("ancien", "neuf") == "renomme"
    assert box.etat() == {"admin": True, "neuf": True}
    assert box.audit()[0]["evenement"] == "compte_machine_renomme"


def test_renommage_nouveau_nom_deja_pris_ou_impossible(box):
    box.pose(compte("admin"), compte("ancien"), compte("neuf"))
    assert box.e.renommer_compte_machine("ancien", "neuf") == "desactive"
    box.pose(compte("admin"), compte("ancien"))
    assert box.e.renommer_compte_machine("ancien", "a" * 60) == "desactive"
    box.pose(compte("ancien"), compte("console", CHOISI))
    assert box.e.renommer_compte_machine("ancien", "console") == "garde" and box.etat()["ancien"] is True


@pytest.mark.parametrize("u", [compte("ancien", CHOISI), compte("ancien", DEFAUT), compte("ancien", role="viewer"),
                               compte("ancien", enabled=False)])
def test_renommage_ne_touche_pas_les_autres_comptes(box, u):
    box.pose(compte("chef", CHOISI), u)
    avant = box.users.read_bytes()
    assert box.e.renommer_compte_machine("ancien", "neuf") == "aucun" and box.users.read_bytes() == avant


def test_renommage_un_compte_qui_a_servi_n_est_pas_renomme(box):
    box.pose(compte("admin"), compte("ancien", last_login="2026-10-01T00:00:00+00:00"))
    assert box.e.renommer_compte_machine("ancien", "neuf") == "desactive" and box.etat()["ancien"] is False


# ── Création par la page Utilisateurs ─────────────────────────────────────────────────────────────────────────────────

def test_un_compte_cree_par_la_page_a_son_mot_de_passe(box, monkeypatch):
    """Sans empreinte, il ne s'ouvrait que par la première configuration, désormais fermée sur une box configurée."""
    import importlib
    monkeypatch.setenv("USERS_FILE", str(box.users))
    box.pose(compte("chef", CHOISI))
    import api.main as m
    importlib.reload(m)
    r = m.create_user(m.UserCreate(username="usager", email="u@example.org", password="provisoire bien long"))
    assert r["success"] is True and "password_hash" not in json.dumps(r)
    u = box.e.get_user("usager")
    assert u["must_change_password"] is True and u["role"] == "viewer"
    assert box.e.verify_password_for_user("usager", "provisoire bien long")
