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
        self.d, self.users, self.journal = d, d / "users.json", d / "journal" / "audit.log"
        self.journal.parent.mkdir(exist_ok=True)
        self.env = {"PATH": os.environ["PATH"], "USERS_FILE": str(self.users), "SECUBOX_AUDIT_LOG": str(self.journal),
                    "SECUBOX_CONF": str(d / "secubox.conf"), "SECUBOX_AUTH_DELEGUES": str(d / "delegues.json"),
                    "SECUBOX_AUTH_SESSIONS": str(d / "sessions.json"), "SBXID_DB": str(d / "sbx.db"),
                    "SECUBOX_ACCES_DEMANDES": str(d / "demandes.json"), "SECUBOX_AUTH_DATA_DIR": str(d), "PYTHONPATH": f"{ROOT / 'common'}:{USERS}"}

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
    for k in b.env:
        if k.startswith(("SECUBOX_", "SBXID_")):
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
    gardes += [compte("vieux", hashlib.sha256(b"x").hexdigest()), compte("op", role="operator")]
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
    (box.d / "sessions.json").write_text(json.dumps([{"id": "b", "username": "chef"}]))
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


def test_renommage_un_compte_qui_a_servi_est_garde(box):
    for autre in (compte("admin"), compte("chef", CHOISI)):
        box.pose(autre, compte("ancien", last_login="2026-10-01T00:00:00+00:00"))
        assert box.e.renommer_compte_machine("ancien", "neuf") == "garde" and box.etat()["ancien"] is True


# ── Création par la page Utilisateurs ─────────────────────────────────────────────────────────────────────────────────

def test_un_compte_cree_par_la_page_a_son_mot_de_passe(box, monkeypatch):
    """Sans empreinte, il ne s'ouvrait que par la première configuration, désormais fermée sur une box configurée."""
    import importlib
    monkeypatch.setenv("USERS_FILE", str(box.users))
    monkeypatch.setattr("secubox_core.config._CONFIG", {})
    box.pose(compte("chef", CHOISI))
    import api.main as m
    importlib.reload(m)
    r = m.create_user(m.UserCreate(username="usager", email="u@example.org", password="provisoire bien long"))
    assert r["success"] is True and "password_hash" not in json.dumps(r)
    u = box.e.get_user("usager")
    assert u["must_change_password"] is True and u["role"] == "viewer"
    assert box.e.verify_password_for_user("usager", "provisoire bien long")


# ── I1 : un compte qui sert n'est jamais désactivé ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("champ", [{"totp": {"enabled": True}}, {"google": {"sub": "1"}}, {"services": ["nextcloud"]},
                                   {"last_login": "2026-10-01T00:00:00+00:00"}])
@pytest.mark.parametrize("h", [None, DEFAUT])
def test_compte_qui_sert_jamais_desactive(box, champ, h):
    box.pose(compte("chef", CHOISI), compte("sert", h, **champ))
    assert box.e.desactiver_admins_sans_mot_de_passe() == [] and box.etat()["sert"] is True


def _sbxid(chemin, nom):
    import sqlite3
    c = sqlite3.connect(chemin)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE sbx_app_links (user_uuid, app, app_id, libelle)")
    c.execute("INSERT INTO sbx_app_links VALUES ('u','systeme',?,?)", (nom, nom))
    c.commit()
    return c                                    # laissée ouverte : le lien n'est encore que dans le journal WAL


def test_appareil_ou_session_jamais_desactive(box):
    box.pose(compte("chef", CHOISI), compte("lie-acces"), compte("lie-sbxid"), compte("session"), compte("refuse"),
             compte("orphelin"))
    (box.d / "demandes.json").write_text(json.dumps({"demandes": [
        {"compte": "lie-acces", "etat": "acceptee"}, {"compte": "refuse", "etat": "refusee"}, {"compte": None}]}))
    (box.d / "sessions.json").write_text(json.dumps([{"id": "a", "username": "session"}]))
    c = _sbxid(box.d / "sbx.db", "lie-sbxid")
    avant = {f.name: f.stat().st_mtime_ns for f in box.d.glob("sbx.db*")}
    assert box.e.desactiver_admins_sans_mot_de_passe() == ["refuse", "orphelin"]
    assert {f.name: f.stat().st_mtime_ns for f in box.d.glob("sbx.db*")} == avant     # jamais ouverte sur place (#1806)
    c.close()


@pytest.mark.parametrize("fichier", ["demandes.json", "sessions.json", "sbx.db"])
def test_trace_illisible_on_ne_desactive_personne(box, fichier):
    box.pose(compte("chef", CHOISI), compte("orphelin"))
    (box.d / fichier).write_text("{casse" * 50)
    assert box.e.desactiver_admins_sans_mot_de_passe() == []


def test_admin_a_changer_n_est_pas_configure(box):
    box.pose(compte("chef", CHOISI, must_change_password=True), compte("orphelin"))
    assert box.e.desactiver_admins_sans_mot_de_passe() == []


def test_plusieurs_admins(box):
    box.pose(compte("chef", CHOISI), compte("second", CHOISI), compte("sert", last_login="x"), compte("root", DEFAUT),
             compte("o1"), compte("o2"), compte("deja", enabled=False))
    assert box.e.desactiver_admins_sans_mot_de_passe() == ["root", "o1", "o2"]
    assert [a["motif"] for a in box.audit()] == ["mot_de_passe_defaut", "sans_mot_de_passe", "sans_mot_de_passe"]
    u = {x["username"]: x.get("desactive_motif") for x in json.loads(box.users.read_text())["users"]}
    assert u["root"] == u["o1"] == "sans-mot-de-passe-3708" and u["deja"] is None
    box.e.enable_user("o1")
    assert "desactive_motif" not in box.e.get_user("o1")


def test_cle_neuve_seulement_des_defauts_rien_n_est_desactive(box):
    box.pose(compte("admin", DEFAUT, must_change_password=True), compte("root", DEFAUT, must_change_password=True))
    assert box.e.desactiver_admins_sans_mot_de_passe() == [] and all(box.etat().values())


# ── M6 : anciens comptes de service ───────────────────────────────────────────────────────────────────────────────────

def test_ancienne_console_et_delegue_ferme_ne_comptent_pas(box):
    box.pose(compte("admin"), compte("vieille-console", CHOISI, last_login="x"), compte("marque", CHOISI, origine="service"))
    (box.d / "audit.log").write_text('{"event": "console_compte_cree", "user": "vieille-console"}\nbruit\n')
    assert box.e.desactiver_admins_sans_mot_de_passe() == []
    box.pose(compte("chef", CHOISI), compte("vieille-console"), compte("marque", origine="service"))
    assert box.e.desactiver_admins_sans_mot_de_passe() == []


# ── I2 : écriture perdue ──────────────────────────────────────────────────────────────────────────────────────────────

def _ecrivain_ancien(box, nom, **champs):
    """Un écrivain qui ne prend pas le verrou (code d'avant, encore en mémoire pendant la mise à jour)."""
    d = json.loads(box.users.read_text())
    next(u for u in d["users"] if u["username"] == nom).update(champs)
    box.users.write_text(json.dumps(d))


@pytest.mark.parametrize("nom,champs", [("orphelin", {"password_hash": CHOISI, "must_change_password": False}),
                                        ("autre", {"enabled": False})])
def test_changement_dans_la_fenetre_jamais_ecrase(box, monkeypatch, nom, champs):
    box.pose(compte("chef", CHOISI), compte("autre", CHOISI), compte("orphelin"))
    e, fois = box.e, []
    vrai = e._auditer_securite

    def audite(evenement, **k):
        vrai(evenement, **k)
        if not fois:
            fois.append(1)
            _ecrivain_ancien(box, nom, **champs)
    monkeypatch.setattr(e, "_auditer_securite", audite)
    noms = e.desactiver_admins_sans_mot_de_passe()
    u = e.get_user(nom)
    assert all(u[k] == v for k, v in champs.items())
    assert noms == ([] if nom == "orphelin" else ["orphelin"])
    assert "comptes_admin_decision_annulee" in [a["evenement"] for a in box.audit()]


def test_ecritures_concurrentes_aucune_perdue(box):
    """Entre processus : chaque usersctl relit sous le verrou, aucun compte ne disparaît."""
    box.pose(compte("chef", CHOISI))
    ps = [subprocess.Popen([sys.executable, str(USERS / "sbin" / "usersctl"), "add", f"u{i}", "--email", "a@b.c",
                            "--role", "viewer"], env=box.env, cwd="/", stdout=subprocess.DEVNULL) for i in range(8)]
    assert all(p.wait(60) == 0 for p in ps)
    assert len(box.etat()) == 9


def test_verrou_tenu_refus_borne_sans_rien_changer(box, monkeypatch):
    import fcntl
    from api.engine import _comptes_admin
    ca = _comptes_admin()
    box.pose(compte("chef", CHOISI), compte("orphelin"))
    vrai = ca.verrou
    monkeypatch.setattr(ca, "verrou", lambda p: vrai(p, delai=0.2))
    with open(box.d / ".users.json.verrou", "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        with pytest.raises(EngineError):
            box.e.desactiver_admins_sans_mot_de_passe()
    assert box.etat()["orphelin"] is True


def test_verrou_par_lien_refuse(box):
    (box.d / ".users.json.verrou").symlink_to("/etc/passwd")
    box.pose(compte("chef", CHOISI), compte("orphelin"))
    with pytest.raises(OSError):
        box.e.desactiver_admins_sans_mot_de_passe()


# ── M3 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_creation_avec_mot_de_passe_en_une_ecriture(box, monkeypatch):
    box.pose()
    e, vus = box.e, []
    vrai = e._save
    monkeypatch.setattr(e, "_save", lambda d: (vus.append(json.dumps(d)), vrai(d)))
    e.create_user("neuf", None, "admin", password="une phrase longue")
    assert len(vus) == 1 and json.loads(vus[0])["users"][0]["password_hash"]


def test_import_refuse_un_admin_sans_mot_de_passe(box, monkeypatch):
    import importlib
    import io
    from types import SimpleNamespace
    monkeypatch.setenv("USERS_FILE", str(box.users))
    monkeypatch.setattr("secubox_core.config._CONFIG", {})
    box.pose(compte("chef", CHOISI))
    import api.main as m
    importlib.reload(m)
    lot = {"users": [{"username": "a1", "role": "admin"}, {"username": "v1"},
                     {"username": "a2", "role": "admin", "password": "phrase longue"}]}
    r = m.import_users(SimpleNamespace(file=io.BytesIO(json.dumps(lot).encode())))
    assert r["created"] == ["v1", "a2"] and [x["username"] for x in r["errors"]] == ["a1"]


# ── M2 : le postinst réel, exécuté ────────────────────────────────────────────────────────────────────────────────────

def _postinst(box, hote="boite"):
    faux = box.d / "faux"
    faux.mkdir(exist_ok=True)
    for n, corps in {"hostname": f"echo {hote}", "ischroot": "exit 1", "getent": "exit 0", "install": "exit 0",
                     "chown": "exit 0", "systemctl": f"echo \"$*\" >> {box.d}/systemctl"}.items():
        (faux / n).write_text(f"#!/bin/sh\n{corps}\n")
        (faux / n).chmod(0o755)
    (faux / "python3").symlink_to(sys.executable) if not (faux / "python3").exists() else None
    etc = box.d / "etc"
    etc.mkdir(exist_ok=True)
    (faux / "usersctl").write_text(f"#!/bin/sh\nexec {sys.executable} {USERS}/sbin/usersctl \"$@\"\n")
    (faux / "usersctl").chmod(0o755)
    t = (USERS / "debian" / "postinst").read_text()
    t = t.replace("/usr/sbin/usersctl", "usersctl").replace("/usr/lib/secubox/users", str(USERS)).replace("/etc/secubox", str(etc))
    s = box.d / "postinst"
    s.write_text(t)
    return subprocess.run(["sh", str(s), "configure"], env={**box.env, "PATH": f"{faux}:{os.environ['PATH']}"},
                          capture_output=True, text=True, timeout=90, check=False)


@pytest.mark.parametrize("depart,attendu", [
    ([], {"admin": True, "boite": True}),
    ([compte("admin", DEFAUT, must_change_password=True)], {"admin": True}),
    ([compte("admin", CHOISI)], {"admin": True}),
    ([compte("admin", CHOISI), compte("runnervm0000"), compte("secubox-rpi")],
     {"admin": True, "runnervm0000": False, "secubox-rpi": False}),
    ([compte("chef", CHOISI), compte("sert", last_login="x")], {"chef": True, "sert": True, "admin": False}),
])
def test_postinst_execute(box, depart, attendu):
    box.users = box.d / "etc" / "users.json"
    box.users.parent.mkdir()
    box.env["USERS_FILE"] = str(box.users)
    box.pose(*depart)
    for _ in range(2):
        r = _postinst(box)
        assert r.returncode == 0 and "WARN" not in r.stderr, r.stderr
        assert box.etat() == attendu
    assert len(box.audit()) == sum(not v for v in attendu.values())
