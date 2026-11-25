# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3708, seconde revue : marque durable, verrou réparable, 503 si le registre est occupé, boucles d'écriture."""
import fcntl
import importlib
import inspect
import json
import os

import pytest
from api import engine as E
from test_admins_sans_mot_de_passe_3708 import CHOISI, DEFAUT, Box, compte


@pytest.fixture
def box(tmp_path, monkeypatch):
    b = Box(tmp_path)
    for k, v in b.env.items():
        if k.startswith(("SECUBOX_", "SBXID_")):
            monkeypatch.setenv(k, v)
    monkeypatch.setenv("USERS_FILE", str(b.users))
    monkeypatch.setattr("secubox_core.config._CONFIG", {})
    return b


@pytest.fixture
def api(box):
    import api.main as m
    return importlib.reload(m)


def marque(box):
    return json.loads(box.users.read_text()).get("admin_configure_le")


# ── R1 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_marque_posee_au_premier_mot_de_passe_choisi_et_durable(box):
    ca = E._comptes_admin()
    box.pose(compte("admin"), compte("sert", last_login="x"))
    e = box.e
    e.enable_user("admin")
    assert marque(box) is None
    e.set_password("admin", "une phrase longue")
    posee = marque(box)
    assert posee
    e.set_password("admin", "provisoire", must_change=True)       # l'administrateur unique réinitialisé
    e.clear_password("admin")
    doc = json.loads(box.users.read_text())
    assert doc["admin_configure_le"] == posee
    assert not ca.premiere_configuration_permise("sert", doc) and not ca.premiere_configuration_permise("admin", doc)
    assert e.desactiver_admins_sans_mot_de_passe() == []          # fermer un compte garde la règle stricte
    assert e.semer_comptes("boite") == []


@pytest.mark.parametrize("u,attendu", [(compte("admin", DEFAUT), False), (compte("admin"), False),
                                       (compte("admin", CHOISI), True),
                                       (compte("admin", CHOISI, must_change_password=True), False),
                                       (compte("admin", CHOISI, must_change_password=True, totp={"enabled": False}), False),
                                       (compte("admin", CHOISI, must_change_password=True, totp={"enabled": True}), True),
                                       (compte("admin", CHOISI, must_change_password=True, last_login="x"), True),
                                       (compte("console", CHOISI), False), (compte("v", CHOISI, role="viewer"), False)])
def test_marque_semee_par_le_postinst(box, u, attendu):
    box.pose(u)
    assert box.ctl("marquer-configure").returncode == 0
    assert bool(marque(box)) is attendu


def test_le_mot_de_passe_par_defaut_ne_se_choisit_plus_une_fois_configure(box):
    box.pose(compte("admin", CHOISI))
    box.ctl("marquer-configure")
    with pytest.raises(E.EngineError):
        box.e.set_password("admin", "secubox")


def test_rouvrir_est_un_geste_root_audite_refuse_s_il_reste_un_admin_configure(box, monkeypatch):
    box.pose(compte("admin", CHOISI))
    box.ctl("marquer-configure")
    with pytest.raises(E.EngineError):
        box.e.rouvrir_premiere_configuration()
    box.e.clear_password("admin")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(E.EngineError):
        box.e.rouvrir_premiere_configuration()
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda *a: None)
    box.e.rouvrir_premiere_configuration()
    assert marque(box) is None and box.audit()[-1]["evenement"] == "premiere_configuration_rouverte"


def test_la_migration_garde_la_marque(box):
    box.users.write_text(json.dumps({"admin_configure_le": "2026-01-01", "users": [compte("admin", CHOISI)]}))
    from api.migrate_v1_to_v2 import migrate
    migrate(box.users, None)
    assert marque(box) == "2026-01-01"


# ── R2 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_roles_d_un_compte_qui_n_est_pas_le_premier(box, api):
    box.pose(compte("un"), compte("deux"))
    api.assign_user_roles("deux", api.UserRoleAssign(roles=["admin"]))
    assert box.e.get_user("deux")["roles"] == ["admin"] and "roles" not in box.e.get_user("un")
    with pytest.raises(api.HTTPException) as x:
        api.assign_user_roles("absent", api.UserRoleAssign(roles=["admin"]))
    assert x.value.status_code == 404


def test_groupe_qui_n_est_pas_le_premier(box, api):
    box.pose(compte("un"))
    for g in ("g1", "g2"):
        api.create_group(api.GroupCreate(name=g))
    api.delete_group("g2")
    assert [g["name"] for g in json.loads(box.users.read_text())["groups"]] == ["g1"]
    with pytest.raises(api.HTTPException) as x:
        api.delete_group("absent")
    assert x.value.status_code == 404


def test_modification_et_services_d_un_compte_qui_n_est_pas_le_premier(box, api):
    box.pose(compte("un"), compte("deux"))
    api.update_user("deux", api.UserUpdate(email="d@example.org"))
    api._note_services("deux", "nextcloud", True)
    u = box.e.get_user("deux")
    assert u["email"] == "d@example.org" and u["services"] == ["nextcloud"] and box.e.get_user("un")["services"] == []


# ── R4 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_root_repare_le_verrou(box, monkeypatch):
    box.pose(compte("admin"))
    v = box.d / ".users.json.verrou"
    v.write_text("")
    v.chmod(0o600)
    vus = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda fd, u, g: vus.append((u, g)))
    monkeypatch.setattr(E._comptes_admin(), "_gid_secubox", lambda: 4242)
    with box.e.verrou():
        pass
    assert vus == [(0, 4242)] and v.stat().st_mode & 0o777 == 0o640


def test_postinst_ne_touche_pas_le_verrou_par_chemin():
    """/etc/secubox est au compte secubox : un chown par chemin s'y détourne. `usersctl semer` répare par descripteur."""
    from test_admins_sans_mot_de_passe_3708 import USERS
    t = (USERS / "debian" / "postinst").read_text()
    assert ".users.json.verrou" not in t
    assert t.index("usersctl semer") < t.index("usersctl marquer-configure") < t.index("usersctl desactiver-admins")


def test_verrou_illisible_devient_engineerror_et_la_connexion_tient(box):
    box.pose(compte("admin", CHOISI))
    v = box.d / ".users.json.verrou"
    v.write_text("")
    v.chmod(0)
    if os.geteuid() == 0:
        pytest.skip("root lit tout")
    with pytest.raises(E.EngineError):
        box.e.enable_user("admin")
    box.e.touch_last_login("admin")                       # jamais d'exception


def test_touch_last_login_avale_une_ecriture_impossible(box, monkeypatch):
    box.pose(compte("admin", CHOISI))
    e = box.e
    monkeypatch.setattr(e, "_save", lambda d: (_ for _ in ()).throw(OSError("disque")))
    e.touch_last_login("admin")


# ── Mineurs ───────────────────────────────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("appel", [
    lambda m: m.disable_user("admin"), lambda m: m.enable_user("admin"), lambda m: m.disable_user_totp("admin"),
    lambda m: m.change_password("admin", m.PasswordChange(password="une phrase longue")),
    lambda m: m.create_group(m.GroupCreate(name="g")), lambda m: m.update_user("admin", m.UserUpdate(enabled=False)),
    lambda m: m.set_user_otp_mode("admin", {"mode": "toujours"}, {"sub": "x"}),
    lambda m: m.delete_user("admin")])
def test_registre_occupe_503(box, api, monkeypatch, appel):
    box.pose(compte("admin", CHOISI))
    ca = E._comptes_admin()
    vrai = ca.verrou
    monkeypatch.setattr(ca, "verrou", lambda p: vrai(p, delai=0.1))
    with open(box.d / ".users.json.verrou", "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            appel(api)
            pytest.fail("aurait dû refuser")
        except api.HTTPException as x:
            assert x.status_code == 503
        except api._engine_mod.EngineBusy:
            assert api._engine_mod.EngineBusy in api.app.exception_handlers      # rendu 503 par l'application


def test_aucune_ecriture_sur_la_boucle(api):
    for n in ("disable_user_totp", "set_user_otp_mode", "regen_backup_codes", "update_user", "assign_user_roles"):
        assert not inspect.iscoroutinefunction(getattr(api, n)), n


# ── N1 : le plancher anti-rejeu sous verrou ───────────────────────────────────────────────────────────────────────────

def test_un_code_totp_n_est_accepte_qu_une_fois_en_parallele(box, monkeypatch):
    import threading
    import time

    import pyotp
    noms = [f"u{i}" for i in range(6)]
    secret = pyotp.random_base32()
    box.pose(*(compte(n, CHOISI, totp={"enabled": True, "secret": secret}) for n in noms))
    monkeypatch.setenv("SECUBOX_TOTP_REPLAY_PATH", str(box.d / "plancher.json"))
    e = box.e
    vrai = e._replay_load
    monkeypatch.setattr(e, "_replay_load", lambda: (vrai(), time.sleep(0.005))[0])      # élargit la fenêtre
    code, depart = pyotp.TOTP(secret).now(), threading.Barrier(24)
    oui, erreurs = [], []

    def f(nom):
        depart.wait()
        try:
            if e.verify_totp_for_user(nom, code):
                oui.append(nom)
        except Exception as x:  # noqa: BLE001 — c'est le constat du test
            erreurs.append(x)
    fils = [threading.Thread(target=f, args=(noms[i % 6],)) for i in range(24)]
    [t.start() for t in fils]
    [t.join() for t in fils]
    assert erreurs == [] and sorted(oui) == noms
    assert sorted(json.loads((box.d / "plancher.json").read_text())) == noms        # aucun plancher perdu


def test_plancher_partage_avec_le_second_facteur_commun(box, monkeypatch):
    import pyotp
    from secubox_core import second_facteur, user_store
    secret = pyotp.random_base32()
    box.pose(compte("admin", CHOISI, totp={"enabled": True, "secret": secret}))
    monkeypatch.setenv("SECUBOX_TOTP_REPLAY_PATH", str(box.d / "plancher.json"))
    monkeypatch.setattr(user_store, "USERS_PATH", box.users)
    code = pyotp.TOTP(secret).now()
    assert box.e.verify_totp_for_user("admin", code) and not second_facteur.verifie_totp("admin", code)
