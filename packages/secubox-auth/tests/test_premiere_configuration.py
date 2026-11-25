# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1707 : la première configuration d'un compte est un acte LOCAL."""
import importlib
import json
import os
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient


def _compte(nom, mdp, a_changer):
    return {"username": nom, "email": None, "role": "admin", "enabled": True,
            "password_hash": PasswordHasher().hash(mdp) if mdp else None,
            "must_change_password": a_changer, "totp": None, "google": None, "services": [],
            "created": "2026-09-01T00:00:00+00:00", "last_login": None}


@pytest.fixture
def c(tmp_path: Path, monkeypatch):
    users = tmp_path / "users.json"
    users.write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("gk3", None, True),               # le cas vécu : admin, aucun mot de passe
        _compte("admin", "secubox", True),        # le compte du premier démarrage
    ]}))
    (tmp_path / "sessions.json").write_text("[]")
    (tmp_path / "totp-pending.json").write_text("{}")
    for k, v in {"USERS_FILE": users, "SECUBOX_AUTH_DATA_DIR": tmp_path,
                 "SECUBOX_AUTH_SESSIONS": tmp_path / "sessions.json",
                 "SECUBOX_AUTH_AUDIT": tmp_path / "audit.log",
                 "SECUBOX_AUTH_TOTP_PENDING": tmp_path / "totp-pending.json",
                 "SECUBOX_AUTH_DELEGUES": tmp_path / "delegues.json", "SECUBOX_CONF": tmp_path / "secubox.conf",
                 "SECUBOX_AUTH_REGLAGES": tmp_path / "reglages.json",
                 "SECUBOX_USERS_JSON": users, "SECUBOX_AUDIT_LOG": tmp_path / "audit-secubox.log"}.items():
        monkeypatch.setenv(k, str(v))
    monkeypatch.setenv("SECUBOX_JWT_SECRET", "test-secret-de-trente-deux-octets!!")
    from secubox_core import config as sbx_config, user_store
    monkeypatch.setattr(sbx_config, "_CONF_PATHS", [])
    monkeypatch.setattr(sbx_config, "_CONFIG", None)
    monkeypatch.setattr(user_store, "USERS_PATH", users)
    from api import main as auth_main
    importlib.reload(auth_main)
    return TestClient(auth_main.app)


def _login(c, nom, mdp, lan):
    return c.post("/login", json={"username": nom, "password": mdp}, headers={"X-SecuBox-LAN": lan})


def test_depuis_le_wan_un_mot_de_passe_vide_ne_donne_rien(c):
    r = _login(c, "gk3", "", "0")
    assert r.status_code == 401 and "setup_token" not in r.text


def test_depuis_le_lan_la_premiere_configuration_est_offerte(c):
    r = _login(c, "gk3", "", "1")
    assert r.status_code == 200 and r.json().get("setup_required") is True


def test_compte_a_changer_avec_mot_de_passe_le_vide_ne_suffit_pas(c):
    r = _login(c, "admin", "", "1")
    assert r.status_code == 401 and "setup_token" not in r.text


def test_le_bon_mot_de_passe_impose_le_changement_pas_une_session(c):
    # Sans le marqueur « Plus tard », le flux d'origine (#1707) : changement obligatoire.
    r = _login(c, "admin", "secubox", "1").json()
    assert r.get("setup_required") is True and "access_token" not in r


def _setup(c, nom="admin", lan="1", xff=None):
    h = {"X-SecuBox-LAN": lan}
    if xff:
        h["X-Forwarded-For"] = xff
    r = c.post("/login", json={"username": nom, "password": "secubox"}, headers=h).json()
    assert r.get("setup_required") is True and "access_token" not in r
    return r["setup_token"]


def _plus_tard(c, jeton, lan="1", xff=None):
    h = {"Authorization": "Bearer " + jeton, "X-SecuBox-LAN": lan}
    if xff:
        h["X-Forwarded-For"] = xff
    return c.post("/plus-tard", headers=h)


def test_plus_tard_ouvre_une_session_lan_admin_auditee(c, tmp_path):
    r = _plus_tard(c, _setup(c))
    assert r.status_code == 200 and "access_token" in r.json()
    lignes = [json.loads(x) for x in (tmp_path / "audit-secubox.log").read_text().splitlines()]
    assert lignes[-1]["evenement"] == "mot_de_passe_defaut_reporte" and lignes[-1]["compte"] == "admin"


def test_plus_tard_depuis_le_maillage(c):
    jeton = _setup(c, lan="0", xff="10.10.0.7")
    assert _plus_tard(c, jeton, lan="0", xff="10.64.2.9").status_code == 200


def test_plus_tard_refuse_hors_lan(c):
    jeton = _setup(c)
    r = _plus_tard(c, jeton, lan="0", xff="203.0.113.9")
    assert r.status_code == 401 and "access_token" not in r.text


def test_plus_tard_refuse_pour_un_non_admin(c, tmp_path):
    users = tmp_path / "users.json"
    d = json.loads(users.read_text())
    d["users"].append(_compte("bob", "secubox", True))
    users.write_text(json.dumps(d))
    r = _plus_tard(c, _setup(c, "bob"))
    assert r.status_code == 403 and "access_token" not in r.text


def test_la_connexion_suivante_redemande(c):
    _plus_tard(c, _setup(c))
    _setup(c)                                   # la question revient : rien n'a été persisté


def test_setup_token_a_usage_unique(c):
    jeton = _setup(c)
    assert _plus_tard(c, jeton).status_code == 200
    assert _plus_tard(c, jeton).status_code == 401
    r = c.post("/set-password", json={"new_password": "une phrase longue et choisie"},
               headers={"Authorization": "Bearer " + jeton})
    assert r.status_code == 401


def test_defaut_depuis_le_maillage_demande_le_changement(c):
    _setup(c, lan="0", xff="10.10.0.7")


def test_depuis_le_wan_le_defaut_est_un_401_identique_mais_audite(c, tmp_path):
    bon = _login(c, "admin", "secubox", "0")
    faux = _login(c, "admin", "secubox2", "0")
    assert bon.status_code == faux.status_code == 401 and bon.json() == faux.json()
    assert "connexion_refusee_hors_lan" in (tmp_path / "audit-secubox.log").read_text()


def test_depuis_le_wan_un_mauvais_mot_de_passe_reste_un_401_muet(c):
    r = _login(c, "admin", "secubox2", "0")
    assert r.status_code == 401 and "défaut" not in r.text


def test_un_mot_de_passe_reinitialise_impose_encore_le_changement(c, tmp_path):
    users = tmp_path / "users.json"
    d = json.loads(users.read_text())
    d["users"].append(_compte("bob", "provisoire-tres-long", True))
    users.write_text(json.dumps(d))
    r = _login(c, "bob", "provisoire-tres-long", "1").json()
    assert r.get("setup_required") is True and "access_token" not in r


def test_etat_refuse_a_un_non_administrateur(c):
    assert c.get("/mot-de-passe-defaut").status_code == 401
    assert c.get("/mot-de-passe-defaut", headers={"Authorization": "Bearer faux"}).status_code == 401


def test_etat_garde_par_require_jwt():
    from api import main as m
    r = next(r for r in m._login_router.routes if getattr(r, "path", "") == "/mot-de-passe-defaut")
    assert any(d.call is m.require_jwt for d in r.dependant.dependencies)


def test_etat_rendu_a_un_administrateur_reel(c):
    from api import main as m
    c.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "admin"}
    try:
        assert c.get("/mot-de-passe-defaut").json()["etat"] == "actif"
    finally:
        c.app.dependency_overrides.clear()


# ── #3708 : la première configuration se ferme dès qu'un administrateur est configuré ─────────────────────────────────

@pytest.fixture
def configuree(c, tmp_path):
    """Box configurée : « chef » a choisi son mot de passe ; deux orphelins et un usager n'en ont pas."""
    (tmp_path / "users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("chef", "une phrase longue et choisie", False), _compte("boite", None, True),
        _compte("secubox-rpi", None, True), {**_compte("usager", None, True), "role": "viewer"},
        {**_compte("coupe", None, True), "enabled": False}]}))
    return c


def _audit(tmp_path):
    return [json.loads(x) for x in (tmp_path / "audit-secubox.log").read_text().splitlines()]


@pytest.mark.parametrize("nom", ["boite", "secubox-rpi", "usager"])
def test_box_configuree_plus_rien_a_revendiquer(configuree, tmp_path, nom):
    r, inconnu = _login(configuree, nom, "", "1"), _login(configuree, "inconnu", "", "1")
    assert r.status_code == inconnu.status_code == 401 and r.json() == inconnu.json()
    assert "setup_token" not in r.text
    ligne = _audit(tmp_path)[-1]
    assert ligne["evenement"] == "premiere_configuration_refusee" and ligne["compte"] == nom


def test_revendication_refusee_depuis_le_maillage(configuree):
    r = configuree.post("/login", json={"username": "boite", "password": ""},
                        headers={"X-SecuBox-LAN": "0", "X-Forwarded-For": "10.10.0.7"})
    assert r.status_code == 401 and "setup_token" not in r.text


@pytest.mark.parametrize("lan", ["0", "1"])
@pytest.mark.parametrize("mdp", ["", "faux", "secubox"])
def test_reponses_uniformes_quel_que_soit_le_compte(configuree, lan, mdp):
    reponses = {(r.status_code, r.text) for r in (
        _login(configuree, n, mdp, lan) for n in ("inconnu", "boite", "usager", "coupe", "chef", "console"))}
    assert reponses == {(401, '{"detail":"Identifiants incorrects"}')}


@pytest.mark.parametrize("mdp", ["", "faux", "secubox", "une phrase longue et choisie"])
def test_une_et_une_seule_verification_argon2_par_demande(configuree, monkeypatch, mdp):
    """M1 : compte connu, inconnu, désactivé, sans empreinte, de service ; verdict lu une fois. Les empreintes des AUTRES
    admins (règle « configuré ») sont en cache après la première lecture."""
    from secubox_core import user_store
    vrai, appels = user_store._HASHER, []

    class Compte:
        def hash(self, x):
            return vrai.hash(x)

        def verify(self, h, p):
            appels.append(h)
            return vrai.verify(h, p)
    for n in ("boite", "inconnu"):
        _login(configuree, n, "", "1")
    monkeypatch.setattr(user_store, "_HASHER", Compte())
    for n in ("inconnu", "boite", "coupe", "console", "usager", "chef"):
        appels.clear()
        _login(configuree, n, mdp, "1")
        assert len(appels) == 1, n


def test_mot_de_passe_demesure_refuse_sans_argon2(configuree, monkeypatch):
    from secubox_core import user_store
    monkeypatch.setattr(user_store, "_HASHER", None)
    r = _login(configuree, "chef", "x" * 5000, "1")
    assert r.status_code == 401 and r.json() == {"detail": "Identifiants incorrects"}


def test_porte_saturee_503_quel_que_soit_le_compte(configuree, monkeypatch):
    from contextlib import contextmanager
    from secubox_core import porte_argon2

    @contextmanager
    def pleine(*_a):
        raise porte_argon2.Saturee(503)
        yield
    monkeypatch.setattr(porte_argon2.PORTE, "passage", pleine)
    rs = [_login(configuree, n, "x", "1") for n in ("inconnu", "boite", "chef", "console")]
    assert {(r.status_code, r.text, r.headers["retry-after"]) for r in rs} == {
        (503, '{"detail":"Trop de connexions en cours, réessayez dans un instant"}', "5")}


def _ajoute(tmp_path, *comptes):
    f = tmp_path / "users.json"
    d = json.loads(f.read_text())
    d["users"] += comptes
    f.write_text(json.dumps(d))


def test_admin_au_mot_de_passe_par_defaut_ferme_quand_un_autre_est_configure(configuree, tmp_path):
    """I4 : `root/secubox` d'une image restait ouvert après la configuration d'admin."""
    _ajoute(tmp_path, _compte("root", "secubox", True))
    r, f = _login(configuree, "root", "secubox", "1"), _login(configuree, "root", "faux", "1")
    assert r.status_code == f.status_code == 401 and r.json() == f.json()
    assert _audit(tmp_path)[-1]["evenement"] == "premiere_configuration_refusee"


def test_cle_neuve_plusieurs_admins_au_defaut_reste_utilisable(c, tmp_path):
    (tmp_path / "users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("admin", "secubox", True), _compte("root", "secubox", True)]}))
    jeton_root = _setup(c, "root")
    plus_tard = _setup(c)
    assert _poser(c, _setup(c)).status_code == 200            # admin configuré
    assert _poser(c, jeton_root).status_code == 401           # jeton obtenu avant : refusé à la pose
    assert _plus_tard(c, plus_tard).status_code in (401, 403)
    assert _login(c, "root", "secubox", "1").status_code == 401


def test_un_admin_a_changer_ne_ferme_pas_la_premiere_configuration(c, tmp_path):
    """I1 : « configuré » exige un mot de passe choisi, pas provisoire."""
    (tmp_path / "users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("admin", None, True), _compte("chef", "provisoire-tres-long", True)]}))
    assert _login(c, "admin", "", "1").json().get("setup_required") is True


def test_pose_sous_le_verrou_deux_revendications_simultanees(c, tmp_path):
    """M7 : deux comptes revendiqués en même temps — un seul est posé."""
    import threading
    (tmp_path / "users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("admin", None, True), _compte("boite", None, True)]}))
    jetons = [_login(c, n, "", "1").json()["setup_token"] for n in ("admin", "boite")]
    codes, depart = [], threading.Barrier(2)

    def pose(j):
        depart.wait()
        codes.append(_poser(c, j).status_code)
    fils = [threading.Thread(target=pose, args=(j,)) for j in jetons]
    [f.start() for f in fils]
    [f.join() for f in fils]
    assert sorted(codes) == [200, 401]


def test_un_compte_de_service_a_mot_de_passe_ne_ferme_pas_la_box_vierge(c, tmp_path):
    (tmp_path / "users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("admin", None, True), _compte("console", "jete-par-le-kiosque", False)]}))
    assert _login(c, "admin", "", "1").json().get("setup_required") is True


def _poser(c, jeton, mdp="une phrase longue et choisie"):
    return c.post("/set-password", json={"new_password": mdp}, headers={"Authorization": "Bearer " + jeton})


def test_box_vierge_le_premier_configure_les_suivants_sont_refuses(c, tmp_path):
    (tmp_path / "users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("admin", None, True), _compte("boite", None, True)]}))
    un = _login(c, "admin", "", "1").json()["setup_token"]
    deux = _login(c, "boite", "", "1").json()["setup_token"]        # obtenu AVANT la configuration
    assert _poser(c, un).status_code == 200
    assert _poser(c, deux).status_code == 401
    assert _login(c, "boite", "", "1").status_code == 401
    assert _login(c, "admin", "une phrase longue et choisie", "1").json().get("access_token")
    assert [x["etape"] for x in _audit(tmp_path)] == ["pose", "connexion"]


def test_deux_jetons_du_meme_compte_le_second_n_ecrase_rien(c):
    a, b = (_login(c, "gk3", "", "1").json()["setup_token"] for _ in range(2))
    assert _poser(c, a).status_code == 200
    assert _poser(c, b, "un mot de passe voleur").status_code == 401
    assert _login(c, "gk3", "un mot de passe voleur", "1").status_code == 401


def test_jeton_d_un_compte_desactive_entre_temps(c, tmp_path):
    jeton = _login(c, "gk3", "", "1").json()["setup_token"]
    d = json.loads((tmp_path / "users.json").read_text())
    d["users"][0]["enabled"] = False
    (tmp_path / "users.json").write_text(json.dumps(d))
    assert _poser(c, jeton).status_code == 401


def test_changement_impose_reste_ouvert_sur_une_box_configuree(configuree, tmp_path):
    d = json.loads((tmp_path / "users.json").read_text())
    d["users"].append(_compte("bob", "provisoire-tres-long", True))
    (tmp_path / "users.json").write_text(json.dumps(d))
    r = _login(configuree, "bob", "provisoire-tres-long", "1").json()
    assert _poser(configuree, r["setup_token"], "ma phrase a moi, longue").status_code == 200


# ── Seconde revue ─────────────────────────────────────────────────────────────────────────────────────────────────────

def test_marque_durable_les_revendications_restent_fermees(c, tmp_path):
    """R1 : le seul admin réinitialisé (provisoire) ne rouvre ni les comptes sans mot de passe ni root/secubox."""
    (tmp_path / "users.json").write_text(json.dumps({"version": 2, "groups": [], "admin_configure_le": "2026-01-01",
        "users": [_compte("chef", "provisoire-tres-long", True), _compte("sert", None, True),
                  _compte("root", "secubox", True)]}))
    assert _login(c, "sert", "", "1").status_code == 401
    assert _login(c, "root", "secubox", "1").status_code == 401
    r = _login(c, "chef", "provisoire-tres-long", "1").json()
    assert _poser(c, r["setup_token"], "ma phrase a moi, longue").status_code == 200


def test_set_password_registre_occupe_503(c, monkeypatch):
    from api import main as m
    jeton = _login(c, "gk3", "", "1").json()["setup_token"]

    def occupe(*a, **k):
        raise m._users_engine_mod.EngineBusy("occupé")
    monkeypatch.setattr(m._users_engine, "set_password", occupe)
    assert _poser(c, jeton).status_code == 503


def test_connexion_reussie_jamais_500_si_le_registre_ne_s_ecrit_pas(c, tmp_path, monkeypatch):
    from api import main as m
    (tmp_path / "users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("chef", "une phrase longue et choisie", False)]}))
    monkeypatch.setattr(m._users_engine, "_save", lambda d: (_ for _ in ()).throw(PermissionError("lecture seule")))
    assert _login(c, "chef", "une phrase longue et choisie", "1").json().get("access_token")


def test_mfa_hors_de_la_boucle_et_codes_de_secours_derriere_la_porte(c, tmp_path, monkeypatch):
    import inspect
    from contextlib import contextmanager
    from api import main as m
    from secubox_core import porte_argon2
    assert not inspect.iscoroutinefunction(m._login_mfa)
    (tmp_path / "users.json").write_text(json.dumps({"version": 2, "groups": [], "users": [
        _compte("chef", "une phrase longue et choisie", False)]}))
    m._users_engine.enroll_totp("chef", "JBSWY3DPEHPK3PXP")
    jeton = _login(c, "chef", "une phrase longue et choisie", "0").json()["mfa_token"]

    @contextmanager
    def pleine(*_a):
        raise porte_argon2.Saturee(503)
        yield
    monkeypatch.setattr(porte_argon2.PORTE, "passage", pleine)
    h = {"Authorization": "Bearer " + jeton}
    assert c.post("/login/mfa", json={"code": "ABCDEFGHJK"}, headers=h).status_code == 503
    assert c.post("/login/mfa", json={"code": "000000"}, headers=h).status_code == 401      # TOTP : pas d'argon2
