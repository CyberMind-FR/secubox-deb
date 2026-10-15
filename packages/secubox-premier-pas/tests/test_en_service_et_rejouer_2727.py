# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2727 — une mise à jour du paquet ne ferme plus l'assistant en plein parcours, et `premier-pasctl rejouer` le rouvre de force.

CONSTAT (RPi400, 2026-10-15, lu par `GET /etat`) : `fait: true`, profil complet, `moteur` vide — le marqueur avait été posé sans que l'assistant s'applique.
Le `postinst` le posait à CHAQUE configuration du paquet dès qu'un admin « avait servi », sans regarder si un assistant était en cours."""
import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))

from premier_pas import en_service as E  # noqa: E402

MDP_CHOISI = {"users": [{"username": "admin", "password_hash": "$argon2id$x", "must_change_password": False}]}
MDP_PAR_DEFAUT = {"users": [{"username": "admin", "password_hash": "$argon2id$x", "must_change_password": True}]}
TOTP_SEUL = {"users": [{"username": "admin", "password_hash": "$argon2id$x", "must_change_password": True, "totp": "JBSWY3DP"}]}
SANS_ADMIN = {"users": [{"username": "autre", "password_hash": "x"}]}
PROFIL = '[box]\nnom = "secubox-rpi"\n'


@pytest.fixture
def lieux(tmp_path):
    return tmp_path / "users.json", tmp_path / "pp"


def pose(users, d, contenu=None, profil=None):
    if contenu is not None:
        users.write_text(json.dumps(contenu))
    if profil is not None:
        d.mkdir(exist_ok=True)
        (d / "profil.toml").write_text(profil)


# ---------- box en service (la règle de l'ancien postinst, inchangée) ----------

@pytest.mark.parametrize("contenu,attendu", [(MDP_CHOISI, True), (TOTP_SEUL, True), (MDP_PAR_DEFAUT, False), (SANS_ADMIN, False), ({}, False)])
def test_box_en_service(lieux, contenu, attendu):
    u, d = lieux
    pose(u, d, contenu)
    assert E.box_en_service(u) is attendu


def test_sans_fichier_ou_fichier_casse_la_box_n_est_pas_en_service(lieux):
    u, _ = lieux
    assert E.box_en_service(u) is False
    u.write_text("{pas du json")
    assert E.box_en_service(u) is False


# ---------- assistant en cours ----------

def test_assistant_en_cours_si_un_profil_est_rempli(lieux):
    _, d = lieux
    assert E.assistant_en_cours(d) is False
    pose(*lieux, profil="")
    assert E.assistant_en_cours(d) is False
    pose(*lieux, profil=PROFIL)
    assert E.assistant_en_cours(d) is True


def test_un_profil_illisible_compte_comme_en_cours(lieux):
    """Dans le doute on n'enferme pas la personne : un profil qu'on ne sait pas lire est le signe d'un assistant commencé, pas d'une box finie."""
    pose(*lieux, profil="[box\nnom =")
    assert E.assistant_en_cours(lieux[1]) is True


# ---------- la décision du postinst ----------

def test_une_box_en_service_sans_assistant_en_cours_recoit_le_marqueur(lieux):
    pose(*lieux, contenu=MDP_CHOISI)
    assert E.doit_marquer(*lieux) is True


def test_une_box_en_service_avec_un_assistant_en_cours_ne_recoit_pas_le_marqueur(lieux):
    """LE CAS DU RPi400 : admin déjà utilisé, assistant rempli mais pas appliqué."""
    pose(*lieux, contenu=MDP_CHOISI, profil=PROFIL)
    assert E.doit_marquer(*lieux) is False


def test_une_box_pas_en_service_ne_recoit_jamais_le_marqueur(lieux):
    pose(*lieux, contenu=MDP_PAR_DEFAUT)
    assert E.doit_marquer(*lieux) is False


def test_la_commande_du_postinst_rend_0_pour_marquer_et_1_sinon(lieux, tmp_path):
    u, d = lieux
    env = {"SECUBOX_USERS_JSON": str(u), "PREMIER_PAS_DIR": str(d), "PYTHONPATH": str(PKG), "PATH": "/usr/bin:/bin"}
    pose(u, d, contenu=MDP_CHOISI)
    assert subprocess.run([sys.executable, "-m", "premier_pas.en_service"], env=env).returncode == 0
    pose(u, d, profil=PROFIL)
    assert subprocess.run([sys.executable, "-m", "premier_pas.en_service"], env=env).returncode == 1


def test_le_postinst_passe_par_le_module_et_non_par_un_script_inline():
    texte = (PKG / "debian" / "postinst").read_text()
    assert "premier_pas.en_service" in texte
    assert "must_change_password" not in texte, "la règle vit dans premier_pas/en_service.py, testable : pas de seconde copie inline"
    assert "premier-pas-fait" in texte


# ---------- l'ouverture distante ne s'offre pas à une box en service ----------

@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("PREMIER_PAS_DIR", str(tmp_path / "pp"))
    monkeypatch.setenv("PREMIER_PAS_JETON", str(tmp_path / "jeton"))
    monkeypatch.setenv("PREMIER_PAS_JETON_LOCAL", str(tmp_path / "jeton-local"))
    monkeypatch.setenv("PREMIER_PAS_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SECUBOX_USERS_JSON", str(tmp_path / "users.json"))
    (tmp_path / "jeton").write_text("code\n")
    (tmp_path / "jeton-local").write_text("local\n")
    from api import main
    from premier_pas import remplir
    importlib.reload(remplir)
    importlib.reload(main)
    monkeypatch.setattr(main.M, "MARQUEUR", tmp_path / "fait")
    monkeypatch.setattr(main, "_maintenant", lambda: 60)
    from fastapi.testclient import TestClient
    return TestClient(main.app), tmp_path


def test_la_session_distante_est_refusee_sur_une_box_en_service(api):
    c, t = api
    (t / "users.json").write_text(json.dumps(MDP_CHOISI))
    r = c.post("/session")
    assert r.status_code == 409 and "en service" in r.json()["detail"]


def test_la_session_distante_reste_possible_pour_un_assistant_en_cours_meme_si_l_admin_a_servi(api):
    """Après `rejouer` (profil gardé) l'assistant doit pouvoir se rouvrir à distance : c'est le cas de la box touchée."""
    c, t = api
    (t / "users.json").write_text(json.dumps(MDP_CHOISI))
    (t / "pp").mkdir()
    (t / "pp" / "profil.toml").write_text(PROFIL)
    assert c.post("/session").status_code == 200


def test_la_session_distante_reste_possible_sur_une_box_neuve(api):
    c, t = api
    (t / "users.json").write_text(json.dumps(MDP_PAR_DEFAUT))
    assert c.post("/session").status_code == 200


# ---------- rejouer ----------

from premier_pas import rejouer as RJ  # noqa: E402


@pytest.fixture
def box_fermee(tmp_path, monkeypatch):
    from premier_pas import moteur as M
    d = tmp_path / "pp"
    d.mkdir()
    monkeypatch.setenv("PREMIER_PAS_DIR", str(d))
    monkeypatch.setattr(M, "MARQUEUR", tmp_path / "fait")
    monkeypatch.setattr(M, "ETAT", tmp_path / "etat.json")
    monkeypatch.setattr(M, "MARQUEUR_AIDE", d / "aide-demandee")
    for nom in ("profil.toml", "demande", "proposition.json", "session-distante.json", "aide-demandee"):
        (d / nom).write_text("x")
    (tmp_path / "fait").write_text("2026-10-15")
    (tmp_path / "etat.json").write_text("{}")
    return tmp_path, d


def test_rejouer_rouvre_l_assistant_et_garde_le_profil(box_fermee):
    t, d = box_fermee
    appels = []
    r = RJ.rejouer(vierge=False, relance=lambda: appels.append("relance"), uid=0)
    assert not (t / "fait").exists() and not (t / "etat.json").exists()
    for nom in ("demande", "proposition.json", "session-distante.json", "aide-demandee"):
        assert not (d / nom).exists(), nom
    assert (d / "profil.toml").exists()
    assert appels == ["relance"] and r["marqueur"] is True


def test_rejouer_vierge_efface_aussi_le_profil(box_fermee):
    _, d = box_fermee
    RJ.rejouer(vierge=True, relance=lambda: None, uid=0)
    assert not (d / "profil.toml").exists()


def test_rejouer_sur_une_box_deja_ouverte_ne_plante_pas(box_fermee):
    t, _ = box_fermee
    (t / "fait").unlink()
    assert RJ.rejouer(vierge=False, relance=lambda: None, uid=0)["marqueur"] is False


def test_rejouer_exige_root(box_fermee):
    with pytest.raises(RJ.Refus, match="root"):
        RJ.rejouer(vierge=False, relance=lambda: None, uid=1000)


def test_la_commande_rejouer_existe_dans_premier_pasctl():
    texte = (PKG / "sbin" / "premier-pasctl").read_text()
    assert '"rejouer"' in texte and "--vierge" in texte
