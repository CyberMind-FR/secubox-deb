# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""#1757 — ce que la fusion aff481735 avait encore effacé.

Gestion des comptes (e2f71a500), liste détaillée (79aac6487), gestionnaires
bloquants en `def` (f703692b7), /storage dans le schéma de la page, et des
sauvegardes qui parlent enfin du fichier que le helper écrit. Réappliqué sur
l'architecture actuelle : tout passe par `sudo -n nextcloudctl`, le mot de
passe par stdin seulement, et rien de lourd sur le chemin d'une requête.
"""
import importlib
import inspect
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

RACINE = Path(__file__).resolve().parent.parent
PAGE = RACINE / "www" / "nextcloud" / "index.html"
HELPER = RACINE / "sbin" / "nextcloudctl"
NCTL = ["sudo", "-n", "/usr/sbin/nextcloudctl"]
HOSTILE = "a'; touch /tmp/pwn; echo '$(id)`id`"
OCCUPE = "\x1b[0;31m[ERROR]\x1b[0m occ déjà en cours (single-flight) — cache servi"


def _load(monkeypatch, running=True, reponse=(True, "", "")):
    import api.main as m
    importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "lxc_running", lambda: running)
    monkeypatch.setattr(m, "lxc_installed", lambda: True)
    appels = []

    def faux_run_cmd(cmd, timeout=30, stdin=None):
        # le rafraîchisseur de fond n'est pas la requête testée
        if threading.current_thread().name != "nc-cache":
            appels.append({"cmd": list(cmd), "stdin": stdin, "timeout": timeout})
        return reponse(cmd) if callable(reponse) else reponse
    monkeypatch.setattr(m, "run_cmd", faux_run_cmd)
    return m, TestClient(m.app), appels


# ---------------------------------------------------------------------------
# La page et l'API parlent la même langue
# ---------------------------------------------------------------------------

def _decouper(texte, sep):
    """Découpe `texte` sur `sep` hors parenthèses, crochets et accolades."""
    morceaux, prof, debut = [], 0, 0
    for i, ch in enumerate(texte):
        if ch in "([{":
            prof += 1
        elif ch in ")]}":
            prof -= 1
        elif ch == sep and prof == 0:
            morceaux.append(texte[debut:i])
            debut = i + 1
    morceaux.append(texte[debut:])
    return morceaux


def _appels_de_la_page():
    """(méthode, chemin) de chaque `await api(...)` de la page ; une
    expression dynamique devient le segment joker `{}`."""
    src = PAGE.read_text()
    res = []
    for trouve in re.finditer(r"await api\(", src):
        i = j = trouve.end()
        prof = 1
        while prof:
            if src[j] in "([{":
                prof += 1
            elif src[j] in ")]}":
                prof -= 1
            j += 1
        args = _decouper(src[i:j - 1], ",")
        chemin = ""
        for jeton in _decouper(args[0], "+"):
            litteral = re.fullmatch(r"\s*'([^']*)'\s*", jeton)
            chemin += litteral.group(1) if litteral else "{}"
        methode = re.search(r"method:\s*'(\w+)'", ",".join(args[1:]))
        res.append((methode.group(1) if methode else "GET", chemin.split("?")[0]))
    return res


def _route_existe(app, methode, chemin):
    segs = chemin.strip("/").split("/")
    for r in app.routes:
        if methode not in getattr(r, "methods", set()):
            continue
        rsegs = r.path.strip("/").split("/")
        if len(rsegs) == len(segs) and all(
                a == "{}" or b.startswith("{") or a == b for a, b in zip(segs, rsegs)):
            return True
    return False


def test_chaque_route_appelee_par_la_page_existe(monkeypatch):
    m, _, _ = _load(monkeypatch)
    appels = _appels_de_la_page()
    assert len(appels) >= 20, appels  # l'analyse n'a pas rendu du vide
    manquantes = [a for a in appels if not _route_existe(m.app, *a)]
    assert manquantes == []


@pytest.mark.parametrize("op", ["enable", "disable"])
def test_bascule_de_compte_de_la_page(monkeypatch, op):
    # la page construit '/user/' + uid + '/' + op, op ∈ {enable, disable}
    m, c, appels = _load(monkeypatch)
    assert c.post(f"/user/alice/{op}").status_code == 200
    assert appels[0]["cmd"] == NCTL + ["user", op, "alice"]


def _champs_lus(fonction, variable):
    src = PAGE.read_text()
    corps = src.split(f"async function {fonction}(")[1].split("async function ")[0]
    return set(re.findall(rf"\b{variable}\.(\w+)", corps)) - {"__error"}


def test_status_porte_les_champs_de_la_page(monkeypatch):
    m, c, _ = _load(monkeypatch)
    b = c.get("/status").json()
    lus = _champs_lus("loadStatus", "s")
    assert "reachable" in lus
    assert lus <= set(b), lus - set(b)
    assert b["reachable"] is True


def test_storage_porte_les_champs_de_la_page(monkeypatch):
    m, c, _ = _load(monkeypatch)
    b = c.get("/storage").json()
    lus = _champs_lus("loadStorage", "d")
    assert {"used", "total", "used_pct", "data"} <= lus
    assert lus <= set(b), lus - set(b)


# ---------------------------------------------------------------------------
# Comptes
# ---------------------------------------------------------------------------

def test_creation_mot_de_passe_par_stdin_jamais_argv(monkeypatch):
    m, c, appels = _load(monkeypatch)
    r = c.post("/user", json={"uid": "bob", "display_name": "Bob L'Éponge", "password": HOSTILE})
    assert r.status_code == 200, r.text
    (appel,) = appels
    assert appel["cmd"] == NCTL + ["user", "add", "bob", "Bob L'Éponge"]
    assert not any(HOSTILE in a or "OC_PASS" in a for a in appel["cmd"])
    assert appel["stdin"] == HOSTILE + "\n"
    assert appel["timeout"] <= 25  # HAProxy coupe à 30 s


def test_creation_nom_affiche_par_defaut_uid(monkeypatch):
    m, c, appels = _load(monkeypatch)
    assert c.post("/user", json={"uid": "bob", "password": "x"}).status_code == 200
    assert appels[0]["cmd"][-2:] == ["bob", "bob"]


@pytest.mark.parametrize("corps", [
    {"uid": "a;id", "password": "x"},
    {"uid": "a b", "password": "x"},
    {"uid": "alice\n", "password": "x"},
    {"uid": "", "password": "x"},
    {"uid": "bob", "password": ""},
    {"uid": "bob", "password": "deux\nlignes"},
    {"uid": "bob", "password": "nul\0"},
    {"uid": "bob", "password": "x", "display_name": "Bob\nroot ALL"},
])
def test_creation_saisie_hostile_refusee(monkeypatch, corps):
    m, c, appels = _load(monkeypatch)
    assert c.post("/user", json=corps).status_code == 400
    assert appels == []


@pytest.mark.parametrize("methode,chemin,corps,queue", [
    ("DELETE", "/user/alice", None, ["user", "del", "alice"]),
    ("POST", "/user/alice/enable", None, ["user", "enable", "alice"]),
    ("POST", "/user/alice/disable", None, ["user", "disable", "alice"]),
    ("POST", "/user/alice/quota", {"quota": "5GB"}, ["user", "quota", "alice", "5GB"]),
])
def test_operations_passent_par_le_helper(monkeypatch, methode, chemin, corps, queue):
    m, c, appels = _load(monkeypatch)
    r = c.request(methode, chemin, json=corps)
    assert r.status_code == 200, r.text
    (appel,) = appels
    assert appel["cmd"] == NCTL + queue
    assert appel["stdin"] is None
    assert appel["timeout"] <= 25


@pytest.mark.parametrize("methode,chemin,corps", [
    ("POST", "/user", {"uid": "bob", "password": "x"}),
    ("DELETE", "/user/alice", None),
    ("POST", "/user/alice/enable", None),
    ("POST", "/user/alice/disable", None),
    ("POST", "/user/alice/quota", {"quota": "5GB"}),
])
def test_conteneur_arrete_409(monkeypatch, methode, chemin, corps):
    m, c, appels = _load(monkeypatch, running=False)
    assert c.request(methode, chemin, json=corps).status_code == 409
    assert appels == []


@pytest.mark.parametrize("quota", ["$(id)", "5 GB", "-1", "5GB\n", "", "1e9"])
def test_quota_hostile_refuse(monkeypatch, quota):
    m, c, appels = _load(monkeypatch)
    assert c.post("/user/alice/quota", json={"quota": quota}).status_code == 400
    assert appels == []


@pytest.mark.parametrize("quota", ["5GB", "512MB", "10G", "1.5T", "none", "default", "NONE"])
def test_quota_valide_accepte(monkeypatch, quota):
    m, c, appels = _load(monkeypatch)
    assert c.post("/user/alice/quota", json={"quota": quota}).status_code == 200


@pytest.mark.parametrize("methode,chemin,corps", [
    ("GET", "/users", None),
    ("DELETE", "/user/alice", None),
    ("POST", "/user/alice/enable", None),
    ("POST", "/user/alice/quota", {"quota": "5GB"}),
])
def test_occ_occupe_503_pas_500(monkeypatch, methode, chemin, corps):
    # le rafraîchisseur tient l'occ à vol unique : le helper sort en 75
    m, c, _ = _load(monkeypatch, reponse=(False, "", OCCUPE))
    r = c.request(methode, chemin, json=corps)
    assert r.status_code == 503, r.text
    assert r.headers.get("retry-after")


def test_delai_depasse_504(monkeypatch):
    m, c, _ = _load(monkeypatch, reponse=(False, "", "Command timed out"))
    assert c.delete("/user/alice").status_code == 504


def test_autre_echec_500_avec_message(monkeypatch):
    m, c, _ = _load(monkeypatch, reponse=(False, "", "user does not exist"))
    r = c.delete("/user/alice")
    assert r.status_code == 500 and "user does not exist" in r.json()["detail"]


def test_liste_detaillee_normalisee(monkeypatch):
    sortie = ('[NEXTCLOUD] bruit avant le JSON\n'
              '{"admin":{"user_id":"admin","display_name":"Admin","email":null,'
              '"enabled":true,"quota":"none","last_seen":"2026-09-30T10:00:00+00:00"},'
              '"bob":{"user_id":"bob","display_name":"","enabled":false,"quota":"5 GB"}}')
    m, c, appels = _load(monkeypatch, reponse=(True, sortie, ""))
    r = c.get("/users")
    assert r.status_code == 200, r.text
    assert appels[0]["cmd"] == NCTL + ["user", "list"]
    comptes = {u["uid"]: u for u in r.json()["users"]}
    assert comptes["admin"] == {"uid": "admin", "displayname": "Admin", "enabled": True,
                                "quota": "none", "last_seen": "2026-09-30T10:00:00+00:00",
                                "email": ""}
    assert comptes["bob"]["enabled"] is False and comptes["bob"]["displayname"] == "bob"


def test_liste_conteneur_arrete_vide_sans_appel(monkeypatch):
    m, c, appels = _load(monkeypatch, running=False)
    assert c.get("/users").json() == {"users": []}
    assert appels == []


# ---------------------------------------------------------------------------
# /storage : mesuré par le rafraîchisseur, jamais à la requête
# ---------------------------------------------------------------------------

def test_storage_jamais_sur_le_chemin_de_la_requete(monkeypatch):
    m, c, appels = _load(monkeypatch)
    for _ in range(3):
        assert c.get("/storage").status_code == 200
    assert appels == []


def _faux_helper(stockage='{"used":"12G","total":"100G","used_pct":12,"data":"11G"}',
                 version=True):
    appels = []

    def faux(cmd, timeout=30, stdin=None):
        sub = cmd[len(NCTL):]
        appels.append(sub)
        if sub[:2] == ["occ", "--version"]:
            return (True, "Nextcloud 29.0.1", "") if version else (False, "", OCCUPE)
        if sub[:2] == ["occ", "user:list"]:
            return True, '{"admin":"admin","bob":"bob"}', ""
        if sub == ["storage", "--json"]:
            return True, stockage, ""
        return False, "", "inattendu"
    return faux, appels


def test_rafraichisseur_mesure_le_stockage(monkeypatch):
    m, _, _ = _load(monkeypatch)
    faux, appels = _faux_helper()
    monkeypatch.setattr(m, "run_cmd", faux)
    cache = m._compute_nc_cache({})
    assert cache["version"] == "29.0.1" and cache["user_count"] == 2
    assert cache["storage"]["used"] == "12G" and cache["storage"]["used_pct"] == 12
    assert cache["storage"]["data"] == "11G" and cache["disk_used"] == "11G"
    # `nextcloudctl status` refaisait un occ et un du à chaque tour : plus appelé
    assert ["status"] not in appels
    assert appels.count(["storage", "--json"]) == 1


def test_rafraichisseur_espace_la_mesure_du_stockage(monkeypatch):
    m, _, _ = _load(monkeypatch)
    faux, appels = _faux_helper()
    monkeypatch.setattr(m, "run_cmd", faux)
    cache = m._compute_nc_cache({})
    cache = m._compute_nc_cache(cache)          # < 10 min : pas de nouveau du
    assert appels.count(["storage", "--json"]) == 1
    assert cache["storage"]["used"] == "12G"    # la mesure est conservée
    cache["storage"]["ts"] -= m.INTERVALLE_STOCKAGE
    m._compute_nc_cache(cache)
    assert appels.count(["storage", "--json"]) == 2


def test_rafraichisseur_garde_la_mesure_quand_occ_echoue(monkeypatch):
    # conteneur engorgé : le disjoncteur vaut aussi pour le du
    m, _, _ = _load(monkeypatch)
    faux, appels = _faux_helper(version=False)
    monkeypatch.setattr(m, "run_cmd", faux)
    prec = {"disk_used": "9G", "storage": {"used": "10G", "total": "100G", "used_pct": 10,
                                           "data": "9G", "ts": 0}}
    cache = m._compute_nc_cache(prec)
    assert ["storage", "--json"] not in appels
    assert cache["storage"]["used"] == "10G" and cache["disk_used"] == "9G"


def test_rafraichisseur_mesure_illisible_ignoree_et_espacee(monkeypatch):
    m, c, _ = _load(monkeypatch)
    faux, appels = _faux_helper(stockage="pas du json")
    monkeypatch.setattr(m, "run_cmd", faux)
    cache = m._compute_nc_cache({})
    assert "used" not in cache["storage"] and cache["disk_used"] == "0"
    # un échec compte comme un essai : pas de nouveau du au tour suivant
    m._compute_nc_cache(cache)
    assert appels.count(["storage", "--json"]) == 1
    monkeypatch.setattr(m, "_nc_cache", cache)
    assert c.get("/storage").json()["ts"] == 0


# ---------------------------------------------------------------------------
# Gestionnaires bloquants : `def`, hors de la boucle (f703692b7)
# ---------------------------------------------------------------------------

def test_gestionnaires_bloquants_hors_de_la_boucle(monkeypatch):
    m, _, _ = _load(monkeypatch)
    purs = {("/health", "GET"), ("/config", "POST")}
    fautifs = sorted(
        (r.path, meth) for r in m.app.routes if isinstance(r, APIRoute)
        for meth in r.methods
        if (r.path, meth) not in purs and inspect.iscoroutinefunction(r.endpoint))
    assert fautifs == []


# ---------------------------------------------------------------------------
# Sauvegardes : backups/nextcloud_<nom>.tar.gz, comme le helper les écrit
# ---------------------------------------------------------------------------

def _sauvegardes(monkeypatch, m, tmp_path, *noms):
    (tmp_path / "backups").mkdir()
    for n in noms:
        (tmp_path / "backups" / f"nextcloud_{n}.tar.gz").write_bytes(b"x")
    monkeypatch.setattr(m, "DATA_PATH", tmp_path)


def test_liste_des_sauvegardes_du_helper(monkeypatch, tmp_path):
    m, c, _ = _load(monkeypatch)
    _sauvegardes(monkeypatch, m, tmp_path, "nightly", "20260930_120000", "bad name")
    (tmp_path / "backups" / "vieux-db.sql").write_text("")
    noms = {b["name"] for b in c.get("/backups").json()["backups"]}
    assert noms == {"nightly", "20260930_120000"}


def test_suppression_par_le_helper(monkeypatch, tmp_path):
    m, c, appels = _load(monkeypatch)
    _sauvegardes(monkeypatch, m, tmp_path, "nightly")
    (b,) = c.get("/backups").json()["backups"]
    r = c.delete("/backup/" + b["name"])
    assert r.status_code == 200, r.text
    (appel,) = appels
    assert appel["cmd"] == NCTL + ["backup-delete", "nightly"]
    # l'API ne délie rien elle-même (répertoire de root) : c'est le helper
    assert (tmp_path / "backups" / "nextcloud_nightly.tar.gz").exists()


def test_suppression_sauvegarde_absente_404(monkeypatch, tmp_path):
    m, c, appels = _load(monkeypatch)
    _sauvegardes(monkeypatch, m, tmp_path)
    assert c.delete("/backup/absente").status_code == 404
    assert appels == []


def test_sauvegarde_sans_corps(monkeypatch, tmp_path):
    # la page poste /backup SANS corps : un modèle obligatoire rendait 422 ;
    # la sauvegarde part en arrière-plan (HAProxy coupe à 30 s)
    m, c, appels = _load(monkeypatch)
    monkeypatch.setattr(m, "JOURNAUX", tmp_path)
    lances = []
    monkeypatch.setattr(m.subprocess, "Popen", lambda cmd, **k: lances.append(cmd))
    r = c.post("/backup")
    assert r.status_code == 200, r.text
    assert lances == [NCTL + ["backup"]]


# ---------------------------------------------------------------------------
# Le helper
# ---------------------------------------------------------------------------

needs_bash = pytest.mark.skipif(not shutil.which("bash"), reason="bash absent")


def _helper(tmp_path, *args, entree=None):
    env = dict(os.environ, SECUBOX_NEXTCLOUD_DATA=str(tmp_path),
               SECUBOX_LXC_PATH=str(tmp_path / "lxc"))
    return subprocess.run(["bash", str(HELPER), *args], input=entree, text=True,
                          capture_output=True, env=env, timeout=30)


@needs_bash
def test_helper_supprime_la_sauvegarde_nommee(tmp_path):
    (tmp_path / "backups").mkdir()
    cible = tmp_path / "backups" / "nextcloud_nightly.tar.gz"
    voisin = tmp_path / "backups" / "nextcloud_autre.tar.gz"
    cible.write_bytes(b"x")
    voisin.write_bytes(b"x")
    r = _helper(tmp_path, "backup-delete", "nightly")
    assert r.returncode == 0, r.stderr
    assert not cible.exists() and voisin.exists()


@needs_bash
@pytest.mark.parametrize("nom", ["../garde", "a/b", "x\ny", ""])
def test_helper_refuse_un_nom_hostile(tmp_path, nom):
    (tmp_path / "backups").mkdir()
    garde = tmp_path / "garde"
    garde.write_text("")
    r = _helper(tmp_path, "backup-delete", nom)
    assert r.returncode == 2
    assert garde.exists()


@needs_bash
def test_helper_sauvegarde_absente(tmp_path):
    (tmp_path / "backups").mkdir()
    r = _helper(tmp_path, "backup-delete", "absente")
    # 1 ET le bon message : un verbe inconnu sort aussi en 1
    assert r.returncode == 1 and "introuvable" in r.stderr


@needs_bash
def test_helper_sauvegarde_refuse_un_nom_hostile(tmp_path):
    (tmp_path / "backups").mkdir()
    assert _helper(tmp_path, "backup", "../x").returncode == 2
    assert list((tmp_path / "backups").iterdir()) == []


@needs_bash
def test_helper_restaure_par_le_nom(tmp_path):
    # l'API transmet un NOM ; on refuse la confirmation, rien n'est touché
    (tmp_path / "backups").mkdir()
    (tmp_path / "backups" / "nextcloud_nightly.tar.gz").write_bytes(b"x")
    r = _helper(tmp_path, "restore", "nightly", entree="no\n")
    assert "Aborted" in r.stdout and "Usage" not in r.stdout


def test_marqueur_occ_occupe_suit_le_helper(monkeypatch):
    # 503 se reconnaît au message du helper : s'il change, ce test le dit
    m, _, _ = _load(monkeypatch)
    lignes = [ligne for ligne in HELPER.read_text().splitlines() if "exit 75" in ligne]
    assert lignes and all(m.OCC_OCCUPE in ligne for ligne in lignes)
