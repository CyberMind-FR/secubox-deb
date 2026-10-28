# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3247 — dépôt et démarrage en 500 quand le conteneur dort (constaté sur gk2 le 2026-10-28).

1. Le dépôt, le démarrage et l'exposition réveillent le conteneur (même chemin que /power/wake : `streamlitctl
   start`), délai borné ; s'il reste endormi : 503 avec la cause réelle, jamais un message vide.
2. Sans port fourni, le port vient du ctl (`app port`), plus jamais `default_port` (8501).
3. Publication par la déclaration `[instances.<nom public>]` + route sbxwaf, posées par le ctl ; automatique
   seulement si `[publication] auto = true` (sur demande par défaut).
4. Nom public modifiable (`POST /app/{name}/rename`), validé avant sudo.
"""
import io
import subprocess
import zipfile
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api import main as api_main
from api.main import app
from secubox_core.auth import require_jwt, require_lecture


@pytest.fixture
def ctl(monkeypatch, tmp_path):
    """Faux streamlitctl : chaque appel est enregistré ; `start` réveille (ou non) le conteneur."""
    etat = {"conteneur": False, "reveil_reussit": True, "installe": True, "appels": [], "reponses": {}}

    def faux_run_ctl(*args, timeout=30, entree=None):
        etat["appels"].append(args)
        if args[0] == "start":
            if etat["reveil_reussit"]:
                etat["conteneur"] = True
                return {"output": "[2026-10-28 14:47:53] Container started\n", "code": 0}
            return {"output": "", "error": "lxc-start: streamlit: Failed to start container", "code": 1}
        rep = etat["reponses"].get(args[:2])
        if callable(rep):
            rep = rep(args)
        if rep is not None:
            return rep
        if args[:2] == ("app", "port"):
            return {"ok": True, "port": 8507, "source": "auto", "applique": True, "code": 0}
        if args[:2] == ("app", "publish"):
            nom = args[3] if len(args) > 3 and not args[3].startswith("--") else "existant"
            return {"ok": True, "nom_public": nom, "domaine": f"{nom}.gk2.secubox.in", "evenement": "publication",
                    "code": 0}
        if args[:2] == ("app", "deploy"):
            return {"success": True, "name": args[3], "path": f"/srv/streamlit/apps/{args[3]}", "code": 0}
        return {"output": "", "code": 0}

    monkeypatch.setattr(api_main, "_run_ctl", faux_run_ctl)
    monkeypatch.setattr(api_main, "_lxc_running", lambda: etat["conteneur"])
    monkeypatch.setattr(api_main, "_cfg", lambda: {"use_lxc": True, "default_port": 8501, "apps_dir": "/srv/x"})
    monkeypatch.setattr(api_main, "_lxc_exists", lambda: etat["installe"])
    monkeypatch.setattr(api_main, "_noter_reveil", lambda: None)
    monkeypatch.setattr(api_main, "_start_autostart_instances", lambda: etat["appels"].append(("autostart",)) or [])
    conf = tmp_path / "streamlit.toml"
    conf.write_text("[main]\nenabled = true\n")
    monkeypatch.setattr(api_main, "STREAMLIT_CONF", conf)
    monkeypatch.setenv("SECUBOX_DOMAINE", "gk2.secubox.in")
    (tmp_path / "nginx" / "sites-enabled").mkdir(parents=True)
    monkeypatch.setenv("SECUBOX_NGINX_DIR", str(tmp_path / "nginx"))
    monkeypatch.setenv("SECUBOX_STREAMLIT_ROUTES", str(tmp_path / "haproxy-routes.json"))
    monkeypatch.setenv("SECUBOX_HAPROXY_TOML", str(tmp_path / "haproxy.toml"))
    monkeypatch.setattr(api_main, "domaine_box", lambda: "gk2.secubox.in")
    etat["conf"] = conf
    app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    try:
        yield TestClient(app), etat
    finally:
        app.dependency_overrides.clear()


def verbes(etat):
    return [a[:2] if a[0] == "app" else a[:1] for a in etat["appels"]]


def zip_appli(entrees=(("app.py", "import streamlit\n"),)):
    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w") as z:
        for nom, contenu in entrees:
            z.writestr(nom, contenu)
    return tampon.getvalue()


# ─── 1. Réveil du conteneur ────────────────────────────────────────────────

def test_demarrage_reveille_le_conteneur_qui_dort_avant_de_demarrer(ctl):
    client, etat = ctl
    r = client.post("/app/atelier-partage-1/start")
    assert r.status_code == 200, r.text
    assert verbes(etat)[:3] == [("start",), ("app", "port"), ("app", "start")]
    assert r.json()["conteneur_reveille"] is True
    assert ("autostart",) not in etat["appels"]      # un réveil implicite ne démarre pas tout le parc (#982)


def test_demarrage_conteneur_eveille_aucun_reveil(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    r = client.post("/app/atelier/start")
    assert r.status_code == 200, r.text
    assert ("start",) not in etat["appels"]
    assert r.json()["conteneur_reveille"] is False


def test_reveil_impossible_503_avec_la_cause_reelle(ctl):
    client, etat = ctl
    etat["reveil_reussit"] = False
    r = client.post("/app/atelier/start")
    assert r.status_code == 503, r.text
    detail = r.json()["detail"]
    assert "lxc-start" in detail and "endormi" in detail
    assert ("app", "start") not in verbes(etat)


def test_conteneur_non_installe_409(ctl):
    client, etat = ctl
    etat["installe"] = False
    r = client.post("/app/atelier/start")
    assert r.status_code == 409 and "install" in r.json()["detail"]


def test_depot_reveille_le_conteneur_et_lit_le_formulaire(ctl):
    client, etat = ctl
    r = client.post("/deploy", files={"file": ("x.zip", zip_appli(), "application/zip")},
                    data={"name": "atelier-partage-1", "port": "", "public_name": ""})
    assert r.status_code == 200, r.text
    assert verbes(etat)[:3] == [("start",), ("app", "deploy"), ("app", "port")]
    deploy = next(a for a in etat["appels"] if a[:2] == ("app", "deploy"))
    assert deploy[3] == "atelier-partage-1"                       # le nom du formulaire, pas celui du fichier
    corps = r.json()
    assert corps["success"] is True and corps["port"] == 8507


def test_depot_port_du_formulaire_transmis(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    r = client.post("/deploy", files={"file": ("x.zip", zip_appli(), "application/zip")},
                    data={"name": "atelier", "port": "8555"})
    assert r.status_code == 200, r.text
    assert ("app", "port", "atelier", "8555", "--apply") in etat["appels"]


@pytest.mark.parametrize("entree", ["../evil.py", "/etc/cron.d/x", "a/../../b.py"])
def test_depot_zip_hostile_refuse_avant_tout_geste(ctl, entree):
    client, etat = ctl
    r = client.post("/deploy", files={"file": ("x.zip", zip_appli(((entree, "x"),)), "application/zip")},
                    data={"name": "atelier"})
    assert r.status_code == 400, r.text
    assert etat["appels"] == []


def test_power_wake_meme_chemin_et_503_au_lieu_de_500(ctl):
    client, etat = ctl
    r = client.post("/power/wake")
    assert r.status_code == 200, r.text
    assert verbes(etat)[0] == ("start",) and ("autostart",) in etat["appels"]
    etat["conteneur"], etat["reveil_reussit"], etat["appels"] = False, False, []
    r = client.post("/power/wake")
    assert r.status_code == 503 and r.json()["detail"]


def test_instance_et_autostart_reveillent_le_conteneur(ctl):
    client, etat = ctl
    assert client.post("/instance/cpf/start").status_code == 200
    assert verbes(etat)[0] == ("start",)
    etat["conteneur"], etat["appels"] = False, []
    assert client.post("/autostart/run").status_code == 200
    assert verbes(etat)[0] == ("start",)


# ─── 1bis. Erreurs du ctl : jamais vides ───────────────────────────────────

def _proc(rc, stdout="", stderr=""):
    if rc:
        return subprocess.CalledProcessError(rc, ["sudo"], output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(["sudo"], 0, stdout=stdout, stderr=stderr)


def _run_ctl_avec(rc, stdout="", stderr=""):
    p = _proc(rc, stdout, stderr)

    def faux(*a, **k):
        if isinstance(p, Exception):
            raise p
        return p
    with patch("api.main.subprocess.run", side_effect=faux):
        return api_main._run_ctl("app", "start", "x")


def test_run_ctl_cause_sur_stderr_sans_horodatage():
    r = _run_ctl_avec(75, stderr="[2026-10-28 14:47:53] ERROR: Container not running. Start it first.\n")
    assert r["code"] == 75 and r["error"] == "Container not running. Start it first."


def test_run_ctl_stderr_vide_la_cause_vient_de_stdout():
    r = _run_ctl_avec(1, stdout="[2026-10-28 14:47:53] Deploying x...\nunzip: cannot find zipfile\n")
    assert "unzip: cannot find zipfile" in r["error"]


def test_run_ctl_tout_vide_le_message_dit_le_code():
    r = _run_ctl_avec(3)
    assert r["error"] and "3" in r["error"]


def test_run_ctl_json_apres_les_lignes_de_journal():
    """La cause de « Deploy failed: » sur gk2 : `log` écrit sur stdout AVANT le JSON de `app deploy` ; la sortie
    ne commençait donc pas par « { », le JSON n'était pas lu et un dépôt réussi devenait un 500 sans message."""
    r = _run_ctl_avec(0, stdout="[2026-10-28 14:47:53] Deploying x...\n[2026-10-28 14:47:54] App x deployed\n"
                                '{"success": true, "name": "x", "path": "/srv/streamlit/apps/x"}\n')
    assert r["success"] is True and r["code"] == 0 and "error" not in r


def test_run_ctl_succes_sans_json_n_est_pas_une_erreur():
    r = _run_ctl_avec(0, stdout="[2026-10-28 14:47:53] Container started\n")
    assert "error" not in r and r["code"] == 0


def test_run_ctl_masque_les_secrets():
    r = _run_ctl_avec(1, stderr="fatal: unable to access 'https://bob:t0k3n@git.local/x.git'\ntoken=abcdef\n")
    assert "t0k3n" not in r["error"] and "abcdef" not in r["error"]


def test_run_ctl_delai_depasse_message_lisible():
    with patch("api.main.subprocess.run", side_effect=subprocess.TimeoutExpired(["sudo"], 20)):
        r = api_main._run_ctl("start", timeout=20)
    assert r["timeout"] is True and "20" in r["error"]


def test_reveil_d_une_appli_conteneur_indisponible_503(monkeypatch):
    api_main._WAKE_ECHECS.clear()
    monkeypatch.setattr(api_main, "_spawn_shotter", lambda *a, **k: None)
    with patch("api.main.subprocess.run",
               return_value=subprocess.CompletedProcess(["sudo"], 75, stdout=b"",
                                                        stderr=b"conteneur streamlit injoignable\n")):
        api_main._do_wake_in_background("foo")
    code, detail = api_main._wake_prendre_echec("foo")
    assert code == 503 and "conteneur" in detail


# ─── 2. Port automatique ───────────────────────────────────────────────────

def test_demarrage_sans_port_le_ctl_choisit_plus_jamais_8501(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    r = client.post("/app/atelier/start")
    assert r.status_code == 200, r.text
    assert ("app", "port", "atelier", "--apply") in etat["appels"]
    assert ("app", "start", "atelier", "8507") in etat["appels"]
    assert not any("8501" in a for a in etat["appels"])
    assert r.json()["port"] == 8507 and r.json()["port_source"] == "auto"


def test_demarrage_port_explicite_transmis(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    r = client.post("/app/atelier/start?port=8555")
    assert r.status_code == 200, r.text
    assert ("app", "port", "atelier", "8555", "--apply") in etat["appels"]


def test_demarrage_port_pris_409_sans_demarrer(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    etat["reponses"][("app", "port")] = {"ok": False, "code": 4,
                                         "error": "port 8529 déjà attribué à l'appli « atelier »"}
    r = client.post("/app/nouvelle/start?port=8529")
    assert r.status_code == 409 and "8529" in r.json()["detail"]
    assert ("app", "start") not in verbes(etat)


@pytest.mark.parametrize("port", [-1, 80, 70000])
def test_port_hors_limites_refuse_avant_sudo(ctl, port):
    client, etat = ctl
    r = client.post(f"/app/atelier/start?port={port}")
    assert r.status_code == 400 and etat["appels"] == []


def test_demarrage_echec_du_ctl_statut_et_message(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    etat["reponses"][("app", "start")] = {"output": "", "code": 3,
                                          "error": "App archivée : atelier — désarchivez-la d'abord"}
    r = client.post("/app/atelier/start")
    assert r.status_code == 409 and "archiv" in r.json()["detail"]


# ─── 3. Publication automatique (réglage) ──────────────────────────────────

def test_publication_sur_demande_par_defaut(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    r = client.post("/app/atelier/start")
    assert r.status_code == 200
    assert ("app", "publish") not in verbes(etat)
    pub = r.json()["publication"]
    assert pub["publiee"] is False and "auto" in pub["raison"]


def test_publication_automatique_activee_par_le_reglage(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    etat["conf"].write_text("[publication]\nauto = true\n")
    r = client.post("/app/Atelier_Partage/start")
    assert r.status_code == 200, r.text
    assert ("app", "publish", "Atelier_Partage", "atelier-partage", "--par", "admin", "--apply") in etat["appels"]
    assert r.json()["publication"]["domaine"] == "atelier-partage.gk2.secubox.in"


def test_appli_deja_publiee_la_route_suit_le_port(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    etat["conf"].write_text('[instances.at]\napp = "atelier"\nport = 8529\ndomain = "at.gk2.secubox.in"\n')
    r = client.post("/app/atelier/start")
    assert r.status_code == 200, r.text
    assert ("app", "publish", "atelier", "--par", "admin", "--apply") in etat["appels"]


def test_depot_avec_nom_public_publie(ctl):
    client, etat = ctl
    r = client.post("/deploy", files={"file": ("x.zip", zip_appli(), "application/zip")},
                    data={"name": "atelier-partage-1", "public_name": "atelier"})
    assert r.status_code == 200, r.text
    assert ("app", "publish", "atelier-partage-1", "atelier", "--par", "admin", "--apply") in etat["appels"]
    assert r.json()["publication"]["domaine"] == "atelier.gk2.secubox.in"


def test_publication_refusee_ne_casse_pas_le_demarrage(ctl):
    client, etat = ctl
    etat["conteneur"] = True
    etat["conf"].write_text("[publication]\nauto = true\n")
    etat["reponses"][("app", "publish")] = {"ok": False, "code": 4, "error": "nom pris : cpf.gk2.secubox.in"}
    r = client.post("/app/cpf/start")
    assert r.status_code == 200
    assert r.json()["publication"] == {"publiee": False, "erreur": "nom pris : cpf.gk2.secubox.in"}


@pytest.mark.parametrize("nom,statut", [("Mauvais_Nom", 400), ("a.b", 400), ("admin", 409)])
def test_depot_nom_public_refuse_avant_tout_geste(ctl, nom, statut):
    client, etat = ctl
    r = client.post("/deploy", files={"file": ("x.zip", zip_appli(), "application/zip")},
                    data={"name": "atelier", "public_name": nom})
    assert r.status_code == statut, r.text
    assert etat["appels"] == []


def test_publier_sur_demande(ctl):
    client, etat = ctl
    r = client.post("/app/atelier-partage-1/publish", json={"public_name": "atelier"})
    assert r.status_code == 200, r.text
    assert verbes(etat)[:3] == [("start",), ("app", "port"), ("app", "publish")]
    assert ("app", "publish", "atelier-partage-1", "atelier", "--par", "admin", "--apply") in etat["appels"]


def test_retirer_la_publication(ctl):
    client, etat = ctl
    r = client.post("/app/atelier/unpublish")
    assert r.status_code == 200, r.text
    assert ("app", "unpublish", "atelier", "--par", "admin", "--apply") in etat["appels"]


def test_suppression_retire_d_abord_la_publication(ctl):
    client, etat = ctl
    r = client.delete("/app/atelier")
    assert r.status_code == 200, r.text
    assert verbes(etat) == [("app", "unpublish"), ("app", "remove")]


def test_lecture_des_publications(ctl):
    client, etat = ctl
    etat["conf"].write_text('[publication]\nauto = false\n\n[instances.at]\napp = "atelier"\nport = 8529\n'
                            'domain = "at.gk2.secubox.in"\n')
    app.dependency_overrides[require_lecture] = lambda: {"sub": "lecteur"}
    r = client.get("/publications")
    assert r.status_code == 200, r.text
    corps = r.json()
    assert corps["auto"] is False and corps["domaine"] == "gk2.secubox.in"
    assert corps["apps"]["atelier"][0]["domaine"] == "at.gk2.secubox.in"


# ─── 4. Nom public modifiable ──────────────────────────────────────────────

def test_renommer(ctl):
    client, etat = ctl
    etat["conf"].write_text('[instances.at]\napp = "atelier"\nport = 8529\ndomain = "at.gk2.secubox.in"\n')
    etat["reponses"][("app", "publish")] = {"ok": True, "nom_public": "partage", "evenement": "renommage",
                                            "domaine": "partage.gk2.secubox.in",
                                            "ancien": {"nom_public": "at", "domaine": "at.gk2.secubox.in"},
                                            "code": 0}
    r = client.post("/app/atelier/rename", json={"public_name": "partage"})
    assert r.status_code == 200, r.text
    assert ("app", "publish", "atelier", "partage", "--par", "admin", "--apply") in etat["appels"]
    assert r.json()["domaine"] == "partage.gk2.secubox.in" and r.json()["evenement"] == "renommage"


@pytest.mark.parametrize("nom,statut", [("Partage", 400), ("par_tage", 400), ("-x", 400), ("", 400),
                                        ("hall", 409)])
def test_renommer_refuse_avant_sudo(ctl, nom, statut):
    client, etat = ctl
    etat["conf"].write_text('[instances.at]\napp = "atelier"\nport = 8529\n')
    r = client.post("/app/atelier/rename", json={"public_name": nom})
    assert r.status_code == statut, r.text
    assert etat["appels"] == []


def test_renommer_une_appli_non_publiee_409(ctl):
    client, etat = ctl
    r = client.post("/app/atelier/rename", json={"public_name": "partage"})
    assert r.status_code == 409 and "publi" in r.json()["detail"]
    assert etat["appels"] == []


def test_renommer_vers_un_nom_pris_409(ctl):
    client, etat = ctl
    etat["conf"].write_text('[instances.at]\napp = "atelier"\nport = 8529\n')
    etat["reponses"][("app", "publish")] = {"ok": False, "code": 4,
                                            "error": "nom pris : cpf.gk2.secubox.in est déjà routé"}
    r = client.post("/app/atelier/rename", json={"public_name": "cpf"})
    assert r.status_code == 409 and "cpf" in r.json()["detail"]


# ─── Gardes ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("methode,chemin", [("POST", "/app/{name}/publish"), ("POST", "/app/{name}/rename"),
                                            ("POST", "/app/{name}/unpublish"), ("POST", "/deploy"),
                                            ("POST", "/app/{name}/start"), ("DELETE", "/app/{name}")])
def test_routes_mutantes_gardees_par_require_jwt(methode, chemin):
    route = next(r for r in api_main.router.routes if r.path == chemin and methode in r.methods)
    gardes = [d.call for d in route.dependant.dependencies] + [d.dependency for d in route.dependencies]
    assert require_jwt in gardes


def test_lecture_des_publications_gardee():
    route = next(r for r in api_main.router.routes if r.path == "/publications")
    assert any(d.dependency is require_lecture for d in route.dependencies)


# ─── Environnement de l'appli ──────────────────────────────────────────────

def test_environnement_valeurs_par_l_entree_standard_jamais_en_argument(ctl, monkeypatch):
    client, etat = ctl
    vus = []

    def faux(*args, timeout=30, entree=None):
        vus.append((args, entree))
        if args[0] == "start":
            etat["conteneur"] = True
            return {"output": "", "code": 0}
        return {"ok": True, "cles": ["AP_DB_PATH"], "redemarrage_requis": True, "code": 0}
    monkeypatch.setattr(api_main, "_run_ctl", faux)
    r = client.put("/app/atelier-partage-1/env", json={"vars": {"AP_ADMIN_PASSWORD_HASH": "$2b$12$secret"},
                                                       "unset": ["AP_VIEUX"]})
    assert r.status_code == 200, r.text
    (args, entree), = [v for v in vus if v[0][:2] == ("app", "env")]
    assert args == ("app", "env", "atelier-partage-1", "set", "--unset", "AP_VIEUX", "--par", "admin", "--apply")
    assert entree == "AP_ADMIN_PASSWORD_HASH=$2b$12$secret\n"
    assert "secret" not in r.text


@pytest.mark.parametrize("corps", [{"vars": {"LD_PRELOAD": "/tmp/x.so"}}, {"vars": {"A": "x\ny"}},
                                   {"unset": ["PATH"]}, {"vars": {"1A": "x"}}])
def test_environnement_refuse_avant_sudo(ctl, corps):
    client, etat = ctl
    r = client.put("/app/atelier/env", json=corps)
    assert r.status_code == 400, r.text
    assert etat["appels"] == []


def test_journaux_d_une_appli_rendus_tels_quels_meme_finis_par_du_json():
    sortie = 'INFO démarrage\n{"event": "ready", "port": 8529}\n'
    with patch("api.main.subprocess.run", return_value=subprocess.CompletedProcess(["sudo"], 0, stdout=sortie,
                                                                                    stderr="")):
        r = api_main._run_ctl("app", "logs", "x", "100", brut=True)
    assert r["output"] == sortie
