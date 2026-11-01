# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3362 : « oublier » un nœud le retire de TOUS les états d'exécution du maître, par un seul point d'entrée
(POST /master-link/oublier) ; le statut « online » d'un pair repose sur une poignée de main WireGuard récente."""
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import main, mesh, oubli

ICI = Path(__file__).resolve().parents[1]
K_OLD = "O" * 43 + "="           # ancienne clé de gk1 (10.10.0.2)
K_GK1 = "G" * 43 + "="           # gk1 actuel
K_LGM = "K" * 43 + "="
K_GK4 = "L" * 43 + "="

PEERS = {"peers": [
    {"id": "a", "name": "lgm-ebin", "mesh_ip": "10.10.0.7", "fingerprint": "sb-lgm", "status": "online"},
    {"id": "b", "name": "gk4", "mesh_ip": "10.10.0.9", "fingerprint": "sb-gk4", "status": "online"},
    {"id": "c", "name": "gk1", "mesh_ip": "10.10.0.2", "fingerprint": "sb-gk1-old", "status": "online"},
    {"id": "d", "name": "gk1", "mesh_ip": "10.10.0.3", "fingerprint": "sb-gk1", "status": "online"},
]}
WG = {"enabled": True, "network": "10.10.0.0/24", "private_key": "PRIV", "peers": [
    {"name": "lgm-ebin", "public_key": K_LGM, "mesh_ip": "10.10.0.7", "allowed_ips": "10.10.0.7/32"},
    {"name": "gk4", "public_key": K_GK4, "mesh_ip": "10.10.0.9", "allowed_ips": "10.10.0.9/32"},
    {"name": "gk1", "public_key": K_OLD, "allowed_ips": "10.10.0.2/32"},
    {"name": "gk1", "public_key": K_GK1, "mesh_ip": "10.10.0.3", "allowed_ips": "10.10.0.3/32"},
]}


# ── calcul pur ───────────────────────────────────────────────────────────────────────────────────────────────────────

def test_par_cle_seule_l_entree_de_cette_cle_part_l_homonyme_reste():
    peers, wg, r = oubli.oublier(PEERS, WG, "gk1", handshakes={}, now=1000, local="gk2", cle=K_OLD)
    assert [p["public_key"] for p in wg["peers"]] == [K_LGM, K_GK4, K_GK1]
    assert [p["fingerprint"] for p in peers["peers"]] == ["sb-lgm", "sb-gk4", "sb-gk1"]     # l'entrée 10.10.0.3 reste
    assert r["cles"] == [K_OLD] and r["ips"] == ["10.10.0.2"] and r["empreintes"] == ["sb-gk1-old"]
    assert r["nom_libre"] is False                     # gk1 existe toujours : abonnement et Flotte gardés


def test_par_nom_les_cibles_sont_rendues_et_le_nom_est_libre():
    _, _, r = oubli.oublier(PEERS, WG, "lgm-ebin", handshakes={}, now=1000, local="gk2")
    assert r["registre"] == 1 and r["wg"] == 1
    assert r["cles"] == [K_LGM] and r["ips"] == ["10.10.0.7"] and r["empreintes"] == ["sb-lgm"] and r["nom_libre"] is True


def test_jonctions_et_jetons_du_pair_oublie():
    demandes = [
        {"fingerprint": "sb-lgm", "hostname": "lgm-ebin", "status": "approved", "wg_public_key": K_LGM, "mesh_ip": "10.10.0.7"},
        {"fingerprint": "sb-autre", "hostname": "lgm-ebin-x", "status": "approved", "wg_public_key": "Z" * 43 + "="},
        {"fingerprint": "sb-sanscle", "hostname": "x", "status": "approved", "wg_public_key": K_LGM},
        {"fingerprint": "sb-gk4", "hostname": "gk4", "status": "approved", "wg_public_key": K_GK4},
    ]
    jetons = [
        {"hash": "h1", "status": "used", "peer_fp": "sb-lgm"},
        {"hash": "h2", "status": "used", "peer_fp": "sb-gk4"},
        {"hash": "h3", "status": "active", "flash": True, "nom_prevu": "lgm-ebin"},
        {"hash": "h4", "status": "active", "flash": True, "nom_prevu": "gk4"},
    ]
    cibles = {"cles": [K_LGM], "ips": ["10.10.0.7"], "empreintes": ["sb-lgm"], "nom_libre": True}
    d, j, n = oubli.oublier_jonctions(demandes, jetons, "lgm-ebin", cibles)
    assert [x["fingerprint"] for x in d] == ["sb-autre", "sb-gk4"]
    assert {x["hash"]: x["status"] for x in j} == {"h1": "revoked", "h2": "used", "h3": "revoked", "h4": "active"}
    assert n == {"demandes": 2, "jetons": 2}
    assert demandes[0]["status"] == "approved" and jetons[0]["status"] == "used"        # entrées d'origine intactes
    # nom encore porté (homonyme) : un jeton flash prévu pour ce nom reste
    _, j2, _ = oubli.oublier_jonctions(demandes, jetons, "lgm-ebin", dict(cibles, nom_libre=False))
    assert {x["hash"]: x["status"] for x in j2}["h3"] == "active"


def test_statut_du_registre_mesure_jamais_fige():
    hs = {K_GK4: 990}
    st = {p["mesh_ip"]: p["status"] for p in mesh.statut_registre(PEERS["peers"], WG, hs, now=1000)}
    assert st == {"10.10.0.7": "offline", "10.10.0.9": "online", "10.10.0.2": "offline", "10.10.0.3": "offline"}
    assert {p["status"] for p in mesh.statut_registre(PEERS["peers"], WG, None, now=1000)} == {"unknown"}
    sans_wg = [{"name": "x", "mesh_ip": "10.10.0.50", "status": "online"}]
    assert mesh.statut_registre(sans_wg, WG, hs, now=1000)[0]["status"] == "offline"
    assert PEERS["peers"][0]["status"] == "online"      # pas de modification en place


def test_le_pair_approuve_n_est_plus_ecrit_online():
    src = (ICI / "api" / "main.py").read_text(encoding="utf-8")
    i = src.index("def _add_approved_peer(")
    assert '"status": "online"' not in src[i:src.index("\nclass ", i)]


# ── route ────────────────────────────────────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def maitre(tmp_path, monkeypatch):
    p2p = tmp_path / "p2p"
    ml = p2p / "master-link"
    ml.mkdir(parents=True)
    (tmp_path / "public").mkdir(mode=0o755)
    (p2p / "peers.json").write_text(json.dumps(PEERS))
    (p2p / "wg_mesh.json").write_text(json.dumps(WG))
    (ml / "requests.json").write_text(json.dumps([
        {"fingerprint": "sb-lgm", "hostname": "lgm-ebin", "status": "approved", "wg_public_key": K_LGM, "mesh_ip": "10.10.0.7"},
        {"fingerprint": "sb-gk4", "hostname": "gk4", "status": "approved", "wg_public_key": K_GK4, "mesh_ip": "10.10.0.9"}]))
    (ml / "tokens.json").write_text(json.dumps([{"hash": "h1", "status": "used", "peer_fp": "sb-lgm"}]))
    for nom, val in (("P2P_DIR", p2p), ("PEERS_FILE", p2p / "peers.json"), ("WG_MESH_CONFIG", p2p / "wg_mesh.json"),
                     ("ML_DIR", ml), ("ML_REQUESTS_FILE", ml / "requests.json"), ("ML_TOKENS_FILE", ml / "tokens.json"),
                     ("ML_CONFIG_FILE", ml / "config.json"), ("PAIRS_ENROLES_DIR", tmp_path / "public")):
        monkeypatch.setattr(main, nom, val)
    monkeypatch.setattr(main.mesh, "load_handshakes", lambda *a, **k: {})
    monkeypatch.setattr(main.ancre, "lire", lambda *a, **k: None)
    monkeypatch.setenv("SBX_AUDIT", str(tmp_path / "audit.log"))
    appels = {"root": [], "pilotage": []}

    def root(cibles, nom):
        appels["root"].append((list(cibles["cles"]), list(cibles["ips"]), nom))
        return dict(appels.get("etapes_root") or {"wg_direct": {"ok": True, "detail": "retiré"},
                                                  "relais": {"ok": True, "detail": ""}, "noms": {"ok": True, "detail": ""},
                                                  "autoload": {"ok": True, "detail": ""}})

    def pilotage(nom, force):
        appels["pilotage"].append((nom, force))
        return {"ok": True, "detail": "box oubliée"}
    monkeypatch.setattr(main, "_oubli_suites_root", root)
    monkeypatch.setattr(main, "_oubli_pilotage", pilotage)
    main.app.dependency_overrides[main.require_jwt] = lambda: {"sub": "admin"}
    yield tmp_path, appels
    main.app.dependency_overrides.clear()


def test_route_enchaine_tous_les_nettoyages(maitre):
    tmp, appels = maitre
    r = TestClient(main.app).post("/master-link/oublier", json={"nom": "lgm-ebin", "confirmation": "lgm-ebin"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["status"] == "ok" and d["restes"] == []
    assert set(d["etapes"]) >= {"registre", "jonctions", "projection", "wg_direct", "relais", "noms", "autoload", "pilotage"}
    assert appels["root"] == [([K_LGM], ["10.10.0.7"], "lgm-ebin")] and appels["pilotage"] == [("lgm-ebin", False)]
    p2p = tmp / "p2p"
    assert "lgm-ebin" not in (p2p / "peers.json").read_text() and K_LGM not in (p2p / "wg_mesh.json").read_text()
    assert "sb-lgm" not in (p2p / "master-link" / "requests.json").read_text()
    assert json.loads((p2p / "master-link" / "tokens.json").read_text())[0]["status"] == "revoked"
    assert "lgm-ebin" not in (tmp / "public" / "pairs-enroles.json").read_text()
    audit = (tmp / "audit.log").read_text()
    assert "p2p_noeud_oublie" in audit and '"restes": []' in audit


def test_route_rapporte_ce_qui_reste_sans_mentir(maitre):
    tmp, appels = maitre
    appels["etapes_root"] = {"wg_direct": {"ok": True, "detail": ""}, "relais": {"ok": False, "detail": "haproxy refusé"},
                             "noms": {"ok": True, "detail": ""}, "autoload": {"ok": True, "detail": ""}}
    r = TestClient(main.app).post("/master-link/oublier", json={"nom": "lgm-ebin", "confirmation": "lgm-ebin"})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "partiel" and d["restes"] == ["relais"]
    assert "p2p_noeud_oubli_partiel" in (tmp / "audit.log").read_text()


def test_route_homonyme_garde_abonnement_et_flotte(maitre):
    tmp, appels = maitre
    r = TestClient(main.app).post("/master-link/oublier", json={"nom": "gk1", "confirmation": "gk1", "public_key": K_OLD})
    assert r.status_code == 200, r.text
    assert appels["root"] == [([K_OLD], ["10.10.0.2"], None)]       # pas de nom : autoload et noms du pair gardés
    assert appels["pilotage"] == []
    assert r.json()["etapes"]["pilotage"]["ok"] is True


def test_suites_root_par_sudo_argv_fixe(monkeypatch):
    vus = []

    class R:
        returncode = 0
        stdout = json.dumps({"etapes": {"wg_direct": {"ok": True, "detail": "x"}}})
        stderr = ""
    monkeypatch.setattr(main.subprocess, "run", lambda argv, **k: vus.append((argv, k)) or R())
    e = main._oubli_suites_root({"cles": [K_LGM], "ips": ["10.10.0.7"]}, "lgm-ebin")
    assert e == {"wg_direct": {"ok": True, "detail": "x"}}
    argv, k = vus[0]
    assert argv == ["sudo", "-n", "/usr/sbin/secubox-oubli-pair", "--cle", K_LGM, "--ip", "10.10.0.7", "--nom", "lgm-ebin"]
    assert k.get("shell") is not True and k.get("timeout")
    R.returncode, R.stdout, R.stderr = 1, "", "sudo: refus"
    e = main._oubli_suites_root({"cles": [K_LGM], "ips": []}, None)
    assert e["racine"]["ok"] is False


def test_peers_en_repli_et_status_mesures(maitre, monkeypatch):
    monkeypatch.setattr(main, "get_wg_mesh_config", lambda: {"peers": []})
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "admin"}
    c = TestClient(main.app)
    assert {p["status"] for p in c.get("/peers").json()["peers"]} == {"offline"}
    assert c.get("/status").json()["online_peers"] == 0


# ── assistant root : secubox-oubli-pair ──────────────────────────────────────────────────────────────────────────────

HELPER = ICI / "sbin" / "secubox-oubli-pair"


def _bin(tmp, nom, corps):
    f = tmp / nom
    f.write_text("#!/bin/sh\n" + corps + "\n")
    f.chmod(0o755)
    return f


@pytest.fixture
def banc(tmp_path):
    wg_etat = {"network": "10.10.0.0/24", "peers": [{"name": "gk4", "public_key": K_GK4, "mesh_ip": "10.10.0.9"}]}
    (tmp_path / "wg_mesh.json").write_text(json.dumps(wg_etat))
    (tmp_path / "peers.json").write_text(json.dumps({"peers": [{"name": "gk4", "mesh_ip": "10.10.0.9"}]}))
    (tmp_path / "noms.conf").write_text('local-data: "gk4.mesh.x. A 10.10.0.9"\n')
    log = tmp_path / "appels.log"
    env = dict(os.environ,
               SBX_OUBLI_WG_ETAT=str(tmp_path / "wg_mesh.json"), SBX_OUBLI_PEERS=str(tmp_path / "peers.json"),
               SBX_OUBLI_AUDIT=str(tmp_path / "audit.log"), SBX_OUBLI_NOMS_CONF=str(tmp_path / "noms.conf"),
               SBX_OUBLI_ANCRE=str(tmp_path / "ancre.json"),
               SBX_OUBLI_WG_BIN=str(_bin(tmp_path, "wg", f'echo "wg $*" >> {log}\n[ "$1" = set ] && touch {tmp_path}/retire\n'
                                                f'[ "$1" = show ] && {{ [ -e {tmp_path}/retire ] || echo {K_LGM}; echo {K_GK4}; }}\nexit 0')),
               SBX_OUBLI_RELAIS=str(_bin(tmp_path, "relais", f'echo "relais $*" >> {log}')),
               SBX_OUBLI_NOMS=str(_bin(tmp_path, "noms", f'echo "noms" >> {log}')),
               SBX_OUBLI_AUTOLOADCTL=str(_bin(tmp_path, "autoloadctl", f'echo "autoload $*" >> {log}')))
    return tmp_path, env, log


def _helper(env, *args):
    return subprocess.run([sys.executable, str(HELPER), *args], env=env, capture_output=True, text=True, timeout=30)


def test_helper_retire_la_seule_cle_exacte_et_enchaine(banc):
    tmp, env, log = banc
    r = _helper(env, "--cle", K_LGM, "--ip", "10.10.0.7", "--nom", "lgm-ebin")
    assert r.returncode == 0, r.stderr
    e = json.loads(r.stdout)["etapes"]
    assert all(v["ok"] for v in e.values()), e
    appels = log.read_text().splitlines()
    assert f"wg set wg-mesh peer {K_LGM} remove" in appels
    assert not [a for a in appels if "remove" in a and K_LGM not in a]
    assert "relais oublier-pair 10.10.0.7" in appels and "noms" in appels and "autoload maillage-oublier --nom lgm-ebin" in appels
    assert "p2p_oubli_suite" in (tmp / "audit.log").read_text()


@pytest.mark.parametrize("args", [
    ["--cle", K_GK4],                                  # clé encore dans wg_mesh.json
    ["--cle", "pas-une-cle"],
    ["--ip", "10.10.0.9"],                             # adresse encore tenue
    ["--ip", "192.168.1.1"],                           # hors du maillage
    ["--cle", K_LGM, "--nom", "gk4"],                  # nom encore porté
    ["--cle", K_LGM, "--nom", "GK;rm"],
    [],
])
def test_helper_refuse_ce_qui_n_est_pas_oublie(banc, args):
    tmp, env, log = banc
    r = _helper(env, *args)
    assert r.returncode == 2
    assert not log.exists() or "remove" not in log.read_text()


def test_helper_refuse_la_cle_de_l_ancre(banc):
    tmp, env, log = banc
    (tmp / "ancre.json").write_text(json.dumps({"cle_publique": K_LGM}))
    assert _helper(env, "--cle", K_LGM).returncode == 2


def test_helper_rapporte_l_echec_d_une_etape(banc):
    tmp, env, log = banc
    env["SBX_OUBLI_RELAIS"] = str(_bin(tmp, "relais-ko", "echo boum >&2; exit 1"))
    (tmp / "noms.conf").write_text('local-data: "lgm-ebin.mesh.x. A 10.10.0.7"\n')     # régénération sans effet
    r = _helper(env, "--cle", K_LGM, "--ip", "10.10.0.7", "--nom", "lgm-ebin")
    assert r.returncode == 0
    e = json.loads(r.stdout)["etapes"]
    assert e["relais"]["ok"] is False and "boum" in e["relais"]["detail"]
    assert e["noms"]["ok"] is False                    # le nom reste dans Unbound : dit, pas caché
    assert e["wg_direct"]["ok"] is True


def test_sudoers_et_installation_du_helper():
    s = (ICI / "sudoers" / "secubox-p2p-oubli").read_text()
    lignes = [x for x in s.splitlines() if x.strip() and not x.startswith("#")]
    assert lignes == ["secubox ALL=(root) NOPASSWD: /usr/sbin/secubox-oubli-pair"]
    rules = (ICI / "debian" / "rules").read_text()
    assert "sbin/secubox-oubli-pair" in rules and "sudoers/secubox-p2p-oubli" in rules
    assert HELPER.stat().st_mode & stat.S_IXUSR


# ── relais : noms relayés vers l'adresse du pair oublié ──────────────────────────────────────────────────────────────

def test_relais_oublier_pair_retire_les_noms_de_cette_ip(tmp_path):
    texte = (ICI / "sbin" / "secubox-relais-maillage").read_text()
    assert re.search(r"^\s+oublier-pair\) shift; verrou_commun; cmd_oublier_pair", texte, re.M)
    debut = texte.index("routes_de_ip() {")
    corps = texte[debut:texte.index("\n}\n", debut)]
    code = tmp_path / "r.py"
    code.write_text(re.search(r"<<'PY'\n(.*?)\nPY", corps, re.S).group(1))
    routes = tmp_path / "routes.json"
    routes.write_text(json.dumps({"hall.lgm.x.in": ["10.10.0.7", 9080], "cloud.lgm.x.in": ["10.10.0.7", 9080],
                                  "hall.gk4.x.in": ["10.10.0.9", 9080], "hall.x.in": ["127.0.0.1", 8085]}))
    r = subprocess.run([sys.executable, "-I", str(code), str(routes), "10.10.0.7"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.split() == ["cloud.lgm.x.in", "hall.lgm.x.in"]
