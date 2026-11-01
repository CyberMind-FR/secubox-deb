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
import threading
import time
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

    def root(cibles, nom, force=False, acteur="?"):
        appels["root"].append((list(cibles["cles"]), list(cibles["ips"]), nom))
        appels.setdefault("force", []).append(force)
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


def _oublier(corps, attendu=202):
    """#3362 (correction) : la route répond 202 avec une opération ; les étapes root se suivent par GET."""
    c = TestClient(main.app)
    r = c.post("/master-link/oublier", json=corps)
    assert r.status_code == attendu, r.text
    if attendu != 202:
        return r
    op = r.json()["operation"]
    assert re.fullmatch(r"[0-9a-f]{32}", op)
    for _ in range(200):
        d = c.get(f"/master-link/oublier/{op}").json()
        if d["etat"] == "termine":
            return d
        time.sleep(0.02)
    raise AssertionError("opération jamais terminée")


def test_route_enchaine_tous_les_nettoyages(maitre):
    tmp, appels = maitre
    d = _oublier({"nom": "lgm-ebin", "confirmation": "lgm-ebin"})
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
    d = _oublier({"nom": "lgm-ebin", "confirmation": "lgm-ebin"})
    assert d["status"] == "partiel" and d["restes"] == ["relais"]
    assert "p2p_noeud_oubli_partiel" in (tmp / "audit.log").read_text()


def test_route_homonyme_garde_abonnement_et_flotte(maitre):
    tmp, appels = maitre
    d = _oublier({"nom": "gk1", "confirmation": "gk1", "public_key": K_OLD})
    assert appels["root"] == [([K_OLD], ["10.10.0.2"], None)]       # pas de nom : autoload et noms du pair gardés
    assert appels["pilotage"] == []
    assert d["etapes"]["pilotage"]["ok"] is True


def test_suites_root_par_sudo_argv_fixe(monkeypatch):
    vus = []

    class R:
        returncode = 0
        stdout = json.dumps({"etapes": {"wg_direct": {"ok": True, "detail": "x"}}})
        stderr = ""
    monkeypatch.setattr(main.subprocess, "run", lambda argv, **k: vus.append((argv, k)) or R())
    e = main._oubli_suites_root({"cles": [K_LGM], "ips": ["10.10.0.7"]}, "lgm-ebin", force=True, acteur="admin")
    assert e == {"wg_direct": {"ok": True, "detail": "x"}}
    argv, k = vus[0]
    assert argv == ["sudo", "-n", "/usr/sbin/secubox-oubli-pair", "--acteur", "admin", "--cle", K_LGM, "--ip", "10.10.0.7",
                    "--nom", "lgm-ebin", "--force"]
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


# ── passe de correction après revue (#3362) ──────────────────────────────────────────────────────────────────────────

def test_jetons_illisibles_503_et_fichier_intact(maitre):
    tmp, appels = maitre
    f = tmp / "p2p" / "master-link" / "tokens.json"
    f.write_text("{coupé")
    _oublier({"nom": "lgm-ebin", "confirmation": "lgm-ebin"}, attendu=503)
    assert f.read_text() == "{coupé"
    assert "lgm-ebin" in (tmp / "p2p" / "peers.json").read_text() and appels["root"] == []
    (tmp / "p2p" / "master-link" / "requests.json").write_text("[1, ")
    f.write_text("[]")
    _oublier({"nom": "lgm-ebin", "confirmation": "lgm-ebin"}, attendu=503)


def test_jetons_non_reecrits_sans_entree_du_pair(maitre):
    tmp, appels = maitre
    f = tmp / "p2p" / "master-link" / "tokens.json"
    f.write_text(json.dumps([{"hash": "hx", "status": "active", "flash": True, "nom_prevu": "gk9"}]))
    avant = f.stat().st_mtime_ns
    time.sleep(0.01)
    _oublier({"nom": "lgm-ebin", "confirmation": "lgm-ebin"})
    assert f.stat().st_mtime_ns == avant


def test_ecriture_concurrente_des_jetons_non_perdue(maitre):
    tmp, appels = maitre
    from api import jetons as J
    tient, relache = threading.Event(), threading.Event()

    def ecrivain():
        with oubli.verrou(tmp / "p2p"):
            tient.set()
            relache.wait(5)
        J.generer(3600, True, nom_prevu="gk9", flash=True, chemin=str(tmp / "p2p" / "master-link" / "tokens.json"))
    t = threading.Thread(target=ecrivain)
    t.start()
    tient.wait(5)
    res = {}
    o = threading.Thread(target=lambda: res.update(d=_oublier({"nom": "lgm-ebin", "confirmation": "lgm-ebin"})))
    o.start()
    time.sleep(0.1)
    relache.set()
    t.join(5)
    o.join(10)
    jet = json.loads((tmp / "p2p" / "master-link" / "tokens.json").read_text())
    assert {j["hash"]: j["status"] for j in jet}["h1"] == "revoked"
    assert any(j.get("nom_prevu") == "gk9" for j in jet)              # le jeton émis pendant l'oubli est gardé


def test_generer_un_jeton_sous_le_verrou_et_lecture_stricte(tmp_path):
    from api import jetons as J
    ml = tmp_path / "master-link"
    ml.mkdir()
    (ml / "tokens.json").write_text("{coupé")
    with pytest.raises(oubli.EtatIllisible):
        J.generer(3600, True, chemin=str(ml / "tokens.json"))
    assert (ml / "tokens.json").read_text() == "{coupé"
    src = (ICI / "api" / "jetons.py").read_text()
    assert "oubli.verrou(" in src


def test_save_json_des_fichiers_de_jonction_atomique_sous_verrou():
    src = (ICI / "api" / "main.py").read_text()
    i = src.index("def save_json(")
    bloc = src[i:src.index("\ndef ", i + 10)]
    assert "ML_REQUESTS_FILE" in bloc and "ML_TOKENS_FILE" in bloc


def test_get_operation_garde_et_inconnue(maitre):
    c = TestClient(main.app)
    assert c.get("/master-link/oublier/" + "0" * 32).status_code == 404
    assert c.get("/master-link/oublier/pas-un-id").status_code in (404, 422)
    src = (ICI / "api" / "main.py").read_text()
    i = src.index('@app.get("/master-link/oublier/{operation}")')
    assert "require_jwt" in src[i:i + 300]


def test_force_et_acteur_transmis(maitre):
    tmp, appels = maitre
    _oublier({"nom": "lgm-ebin", "confirmation": "lgm-ebin", "force": True})
    assert appels["force"] == [True]


def test_helper_refuse_une_poignee_recente_sauf_force(banc):
    tmp, env, log = banc
    env["SBX_OUBLI_WG_BIN"] = str(_bin(tmp, "wg-hs", f'echo "wg $*" >> {log}\n'
                                         f'[ "$3" = latest-handshakes ] && {{ echo "{K_LGM}\t$(date +%s)"; exit 0; }}\n'
                                         f'[ "$1" = show ] && echo {K_LGM}\nexit 0'))
    r = _helper(env, "--cle", K_LGM, "--acteur", "admin")
    assert r.returncode == 2 and "poignée" in r.stdout
    assert "remove" not in log.read_text()
    r = _helper(env, "--cle", K_LGM, "--acteur", "admin", "--force")
    assert r.returncode == 0
    a = (tmp / "audit.log").read_text()
    assert '"force": true' in a and '"acteur": "admin"' in a


def test_helper_acteur_valide_et_audit_en_echec_remonte(banc):
    tmp, env, log = banc
    assert _helper(env, "--cle", K_LGM, "--acteur", "a b;c").returncode == 2
    env["SBX_OUBLI_AUDIT"] = str(tmp / "absent" / "audit.log")
    r = _helper(env, "--cle", K_LGM, "--acteur", "admin")
    assert r.returncode == 0 and json.loads(r.stdout)["audit_ok"] is False and "audit" in r.stderr


def test_helper_nom_31_et_shebang_isole(banc):
    tmp, env, log = banc
    assert _helper(env, "--cle", K_LGM, "--nom", "a" * 32).returncode == 2
    assert HELPER.read_text().splitlines()[0] == "#!/usr/bin/python3 -I"


def test_helper_refuse_un_etat_en_lien(banc):
    tmp, env, log = banc
    (tmp / "vrai.json").write_text((tmp / "wg_mesh.json").read_text())
    (tmp / "wg_mesh.json").unlink()
    (tmp / "wg_mesh.json").symlink_to(tmp / "vrai.json")
    assert _helper(env, "--cle", K_LGM).returncode == 2


def test_helper_noms_partiel_sans_redemarrage(banc):
    tmp, env, log = banc
    env["SBX_OUBLI_NOMS"] = str(_bin(tmp, "noms-3", f'echo "noms $*" >> {log}; exit 3'))
    r = _helper(env, "--cle", K_LGM, "--ip", "10.10.0.7")
    e = json.loads(r.stdout)["etapes"]["noms"]
    assert e["ok"] is False and "administrateur" in e["detail"]
    assert "noms --sans-redemarrage" in log.read_text()


def test_apparmor_du_helper():
    prof = (ICI / "apparmor" / "usr.sbin.secubox-oubli-pair").read_text()
    assert "flags=(enforce)" in prof or "profile secubox-oubli-pair /usr/sbin/secubox-oubli-pair" in prof
    for x in ("/usr/bin/wg", "/usr/sbin/secubox-relais-maillage", "/usr/sbin/secubox-annuaire-noms", "/usr/sbin/autoloadctl",
              "/var/log/secubox/audit.log", "/var/lib/secubox/p2p/wg_mesh.json"):
        assert x in prof, x
    assert "SPDX" in prof
    rules = (ICI / "debian" / "rules").read_text()
    post = (ICI / "debian" / "postinst").read_text()
    assert "apparmor/usr.sbin.secubox-oubli-pair" in rules and "apparmor_parser" in post and "secubox-oubli-pair" in post


def test_relais_greps_litteraux_et_retrait_journalise():
    texte = (ICI / "sbin" / "secubox-relais-maillage").read_text()
    i = texte.index("cmd_oublier_pair() {")
    corps = texte[i:texte.index("\n}\n", i)]
    assert ">/dev/null 2>&1" not in corps
    assert texte.index("pair_du_maillage_exact() {") < i
    j = texte.index("pair_du_maillage_exact() {")
    assert "grep -qE" not in texte[j:texte.index("\n}\n", j)]


# ── passe 2 (#3362) : lecture-modification-écriture des jonctions en UNE section critique ────────────────────────────

def _jeton(c="a"):
    return c * 64


def _ml(tmp):
    return tmp / "p2p" / "master-link"


def _concurrent(tmp, action, pendant):
    """`pendant` (un « oubli ») tient le verrou ; `action` part pendant ce temps. Sans section critique unique, l'action lit
    l'état d'avant et le réécrit après : ce que l'oubli a retiré revient."""
    tient, relache = threading.Event(), threading.Event()

    def oubli_concurrent():
        with oubli.verrou(tmp / "p2p"):
            tient.set()
            relache.wait(5)
            pendant()
    t = threading.Thread(target=oubli_concurrent)
    t.start()
    tient.wait(5)
    res = {}
    a = threading.Thread(target=lambda: res.update(r=action()))
    a.start()
    time.sleep(0.2)
    relache.set()
    t.join(5)
    a.join(10)
    return res["r"]


def test_validation_concurrente_d_un_oubli_ne_reactive_pas_le_jeton(maitre, monkeypatch):
    tmp, _ = maitre
    f = _ml(tmp) / "tokens.json"
    h = main.hash_token(_jeton())
    f.write_text(json.dumps([{"hash": h, "status": "active", "expires_ts": time.time() + 3600, "auto_approve": True}]))
    monkeypatch.setattr(main, "_provision", lambda *a, **k: None)

    def revoquer():
        d = json.loads(f.read_text())
        d[0]["status"] = "revoked"
        oubli.ecrire_atomique(f, d, 0o600)
    r = _concurrent(tmp, lambda: TestClient(main.app).post("/master-link/join", json={
        "token": _jeton(), "fingerprint": "sb-neuf", "hostname": "neuf"}), revoquer)
    assert r.status_code == 403
    assert json.loads(f.read_text())[0]["status"] == "revoked"
    assert "sb-neuf" not in (_ml(tmp) / "requests.json").read_text()


def test_approbation_concurrente_d_un_oubli_ne_ramene_pas_le_pair(maitre, monkeypatch):
    tmp, _ = maitre
    f = _ml(tmp) / "requests.json"
    f.write_text(json.dumps([{"fingerprint": "sb-x", "hostname": "x", "status": "pending", "mesh_ip": "10.10.0.30"}]))
    monkeypatch.setattr(main, "_provision", lambda *a, **k: None)

    def oublier_la_demande():
        oubli.ecrire_atomique(f, [], 0o600)
    r = _concurrent(tmp, lambda: TestClient(main.app).post("/master-link/approve", json={"fingerprint": "sb-x", "action": "approve"}),
                    oublier_la_demande)
    assert r.status_code == 404
    assert json.loads(f.read_text()) == []
    assert "sb-x" not in (tmp / "p2p" / "peers.json").read_text()


@pytest.mark.parametrize("appel", [
    lambda c: c.post("/master-link/join", json={"token": _jeton(), "fingerprint": "sb-n", "hostname": "n"}),
    lambda c: c.post("/master-link/token/cleanup"),
    lambda c: c.post("/master-link/token/revoke", params={"token": _jeton()}),
])
def test_jetons_corrompus_503_et_intacts_partout(maitre, appel):
    tmp, _ = maitre
    f = _ml(tmp) / "tokens.json"
    f.write_text("{coupé")
    assert appel(TestClient(main.app)).status_code == 503
    assert f.read_text() == "{coupé"


def test_demandes_corrompues_503_et_intactes(maitre):
    tmp, _ = maitre
    f = _ml(tmp) / "requests.json"
    f.write_text("[coupé")
    assert TestClient(main.app).post("/master-link/approve", json={"fingerprint": "sb-x", "action": "approve"}).status_code == 503
    assert f.read_text() == "[coupé"


def test_verrou_reentrant_dans_le_meme_fil(tmp_path):
    with oubli.verrou(tmp_path):
        assert oubli.tenu(tmp_path)
        with oubli.verrou(tmp_path):                  # save_json sous la section critique : pas d'auto-blocage
            pass
        assert oubli.tenu(tmp_path)
    assert not oubli.tenu(tmp_path)


def test_garde_wg_fermee_si_la_mesure_echoue(banc):
    tmp, env, log = banc
    env["SBX_OUBLI_WG_BIN"] = str(_bin(tmp, "wg-ko", 'echo "permission refusée" >&2; exit 1'))
    env["SBX_OUBLI_IP_BIN"] = str(_bin(tmp, "ip-ok", 'echo "5: wg-mesh: <POINTOPOINT>"; exit 0'))
    r = _helper(env, "--cle", K_LGM)
    assert r.returncode == 2 and "mesure" in r.stdout
    assert _helper(env, "--cle", K_LGM, "--force").returncode == 0
    env["SBX_OUBLI_IP_BIN"] = str(_bin(tmp, "ip-absent", 'echo \'Device "wg-mesh" does not exist.\' >&2; exit 1'))
    assert _helper(env, "--cle", K_LGM).returncode == 0          # interface absente, vérifiée : aucun pair n'y vit
    env["SBX_OUBLI_IP_BIN"] = str(_bin(tmp, "ip-ko", 'echo "RTNETLINK: autre" >&2; exit 2'))
    assert _helper(env, "--cle", K_LGM).returncode == 2


def test_documentation_force_et_pux():
    readme = (ICI / "README.md").read_text()
    assert "tout appelant du compte" in readme and "hors confinement" in readme
    prof = (ICI / "apparmor" / "usr.sbin.secubox-oubli-pair").read_text()
    assert "hors confinement" in prof
    assert "tout appelant du compte" in (ICI / "debian" / "changelog").read_text().split("\n -- ")[0]


def test_operations_terminees_seules_purgees_et_etat_passe_en_argument():
    src = (ICI / "api" / "main.py").read_text()
    i = src.index("def _finir_oubli(")
    corps = src[i:src.index("\ndef ", i + 10)]
    assert "OPERATIONS_OUBLI[op]" not in corps.split("_operation_maj")[0]
    j = src.index('@app.post("/master-link/oublier"')
    assert '"termine"' in src[j:j + 6000].split("OPERATIONS_OUBLI[op] = ")[0]


def test_jetons_chown_avant_remplacement():
    src = (ICI / "api" / "jetons.py").read_text()
    i = src.index("def ecrire(")
    corps = src[i:src.index("\ndef ", i + 5)]
    assert "fchown" in corps and corps.index("fchown") < corps.index("os.replace")


def test_postinst_echec_apparmor_audite():
    post = (ICI / "debian" / "postinst").read_text()
    i = post.index("usr.sbin.secubox-oubli-pair")
    assert "audit.log" in post[i:i + 900]


# ── passe 3 (#3362) : jamais de flock bloquant dans la boucle asyncio ────────────────────────────────────────────────

def _tenir(tmp, duree):
    tient = threading.Event()

    def t():
        with oubli.verrou(tmp / "p2p"):
            tient.set()
            time.sleep(duree)
    th = threading.Thread(target=t, daemon=True)
    th.start()
    tient.wait(5)
    return th


def test_route_publique_503_vite_et_status_repond_pendant_un_verrou_tenu(maitre):
    tmp, _ = maitre
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "admin"}
    with TestClient(main.app) as c:                        # UNE boucle : un flock bloquant la figerait pour tous
        th = _tenir(tmp, 6)                                # gel attendu sans correction : ~6 s ; seuils tenus sous charge
        res = {}

        def publique():
            t0 = time.monotonic()
            res["r"] = c.post("/master-link/token/validate", params={"token": _jeton()})
            res["t"] = time.monotonic() - t0
        a = threading.Thread(target=publique)
        a.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        assert c.get("/status").status_code == 200
        assert time.monotonic() - t0 < 3
        a.join(8)
        assert res["r"].status_code == 503 and res["t"] < 3
        th.join(8)


def test_approbation_hors_de_la_boucle(maitre):
    tmp, _ = maitre
    (_ml(tmp) / "requests.json").write_text(json.dumps([{"fingerprint": "sb-x", "hostname": "x", "status": "pending"}]))
    main.app.dependency_overrides[main.require_lecture] = lambda: {"sub": "admin"}
    with TestClient(main.app) as c:
        th = _tenir(tmp, 2)
        a = threading.Thread(target=lambda: c.post("/master-link/approve", json={"fingerprint": "sb-x", "action": "reject"}))
        a.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        assert c.get("/status").status_code == 200
        assert time.monotonic() - t0 < 1.5
        a.join(5)
        th.join(5)
    assert json.loads((_ml(tmp) / "requests.json").read_text())[0]["status"] == "rejected"


def test_promotion_notifiee_apres_le_fil(maitre, monkeypatch):
    tmp, _ = maitre
    (_ml(tmp) / "requests.json").write_text(json.dumps([{"fingerprint": "sb-x", "hostname": "x", "status": "approved",
                                                         "address": "192.168.1.9", "depth": 1}]))
    vus = []

    async def notifier(addr, depth):
        vus.append((addr, depth))
    monkeypatch.setattr(main, "_notify_peer_promotion", notifier)
    with TestClient(main.app) as c:
        r = c.post("/master-link/approve", json={"fingerprint": "sb-x", "action": "promote"})
        assert r.status_code == 200, r.text
        assert r.json()["new_role"] == "sub-master"
        for _ in range(50):
            if vus:
                break
            time.sleep(0.02)
    assert vus == [("192.168.1.9", 1)]


def test_routes_de_jetons_hors_boucle():
    src = (ICI / "api" / "main.py").read_text()
    for f in ("ml_validate_token", "ml_revoke_token", "ml_cleanup", "ml_cleanup_local"):
        assert f"\ndef {f}(" in src and f"async def {f}(" not in src, f
    i = src.index("async def ml_approve(")
    assert "asyncio.to_thread(" in src[i:i + 900]


def test_oubli_429_si_aucune_operation_purgeable(maitre):
    tmp, _ = maitre
    with main._operations_verrou:
        main.OPERATIONS_OUBLI.clear()
        for i in range(main._OPERATIONS_MAX):
            main.OPERATIONS_OUBLI[f"{i:032x}"] = {"etat": "en_cours"}
    try:
        r = TestClient(main.app).post("/master-link/oublier", json={"nom": "lgm-ebin", "confirmation": "lgm-ebin"})
        assert r.status_code == 429
        assert "lgm-ebin" in (tmp / "p2p" / "peers.json").read_text()     # rien n'est oublié
    finally:
        with main._operations_verrou:
            main.OPERATIONS_OUBLI.clear()


def test_helper_erreur_d_execution_de_wg_refus_sans_trace(banc):
    tmp, env, log = banc
    env["SBX_OUBLI_WG_BIN"] = str(tmp / "wg-introuvable")
    env["SBX_OUBLI_IP_BIN"] = str(tmp / "ip-introuvable")
    r = _helper(env, "--cle", K_LGM)
    assert r.returncode == 2 and "mesure" in r.stdout and "Traceback" not in r.stderr


def test_helper_ip_link_une_seule_fois_si_absente(banc):
    tmp, env, log = banc
    env["SBX_OUBLI_WG_BIN"] = str(_bin(tmp, "wg-absent", 'echo "Unable to access interface" >&2; exit 1'))
    env["SBX_OUBLI_IP_BIN"] = str(_bin(tmp, "ip-absent1", f'echo "ip $*" >> {log}; echo \'Device "wg-mesh" does not exist.\' >&2; exit 1'))
    r = _helper(env, "--cle", K_LGM)
    assert r.returncode == 0, r.stdout
    assert log.read_text().count("ip link show wg-mesh") == 1


def test_iproute2_dans_depends():
    ctl = (ICI / "debian" / "control").read_text()
    dep = ctl[ctl.index("\nDepends:"):ctl.index("\nRecommends:")]
    assert "\n iproute2," in dep


# ── passe 4 (#3362) : aucune écriture verrouillée dans la boucle ─────────────────────────────────────────────────────

def _async_qui_verrouillent():
    """Coroutines du module qui atteignent (directement ou par des fonctions SYNCHRONES du module) save_json,
    oubli.verrou ou jetons.generer. Un appel passé à asyncio.to_thread n'est pas un appel : la fonction n'est que nommée."""
    import ast
    arbre = ast.parse((ICI / "api" / "main.py").read_text())
    defs = {n.name: n for n in arbre.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    interdits = {"save_json", "verrou", "generer", "ecrire_atomique", "publier", "_ecrire_sous_verrou", "maj_json"}

    def appels(f):
        out = set()
        for n in ast.walk(f):
            if isinstance(n, ast.Call):
                c = n.func
                out.add(c.id if isinstance(c, ast.Name) else c.attr if isinstance(c, ast.Attribute) else None)
        return out - {None}

    memo = {}

    def parcours(nom, pile):
        """(atteint, a_croise_un_cycle). Un résultat n'est mémorisé que s'il ne dépend d'aucun cycle en cours."""
        if nom in interdits:
            return True, False
        f = defs.get(nom)
        if f is None or isinstance(f, ast.AsyncFunctionDef):
            return False, False
        if nom in pile:
            return False, True
        if nom in memo:
            return memo[nom], False
        cycle = False
        for x in appels(f):
            a, c = parcours(x, pile | {nom})
            cycle = cycle or c
            if a:
                memo[nom] = True
                return True, False
        if not cycle:
            memo[nom] = False
        return False, cycle

    def atteint(nom):
        return parcours(nom, frozenset())[0]
    return sorted(n for n, f in defs.items() if isinstance(f, ast.AsyncFunctionDef)
                  and any(atteint(x) for x in appels(f)))


def test_aucune_coroutine_n_ecrit_sous_verrou():
    assert _async_qui_verrouillent() == []


def test_taches_gardees_et_place_reservee_avec_le_429():
    src = (ICI / "api" / "main.py").read_text()
    assert "_TACHES" in src and "add_done_callback(_TACHES.discard)" in src
    i = src.index("trop d'oublis en cours")
    bloc = src[src.rindex("with _operations_verrou:", 0, i):i + 900]
    assert "OPERATIONS_OUBLI[op] =" in bloc                     # réservée dans la même section que le contrôle


def test_invite_master_link_en_lien_message_clair(tmp_path):
    p2p = tmp_path / "p2p"
    p2p.mkdir()
    (tmp_path / "ailleurs").mkdir()
    (p2p / "master-link").symlink_to(tmp_path / "ailleurs")
    script = ICI / "scripts" / "sbx-mesh-invite"
    env = dict(os.environ, SBX_P2P_DIR=str(p2p), SBX_AUDIT=str(tmp_path / "audit.log"), PYTHONPATH=str(ICI))
    r = subprocess.run([sys.executable, str(script), "--code", "--json", "--adresse", "192.168.1.1"],
                       env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 1 and "Traceback" not in r.stderr and "lien" in r.stderr


# ── passe 5 (#3362) : lecture-modification-écriture du registre sous UN verrou ───────────────────────────────────────

def _crochet_lecture(monkeypatch, quand):
    """Après chaque lecture TOLÉRANTE de peers.json (ancien chemin), `quand()` s'exécute avant que l'appelant écrive."""
    reel = main.load_json

    def load_json(path, default=None):
        d = reel(path, default)
        if Path(path) == main.PEERS_FILE:
            quand()
        return d
    monkeypatch.setattr(main, "load_json", load_json)


def test_deux_ajouts_concurrents_aucune_mise_a_jour_perdue(maitre, monkeypatch):
    tmp, _ = maitre
    _crochet_lecture(monkeypatch, lambda: time.sleep(0.3))
    corps = [{"address": f"192.168.1.{i}", "fingerprint": f"fp{i}", "action": "approve"} for i in (51, 52)]
    fils = [threading.Thread(target=lambda c=c: TestClient(main.app).post("/peers", json=c)) for c in corps]
    for f in fils:
        f.start()
    for f in fils:
        f.join(10)
    adresses = {p.get("address") for p in json.loads((tmp / "p2p" / "peers.json").read_text())["peers"]}
    assert {"192.168.1.51", "192.168.1.52"} <= adresses


def _oubli_pendant(tmp, monkeypatch):
    """Un oubli de lgm-ebin lancé PENDANT la fenêtre lecture → écriture de l'appelant."""
    fini = threading.Event()

    def oublier():
        TestClient(main.app).post("/master-link/oublier", json={"nom": "lgm-ebin", "confirmation": "lgm-ebin"})
        fini.set()

    def quand():
        if not getattr(quand, "fait", False):
            quand.fait = True
            threading.Thread(target=oublier, daemon=True).start()
            fini.wait(1.0)                       # ancien chemin : l'oubli passe pendant la fenêtre
    _crochet_lecture(monkeypatch, quand)
    fini.quand = quand
    fini.oublier = oublier
    return fini


@pytest.mark.parametrize("appel", ["add_peer", "discover", "probe"])
def test_ecriture_qui_chevauche_un_oubli_ne_ramene_pas_le_pair(maitre, monkeypatch, appel):
    tmp, _ = maitre
    f = tmp / "p2p" / "peers.json"
    d = json.loads(f.read_text())
    d["peers"][1]["address"] = "192.168.1.40"                 # gk4 sondable
    f.write_text(json.dumps(d))
    fini = _oubli_pendant(tmp, monkeypatch)

    async def decouverte(method, timeout):
        return {"discovered": [{"id": "sb-nouveau", "name": "nouveau", "address": "192.168.1.77"},
                               {"id": "a", "name": "lgm-ebin", "address": "192.168.1.70"}], "count": 2}   # l'oublié, revu
    monkeypatch.setattr(main, "discover_peers", decouverte)

    async def sans_reseau(*a, **k):
        raise OSError("pas de réseau dans l'essai")
    monkeypatch.setattr(main.asyncio, "create_subprocess_exec", sans_reseau)
    c = TestClient(main.app)
    if appel == "add_peer":
        r = c.post("/peers", json={"address": "192.168.1.77", "fingerprint": "fp", "action": "approve"})
    elif appel == "discover":
        r = c.post("/discover", json={"method": "all", "timeout": 1})
    else:
        r = c.post("/peers/b/probe")                     # sonde gk4 (id « b »)
    assert r.status_code == 200, r.text
    if not getattr(fini.quand, "fait", False):      # chemin corrigé : aucune lecture tolérante, l'oubli passe après
        fini.oublier()
    fini.wait(5)
    for _ in range(100):
        if "en_cours" not in json.dumps(main.OPERATIONS_OUBLI):
            break
        time.sleep(0.02)
    noms = [p.get("name") for p in json.loads((tmp / "p2p" / "peers.json").read_text())["peers"]]
    assert "lgm-ebin" not in noms
    if appel in ("add_peer", "discover"):
        assert "192.168.1.77" in (tmp / "p2p" / "peers.json").read_text()      # l'ajout lui-même n'est pas perdu


def test_jetons_ecrits_par_descripteur_de_dossier(tmp_path):
    from api import jetons as J
    src = (ICI / "api" / "jetons.py").read_text()
    i = src.index("def ecrire(")
    corps = src[i:src.index("\ndef ", i + 5)]
    assert "O_DIRECTORY" in corps and "O_NOFOLLOW" in corps and "dir_fd" in corps and "src_dir_fd" in corps
    ml = tmp_path / "ml"
    ml.mkdir()
    J.ecrire([{"hash": "x"}], str(ml / "tokens.json"))
    assert json.loads((ml / "tokens.json").read_text()) == [{"hash": "x"}]
    assert (ml / "tokens.json").stat().st_mode & 0o777 == 0o600 and [p.name for p in ml.iterdir()] == ["tokens.json"]
    (tmp_path / "lien").symlink_to(ml)
    with pytest.raises(OSError):
        J.ecrire([], str(tmp_path / "lien" / "tokens.json"))


def test_repere_porte_le_ctime():
    src = (ICI / "sbin" / "secubox-maillage-pairs").read_text()
    i = src.index("def _repere(")
    assert "st_ctime_ns" in src[i:i + 400]


def test_429_place_rendue_seulement_avant_toute_ecriture(maitre, monkeypatch):
    tmp, _ = maitre
    main.OPERATIONS_OUBLI.clear()

    def boum(*a, **k):
        raise RuntimeError("après écriture")
    monkeypatch.setattr(main.pairs_enroles, "publier", boum)          # échec APRÈS l'écriture de l'état
    with pytest.raises(RuntimeError):
        TestClient(main.app).post("/master-link/oublier", json={"nom": "lgm-ebin", "confirmation": "lgm-ebin"})
    ops = list(main.OPERATIONS_OUBLI.values())
    assert len(ops) == 1 and ops[0]["etat"] == "termine" and ops[0]["restes"]
    main.OPERATIONS_OUBLI.clear()
    r = TestClient(main.app).post("/master-link/oublier", json={"nom": "inconnu", "confirmation": "inconnu"})
    assert r.status_code == 409 and main.OPERATIONS_OUBLI == {}      # refus avant écriture : place rendue


# ── passe 6 (#3362) : la projection pairs-enroles.json est publiée SOUS le verrou ───────────────────────────────────

def test_ajout_et_oubli_entrelaces_projection_sans_le_pair_oublie(maitre, monkeypatch):
    tmp, _ = maitre
    f = tmp / "p2p" / "peers.json"
    d = json.loads(f.read_text())
    for p in d["peers"]:
        p["joined_via"] = "master-link"                 # pairs enrôlés : présents dans la projection
    f.write_text(json.dumps(d))
    reel = main.pairs_enroles.publier
    fini = threading.Event()

    def publier(doc, dossier):
        noms = [p.get("name") for p in (doc.get("peers") or [])]
        if "lgm-ebin" in noms and not getattr(publier, "fait", False):
            publier.fait = True                     # publication de l'AJOUT, encore porteuse de lgm-ebin
            threading.Thread(target=lambda: (TestClient(main.app).post(
                "/master-link/oublier", json={"nom": "lgm-ebin", "confirmation": "lgm-ebin"}), fini.set()),
                daemon=True).start()
            fini.wait(1.0)                          # hors verrou (ancien code) : l'oubli publie avant nous
        return reel(doc, dossier)
    monkeypatch.setattr(main.pairs_enroles, "publier", publier)
    r = TestClient(main.app).post("/peers", json={"address": "192.168.1.88", "fingerprint": "fp", "action": "approve"})
    assert r.status_code == 200
    fini.wait(5)
    proj = (tmp / "public" / "pairs-enroles.json").read_text()
    assert "lgm-ebin" not in proj


def test_maj_json_signale_l_ecriture_et_rappelle_sous_verrou(tmp_path):
    f = tmp_path / "x.json"
    vus = []
    r = oubli.maj_json(f, lambda d: d.update(a=1), defaut={}, apres_ecriture=lambda d: vus.append(oubli.tenu(tmp_path)))
    assert vus == [True] and r is None
    r = oubli.maj_json(f, lambda d: oubli.SANS_ECRITURE, defaut={}, apres_ecriture=lambda d: vus.append("non"))
    assert r is oubli.SANS_ECRITURE and vus == [True]


def test_cles_wg_hors_verrou_et_rejoindre_503_audite():
    src = (ICI / "api" / "main.py").read_text()
    i = src.index("def init_wireguard(")
    corps = src[i:src.index("\ndef _init_wireguard(", i)]
    assert "generate_wg_keypair()" in corps                      # calculées AVANT la section critique
    j = src.index("def _init_wireguard(")
    assert "generate_wg_keypair()" not in src[j:src.index("\n@app", j)]
    k = src.index("async def _rejoindre_maitre(")
    bloc = src[k:k + 4000]
    assert "except HTTPException" in bloc and "_audit_jonction(" in bloc
