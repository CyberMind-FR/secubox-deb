# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — secubox-maillage-pairs : l'exécuteur sans privilège des liens directs (module chargé depuis le fichier)."""
import base64
import importlib.machinery
import importlib.util
import json
import os
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from api import mesh

RACINE = Path(__file__).resolve().parents[1]
SCRIPT = RACINE / "sbin" / "secubox-maillage-pairs"

def _cle(c):
    return base64.b64encode(c.encode() * 32).decode()


K_MOI, K_MAITRE, K_A, K_B = _cle("m"), _cle("X"), _cle("A"), _cle("B")


def _charger():
    ld = importlib.machinery.SourceFileLoader("sbx_maillage_pairs", str(SCRIPT))
    spec = importlib.util.spec_from_loader("sbx_maillage_pairs", ld)
    m = importlib.util.module_from_spec(spec)
    ld.exec_module(m)
    return m


def _etat(role="peer"):
    return {"role": role, "private_key": "secret", "public_key": K_MOI, "address": "10.10.0.5/24",
            "listen_port": 51820, "extra": {"garde": 1},
            "peers": [{"public_key": K_MAITRE, "allowed_ips": "10.10.0.0/24", "mesh_ip": "10.10.0.1",
                       "endpoint": "198.51.100.1:51820", "name": "master"}]}


def _pair(nom, cle, ip, ep):
    return {"nom": nom, "mesh_ip": ip, "cle_publique": cle, "endpoint": ep}


class Maitre:
    """Faux maître : renvoie (statut, corps) et compte les requêtes."""
    def __init__(self, statut=200, corps=None, brut=None):
        self.statut, self.requetes = statut, []
        self.corps = brut if brut is not None else json.dumps(corps).encode()
        maitre = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                maitre.requetes.append(self.path)
                self.send_response(maitre.statut)
                self.send_header("Content-Length", str(len(maitre.corps)))
                self.end_headers()
                self.wfile.write(maitre.corps)

            def log_message(self, *a):
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_port

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def env(tmp_path, monkeypatch):
    class E:
        pass
    e = E()
    e.etat, e.ancre = tmp_path / "wg_mesh.json", tmp_path / "ancre.json"
    e.poignees = tmp_path / "hs.json"
    e.audit, e.conf = tmp_path / "audit.log", tmp_path / "p2p.toml"
    e.etat.write_text(json.dumps(_etat()))
    os.chmod(e.etat, 0o640)
    e.ancre.write_text(json.dumps({"cle_publique": K_MAITRE}))
    e.audit.write_text("")
    for var, chemin in (("ETAT", e.etat), ("ANCRE", e.ancre), ("POIGNEES", e.poignees), ("AUDIT", e.audit),
                        ("CONFIG", e.conf)):
        monkeypatch.setenv("SBX_PAIRS_" + var, str(chemin))
    e.poignees.write_text(json.dumps({"written_at": time.time(), "handshakes": {}}))

    def poignees(**par_cle):
        e.poignees.write_text(json.dumps({"written_at": time.time(), "handshakes": par_cle}))
    e.poignees_ecrire = poignees
    e.maitres = []
    monkeypatch.setattr(os, "geteuid", lambda: 1000)     # les tests ne dépendent jamais de l'euid réel

    def maitre(*a, **k):
        m = Maitre(*a, **k)
        e.maitres.append(m)
        monkeypatch.setenv("SBX_PAIRS_MAITRE_URL", m.url)
        return m
    e.maitre = maitre
    yield e
    for m in e.maitres:
        m.close()


LISTE = {"version": 1, "pairs": [_pair("gk3", K_A, "10.10.0.3", "192.168.1.30:51820"),
                                 _pair("gk4", K_B, "10.10.0.4", "192.168.1.40:51820")]}


def _pairs_ecrits(env):
    return json.loads(env.etat.read_text())["peers"]


def _direct(nom, cle, ip, ep, etat_d="actif", depuis=1):
    e = {"public_key": cle, "mesh_ip": ip, "name": nom, "endpoint": ep, "direct": True, "direct_etat": etat_d,
         "direct_depuis": depuis}
    if etat_d == "actif":
        e["allowed_ips"] = ip + "/32"
    return e


def _evenements(env):
    return [json.loads(x) for x in env.audit.read_text().splitlines()]


def test_liste_valide_ajoute_des_sondes_et_audite(env):
    env.maitre(corps=LISTE)
    avant = env.etat.stat()
    assert _charger().synchroniser() == 0
    doc = json.loads(env.etat.read_text())
    directs = [p for p in doc["peers"] if p.get("direct") is True]
    assert {p["name"] for p in directs} == {"gk3", "gk4"}
    assert all(p["direct_etat"] == "sonde" and "allowed_ips" not in p for p in directs)   # aucun trafic capté
    assert doc["extra"] == {"garde": 1} and doc["private_key"] == "secret"
    assert doc["peers"][0]["name"] == "master" and doc["peers"][0]["allowed_ips"] == "10.10.0.0/24"
    apres = env.etat.stat()
    assert stat.S_IMODE(apres.st_mode) == 0o640 and (apres.st_uid, apres.st_gid) == (avant.st_uid, avant.st_gid)
    lignes = [json.loads(x) for x in env.audit.read_text().splitlines()]
    assert [x["evenement"] for x in lignes] == ["pair_direct_ajoute"] * 2
    assert {x["cle"] for x in lignes} == {K_A, K_B} and {x["nom"] for x in lignes} == {"gk3", "gk4"}
    assert {x["etat"] for x in lignes} == {"sonde"}
    assert all("mesh_ip" in x and "token" not in x and "jeton" not in x for x in lignes)


def test_chemin_demande_et_aucun_fichier_temporaire_restant(env):
    m = env.maitre(corps=LISTE)
    _charger().synchroniser()
    assert m.requetes == ["/api/v1/p2p/master-link/pairs"]
    assert sorted(p.name for p in env.etat.parent.glob(".maillage-pairs-*")) == []


def test_etat_inchange_ne_reecrit_pas(env):
    env.maitre(corps=LISTE)
    cli = _charger()
    cli.synchroniser()
    inode = env.etat.stat().st_ino
    mtime = env.etat.stat().st_mtime_ns
    time.sleep(0.01)
    cli.synchroniser()
    assert env.etat.stat().st_ino == inode and env.etat.stat().st_mtime_ns == mtime


@pytest.mark.parametrize("statut,corps,brut", [
    (500, {"version": 1, "pairs": []}, None),
    (404, {"version": 1, "pairs": []}, None),
    (200, None, b"pas du json"),
    (200, {"version": 2, "pairs": []}, None),
    (200, {"version": True, "pairs": []}, None),
    (200, {"version": 1}, None),
    (200, {"version": 1, "pairs": {}}, None),
    (200, [1], None),
    (200, None, b"x" * (300 * 1024)),
])
def test_reponse_anormale_ne_change_rien(env, statut, corps, brut):
    # état de départ avec un direct existant : il doit survivre à une réponse anormale
    doc = _etat()
    doc["peers"].append(_direct("gk3", K_A, "10.10.0.3", "192.168.1.30:51820"))
    env.etat.write_text(json.dumps(doc))
    avant = env.etat.read_bytes()
    env.maitre(statut=statut, corps=corps, brut=brut)
    assert _charger().synchroniser() == 0
    assert env.etat.read_bytes() == avant and env.audit.read_text() == ""


def test_reseau_injoignable_ne_change_rien(env, monkeypatch):
    monkeypatch.setenv("SBX_PAIRS_MAITRE_URL", "http://127.0.0.1:9")
    avant = env.etat.read_bytes()
    assert _charger().synchroniser() == 0
    assert env.etat.read_bytes() == avant


def test_redirection_non_suivie(env):
    cible = env.maitre(corps=LISTE)

    class R(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", cible.url + "/api/v1/p2p/master-link/pairs")
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), R)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    os.environ["SBX_PAIRS_MAITRE_URL"] = "http://127.0.0.1:%d" % srv.server_port
    try:
        avant = env.etat.read_bytes()
        _charger().synchroniser()
        assert env.etat.read_bytes() == avant and cible.requetes == []
    finally:
        srv.shutdown()
        srv.server_close()
        os.environ["SBX_PAIRS_MAITRE_URL"] = cible.url


def test_liste_vide_valide_retire_seulement_les_directs(env):
    doc = _etat()
    doc["peers"].append(_direct("gk3", K_A, "10.10.0.3", "192.168.1.30:51820"))
    doc["peers"].append({"public_key": K_B, "allowed_ips": "10.10.0.4/32", "mesh_ip": "10.10.0.4", "name": "gk4"})
    env.etat.write_text(json.dumps(doc))
    env.maitre(corps={"version": 1, "pairs": []})
    _charger().synchroniser()
    noms = [p["name"] for p in _pairs_ecrits(env)]
    assert noms == ["master", "gk4"]
    lignes = [json.loads(x) for x in env.audit.read_text().splitlines()]
    assert [x["evenement"] for x in lignes] == ["pair_direct_retire"] and lignes[0]["cle"] == K_A


def test_sonde_promue_puis_retrogradee_jamais_retiree(env):
    # remplace l'ancien « retiré et refusé 1 h » (mécanisme supprimé) : sonde -> actif sur poignée -> sonde
    env.maitre(corps={"version": 1, "pairs": [_pair("gk3", K_A, "10.10.0.3", "192.168.1.30:51820")]})
    cli = _charger()
    t0 = time.time()
    cli.synchroniser(t0)
    assert _pairs_ecrits(env)[1]["direct_etat"] == "sonde"
    env.poignees_ecrire(**{K_A: int(t0) + 10})
    cli.synchroniser(t0 + 20)
    p = _pairs_ecrits(env)[1]
    assert p["direct_etat"] == "actif" and p["allowed_ips"] == "10.10.0.3/32"
    cli.synchroniser(t0 + 400)                          # plus de poignée depuis 390 s, promu depuis 380 s
    p = _pairs_ecrits(env)[1]
    assert p["direct_etat"] == "sonde" and "allowed_ips" not in p and p["name"] == "gk3"
    assert [x["evenement"] for x in _evenements(env)] == ["pair_direct_ajoute", "pair_direct_promu",
                                                         "pair_direct_retrograde"]
    assert all(x["cle"] == K_A and x["mesh_ip"] == "10.10.0.3" for x in _evenements(env))
    assert sorted(p.name for p in env.etat.parent.iterdir() if "refus" in p.name) == []


@pytest.mark.parametrize("contenu", ["corrompu", None, "perime"])
def test_sans_mesure_des_poignees_rien_ne_change(env, contenu, capsys):
    doc = _etat()
    doc["peers"].append(_direct("gk3", K_A, "10.10.0.3", "192.168.1.30:51820", depuis=1))          # actif ancien
    doc["peers"].append(_direct("gk4", K_B, "10.10.0.4", "192.168.1.40:51820", etat_d="sonde"))    # sonde
    env.etat.write_text(json.dumps(doc))
    if contenu is None:
        env.poignees.unlink()
    elif contenu == "perime":
        env.poignees.write_text(json.dumps({"written_at": time.time() - 3600, "handshakes": {K_B: time.time()}}))
    else:
        env.poignees.write_text(contenu)
    nouveau = _cle("N")
    env.maitre(corps={"version": 1, "pairs": [_pair("gk3", K_A, "10.10.0.3", "192.168.1.30:51820"),
                                              _pair("gk4", K_B, "10.10.0.4", "192.168.1.40:51820"),
                                              _pair("gk9", nouveau, "10.10.0.9", "192.168.1.90:51820")]})
    avant = env.etat.read_bytes()
    capsys.readouterr()
    assert _charger().synchroniser() == 0
    # ni ajout (gk9), ni rétrogradation (gk3), ni promotion (gk4) : l'état et l'audit sont intacts
    assert env.etat.read_bytes() == avant and env.audit.read_text() == ""
    assert "mesure des poignées" in capsys.readouterr().out


def test_maitre_absent_de_l_etat(env):
    doc = _etat()
    doc["peers"] = []
    env.etat.write_text(json.dumps(doc))
    m = env.maitre(corps=LISTE)
    _charger().synchroniser()
    assert m.requetes == [] and _pairs_ecrits(env) == []


def test_cle_du_maitre_differente_de_l_ancre_aucune_requete(env):
    env.ancre.write_text(json.dumps({"cle_publique": _cle("Z")}))
    m = env.maitre(corps=LISTE)
    avant = env.etat.read_bytes()
    _charger().synchroniser()
    assert m.requetes == [] and env.etat.read_bytes() == avant


def test_sans_ancre_rien(env):
    env.ancre.unlink()
    m = env.maitre(corps=LISTE)
    _charger().synchroniser()
    assert m.requetes == []


def test_role_maitre_rien(env):
    env.etat.write_text(json.dumps(_etat("master")))
    m = env.maitre(corps=LISTE)
    _charger().synchroniser()
    assert m.requetes == []


@pytest.mark.parametrize("contenu,attendu_requetes", [("[maillage]\nliens_directs = false\n", 0),
                                                       ("[maillage]\nliens_directs = true\n", 1),
                                                       ("pas = du toml [", 1), (None, 1)])
def test_reglage_liens_directs(env, contenu, attendu_requetes):
    if contenu is not None:
        env.conf.write_text(contenu)
    m = env.maitre(corps=LISTE)
    _charger().synchroniser()
    assert len(m.requetes) == attendu_requetes


def test_desactive_retire_les_directs_de_cette_box(env, capsys):
    env.conf.write_text("[maillage]\nliens_directs = false\n")
    doc = _etat()
    doc["peers"].append(_direct("gk3", K_A, "10.10.0.3", "192.168.1.30:51820"))
    doc["peers"].append(_direct("gk4", K_B, "10.10.0.4", "192.168.1.40:51820", etat_d="sonde"))
    env.etat.write_text(json.dumps(doc))
    m = env.maitre(corps=LISTE)
    cli = _charger()
    assert cli.synchroniser() == 0
    assert m.requetes == [] and [p["name"] for p in _pairs_ecrits(env)] == ["master"]
    assert sorted((x["evenement"], x["nom"]) for x in _evenements(env)) == [("pair_direct_retire", "gk3"),
                                                                           ("pair_direct_retire", "gk4")]
    assert json.loads(env.etat.read_text())["extra"] == {"garde": 1}
    inode = env.etat.stat().st_ino
    capsys.readouterr()
    assert cli.synchroniser() == 0 and env.etat.stat().st_ino == inode          # plus rien à retirer : pas réécrit
    assert "désactivés" in capsys.readouterr().out


def test_etat_lien_symbolique_refuse(env, tmp_path):
    reel = tmp_path / "reel.json"
    reel.write_text(env.etat.read_text())
    env.etat.unlink()
    env.etat.symlink_to(reel)
    m = env.maitre(corps=LISTE)
    avant = reel.read_bytes()
    _charger().synchroniser()
    assert m.requetes == [] and reel.read_bytes() == avant


def test_main_sans_privilege_et_sortie_inconnue(env, monkeypatch):
    cli = _charger()
    env.maitre(corps=LISTE)
    assert cli.main(["synchroniser"]) == 0 and len(_pairs_ecrits(env)) == 3
    assert cli.main(["inconnu"]) == 2


def test_ecriture_refusee_code_1_et_etat_intact(env, monkeypatch, capsys):
    cli = _charger()
    env.maitre(corps=LISTE)
    avant = env.etat.read_bytes()

    def refus(*a, **k):
        raise PermissionError(13, "refusé")
    monkeypatch.setattr(cli.tempfile, "mkstemp", refus)
    assert cli.main(["synchroniser"]) == 1
    assert "refusée" in capsys.readouterr().err and env.etat.read_bytes() == avant


def test_synchroniser_refuse_en_root(env, monkeypatch, capsys):
    cli = _charger()
    m = env.maitre(corps=LISTE)
    avant = env.etat.read_bytes()
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert cli.main(["synchroniser"]) != 0 and cli.main([]) != 0
    assert "sudo -u secubox" in capsys.readouterr().err
    assert m.requetes == [] and env.etat.read_bytes() == avant
    assert cli.main(["etat"]) == 0       # lecture seule : permise


def test_pas_de_chown_ni_chmod_par_chemin():
    src = SCRIPT.read_text()
    assert "os.chown" not in src and "os.chmod" not in src and "fchmod" in src


def test_mode_pris_sur_le_descripteur_lu(env, tmp_path):
    cli = _charger()
    cible = tmp_path / "autre.json"
    cible.write_text("{}")
    os.chmod(cible, 0o600)
    original = cli.os.open
    appels = []

    def open_puis_echange(chemin, *a, **k):
        fd = original(chemin, *a, **k)
        if str(chemin) == str(env.etat) and not appels:
            appels.append(1)
            env.etat.unlink()               # échange après l'ouverture : lien vers une autre cible
            env.etat.symlink_to(cible)
        return fd
    cli.os.open = open_puis_echange
    try:
        doc, st = cli._lire_json_stat(str(env.etat))
    finally:
        cli.os.open = original
    assert doc["role"] == "peer" and stat.S_IMODE(st.st_mode) == 0o640


def test_audit_seulement_pour_les_liens_reellement_ajoutes(env):
    cli = _charger()
    env.maitre(corps=LISTE)
    reel = cli.pairs_directs.appliquer
    cli.pairs_directs.appliquer = lambda etat, calcul, t: reel(etat, dict(calcul, ajouts=calcul["ajouts"][:1]), t)
    try:
        cli.synchroniser()
    finally:
        cli.pairs_directs.appliquer = reel
    lignes = [json.loads(x) for x in env.audit.read_text().splitlines()]
    assert [x["cle"] for x in lignes] == [K_A]


def test_peers_null_sans_exception(env):
    doc = _etat()
    doc["peers"] = None
    env.etat.write_text(json.dumps(doc))
    env.maitre(corps=LISTE)
    cli = _charger()
    assert cli.synchroniser() == 0 and cli.etat_json()["liens_directs"] == []


def test_sous_commande_etat_lecture_seule(env, monkeypatch, capsys):
    env.maitre(corps=LISTE)
    cli = _charger()
    cli.synchroniser()
    avant = env.etat.read_bytes()
    capsys.readouterr()
    assert cli.main(["etat"]) == 0
    sortie = json.loads(capsys.readouterr().out)
    assert {p["name"] for p in sortie["liens_directs"]} == {"gk3", "gk4"} and sortie["actif"] is True
    assert {p["direct_etat"] for p in sortie["liens_directs"]} == {"sonde"}
    assert sortie["sondes"] == 2 and sortie["actifs"] == 0 and "refuses" not in sortie
    assert env.etat.read_bytes() == avant


def test_rendu_wg_conf_sonde_puis_actif(env):
    env.maitre(corps=LISTE)
    cli = _charger()
    cli.synchroniser()
    conf = mesh.render_wg_conf(json.loads(env.etat.read_text()))
    # sondes : clé, endpoint, keepalive, AUCUNE AllowedIPs ; le maître garde seul le /24
    assert "Endpoint = 192.168.1.30:51820" in conf and conf.count("PersistentKeepalive = 25") == 3
    assert conf.count("AllowedIPs") == 1 and "AllowedIPs = 10.10.0.0/24" in conf
    env.poignees_ecrire(**{K_A: int(time.time())})
    cli.synchroniser()
    conf = mesh.render_wg_conf(json.loads(env.etat.read_text()))
    assert "AllowedIPs = 10.10.0.3/32" in conf and "10.10.0.4/32" not in conf and conf.count("AllowedIPs") == 2


def test_conditionnement():
    svc = (RACINE / "systemd" / "secubox-maillage-pairs.service").read_text()
    assert "Type=oneshot" in svc and "ExecStart=/usr/sbin/secubox-maillage-pairs synchroniser" in svc
    assert "After=wg-quick@wg-mesh.service" in svc and "TimeoutStartSec=2min" in svc
    for d in ("User=secubox", "Group=secubox", "NoNewPrivileges=yes", "ProtectSystem=strict",
              "ReadWritePaths=/var/lib/secubox/p2p /var/log/secubox", "ProtectHome=yes", "PrivateTmp=yes",
              "RestrictAddressFamilies=AF_INET AF_UNIX", "IPAddressDeny=any", "IPAddressAllow=10.10.0.0/24 localhost"):
        assert d in svc
    tim = (RACINE / "systemd" / "secubox-maillage-pairs.timer").read_text()
    for ligne in ("OnBootSec=3min", "OnActiveSec=3min", "OnUnitActiveSec=5min", "RandomizedDelaySec=30s",
                  "Persistent=true"):
        assert ligne in tim
    rules = (RACINE / "debian" / "rules").read_text()
    assert "sbin/secubox-maillage-pairs" in rules and "secubox-maillage-pairs.timer" in rules
    assert "secubox-maillage-pairs.service" in rules
    post = (RACINE / "debian" / "postinst").read_text()
    assert "systemctl enable secubox-maillage-pairs.timer" in post
    assert "systemctl start secubox-maillage-pairs.timer" in post
    assert os.access(SCRIPT, os.X_OK) and SCRIPT.read_text().startswith("#!/usr/bin/env python3")
