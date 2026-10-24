# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — contrat « aller-retour » des liens directs, de bout en bout, sans liste écrite à la main :

état du maître (pairs vivants / périmés / invalides) -> route GET /master-link/pairs (vraie application FastAPI,
liste_publiable, clés nom/cle_publique) -> JSON sur HTTP local -> CLI secubox-maillage-pairs (adaptateur
_au_format_de_l_etat) -> calculer -> appliquer -> wg_mesh.json du pair.

Le serveur HTTP local joue nginx : il retire le préfixe /api/v1/p2p et pose l'en-tête X-SecuBox-Pair (le jeton)."""
import base64
import importlib.machinery
import importlib.util
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import main
from api import pairs_directs as pd

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-maillage-pairs"
JETON = "5e" * 32


def _cle(c):
    return base64.b64encode(c.encode() * 32).decode()


K_MAITRE, K_MOI = _cle("X"), _cle("m")
K_VIF1, K_VIF2, K_PERIME, K_SANS, K_MAUVAIS = _cle("1"), _cle("2"), _cle("3"), _cle("4"), _cle("5")


def _entree_maitre(cle, n, nom, endpoint=None):
    """Vue du MAÎTRE sur un pair (clés de wg_mesh.json côté maître : name/public_key/allowed_ips /32)."""
    return {"public_key": cle, "allowed_ips": f"10.10.0.{n}/32", "mesh_ip": f"10.10.0.{n}", "name": nom,
            "endpoint": endpoint or f"192.168.1.{n}:51820"}


def _etat_du_maitre():
    return {"role": "master", "private_key": "SECRET-MAITRE", "public_key": K_MAITRE, "address": "10.10.0.1/24",
            "peers": [_entree_maitre(K_MOI, 5, "moi"),                     # le pair lui-même : jamais un lien
                      _entree_maitre(K_VIF1, 7, "vif-un"),
                      _entree_maitre(K_VIF2, 9, "vif-deux"),
                      _entree_maitre(K_PERIME, 11, "perime"),              # poignée de plus de 10 min
                      _entree_maitre(K_SANS, 12, "sans-poignee"),
                      _entree_maitre(K_MAUVAIS, 13, "public", endpoint="203.0.113.13:51820")]}   # endpoint public


def _poignees_du_maitre(t):
    return {K_MOI: t - 10, K_VIF1: t - 20, K_VIF2: t - 300, K_PERIME: t - 700, K_MAUVAIS: t - 5}


def _etat_du_pair(*directs):
    return {"role": "peer", "private_key": "secret", "public_key": K_MOI, "address": "10.10.0.5/24",
            "listen_port": 51820,
            "peers": [{"public_key": K_MAITRE, "allowed_ips": "10.10.0.0/24", "mesh_ip": "10.10.0.1",
                       "endpoint": "198.51.100.1:51820", "name": "master"}, *directs]}


def _charger_cli():
    ld = importlib.machinery.SourceFileLoader("sbx_maillage_pairs_contrat", str(SCRIPT))
    spec = importlib.util.spec_from_loader("sbx_maillage_pairs_contrat", ld)
    m = importlib.util.module_from_spec(spec)
    ld.exec_module(m)
    return m


@pytest.fixture
def banc(tmp_path, monkeypatch):
    """Un maître (vraie application) derrière un faux nginx en HTTP local, et l'environnement d'un pair."""
    t = time.time()
    jeton = tmp_path / "pair.token"
    jeton.write_text(JETON + "\n")
    monkeypatch.setenv("SBX_P2P_PAIR_TOKEN", str(jeton))
    monkeypatch.setenv("SECUBOX_TABLEAU_DE_BORD", "0")
    monkeypatch.setattr(main, "get_wg_mesh_config", _etat_du_maitre)
    mesure = {"poignees": _poignees_du_maitre(t)}
    monkeypatch.setattr(main.mesh, "load_handshakes", lambda *a, **k: mesure["poignees"])
    application = TestClient(main.app)
    requetes = []

    class Nginx(BaseHTTPRequestHandler):
        def do_GET(self):
            chemin = self.path.removeprefix("/api/v1/p2p")
            r = application.get(chemin, headers={"X-SecuBox-Pair": JETON})
            requetes.append((self.path, r.status_code))
            self.send_response(r.status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(r.content)))
            self.end_headers()
            self.wfile.write(r.content)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), Nginx)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    class B:
        pass
    b = B()
    b.t, b.mesure, b.requetes = t, mesure, requetes
    b.etat, b.ancre, b.poignees = tmp_path / "wg_mesh.json", tmp_path / "ancre.json", tmp_path / "hs.json"
    b.audit = tmp_path / "audit.log"
    b.etat.write_text(json.dumps(_etat_du_pair()))
    os.chmod(b.etat, 0o640)
    b.ancre.write_text(json.dumps({"cle_publique": K_MAITRE}))
    b.poignees.write_text(json.dumps({"written_at": t, "handshakes": {}}))
    for var, chemin in (("ETAT", b.etat), ("ANCRE", b.ancre), ("POIGNEES", b.poignees), ("AUDIT", b.audit),
                        ("CONFIG", tmp_path / "p2p.toml")):
        monkeypatch.setenv("SBX_PAIRS_" + var, str(chemin))
    monkeypatch.setenv("SBX_PAIRS_MAITRE_URL", "http://127.0.0.1:%d" % srv.server_port)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    yield b
    srv.shutdown()
    srv.server_close()


def _directs(b):
    return [p for p in json.loads(b.etat.read_text())["peers"] if p.get("direct") is True]


def test_aller_retour_maitre_vers_pair_donne_des_sondes_pour_les_seuls_vivants_valides(banc):
    cli = _charger_cli()
    assert cli.synchroniser(banc.t) == 0
    assert banc.requetes == [("/api/v1/p2p/master-link/pairs", 200)]
    directs = _directs(banc)
    # vivants ET valides, sauf soi-même ; ni périmé, ni sans poignée, ni endpoint public
    assert directs == [
        {"public_key": K_VIF1, "mesh_ip": "10.10.0.7", "name": "vif-un", "endpoint": "192.168.1.7:51820",
         "direct": True, "direct_etat": "sonde", "direct_depuis": int(banc.t)},
        {"public_key": K_VIF2, "mesh_ip": "10.10.0.9", "name": "vif-deux", "endpoint": "192.168.1.9:51820",
         "direct": True, "direct_etat": "sonde", "direct_depuis": int(banc.t)},
    ]
    assert "SECRET-MAITRE" not in banc.etat.read_text()
    # la même liste, côté pur, donne la même décision (aucune divergence de vocabulaire nom/name)
    publiee = json.loads(json.dumps({"version": 1, "pairs": pd.liste_publiable(
        _etat_du_maitre(), _poignees_du_maitre(banc.t), banc.t)}))
    adaptee = [cli._au_format_de_l_etat(p) for p in publiee["pairs"]]
    assert {p["public_key"] for p in adaptee} == {K_MOI, K_VIF1, K_VIF2}
    assert pd.calculer(json.loads(banc.etat.read_text()), adaptee, {}, banc.t + 1)["ajouts"] == []
    # puis la poignée de main avec vif-un arrive : promotion par le même chemin
    banc.poignees.write_text(json.dumps({"written_at": time.time(), "handshakes": {K_VIF1: int(banc.t) + 30}}))
    assert cli.synchroniser(banc.t + 60) == 0
    etats = {p["name"]: (p["direct_etat"], p.get("allowed_ips")) for p in _directs(banc)}
    assert etats == {"vif-un": ("actif", "10.10.0.7/32"), "vif-deux": ("sonde", None)}


def test_mesure_du_maitre_absente_route_503_et_pair_inchange(banc):
    # F3 : une mesure périmée ou absente côté maître n'est PAS une liste vide valide
    banc.etat.write_text(json.dumps(_etat_du_pair(
        {"public_key": K_VIF1, "allowed_ips": "10.10.0.7/32", "mesh_ip": "10.10.0.7", "name": "vif-un",
         "endpoint": "192.168.1.7:51820", "direct": True, "direct_etat": "actif", "direct_depuis": 1},
        {"public_key": K_VIF2, "mesh_ip": "10.10.0.9", "name": "vif-deux", "endpoint": "192.168.1.9:51820",
         "direct": True, "direct_etat": "sonde", "direct_depuis": 1})))
    avant = banc.etat.read_bytes()
    banc.mesure["poignees"] = None
    assert _charger_cli().synchroniser(banc.t) == 0
    assert banc.requetes == [("/api/v1/p2p/master-link/pairs", 503)]
    assert banc.etat.read_bytes() == avant and not banc.audit.exists()
