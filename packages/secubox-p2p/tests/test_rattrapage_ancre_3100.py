# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100 — sbx-mesh-ancre rattraper : ancre posée depuis le tunnel existant, sinon rien."""
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
SCRIPT = PKG / "scripts" / "sbx-mesh-ancre"
CLE_M = base64.b64encode(b"m" * 32).decode()
CLE_P = base64.b64encode(b"p" * 32).decode()
CLE_Q = base64.b64encode(b"q" * 32).decode()


def _pair(cle, endpoint, allowed):
    return "\t".join([cle, "(none)", endpoint, allowed, "1700000000", "1", "2", "25"])


def _lancer(tmp_path, pairs, role="satellite", ancre_existante=None, dump=True):
    d = tmp_path / "p2p"
    d.mkdir()
    (d / "wg_mesh.json").write_text(json.dumps({
        "role": role, "network": "10.10.0.0/24",
        "peers": [{"public_key": CLE_M, "name": "gk2", "mesh_ip": "10.10.0.1", "allowed_ips": "10.10.0.0/24"}]}))
    ancre = tmp_path / "ancre.json"
    if ancre_existante:
        ancre.write_text(json.dumps(ancre_existante))
    audit = tmp_path / "audit.log"
    f = tmp_path / "dump"
    f.write_text("\t".join(["priv", "pub", "51822", "off"]) + "\n" + "\n".join(pairs) + ("\n" if pairs else ""))
    env = dict(os.environ, SBX_P2P_DIR=str(d), SBX_P2P_LIB=str(PKG), SBX_ANCRE=str(ancre), SBX_AUDIT=str(audit))
    args = [sys.executable, str(SCRIPT), "rattraper"] + (["--dump", str(f)] if dump else [])
    r = subprocess.run(args, env=env, capture_output=True, text=True)
    return r, ancre, audit


def test_un_seul_pair_maitre_ancre_ecrite(tmp_path):
    r, ancre, audit = _lancer(tmp_path, [_pair(CLE_M, "192.168.1.200:51822", "10.10.0.0/24"),
                                         _pair(CLE_P, "(none)", "10.10.0.5/32")])
    assert r.returncode == 0, r.stderr
    a = json.loads(ancre.read_text())
    assert a["cle_publique"] == CLE_M and a["adresse"] == "192.168.1.200" and a["nom"] == "gk2"
    assert len(a["empreinte"]) == 16
    assert "ancre_rattrapee" in audit.read_text()


def test_deux_pairs_reseau_rien_ecrit(tmp_path):
    r, ancre, _ = _lancer(tmp_path, [_pair(CLE_M, "192.168.1.200:51822", "10.10.0.0/24"),
                                     _pair(CLE_Q, "192.168.1.9:51822", "10.10.0.0/24")])
    assert r.returncode == 0 and not ancre.exists()


def test_role_maitre_rien_ecrit(tmp_path):
    r, ancre, _ = _lancer(tmp_path, [_pair(CLE_M, "192.168.1.200:51822", "10.10.0.0/24")], role="master")
    assert r.returncode == 0 and not ancre.exists()


def test_ancre_existante_jamais_ecrasee(tmp_path):
    ex = {"cle_publique": CLE_Q, "adresse": "1.2.3.4", "nom": "autre", "empreinte": "x"}
    r, ancre, audit = _lancer(tmp_path, [_pair(CLE_M, "192.168.1.200:51822", "10.10.0.0/24")], ancre_existante=ex)
    assert r.returncode == 0 and json.loads(ancre.read_text()) == ex
    assert not audit.exists()


def test_sans_tunnel_rien_ecrit(tmp_path):
    r, ancre, _ = _lancer(tmp_path, [])
    assert r.returncode == 0 and not ancre.exists()
