# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3100 — codes de flash au format automesh (64 hex) et reflash qui remplace la clé du pair."""
import json
import os
import pathlib
import subprocess
import sys

import pytest
from fastapi import HTTPException

from api import automesh, jetons, main, mesh

RACINE = pathlib.Path(__file__).resolve().parents[1]
CLI = RACINE / "scripts" / "sbx-mesh-invite"
ANCIENNE = "A" * 43 + "="
NOUVELLE = "B" * 43 + "="
C3BOX = "C" * 43 + "="


def _cli(tmp_path, *args):
    env = dict(os.environ, SBX_P2P_DIR=str(tmp_path / "p2p"), SBX_AUDIT=str(tmp_path / "audit.log"),
               PYTHONPATH=str(RACINE))
    return subprocess.run([sys.executable, str(CLI), "--adresse", "192.168.1.1", *args],
                          capture_output=True, text=True, env=env, cwd=str(RACINE))


def test_code_au_format_automesh_64_hex(tmp_path):
    r = _cli(tmp_path, "--code", "--nom", "gk9", "--flash", "--json")
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    adresse, jeton = automesh.decoder(d["code"])
    assert adresse == "192.168.1.1" and len(jeton) == 64 and int(jeton, 16) >= 0
    assert d["nom"] == "gk9" and d["expire"]
    jetons_fichier = json.loads((tmp_path / "p2p" / "master-link" / "tokens.json").read_text())
    assert jetons_fichier[0]["nom_prevu"] == "gk9" and jetons_fichier[0]["flash"] is True
    assert jeton not in json.dumps(jetons_fichier)                      # empreinte seule


def test_cli_json_sans_le_jeton_dans_l_audit(tmp_path):
    r = _cli(tmp_path, "--code", "--nom", "gk9", "--json", "--ttl", "120")
    assert r.returncode == 0, r.stderr
    code = json.loads(r.stdout)["code"]
    _, jeton = automesh.decoder(code)
    audit = (tmp_path / "audit.log").read_text()
    ligne = json.loads(audit.splitlines()[-1])
    assert ligne["evenement"] == "code_emis" and ligne["nom"] == "gk9" and ligne["ttl"] == 120
    assert jeton not in audit and code not in audit


# ── côté maître : ml_join ────────────────────────────────────────────────────

class _Client:
    host = "127.0.0.1"


class _Req:
    client = _Client()


@pytest.fixture
def maitre(tmp_path, monkeypatch):
    wg = tmp_path / "wg_mesh.json"
    wg.write_text(json.dumps({
        "private_key": "P" * 43 + "=", "public_key": "M" * 43 + "=", "address": "10.10.0.1/24",
        "listen_port": 51820, "peers": [
            {"public_key": C3BOX, "allowed_ips": "10.10.0.2/32", "mesh_ip": "10.10.0.2", "name": "c3box"},
            {"public_key": ANCIENNE, "allowed_ips": "10.10.0.3/32", "mesh_ip": "10.10.0.3",
             "name": "gk9", "fingerprint": "ancien-fp"}]}))
    peers = tmp_path / "peers.json"
    peers.write_text(json.dumps({"peers": [{"id": "sb-x", "fingerprint": "ancien-fp", "name": "gk9",
                                            "mesh_ip": "10.10.0.3"}]}))
    requetes = [{"fingerprint": "ancien-fp", "hostname": "gk9", "status": "approved",
                 "mesh_ip": "10.10.0.3", "wg_public_key": ANCIENNE, "address": "192.168.1.9"}]
    monkeypatch.setattr(main, "WG_MESH_CONFIG", wg)
    monkeypatch.setattr(main, "PEERS_FILE", peers)
    monkeypatch.setattr(main, "get_ml_requests", lambda: requetes)
    monkeypatch.setattr(main, "save_ml_requests", lambda r: requetes.__setitem__(slice(None), r))
    monkeypatch.setattr(main, "get_ml_config", lambda: {"depth": 0, "auto_approve": False})
    monkeypatch.setattr(main, "ml_token_mark_used", lambda *a: None)
    etat = {"flash": True, "nom": "gk9"}
    monkeypatch.setattr(main, "ml_token_validate", lambda t: {
        "valid": True, "token_hash": "h", "auto_approve": True,
        "flash": etat["flash"], "nom_prevu": etat["nom"]})
    return wg, peers, requetes, etat


def _join(nom="gk9", fp="nouveau-fp", cle=NOUVELLE):
    return main.ml_join(main.JoinRequest(token="t", fingerprint=fp, hostname=nom,
                                         address="192.168.1.9", wg_public_key=cle, wg_port=51822), _Req())


def test_reflash_remplace_la_cle_et_garde_l_adresse(maitre):
    wg, peers, requetes, _ = maitre
    r = _join()
    assert r["status"] == "approved" and r["mesh_ip"] == "10.10.0.3"
    etat = json.loads(wg.read_text())
    cles = [p["public_key"] for p in etat["peers"]]
    assert NOUVELLE in cles and ANCIENNE not in cles and C3BOX in cles
    assert [p for p in etat["peers"] if p["public_key"] == NOUVELLE][0]["mesh_ip"] == "10.10.0.3"
    assert [q["fingerprint"] for q in requetes if q.get("hostname") == "gk9"] == ["nouveau-fp"]
    assert [p["fingerprint"] for p in json.loads(peers.read_text())["peers"]] == ["nouveau-fp"]


def test_doublon_sans_flash_refuse(maitre):
    wg, _, requetes, etat = maitre
    etat["flash"] = False
    avant = wg.read_text()
    with pytest.raises(HTTPException) as e:
        _join()
    assert e.value.status_code == 409 and wg.read_text() == avant


def test_jeton_flash_pour_un_autre_nom_refuse(maitre):
    wg, _, _, etat = maitre
    etat["nom"] = "gk7"
    avant = wg.read_text()
    with pytest.raises(HTTPException) as e:
        _join()                                            # hostname gk9 demandé avec un jeton pour gk7
    assert e.value.status_code == 403 and wg.read_text() == avant
