# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2885 — la jonction par l'API monte aussi le tunnel wg-mesh du pair.

Essai reel lgm-ebin -> gk2 (2026-10-17) : le pair etait « approved » avec une
adresse mesh, mais `wg: null` — _rejoindre_maitre n'envoyait pas de cle. Seul
le script sbx-mesh-join savait monter le tunnel.
"""
import asyncio
import base64
import json

from api import main, mesh

CLE_A = base64.b64encode(b"a" * 32).decode()
CLE_B = base64.b64encode(b"b" * 32).decode()
OFFRE = {"master_public_key": CLE_B, "master_port": 51822,
         "master_mesh_ip": "10.10.0.1", "address": "10.10.0.7/24",
         "network": "10.10.0.0/24"}


def test_preparer_cree_la_cle_et_garde_celle_qui_existe():
    etat, pub = mesh.preparer_pair({}, lambda: CLE_A, lambda k: CLE_B)
    assert etat["private_key"] == CLE_A and pub == CLE_B and etat["role"] == "peer"
    etat2, _ = mesh.preparer_pair(dict(etat), lambda: 1 / 0, lambda k: CLE_B)
    assert etat2["private_key"] == CLE_A, "une cle existante n'est jamais remplacee"


def test_offre_devient_un_pair_maitre_avec_endpoint():
    etat = mesh.appliquer_offre({"private_key": CLE_A, "peers": []}, OFFRE, "10.64.0.1")
    p = etat["peers"][0]
    assert p["public_key"] == CLE_B and p["endpoint"] == "10.64.0.1:51822"
    assert p["allowed_ips"] == "10.10.0.0/24" and etat["address"] == "10.10.0.7/24"
    assert etat["enabled"] is True and etat["role"] == "peer"
    assert "PersistentKeepalive = 25" in mesh.render_wg_conf(etat)


def test_offre_refusee_si_cle_ou_adresse_invalide():
    import pytest
    for mauvaise in ({**OFFRE, "master_public_key": "x"}, {**OFFRE, "address": "boom\nPostUp=x"},
                     {**OFFRE, "master_port": 99999}, {**OFFRE, "network": "pas-un-reseau"}):
        with pytest.raises(ValueError):
            mesh.appliquer_offre({"private_key": CLE_A, "peers": []}, mauvaise, "10.64.0.1")


def test_rejoindre_envoie_la_cle_et_applique_l_offre(tmp_path, monkeypatch):
    envoye = {}

    class Proc:
        returncode = 0

        async def communicate(self):
            return json.dumps({"status": "approved", "depth": 1, "wg": OFFRE}).encode(), b""

    async def faux(*args, **kw):
        envoye.update(json.loads(args[args.index("-d") + 1]))
        return Proc()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", faux)
    monkeypatch.setattr(main, "WG_MESH_CONFIG", tmp_path / "wg_mesh.json")
    monkeypatch.setattr(main, "P2P_DIR", tmp_path)
    monkeypatch.setattr(main, "_wg_cles", lambda: (lambda: CLE_A, lambda k: CLE_B))
    monkeypatch.setattr(main, "get_ml_config", lambda: {})
    monkeypatch.setattr(main, "save_ml_config", lambda c: None)
    monkeypatch.setattr(main, "get_node_id", lambda: "fp")
    monkeypatch.setattr(main, "get_hostname", lambda: "h")
    monkeypatch.setattr(main, "get_lan_ip", lambda: "192.0.2.9")

    r = asyncio.run(main._rejoindre_maitre("10.64.0.1", "t" * 64))
    assert r["status"] == "approved"
    assert envoye["wg_public_key"] == CLE_B and envoye["wg_port"] == 51822
    etat = json.loads((tmp_path / "wg_mesh.json").read_text())
    assert etat["peers"][0]["endpoint"] == "10.64.0.1:51822"
    assert oct((tmp_path / "wg_mesh.json").stat().st_mode & 0o777) == "0o600"
