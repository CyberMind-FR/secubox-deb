# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3335 : « Oublier ce nœud » — retrait d'un nœud obsolète du registre des pairs et de wg-mesh."""
import json
from pathlib import Path

import pytest

from api import oubli

PEERS = {"peers": [
    {"id": "a", "name": "lgm-ebin", "mesh_ip": "10.10.0.7", "fingerprint": "sb-1", "joined_via": "master-link"},
    {"id": "b", "name": "gk4", "mesh_ip": "10.10.0.9", "fingerprint": "sbx-2", "joined_via": "master-link"},
]}
WG = {"enabled": True, "peers": [
    {"name": "lgm-ebin", "public_key": "K" * 43 + "=", "mesh_ip": "10.10.0.7"},
    {"name": "gk4", "public_key": "L" * 43 + "=", "mesh_ip": "10.10.0.9"},
]}


def test_oublier_retire_le_pair_du_registre_et_de_wg_mesh():
    peers, wg, retires = oubli.oublier(PEERS, WG, "lgm-ebin", handshakes={}, now=1000, local="gk2")
    assert [p["name"] for p in peers["peers"]] == ["gk4"]
    assert [p["name"] for p in wg["peers"]] == ["gk4"]
    assert retires == {"registre": 1, "wg": 1}
    assert wg["enabled"] is True                       # le reste de l'état est gardé tel quel


def test_oublier_refuse_le_maitre_le_noeud_local_et_un_nom_invalide():
    for nom in ("gk2", "master", "../x", "", "GK4 ", "a;b"):
        with pytest.raises(oubli.Refus):
            oubli.oublier(PEERS, WG, nom, handshakes={}, now=1000, local="gk2")


def test_oublier_refuse_un_noeud_en_ligne_sauf_force():
    hs = {"L" * 43 + "=": 990}                         # poignée de main il y a 10 s
    with pytest.raises(oubli.Refus, match="en ligne"):
        oubli.oublier(PEERS, WG, "gk4", handshakes=hs, now=1000, local="gk2")
    peers, wg, _ = oubli.oublier(PEERS, WG, "gk4", handshakes=hs, now=1000, local="gk2", force=True)
    assert [p["name"] for p in peers["peers"]] == ["lgm-ebin"]


def test_oublier_un_nom_inconnu_est_refuse():
    with pytest.raises(oubli.Refus, match="inconnu"):
        oubli.oublier(PEERS, WG, "fantome", handshakes={}, now=1000, local="gk2")


def test_la_route_exige_l_administrateur_et_la_confirmation():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text(encoding="utf-8")
    i = src.index('@app.post("/master-link/oublier")')
    bloc = src[i:i + 3200]
    assert "require_jwt" in bloc and "confirmation" in bloc and "_audit_jonction" in bloc


# ── relecture #3341 ──────────────────────────────────────────────────────────────────────────────────────────────────

def test_designation_par_cle_et_nom_ambigu_refuse():
    wg = {"peers": WG["peers"] + [{"name": "gk4", "public_key": "M" * 43 + "=", "mesh_ip": "10.10.0.19"}]}
    with pytest.raises(oubli.Refus, match="ambigu"):
        oubli.oublier(PEERS, wg, "gk4", handshakes={}, now=1000, local="gk2")
    _, wg2, r = oubli.oublier(PEERS, wg, "gk4", handshakes={}, now=1000, local="gk2", cle="M" * 43 + "=")
    assert [p["public_key"] for p in wg2["peers"]] == ["K" * 43 + "=", "L" * 43 + "="] and r["wg"] == 1
    with pytest.raises(oubli.Refus, match="inconnu"):
        oubli.oublier(PEERS, wg, "gk4", handshakes={}, now=1000, local="gk2", cle="Z" * 43 + "=")


def test_sans_mesure_des_poignees_force_exige():
    with pytest.raises(oubli.Refus, match="mesure"):
        oubli.oublier(PEERS, WG, "lgm-ebin", handshakes=None, now=1000, local="gk2")
    oubli.oublier(PEERS, WG, "lgm-ebin", handshakes=None, now=1000, local="gk2", force=True)


def test_le_pair_maitre_est_refuse_par_role_ou_par_ancre():
    wg = {"peers": [{"name": "gk2", "public_key": "A" * 43 + "=", "mesh_ip": "10.10.0.1"}]}
    with pytest.raises(oubli.Refus, match="maître"):
        oubli.oublier({"peers": []}, wg, "gk2", handshakes={}, now=1000, local="gk4", cle_maitre="A" * 43 + "=", force=True)
    wg = {"peers": [{"name": "gk2", "public_key": "A" * 43 + "=", "role": "master"}]}
    with pytest.raises(oubli.Refus, match="maître"):
        oubli.oublier({"peers": []}, wg, "gk2", handshakes={}, now=1000, local="gk4", force=True)


def test_etat_illisible_jamais_reecrit(tmp_path):
    p = tmp_path / "wg_mesh.json"
    p.write_text("{coupé")
    with pytest.raises(oubli.EtatIllisible):
        oubli.lire_strict(p, {"peers": []})
    assert oubli.lire_strict(tmp_path / "absent.json", {"peers": []}) == {"peers": []}


def test_ecriture_atomique_sous_verrou(tmp_path):
    p = tmp_path / "wg_mesh.json"
    with oubli.verrou(tmp_path):
        oubli.ecrire_atomique(p, {"peers": [], "private_key": "x"}, 0o600)
    assert json.loads(p.read_text())["private_key"] == "x" and (p.stat().st_mode & 0o777) == 0o600
    assert not [x for x in tmp_path.iterdir() if x.name.startswith(".") and x.name != ".etat.lock"]


def test_la_route_est_synchrone_et_lit_strictement():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text(encoding="utf-8")
    i = src.index('@app.post("/master-link/oublier")')
    bloc = src[i:i + 2600]
    assert "\ndef ml_oublier(" in bloc and "async def ml_oublier" not in bloc
    assert "oubli.verrou(" in bloc and "lire_strict" in bloc and "503" in bloc and "ecrire_atomique" in bloc
