# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2569 — maillage automatique : les pairs de synchro ne sont plus seulement ceux de wg_mesh.json.

Sur une étoile (gk1 et gk3 n'ont que gk2 comme pair WireGuard), gk1 et gk3 ne se synchronisaient jamais directement : tout passait par le hub, en deux sauts.
Un nœud inscrit dans le répertoire porte une mesh_ip signée ; elle est joignable (les satellites routent le réseau du maillage par le hub)."""
import json

import api.main as m
from annuaire import mesh_sync

WG = [{"mesh_ip": "10.10.0.1", "name": "master"}]
NOEUDS = [
    {"did": "d1", "boxname": "gk2", "mesh_ip": "10.10.0.1"},     # déjà pair WireGuard : pas de doublon
    {"did": "d2", "boxname": "gk1", "mesh_ip": "10.10.0.3"},     # soi-même : jamais
    {"did": "d3", "boxname": "gk3", "mesh_ip": "10.10.0.5"},     # découvert
    {"did": "d4", "boxname": "c3box", "mesh_ip": "10.10.0.2"},   # découvert
]


def test_les_noeuds_du_repertoire_s_ajoutent_sans_doublon_ni_soi_meme():
    pairs = mesh_sync.completer_pairs(WG, NOEUDS, soi="10.10.0.3")
    assert [p["mesh_ip"] for p in pairs] == ["10.10.0.1", "10.10.0.5", "10.10.0.2"]
    assert pairs[1]["name"] == "gk3" and pairs[0]["name"] == "master"   # le pair WireGuard garde son nom


def test_une_adresse_hors_du_maillage_n_est_jamais_suivie():
    """Une fiche de nœud est auto-déclarée : une mesh_ip hors du réseau du maillage (ou invalide) ne doit pas faire sortir la synchro."""
    hostiles = [{"did": "x", "boxname": "a", "mesh_ip": "192.0.2.9"}, {"did": "y", "boxname": "b", "mesh_ip": "pas-une-ip"},
                {"did": "z", "boxname": "c", "mesh_ip": ""}, {"did": "w", "boxname": "d"}]
    assert mesh_sync.completer_pairs(WG, hostiles, soi="10.10.0.3") == WG


def test_le_reseau_vient_du_fichier_wg_mesh(tmp_path):
    f = tmp_path / "wg.json"
    f.write_text(json.dumps({"network": "10.20.0.0/24", "address": "10.20.0.3/24", "peers": [{"name": "master", "mesh_ip": "10.20.0.1"}]}))
    assert mesh_sync.reseau_maillage(str(f)) == "10.20.0.0/24"
    pairs = mesh_sync.completer_pairs(mesh_sync.read_mesh_peers(str(f)), [{"did": "n", "boxname": "n", "mesh_ip": "10.20.0.7"}], soi="10.20.0.3", reseau="10.20.0.0/24")
    assert [p["mesh_ip"] for p in pairs] == ["10.20.0.1", "10.20.0.7"]
    assert mesh_sync.reseau_maillage(str(tmp_path / "absent.json")) == "10.10.0.0/24"   # défaut, jamais d'exception


def test_le_cycle_de_synchro_tire_aussi_depuis_les_pairs_decouverts(tmp_path, monkeypatch):
    f = tmp_path / "wg.json"
    f.write_text(json.dumps({"network": "10.10.0.0/24", "address": "10.10.0.3/24", "peers": [{"name": "master", "mesh_ip": "10.10.0.1"}]}))
    vus = []
    monkeypatch.setattr(m, "get_journal", lambda: object())
    monkeypatch.setattr(mesh_sync, "noeuds_du_repertoire", lambda j: NOEUDS)
    monkeypatch.setattr(mesh_sync, "sync_once", lambda j, peers, **kw: vus.extend(p["mesh_ip"] for p in peers) or {"peers": len(peers), "ingested": 0, "skipped": 0, "rejected": 0, "errors": 0})
    m._cycle_sync(str(f))
    assert vus == ["10.10.0.1", "10.10.0.5", "10.10.0.2"]
