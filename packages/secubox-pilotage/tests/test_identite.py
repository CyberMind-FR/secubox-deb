# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Identité d'une box par son adresse dans le tunnel (#3126)."""
import json
import os

from pilotage.identite import Box, box_par_adresse


def _fichiers(tmp_path, pairs=None):
    peers = tmp_path / "peers.json"
    peers.write_text(json.dumps({"peers": [
        {"id": "sb-1", "name": "gk5", "mesh_ip": "10.10.0.10"},
        {"id": "sb-2", "name": "c3box", "mesh_ip": "10.10.0.2"}]}))
    auto = tmp_path / "pairs-publics.json"
    auto.write_text(json.dumps({"version": 1, "pairs": pairs if pairs is not None else [
        {"adresse": "10.64.0.9", "client": "lgm", "lot": "L1", "serie": "", "profil": "lite", "abonnement": "actif"},
        {"adresse": "10.64.0.10", "client": "lgm", "lot": "L1", "serie": "SB-0042", "profil": "lite", "abonnement": "suspendu"},
        {"adresse": "10.64.0.11", "client": "vieux", "lot": "L0", "serie": "", "profil": "lite", "abonnement": "echu"},
        {"adresse": "10.64.0.99", "client": "ex", "lot": "L1", "serie": "", "profil": "lite", "abonnement": "revoque"}]}))
    return peers, auto


def test_identite_maillage_et_autoload(tmp_path):
    peers, auto = _fichiers(tmp_path)
    b = box_par_adresse("10.10.0.10", peers, auto)
    assert b == Box("gk5", "10.10.0.10", "maillage", None, None)
    b = box_par_adresse("10.64.0.9", peers, auto)
    assert (b.reseau, b.client, b.nom, b.abonnement) == ("autoload", "lgm", "lgm-10.64.0.9", "actif")
    assert box_par_adresse("10.64.0.10", peers, auto).nom == "SB-0042"
    assert box_par_adresse("10.64.0.10", peers, auto).abonnement == "suspendu"
    assert box_par_adresse("10.64.0.11", peers, auto).abonnement == "echu"
    assert box_par_adresse("10.64.0.99", peers, auto) is None


def test_identite_plages_strictes_et_adresses_invalides(tmp_path):
    peers, auto = _fichiers(tmp_path)
    for a in ("10.10.0.200", "10.10.1.10", "10.11.0.10", "192.168.1.10", "127.0.0.1", "10.64.9.9",
              "", "abc", "10.10.0.10/32", " 10.10.0.10", "::ffff:10.10.0.10", "fe80::1", "10.10.0.010"):
        assert box_par_adresse(a, peers, auto) is None, a


def test_identite_ferme_par_defaut(tmp_path):
    peers, auto = _fichiers(tmp_path)
    absent = tmp_path / "rien.json"
    assert box_par_adresse("10.10.0.10", absent, auto) is None
    assert box_par_adresse("10.64.0.9", peers, absent) is None
    peers.write_text("{pas du json")
    auto.write_text("[1, 2")
    assert box_par_adresse("10.10.0.10", peers, auto) is None
    assert box_par_adresse("10.64.0.9", peers, auto) is None
    peers.write_text(json.dumps({"peers": "n importe quoi"}))
    assert box_par_adresse("10.10.0.10", peers, auto) is None
    peers.write_text(json.dumps({"peers": [42, {"name": 3, "mesh_ip": "10.10.0.10"}, {"name": "", "mesh_ip": "10.10.0.10"}]}))
    assert box_par_adresse("10.10.0.10", peers, auto) is None


def test_identite_lecture_bornee(tmp_path):
    peers, auto = _fichiers(tmp_path)
    peers.write_text(json.dumps({"peers": [{"name": "gk5", "mesh_ip": "10.10.0.10"}], "bourrage": "x" * (2 << 20)}))
    assert box_par_adresse("10.10.0.10", peers, auto) is None


def test_identite_recharge_au_changement(tmp_path):
    peers, auto = _fichiers(tmp_path)
    assert box_par_adresse("10.64.0.9", peers, auto).abonnement == "actif"
    auto.write_text(json.dumps({"version": 1, "pairs": [
        {"adresse": "10.64.0.9", "client": "lgm", "lot": "L1", "serie": "", "profil": "lite", "abonnement": "revoque"}]}))
    os.utime(auto, ns=(1, 2_000_000_000))  # date différente quoi qu'il arrive
    assert box_par_adresse("10.64.0.9", peers, auto) is None
    # une box retirée du maillage disparaît aussi
    peers.write_text(json.dumps({"peers": []}))
    os.utime(peers, ns=(1, 3_000_000_000))
    assert box_par_adresse("10.10.0.10", peers, auto) is None


def test_identite_accepte_aussi_une_liste_nue(tmp_path):
    peers, auto = _fichiers(tmp_path)
    peers.write_text(json.dumps([{"name": "gk5", "mesh_ip": "10.10.0.10"}]))
    assert box_par_adresse("10.10.0.10", peers, auto).nom == "gk5"
