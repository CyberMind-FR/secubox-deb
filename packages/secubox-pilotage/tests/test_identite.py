# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Identité d'une box par son adresse dans le tunnel (#3126)."""
import json
import os

from pilotage.identite import Box, box_par_adresse


ENR = {"fingerprint": "f", "joined_via": "master-link"}


def _fichiers(tmp_path, pairs=None):
    peers = tmp_path / "peers.json"
    peers.write_text(json.dumps({"peers": [
        {"id": "sb-1", "name": "gk5", "mesh_ip": "10.10.0.10", **ENR},
        {"id": "sb-2", "name": "c3box", "mesh_ip": "10.10.0.2", **ENR}]}))
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
    peers.write_text(json.dumps({"peers": [{"name": "gk5", "mesh_ip": "10.10.0.10", **ENR}], "bourrage": "x" * (2 << 20)}))
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
    peers.write_text(json.dumps([{"name": "gk5", "mesh_ip": "10.10.0.10", **ENR}]))
    assert box_par_adresse("10.10.0.10", peers, auto).nom == "gk5"


def _ecrire(chemin, doc):
    chemin.write_text(json.dumps(doc))


def test_identite_deux_pairs_de_meme_nom_sont_ecartes(tmp_path, caplog):
    peers, auto = _fichiers(tmp_path)
    _ecrire(peers, {"peers": [
        {"name": "mochabin", "mesh_ip": "10.10.0.20", **ENR}, {"name": "mochabin", "mesh_ip": "10.10.0.21", **ENR},
        {"name": "gk5", "mesh_ip": "10.10.0.10", **ENR}]})
    with caplog.at_level("WARNING"):
        for _ in range(3):
            assert box_par_adresse("10.10.0.20", peers, auto) is None
            assert box_par_adresse("10.10.0.21", peers, auto) is None
            assert box_par_adresse("10.10.0.10", peers, auto).nom == "gk5"
    assert len([r for r in caplog.records if r.name == "pilotage.identite"]) == 1  # une ligne par rechargement


def test_identite_meme_adresse_deux_noms_est_ecartee(tmp_path):
    peers, auto = _fichiers(tmp_path)
    _ecrire(peers, {"peers": [{"name": "gk5", "mesh_ip": "10.10.0.10", **ENR}, {"name": "c3box", "mesh_ip": "10.10.0.10", **ENR},
                              {"name": "c3box", "mesh_ip": "10.10.0.2", **ENR}]})
    assert box_par_adresse("10.10.0.10", peers, auto) is None
    assert box_par_adresse("10.10.0.2", peers, auto).nom == "c3box"  # le nom retombe à une seule adresse valable


def test_identite_deux_pairs_autoload_de_meme_serie_sont_ecartes(tmp_path):
    peers, auto = _fichiers(tmp_path)
    p = {"client": "lgm", "lot": "L", "profil": "lite", "abonnement": "actif"}
    _ecrire(auto, {"version": 1, "pairs": [{**p, "adresse": "10.64.0.9", "serie": "SB-1"}, {**p, "adresse": "10.64.0.12", "serie": "SB-1"},
                                           {**p, "adresse": "10.64.0.13", "serie": "SB-2"}]})
    assert box_par_adresse("10.64.0.9", peers, auto) is None
    assert box_par_adresse("10.64.0.12", peers, auto) is None
    assert box_par_adresse("10.64.0.13", peers, auto).nom == "SB-2"
    # même adresse, deux entrées divergentes (dont une révoquée)
    _ecrire(auto, {"version": 1, "pairs": [{**p, "adresse": "10.64.0.9", "serie": "SB-1"},
                                           {**p, "adresse": "10.64.0.9", "serie": "SB-1", "abonnement": "revoque"}]})
    os.utime(auto, ns=(1, 5_000_000_000))
    assert box_par_adresse("10.64.0.9", peers, auto) is None


def test_identite_maillage_exige_une_entree_enrolee(tmp_path):
    peers, auto = _fichiers(tmp_path)
    _ecrire(peers, {"peers": [
        {"name": "gk5", "mesh_ip": "10.10.0.10"},                                      # mDNS non authentifié
        {"name": "a", "mesh_ip": "10.10.0.11", "fingerprint": "f"},
        {"name": "b", "mesh_ip": "10.10.0.12", "joined_via": "master-link"},
        {"name": "c", "mesh_ip": "10.10.0.13", "fingerprint": "", "joined_via": "x"},
        {"name": "d", "mesh_ip": "10.10.0.14", **ENR}]})
    for a in ("10.10.0.10", "10.10.0.11", "10.10.0.12", "10.10.0.13"):
        assert box_par_adresse(a, peers, auto) is None, a
    assert box_par_adresse("10.10.0.14", peers, auto).nom == "d"


def test_identite_abonnement_inconnu_refuse(tmp_path):
    peers, auto = _fichiers(tmp_path)
    p = {"client": "lgm", "lot": "L", "profil": "lite"}
    _ecrire(auto, {"version": 1, "pairs": [{**p, "adresse": "10.64.0.9", "serie": "A", "abonnement": "inconnu-futur"},
                                           {**p, "adresse": "10.64.0.10", "serie": "B", "abonnement": None},
                                           {**p, "adresse": "10.64.0.11", "serie": "C", "abonnement": "actif"}]})
    assert box_par_adresse("10.64.0.9", peers, auto) is None
    assert box_par_adresse("10.64.0.10", peers, auto) is None
    assert box_par_adresse("10.64.0.11", peers, auto).nom == "C"


def test_identite_adresses_reservees_exclues(tmp_path):
    peers, auto = _fichiers(tmp_path)
    p = {"client": "lgm", "lot": "L", "profil": "lite", "abonnement": "actif"}
    adr = ["10.64.0.1", "10.64.0.0", "10.64.255.255"]
    _ecrire(auto, {"version": 1, "pairs": [{**p, "adresse": a, "serie": f"S{i}"} for i, a in enumerate(adr)]})
    _ecrire(peers, {"peers": [{"name": f"m{i}", "mesh_ip": a, **ENR} for i, a in enumerate(["10.10.0.1", "10.10.0.0", "10.10.0.255"])]})
    for a in adr + ["10.10.0.1", "10.10.0.0", "10.10.0.255"]:
        assert box_par_adresse(a, peers, auto) is None, a


def test_identite_lien_et_fifo_refuses(tmp_path):
    peers, auto = _fichiers(tmp_path)
    lien = tmp_path / "lien.json"
    lien.symlink_to(peers)
    assert box_par_adresse("10.10.0.10", lien, auto) is None
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    assert box_par_adresse("10.10.0.10", fifo, auto) is None
