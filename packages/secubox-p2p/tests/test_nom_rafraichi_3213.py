# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3213 — un pair approuvé qui revient sous un autre nom d'hôte est renommé chez le maître.

Vécu sur gk2 : gk3 a rejoint le maillage le 2026-09-26 sous « secubox-live » (live USB), puis a pris le nom gk3 ;
le maître l'affichait toujours « secubox-live » (requests.json, wg_mesh.json, peers.json)."""
import json

import pytest

from api import main

CLE_GK3 = "G" * 43 + "="
CLE_GK1 = "K" * 43 + "="


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
            {"public_key": CLE_GK3, "allowed_ips": "10.10.0.5/32", "mesh_ip": "10.10.0.5", "name": "secubox-live",
             "fingerprint": "fp-gk3"},
            {"public_key": CLE_GK1, "allowed_ips": "10.10.0.7/32", "mesh_ip": "10.10.0.7", "name": "gk1",
             "fingerprint": "fp-gk1"}]}))
    peers = tmp_path / "peers.json"
    peers.write_text(json.dumps({"peers": [
        {"id": "sb-b3f6", "fingerprint": "fp-gk3", "name": "secubox-live", "mesh_ip": "10.10.0.5"},
        {"id": "sb-gk1", "fingerprint": "fp-gk1", "name": "gk1", "mesh_ip": "10.10.0.7"}]}))
    requetes = [
        {"fingerprint": "fp-gk3", "hostname": "secubox-live", "status": "approved", "mesh_ip": "10.10.0.5",
         "wg_public_key": CLE_GK3, "address": "192.168.1.9"},
        {"fingerprint": "fp-gk1", "hostname": "gk1", "status": "approved", "mesh_ip": "10.10.0.7",
         "wg_public_key": CLE_GK1, "address": "192.168.1.94"}]
    monkeypatch.setattr(main, "WG_MESH_CONFIG", wg)
    monkeypatch.setattr(main, "PEERS_FILE", peers)
    monkeypatch.setattr(main, "get_ml_requests", lambda: requetes)
    monkeypatch.setattr(main, "save_ml_requests", lambda r: requetes.__setitem__(slice(None), r))
    monkeypatch.setattr(main, "get_ml_config", lambda: {"depth": 0, "auto_approve": False})
    monkeypatch.setattr(main, "ml_token_mark_used", lambda *a: None)
    monkeypatch.setattr(main, "ml_token_validate", lambda t: {"valid": True, "token_hash": "h", "auto_approve": False})
    monkeypatch.setenv("SBX_AUDIT", str(tmp_path / "audit.log"))

    def audit():
        f = tmp_path / "audit.log"
        return [json.loads(ligne) for ligne in f.read_text().splitlines()] if f.exists() else []
    return wg, peers, requetes, audit


def _retour(nom, fp="fp-gk3", cle=CLE_GK3):
    return main.ml_join(main.JoinRequest(token="t", fingerprint=fp, hostname=nom, address="192.168.1.9",
                                         wg_public_key=cle, wg_port=51820), _Req())


def _noms(wg, peers, requetes, fp="fp-gk3"):
    return ([p["name"] for p in json.loads(wg.read_text())["peers"] if p.get("fingerprint") == fp],
            [p["name"] for p in json.loads(peers.read_text())["peers"] if p.get("fingerprint") == fp],
            [r["hostname"] for r in requetes if r["fingerprint"] == fp])


def test_le_retour_sous_un_nouveau_nom_renomme_partout(maitre):
    wg, peers, requetes, audit = maitre
    r = _retour("gk3")
    assert r["status"] == "approved" and r["mesh_ip"] == "10.10.0.5"
    assert _noms(wg, peers, requetes) == (["gk3"], ["gk3"], ["gk3"])
    ligne = [x for x in audit() if x["evenement"] == "pair_renomme"][0]
    assert (ligne["ancien_nom"], ligne["nom"], ligne["mesh_ip"]) == ("secubox-live", "gk3", "10.10.0.5")


def test_meme_nom_rien_n_est_audite(maitre):
    wg, peers, requetes, audit = maitre
    _retour("secubox-live")
    assert _noms(wg, peers, requetes) == (["secubox-live"], ["secubox-live"], ["secubox-live"])
    assert not [x for x in audit() if x["evenement"] == "pair_renomme"]


@pytest.mark.parametrize("nom", [None, "", "unknown", "secubox", "secubox-mochabin", "localhost"])
def test_un_nom_par_defaut_ne_remplace_jamais_le_nom_connu(maitre, nom):
    wg, peers, requetes, _ = maitre
    assert _retour(nom)["status"] == "approved"
    assert _noms(wg, peers, requetes) == (["secubox-live"], ["secubox-live"], ["secubox-live"])


@pytest.mark.parametrize("nom", ["GK3", "gk 3", "gk3;rm", "-gk3", "g" * 40, "gk3.secubox.in"])
def test_un_nom_invalide_pour_les_liens_directs_est_ignore(maitre, nom):
    """pairs_directs.valider_pair écarte un pair dont le nom sort de [a-z0-9][a-z0-9-]{0,30} : jamais écrit."""
    wg, peers, requetes, _ = maitre
    assert _retour(nom)["status"] == "approved"
    assert _noms(wg, peers, requetes) == (["secubox-live"], ["secubox-live"], ["secubox-live"])


def test_le_nom_d_un_autre_pair_approuve_n_est_pas_pris(maitre):
    wg, peers, requetes, audit = maitre
    assert _retour("gk1")["status"] == "approved"                  # la jonction n'est pas cassée pour autant
    assert _noms(wg, peers, requetes) == (["secubox-live"], ["secubox-live"], ["secubox-live"])
    assert _noms(wg, peers, requetes, "fp-gk1") == (["gk1"], ["gk1"], ["gk1"])
    refus = [x for x in audit() if x["evenement"] == "renommage_refuse"]
    assert refus and refus[0]["nom"] == "gk1" and refus[0]["raison"] == "nom deja pris"
