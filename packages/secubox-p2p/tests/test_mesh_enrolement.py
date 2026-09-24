# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""L'enrôlement MirrorNet monte un tunnel, et le statut le mesure (#1360).

CE QUE CES TESTS GARDENT. Test de bout en bout du 2026-09-24, VM VirtualBox
contre gk2 : `sbx-mesh-join` affichait « SUCCESS: Joined mesh network! », le
maître comptait le pair approuvé — et AUCUN tunnel n'existait. La requête ne
portait pas de clé WireGuard, et l'approbation écrivait dans le registre
hérité, jamais dans `wg_mesh.json`. En parallèle, l'API annonçait deux pairs
« en ligne » qui n'avaient jamais échangé un paquet.

Les états reproduits ici sont ceux relevés sur gk2, collision comprise.
"""
import json
import subprocess

import pytest
from fastapi import HTTPException

from api import mesh

# Clés WireGuard réelles (générées pour les tests, sans valeur ailleurs).
def _cle():
    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True).stdout.strip()
    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True).stdout.strip()
    return priv, pub

# L'état de gk2 au moment du test : c3box (.2) et amd64 (.3) configurés.
C3BOX = "L9/oahRdcSOmIopWFj8OWYy9iBTFB1Hx068ORZi4Bmo="
AMD64 = "j6ZWCGeYoyNCwDLPSH4+bvT1SsTdeCsjL0deS3h1Fio="


def etat_gk2(priv):
    return {
        "address": "10.10.0.1/24", "private_key": priv, "listen_port": 51822,
        "network": "10.10.0.0/24",
        "peers": [
            {"name": "c3box", "public_key": C3BOX, "allowed_ips": "10.10.0.2/32",
             "mesh_ip": "10.10.0.2", "endpoint": "192.168.1.94:51822"},
            {"name": "amd64", "public_key": AMD64, "allowed_ips": "10.10.0.3/32",
             "mesh_ip": "10.10.0.3"},
        ],
    }


# ── La clé ────────────────────────────────────────────────────────────────────

def test_une_vraie_cle_est_acceptee():
    assert mesh.valid_wg_key(_cle()[1])


@pytest.mark.parametrize("mauvaise", [
    None, "", "abc", C3BOX[:-1],
    # Une « clé » qui tenterait de sortir de sa ligne dans le fichier rendu :
    "L9/oahRdcSOmIopWFj8OWYy9iBT\nPostUp=id>/tmp/x#=",
])
def test_une_cle_invalide_est_refusee(mauvaise):
    assert not mesh.valid_wg_key(mauvaise)


def test_le_rendu_refuse_une_valeur_multiligne():
    """wg-quick lit ce fichier EN ROOT et exécute ses PostUp : un saut de ligne
    dans un endpoint serait une commande. On refuse, on ne nettoie pas."""
    priv, _ = _cle()
    st = etat_gk2(priv)
    st["peers"][0]["endpoint"] = "192.168.1.94:51822\nPostUp = id > /tmp/pwn"
    with pytest.raises(ValueError):
        mesh.render_wg_conf(st)


# ── L'allocation ─────────────────────────────────────────────────────────────

def test_l_allocation_voit_les_pairs_wireguard():
    """LA COLLISION RÉELLE. L'ancien allocateur ne regardait que peers.json :
    la VM de test y a reçu 10.10.0.2, l'adresse de c3box."""
    priv, _ = _cle()
    legacy = [{"name": "secubox-vm-x64", "mesh_ip": "10.10.0.2"}]
    taken = mesh.taken_mesh_ips(etat_gk2(priv), legacy, [])
    ip = mesh.allocate_mesh_ip("10.10.0.0/24", taken)
    assert ip == "10.10.0.4"


def test_une_demande_en_attente_reserve_son_adresse():
    priv, _ = _cle()
    reqs = [{"mesh_ip": "10.10.0.4", "status": "pending"}]
    taken = mesh.taken_mesh_ips(etat_gk2(priv), [], reqs)
    assert mesh.allocate_mesh_ip("10.10.0.0/24", taken) == "10.10.0.5"


# ── L'inscription au transport ───────────────────────────────────────────────

def test_un_reenrolement_remplace_au_lieu_d_empiler():
    priv, pub1 = _cle()
    _, pub2 = _cle()
    st = etat_gk2(priv)
    mesh.upsert_mesh_peer(st, {"public_key": pub1, "mesh_ip": "10.10.0.4",
                               "allowed_ips": "10.10.0.4/32", "fingerprint": "vm"})
    mesh.upsert_mesh_peer(st, {"public_key": pub2, "mesh_ip": "10.10.0.4",
                               "allowed_ips": "10.10.0.4/32", "fingerprint": "vm"})
    vm = [p for p in st["peers"] if p.get("fingerprint") == "vm"]
    assert len(vm) == 1 and vm[0]["public_key"] == pub2


def test_une_adresse_tenue_par_une_autre_cle_est_refusee():
    """WireGuard déplacerait la route EN SILENCE vers le dernier arrivé."""
    priv, pub = _cle()
    with pytest.raises(ValueError):
        mesh.upsert_mesh_peer(etat_gk2(priv), {"public_key": pub, "mesh_ip": "10.10.0.2",
                                               "allowed_ips": "10.10.0.2/32"})


# ── La vivacité ──────────────────────────────────────────────────────────────

NOW = 1_800_000_000


def test_sans_mesure_le_statut_est_inconnu_pas_en_ligne():
    assert mesh.peer_liveness(None, C3BOX, NOW) == "unknown"


def test_jamais_de_poignee_de_main_vaut_hors_ligne():
    """c3box : 16,3 Mo envoyés, 0 reçu, jamais de poignée de main."""
    assert mesh.peer_liveness({C3BOX: 0}, C3BOX, NOW) == "offline"


def test_une_poignee_de_main_recente_vaut_en_ligne():
    assert mesh.peer_liveness({C3BOX: NOW - 17}, C3BOX, NOW) == "online"


def test_une_poignee_de_main_ancienne_vaut_hors_ligne():
    assert mesh.peer_liveness({C3BOX: NOW - 600}, C3BOX, NOW) == "offline"


def test_l_etat_de_gk2_n_affiche_plus_deux_pairs_en_ligne():
    """LE MENSONGE MESURÉ : deux pairs « en ligne » qui n'avaient jamais
    établi de poignée de main."""
    priv, _ = _cle()
    nodes = mesh.peer_nodes(etat_gk2(priv), {C3BOX: 0, AMD64: 0}, NOW)
    assert [n["status"] for n in nodes] == ["offline", "offline"]


def test_un_fichier_perime_ne_fait_pas_foi(tmp_path):
    """Si le minuteur root est arrêté, dire « hors ligne » accuserait les pairs
    d'une panne qui est la nôtre."""
    f = tmp_path / "hs.json"
    f.write_text(json.dumps({"written_at": NOW - 600, "handshakes": {C3BOX: NOW - 700}}))
    assert mesh.load_handshakes(f, NOW) is None
    f.write_text(json.dumps({"written_at": NOW - 5, "handshakes": {C3BOX: NOW - 10}}))
    assert mesh.load_handshakes(f, NOW) == {C3BOX: NOW - 10}


# ── La jonction, de bout en bout côté maître ─────────────────────────────────

class _Client:
    host = "127.0.0.1"          # derrière nginx : l'adresse vue n'est pas le pair


class _Req:
    client = _Client()


@pytest.fixture
def maitre(tmp_path, monkeypatch):
    from api import main
    priv, _ = _cle()
    wg_path = tmp_path / "wg_mesh.json"
    wg_path.write_text(json.dumps(etat_gk2(priv)))
    peers_path = tmp_path / "peers.json"
    peers_path.write_text(json.dumps({"peers": []}))
    requests = []
    monkeypatch.setattr(main, "WG_MESH_CONFIG", wg_path)
    monkeypatch.setattr(main, "PEERS_FILE", peers_path)
    monkeypatch.setattr(main, "get_ml_requests", lambda: requests)
    monkeypatch.setattr(main, "save_ml_requests", lambda r: None)
    monkeypatch.setattr(main, "get_ml_config", lambda: {"depth": 0, "auto_approve": False})
    monkeypatch.setattr(main, "ml_token_mark_used", lambda *a: None)
    etat = {"auto": True}
    monkeypatch.setattr(main, "ml_token_validate",
                        lambda t: {"valid": True, "token_hash": "h", "auto_approve": etat["auto"]})
    return main, wg_path, requests, etat


def _join(main, pub, fp="vm-fp", **kw):
    return main.ml_join(main.JoinRequest(token="t", fingerprint=fp, hostname="secubox-vm-x64",
                                         address="192.168.1.78", wg_public_key=pub,
                                         wg_port=51822, **kw), _Req())


def test_la_jonction_monte_le_pair_dans_wg_mesh(maitre):
    main, wg_path, _, _ = maitre
    _, pub = _cle()
    r = _join(main, pub)
    assert r["status"] == "approved"
    # Le maître renvoie de quoi monter l'autre côté.
    assert mesh.valid_wg_key(r["wg"]["master_public_key"])
    assert r["wg"]["address"] == "10.10.0.4/24"          # PAS .2 : c3box la tient
    assert r["wg"]["master_mesh_ip"] == "10.10.0.1"
    # Et le pair est dans le TRANSPORT, pas seulement au registre.
    st = json.loads(wg_path.read_text())
    vm = [p for p in st["peers"] if p["public_key"] == pub][0]
    assert vm["allowed_ips"] == "10.10.0.4/32"
    assert vm["endpoint"] == "192.168.1.78:51822"        # l'adresse DÉCLARÉE, pas 127.0.0.1
    # Les pairs existants sont intacts.
    assert {p["public_key"] for p in st["peers"]} >= {C3BOX, AMD64}


def test_le_reenrolement_d_un_pair_en_collision_le_deplace(maitre):
    """LE CAS DE LA VM : déjà approuvée avec 10.10.0.2, l'adresse de c3box."""
    main, wg_path, requests, _ = maitre
    requests.append({"fingerprint": "vm-fp", "status": "approved",
                     "mesh_ip": "10.10.0.2", "address": "192.168.1.78"})
    _, pub = _cle()
    r = _join(main, pub)
    assert r["wg"]["address"] != "10.10.0.2/24"
    st = json.loads(wg_path.read_text())
    c3 = [p for p in st["peers"] if p["public_key"] == C3BOX][0]
    assert c3["allowed_ips"] == "10.10.0.2/32"          # c3box garde sa route


def test_une_demande_en_attente_ne_monte_rien(maitre):
    main, wg_path, _, etat = maitre
    etat["auto"] = False
    _, pub = _cle()
    r = _join(main, pub)
    assert r["status"] == "pending" and "wg" not in r
    assert pub not in wg_path.read_text()


def test_une_cle_invalide_est_refusee_a_la_jonction(maitre):
    main, _, _, _ = maitre
    with pytest.raises(HTTPException) as e:
        _join(main, "pas-une-cle")
    assert e.value.status_code == 400


def test_un_ancien_pair_sans_cle_reste_inscrit_sans_tunnel(maitre):
    """Compatibilité : les anciens scripts n'envoient pas de clé."""
    main, wg_path, _, _ = maitre
    r = main.ml_join(main.JoinRequest(token="t", fingerprint="old", hostname="h",
                                      address="192.168.1.50"), _Req())
    assert r["status"] == "approved" and r["wg"] is None
    assert len(json.loads(wg_path.read_text())["peers"]) == 2


# ── Les unités systemd ───────────────────────────────────────────────────────

def test_aucune_unite_ne_porte_de_guillemets_echappes():
    """LE BOGUE QUI A FAIT ÉCHOUER LE PREMIER ESSAI RÉEL. L'ExecCondition était
    `/bin/sh -c '… "\\"private_key\\"…" …'` : systemd réinterprète les
    échappements avant le shell, qui recevait une chaîne coupée. Le service
    était SAUTÉ à chaque enrôlement, et `systemd-analyze verify` ne le voit
    pas — il lit la syntaxe sans exécuter la condition. La logique vit dans un
    script ; les unités ne portent plus de shell citable."""
    import pathlib
    for f in pathlib.Path(__file__).resolve().parents[1].glob("systemd/secubox-p2p-mesh*"):
        for ligne in f.read_text().splitlines():
            if ligne.startswith("Exec"):
                assert '\\"' not in ligne and "sh -c" not in ligne, f"{f.name}: {ligne}"
