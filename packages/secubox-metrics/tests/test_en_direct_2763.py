# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2763 — /api/v1/metrics/live : connexions TCP établies par pays, débit, charge, mémoire, en temps réel.

Jamais d'adresse IP dans la réponse : seulement des pays et des compteurs."""
import json

import pytest

import en_direct

SS = """\
0      0         192.168.1.200:443       203.0.113.10:51000
0      0         192.168.1.200:443       203.0.113.11:51001
0      0         192.168.1.200:80        198.51.100.7:40000
0      0         192.168.1.200:22        192.0.2.50:50022
0      0         192.168.1.200:443       192.168.1.20:55555
0      0         127.0.0.1:8085          127.0.0.1:44444
0      0         [::ffff:192.168.1.200]:443 [::ffff:203.0.113.10]:52000
0      0         192.168.1.200:41234     198.51.100.99:443
0      0         [2001:db8::1]:443       [2001:db8::2]:60000
"""
PAYS = {"203.0.113.10": "FR", "203.0.113.11": "DE", "198.51.100.7": "US", "192.0.2.50": "FR", "198.51.100.99": "NL", "2001:db8::2": None}


def publique(ip):
    """Les adresses de documentation (RFC 5737) comptent comme publiques dans ces tests ; le LAN de test reste privé."""
    return not ip.startswith(("192.168.", "127.", "10."))


def pays(ip):
    return PAYS.get(ip)


def test_analyse_lit_port_local_et_pair():
    c = en_direct.analyse_ss(SS)
    assert (443, "203.0.113.10") in c and (22, "192.0.2.50") in c
    assert (443, "203.0.113.10") in c and c.count((443, "203.0.113.10")) == 2, "IPv4 mappé en IPv6 : la même adresse"
    assert (41234, "198.51.100.99") in c


def test_lignes_invalides_ignorees():
    assert en_direct.analyse_ss("n'importe quoi\n\n0 0 x y\n") == []


def test_agregation_par_pays_entrantes_et_sortantes():
    r = en_direct.agreger(en_direct.analyse_ss(SS), pays, publique=publique)
    ent = {p["code"]: p["n"] for p in r["entrantes"]}
    assert ent == {"FR": 3, "DE": 1, "US": 1}, "FR : 203.0.113.10 (×2) + 192.0.2.50"
    assert {p["code"]: p["n"] for p in r["sortantes"]} == {"NL": 1}


def test_lan_loopback_et_inconnus_ne_sont_pas_des_pays():
    r = en_direct.agreger(en_direct.analyse_ss(SS), pays, publique=publique)
    assert r["lan"] == 1, "192.168.1.20 est un client du LAN"
    assert r["inconnu"] == 1, "2001:db8::2 sans pays"
    assert all(p["code"] not in ("LAN", "??", "") for p in r["entrantes"] + r["sortantes"])
    assert "127.0.0.1" not in json.dumps(r)


def test_total_est_la_somme_hors_loopback():
    r = en_direct.agreger(en_direct.analyse_ss(SS), pays, publique=publique)
    assert r["total"] == 8, "neuf lignes, dont une en boucle locale"
    assert r["total"] == sum(p["n"] for p in r["entrantes"]) + sum(p["n"] for p in r["sortantes"]) + r["lan"] + r["inconnu"]


def test_aucune_adresse_ip_dans_la_reponse():
    r = en_direct.agreger(en_direct.analyse_ss(SS), pays, publique=publique)
    texte = json.dumps(r)
    for ip in ("203.0.113", "198.51.100", "192.0.2", "192.168", "2001:db8"):
        assert ip not in texte


def test_tri_decroissant_et_borne():
    lignes = "\n".join(f"0 0 192.168.1.200:443 198.51.{i % 100}.{i // 100 + 1}:5000" for i in range(300))
    codes = {f"198.51.{i % 100}.{i // 100 + 1}": chr(65 + (i % 40) // 20) + chr(65 + i % 20) for i in range(300)}
    r = en_direct.agreger(en_direct.analyse_ss(lignes), codes.get, max_pays=10, publique=publique)
    assert len(r["entrantes"]) == 10
    n = [p["n"] for p in r["entrantes"]]
    assert n == sorted(n, reverse=True)


def test_trop_de_lignes_borne_le_travail():
    lignes = "\n".join("0 0 192.168.1.200:443 203.0.113.10:5000" for _ in range(20000))
    c = en_direct.analyse_ss(lignes, max_lignes=500)
    assert len(c) == 500


PROC = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth2: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0
  eth1: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0
 veth1: 9999 1 0 0 0 0 0 0 9999 1 0 0 0 0 0 0
br-lxc: 8888 1 0 0 0 0 0 0 8888 1 0 0 0 0 0 0
"""


def test_debit_somme_les_interfaces_physiques_seulement():
    d = en_direct.lire_debit(PROC)
    assert d == {"rx": 5100, "tx": 7200}, "ni lo, ni veth, ni pont : sinon le trafic serait compté deux fois"


def test_debit_illisible_rend_none():
    assert en_direct.lire_debit("") is None


def test_instantane_assemble_les_mesures(monkeypatch):
    monkeypatch.setattr(en_direct, "_lire_ss", lambda: SS)
    monkeypatch.setattr(en_direct, "_lire_proc_net", lambda: PROC)
    monkeypatch.setattr(en_direct, "_charge", lambda: 1.5)
    monkeypatch.setattr(en_direct, "_memoire_pct", lambda: 42.0)
    r = en_direct.instantane(pays, publique)
    assert set(r) >= {"ts", "connexions", "debit", "charge", "memoire_pct"}
    assert r["debit"] == {"rx": 5100, "tx": 7200} and r["charge"] == 1.5 and r["memoire_pct"] == 42.0
    assert r["connexions"]["total"] > 0


def test_instantane_degrade_sans_ss(monkeypatch):
    monkeypatch.setattr(en_direct, "_lire_ss", lambda: None)
    monkeypatch.setattr(en_direct, "_lire_proc_net", lambda: PROC)
    monkeypatch.setattr(en_direct, "_charge", lambda: None)
    monkeypatch.setattr(en_direct, "_memoire_pct", lambda: None)
    r = en_direct.instantane(pays, publique)
    assert r["connexions"] is None and r["charge"] is None and r["debit"] is not None


def test_la_route_est_en_lecture_sans_cache():
    src = open(__file__.replace("tests/test_en_direct_2763.py", "api/main.py")).read()
    i = src.index('@app.get("/api/v1/metrics/live"')
    bloc = src[i:i + 700]
    assert "require_lecture" in bloc and "no-store" in bloc and "en_direct" in bloc


def test_le_pays_de_la_box_est_configurable_et_borne(monkeypatch):
    monkeypatch.setenv("SECUBOX_PAYS", "be")
    assert en_direct._pays_de_la_box() == "BE"
    for faux in ("", "FRA", "1x", "<script>"):
        monkeypatch.setenv("SECUBOX_PAYS", faux)
        assert en_direct._pays_de_la_box() == "FR", faux
    monkeypatch.delenv("SECUBOX_PAYS")
    assert en_direct._pays_de_la_box() == "FR"
