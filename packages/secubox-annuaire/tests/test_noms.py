# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-annuaire-noms : Bonjour + noms <box>.lan/.mesh.<zone> (#1556)."""
import importlib.machinery
import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "sbin" / "secubox-annuaire-noms"


def charge():
    loader = importlib.machinery.SourceFileLoader("noms", str(SCRIPT))
    spec = importlib.util.spec_from_loader("noms", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


N = charge()
# Le vrai wg_mesh.json de gk3 (pair) et celui de gk2 (maître), 2026-09-28.
GK3 = {"role": "peer", "address": "10.10.0.5/24", "network": "10.10.0.0/24",
       "peers": [{"endpoint": "192.168.1.200:51822", "allowed_ips": "10.10.0.0/24", "mesh_ip": "10.10.0.1", "name": "master"}]}
GK2 = {"role": "master", "address": "10.10.0.1/24", "network": "10.10.0.0/24",
       "peers": [{"allowed_ips": "10.10.0.5/32", "mesh_ip": "10.10.0.5", "name": "secubox-live"}]}


def test_le_maitre_d_un_pair_porte_tout_le_reseau():
    assert N.maitre_de(GK3) == "10.10.0.1"
    assert N.maitre_de(GK2) is None                         # le maître n'a pas de maître


def test_zones_du_maitre():
    c = N.unbound_maitre("secubox.in", "10.10.0.1", [
        {"boxname": "gk2", "mesh_ip": "10.10.0.1", "lan_ip": "192.168.1.200"},
        {"boxname": "gk3", "mesh_ip": "10.10.0.5", "lan_ip": "192.168.1.9"},
        {"boxname": "GK3", "mesh_ip": "10.10.0.9"},             # doublon : le premier gagne
        {"boxname": "pas un nom!", "mesh_ip": "10.10.0.7"}])    # jamais une étiquette invalide
    assert 'local-data: "gk3.lan.secubox.in. 300 IN A 192.168.1.9"' in c
    assert 'local-data: "gk2.mesh.secubox.in. 300 IN A 10.10.0.1"' in c
    assert "10.10.0.9" not in c and "10.10.0.7" not in c
    assert "ip-freebind: yes" in c and "interface: 10.10.0.1" in c   # sans lui, Unbound tombe au boot
    assert "access-control: 10.10.0.0/24 allow" in c


def test_un_pair_demande_au_maitre_et_n_echoue_pas_au_dnssec():
    c = N.unbound_pair("secubox.in", "10.10.0.1")
    assert 'domain-insecure: "lan.secubox.in."' in c and 'domain-insecure: "mesh.secubox.in."' in c
    assert c.count("stub-addr: 10.10.0.1") == 2


def test_annonce_bonjour():
    x = N.avahi_xml("gk3", "sbx-38c2ec6a7580", "10.10.0.5")
    assert "<type>_secubox._tcp</type>" in x and "<txt-record>boxname=gk3</txt-record>" in x
    assert "<txt-record>mesh_ip=10.10.0.5</txt-record>" in x
    assert N.avahi_xml("gk3", "", "").count("<txt-record>") == 1     # un champ vide n'est pas annoncé


def test_une_adresse_nouvelle_exige_un_redemarrage():
    """reload n'ouvre pas une adresse nouvelle : vu sur gk2 (#1556)."""
    c = N.unbound_maitre("secubox.in", "10.10.0.1", [])
    gk2 = "10.99.0.1:53 10.99.1.1:53 10.100.0.1:53 192.168.1.200:53 10.0.3.1:53"
    assert N.ecoute_manquante(c, gk2) == ["10.10.0.1"]
    assert N.ecoute_manquante(c, gk2 + " 10.10.0.1:53") == []
    assert N.ecoute_manquante(N.unbound_pair("secubox.in", "10.10.0.1"), "") == []   # un pair n'écoute rien de plus
