# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2236 : /clients et /client/{mac} exposent os, os_source, device_subtype et mac_random ; les conteneurs LXC sont signalés et excluables à la source."""
from tests.test_endpoints import USER, _setup


def _deux(main):
    main.store.upsert({"mac": "3c:22:fb:00:00:01", "ip": "192.168.1.20", "hostname": "iPhone", "last_seen": 100, "source": "arp"})
    main.store.set_detection("3c:22:fb:00:00:01", os="iOS", os_source="hostname:iPhone", device_subtype="smartphone", mac_random=False)
    main.store.upsert({"mac": "00:16:3e:aa:bb:cc", "ip": "10.100.0.150", "hostname": "peertube", "interface": "br-lxc", "last_seen": 100, "source": "arp"})


def test_clients_expose_les_champs_de_detection_avec_la_preuve(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    _deux(main)
    c = [x for x in main.clients(user=USER)["clients"] if x["mac"] == "3c:22:fb:00:00:01"][0]
    assert (c["os"], c["os_source"], c["device_subtype"], c["mac_random"]) == ("iOS", "hostname:iPhone", "smartphone", 0)


def test_la_fiche_d_un_client_porte_aussi_la_detection(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    _deux(main)
    d = main.get_client("3c:22:fb:00:00:01", user=USER)
    assert d["os"] == "iOS" and d["os_source"] == "hostname:iPhone"


def test_les_conteneurs_sont_signales_par_defaut_et_exclus_sur_demande(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    _deux(main)
    tous = main.clients(user=USER)
    assert tous["count"] == 2                                              # défaut inchangé : les autres consommateurs (zones, toolbox) comptent sur eux
    assert {x["mac"]: x["conteneur"] for x in tous["clients"]} == {"3c:22:fb:00:00:01": False, "00:16:3e:aa:bb:cc": True}
    sans = main.clients(exclure_conteneurs=True, user=USER)
    assert [x["mac"] for x in sans["clients"]] == ["3c:22:fb:00:00:01"] and sans["count"] == 1 and sans["conteneurs_exclus"] == 1


def test_le_cache_ne_melange_pas_les_deux_vues(tmp_path, monkeypatch):
    main, _ = _setup(tmp_path, monkeypatch)
    _deux(main)
    main.clients(user=USER)                                                # remplit le cache de la vue complète
    assert main.clients(exclure_conteneurs=True, user=USER)["count"] == 1
    assert main.clients(user=USER)["count"] == 2
