# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2236 : colonnes os / os_source / device_subtype / mac_random dans devices.db, remplies par le collecteur, exposées par l'API."""
import sqlite3
import time


def _store(tmp_path):
    from api.store import DeviceStore
    return DeviceStore(str(tmp_path / "d.db"))


def test_une_base_ancienne_recoit_les_colonnes_sans_perdre_ses_lignes(tmp_path):
    p = tmp_path / "ancienne.db"
    cx = sqlite3.connect(p)
    cx.executescript("CREATE TABLE devices(mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, interface TEXT, oui_vendor TEXT, is_router INTEGER DEFAULT 0, "
                     "is_openwrt INTEGER DEFAULT 0, is_secubox INTEGER DEFAULT 0, model TEXT, luci_version TEXT, device_type TEXT DEFAULT 'unknown', "
                     "risk_level TEXT DEFAULT 'unknown', risk_score INTEGER DEFAULT 50, zone TEXT, allow_state TEXT DEFAULT 'unknown', quarantined INTEGER DEFAULT 0, "
                     "parental_profile TEXT, first_seen INTEGER, last_seen INTEGER, source TEXT, tags TEXT, notes TEXT, group_id TEXT, plane TEXT, provenance TEXT, "
                     "geo_cc TEXT, geo_asn TEXT); INSERT INTO devices(mac, ip) VALUES('aa:bb:cc:00:00:01','10.0.0.1');")
    cx.commit()
    cx.close()
    from api.store import DeviceStore
    s = DeviceStore(str(p))
    d = s.get("aa:bb:cc:00:00:01")
    assert d["ip"] == "10.0.0.1" and d["os"] is None and d["os_source"] is None and d["device_subtype"] is None and d["mac_random"] in (None, 0)


def test_set_detection_remplace_et_peut_retirer_une_conclusion_perimee(tmp_path):
    s = _store(tmp_path)
    s.upsert({"mac": "aa:bb:cc:00:00:02", "ip": "10.0.0.2", "last_seen": 1, "first_seen": 1})
    s.set_detection("aa:bb:cc:00:00:02", os="Android 13", os_source="dhcp-vendor-class:android-dhcp-13", device_subtype="smartphone", mac_random=True)
    d = s.get("aa:bb:cc:00:00:02")
    assert (d["os"], d["os_source"], d["device_subtype"], d["mac_random"]) == ("Android 13", "dhcp-vendor-class:android-dhcp-13", "smartphone", 1)
    s.set_detection("aa:bb:cc:00:00:02", os="iOS 17", os_source="user-agent:x", device_subtype="smartphone", mac_random=True)    # nouvelle preuve : elle REMPLACE
    assert s.get("aa:bb:cc:00:00:02")["os"] == "iOS 17"
    s.set_detection("aa:bb:cc:00:00:02", os=None, os_source=None, device_subtype=None, mac_random=True)                          # plus de preuve : on n'affirme plus
    assert s.get("aa:bb:cc:00:00:02")["os"] is None


def test_un_os_sans_source_est_refuse(tmp_path):
    import pytest
    s = _store(tmp_path)
    s.upsert({"mac": "aa:bb:cc:00:00:03", "ip": "10.0.0.3", "last_seen": 1, "first_seen": 1})
    with pytest.raises(ValueError):
        s.set_detection("aa:bb:cc:00:00:03", os="Windows", os_source=None, device_subtype=None, mac_random=False)


def _cycle(tmp_path, monkeypatch, devices, dns=None):
    import api.collector as C
    from api.collector import Collector
    s = _store(tmp_path)
    monkeypatch.setattr(C, "discover", lambda **k: devices)
    col = Collector(s, oui_map={}, interval=0, dns_provider=dns)
    col._emit = lambda ev, d: None
    col.cycle_once()
    return s, col


def test_le_collecteur_renseigne_l_os_d_apres_le_nom_avec_sa_preuve(tmp_path, monkeypatch):
    s, _ = _cycle(tmp_path, monkeypatch, [{"mac": "aa:bb:cc:00:00:10", "ip": "192.168.1.50", "hostname": "iPhone-de-Marie", "source": "dnsmasq"}])
    d = s.get("aa:bb:cc:00:00:10")
    assert d["os"] == "iOS" and d["os_source"] == "hostname:iPhone-de-Marie" and d["device_subtype"] == "smartphone"


def test_le_collecteur_n_invente_rien_sans_preuve(tmp_path, monkeypatch):
    s, _ = _cycle(tmp_path, monkeypatch, [{"mac": "aa:bb:cc:00:00:11", "ip": "192.168.1.51", "hostname": "salon", "source": "arp"}])
    d = s.get("aa:bb:cc:00:00:11")
    assert d["os"] is None and d["os_source"] is None


def test_les_domaines_dns_servent_de_preuve_par_adresse(tmp_path, monkeypatch):
    s, _ = _cycle(tmp_path, monkeypatch, [{"mac": "aa:bb:cc:00:00:12", "ip": "192.168.1.52", "hostname": "", "source": "arp"}],
                  dns=lambda: {"192.168.1.52": ["www.msftconnecttest.com"]})
    d = s.get("aa:bb:cc:00:00:12")
    assert d["os"] == "Windows" and d["os_source"] == "dns:www.msftconnecttest.com"


def test_un_fournisseur_dns_defaillant_ne_casse_pas_le_cycle(tmp_path, monkeypatch):
    def boom():
        raise RuntimeError("base DNS illisible")
    s, col = _cycle(tmp_path, monkeypatch, [{"mac": "aa:bb:cc:00:00:13", "ip": "192.168.1.53", "hostname": "DESKTOP-9", "source": "arp"}], dns=boom)
    assert s.get("aa:bb:cc:00:00:13")["os"] == "Windows"            # le nom suffit, le DNS manquant n'empêche rien


def test_les_macs_aleatoires_sont_marquees(tmp_path, monkeypatch):
    s, _ = _cycle(tmp_path, monkeypatch, [{"mac": "da:a1:19:00:00:14", "ip": "192.168.1.54", "hostname": "", "source": "arp"},
                                          {"mac": "3c:22:fb:00:00:15", "ip": "192.168.1.55", "hostname": "", "source": "arp"}])
    assert s.get("da:a1:19:00:00:14")["mac_random"] == 1 and s.get("3c:22:fb:00:00:15")["mac_random"] == 0


def test_une_nouvelle_preuve_remplace_l_ancienne_au_cycle_suivant(tmp_path, monkeypatch):
    import api.collector as C
    s, col = _cycle(tmp_path, monkeypatch, [{"mac": "aa:bb:cc:00:00:16", "ip": "192.168.1.56", "hostname": "", "source": "arp"}])
    assert s.get("aa:bb:cc:00:00:16")["os"] is None
    monkeypatch.setattr(C, "discover", lambda **k: [{"mac": "aa:bb:cc:00:00:16", "ip": "192.168.1.56", "hostname": "android-123", "source": "dnsmasq"}])
    col.cycle_once()
    assert s.get("aa:bb:cc:00:00:16")["os"] == "Android"
