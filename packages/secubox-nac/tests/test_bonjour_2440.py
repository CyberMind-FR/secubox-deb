# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#2440 — noms et services par Bonjour (mDNS) : analyse d'avahi-browse, repli sûr, intégration à discover() et au magasin."""
from api import bonjour
from api.store import DeviceStore

SORTIE = "\n".join([
    "+;eth2;IPv4;Salon;_airplay._tcp;local",
    r"=;eth2;IPv4;Apple\032TV\032du\032salon;_airplay._tcp;local;apple-tv.local;192.0.2.20;7000;\"model=AppleTV6,2\"",
    r"=;eth2;IPv4;Apple\032TV\032du\032salon;_raop._tcp;local;apple-tv.local;192.0.2.20;7000;\"a=b\"",
    r"=;eth2;IPv6;Apple\032TV\032du\032salon;_airplay._tcp;local;apple-tv.local;fe80::1;7000;\"x=y\"",
    r"=;eth2;IPv4;Brother\032HL;_ipp._tcp;local;BRN123.local;192.0.2.30;631;\"ty=HL\"",
    r"=;eth2;IPv4;Brother\032HL;_workstation._tcp;local;BRN123.local;192.0.2.30;9;",
    r"=;eth2;IPv4;<img src=x onerror=alert(1)>;_smb._tcp;local;pc.local;192.0.2.40;445;",
    "ligne;inutilisable",
])


def test_analyse_regroupe_par_adresse_ipv4():
    r = bonjour.parse_browse(SORTIE)
    assert set(r) == {"192.0.2.20", "192.0.2.30", "192.0.2.40"}
    tv = r["192.0.2.20"]
    assert tv["host"] == "apple-tv" and tv["name"] == "Apple TV du salon"
    assert tv["services"] == ["AirPlay", "AirPlay audio"] and "_airplay._tcp" in tv["types"]


def test_service_technique_non_affiche_mais_garde_dans_les_types():
    imp = bonjour.parse_browse(SORTIE)["192.0.2.30"]
    assert imp["services"] == ["Impression"] and "_workstation._tcp" in imp["types"]


def test_sortie_vide_ou_illisible_ne_leve_pas():
    assert bonjour.parse_browse("") == {} and bonjour.parse_browse("n'importe quoi\n=;x") == {}


def test_nom_hostile_reste_du_texte_brut():
    assert bonjour.parse_browse(SORTIE)["192.0.2.40"]["name"] == "<img src=x onerror=alert(1)>"   # l'échappement est affaire de l'interface


def test_snapshot_utilise_le_cache_et_survit_a_un_echec(monkeypatch):
    appels = []
    monkeypatch.setattr(bonjour, "_lancer", lambda: appels.append(1) or SORTIE)
    bonjour._CACHE.update(at=0.0, data={})
    a = bonjour.snapshot(); b = bonjour.snapshot()
    assert a == b and len(appels) == 1
    bonjour._CACHE["at"] = 0.0
    monkeypatch.setattr(bonjour, "_lancer", lambda: (_ for _ in ()).throw(OSError("pas d'avahi")))
    assert bonjour.snapshot() == a                                           # dernier résultat connu


def test_discover_remplit_nom_vide_sans_ecraser_un_bail(monkeypatch):
    from api import discovery
    monkeypatch.setattr(bonjour, "snapshot", lambda: bonjour.parse_browse(SORTIE))
    monkeypatch.setattr(discovery, "resolve_hostname", lambda ip: None)
    arp = "192.0.2.20 dev eth2 lladdr aa:bb:cc:00:00:01 REACHABLE\n192.0.2.30 dev eth2 lladdr aa:bb:cc:00:00:02 REACHABLE\n"
    bail = "1999999999 aa:bb:cc:00:00:02 192.0.2.30 imprimante-bail *\n"
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(bail)
    try:
        res = {d["mac"]: d for d in discovery.discover(dnsmasq_leases=f.name, isc_leases="/nonexistent", arp_cmd=lambda: arp)}
    finally:
        os.unlink(f.name)
    assert res["aa:bb:cc:00:00:01"]["hostname"] == "apple-tv" and res["aa:bb:cc:00:00:01"]["services"] == ["AirPlay", "AirPlay audio"]
    assert res["aa:bb:cc:00:00:02"]["hostname"] == "imprimante-bail" and res["aa:bb:cc:00:00:02"]["services"] == ["Impression"]


def test_magasin_garde_les_services_et_les_remplace(tmp_path):
    s = DeviceStore(str(tmp_path / "d.db"))
    s.upsert({"mac": "aa:bb:cc:00:00:01", "ip": "192.0.2.20", "source": "arp", "first_seen": 1, "last_seen": 1})
    s.set_services("aa:bb:cc:00:00:01", ["AirPlay"], "Apple TV du salon")
    r = s.get("aa:bb:cc:00:00:01")
    assert r["services"] == '["AirPlay"]' and r["bonjour_name"] == "Apple TV du salon"
    s.set_services("aa:bb:cc:00:00:01", [], None)
    assert s.get("aa:bb:cc:00:00:01")["services"] in (None, "[]")


def test_la_commande_demande_les_types_bruts_2444(monkeypatch):
    """Sans -k avahi traduit les types (« AirTunes Remote Audio ») et plus rien n'est reconnu."""
    vu = {}
    monkeypatch.setattr(bonjour.shutil, "which", lambda n: "/usr/bin/avahi-browse")
    monkeypatch.setattr(bonjour.subprocess, "run", lambda cmd, **k: vu.setdefault("cmd", cmd) and type("R", (), {"stdout": ""})())
    bonjour._lancer()
    assert "-k" in vu["cmd"]


def test_inventaire_lxc_nom_par_adresse_et_refus_des_noms_hostiles_2445(tmp_path, monkeypatch):
    import importlib.machinery, importlib.util, pathlib, json
    src = pathlib.Path(__file__).resolve().parents[1] / "sbin" / "secubox-nac-lxc-names"
    loader = importlib.machinery.SourceFileLoader("lxcnoms", str(src))
    spec = importlib.util.spec_from_loader("lxcnoms", loader); mod = importlib.util.module_from_spec(spec); loader.exec_module(mod)
    (tmp_path / "gitea").mkdir(); (tmp_path / "gitea" / "config").write_text("lxc.uts.name = gitea\nlxc.net.0.ipv4.address = 192.0.2.40/24\nlxc.net.0.hwaddr = 00:16:3E:AA:BB:CC\n")
    (tmp_path / "mal").mkdir(); (tmp_path / "mal" / "config").write_text("lxc.uts.name = <b>x</b>\nlxc.net.0.ipv4.address = 192.0.2.99/24\n")
    inv = mod.inventaire(str(tmp_path))
    assert inv["ips"] == {"192.0.2.40": "gitea", "192.0.2.99": "mal"}          # le nom hostile est ignoré, le nom du dossier garde
    assert inv["macs"] == {"00:16:3e:aa:bb:cc": "gitea"}
    sortie = tmp_path / "out.json"
    mod.ecrire(inv, str(sortie))
    from api import lxcnames
    assert lxcnames.nom("192.0.2.40", "", str(sortie)) == "gitea" and lxcnames.nom("", "00:16:3E:AA:BB:CC", str(sortie)) == "gitea"
    assert lxcnames.nom("192.0.2.1", "", str(tmp_path / "absent.json")) is None


def test_discover_nomme_un_conteneur_sans_nom_2445(monkeypatch, tmp_path):
    import json
    from api import discovery, lxcnames
    f = tmp_path / "c.json"; f.write_text(json.dumps({"ips": {"10.100.0.40": "gitea"}, "macs": {}}))
    monkeypatch.setattr(lxcnames, "CHEMIN", str(f)); lxcnames._CACHE.update(mtime=None)
    monkeypatch.setattr(bonjour, "snapshot", lambda: {}); monkeypatch.setattr(discovery, "resolve_hostname", lambda ip: None)
    res = discovery.discover(dnsmasq_leases="/nonexistent", isc_leases="/nonexistent", arp_cmd=lambda: "10.100.0.40 dev br-lxc lladdr 00:16:3e:00:00:09 REACHABLE\n")
    assert res[0]["hostname"] == "gitea" and res[0]["lxc_module"] == "gitea"
