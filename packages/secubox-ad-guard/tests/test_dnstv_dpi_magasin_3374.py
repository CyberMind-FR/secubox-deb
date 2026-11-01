# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374) : magasin borné `dpi-appareils.db` et passage du moteur (sources sbxdpi / conntrack, découvertes, couverture)."""
import json
from pathlib import Path

from api import dnstv_dpi as D
from api import dnstv_taxonomie as T

LISTES = Path(__file__).resolve().parents[1] / "lists"
TAXO = T.Taxonomie.depuis_dossier(LISTES)
MAC = "aa:bb:cc:00:00:01"
MAC2 = "aa:bb:cc:00:00:02"
NOW = 1_800_000_000


def cat(d):
    return TAXO.classer(d)["categorie"]


def etat():
    return {"actif": True, "clients": [{"ip": "192.168.1.50", "nom": "TV salon", "mode": "auto", "mac": MAC},
                                       {"ip": "192.168.1.51", "nom": "TV banc", "mode": "observe", "mac": MAC2},
                                       {"ip": "192.168.1.60", "nom": "Hors", "mode": "off", "mac": "aa:bb:cc:00:00:09"}]}


class FauxDNS:
    def __init__(self, evts):
        self.evts = evts

    def evenements(self, clients, depuis, limite=20000):
        return [e for e in self.evts if e["client"] in clients and e["ts"] >= depuis]


def test_magasin_borne_ingere_agrege_et_fait_le_menage(tmp_path):
    m = D.MagasinDPI(tmp_path / "dpi-appareils.db")
    base = {"appli": "TLS.Google", "categorie_ndpi": "Advertisement", "hote": "pagead2.googlesyndication.com", "port": 443,
            "distant": "", "flux": 2, "octets": 1000, "sans_dns": 0, "dns_chiffre": 0}
    m.ingerer([dict(base, mac=MAC, minute=NOW // 60), dict(base, mac=MAC, minute=NOW // 60, flux=3, octets=1500),
               dict(base, mac=MAC, minute=NOW // 60 - 1, appli="QUIC.YouTube", hote="rr1.googlevideo.com", octets=9000)])
    apps = m.applications(MAC, NOW - 3600)
    assert [a["appli"] for a in apps] == ["QUIC.YouTube", "TLS.Google"]          # triées par octets
    assert apps[1]["octets"] == 1500 and apps[1]["flux"] == 3                     # même minute : la dernière valeur remplace
    assert apps[1]["hotes"] == ["pagead2.googlesyndication.com"]
    assert m.dernier_flux(MAC) == NOW - NOW % 60 and m.dernier_flux(MAC2) is None
    m.ingerer([dict(base, mac=MAC, minute=(NOW - 8 * 86400) // 60)])
    m.menage(NOW)
    assert all(a["dernier"] >= NOW - 7 * 86400 for a in m.applications(MAC, 0))


def test_decouvertes_dedoublonnees_ordonnees_et_lisibles_par_id(tmp_path):
    m = D.MagasinDPI(tmp_path / "d.db")
    d = {"type": "repli", "domaine": "metaproxy.francetvpub.fr", "categorie": "PUBLICITE", "refus_domaine": "pagead2.googlesyndication.com",
         "refus_ts": NOW, "ts": NOW + 3, "delai_s": 3, "coupures": 1, "confiance": 70, "raison": "apparu 3 s après le blocage de pagead2.googlesyndication.com"}
    assert m.ajouter_decouvertes(MAC, [d, d]) == 1
    assert m.ajouter_decouvertes(MAC, [dict(d, refus_ts=NOW + 500, ts=NOW + 503)]) == 1
    lst = m.decouvertes()
    assert [x["id"] for x in lst] == sorted(x["id"] for x in lst) and len(lst) == 2
    assert m.decouvertes(depuis_id=lst[0]["id"])[0]["id"] == lst[1]["id"]
    assert lst[0]["mac"] == MAC and lst[0]["etat"] == "nouvelle"


def test_base_corrompue_est_recreee(tmp_path):
    f = tmp_path / "d.db"
    f.write_bytes(b"pas une base sqlite" * 100)
    m = D.MagasinDPI(f)
    assert m.decouvertes() == [] and m.corrompue_recreee


def test_passage_sans_flux_dit_dns_seulement_et_correle_le_repli(tmp_path):
    t0 = NOW - 100
    evts = [{"ts": t0, "client": "192.168.1.50", "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"},
            {"ts": t0 + 3, "client": "192.168.1.50", "domaine": "metaproxy.francetvpub.fr", "decision": "ALLOWED"},
            {"ts": t0 + 5, "client": "192.168.1.51", "domaine": "pagead2.googlesyndication.com", "decision": "BLOCKED"}]
    m = D.MagasinDPI(tmp_path / "d.db")
    r = D.passage(etat(), FauxDNS(evts), m, cat, NOW, voisins={"2a01:e0a::1": MAC}, sbxdpi_texte=None, conntrack_texte=None,
                  resolus=set(), box={"192.168.1.200"}, doh=(set(), set()), memoire={})
    par = {a["mac"]: a for a in r["etat"]["appareils"]}
    assert set(par) == {MAC, MAC2}                                      # OFF hors périmètre
    assert par[MAC]["couverture"] == "dns" and r["etat"]["sources"] == {"sbxdpi": "absent", "conntrack": "absent"}
    dec = m.decouvertes()
    assert [(x["mac"], x["domaine"]) for x in dec] == [(MAC, "metaproxy.francetvpub.fr")]
    assert [c["domaine"] for c in r["candidats"][MAC]] == ["metaproxy.francetvpub.fr"]


def test_passage_avec_sbxdpi_et_conntrack_rattache_par_mac_et_releve_les_constats(tmp_path):
    sbx = {"version": 1, "genere": NOW - 10, "flux": [
        {"local": "2a01:e0a::1", "appli": "TLS", "categorie": "", "hote": "", "distant": "151.101.1.9", "port": 443, "proto": "tcp",
         "flux": 1, "octets": 500, "premier": NOW - 70, "dernier": NOW - 65},
        {"local": "192.168.1.50", "appli": "QUIC.YouTube", "categorie": "Media", "hote": "rr1.googlevideo.com", "distant": "",
         "port": 443, "proto": "udp", "flux": 4, "octets": 9000, "premier": NOW - 60, "dernier": NOW - 20}]}
    ct = ("ipv4     2 udp      17 29 src=192.168.1.50 dst=9.9.9.9 sport=5000 dport=53 src=9.9.9.9 dst=192.168.1.50 sport=53 dport=5000 mark=0 use=1\n"
          "ipv4     2 tcp      6 100 ESTABLISHED src=192.168.1.50 dst=1.1.1.1 sport=5001 dport=853 src=1.1.1.1 dst=192.168.1.50 sport=853 dport=5001 mark=0 use=1\n")
    m = D.MagasinDPI(tmp_path / "d.db")
    r = D.passage(etat(), FauxDNS([]), m, cat, NOW, voisins={"2a01:e0a::1": MAC, "192.168.1.50": MAC}, sbxdpi_texte=json.dumps(sbx),
                  conntrack_texte=ct, resolus=set(), box={"192.168.1.200"}, doh=({"1.1.1.1"}, set()), memoire={})
    par = {a["mac"]: a for a in r["etat"]["appareils"]}
    assert par[MAC]["couverture"] == "dns+dpi" and par[MAC2]["couverture"] == "dns"
    assert {a["appli"] for a in m.applications(MAC, 0)} >= {"TLS", "QUIC.YouTube"}
    types = {(x["type"], x["domaine"]) for x in m.decouvertes()}
    assert ("sans-dns", "151.101.1.9:443") in types and ("contournement", "9.9.9.9:53") in types and ("dns-chiffre", "1.1.1.1:853") in types
    assert r["etat"]["sources"]["sbxdpi"] == "ok" and r["etat"]["sources"]["conntrack"] == "ok"


def test_sbxdpi_perime_n_est_pas_lu(tmp_path):
    sbx = {"version": 1, "genere": NOW - 600, "flux": []}
    r = D.passage(etat(), FauxDNS([]), D.MagasinDPI(tmp_path / "d.db"), cat, NOW, voisins={}, sbxdpi_texte=json.dumps(sbx),
                  conntrack_texte=None, resolus=set(), box=set(), doh=(set(), set()), memoire={})
    assert r["etat"]["sources"]["sbxdpi"] == "perime"


def test_cibles_pour_sbxdpi_et_nft(tmp_path):
    c = D.cibles(etat(), {"2a01:e0a::1": MAC, "192.168.1.51": MAC2})
    assert c == {"version": 1, "appareils": [{"mac": MAC, "adresses": ["192.168.1.50", "2a01:e0a::1"]},
                                             {"mac": MAC2, "adresses": ["192.168.1.51"]}]}
