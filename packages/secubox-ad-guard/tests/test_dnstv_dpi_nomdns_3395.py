# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3395 : corrélation DNS/DPI. Une adresse distante sans SNI est nommée par la réponse DNS la plus récente (reponses.db, 24 h),
rangée dans `flux` (colonnes `nom_dns`, `categorie_dns` ajoutées sans rien détruire), exposée dans les lectures du lot 4 ;
les constats (`sans-dns` = jamais résolue) ne changent pas."""
import sqlite3
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import dnstv, dnstv_dpi as D

MAC = "aa:bb:cc:00:00:01"
TV = "192.168.1.50"
BOX = {"192.168.1.1"}
NOW = 1_800_000_000


def _ct(src, dst, dport, proto="tcp"):
    num = "17" if proto == "udp" else "6"
    return (f"ipv4     2 {proto}      {num} 29 src={src} dst={dst} sport=40000 dport={dport} src={dst} dst={src} sport={dport} "
            f"dport=40000 mark=0 use=1\n")


class SansDNS:
    def evenements(self, clients, depuis, limite=20000):
        return []


def _reponses(dossier, lignes):
    cx = sqlite3.connect(str(dossier / "reponses.db"))
    cx.executescript("CREATE TABLE rep (registre TEXT NOT NULL, nom TEXT NOT NULL, ip TEXT NOT NULL, reseau TEXT NOT NULL, "
                     "premiere INTEGER NOT NULL, derniere INTEGER NOT NULL, PRIMARY KEY (nom, ip));")
    cx.executemany("INSERT INTO rep VALUES (?,?,?,?,?,?)", lignes)
    cx.commit()
    cx.close()


def test_resolus_ip_vers_nom_le_plus_recent_dans_la_fenetre(tmp_path, monkeypatch):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    _reponses(tmp_path, [("example.com", "ancien.example.com", "151.101.1.7", "AS1", NOW - 5000, NOW - 1000),
                         ("example.net", "recent.example.net", "151.101.1.7", "AS1", NOW - 5000, NOW - 10),
                         ("example.org", "perime.example.org", "93.184.216.9", "AS2", NOW - 200000, NOW - 90000)])
    assert D._resolus(NOW) == {"151.101.1.7": "recent.example.net"}


def test_resolus_sans_base_est_vide(tmp_path, monkeypatch):
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    assert D._resolus(NOW) == {}


def test_constats_inchanges_avec_la_correspondance():
    flux = [{"local": TV, "distant": "151.101.1.7", "port": 443, "proto": "tcp", "appli": "", "hote": ""},
            {"local": TV, "distant": "93.184.216.9", "port": 443, "proto": "tcp", "appli": "", "hote": ""}]
    ens = D.constats(flux, {"151.101.1.7"}, BOX, set(), set())
    dic = D.constats(flux, {"151.101.1.7": "cdn.example.com"}, BOX, set(), set())
    assert ens == dic and [x["distant"] for x in dic] == ["93.184.216.9"] and dic[0]["type"] == "sans-dns"


def test_migration_non_destructive_de_la_table_flux(tmp_path):
    f = tmp_path / "d.db"
    ancien = D.SCHEMA.replace("nom_dns TEXT NOT NULL DEFAULT '', categorie_dns TEXT NOT NULL DEFAULT '',", "")
    assert ancien != D.SCHEMA
    cx = sqlite3.connect(str(f))
    cx.execute("PRAGMA auto_vacuum=INCREMENTAL")
    cx.executescript(ancien)
    cx.execute("INSERT INTO flux (mac, minute, appli, hote, port, distant, flux, octets, local, proto) VALUES (?,?,?,?,?,?,?,?,?,?)",
               (MAC, NOW // 60, "TLS", "", 443, "151.101.1.7", 1, 10, TV, "tcp"))
    cx.commit()
    assert "nom_dns" not in {r[1] for r in cx.execute("PRAGMA table_info(flux)")}
    cx.close()
    # l'API (lecture seule) lit l'ancienne base sans planter, colonnes absentes = vides
    total, lignes = D.MagasinDPI(f, lecture_seule=True).lignes_flux(MAC, NOW - 3600)
    assert total == 1 and lignes[0]["nom_dns"] == "" and lignes[0]["categorie_dns"] == ""
    assert D.MagasinDPI(f, lecture_seule=True).applications(MAC, NOW - 3600)[0]["domaines_dns"] == []
    m = D.MagasinDPI(f)                                                  # le moteur migre
    assert not m.corrompue_recreee
    with sqlite3.connect(str(f)) as cx:
        assert {"nom_dns", "categorie_dns"} <= {r[1] for r in cx.execute("PRAGMA table_info(flux)")}
    total, lignes = m.lignes_flux(MAC, NOW - 3600)
    assert total == 1 and lignes[0]["distant"] == "151.101.1.7"         # la ligne est gardée


def test_passage_enrichit_la_ligne_de_flux(tmp_path):
    etat = {"actif": True, "clients": [{"ip": TV, "nom": "TV", "mode": "auto", "mac": MAC}]}
    m = D.MagasinDPI(tmp_path / "d.db")
    texte = _ct(TV, "151.101.1.7", 443) + _ct(TV, "93.184.216.9", 443)
    cats = {"cdn.example.com": "CDN"}
    D.passage(etat, SansDNS(), m, lambda d: cats.get(d, "INCONNU"), NOW, {}, None, texte, {"151.101.1.7": "cdn.example.com"}, BOX,
              (set(), set()))
    _, lignes = m.lignes_flux(MAC, NOW - 3600)
    par = {x["distant"]: x for x in lignes}
    assert par["151.101.1.7"]["nom_dns"] == "cdn.example.com" and par["151.101.1.7"]["categorie_dns"] == "CDN"
    assert par["151.101.1.7"]["sans_dns"] is False
    assert par["93.184.216.9"]["nom_dns"] == "" and par["93.184.216.9"]["sans_dns"] is True
    apps = m.applications(MAC, NOW - 3600)
    assert apps[0]["domaines_dns"] == [{"nom": "cdn.example.com", "categorie": "CDN"}]


def test_sni_identique_au_nom_dns_n_est_pas_repete(tmp_path):
    etat = {"actif": True, "clients": [{"ip": TV, "nom": "TV", "mode": "auto", "mac": MAC}]}
    m = D.MagasinDPI(tmp_path / "d.db")
    import json
    sbx = {"version": 1, "genere": NOW, "flux": [
        {"local": TV, "appli": "TLS", "hote": "video.example.org", "distant": "151.101.1.8", "port": 443, "proto": "tcp", "flux": 1,
         "octets": 10, "premier": NOW - 30, "dernier": NOW},
        {"local": TV, "appli": "TLS", "hote": "video2.example.org", "distant": "151.101.1.9", "port": 443, "proto": "tcp", "flux": 1,
         "octets": 10, "premier": NOW - 30, "dernier": NOW}]}
    D.passage(etat, SansDNS(), m, lambda d: "STREAMING", NOW, {}, json.dumps(sbx), None,
              {"151.101.1.8": "video.example.org", "151.101.1.9": "edge.cdn.example"}, BOX, (set(), set()))
    _, lignes = m.lignes_flux(MAC, NOW - 3600)
    assert sorted(x["nom_dns"] for x in lignes) == ["", "edge.cdn.example"]


def test_etats_dns_derniere_decision():
    evts = [{"ts": 1, "domaine": "ads.example.com", "decision": "ALLOWED"}, {"ts": 2, "domaine": "ads.example.com", "decision": "BLOCKED"},
            {"ts": 3, "domaine": "cdn.example.com", "decision": "ALLOWED"}]
    assert D.etats_dns(evts) == {"ads.example.com": "bloque", "cdn.example.com": "autorise"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    from secubox_core import auth
    from api import dnstv_lot4_routes as L
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    monkeypatch.setattr(dnstv, "DOSSIER_LISTES", __import__("pathlib").Path(__file__).resolve().parents[1] / "lists")
    dnstv.ecrire_etat({"actif": True, "clients": [{"ip": TV, "nom": "TV salon", "mode": "auto", "mac": MAC}]}, tmp_path)
    now = int(time.time())
    dnstv.Magasin(tmp_path / "dnstv.db").ajouter([(dnstv.Evenement(now - 100, TV, "cdn.example.com", "A", "NOERROR", "ALLOWED"), "")])
    mag = D.MagasinDPI(tmp_path / "dpi-appareils.db")
    mag.ingerer([{"mac": MAC, "minute": now // 60, "appli": "TLS", "hote": "", "port": 443, "distant": "151.101.1.7", "flux": 1,
                  "octets": 500, "local": TV, "proto": "tcp", "nom_dns": "cdn.example.com", "categorie_dns": "CDN"}])
    app = FastAPI()
    app.include_router(L.router)
    app.dependency_overrides[auth.require_jwt] = lambda: {"sub": "admin"}
    app.dependency_overrides[auth.require_lecture] = lambda: {"sub": "admin"}
    return TestClient(app)


def test_routes_exposent_la_correlation(client):
    apps = client.get(f"/adblock-tv/protection/dpi/applications?mac={MAC}").json()["applications"]
    assert apps[0]["domaines_dns"] == [{"nom": "cdn.example.com", "categorie": "CDN", "etat": "autorise"}]
    lignes = client.get(f"/adblock-tv/protection/dpi/flux?mac={MAC}").json()["lignes"]
    assert lignes[0]["nom_dns"] == "cdn.example.com" and lignes[0]["categorie_dns"] == "CDN"


# ── passe de correction (relecture #3395) ──
def test_derniers_etats_dns_le_plus_recent_gagne_meme_au_dela_de_la_limite(tmp_path):
    m = dnstv.Magasin(tmp_path / "dnstv.db")
    vieux = [(dnstv.Evenement(NOW - 5000 + i, TV, "ads.example.com", "A", "NOERROR", "ALLOWED"), "") for i in range(30)]
    m.ajouter(vieux + [(dnstv.Evenement(NOW - 10, TV, "ads.example.com", "A", "NOERROR", "BLOCKED"), ""),
                       (dnstv.Evenement(NOW - 9, "192.168.1.99", "cdn.example.com", "A", "NOERROR", "BLOCKED"), "")])
    avant = (tmp_path / "dnstv.db").stat().st_mtime_ns
    e = D.derniers_etats_dns(tmp_path / "dnstv.db", [TV], ["ADS.example.com.", "cdn.example.com"], NOW - 86400, limite=5)
    assert e == {"ads.example.com": "bloque"}                       # autre appareil ignoré ; tri du plus récent
    assert (tmp_path / "dnstv.db").stat().st_mtime_ns == avant      # lecture seule
    assert D.derniers_etats_dns(tmp_path / "absente.db", [TV], ["x.example"], 0) == {}
    assert not (tmp_path / "absente.db").exists()


def test_resolus_garde_les_plus_recents_et_index(tmp_path, monkeypatch):
    from api import dnstv_reponses as R
    monkeypatch.setattr(dnstv, "DOSSIER_ETAT", tmp_path)
    cx = R.ouvrir(tmp_path / "reponses.db")
    cx.executemany("INSERT INTO rep VALUES (?,?,?,?,?,?)", [("a.example", "a.example", "151.101.1.1", "", NOW - 50, NOW - 50),
                                                            ("b.example", "b.example", "151.101.1.2", "", NOW - 5, NOW - 5)])
    cx.commit()
    assert "rep_ip" in {r[1] for r in cx.execute("PRAGMA index_list(rep)")}
    cx.close()
    monkeypatch.setattr(D, "MAX_RESOLUS", 1)
    assert D._resolus(NOW) == {"151.101.1.2": "b.example"}


def test_nom_dns_normalise_et_compare_au_sni_normalise(tmp_path):
    import json
    etat = {"actif": True, "clients": [{"ip": TV, "nom": "TV", "mode": "auto", "mac": MAC}]}
    m = D.MagasinDPI(tmp_path / "d.db")
    sbx = {"version": 1, "genere": NOW, "flux": [
        {"local": TV, "appli": "TLS", "hote": "video.example.org", "distant": "151.101.1.8", "port": 443, "proto": "tcp", "flux": 1,
         "octets": 10, "premier": NOW - 30, "dernier": NOW}]}
    D.passage(etat, SansDNS(), m, lambda d: "STREAMING", NOW, {}, json.dumps(sbx), _ct(TV, "151.101.1.9", 443),
              {"151.101.1.8": "Video.Example.org.", "151.101.1.9": "Edge.CDN.example."}, BOX, (set(), set()))
    _, lignes = m.lignes_flux(MAC, NOW - 3600)
    assert sorted(x["nom_dns"] for x in lignes) == ["", "edge.cdn.example"]


def test_page_flux_garde_de_generation_et_note():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "www/tv-privacy/index.html").read_text(encoding="utf-8")
    assert "pas forcément demandé par cet appareil" in src
    assert "generation" in src and "fermerFlux" in src
