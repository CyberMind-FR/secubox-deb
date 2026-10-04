# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Métriques du panneau DNS Guard d'après le puits et les compteurs DNS d'ad-guard (#1978) : un chiffre absent est dit absent, jamais un zéro."""
import json
import sqlite3

import pytest

from api import metriques

JOUR = "2026-10-04"


def base(tmp_path, lignes):
    f = tmp_path / "dnstv.db"
    cx = sqlite3.connect(f)
    cx.execute("""CREATE TABLE dnstv_counts (jour TEXT NOT NULL, client TEXT NOT NULL, domaine TEXT NOT NULL, categorie TEXT NOT NULL DEFAULT '',
                  decision TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (jour, client, domaine, decision))""")
    cx.executemany("INSERT INTO dnstv_counts VALUES (?, ?, ?, ?, ?, ?)", lignes)
    cx.commit()
    cx.close()
    return f


LIGNES = [(JOUR, "192.168.1.5", "pub.example.com", "advertising", "BLOCKED", 40), (JOUR, "192.168.1.6", "pub.example.com", "advertising", "BLOCKED", 10),
          (JOUR, "192.168.1.5", "trk.example.net", "tracking", "BLOCKED", 7), (JOUR, "192.168.1.5", "ok.example.org", "", "ALLOWED", 900),
          (JOUR, "192.168.1.6", "err.example.org", "", "UPSTREAM_ERROR", 3), ("2026-10-03", "192.168.1.5", "vieux.example.com", "advertising", "BLOCKED", 500)]


def test_compteurs_du_jour(tmp_path):
    assert metriques.compteurs_dns(base(tmp_path, LIGNES), JOUR) == {"requetes": 40 + 10 + 7 + 900 + 3, "bloquees": 57}


def test_compteurs_absents_ou_illisibles_donnent_none(tmp_path):
    assert metriques.compteurs_dns(tmp_path / "absente.db", JOUR) is None
    f = tmp_path / "x.db"
    f.write_text("pas une base")
    assert metriques.compteurs_dns(f, JOUR) is None
    vide = tmp_path / "vide.db"
    sqlite3.connect(vide).close()
    assert metriques.compteurs_dns(vide, JOUR) is None                 # pas de table : pas de mesure


def test_un_jour_sans_ligne_est_zero_et_non_absent(tmp_path):
    assert metriques.compteurs_dns(base(tmp_path, LIGNES), "2026-10-05") == {"requetes": 0, "bloquees": 0}


def test_la_base_est_ouverte_en_lecture_seule(tmp_path):
    f = base(tmp_path, LIGNES)
    avant = f.read_bytes()
    metriques.compteurs_dns(f, JOUR)
    metriques.top_bloques(f, JOUR, 5)
    assert f.read_bytes() == avant and [p.name for p in tmp_path.iterdir()] == ["dnstv.db"]


def test_top_des_domaines_bloques(tmp_path):
    f = base(tmp_path, LIGNES)
    assert metriques.top_bloques(f, JOUR, 10) == [{"domain": "pub.example.com", "category": "advertising", "hits": 50},
                                                 {"domain": "trk.example.net", "category": "tracking", "hits": 7}]
    assert metriques.top_bloques(f, JOUR, 1) == [{"domain": "pub.example.com", "category": "advertising", "hits": 50}]
    assert metriques.top_bloques(tmp_path / "absente.db", JOUR, 10) == []


@pytest.mark.parametrize("limite", [0, -3, 10_000, "x", None])
def test_limite_bornee(tmp_path, limite):
    assert len(metriques.top_bloques(base(tmp_path, LIGNES), JOUR, limite)) <= 50


def test_categorie_vide_devient_inconnue(tmp_path):
    f = base(tmp_path, [(JOUR, "c", "x.example.com", "", "BLOCKED", 2)])
    assert metriques.top_bloques(f, JOUR, 5) == [{"domain": "x.example.com", "category": "inconnue", "hits": 2}]


def test_puits(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"ok": True, "enabled": True, "blocked": 656704}))
    assert metriques.lire_puits(f) == {"blocklist_size": 656704, "actif": True}
    f.write_text(json.dumps({"enabled": False, "blocked": 12}))
    assert metriques.lire_puits(f) == {"blocklist_size": 12, "actif": False}


@pytest.mark.parametrize("contenu", ["pas du json", "[]", "null", '{"blocked": -1}', '{"blocked": "beaucoup"}', '{"blocked": true}', "{}"])
def test_puits_illisible_donne_none(tmp_path, contenu):
    f = tmp_path / "s.json"
    f.write_text(contenu)
    assert metriques.lire_puits(f) is None
    assert metriques.lire_puits(tmp_path / "absent.json") is None


def test_menaces_depuis_les_alertes():
    from api.main import DnsAlert
    a = DnsAlert(id="1", type="dga", severity="high", domain="xkqzp.example.com", client_ip="192.168.1.5", description="d", timestamp="2026-10-04T05:00:00Z", blocked=True)
    assert metriques.menaces([a]) == [{"timestamp": "2026-10-04T05:00:00Z", "domain": "xkqzp.example.com", "type": "dga", "client_ip": "192.168.1.5", "blocked": True}]
