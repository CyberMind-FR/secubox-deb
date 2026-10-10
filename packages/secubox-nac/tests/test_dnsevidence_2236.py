# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2236 : les domaines de connectivité vus par le DNS (base d'ad-guard, lecture seule) comme preuve d'OS, par adresse."""
import sqlite3
import time

from api.dnsevidence import domaines_par_adresse


def _base(tmp_path, lignes):
    p = tmp_path / "dnstv.db"
    cx = sqlite3.connect(p)
    cx.execute("CREATE TABLE dnstv_counts (jour TEXT NOT NULL, client TEXT NOT NULL, domaine TEXT NOT NULL, categorie TEXT NOT NULL DEFAULT '', "
               "decision TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (jour, client, domaine, decision))")
    cx.executemany("INSERT INTO dnstv_counts(jour,client,domaine,decision,hits) VALUES (?,?,?,?,?)", lignes)
    cx.commit()
    cx.close()
    return str(p)


def test_seuls_les_domaines_de_connectivite_sont_rendus_par_adresse(tmp_path):
    j = time.strftime("%Y-%m-%d")
    p = _base(tmp_path, [(j, "192.168.1.20", "connectivitycheck.gstatic.com", "ALLOWED", 5), (j, "192.168.1.20", "www.example.org", "ALLOWED", 50),
                         (j, "192.168.1.21", "www.msftconnecttest.com", "ALLOWED", 2), (j, "192.168.1.21", "ads.tracker.net", "BLOCKED", 9)])
    r = domaines_par_adresse(p)
    assert r == {"192.168.1.20": ["connectivitycheck.gstatic.com"], "192.168.1.21": ["www.msftconnecttest.com"]}


def test_les_jours_anciens_ne_comptent_pas(tmp_path):
    p = _base(tmp_path, [("2020-01-01", "192.168.1.22", "captive.apple.com", "ALLOWED", 3)])
    assert domaines_par_adresse(p) == {}


def test_un_nom_qui_finit_comme_un_domaine_mais_n_en_est_pas_un_est_ignore(tmp_path):
    j = time.strftime("%Y-%m-%d")
    p = _base(tmp_path, [(j, "192.168.1.23", "evilmsftconnecttest.com", "ALLOWED", 1), (j, "192.168.1.23", "x.captive.apple.com.evil.net", "ALLOWED", 1)])
    assert domaines_par_adresse(p) == {}


def test_base_absente_ou_illisible_donne_vide_sans_exception(tmp_path):
    assert domaines_par_adresse(str(tmp_path / "absente.db")) == {}
    (tmp_path / "x.db").write_bytes(b"pas une base")
    assert domaines_par_adresse(str(tmp_path / "x.db")) == {}
