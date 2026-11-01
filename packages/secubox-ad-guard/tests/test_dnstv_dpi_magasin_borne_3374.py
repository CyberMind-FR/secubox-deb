# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Lot 4 (#3374), passe 2 : B1 borne en octets de dpi-appareils.db ; I1 verrou ≠ corruption, API en lecture seule ; m2 clé avec adresse
locale et protocole."""
import sqlite3
import threading
import time

from api import dnstv_dpi as D

MAC = "aa:bb:cc:00:00:01"
NOW = 1_800_000_000


def _conntrack(n, depart):
    """Volume réaliste : une ligne par connexion vivante et par minute (3 TV, ~50 connexions chacune)."""
    for i in range(n):
        yield {"mac": f"aa:bb:cc:00:00:0{i % 3 + 1}", "minute": depart + i // 150, "local": f"192.168.1.{50 + i % 3}", "proto": "tcp",
               "appli": "TCP", "hote": "", "port": 443, "distant": f"151.101.{(i // 250) % 250}.{i % 250}", "flux": 1, "octets": 0}


def test_la_base_reste_sous_20_mio_avec_un_volume_reel_de_conntrack(tmp_path):
    f = tmp_path / "d.db"
    m = D.MagasinDPI(f)
    depart = (NOW - 6 * 86400) // 60
    for lot in range(8):                                             # 400 000 lignes ≈ 3 TV × 2 jours de conntrack à la minute
        m.ingerer(list(_conntrack(50_000, depart + lot * 334)))
        m.menage(NOW)
    taille = f.stat().st_size
    assert taille <= D.MAX_OCTETS, taille
    with sqlite3.connect(f) as cx:
        assert cx.execute("PRAGMA auto_vacuum").fetchone()[0] == 2      # INCREMENTAL
        plus_ancienne = cx.execute("SELECT MIN(minute) FROM flux").fetchone()[0]
    assert plus_ancienne > depart                                       # ce sont les plus anciennes qui partent


def test_un_verrou_n_est_jamais_pris_pour_une_corruption(tmp_path):
    f = tmp_path / "d.db"
    D.MagasinDPI(f)
    cx = sqlite3.connect(f, timeout=0, check_same_thread=False)
    cx.execute("BEGIN EXCLUSIVE")
    libere = threading.Timer(0.5, lambda: (cx.rollback(), cx.close()))
    libere.start()
    m = D.MagasinDPI(f, verifier=True)                                  # attend le verrou au lieu de renommer la base
    libere.join()
    assert not m.corrompue_recreee and not (tmp_path / "d.db.corrompue").exists()


def test_api_en_lecture_seule_n_ecrit_rien(tmp_path):
    f = tmp_path / "d.db"
    w = D.MagasinDPI(f)
    w.ingerer([{"mac": MAC, "minute": NOW // 60, "local": "192.168.1.50", "proto": "tcp", "appli": "TLS", "hote": "x.example", "port": 443,
                "distant": "", "flux": 1, "octets": 10}])
    avant = f.stat().st_mtime_ns
    time.sleep(0.01)
    r = D.MagasinDPI(f, lecture_seule=True)
    assert r.applications(MAC, 0)[0]["appli"] == "TLS"
    assert f.stat().st_mtime_ns == avant
    absent = D.MagasinDPI(tmp_path / "absente.db", lecture_seule=True)
    assert absent.applications(MAC, 0) == [] and absent.decouvertes() == [] and not (tmp_path / "absente.db").exists()


def test_v4_et_v6_de_la_meme_mac_ne_s_ecrasent_pas(tmp_path):
    m = D.MagasinDPI(tmp_path / "d.db")
    base = {"mac": MAC, "minute": NOW // 60, "appli": "TLS", "hote": "x.example", "port": 443, "distant": "", "flux": 1, "octets": 100}
    m.ingerer([dict(base, local="192.168.1.50", proto="tcp"), dict(base, local="2a01:e0a::1", proto="tcp"),
               dict(base, local="192.168.1.50", proto="udp")])
    assert m.applications(MAC, 0)[0]["octets"] == 300
