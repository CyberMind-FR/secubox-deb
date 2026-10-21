# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2996 (phase 2) — relevé système du Hero : parsing /proc et route publique /public/systeme (cache 5 s)."""
from fastapi.testclient import TestClient

import api.main as m
from api import systeme

STAT1 = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n"
STAT2 = "cpu  200 0 200 1400 0 0 0 0 0 0\n"
MEMINFO = "MemTotal:       4000000 kB\nMemFree:         500000 kB\nMemAvailable:   3000000 kB\nBuffers: 1 kB\n"
NETDEV = ("Inter-|   Receive                                                |  Transmit\n"
          " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
          "    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n"
          "  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
          "   wg0: 500 5 0 0 0 0 0 0 250 2 0 0 0 0 0 0\n")


def test_cpu_par_difference_de_deux_releves():
    pct, prec = systeme.cpu_pct(STAT1, None)
    assert pct is None and prec == (1000, 800)
    pct, _ = systeme.cpu_pct(STAT2, prec)
    # +800 total, +600 idle → 25 % occupé
    assert pct == 25.0


def test_memoire_utilisee_est_total_moins_disponible():
    mem = systeme.memoire(MEMINFO)
    assert mem == {"total_mb": 3906, "used_mb": 976, "pct": 25.0}


def test_reseau_somme_les_interfaces_sauf_lo():
    assert systeme.reseau(NETDEV) == {"rx_o": 1500, "tx_o": 2250}


DISKSTATS = ("   8       0 sda 100 0 2000 50 200 0 4000 80 0 100 130 0 0 0 0\n"
             "   8       1 sda1 90 0 1800 40 190 0 3800 70 0 90 110 0 0 0 0\n"
             " 179       0 mmcblk0 10 0 200 5 10 0 400 8 0 10 13 0 0 0 0\n"
             "   7       0 loop0 1 0 100 0 0 0 0 0 0 0 0 0 0 0 0\n"
             " 254       0 zram0 1 0 100 0 1 0 100 0 0 0 0 0 0 0 0\n")


def test_es_disque_somme_les_disques_entiers_seulement():
    # sda (2000 + 4000 secteurs) + mmcblk0 (200 + 400) ; sda1, loop0, zram0 ignorés
    assert systeme.es_disque(DISKSTATS) == {"lu_o": 2200 * 512, "ecrit_o": 4400 * 512}


def test_releve_complet_depuis_un_proc_factice(tmp_path):
    (tmp_path / "diskstats").write_text(DISKSTATS)
    (tmp_path / "stat").write_text(STAT1)
    (tmp_path / "meminfo").write_text(MEMINFO)
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "dev").write_text(NETDEV)
    (tmp_path / "uptime").write_text("12345.67 1000.0\n")
    systeme._prec["cpu"] = None
    r = systeme.releve(tmp_path, disque=str(tmp_path))
    assert r["uptime_s"] == 12345 and r["mem"]["pct"] == 25.0 and r["reseau"]["rx_o"] == 1500
    assert r["cpu_pct"] is None and len(r["charge"]) == 3 and r["disque"]["total_mb"] > 0
    assert r["es"]["lu_o"] == 2200 * 512 and r["es"]["t"] > 0
    assert r["releve"].endswith("+00:00") and set(r) == {"hote", "releve", "cpu_pct", "charge", "coeurs", "mem", "disque", "reseau", "es", "uptime_s"}


def test_route_publique_mise_en_cache_5s(monkeypatch):
    appels = []

    def faux():
        appels.append(1)
        return {"hote": "sbx", "cpu_pct": 3.0}
    monkeypatch.setattr(m.systeme, "releve", faux)
    m._sys.update({"d": None, "t": 0.0})
    c = TestClient(m.app)
    assert c.get("/public/systeme").json()["hote"] == "sbx"
    assert c.get("/public/systeme").json()["cpu_pct"] == 3.0
    assert len(appels) == 1


def test_route_publique_503_si_proc_illisible(monkeypatch):
    def boom():
        raise OSError("proc")
    monkeypatch.setattr(m.systeme, "releve", boom)
    m._sys.update({"d": None, "t": 0.0})
    assert TestClient(m.app).get("/public/systeme").status_code == 503
