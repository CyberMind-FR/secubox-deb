# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2765 — historique des courbes (remplace Grafana) : un relevé par minute, 7 jours, stdlib seule.

CPU, mémoire, charge, débit réseau, connexions TCP, disque. Les débits et le CPU se déduisent de COMPTEURS bruts (jiffies, octets) : un compteur qui
repart de zéro (redémarrage) donne un trou, jamais un pic négatif ou énorme."""
import json
from pathlib import Path

import pytest

import serie


def proc(tmp_path, jiffies=(1000, 0, 500, 8000, 100, 0, 50, 0), mem=(8000000, 2000000), load="0.52 0.40 0.30 1/200 999", rx=1000, tx=500, etab=3):
    p = tmp_path / "proc"
    (p / "net").mkdir(parents=True, exist_ok=True)
    (p / "stat").write_text("cpu  " + " ".join(map(str, jiffies)) + " 0 0\ncpu0 1 2 3\n")
    (p / "meminfo").write_text(f"MemTotal: {mem[0]} kB\nMemFree: 1 kB\nMemAvailable: {mem[1]} kB\n")
    (p / "loadavg").write_text(load + "\n")
    (p / "net" / "dev").write_text(
        "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
        f"    lo: 9999 1 0 0 0 0 0 0 9999 1 0 0 0 0 0 0\n  eth2: {rx} 1 0 0 0 0 0 0 {tx} 1 0 0 0 0 0 0\n veth1: 777 1 0 0 0 0 0 0 777 1 0 0 0 0 0 0\n")
    tcp = "  sl  local_address rem_address   st tx_queue\n" + "".join(f"   {i}: 0100007F:1F90 0100007F:C000 01 0:0\n" for i in range(etab)) + "   9: 0100007F:1F90 00000000:0000 0A 0:0\n"
    (p / "net" / "tcp").write_text(tcp)
    (p / "net" / "tcp6").write_text("  sl  local_address rem_address   st\n   0: 0:1 0:2 01 0:0\n   1: 0:1 0:2 06 0:0\n")
    return p


def test_releve_lit_les_compteurs_bruts(tmp_path):
    r = serie.releve(proc(tmp_path), racine=str(tmp_path), maintenant=1000.0)
    assert r["t"] == 1000.0
    assert r["cpu_tot"] == 1000 + 0 + 500 + 8000 + 100 + 0 + 50 + 0 and r["cpu_idle"] == 8000 + 100
    assert r["mem_pct"] == 75.0 and r["load1"] == 0.52
    assert r["rx"] == 1000 and r["tx"] == 500, "ni lo ni veth"
    assert r["conn"] == 3 + 1, "établies : IPv4 (3) + IPv6 (1), pas les écoutes ni les autres états"
    assert 0 <= r["disque_pct"] <= 100


def test_releve_illisible_ne_leve_pas(tmp_path):
    r = serie.releve(tmp_path / "absent", racine=str(tmp_path), maintenant=5.0)
    assert r["t"] == 5.0 and r["cpu_tot"] is None and r["mem_pct"] is None and r["rx"] is None


def test_ajout_et_retention(tmp_path):
    f = tmp_path / "s.jsonl"
    serie.ajoute({"t": 100.0}, f, maintenant=100.0)
    serie.ajoute({"t": 100.0 + serie.RETENTION_S + 7200}, f, maintenant=100.0 + serie.RETENTION_S + 7200)
    lignes = [json.loads(x) for x in f.read_text().splitlines()]
    assert [x["t"] for x in lignes] == [100.0 + serie.RETENTION_S + 7200], "ce qui a plus de 7 jours est écarté"


def test_une_ligne_corrompue_est_ignoree(tmp_path):
    f = tmp_path / "s.jsonl"
    f.write_text('{"t": 1.0}\nn importe quoi\n{"t": 2.0}\n')
    assert [x["t"] for x in serie.lire(f, 0)] == [1.0, 2.0]


def pts(n, pas=60, base=1000.0):
    """n relevés réguliers : CPU à 50 %, réseau 1000 o/s reçus et 500 o/s émis."""
    return [{"t": base + i * pas, "cpu_tot": 1000 * (i + 1), "cpu_idle": 500 * (i + 1), "mem_pct": 40.0 + i, "load1": 1.0, "rx": 1000 * pas * i, "tx": 500 * pas * i,
             "conn": 10 + i, "disque_pct": 60.0} for i in range(n)]


def test_vue_deduit_cpu_et_debits_des_compteurs(tmp_path):
    f = tmp_path / "s.jsonl"
    for p in pts(6):
        serie.ajoute(p, f, maintenant=p["t"])
    v = serie.vue(3600, 6, f, maintenant=1000.0 + 5 * 60)
    s = v["series"]
    assert set(s) == {"cpu", "mem", "charge", "rx", "tx", "conn", "disque"}
    valides = [x for x in s["cpu"] if x is not None]
    assert valides and all(abs(x - 50.0) < 0.01 for x in valides)
    assert all(abs(x - 1000.0) < 0.01 for x in s["rx"] if x is not None) and all(abs(x - 500.0) < 0.01 for x in s["tx"] if x is not None)
    assert len(v["t"]) == len(s["cpu"]) == 6


def test_un_compteur_qui_repart_de_zero_donne_un_trou(tmp_path):
    f = tmp_path / "s.jsonl"
    a = pts(4)
    a[3]["rx"] = 5.0
    a[3]["cpu_tot"] = 10
    for p in a:
        serie.ajoute(p, f, maintenant=p["t"])
    v = serie.vue(3600, 12, f, maintenant=1000.0 + 3 * 60)
    assert all(x is None or 0 <= x <= 100 for x in v["series"]["cpu"])
    assert all(x is None or x >= 0 for x in v["series"]["rx"])


def test_fenetre_et_nombre_de_points_bornes(tmp_path):
    f = tmp_path / "s.jsonl"
    for p in pts(300, pas=60):
        serie.ajoute(p, f, maintenant=p["t"])
    v = serie.vue(3600, 10_000, f, maintenant=1000.0 + 299 * 60)
    assert len(v["t"]) <= serie.MAX_POINTS
    assert v["t"][0] >= 1000.0 + 299 * 60 - 3600 - 61
    v = serie.vue(10, 5, f, maintenant=1000.0 + 299 * 60)          # fenêtre trop courte : plancher
    assert v["duree_s"] >= serie.MIN_DUREE_S


def test_moyenne_par_tranche_et_intervalle_personnalise(tmp_path):
    f = tmp_path / "s.jsonl"
    for p in pts(40):
        serie.ajoute(p, f, maintenant=p["t"])
    v = serie.vue(None, 8, f, depuis=1000.0 + 10 * 60, jusqua=1000.0 + 30 * 60)
    assert v["t"][0] >= 1000.0 + 10 * 60 - 1 and v["t"][-1] <= 1000.0 + 30 * 60 + 1
    assert v["pas_s"] > 60, "tranches plus larges que le relevé : moyennes"


def test_historique_vide(tmp_path):
    v = serie.vue(3600, 20, tmp_path / "rien.jsonl", maintenant=5000.0)
    assert v["t"] and all(x is None for x in v["series"]["cpu"]) and v["points"] == 0


def test_la_route_est_en_lecture_et_valide_ses_parametres():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text()
    i = src.index('@app.get("/api/v1/metrics/series"')
    bloc = src[i:i + 900]
    assert "require_lecture" in bloc and "serie.vue" in bloc


def test_unites_systemd_et_paquet():
    ici = Path(__file__).resolve().parents[1]
    s = (ici / "systemd" / "secubox-metrics-serie.service").read_text()
    assert "User=secubox" in s and "ExecStart=/usr/bin/python3 -m api.serie" in s and "NoNewPrivileges=true" in s and "MemoryMax=" in s
    assert "OnUnitActiveSec=1min" in (ici / "systemd" / "secubox-metrics-serie.timer").read_text()
    assert "secubox-metrics-serie.timer" in (ici / "debian" / "rules").read_text() and "secubox-metrics-serie.timer" in (ici / "debian" / "postinst").read_text()


def test_jamais_plus_de_tranches_que_de_releves_possibles(tmp_path):
    """RÉGRESSION (#2770) : 300 tranches de 12 s sur une heure avec un relevé par minute -> chaque point isolé, aucune courbe dessinable."""
    f = tmp_path / "s.jsonl"
    for p in pts(61):
        serie.ajoute(p, f, maintenant=p["t"])
    v = serie.vue(3600, 300, f, maintenant=1000.0 + 60 * 60)
    assert len(v["t"]) <= 60 and v["pas_s"] >= serie.PAS_S
    cpu = v["series"]["cpu"]
    assert sum(1 for x in cpu if x is not None) >= len(cpu) - 2, "sans trou : une tranche par relevé"


def test_un_intervalle_court_garde_au_moins_deux_tranches(tmp_path):
    f = tmp_path / "s.jsonl"
    for p in pts(5):
        serie.ajoute(p, f, maintenant=p["t"])
    v = serie.vue(60, 300, f, maintenant=1000.0 + 4 * 60)
    assert len(v["t"]) >= 2
