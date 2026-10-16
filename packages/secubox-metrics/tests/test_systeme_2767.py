# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2767 — /api/v1/metrics/systeme : instantané système rapide et non bloquant (alternative à l'API bloquante de Glances).

CPU total et par cœur, mémoire, swap, disques, réseau par interface, capteurs, top des processus — JAMAIS la ligne de commande d'un processus
(elle peut contenir un secret)."""
import json
import time
from pathlib import Path

import systeme


def test_la_mesure_est_rapide_et_ne_bloque_pas():
    systeme.instantane()                       # amorce (les pourcentages de CPU se calculent entre deux appels)
    t = time.monotonic()
    systeme.instantane()
    assert time.monotonic() - t < 0.5, "aucun cpu_percent(interval=…) bloquant"


def test_forme_de_la_reponse():
    systeme.instantane()
    r = systeme.instantane()
    assert set(r) >= {"ts", "cpu", "memoire", "swap", "disques", "reseau", "processus", "charge", "uptime_s"}
    assert isinstance(r["cpu"]["coeurs"], list) and len(r["cpu"]["coeurs"]) >= 1
    assert 0 <= r["cpu"]["total"] <= 100 and all(0 <= c <= 100 for c in r["cpu"]["coeurs"])
    assert 0 <= r["memoire"]["pct"] <= 100 and r["memoire"]["total"] > 0
    assert r["uptime_s"] > 0 and len(r["charge"]) == 3


def test_aucune_ligne_de_commande_ni_utilisateur_dans_les_processus():
    systeme.instantane()
    r = systeme.instantane()
    assert 1 <= len(r["processus"]) <= systeme.TOP_PROCESSUS
    for p in r["processus"]:
        assert set(p) == {"pid", "nom", "cpu", "memoire"}, p
    assert "cmdline" not in json.dumps(r)


def test_processus_tries_par_cpu_decroissant():
    systeme.instantane()
    cpu = [p["cpu"] for p in systeme.instantane()["processus"]]
    assert cpu == sorted(cpu, reverse=True)


def test_disques_sans_systemes_de_fichiers_virtuels():
    d = systeme.instantane()["disques"]
    assert all(x["pct"] >= 0 and x["total"] > 0 for x in d)
    assert not [x for x in d if x["point"].startswith(("/proc", "/sys", "/dev/pts", "/run/user"))]
    assert len({x["point"] for x in d}) == len(d), "un point de montage une seule fois"


def test_reseau_interfaces_physiques_comme_pour_les_connexions():
    r = systeme.instantane()["reseau"]
    noms = [i["nom"] for i in r["interfaces"]]
    assert "lo" not in noms and not [n for n in noms if n.startswith(("veth", "br", "docker"))]
    assert r["total"]["rx"] >= 0 and r["total"]["tx"] >= 0


def test_noms_de_processus_bornes_et_nettoyes():
    assert systeme._nom_propre("a" * 100) == "a" * 40
    assert systeme._nom_propre("bon\x00nom\n") == "bonnom"
    assert systeme._nom_propre(None) == "?"


def test_les_capteurs_absents_ne_cassent_rien(monkeypatch):
    monkeypatch.setattr(systeme.psutil, "sensors_temperatures", lambda *a, **k: (_ for _ in ()).throw(AttributeError()), raising=False)
    assert systeme.instantane()["temperatures"] == []


def test_la_route_est_en_lecture_sans_cache():
    src = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text()
    i = src.index('@app.get("/api/v1/metrics/systeme"')
    bloc = src[i:i + 600]
    assert "require_lecture" in bloc and "no-store" in bloc and "systeme" in bloc
