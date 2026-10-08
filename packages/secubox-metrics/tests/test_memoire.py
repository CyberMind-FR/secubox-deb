# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Historique memoire de la box (#2146) : une fuite du noyau doit se voir AVANT la saturation.

Sur gk2, 4,2 Go de memoire noyau non recuperable se sont accumules sans que rien ne le releve :
aucun historique, donc impossible de dire quand ni a quelle vitesse. Le releve est leger (deux
fichiers de /proc), garde 7 jours, et signale les seuils et la croissance."""
import json
import time

import memoire

MEMINFO = """MemTotal:        8113216 kB
MemAvailable:    {avail} kB
SUnreclaim:      {su} kB
SReclaimable:     107000 kB
SwapTotal:      12453000 kB
SwapFree:       {sf} kB
"""


def ecrire(tmp_path, avail=1700000, su=130000, sf=12453000, load="4.50 5.00 6.00 1/900 1234"):
    (tmp_path / "meminfo").write_text(MEMINFO.format(avail=avail, su=su, sf=sf))
    (tmp_path / "loadavg").write_text(load + "\n")
    return str(tmp_path / "meminfo"), str(tmp_path / "loadavg")


def test_le_releve_convertit_en_mo(tmp_path):
    m, l = ecrire(tmp_path)
    r = memoire.releve(m, l, maintenant=1000)
    assert r["t"] == 1000 and r["total_mb"] == 7923
    assert r["slab_unrecl_mb"] == 126 and r["slab_recl_mb"] == 104
    assert r["avail_mb"] == 1660 and r["used_mb"] == 7923 - 1660
    assert r["swap_mb"] == 0 and r["load1"] == 4.5


def test_une_box_saine_ne_leve_aucune_alerte(tmp_path):
    m, l = ecrire(tmp_path)
    assert memoire.alertes(memoire.releve(m, l)) == []


def test_la_memoire_noyau_non_recuperable_leve_une_alerte(tmp_path):
    """4,2 Go sur 7,9 : c'etait la situation de gk2 avant le reboot."""
    m, l = ecrire(tmp_path, su=4294000, avail=240000, sf=6700000)
    a = " | ".join(memoire.alertes(memoire.releve(m, l)))
    assert "noyau" in a and "disponible" in a and "swap" in a


def test_l_historique_est_borne_a_sept_jours(tmp_path):
    f = tmp_path / "memoire.jsonl"
    maintenant = 10 * 86400
    for t in (0, 86400, 5 * 86400, 9 * 86400):
        memoire.ajoute({"t": t, "slab_unrecl_mb": 1}, f, maintenant=maintenant)
    ts = [json.loads(x)["t"] for x in f.read_text().splitlines()]
    assert ts == [5 * 86400, 9 * 86400], "ce qui a plus de 7 jours doit partir"


def test_la_lecture_filtre_par_date_et_ignore_les_lignes_cassees(tmp_path):
    f = tmp_path / "memoire.jsonl"
    f.write_text('{"t": 100, "avail_mb": 1}\nPAS DU JSON\n{"t": 900, "avail_mb": 2}\n')
    assert [r["t"] for r in memoire.lire_historique(f, depuis=500)] == [900]
    assert memoire.lire_historique(tmp_path / "absent.jsonl", depuis=0) == []


def test_la_croissance_se_mesure_en_mo_par_heure():
    serie = [{"t": i * 300, "slab_unrecl_mb": 100 + i * 10} for i in range(13)]   # +10 Mo / 5 min = 120 Mo/h
    assert round(memoire.croissance_mb_h(serie, "slab_unrecl_mb")) == 120
    assert memoire.croissance_mb_h(serie[:2], "slab_unrecl_mb") is None, "deux points ne font pas une tendance"


def test_une_croissance_soutenue_du_noyau_est_signalee_avant_le_seuil(tmp_path):
    """C'est le but : voir la fuite monter a 80 Mo/h, pas la decouvrir a 4 Go."""
    m, l = ecrire(tmp_path, su=300000)          # 293 Mo : sous le seuil absolu
    serie = [{"t": i * 300, "slab_unrecl_mb": 100 + i * 8} for i in range(13)]     # ~96 Mo/h
    a = " | ".join(memoire.alertes(memoire.releve(m, l), serie))
    assert "croit" in a


def test_la_tache_planifiee_ecrit_un_releve_et_journalise_l_alerte(tmp_path, capsys):
    m, l = ecrire(tmp_path, su=4294000)
    f = tmp_path / "h" / "memoire.jsonl"
    assert memoire.main(["--meminfo", m, "--loadavg", l, "--fichier", str(f)]) == 0
    assert json.loads(f.read_text().splitlines()[-1])["slab_unrecl_mb"] > 4000
    assert "ALERTE" in capsys.readouterr().err


def test_la_vue_de_l_api_borne_les_heures_et_porte_alertes_et_croissance(tmp_path):
    f = tmp_path / "memoire.jsonl"
    maintenant = 1_000_000
    for i in range(13):
        memoire.ajoute({"t": maintenant - (12 - i) * 300, "total_mb": 7923, "avail_mb": 1500, "swap_mb": 0,
                        "slab_unrecl_mb": 100 + i * 8}, f, maintenant=maintenant)
    v = memoire.vue(1, f, maintenant=maintenant)
    assert len(v["serie"]) == 13 and v["pas_s"] == memoire.PAS_S
    assert v["croissance_noyau_mb_h"] and v["croissance_noyau_mb_h"] > 50
    assert any("croit" in a for a in v["alertes"])
    assert len(memoire.vue(10_000, f, maintenant=maintenant)["serie"]) == 13, "borne a 7 jours, jamais d'erreur"
    assert memoire.vue(1, tmp_path / "absent.jsonl", maintenant=maintenant) == {
        "serie": [], "alertes": [], "croissance_noyau_mb_h": None, "pas_s": memoire.PAS_S}


def test_la_route_et_le_timer_sont_cables():
    """Ni le releve ni la route ne servent a rien s'ils ne sont ni armes ni exposes (cf. #1311)."""
    from pathlib import Path
    pkg = Path(__file__).resolve().parents[1]
    main = (pkg / "api" / "main.py").read_text()
    assert '"/api/v1/metrics/memory/history"' in main and "memoire.vue(" in main
    route = main.split('"/api/v1/metrics/memory/history"')[1].split("def ")[0]
    assert "require_lecture" in route
    rules = (pkg / "debian" / "rules").read_text()
    assert "secubox-metrics-memoire.timer" in rules and "secubox-metrics-memoire.service" in rules
    assert "enable --now secubox-metrics-memoire.timer" in (pkg / "debian" / "postinst").read_text()
    svc = (pkg / "systemd" / "secubox-metrics-memoire.service").read_text()
    assert "User=secubox" in svc and "StateDirectory=secubox/metrics" in svc and "api.memoire" in svc
    assert "OnUnitActiveSec=5min" in (pkg / "systemd" / "secubox-metrics-memoire.timer").read_text()
