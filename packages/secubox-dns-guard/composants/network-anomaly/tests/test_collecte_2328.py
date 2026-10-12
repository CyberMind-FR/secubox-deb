# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2328 : un passage de collecte écrit l'historique des métriques (la base des lignes de base) ; un échec est dit, jamais silencieux ; l'unité et le minuteur existent et sont durcis."""
from pathlib import Path

from api import collecte as C
from api.main import AnomalyDetector

DEBIAN = Path(__file__).resolve().parents[1] / "debian"


def test_un_passage_ecrit_l_historique_des_metriques(tmp_path):
    d = AnomalyDetector(tmp_path)
    assert not list((tmp_path / "metrics").glob("*.jsonl"))
    res = C.collecter(d)
    assert "alertes" in res
    fichiers = {f.name for f in (tmp_path / "metrics").glob("*.jsonl")}
    assert "tcp_connections.jsonl" in fichiers and "listening_ports.jsonl" in fichiers


def test_deux_passages_allongent_l_historique(tmp_path):
    d = AnomalyDetector(tmp_path)
    C.collecter(d)
    C.collecter(d)
    assert len((tmp_path / "metrics" / "tcp_connections.jsonl").read_text().splitlines()) == 2


def test_un_echec_est_dit_et_rend_un_code_d_erreur(monkeypatch, capsys):
    class Casse:
        def run_detection(self):
            raise RuntimeError("ss absent")
    monkeypatch.setattr(C, "collecter", lambda detector=None: C.__dict__["collecter"].__wrapped__(Casse()) if False else (_ for _ in ()).throw(RuntimeError("ss absent")))
    assert C.main() == 1
    assert "collecte en échec" in capsys.readouterr().err


def test_l_unite_et_le_minuteur_existent_et_sont_durcis():
    u = (DEBIAN / "secubox-network-anomaly-collecte.service").read_text(encoding="utf-8")
    t = (DEBIAN / "secubox-network-anomaly-collecte.timer").read_text(encoding="utf-8")
    assert "Type=oneshot" in u and "User=secubox" in u and "NoNewPrivileges=true" in u and "ProtectSystem=strict" in u
    assert "ReadWritePaths=/var/lib/secubox/network-anomaly" in u and "-m api.collecte" in u
    assert "OnUnitActiveSec=1min" in t and "WantedBy=timers.target" in t
    regles = (Path(__file__).resolve().parents[3] / "debian" / "rules").read_text(encoding="utf-8")
    assert "secubox-network-anomaly-collecte.timer" in regles and "secubox-network-anomaly-collecte.service" in regles


# ── #2459 : les lignes de base se construisent seules ─────────────────────────────────────────────────────────────────────────────────────────
import json  # noqa: E402
from datetime import datetime, timedelta  # noqa: E402


def _historique(d, metrique, valeurs, depuis_min=0):
    f = d.metrics_dir / f"{metrique}.jsonl"
    n = len(valeurs)
    with open(f, "w") as h:
        for i, v in enumerate(valeurs):
            ts = (datetime.utcnow() - timedelta(minutes=depuis_min + n - i)).isoformat() + "Z"
            h.write(json.dumps({"value": v, "timestamp": ts}) + "\n")


def test_sans_ligne_de_base_une_collecte_en_construit_une(tmp_path):
    d = AnomalyDetector(tmp_path)
    _historique(d, "eth0_rx_bytes", [100.0 + (i % 5) for i in range(40)])
    assert d.baselines == {}
    assert C.maj_lignes_de_base(d) == 1
    assert d.baselines["eth0_rx_bytes"].sample_count == 40
    assert (tmp_path / "baselines.json").exists()                              # écrite pour l'API, qui est un autre processus


def test_historique_trop_court_ne_construit_rien(tmp_path):
    d = AnomalyDetector(tmp_path)
    _historique(d, "m", [1.0] * 10)
    assert C.maj_lignes_de_base(d) == 0 and d.baselines == {}                   # 30 échantillons au moins : pas de statistique sur trois points


def test_ligne_de_base_recente_n_est_pas_recalculee(tmp_path):
    d = AnomalyDetector(tmp_path)
    _historique(d, "m", [float(i % 7) for i in range(40)])
    assert C.maj_lignes_de_base(d) == 1
    assert C.maj_lignes_de_base(d) == 0                                         # fraîche : on ne la recalcule pas à chaque minute
    d.baselines["m"].last_updated = (datetime.utcnow() - timedelta(hours=2)).isoformat() + "Z"
    assert C.maj_lignes_de_base(d) == 1                                         # périmée : rafraîchie


def test_une_pointe_apres_construction_donne_une_alerte(tmp_path):
    from api.main import AnomalyType
    d = AnomalyDetector(tmp_path)
    _historique(d, "eth0_rx_bytes", [100.0 + (i % 5) for i in range(40)])
    C.maj_lignes_de_base(d)
    assert d.check_anomaly("eth0_rx_bytes", 100000.0, AnomalyType.BANDWIDTH_SPIKE) is not None      # avant : aucune ligne de base, aucune alerte possible


def test_collecter_construit_les_lignes_de_base_avant_la_detection(tmp_path):
    ordre = []

    class Faux:
        baselines = {}
        metrics_dir = tmp_path
        def run_detection(self):
            ordre.append("detection"); return []
    orig = C.maj_lignes_de_base
    C.maj_lignes_de_base = lambda det, **k: ordre.append("lignes") or 0
    try:
        C.collecter(Faux())
    finally:
        C.maj_lignes_de_base = orig
    assert ordre == ["lignes", "detection"]
