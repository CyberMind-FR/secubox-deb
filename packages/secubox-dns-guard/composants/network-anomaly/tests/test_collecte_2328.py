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
