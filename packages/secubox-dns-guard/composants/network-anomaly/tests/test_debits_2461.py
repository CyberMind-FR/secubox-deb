# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#2461 — les compteurs cumulatifs (octets d'interface, requêtes DNS) deviennent des DÉBITS avant stockage et détection ; sinon la détection alerte en permanence."""
import json

from api import collecte as C
from api.main import AnomalyDetector, AnomalyType


def test_debit_est_la_difference_sur_le_temps(tmp_path):
    d = AnomalyDetector(tmp_path)
    assert d._en_debit("eth0_rx", 1000, 100.0) is None            # premier passage : pas de référence
    assert d._en_debit("eth0_rx", 7000, 160.0) == 100.0            # 6000 octets en 60 s
    assert (tmp_path / "compteurs.json").exists()                  # l'état survit : un passage planifié = un processus


def test_remise_a_zero_ou_trou_ne_donnent_pas_de_debit_absurde(tmp_path):
    d = AnomalyDetector(tmp_path)
    d._en_debit("x", 5000, 100.0)
    assert d._en_debit("x", 10, 160.0) is None                     # compteur reparti de zéro (redémarrage, interface recréée)
    assert d._en_debit("x", 70, 220.0) == 1.0
    assert d._en_debit("x", 99999, 2000.0) is None                 # plus de 10 min sans mesure : le débit moyen ne dit rien d'une pointe


def test_collecte_stocke_des_debits_jamais_des_compteurs(tmp_path, monkeypatch):
    d = AnomalyDetector(tmp_path)
    monkeypatch.setattr(d, "_get_tcp_connections", lambda: 12)
    monkeypatch.setattr(d, "_get_listening_ports", lambda: 30)
    d.collect_metrics(); d.collect_metrics()
    noms = {f.stem for f in (tmp_path / "metrics").glob("*.jsonl")}
    assert not any(n.endswith(("_rx_bytes", "_tx_bytes")) or n == "dns_queries_total" for n in noms), noms


def test_pointe_de_debit_alerte_mais_un_compteur_qui_grossit_non(tmp_path):
    d = AnomalyDetector(tmp_path)
    from datetime import datetime, timedelta
    f = d.metrics_dir / "eth0_rx_bps.jsonl"
    with open(f, "w") as h:
        for i in range(40):
            h.write(json.dumps({"value": 1000.0 + (i % 5) * 10, "timestamp": (datetime.utcnow() - timedelta(minutes=40 - i)).isoformat() + "Z"}) + "\n")
    C.maj_lignes_de_base(d)
    assert d.check_anomaly("eth0_rx_bps", 5_000_000.0, AnomalyType.BANDWIDTH_SPIKE) is not None
    assert d.check_anomaly("eth0_rx_bps", 1020.0, AnomalyType.BANDWIDTH_SPIKE) is None


def test_migration_retire_les_historiques_de_compteurs_et_leurs_lignes(tmp_path):
    d = AnomalyDetector(tmp_path)
    for n in ("eth0_rx_bytes", "eth0_tx_bytes", "dns_queries_total", "tcp_connections", "eth0_rx_bps"):
        (d.metrics_dir / f"{n}.jsonl").write_text("{}\n")
    from api.main import Baseline
    for n in ("eth0_rx_bytes", "tcp_connections"):
        d.baselines[n] = Baseline(metric=n, mean=1, std_dev=1, min_val=0, max_val=2, sample_count=40, last_updated="2026-10-12T00:00:00Z")
    d._save_baselines()
    assert C.migrer_compteurs(d) == 3
    restes = {f.stem for f in d.metrics_dir.glob("*.jsonl")}
    assert restes == {"tcp_connections", "eth0_rx_bps"} and set(d.baselines) == {"tcp_connections"}
    assert C.migrer_compteurs(d) == 0                              # idempotent
