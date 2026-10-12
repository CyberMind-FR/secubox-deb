# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Collecte périodique de network-anomaly (#2328).

La collecte (`collect_metrics`, `run_detection`) n'était déclenchée que par `POST /detect`, à la main : aucune métrique ne remontait, la page restait vide, les lignes de base ne se
construisaient jamais (`/var/lib/secubox/network-anomaly/metrics` vide depuis mai). Un passage, lancé chaque minute par `secubox-network-anomaly-collecte.timer` : il mesure, stocke
l'historique (la base des lignes de base) et enregistre les alertes. Un passage qui échoue le dit sur stderr et sort en erreur : jamais de silence.
"""
import json
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, Optional


def maj_lignes_de_base(detector, heures: int = 24, periode_s: int = 3600, minimum: int = 30) -> int:
    """Construit puis rafraîchit les lignes de base à partir de l'historique (#2459).

    Sans ligne de base `check_anomaly` rend toujours None : la détection ne pouvait JAMAIS alerter, la construction n'étant déclenchée que par un POST manuel.
    Une métrique n'a sa ligne qu'avec `minimum` échantillons (une statistique sur quelques points n'est pas une référence) ; une ligne récente (moins de
    `periode_s`) n'est pas recalculée à chaque minute. Rend le nombre de lignes construites ou rafraîchies."""
    n = 0
    maintenant = datetime.utcnow()
    for f in sorted(detector.metrics_dir.glob("*.jsonl")):
        metrique = f.stem
        b = detector.baselines.get(metrique)
        if b is not None:
            try:
                age = (maintenant - datetime.fromisoformat(str(b.last_updated).rstrip("Z"))).total_seconds()
            except ValueError:
                age = periode_s + 1
            if age < periode_s:
                continue
        valeurs = detector._get_metric_history(metrique, heures)
        if len(valeurs) < minimum:
            continue
        detector.update_baseline(metrique, valeurs)
        n += 1
    return n


def collecter(detector=None) -> Dict[str, Any]:
    """Un passage : rend {alertes: n}. `detector` injectable (tests)."""
    if detector is None:
        from .main import detector as defaut      # importé ici : `python -m api.collecte` ne charge pas l'application tant qu'on n'en a pas besoin
        detector = defaut
    maj_lignes_de_base(detector)                   # AVANT la détection : la première pointe suivante peut alerter
    alertes = detector.run_detection()             # mesure (collect_metrics) PUIS détection ; l'historique est stocké par la mesure
    return {"alertes": len(alertes)}


def main(argv: Optional[list] = None) -> int:
    try:
        res = collecter()
    except Exception as e:  # noqa: BLE001 — une tâche planifiée journalise et sort en erreur
        print(f"network-anomaly : collecte en échec : {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
