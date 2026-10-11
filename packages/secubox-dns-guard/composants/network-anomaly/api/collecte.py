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
from typing import Any, Dict, Optional


def collecter(detector=None) -> Dict[str, Any]:
    """Un passage : rend {metriques: n, alertes: n}. `detector` injectable (tests)."""
    if detector is None:
        from .main import detector as defaut      # importé ici : `python -m api.collecte` ne charge pas l'application tant qu'on n'en a pas besoin
        detector = defaut
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
