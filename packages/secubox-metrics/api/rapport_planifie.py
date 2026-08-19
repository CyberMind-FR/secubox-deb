# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: metrics :: rapport de fréquentation planifié (#1059)
CyberMind — https://cybermind.fr

Agrège une FAMILLE de vhosts (« anibal-amiot » = .com/.fr/.net fondus par
vhost_stats.famille), en produit le PDF et l'expédie par le relais mail interne.

Conçu pour tourner en tâche `oneshot` déclenchée par un timer systemd — JAMAIS
dans la boucle du module : matplotlib et SMTP sont bloquants, et les avoir sur
la boucle mono-worker a déjà produit des 504 ailleurs (cf. rapport.py).

L'orchestrateur `executer` reçoit ses collaborateurs par injection pour rester
testable sans matplotlib ni SMTP.
"""
from __future__ import annotations

import sys
import tomllib
from pathlib import Path

# Comme api/main.py : rendre les modules voisins (rapport, vhost_stats)
# importables quand la tâche tourne en « python3 -m api.rapport_planifie ».
# Sans effet en test (conftest a déjà posé api/ sur le path).
_ici = str(Path(__file__).resolve().parent)
if _ici not in sys.path:
    sys.path.insert(0, _ici)

# Même fichier que rapport.py / le reste du module.
CONF = Path("/etc/secubox/metrics.toml")

# Ce que la demande #1059 fixe par défaut : la famille anibal-amiot, vers la
# boîte interne gk2, chaque semaine. Tout est surchargeable par config.
DEFAUTS = {
    "famille": "anibal-amiot",
    "destinataire": "gk2@secubox.in",
    "periode": "semaine",
}


def config_planifie() -> dict:
    """Config déclarative `[rapport.planifie]` : quelle famille, à qui, sur
    quelle période. Fichier absent ou illisible → les défauts #1059."""
    c = dict(DEFAUTS)
    try:
        with CONF.open("rb") as f:
            bloc = tomllib.load(f).get("rapport", {}).get("planifie", {})
    except (OSError, ValueError):
        bloc = {}
    for k in DEFAUTS:
        if k in bloc:
            c[k] = bloc[k]
    return c


def resoudre_config(argv, base: dict | None = None) -> dict:
    """Config effective : la config déclarative, dont la période peut être
    surchargée par le premier argument. C'est ce qui laisse UN seul module
    servir le rapport hebdomadaire (période de config) ET le quotidien (« jour »)
    sans dupliquer la config — chaque service passe simplement sa période.
    """
    c = dict(base if base is not None else config_planifie())
    if argv:
        c["periode"] = argv[0]
    return c


def executer(agg, construire_pdf, envoyer, cfg: dict | None = None) -> dict:
    """Agrège la famille, produit le PDF, l'expédie. Retourne le bilan d'envoi.

    `agg`, `construire_pdf`, `envoyer` sont injectés : en production ce sont
    `VhostStatsAggregator()`, `rapport.construire_pdf`, `rapport.envoyer` ; en
    test, des doublures.
    """
    c = cfg or config_planifie()
    # Vue d'ensemble GROUPÉE (familles fondues) + détail de la famille visée :
    # detail() somme déjà tous les domaines de la famille.
    vue = agg.current(c["periode"], grouper=True)
    det = agg.detail(c["famille"], c["periode"])
    pdf = construire_pdf(vue, det)
    return envoyer(pdf, c["destinataire"], c["famille"], c["periode"])


def main(argv=None) -> int:
    """Point d'entrée de la tâche planifiée (service oneshot)."""
    from vhost_stats import VhostStatsAggregator
    import rapport

    cfg = resoudre_config(sys.argv[1:] if argv is None else argv)
    agg = VhostStatsAggregator()
    try:
        res = executer(agg, rapport.construire_pdf, rapport.envoyer, cfg)
    except KeyError as e:
        # Aucune donnée pour la famille sur la période : ce n'est pas une panne
        # (parc neuf, famille absente des journaux) — on le dit sans échouer dur.
        print(f"rapport planifié : aucune donnée pour {e}", file=sys.stderr)
        return 0
    except Exception as e:  # noqa: BLE001 — une tâche planifiée journalise et sort
        print(f"rapport planifié : échec de l'expédition : {e}", file=sys.stderr)
        return 1
    print(f"rapport planifié envoyé à {res.get('destinataire')} "
          f"({res.get('octets')} octets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
