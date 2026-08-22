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

import signal
import sys
import time
import tomllib
import traceback
from pathlib import Path

# Garde-temps et reprises de la tâche planifiée. Un matin, un run a mis
# ~80 min avant d'échouer (requête ou rendu bloqué) : une tâche quotidienne ne
# doit JAMAIS rester bloquée aussi longtemps, ni échouer en silence sur un
# incident passager.
BUDGET_SECONDES = 180   # au-delà, on coupe net (data/PDF/SMTP confondus)
ESSAIS = 3              # reprises sur incident passager
BACKOFF_SECONDES = 20   # pause croissante entre deux essais


class _GardeTempsDepasse(Exception):
    """Le run a dépassé son budget de temps."""


def _alarme(_signum, _frame):
    raise _GardeTempsDepasse()


def _executer_borne(agg, construire_pdf, envoyer, cfg) -> dict:
    """Exécute `executer` sous un garde-temps SIGALRM — impossible de dépasser
    BUDGET_SECONDES. SIGALRM n'agit que sur le thread principal ; la tâche
    tourne en processus dédié (oneshot), c'est donc le bon cadre."""
    ancien = signal.signal(signal.SIGALRM, _alarme)
    signal.alarm(BUDGET_SECONDES)
    try:
        return executer(agg, construire_pdf, envoyer, cfg)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, ancien)

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
    # Résumé emoji des codes de retour dans le corps du mail (#1131an). Import
    # local de `rapport` comme `main()` — la tâche tourne avec api/ sur le path.
    import rapport
    resume = rapport.resume_statuts((det or {}).get("statuts"))
    return envoyer(pdf, c["destinataire"], c["famille"], c["periode"], resume=resume)


def main(argv=None) -> int:
    """Point d'entrée de la tâche planifiée (service oneshot)."""
    from vhost_stats import VhostStatsAggregator
    import rapport

    cfg = resoudre_config(sys.argv[1:] if argv is None else argv)
    agg = VhostStatsAggregator()
    derniere = "raison inconnue"
    for essai in range(1, ESSAIS + 1):
        try:
            res = _executer_borne(agg, rapport.construire_pdf, rapport.envoyer, cfg)
        except KeyError as e:
            # Aucune donnée pour la famille sur la période : ce n'est pas une
            # panne (parc neuf, famille absente des journaux). On sort SANS
            # échouer ET sans réessayer — réessayer ne ferait pas apparaître des
            # données qui n'existent pas.
            print(f"rapport planifié : aucune donnée pour {e}", file=sys.stderr)
            return 0
        except _GardeTempsDepasse:
            derniere = f"garde-temps dépassé (>{BUDGET_SECONDES}s) — génération ou envoi bloqué"
            print(f"rapport planifié : {derniere} (essai {essai}/{ESSAIS})", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — on JOURNALISE avec la trace, puis on décide
            derniere = f"{type(e).__name__}: {e}"
            print(f"rapport planifié : échec (essai {essai}/{ESSAIS}) : {derniere}\n"
                  f"{traceback.format_exc()}", file=sys.stderr)
        else:
            marque = f" [essai {essai}]" if essai > 1 else ""
            print(f"rapport planifié envoyé à {res.get('destinataire')} "
                  f"({res.get('octets')} octets){marque}")
            return 0
        if essai < ESSAIS:
            time.sleep(BACKOFF_SECONDES * essai)  # pause croissante avant reprise
    print(f"rapport planifié : ÉCHEC définitif après {ESSAIS} essais — {derniere}",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
