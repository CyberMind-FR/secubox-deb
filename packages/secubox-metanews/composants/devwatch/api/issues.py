# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: DevWatch — métriques des issues (#1585).

Rapport complet, fermées, en cours, ouvertes. Les FAITS viennent de la
recherche GitHub (github.py) ; ce module ne fait que les ranger.

« EN COURS » N'EST PAS UNE ÉTIQUETTE QU'ON OUBLIE DE POSER. Une issue ouverte
est en cours quand une branche de travail vivante porte son numéro
(`feature/<N>-…`, `fix/<N>-…` : ce que crée agent-worktree.sh et que la fusion
supprime), ou qu'elle porte l'étiquette `wip`. Les branches sont lues dans le
miroir git local — aucun appel réseau de plus.
"""
from __future__ import annotations

import re
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

BRANCHE = re.compile(r"^(?:feature|fix)/(\d+)-")
ETIQUETTES_EN_COURS = {"wip", "in progress", "en cours"}


def numeros_des_branches(refs: Iterable[str]) -> set[int]:
    """Numéros d'issue portés par des branches de travail (`feature/12-x`)."""
    out = set()
    for r in refs:
        r = r.strip()
        for pref in ("refs/heads/", "heads/"):
            if r.startswith(pref):
                r = r[len(pref):]
        m = BRANCHE.match(r)
        if m:
            out.add(int(m.group(1)))
    return out


def _date(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def rapport(brut: Optional[dict], branches: set[int], maintenant: Optional[datetime] = None) -> dict:
    """Le rapport rendu à la page. `brut` vient de GitHub.issues() (ou None)."""
    if not brut:
        return {"ok": False}
    maintenant = maintenant or datetime.now(timezone.utc)
    ouvertes = []
    for i in brut.get("open", []):
        labels = [str(x) for x in i.get("labels", [])]
        en_cours = i.get("n") in branches or bool(ETIQUETTES_EN_COURS & {x.lower() for x in labels})
        ouvertes.append({**i, "en_cours": en_cours,
                         "branche": i.get("n") in branches})
    en_cours = [i for i in ouvertes if i["en_cours"]]
    fermees = list(brut.get("closed", []))

    # Délai de clôture sur l'échantillon (les dernières fermées).
    delais = []
    for i in fermees:
        c, f = _date(i.get("cree")), _date(i.get("ferme"))
        if c and f and f >= c:
            delais.append((f - c).total_seconds() / 86400)
    mediane = round(statistics.median(delais), 1) if delais else None
    mediane_h = round(statistics.median(delais) * 24, 1) if delais else None

    par_etiquette: dict[str, int] = {}
    for i in ouvertes:
        for l in i.get("labels", []) or ["(sans étiquette)"]:
            par_etiquette[l] = par_etiquette.get(l, 0) + 1

    ancien = min((_date(i.get("cree")) for i in ouvertes if _date(i.get("cree"))), default=None)
    total_ouvertes = brut.get("open_total")
    total_fermees = brut.get("closed_total")
    return {
        "ok": True,
        "compte": {
            "ouvertes": total_ouvertes if total_ouvertes is not None else len(ouvertes),
            "en_cours": len(en_cours),
            "fermees": total_fermees if total_fermees is not None else len(fermees),
            "total": (total_ouvertes or 0) + (total_fermees or 0),
            "fermees_30j": brut.get("closed_30d"),
            "ouvertes_7j": sum(1 for i in ouvertes
                               if (_date(i.get("cree")) or maintenant) >= maintenant - timedelta(days=7)),
        },
        "delai_median_jours": mediane,
        "delai_median_heures": mediane_h,
        "echantillon_fermees": len(fermees),
        "plus_ancienne_jours": round((maintenant - ancien).total_seconds() / 86400) if ancien else None,
        "par_etiquette": dict(sorted(par_etiquette.items(), key=lambda kv: (-kv[1], kv[0]))),
        "listes": {
            "ouvertes": ouvertes,
            "en_cours": en_cours,
            "fermees": fermees,
        },
        "incomplet": len(ouvertes) < (total_ouvertes or 0),
        "definition_en_cours": "branche de travail vivante (feature|fix/<N>-…) ou étiquette wip",
    }
