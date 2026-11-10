# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""États d'un abonnement (#3647, MIRRORNET_SERVICE_EXCHANGE.md § 4-5) : DÉRIVÉS des faits signés du journal et de
l'horloge, jamais stockés comme vérité. Fonction pure : les tests rejouent toutes les transitions à horloge simulée.

Priorité (la résiliation l'emporte sur le renouvellement, § 5) :
  1. Resilie  : résiliation signée par l'abonné, révocation de l'abonné signée par le fournisseur, fournisseur
                révoqué dans le journal, offre retirée par son fournisseur
  2. Refuse   : SERVICE_REJECT du fournisseur
  3. Demande  : ni approbation automatique (offre en `auto`) ni SERVICE_APPROVE du fournisseur
  4. Expire   : échéance atteinte sans renouvellement valable (signé avant l'échéance alors en cours)
  5. Grace / Suspendu : (abonné seulement) fournisseur injoignable depuis moins / plus de `grace_s`
  6. Actif
Les quotas et les crédits (→ Suspendu) arrivent avec la mesure et le ledger (phase 5).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

ETATS = ("Demande", "Refuse", "Actif", "Grace", "Suspendu", "Expire", "Resilie")
TERMINAUX = frozenset({"Refuse", "Expire", "Resilie"})
EN_COURS = frozenset({"Demande", "Actif", "Grace", "Suspendu"})


def instant(ts: Optional[str]) -> Optional[datetime]:
    if not ts or not isinstance(ts, str):
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@dataclass
class Faits:
    """Faits VÉRIFIÉS (signature, et auteur à la bonne place) d'un abonnement, vus de CE nœud."""
    role: str                                   # « abonne » ou « fournisseur »
    expire_le: Optional[str] = None             # échéance initiale signée par l'abonné (None = sans échéance)
    approbation_auto: bool = False              # dernière offre du fournisseur en approval_mode « auto »
    approuve: bool = False
    rejete: bool = False
    offre_retiree: bool = False
    fournisseur_revoque: bool = False
    resilie_par_abonne: Optional[str] = None    # motif (« » si aucun) ; None = pas de résiliation
    revoque_par_fournisseur: Optional[str] = None
    renouvellements: List[Tuple[str, str]] = field(default_factory=list)   # (renewed_at, expire_le) signés
    grace_s: int = 432000
    echec_fournisseur_depuis: Optional[str] = None   # premier échec de synchronisation depuis le dernier succès


def echeance(expire_le: Optional[str], renouvellements: List[Tuple[str, str]]) -> Optional[datetime]:
    """Même règle que l'annuaire : un renouvellement compte s'il a été signé AU PLUS TARD à l'échéance en cours et
    la repousse ; une période close ne se renouvelle pas."""
    courant = instant(expire_le)
    if courant is None:
        return None
    for fait, neuf in renouvellements:
        f, n = instant(fait), instant(neuf)
        if f and n and f <= courant and n > courant:
            courant = n
    return courant


def deriver(f: Faits, maintenant: datetime) -> Tuple[str, str, Optional[datetime]]:
    """(état, motif, échéance courante)."""
    ech = echeance(f.expire_le, f.renouvellements)
    if f.resilie_par_abonne is not None:
        return "Resilie", ("résilié par l'abonné" + (f" : {f.resilie_par_abonne}" if f.resilie_par_abonne else "")), ech
    if f.revoque_par_fournisseur is not None:
        m = f.revoque_par_fournisseur
        return "Resilie", "abonné révoqué par le fournisseur" + (f" : {m}" if m else ""), ech
    if f.fournisseur_revoque:
        return "Resilie", "fournisseur révoqué dans le journal", ech
    if f.offre_retiree:
        return "Resilie", "offre retirée par le fournisseur", ech
    if f.rejete:
        return "Refuse", "refusé par le fournisseur", ech
    if not (f.approbation_auto or f.approuve):
        return "Demande", "en attente d'approbation du fournisseur", ech
    if ech is not None and maintenant >= ech:
        return "Expire", "échéance atteinte sans renouvellement", ech
    if f.role == "abonne":
        depuis = instant(f.echec_fournisseur_depuis)
        if depuis is not None:
            if maintenant - depuis < timedelta(seconds=max(0, f.grace_s)):
                return "Grace", "fournisseur injoignable : période de grâce", ech
            return "Suspendu", "fournisseur injoignable au-delà de la période de grâce", ech
    return "Actif", "", ech
