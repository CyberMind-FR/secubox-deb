# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Niveaux de confiance MirrorNet (#3647, docs/mirrornet/federated-trust.md § 3) : PROJECTION calculée, jamais stockée.

    révoqué (RevocationNotice autorisée ou Identity REVOKED auto-signée) ........ REVOKED
    pas MEMBER (OBSERVED, inconnu) .............................................. OBSERVER
    MEMBER sans NodeRecord auto-signé (identité non liée au maillage) ........... LIMITED
    MEMBER lié ................................................................... LIMITED

PARTNER et TRUSTED viennent des grants « mirrornet.partenaire » / « mirrornet.confiance » émis par la box maître ancrée :
ils arrivent avec le socle A21 (docs/mirrornet/plan-alpha21.md). D'ici là, aucun nœud n'est élevé au-delà de LIMITED,
et la cause le dit ; on ne présente jamais un niveau qu'on n'a pas calculé.
"""
from __future__ import annotations

from typing import Dict, Tuple

from .verbs import _authorized_revoked_dids, _get_member_dids, _get_nodes

NIVEAUX = ("OBSERVER", "LIMITED", "PARTNER", "TRUSTED", "REVOKED")


def niveaux(journal) -> Dict[str, Tuple[str, str]]:
    """{did: (niveau, cause)} pour chaque did connu du journal (membre, révoqué ou nœud publié)."""
    revoques = _authorized_revoked_dids(journal)
    membres = _get_member_dids(journal)
    lies = {n.get("did") for n in _get_nodes(journal) if n.get("did")}
    res: Dict[str, Tuple[str, str]] = {}
    for did in membres | revoques | lies:
        if did in revoques:
            res[did] = ("REVOKED", "révoqué dans le journal")
        elif did not in membres:
            res[did] = ("OBSERVER", "pas membre")
        elif did not in lies:
            res[did] = ("LIMITED", "membre, identité non liée au maillage")
        else:
            res[did] = ("LIMITED", "membre lié ; PARTNER/TRUSTED par grant au socle A21")
    return res


def niveau(journal, did: str) -> Tuple[str, str]:
    return niveaux(journal).get(did, ("OBSERVER", "inconnu du journal"))
