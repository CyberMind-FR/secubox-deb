# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""« Oublier ce nœud » (#3335) : retire un nœud obsolète du registre des pairs (`peers.json`, donc de la projection
`pairs-enroles.json`) et de l'état wg-mesh (`wg_mesh.json`). Pur calcul : l'appelant écrit les deux fichiers ;
le changement de `wg_mesh.json` déclenche `secubox-p2p-mesh.path` → `sbx-mesh-up` (root), qui retire le pair de
l'interface. Aucun privilège ici, aucune commande `wg`.

Refus : nom invalide, nœud local, `master`, nom inconnu des deux registres, nœud en ligne (poignée de main WireGuard
de moins de `mesh.LIVENESS_MAX_AGE` secondes) sauf `force`."""
from __future__ import annotations

import copy
import re
from typing import Optional

from . import mesh

RE_NOM = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
RESERVES = frozenset({"master"})


class Refus(Exception):
    """Oubli refusé : le message est montré à l'administrateur."""


def oublier(peers_doc, wg_state, nom: str, *, handshakes: Optional[dict], now: float, local: str,
            force: bool = False):
    """(peers_doc, wg_state, {"registre": n, "wg": m}) sans le nœud `nom` ; les entrées d'origine ne sont pas modifiées."""
    if not isinstance(nom, str) or not RE_NOM.fullmatch(nom) or nom in RESERVES or nom == (local or "").lower():
        raise Refus("nom de nœud invalide, local ou réservé")
    peers_doc = copy.deepcopy(peers_doc if isinstance(peers_doc, dict) else {"peers": []})
    wg_state = copy.deepcopy(wg_state if isinstance(wg_state, dict) else {})
    liste = [p for p in peers_doc.get("peers") or [] if isinstance(p, dict)]
    wg = [p for p in wg_state.get("peers") or [] if isinstance(p, dict)]
    a_retirer_wg = [p for p in wg if p.get("name") == nom]
    a_retirer_reg = [p for p in liste if p.get("name") == nom]
    if not a_retirer_wg and not a_retirer_reg:
        raise Refus(f"nœud inconnu : {nom}")
    if not force:
        for p in a_retirer_wg:
            if mesh.peer_liveness(handshakes, str(p.get("public_key") or ""), now) == "online":
                raise Refus(f"{nom} est en ligne : confirmer l'oubli d'un nœud actif (force)")
    peers_doc["peers"] = [p for p in liste if p.get("name") != nom]
    wg_state["peers"] = [p for p in wg if p.get("name") != nom]
    return peers_doc, wg_state, {"registre": len(a_retirer_reg), "wg": len(a_retirer_wg)}
