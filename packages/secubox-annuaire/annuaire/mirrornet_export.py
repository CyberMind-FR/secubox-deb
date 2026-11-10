# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Export de l'annuaire vers secubox-mirrornet (#3647).

secubox-mirrornet tourne sous un compte dédié : il ne lit ni `node.key` ni le journal. L'annuaire (compte `secubox`,
propriétaire du journal) dépose après chaque synchronisation un fichier PUBLIC au sens du maillage — des objets signés
que tout pair peut déjà tirer par /log/export — que MirrorNet relit et REVÉRIFIE (signature, liaison did ↔ clé) :

    {"format": 1, "soi": did, "genere_le": ts, "hauteur": n,
     "entrees": [{op, payload_type, payload, author, author_pubkey, sig}],   # offres de tous ; abonnements de soi
     "noeuds": {did: {"boxname", "mesh_ip", "niveau", "cause"}},
     "joignabilite": {did: {"ok_le", "echec_depuis"}}}

Seuls les abonnements où CE nœud est abonné ou fournisseur sont exportés : qui est abonné à quoi chez les autres ne
regarde pas MirrorNet. Écriture atomique (temporaire + rename), 0640, et seulement si le contenu change.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from . import confiance
from .verbs import _get_nodes, export_entries

FORMAT = 1
CHEMIN_DEFAUT = Path("/var/lib/secubox/annuaire/mirrornet-export.json")
_OPS_ABONNEMENT = {"service_subscribe", "service_approve", "service_reject", "service_revoke_sub",
                   "service_renew", "service_revoke_offer_sub"}


def construire(journal, soi: Optional[str], joignabilite_ip: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    entrees = export_entries(journal, ("service_",))
    fournisseur = {e["payload"].get("service_id"): e["payload"].get("provider") for e in entrees
                   if e["op"] == "service_offer" and e["author"] == e["payload"].get("provider")}
    miens = {e["payload"].get("subscription_id") for e in entrees
             if e["op"] == "service_subscribe"
             and soi in (e["payload"].get("subscriber"), fournisseur.get(e["payload"].get("service_id")))}
    gardees = [e for e in entrees
               if e["op"] not in _OPS_ABONNEMENT or e["payload"].get("subscription_id") in miens]
    niv = confiance.niveaux(journal)
    noeuds: Dict[str, Dict[str, Any]] = {}
    ip_vers_did: Dict[str, str] = {}
    for n in _get_nodes(journal):
        did = n.get("did")
        if not did:
            continue
        noeuds[did] = {"boxname": n.get("boxname"), "mesh_ip": n.get("mesh_ip")}
        if n.get("mesh_ip"):
            ip_vers_did[n["mesh_ip"]] = did
    for did, (niveau, cause) in niv.items():
        noeuds.setdefault(did, {"boxname": None, "mesh_ip": None}).update({"niveau": niveau, "cause": cause})
    for d in noeuds.values():
        d.setdefault("niveau", "OBSERVER")
        d.setdefault("cause", "inconnu du journal")
    joignabilite = {ip_vers_did[ip]: dict(v) for ip, v in joignabilite_ip.items() if ip in ip_vers_did}
    return {"format": FORMAT, "soi": soi, "entrees": gardees, "noeuds": noeuds, "joignabilite": joignabilite}


def ecrire(donnees: Dict[str, Any], chemin: Path = CHEMIN_DEFAUT) -> bool:
    """Dépose l'export si son contenu (hors date) a changé. Rend True quand le fichier a été réécrit."""
    corps = json.dumps(donnees, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    empreinte = hashlib.sha256(corps.encode()).hexdigest()
    try:
        ancien = json.loads(chemin.read_text(encoding="utf-8"))
        if ancien.get("empreinte") == empreinte:
            return False
    except (OSError, ValueError, AttributeError):
        pass
    sortie = dict(donnees, empreinte=empreinte, genere_le=datetime.now(timezone.utc).isoformat())
    chemin.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".mirrornet-export.", dir=str(chemin.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sortie, f, ensure_ascii=False, separators=(",", ":"))
        os.chmod(tmp, 0o640)
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return True
