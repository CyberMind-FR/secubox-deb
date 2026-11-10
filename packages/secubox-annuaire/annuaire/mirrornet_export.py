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
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import confiance
from .verbs import _get_nodes, export_entries

FORMAT = 1
CHEMIN_DEFAUT = Path("/var/lib/secubox/annuaire/mirrornet-export.json")
_OPS_ABONNEMENT = {"service_subscribe", "service_approve", "service_reject", "service_revoke_sub",
                   "service_renew", "service_revoke_offer_sub"}


OFFRES_PAR_FOURNISSEUR = 64          # plafond (déni de service : un pair qui inonde le journal de ses offres)


def hauteur_pertinente(journal) -> int:
    """Dernière hauteur parmi ce que l'export lit (opérations service_*, identités, nœuds, révocations) : l'export
    n'est recalculé que si elle bouge, pas à chaque entrée d'assistance ingérée."""
    con = journal._connect()
    try:
        r = con.execute("SELECT MAX(height) FROM log WHERE substr(op, 1, 8) = 'service_' "
                        "OR payload_type IN ('Identity', 'NodeRecord', 'RevocationNotice')").fetchone()
        return int(r[0] or 0)
    finally:
        con.close()


def construire(journal, soi: Optional[str], joignabilite_ip: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    entrees = export_entries(journal, ("service_",))
    niv = confiance.niveaux(journal)
    # Un service_id appartient au PREMIER fournisseur qui l'a signé (même règle que verbs._get_offers).
    fournisseur: Dict[str, str] = {}
    for e in entrees:
        if e["op"] == "service_offer" and e["author"] == e["payload"].get("provider"):
            fournisseur.setdefault(e["payload"].get("service_id"), e["author"])
    miens = {e["payload"].get("subscription_id") for e in entrees
             if e["op"] == "service_subscribe"
             and soi in (e["payload"].get("subscriber"), fournisseur.get(e["payload"].get("service_id")))}
    sids_miens = {e["payload"].get("service_id") for e in entrees
                  if e["op"] == "service_subscribe" and e["payload"].get("subscription_id") in miens}
    # Offres gardées : propriétaire légitime, fournisseur ni OBSERVER ni REVOKED (sauf nos propres abonnements, pour
    # en voir la fin), au plus OFFRES_PAR_FOURNISSEUR identifiants par fournisseur (les plus récents).
    par_fournisseur: Dict[str, List[str]] = {}
    for e in entrees:
        if e["op"] == "service_offer":
            sid = e["payload"].get("service_id")
            if fournisseur.get(sid) == e["author"]:
                liste = par_fournisseur.setdefault(e["author"], [])
                if sid in liste:
                    liste.remove(sid)
                liste.append(sid)
    gardes = set(sids_miens)
    for did, sids in par_fournisseur.items():
        if niv.get(did, ("OBSERVER",))[0] not in ("OBSERVER", "REVOKED"):
            gardes.update(sids[-OFFRES_PAR_FOURNISSEUR:])
    gardees = []
    for e in entrees:
        op, p = e["op"], e["payload"]
        if op == "service_offer":
            if p.get("service_id") in gardes and fournisseur.get(p.get("service_id")) == e["author"]:
                gardees.append(e)
        elif op == "service_revoke_offer":
            if p.get("service_id") in gardes and fournisseur.get(p.get("service_id")) == e["author"]:
                gardees.append(e)
        elif p.get("subscription_id") in miens:
            gardees.append(e)
    noeuds: Dict[str, Dict[str, Any]] = {}
    dids_par_ip: Dict[str, set] = {}
    for n in _get_nodes(journal):
        did = n.get("did")
        if not did:
            continue
        noeuds[did] = {"boxname": n.get("boxname"), "mesh_ip": n.get("mesh_ip")}
        if n.get("mesh_ip"):
            dids_par_ip.setdefault(n["mesh_ip"], set()).add(did)
    for did, (niveau, cause) in niv.items():
        noeuds.setdefault(did, {"boxname": None, "mesh_ip": None}).update({"niveau": niveau, "cause": cause})
    for d in noeuds.values():
        d.setdefault("niveau", "OBSERVER")
        d.setdefault("cause", "inconnu du journal")
    # Joignabilité : l'adresse est DÉCLARÉE par le nœud ; une adresse revendiquée par plusieurs dids ne prouve rien.
    ip_vers_did = {ip: next(iter(ds)) for ip, ds in dids_par_ip.items() if len(ds) == 1}
    joignabilite = {ip_vers_did[ip]: dict(v) for ip, v in joignabilite_ip.items() if ip in ip_vers_did}
    return {"format": FORMAT, "soi": soi, "entrees": gardees, "noeuds": noeuds, "joignabilite": joignabilite,
            "_ip_vers_did": ip_vers_did}


def ecrire(donnees: Dict[str, Any], chemin: Path = CHEMIN_DEFAUT) -> bool:
    """Dépose l'export si son contenu (hors date) a changé. Rend True quand le fichier a été réécrit."""
    donnees = {k: v for k, v in donnees.items() if not k.startswith("_")}
    # La hauteur bouge à chaque entrée ingérée (assistance comprise) : hors empreinte, elle ne force pas la réécriture.
    corps = json.dumps({k: v for k, v in donnees.items() if k != "hauteur"}, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False)
    empreinte = hashlib.sha256(corps.encode()).hexdigest()
    try:
        ancien = json.loads(chemin.read_text(encoding="utf-8"))
        if ancien.get("empreinte") == empreinte:
            return False
    except FileNotFoundError:
        pass
    except (OSError, ValueError, AttributeError) as e:
        logging.getLogger("secubox.annuaire").debug("export MirrorNet précédent illisible : %s", e)
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
