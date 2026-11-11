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

Seuls les abonnements où CE nœud est abonné ou fournisseur sont exportés — plus, depuis #3661, ceux dont il a besoin
comme espace (abonnés des jeux qu'on lui confie) ou comme abonné (espaces qui gardent ses jeux) : le reste ne regarde
pas MirrorNet. Écriture atomique (temporaire + rename), 0640, et seulement si le contenu change.
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
from .verbs import _get_nodes, export_entries, forme_valide

FORMAT = 1
CHEMIN_DEFAUT = Path("/var/lib/secubox/annuaire/mirrornet-export.json")
_OPS_ABONNEMENT = {"service_subscribe", "service_approve", "service_reject", "service_revoke_sub",
                   "service_renew", "service_revoke_offer_sub"}


OFFRES_PAR_FOURNISSEUR = 64          # plafond (déni de service : un pair qui inonde le journal de ses offres)
ABONNEMENTS_PAR_ABONNE = 32
VERSIONS_PAR_JEU = 16
RETRAITS_PAR_JEU = 64


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


def _abonnements_relayes(entrees: List[Dict[str, Any]], fournisseur: Dict[str, str], soi: Optional[str]) -> set:
    """MirrorNet 4c (#3661) : abonnements d'autres nœuds dont CE nœud a besoin, tous déjà signés.

    - Espace : abonnements aux jeux que des producteurs ont confiés à MES offres d'espace (`jeux` de leur abonnement)
      — pour servir une copie au seul abonné Actif du jeu.
    - Abonné : abonnements d'espace (producteur → espace) qui nomment un jeu auquel JE suis abonné — les répliques
      entre lesquelles répartir les transferts.
    Le producteur d'un jeu nommé doit être le signataire de l'abonnement d'espace (revérifié par MirrorNet). Une simple
    demande d'abonnement suffit à recevoir les abonnements d'espace du jeu : assumé, tout membre lit déjà le journal
    complet ; ce filtre borne l'export, il ne cache rien."""
    if not soi:
        return set()
    kind: Dict[str, str] = {}
    for e in entrees:
        p = e["payload"]
        if e["op"] == "service_offer" and fournisseur.get(p.get("service_id")) == e["author"]:
            kind[p.get("service_id")] = p.get("kind")
    subs = [e["payload"] for e in entrees if e["op"] == "service_subscribe"
            and forme_valide(e["op"], e["payload"], e["author"])]

    def jeux(p):
        j = p.get("jeux")
        return {x for x in j if isinstance(x, str)} if isinstance(j, list) and len(j) <= 32 else set()
    espace = [p for p in subs if kind.get(p.get("service_id")) == "espace"]
    confies = set()
    for p in espace:
        if fournisseur.get(p.get("service_id")) == soi:
            confies |= {j for j in jeux(p) if fournisseur.get(j) == p.get("subscriber")}
    mes_jeux = {p.get("service_id") for p in subs if p.get("subscriber") == soi and kind.get(p.get("service_id")) == "dataset"}
    res = {p.get("subscription_id") for p in subs
           if kind.get(p.get("service_id")) == "dataset" and p.get("service_id") in confies}
    res |= {p.get("subscription_id") for p in espace
            if {j for j in jeux(p) if fournisseur.get(j) == p.get("subscriber")} & mes_jeux}
    return res


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
    miens |= _abonnements_relayes(entrees, fournisseur, soi)
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
    # Une seule offre (la dernière) et un seul retrait par service_id ; au plus ABONNEMENTS_PAR_ABONNE abonnements
    # d'un même abonné (les plus récents) avec leurs gestes : la taille de l'export reste bornée quoi qu'un membre signe.
    derniere: Dict[tuple, int] = {}
    for i, e in enumerate(entrees):
        op, p = e["op"], e["payload"]
        if op in ("service_offer", "service_revoke_offer"):
            sid = p.get("service_id")
            if sid in gardes and fournisseur.get(sid) == e["author"] and forme_valide(op, p, e["author"]):
                derniere[(op, sid)] = i
    par_abonne: Dict[str, List[str]] = {}
    for e in entrees:
        if e["op"] == "service_subscribe" and e["payload"].get("subscription_id") in miens \
                and forme_valide(e["op"], e["payload"], e["author"]):
            par_abonne.setdefault(e["author"], []).append(e["payload"]["subscription_id"])
    retenus = {sid for liste in par_abonne.values() for sid in liste[-ABONNEMENTS_PAR_ABONNE:]}
    # Versions de jeux de données (#3653) : celles du propriétaire de l'offre, les VERSIONS_PAR_JEU dernières, et
    # tous leurs retraits (un retrait doit toujours arriver, même pour une version sortie du plafond).
    versions: Dict[str, List[int]] = {}
    for i, e in enumerate(entrees):
        p = e["payload"]
        if (e["op"] == "service_dataset_version" and p.get("service_id") in gardes
                and fournisseur.get(p.get("service_id")) == e["author"] and forme_valide(e["op"], p, e["author"])):
            versions.setdefault(p["service_id"], []).append(i)
    versions_gardees = {i for liste in versions.values() for i in liste[-VERSIONS_PAR_JEU:]}
    # Retraits : UN par (jeu, empreinte), seulement d'une version que le propriétaire a publiée, au plus
    # RETRAITS_PAR_JEU par jeu (les plus récents) — un pair ne gonfle pas l'export à coups de retraits.
    publiees = {(entrees[i]["payload"]["service_id"], entrees[i]["payload"].get("empreinte"))
                for liste in versions.values() for i in liste}
    vus: Dict[tuple, int] = {}
    for i, e in enumerate(entrees):
        p = e["payload"]
        cle = (p.get("service_id"), p.get("empreinte"))
        if (e["op"] == "service_dataset_retract" and cle in publiees and fournisseur.get(cle[0]) == e["author"]
                and forme_valide(e["op"], p, e["author"])):
            vus.setdefault(cle, i)
    par_jeu: Dict[str, List[int]] = {}
    for (sid, _emp), i in vus.items():
        par_jeu.setdefault(sid, []).append(i)
    retraits_gardes = {i for liste in par_jeu.values() for i in sorted(liste)[-RETRAITS_PAR_JEU:]}
    gardees = []
    for i, e in enumerate(entrees):
        op, p = e["op"], e["payload"]
        if op == "service_dataset_version":
            if i in versions_gardees:
                gardees.append(e)
        elif op == "service_dataset_retract":
            if i in retraits_gardes:
                gardees.append(e)
        elif op in ("service_offer", "service_revoke_offer"):
            if derniere.get((op, p.get("service_id"))) == i:
                gardees.append(e)
        elif p.get("subscription_id") in retenus and forme_valide(op, p, e["author"]):
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


_ECRITES: Dict[str, str] = {}        # chemin -> dernière empreinte écrite ou relue par ce processus


def ecrire(donnees: Dict[str, Any], chemin: Path = CHEMIN_DEFAUT) -> bool:
    """Dépose l'export si son contenu (hors date et hauteur) a changé. Rend True quand le fichier a été réécrit.
    L'empreinte déjà écrite est gardée en mémoire : le fichier n'est pas relu ni réanalysé à chaque passe."""
    donnees = {k: v for k, v in donnees.items() if not k.startswith("_")}
    # La hauteur bouge à chaque entrée ingérée (assistance comprise) : hors empreinte, elle ne force pas la réécriture.
    corps = json.dumps({k: v for k, v in donnees.items() if k != "hauteur"}, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False)
    empreinte = hashlib.sha256(corps.encode()).hexdigest()
    cle = str(chemin)
    if _ECRITES.get(cle) == empreinte and chemin.exists():
        return False
    if cle not in _ECRITES:
        try:
            if json.loads(chemin.read_text(encoding="utf-8")).get("empreinte") == empreinte:
                _ECRITES[cle] = empreinte
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
    _ECRITES[cle] = empreinte
    return True
