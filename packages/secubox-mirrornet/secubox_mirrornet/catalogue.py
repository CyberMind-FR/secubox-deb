# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Catalogue fédéré et synchronisation des abonnements (#3647, MIRRORNET_SERVICE_EXCHANGE.md § 3-4).

L'annuaire (propriétaire du journal et de node.key) dépose `mirrornet-export.json` ; ce module le relit, REVÉRIFIE chaque
entrée (liaison did ↔ clé, signature, auteur à la bonne place, champs bornés), puis met à jour l'index local en UNE
transaction : nœuds, offres, abonnements de ce nœud, et un événement (ajout seul) à chaque changement d'état dérivé.
La base reste un index reconstructible : la vérité est le journal.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import abonnements as A
from .verif import DID, canonical_bytes, entree_valide, forme_valide

TAILLE_MAX = 4 * 1024 * 1024        # l'annuaire plafonne ses offres ; MemoryMax=128M pour tout le service
NS = uuid.UUID("6d1f0f5e-3647-4d6b-9a8e-6d6972726f72")       # identifiants locaux déterministes (idempotence)
CLASSES = ("public", "communaute", "specialise", "professionnel", "prive")
MODELES = ("gratuit", "forfait", "usage", "palier", "reciproque", "parraine")
NIVEAUX = ("OBSERVER", "LIMITED", "PARTNER", "TRUSTED", "REVOKED")
_ID = re.compile(r"^[0-9a-f]{16,64}$")
_USAGE = re.compile(r"^[a-z0-9-]{0,32}$")


class ExportIllisible(Exception):
    pass


def lire_export(chemin: Path) -> Dict[str, Any]:
    try:
        with open(chemin, "rb") as f:
            brut = f.read(TAILLE_MAX + 1)
    except FileNotFoundError:
        raise ExportIllisible("export de l'annuaire absent (secubox-annuaire ≥ 0.18 requis)") from None
    except OSError as e:
        raise ExportIllisible(f"export de l'annuaire illisible ({e.__class__.__name__})") from None
    if len(brut) > TAILLE_MAX:
        raise ExportIllisible("export de l'annuaire trop volumineux")
    try:
        d = json.loads(brut)
    except ValueError:
        raise ExportIllisible("export de l'annuaire : JSON invalide") from None
    if not isinstance(d, dict) or d.get("format") != 1 or not isinstance(d.get("entrees"), list):
        raise ExportIllisible("export de l'annuaire : format inattendu")
    return d


def _texte(v: Any, n: int, defaut: str = "") -> Optional[str]:
    if v is None:
        return defaut
    return v if isinstance(v, str) and len(v) <= n else None


def _entier(v: Any, mini: int, maxi: int) -> Tuple[bool, Optional[int]]:
    if v is None:
        return True, None
    return (type(v) is int and mini <= v <= maxi), (v if type(v) is int else None)


def offre_normalisee(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Charge d'une ServiceOffer bornée et typée, ou None (signée ne veut pas dire bien formée)."""
    sid, fournisseur = p.get("service_id"), p.get("provider")
    if not (isinstance(sid, str) and _ID.match(sid) and isinstance(fournisseur, str) and DID.match(fournisseur)):
        return None
    nom, kind, endpoint = _texte(p.get("name"), 80, None), _texte(p.get("kind"), 24, None), _texte(p.get("endpoint"), 256, None)
    desc, version, sonde = _texte(p.get("description"), 500), _texte(p.get("version"), 64, None), _texte(p.get("sonde"), 256, None)
    if not (nom and kind and endpoint) or desc is None:
        return None
    classe = p.get("classe") or "public"
    tarif = p.get("tarif") or {"modele": "gratuit"}
    if classe not in CLASSES or not isinstance(tarif, dict) or tarif.get("modele") not in MODELES:
        return None
    if set(tarif) - {"modele", "credits", "periode_s", "unite"}:
        return None
    ok_c, _ = _entier(tarif.get("credits"), 0, 10 ** 9)
    ok_d, duree = _entier(p.get("duree_s"), 1, 10 * 365 * 86400)
    ok_g, grace = _entier(p.get("grace_s"), 0, 90 * 86400)
    quotas = p.get("quotas") or {}
    compat = p.get("compat") or {}
    if not (ok_c and ok_d and ok_g and isinstance(quotas, dict) and isinstance(compat, dict)):
        return None
    if len(quotas) > 8 or any(not isinstance(k, str) or len(k) > 32 or type(v) is not int or not 0 <= v <= 10 ** 15
                              for k, v in quotas.items()):
        return None
    if len(json.dumps(compat)) > 1024:
        return None
    # Usage déclaré (#3666) : texte court et sobre, sinon aucun — une offre sans usage n'est jamais livrée localement.
    scope = p.get("scope") if isinstance(p.get("scope"), dict) else {}
    usage = scope.get("usage") if isinstance(scope.get("usage"), str) and _USAGE.match(scope["usage"]) else ""
    return {"service_id": sid, "fournisseur": fournisseur, "nom": nom, "kind": kind, "endpoint": endpoint,
            "description": desc, "version": version, "classe": classe, "tarif": tarif, "quotas": quotas,
            "compat": compat, "duree_s": duree, "grace_s": grace, "sonde": sonde,
            "approval_mode": "auto" if p.get("approval_mode") == "auto" else "pending", "usage": usage}


JEUX_MAX = 32


def jeux_normalises(v: Any) -> List[str]:
    """Jeux nommés par un abonnement à un espace (#3659), tels que signés ; toute forme inattendue = aucun jeu."""
    if not isinstance(v, list) or not 1 <= len(v) <= JEUX_MAX or len(set(map(str, v))) != len(v):
        return []
    return list(v) if all(isinstance(x, str) and _ID.match(x) for x in v) else []


def _acceptee(v: Any) -> Dict[str, Any]:
    """Compatibilité figée dans l'abonnement à un espace (#3659) ; forme inattendue = {} (rien n'est servi)."""
    if not isinstance(v, dict) or set(v) - {"compat", "quotas"} or len(json.dumps(v)) > 2048:
        return {}
    return v if isinstance(v.get("compat", {}), dict) and isinstance(v.get("quotas", {}), dict) else {}


_VERIFIEES: set = set()          # (auteur, clé, sig, empreinte de la charge) vérifiés à la passe précédente


def _valide(e: Any, vues: set) -> bool:
    """entree_valide + forme de l'opération, avec cache. La clé couvre la CHARGE (empreinte de sa forme canonique) :
    une signature réemployée sur une charge modifiée ne retrouve pas le cache, elle est revérifiée — et refusée. Le
    cache ne garde que les clés de la dernière passe (`vues`) : il ne grossit pas au-delà de l'export."""
    if not isinstance(e, dict) or not isinstance(e.get("payload"), dict) or not isinstance(e.get("op"), str):
        return False
    if not forme_valide(e["op"], e["payload"], e.get("author")):
        return False
    try:
        cle = (e.get("author"), e.get("author_pubkey"), e.get("sig"),
               hashlib.sha256(canonical_bytes(e["payload"])).hexdigest())
    except (TypeError, ValueError):
        return False
    if cle in _VERIFIEES or entree_valide(e):
        vues.add(cle)
        return True
    return False


_EMPREINTE = re.compile(r"^b2:[0-9a-f]{64}$")


def version_normalisee(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Manifeste d'une version (#3653), borné et typé, ou None. Vie privée revérifiée À LA RÉCEPTION (§ 6)."""
    ok_n, numero = _entier(p.get("numero"), 1, 10 ** 9)
    ok_t, taille = _entier(p.get("taille"), 0, 2 ** 40)
    ok_f, fraicheur = _entier(p.get("fraicheur_s"), 1, 10 * 365 * 86400)
    empreinte, parent, classe = p.get("empreinte"), p.get("parent", ""), p.get("classe")
    dp = p.get("donnees_personnelles", "non")
    if not (ok_n and numero and ok_t and taille is not None and ok_f and isinstance(empreinte, str)
            and _EMPREINTE.match(empreinte) and isinstance(parent, str) and (parent == "" or _EMPREINTE.match(parent))
            and classe in CLASSES and isinstance(p.get("service_id"), str) and _ID.match(p["service_id"])):
        return None
    if not isinstance(dp, str) or (classe == "public" and dp != "non") or (classe == "communaute" and dp not in ("non", "agregees")):
        return None
    champs = {k: _texte(p.get(k), n, None) for k, n in (("format", 80), ("licence", 64), ("provenance", 160), ("cree_le", 40))}
    if any(v is None for v in champs.values()):
        return None
    return dict(champs, service_id=p["service_id"], fournisseur=p.get("provider"), numero=numero, parent=parent,
                empreinte=empreinte, taille=taille, classe=classe, fraicheur_s=fraicheur, donnees_personnelles=dp[:140])


def _index(entrees: List[Any]) -> Tuple[Dict[str, Any], int]:
    """Entrées vérifiées rangées par objet ; rend (index, nombre d'entrées rejetées)."""
    rejetees = 0
    offres: Dict[str, Dict[str, Any]] = {}
    signatures: Dict[str, str] = {}
    retirees: set = set()
    subs: Dict[str, Dict[str, Any]] = {}
    gestes: List[Dict[str, Any]] = []
    versions: List[Tuple[Dict[str, Any], str, str]] = []
    retraits: set = set()
    vues: set = set()
    for e in entrees:
        if not _valide(e, vues):
            rejetees += 1
            continue
        op, p, auteur = e["op"], e["payload"], e["author"]
        if op == "service_offer":
            o = offre_normalisee(p)
            if o is None or auteur != o["fournisseur"]:
                rejetees += 1
                continue
            deja = offres.get(o["service_id"])
            if deja is not None and deja["fournisseur"] != o["fournisseur"]:
                rejetees += 1                    # un service_id appartient à son PREMIER fournisseur : pas de reprise
                continue
            offres[o["service_id"]] = o          # ordre du journal : la dernière offre du fournisseur l'emporte
            signatures[o["service_id"]] = e["sig"]
        elif op == "service_revoke_offer":
            if isinstance(p.get("service_id"), str) and auteur == p.get("provider"):
                retirees.add((p["service_id"], auteur))
        elif op == "service_subscribe":
            sub_id = p.get("subscription_id")
            if not (isinstance(sub_id, str) and _ID.match(sub_id) and auteur == p.get("subscriber")):
                rejetees += 1
                continue
            subs.setdefault(sub_id, {"p": p, "sig": e["sig"]})
        elif op == "service_dataset_version":
            v = version_normalisee(p)
            if v is None:
                rejetees += 1
                continue
            versions.append((v, e["sig"], auteur))
        elif op == "service_dataset_retract":
            if isinstance(p.get("empreinte"), str) and isinstance(p.get("service_id"), str):
                retraits.add((p["service_id"], p["empreinte"], auteur))
        else:
            gestes.append(e)
    _VERIFIEES.clear()
    _VERIFIEES.update(vues)
    return {"offres": offres, "signatures": signatures, "retirees": retirees, "subs": subs, "gestes": gestes,
            "versions": versions, "retraits": retraits}, rejetees


def _faits(sub_id: str, sub: Dict[str, Any], offre: Dict[str, Any], idx: Dict[str, Any], role: str,
           noeuds: Dict[str, Any], joign: Dict[str, Any], grace_defaut: int) -> A.Faits:
    p = sub["p"]
    abonne, fournisseur = p.get("subscriber"), offre["fournisseur"]
    f = A.Faits(role=role, expire_le=p.get("expire_le") if isinstance(p.get("expire_le"), str) else None,
                demande_le=p.get("requested_at") if isinstance(p.get("requested_at"), str) else None,
                duree_s=offre["duree_s"],
                approbation_auto=offre["approval_mode"] == "auto",
                offre_retiree=(offre["service_id"], fournisseur) in idx["retirees"],
                fournisseur_revoque=(noeuds.get(fournisseur) or {}).get("niveau") == "REVOKED",
                grace_s=offre["grace_s"] if offre["grace_s"] is not None else grace_defaut,
                echec_fournisseur_depuis=(joign.get(fournisseur) or {}).get("echec_depuis"))
    for e in idx["gestes"]:
        g = e["payload"]
        if g.get("subscription_id") != sub_id:
            continue
        op, auteur = e["op"], e["author"]
        motif = g.get("motif") if isinstance(g.get("motif"), str) else ""
        if op == "service_approve" and auteur == fournisseur:
            f.approuve = True
        elif op == "service_reject" and auteur == fournisseur:
            f.rejete = True
        elif op == "service_revoke_sub" and auteur == abonne:
            f.resilie_par_abonne = motif[:200]
        elif op == "service_revoke_offer_sub" and auteur == fournisseur:
            f.revoque_par_fournisseur = motif[:200]
        elif op == "service_renew" and auteur == abonne:
            if isinstance(g.get("renewed_at"), str) and isinstance(g.get("expire_le"), str):
                f.renouvellements.append((g["renewed_at"], g["expire_le"]))
    return f


def _noeud(cx: sqlite3.Connection, did: str, infos: Dict[str, Any], joign: Dict[str, Any], vu_le: str) -> None:
    niveau = infos.get("niveau") if infos.get("niveau") in NIVEAUX else "OBSERVER"
    nom = infos.get("boxname") if isinstance(infos.get("boxname"), str) and infos["boxname"] else did[8:20]
    j = joign.get(did) or {}
    cx.execute(
        "INSERT INTO node(did, nom, mesh_ip, niveau, cause, ok_le, echec_depuis, vu_le) VALUES (?,?,?,?,?,?,?,?) "
        "ON CONFLICT(did) DO UPDATE SET nom=excluded.nom, mesh_ip=excluded.mesh_ip, niveau=excluded.niveau, "
        "cause=excluded.cause, ok_le=excluded.ok_le, echec_depuis=excluded.echec_depuis, vu_le=excluded.vu_le",
        (did, nom[:64], _texte(infos.get("mesh_ip"), 45, None), niveau, _texte(infos.get("cause"), 120) or "",
         _texte(j.get("ok_le"), 40, None), _texte(j.get("echec_depuis"), 40, None), vu_le))


def synchroniser(cx: sqlite3.Connection, export: Dict[str, Any], maintenant: Optional[datetime] = None,
                 grace_defaut: int = 432000) -> Dict[str, Any]:
    """Une passe : index local à jour, événements d'état ajoutés. UNE transaction (BEGIN IMMEDIATE)."""
    maintenant = maintenant or datetime.now(timezone.utc)
    ts = maintenant.isoformat()
    soi = export.get("soi") if isinstance(export.get("soi"), str) and DID.match(export["soi"]) else None
    noeuds = {d: v for d, v in (export.get("noeuds") or {}).items() if isinstance(d, str) and DID.match(d)
              and isinstance(v, dict)}
    joign = {d: v for d, v in (export.get("joignabilite") or {}).items() if isinstance(v, dict)}
    idx, rejetees = _index(export["entrees"])
    stats = {"offres": 0, "abonnements": 0, "rejetees": rejetees, "transitions": 0}
    cx.execute("BEGIN IMMEDIATE")
    try:
        for did, infos in noeuds.items():
            _noeud(cx, did, infos, joign, ts)
        connus = set(noeuds)
        for o in idx["offres"].values():
            if o["fournisseur"] not in connus:
                _noeud(cx, o["fournisseur"], {}, joign, ts)
                connus.add(o["fournisseur"])
            etat = "retiree" if (o["service_id"], o["fournisseur"]) in idx["retirees"] else "publiee"
            cx.execute(
                "INSERT INTO offer(id, ref_annuaire, fournisseur_did, kind, nom, version, classe, tarif, quotas, duree_s, "
                "grace_s, etat, signature, recu_le, endpoint, approval_mode, description, compat, sonde, usage) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ref_annuaire) DO UPDATE SET "
                "kind=excluded.kind, nom=excluded.nom, version=excluded.version, classe=excluded.classe, "
                "tarif=excluded.tarif, quotas=excluded.quotas, duree_s=excluded.duree_s, grace_s=excluded.grace_s, "
                "etat=excluded.etat, signature=excluded.signature, endpoint=excluded.endpoint, "
                "approval_mode=excluded.approval_mode, description=excluded.description, compat=excluded.compat, "
                "sonde=excluded.sonde, usage=excluded.usage WHERE offer.fournisseur_did = excluded.fournisseur_did",
                (str(uuid.uuid5(NS, "offre:" + o["service_id"])), o["service_id"], o["fournisseur"], o["kind"],
                 o["nom"], o["version"], o["classe"], json.dumps(o["tarif"]), json.dumps(o["quotas"]), o["duree_s"],
                 o["grace_s"] if o["grace_s"] is not None else grace_defaut, etat, idx["signatures"][o["service_id"]],
                 ts, o["endpoint"], o["approval_mode"], o["description"], json.dumps(o["compat"]), o["sonde"], o["usage"]))
            stats["offres"] += 1
        for v, sig, auteur in idx["versions"]:
            offre = idx["offres"].get(v["service_id"])
            if offre is None or offre["kind"] != "dataset" or auteur != offre["fournisseur"]:
                stats["rejetees"] += 1          # version d'un autre que le propriétaire, ou d'une offre non « dataset »
                continue
            rang = {c: i for i, c in enumerate(CLASSES)}
            if rang[v["classe"]] < rang.get(offre["classe"], 0) or (
                    v["classe"] in ("specialise", "professionnel") and offre["approval_mode"] != "pending"):
                stats["rejetees"] += 1          # classe moins stricte que l'offre, ou réservée sans approbation manuelle
                continue
            retiree = 1 if (v["service_id"], v["empreinte"], auteur) in idx["retraits"] else 0
            offer_id = str(uuid.uuid5(NS, "offre:" + v["service_id"]))
            pris = cx.execute("SELECT empreinte FROM dataset_version WHERE offer_id = ? AND numero = ?",
                              (offer_id, v["numero"])).fetchone()
            if pris is not None and pris[0] != v["empreinte"]:
                stats["rejetees"] += 1          # deux contenus sous le même numéro : le premier reçu fait foi
                continue
            cx.execute(
                "INSERT INTO dataset_version(id, offer_id, numero, parent, empreinte, taille, format, licence, provenance, "
                "classe, fraicheur_s, donnees_personnelles, cree_le, signature, retiree) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(offer_id, empreinte) DO UPDATE SET retiree = MAX(dataset_version.retiree, excluded.retiree)",
                (str(uuid.uuid5(NS, "version:" + v["service_id"] + v["empreinte"])), offer_id, v["numero"], v["parent"],
                 v["empreinte"], v["taille"], v["format"], v["licence"], v["provenance"], v["classe"], v["fraicheur_s"],
                 v["donnees_personnelles"], v["cree_le"], sig, retiree))
            stats["versions"] = stats.get("versions", 0) + 1
        # Retraits appliqués À PART (#3653, relecture) : une version sortie du plafond de l'export reste connue ici et doit
        # être retirée quand même. Seul le propriétaire de l'offre retire.
        for sid, empreinte, auteur in idx["retraits"]:
            offre = idx["offres"].get(sid)
            if offre is not None and auteur == offre["fournisseur"]:
                cx.execute("UPDATE dataset_version SET retiree = 1 WHERE offer_id = ? AND empreinte = ? AND retiree = 0",
                           (str(uuid.uuid5(NS, "offre:" + sid)), empreinte))
        if soi:
            for sub_id, sub in idx["subs"].items():
                p = sub["p"]
                offre = idx["offres"].get(p.get("service_id"))
                if offre is None:
                    continue
                if p.get("subscriber") == soi:
                    role = "abonne"
                elif offre["fournisseur"] == soi:
                    role = "fournisseur"
                else:
                    continue
                if p.get("provider") is not None and p.get("provider") != offre["fournisseur"]:
                    stats["rejetees"] += 1         # abonnement lié (signé) à un autre fournisseur que le propriétaire
                    continue
                abonne = p["subscriber"]
                if abonne not in connus:
                    _noeud(cx, abonne, {}, joign, ts)
                    connus.add(abonne)
                f = _faits(sub_id, sub, offre, idx, role, noeuds, joign, grace_defaut)
                etat, motif, ech = A.deriver(f, maintenant)
                local = str(uuid.uuid5(NS, "abonnement:" + sub_id))
                tarif = p.get("tarif_accepte") if isinstance(p.get("tarif_accepte"), dict) else {"modele": "gratuit"}
                cx.execute(
                    "INSERT INTO subscription(id, ref_annuaire, abonne_did, offer_id, version, tarif_accepte, expire_le, "
                    "grace_s, role, demande_le, echeance, jeux, compat_acceptee) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(ref_annuaire) DO UPDATE SET echeance=excluded.echeance, grace_s=excluded.grace_s, "
                    "jeux=excluded.jeux, compat_acceptee=excluded.compat_acceptee",
                    (local, sub_id, abonne, str(uuid.uuid5(NS, "offre:" + offre["service_id"])),
                     _texte(p.get("version"), 64, None), json.dumps(tarif)[:1024], f.expire_le, f.grace_s, role,
                     _texte(p.get("requested_at"), 40, None), ech.isoformat() if ech else None,
                     json.dumps(jeux_normalises(p.get("jeux")) if offre["kind"] == "espace" else []),
                     json.dumps(_acceptee(p.get("compat_acceptee")) if offre["kind"] == "espace" else {})))
                dernier = cx.execute("SELECT vers FROM subscription_event WHERE subscription_id = ? "
                                     "ORDER BY ts DESC, rowid DESC LIMIT 1", (local,)).fetchone()
                if dernier is None or dernier[0] != etat:
                    cx.execute("INSERT INTO subscription_event(id, subscription_id, de, vers, motif, ts) "
                               "VALUES (?,?,?,?,?,?)", (str(uuid.uuid4()), local, dernier[0] if dernier else None,
                                                        etat, motif, ts))
                    stats["transitions"] += 1
                stats["abonnements"] += 1
        if soi:
            stats["relais"] = _relais(cx, idx, soi, noeuds, joign, grace_defaut, maintenant, connus, ts)
        hauteur = export.get("hauteur") if type(export.get("hauteur")) is int else None
        cx.execute("INSERT INTO synchro(id, le, soi, export_le, hauteur, offres, abonnements, rejetees, erreur) "
                   "VALUES (1,?,?,?,?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET le=excluded.le, soi=excluded.soi, "
                   "export_le=excluded.export_le, hauteur=excluded.hauteur, offres=excluded.offres, "
                   "abonnements=excluded.abonnements, rejetees=excluded.rejetees, erreur=NULL",
                   (ts, soi, _texte(export.get("genere_le"), 40, None), hauteur, stats["offres"],
                    stats["abonnements"], rejetees))
        cx.execute("COMMIT")
    except BaseException:
        cx.execute("ROLLBACK")
        raise
    return stats


def _relais(cx: sqlite3.Connection, idx: Dict[str, Any], soi: str, noeuds: Dict[str, Any], joign: Dict[str, Any],
            grace_defaut: int, maintenant: datetime, connus: set, ts: str) -> int:
    """Abonnements d'AUTRES nœuds (#3661), reconstruits à chaque passe dans la transaction de synchronisation :
    - répliques : abonnement d'un producteur P à l'espace d'un gardien G, nommant un jeu dont P est le fournisseur ;
    - abonnés relayés : abonnement d'un tiers à un jeu (servi par mes copies si ce jeu est confié à mes espaces).
    État dérivé vu du fournisseur (pas de grâce : c'est l'abonnement lui-même qui compte)."""
    cx.execute("DELETE FROM replique")
    cx.execute("DELETE FROM abonne_relaye")
    n = 0
    for sub_id, sub in idx["subs"].items():
        p = sub["p"]
        offre = idx["offres"].get(p.get("service_id"))
        if offre is None or soi in (p.get("subscriber"), offre["fournisseur"]):
            continue
        if p.get("provider") is not None and p.get("provider") != offre["fournisseur"]:
            continue
        etat, _motif, _ech = A.deriver(_faits(sub_id, sub, offre, idx, "fournisseur", noeuds, joign, grace_defaut),
                                       maintenant)
        if offre["kind"] == "espace":
            for jeu in jeux_normalises(p.get("jeux")):
                d = idx["offres"].get(jeu)
                if d is None or d["kind"] != "dataset" or d["fournisseur"] != p["subscriber"]:
                    continue                    # seul le producteur confie SON jeu
                for did in (offre["fournisseur"], p["subscriber"]):
                    if did not in connus:
                        _noeud(cx, did, {}, joign, ts)
                        connus.add(did)
                cx.execute("INSERT OR IGNORE INTO replique(sub_ref, offer_id, gardien_did, producteur_did, etat) "
                           "VALUES (?,?,?,?,?)", (sub_id, str(uuid.uuid5(NS, "offre:" + jeu)), offre["fournisseur"],
                                                  p["subscriber"], etat))
                n += 1
        elif offre["kind"] == "dataset":
            cx.execute("INSERT OR IGNORE INTO abonne_relaye(sub_ref, abonne_did, offer_id, etat) VALUES (?,?,?,?)",
                       (sub_id, p["subscriber"], str(uuid.uuid5(NS, "offre:" + offre["service_id"])), etat))
            n += 1
    return n


def noter_erreur(cx: sqlite3.Connection, erreur: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    cx.execute("INSERT INTO synchro(id, le, erreur) VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET le=excluded.le, "
               "erreur=excluded.erreur", (ts, erreur[:200]))
