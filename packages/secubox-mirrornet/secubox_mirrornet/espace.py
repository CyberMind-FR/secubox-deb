# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Espace offert en service et propagation des jeux de données (#3659, phase 4b).

Un nœud publie une offre `kind = espace` : capacité (`quotas.octets`, `quotas.octets_objet`) et compatibilité
(`compat.classes`, `compat.formats`, `compat.licences`, `compat.agregees`), signées. Un PRODUCTEUR s'y abonne en nommant
ses jeux (`jeux`, signés avec l'abonnement). Abonnement Actif : l'espace tire chez le producteur la dernière version
non retirée de chaque jeu nommé, revérifie sa compatibilité et la capacité restante, vérifie l'objet (taille, BLAKE2b)
et le garde. Chaque copie garde sa lignée : origine (producteur), parent (nœud d'où l'objet est venu), version (chaîne
`parent` des manifestes). Une nouvelle version du producteur est tirée à son tour : la mise à jour se refait.

Jamais propagé : professionnel, privé, données personnelles autres qu'agrégées (et agrégées seulement si l'espace les
admet). Contrôle aux deux bouts : le producteur ne sert l'objet qu'à un espace auquel il est abonné pour ce jeu
(`transfert.autoriser`), l'espace refuse ce que sa compatibilité ou sa capacité interdit.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import config, objets, transfert

log = logging.getLogger("secubox-mirrornet")
PROPAGEABLES = ("public", "communaute", "specialise")
TERMINAUX = ("Refuse", "Expire", "Resilie")
_LISTE_MAX = 16
_DERNIER_ETAT = ("(SELECT vers FROM subscription_event e WHERE e.subscription_id = s.id "
                 "ORDER BY e.ts DESC, e.rowid DESC LIMIT 1)")

# Dernier refus par (abonnement local, version) : affiché dans la page, jamais persistant (recalculé à chaque passe).
REFUS: Dict[tuple, str] = {}


def _liste(v: Any) -> List[str]:
    if not isinstance(v, list):
        return []
    return [x for x in v if isinstance(x, str) and 0 < len(x) <= 80][:_LISTE_MAX]


def caracteristiques(compat: Any, quotas: Any) -> Dict[str, Any]:
    """Compatibilité et capacité d'une offre d'espace, bornées. Classes absentes = public seulement ; formats ou
    licences vides = tous ; capacité absente = 0 (rien n'est accepté)."""
    compat = compat if isinstance(compat, dict) else {}
    quotas = quotas if isinstance(quotas, dict) else {}
    classes = [c for c in _liste(compat.get("classes")) if c in PROPAGEABLES] if "classes" in compat else ["public"]
    octets = quotas.get("octets") if type(quotas.get("octets")) is int and quotas["octets"] > 0 else 0
    par_objet = quotas.get("octets_objet")
    par_objet = par_objet if type(par_objet) is int and 0 < par_objet <= octets else octets
    return {"classes": classes, "formats": _liste(compat.get("formats")), "licences": _liste(compat.get("licences")),
            "agregees": compat.get("agregees") is True, "octets": octets, "octets_objet": par_objet}


def refus_version(esp: Dict[str, Any], v: Dict[str, Any]) -> Optional[str]:
    """Motif de refus d'une version par un espace (fonction pure), ou None."""
    classe, dp = v.get("classe"), v.get("donnees_personnelles")
    if not isinstance(dp, str) or not dp:
        return "données personnelles non déclarées"
    if classe not in PROPAGEABLES:
        return f"classe {classe} : jamais propagée vers un espace tiers"
    if classe not in esp["classes"]:
        return f"classe {classe} hors de la compatibilité de l'espace ({', '.join(esp['classes']) or 'aucune'})"
    if dp != "non" and not (dp == "agregees" and esp["agregees"]):
        return "données personnelles : l'espace ne garde que des données sans données personnelles" + (
            "" if dp.startswith("base_legale") else " (ou agrégées, s'il les admet)")
    if esp["formats"] and v.get("format") not in esp["formats"]:
        return f"format {v.get('format')} non admis par l'espace"
    if esp["licences"] and v.get("licence") not in esp["licences"]:
        return f"licence {v.get('licence')} non admise par l'espace"
    if type(v.get("taille")) is not int or v["taille"] > esp["octets_objet"]:
        return f"version de {v.get('taille')} octets au-delà de ce que l'espace admet par objet ({esp['octets_objet']})"
    return None


def _soi(cx: sqlite3.Connection) -> Optional[str]:
    return (cx.execute("SELECT soi FROM synchro WHERE id = 1").fetchone() or [None])[0]


def occupe(cx: sqlite3.Connection, espace_offer_id: str) -> int:
    """Octets gardés pour une offre d'espace (objets distincts, tous producteurs confondus)."""
    return cx.execute(
        "SELECT COALESCE(SUM(x.taille), 0) FROM objet x WHERE x.empreinte IN (SELECT c.empreinte FROM copie c "
        "JOIN subscription s ON s.id = c.subscription_id WHERE s.offer_id = ?)", (espace_offer_id,)).fetchone()[0]


def a_propager(cx: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Versions à garder comme espace : dernière version non retirée de chaque jeu nommé par chaque abonnement Actif
    à une offre d'espace publiée par CE nœud, du producteur abonné lui-même, pas encore copiée pour cet abonnement."""
    soi = _soi(cx)
    if not soi:
        return []
    res = []
    for s in cx.execute(
            "SELECT s.id AS sub, s.ref_annuaire AS sub_ref, s.abonne_did AS producteur, s.jeux, e.id AS espace_id, "
            "e.compat, e.quotas, n.mesh_ip FROM subscription s JOIN offer e ON e.id = s.offer_id "
            "JOIN node n ON n.did = s.abonne_did "
            f"WHERE s.role = 'fournisseur' AND e.kind = 'espace' AND e.fournisseur_did = ? AND e.etat = 'publiee' "
            f"AND {_DERNIER_ETAT} = 'Actif'", (soi,)).fetchall():
        try:
            jeux = json.loads(s["jeux"])
        except ValueError:
            continue
        if not isinstance(jeux, list):
            continue
        for v in cx.execute(
                "SELECT v.id, v.empreinte, v.taille, v.format, v.licence, v.classe, v.donnees_personnelles, v.numero, "
                "o.ref_annuaire AS service_id FROM dataset_version v JOIN offer o ON o.id = v.offer_id "
                "WHERE o.kind = 'dataset' AND o.etat = 'publiee' AND o.fournisseur_did = ? AND v.retiree = 0 "
                "AND o.ref_annuaire IN (SELECT value FROM json_each(?)) "
                "AND v.numero = (SELECT MAX(numero) FROM dataset_version w WHERE w.offer_id = o.id AND w.retiree = 0) "
                "AND NOT EXISTS (SELECT 1 FROM copie c WHERE c.subscription_id = ? AND c.version_id = v.id)",
                (s["producteur"], json.dumps(jeux), s["sub"])):
            res.append(dict(dict(v), sub=s["sub"], sub_ref=s["sub_ref"], producteur=s["producteur"],
                            mesh_ip=s["mesh_ip"], espace_id=s["espace_id"],
                            espace=caracteristiques(_json(s["compat"]), _json(s["quotas"]))))
    return res


def _json(t: Any) -> Any:
    try:
        return json.loads(t) if isinstance(t, str) else None
    except ValueError:
        return None


def _noter_copie(cx: sqlite3.Connection, t: Dict[str, Any], parent: str) -> None:
    cx.execute("INSERT INTO copie(subscription_id, version_id, empreinte, origine_did, parent_did, recue_le) "
               "VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING",
               (t["sub"], t["id"], t["empreinte"], t["producteur"], parent, datetime.now(timezone.utc).isoformat()))


def propager(cx: sqlite3.Connection, reglages: Dict[str, Any], flux=None) -> Dict[str, int]:
    """Une passe côté espace : au plus UN téléchargement (débit modéré) ; un objet déjà détenu (abonné du même jeu)
    est copié sans transfert, sa lignée gardant le nœud d'où il est venu."""
    flux = flux or transfert._flux
    stats = {"copiees": 0, "refusees": 0, "purgees": 0}
    candidats = a_propager(cx)
    for k in set(REFUS) - {(t["sub"], t["id"]) for t in candidats}:
        REFUS.pop(k, None)                 # version copiée, remplacée ou abonnement clos : le refus n'a plus cours
    for t in candidats:
        cle = (t["sub"], t["id"])
        memo = "copie:" + t["sub"] + t["empreinte"]
        if not transfert._permis(memo):
            continue
        motif = refus_version(t["espace"], t)
        if motif is None and occupe(cx, t["espace_id"]) + t["taille"] > t["espace"]["octets"]:
            motif = f"capacité de l'espace atteinte ({t['espace']['octets']} octets)"
        if motif:
            if REFUS.get(cle) != motif:
                log.warning("mirrornet : copie de %s refusée (jeu %s) : %s", t["empreinte"][:19], t["service_id"][:12], motif)
            REFUS[cle] = motif
            transfert._differer(memo)
            stats["refusees"] += 1
            continue
        REFUS.pop(cle, None)
        deja = cx.execute("SELECT source, taille FROM objet WHERE empreinte = ?", (t["empreinte"],)).fetchone()
        if deja is not None:
            if deja[1] != t["taille"]:              # taille déclarée fausse : ni capacité faussée, ni copie
                REFUS[cle] = "taille déclarée différente de l'objet détenu"
                transfert._differer(memo)
                stats["refusees"] += 1
                continue
            _noter_copie(cx, t, deja[0])
            stats["copiees"] += 1
            continue
        ip = t.get("mesh_ip")
        try:
            if not ip or ipaddress.ip_address(ip) not in transfert.MAILLAGE:
                continue
        except ValueError:
            continue
        try:
            if t["taille"] > reglages["taille_max_mo"] * 1024 * 1024:
                raise objets.RefusObjet(f"version annoncée au-delà du plafond ({reglages['taille_max_mo']} Mio)")
            objets.verifier_espace(t["taille"], reglages["reserve_mo"])
            url = f"http://{ip}:{config.PORT_MAILLAGE}/mirrornet/objets/{t['empreinte']}"
            empreinte, taille = objets.ecrire(flux(url), t["taille"], attendue=t["empreinte"], taille_attendue=t["taille"])
            try:
                cx.execute("BEGIN IMMEDIATE")
                try:
                    objets.noter(cx, empreinte, taille, t["producteur"])
                    _noter_copie(cx, t, t["producteur"])
                    cx.execute("COMMIT")
                except BaseException:
                    cx.execute("ROLLBACK")
                    raise
            except sqlite3.Error:
                # Base occupée : l'objet écrit mais non noté ne resterait jamais sans ligne qui le cite.
                if cx.execute("SELECT 1 FROM objet WHERE empreinte = ?", (empreinte,)).fetchone() is None:
                    objets.chemin(empreinte).unlink(missing_ok=True)
                raise
            stats["copiees"] += 1
            log.info("mirrornet : copie %s gardée (%s octets) du jeu %s pour %s", empreinte[:19], taille,
                     t["service_id"][:12], t["producteur"][8:20])
            break
        except objets.RefusObjet as e:
            stats["refusees"] += 1
            REFUS[cle] = str(e)
            transfert._differer(memo)
            log.warning("mirrornet : copie %s refusée : %s", t["empreinte"][:19], e)
        except OSError as e:
            transfert._differer(memo)
            log.info("mirrornet : producteur %s injoignable pour %s : %s", ip, t["empreinte"][:19], e.__class__.__name__)
    stats["purgees"] = ranger(cx, reglages["garder"])
    return stats


def ranger(cx: sqlite3.Connection, garder: int) -> int:
    """Copies hors d'usage retirées, puis objets qui n'étaient gardés QUE comme copie effacés : version retirée,
    abonnement à l'espace clos (refusé, expiré, résilié), offre d'espace retirée, au-delà des `garder` dernières
    versions d'un jeu pour un abonnement. Jamais un objet déposé ici, ni un objet d'un jeu auquel ce nœud est abonné."""
    soi = _soi(cx)
    if not soi:
        return 0                       # identité de ce nœud inconnue (pas encore synchronisé) : rien n'est effacé
    cx.execute("DELETE FROM copie WHERE version_id IN (SELECT id FROM dataset_version WHERE retiree = 1)")
    cx.execute(f"DELETE FROM copie WHERE subscription_id IN (SELECT s.id FROM subscription s JOIN offer e ON e.id = s.offer_id "
               f"WHERE e.etat = 'retiree' OR {_DERNIER_ETAT} IN ('Refuse', 'Expire', 'Resilie'))")
    for sub, offer_id in cx.execute("SELECT DISTINCT c.subscription_id, v.offer_id FROM copie c "
                                    "JOIN dataset_version v ON v.id = c.version_id").fetchall():
        anciennes = [r[0] for r in cx.execute(
            "SELECT c.version_id FROM copie c JOIN dataset_version v ON v.id = c.version_id "
            "WHERE c.subscription_id = ? AND v.offer_id = ? ORDER BY v.numero DESC", (sub, offer_id))][garder:]
        cx.executemany("DELETE FROM copie WHERE subscription_id = ? AND version_id = ?", [(sub, v) for v in anciennes])
    cx.execute("DELETE FROM copie WHERE empreinte NOT IN (SELECT empreinte FROM objet)")
    seules = [r[0] for r in cx.execute(
        "SELECT x.empreinte FROM objet x WHERE x.source <> ? "
        "AND NOT EXISTS (SELECT 1 FROM copie c WHERE c.empreinte = x.empreinte) "
        "AND EXISTS (SELECT 1 FROM dataset_version v WHERE v.empreinte = x.empreinte) "
        "AND NOT EXISTS (SELECT 1 FROM dataset_version v JOIN subscription s ON s.offer_id = v.offer_id "
        "WHERE v.empreinte = x.empreinte AND s.role = 'abonne') "
        "AND NOT EXISTS (SELECT 1 FROM dataset_version v JOIN offer o ON o.id = v.offer_id "
        "WHERE v.empreinte = x.empreinte AND o.fournisseur_did = ?)", (soi, soi))]
    return sum(1 for e in seules if objets.supprimer(cx, e))


def lignee(cx: sqlite3.Connection, service_id: str) -> Dict[str, Any]:
    """Où vit un jeu : chaîne des versions, espaces auxquels son producteur l'a confié (abonnements de CE nœud), et
    copies gardées ici (origine, parent, version)."""
    versions = [dict(r) for r in cx.execute(
        "SELECT v.numero, v.parent, v.empreinte, v.taille, v.classe, v.cree_le, v.retiree FROM dataset_version v "
        "JOIN offer o ON o.id = v.offer_id WHERE o.ref_annuaire = ? ORDER BY v.numero DESC LIMIT 50", (service_id,))]
    espaces = [dict(r) for r in cx.execute(
        f"SELECT s.ref_annuaire AS subscription_id, e.ref_annuaire AS espace_id, e.nom AS espace, n.nom AS gardien, "
        f"e.fournisseur_did AS gardien_did, {_DERNIER_ETAT} AS etat, s.echeance FROM subscription s "
        f"JOIN offer e ON e.id = s.offer_id JOIN node n ON n.did = e.fournisseur_did "
        f"WHERE s.role = 'abonne' AND e.kind = 'espace' AND ? IN (SELECT value FROM json_each(s.jeux)) "
        f"ORDER BY s.demande_le DESC", (service_id,))]
    copies = [dict(r) for r in cx.execute(
        "SELECT v.numero, c.empreinte, x.taille, c.origine_did, no.nom AS origine, c.parent_did, np.nom AS parent, "
        "c.recue_le, s.ref_annuaire AS subscription_id FROM copie c JOIN dataset_version v ON v.id = c.version_id "
        "JOIN offer o ON o.id = v.offer_id JOIN subscription s ON s.id = c.subscription_id "
        "LEFT JOIN objet x ON x.empreinte = c.empreinte LEFT JOIN node no ON no.did = c.origine_did "
        "LEFT JOIN node np ON np.did = c.parent_did WHERE o.ref_annuaire = ? ORDER BY v.numero DESC", (service_id,))]
    return {"service_id": service_id, "versions": versions, "espaces": espaces, "copies": copies}


def gardees(cx: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Ce que CE nœud garde comme espace, par abonnement : producteur, jeux, état, capacité occupée, copies, refus."""
    soi = _soi(cx)
    res = []
    for s in cx.execute(
            f"SELECT s.id, s.ref_annuaire AS subscription_id, s.abonne_did AS producteur_did, n.nom AS producteur, "
            f"s.jeux, e.id AS espace_id, e.ref_annuaire AS espace_ref, e.nom AS espace, e.compat, e.quotas, "
            f"{_DERNIER_ETAT} AS etat FROM subscription s JOIN offer e ON e.id = s.offer_id "
            f"JOIN node n ON n.did = s.abonne_did WHERE s.role = 'fournisseur' AND e.kind = 'espace' "
            f"AND e.fournisseur_did = ? ORDER BY s.demande_le DESC", (soi or "",)).fetchall():
        d = dict(s)
        d["jeux"] = _json(d["jeux"]) or []
        car = caracteristiques(_json(d.pop("compat")), _json(d.pop("quotas")))
        d["capacite"], d["occupe"] = car["octets"], occupe(cx, d.pop("espace_id"))
        d["copies"] = [dict(r) for r in cx.execute(
            "SELECT o.ref_annuaire AS service_id, o.nom AS jeu, v.numero, c.empreinte, x.taille, c.parent_did, "
            "c.recue_le FROM copie c JOIN dataset_version v ON v.id = c.version_id JOIN offer o ON o.id = v.offer_id "
            "LEFT JOIN objet x ON x.empreinte = c.empreinte WHERE c.subscription_id = ? ORDER BY o.nom, v.numero DESC",
            (d["id"],))]
        d["refus"] = [{"version_id": k[1], "motif": m} for k, m in REFUS.items() if k[0] == d["id"]]
        d.pop("id")
        res.append(d)
    return res
