# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Moteur de secubox-garde (#3794) : un passage lit, décide, applique, enregistre, prévient.

Tout est injecté : `sources` (voisins, alertes, propositions, doh, protegees, nommer), `effets`
(bannir, isoler, liberer, fermer_evasion, rouvrir, alerte) et `notifs` (mettre_en_file, vider).
Une décision n'est enregistrée `active` que si son effet a réussi (au moins une adresse pour un
appareil) ; sinon une alerte est journalisée et le passage suivant réessaie.
"""
from __future__ import annotations

import logging
import re
import sqlite3
import uuid
from typing import Dict, List, Optional

from . import appareils
from .politique import FAMILLES, FENETRE_INFECTION, QUARANTAINE, Decision, Signal, decider

log = logging.getLogger("secubox-garde")

SEPT_JOURS = 7 * 86400
FENETRE_RAFALE = 600
HEURE = 3600


# -- base

def _actives(db) -> List[tuple]:
    return db.execute("SELECT id, menace, cible, mac, ip, motif, signe, debut, fin FROM decisions "
                      "WHERE etat='active'").fetchall()


def _enregistrer(db, d: Decision, etat: str, motif: Optional[str] = None) -> str:
    did = uuid.uuid4().hex
    db.execute("INSERT INTO decisions(id, menace, cible, mac, ip, motif, signe, debut, fin, etat) "
               "VALUES (?,?,?,?,?,?,?,?,?,?)",
               (did, d.menace, d.cible, d.mac, d.ip, motif or d.motif, d.signe, d.debut, d.fin, etat))
    return did


def _adresses(db, did: str) -> List[str]:
    return [r[0] for r in db.execute("SELECT ip FROM adresses WHERE decision_id=? ORDER BY ip", (did,))]


def _noms(db, did: str) -> List[str]:
    r = db.execute("SELECT noms FROM decision_noms WHERE decision_id=?", (did,)).fetchone()
    return [n for n in (r[0] if r else "").split(",") if n]


def _clore(db, did: str, etat: str, par: str) -> None:
    db.execute("UPDATE decisions SET etat=?, leve_par=? WHERE id=?", (etat, par, did))


def _repere(db, cle: str, valeur: Optional[int] = None) -> int:
    if valeur is None:
        r = db.execute("SELECT valeur FROM etat_moteur WHERE cle=?", (cle,)).fetchone()
        return int(r[0]) if r and r[0] is not None else 0
    db.execute("INSERT INTO etat_moteur(cle, valeur) VALUES (?,?) "
               "ON CONFLICT(cle) DO UPDATE SET valeur=excluded.valeur", (cle, int(valeur)))
    return int(valeur)


# -- effets par appareil

def _poser(effets, menace: str, ip: str, mac, fin: int, noms: List[str], motif: str) -> dict:
    if menace == "evasion" and not noms:    # rien à fermer (décision ancienne sans noms) : aucun appel, aucun échec
        return {"ok": True, "motif": "sans_nom"}
    if menace == "infection":
        return effets.isoler(ip, mac, fin, motif)
    return effets.fermer_evasion(ip, mac, noms, motif)


def _lever(effets, menace: str, ip: str, mac, motif: str) -> dict:
    if menace == "infection":
        return effets.liberer(ip, mac, motif)
    return effets.rouvrir(ip, mac, motif)


def _lever_tout(db, effets, did, menace, mac, motif) -> bool:
    """Lève chaque adresse ; seules les levées réussies quittent `adresses`. True si plus rien n'est posé."""
    for ip in _adresses(db, did):
        if _tenue_ailleurs(db, did, menace, ip, mac):
            # Une décision ACTIVE de même menace tient cette adresse (le ctl lève par IP) : on ne la lève pas,
            # elle quitte simplement cette décision.
            db.execute("DELETE FROM adresses WHERE decision_id=? AND ip=?", (did, ip))
            continue
        if _lever(effets, menace, ip, mac, motif).get("ok"):
            db.execute("DELETE FROM adresses WHERE decision_id=? AND ip=?", (did, ip))
            # #3910 : gardée tout de suite. Un passage tué par son délai (TimeoutStartSec) avant le commit final
            # relevait les mêmes adresses à chaque minute, sans fin.
            db.commit()
    return not _adresses(db, did)


def _tenue_ailleurs(db, did: str, menace: str, ip: str, mac=None) -> bool:
    """Vrai si une autre décision ACTIVE de même menace tient cette IP (une MAC partagée ne suffit pas)."""
    return bool(db.execute(
        "SELECT 1 FROM decisions d WHERE d.id!=? AND d.etat='active' AND d.menace=? AND "
        "(EXISTS (SELECT 1 FROM adresses a WHERE a.decision_id=d.id AND a.ip=?) OR d.ip=?)",
        (did, menace, ip, ip)).fetchone())


def _alerte_une(db, effets, cle: str, texte: str, maintenant: int, delai: int = HEURE) -> None:
    """Une alerte par clé et par `delai` (repère dans etat_moteur)."""
    if maintenant - _repere(db, "alerte:" + cle) < delai:
        return
    effets.alerte(texte)
    _repere(db, "alerte:" + cle, maintenant)


def _terminer(db, effets, did, menace, mac, motif, par: str, maintenant: int, notifs=None) -> bool:
    """Lève puis clôt ; un échec laisse `levee_en_cours` (réessayée à chaque passage) : une alerte au début,
    puis une réalerte (et un courriel) au plus une fois par heure tant que la levée échoue."""
    final = "levee" if par in ("reevaluation", "utilisateur") else "echue"
    if menace not in ("infection", "evasion") or _lever_tout(db, effets, did, menace, mac, motif):
        _clore(db, did, final, par)
        db.execute("DELETE FROM etat_moteur WHERE cle=?", ("levee:" + did,))
        return True
    db.execute("UPDATE decisions SET etat='levee_en_cours', leve_par=? WHERE id=?", (par, did))
    if not _repere(db, "levee:" + did):
        effets.alerte(f"{motif} : levée incomplète ({', '.join(_adresses(db, did))}), réessayée à chaque passage")
        _repere(db, "levee:" + did, maintenant)
    elif maintenant - _repere(db, "levee:" + did) >= HEURE:
        r = db.execute("SELECT cible FROM decisions WHERE id=?", (did,)).fetchone()
        texte = (f"levée toujours en échec : {appareils.nom_de(db, r[0]) if r else did} "
                 f"{', '.join(_adresses(db, did))}")
        effets.alerte(texte)
        if notifs is not None:
            notifs.mettre_en_file(db, "courriel", "levee:" + did, f"SecuBox Garde : {texte}", maintenant)
        _repere(db, "levee:" + did, maintenant)
    return False


def _levees_en_cours(db, effets, maintenant: int, notifs=None) -> int:
    n = 0
    for did, menace, mac, motif, par in db.execute(
            "SELECT id, menace, mac, motif, leve_par FROM decisions WHERE etat='levee_en_cours'").fetchall():
        n += _terminer(db, effets, did, menace, mac, motif, par or "echeance", maintenant, notifs)
    db.commit()
    return n


_RE_SUFFIXE = re.compile(r"[a-z]{2,3}\.[a-z]{2}")


def _nom_fermable(nom: str) -> str:
    """Nom tel que donné par le capteur (dns-guard écrit déjà le domaine ENREGISTRÉ d'un tunnel) ; refusé ("")
    s'il a moins de deux libellés ou s'il a la forme d'un suffixe public `<2-3 lettres>.<2 lettres>` (co.uk,
    com.au…) : garde prudente, quitte à refuser un vrai domaine court de cette forme."""
    n = str(nom or "").lower().rstrip(".")
    if len([x for x in n.split(".") if x]) < 2 or _RE_SUFFIXE.fullmatch(n):
        return ""
    return n


# -- échéances et suivi des adresses

def _echeances(db, effets, notifs, maintenant: int) -> Dict[str, int]:
    n = {"levees": 0, "prolongees": 0}
    for did, menace, cible, mac, ip, motif, signe, debut, fin in _actives(db):
        if fin > maintenant:
            continue
        if menace == "intrusion":            # le ban expire seul (timeout nft)
            _clore(db, did, "echue", "echeance")
            continue
        nom = appareils.nom_de(db, cible)
        if menace == "infection" and appareils.dernier_signal(db, cible) > fin - QUARANTAINE:
            nfin = maintenant + QUARANTAINE
            ok = 0
            for ip_ in _adresses(db, did):   # un échec garde l'ancienne fin : reposé par _suivre_adresses
                if effets.isoler(ip_, mac, nfin, f"{nom} — prolongation 24 h").get("ok"):
                    db.execute("UPDATE adresses SET fin=? WHERE decision_id=? AND ip=?", (nfin, did, ip_))
                    ok += 1
            if ok:
                db.execute("UPDATE decisions SET fin=? WHERE id=?", (nfin, did))
                n["prolongees"] += 1
                continue
            _alerte_une(db, effets, "prolongation:" + did,
                        f"{nom} : prolongation de quarantaine impossible, mesure levée", maintenant)
        par = "reevaluation" if menace == "infection" else "echeance"
        _terminer(db, effets, did, menace, mac, f"{nom} — échéance", par, maintenant, notifs)
        n["levees"] += 1
    db.commit()
    return n


def _suivre_adresses(db, effets, voisins: Dict[str, str], maintenant: int) -> None:
    """Une mesure d'appareil suit ses adresses : nouvelle adresse posée, ancienne levée."""
    for did, menace, cible, mac, ip, motif, signe, debut, fin in _actives(db):
        if menace not in ("infection", "evasion") or not mac or fin <= maintenant:
            continue
        for a, afin in db.execute("SELECT ip, fin FROM adresses WHERE decision_id=?", (did,)).fetchall():
            if afin is not None and afin < fin and _poser(effets, menace, a, mac, fin, _noms(db, did),
                                                          f"{appareils.nom_de(db, cible)} — prolongation").get("ok"):
                db.execute("UPDATE adresses SET fin=? WHERE decision_id=? AND ip=?", (fin, did, a))
        posees = set(_adresses(db, did))
        actuelles = set(appareils.adresses_actuelles(mac, voisins, posees))
        nom = appareils.nom_de(db, cible)
        for vieille in sorted(posees - actuelles):
            if _lever(effets, menace, vieille, mac, f"{nom} — adresse quittée").get("ok"):
                db.execute("DELETE FROM adresses WHERE decision_id=? AND ip=?", (did, vieille))
        for neuve in sorted(actuelles - posees):
            if _poser(effets, menace, neuve, mac, fin, _noms(db, did), f"{nom} — nouvelle adresse").get("ok"):
                db.execute("INSERT OR IGNORE INTO adresses(decision_id, ip, fin) VALUES (?,?,?)", (did, neuve, fin))
        principale = _adresses(db, did)
        if principale and ip not in principale:
            db.execute("UPDATE decisions SET ip=? WHERE id=?", (principale[0], did))
    db.commit()


# -- passage

def _recidives(db, maintenant: int) -> Dict[str, int]:
    return dict(db.execute("SELECT ip, COUNT(*) FROM decisions WHERE menace='intrusion' "
                           "AND etat IN ('active','echue','levee') AND debut>? GROUP BY ip",
                           (maintenant - SEPT_JOURS,)).fetchall())


def _liberations(db, maintenant: int) -> Dict[tuple, int]:
    return {(m, s): j for m, s, j in db.execute("SELECT mac, signe, jusqua FROM liberations WHERE jusqua>?",
                                                 (maintenant,))}


def passage(db: sqlite3.Connection, reglages: dict, sources, effets, notifs, maintenant: int) -> dict:
    maintenant = int(maintenant)
    voisins = sources.voisins() or {}
    signaux: List[Signal] = []
    for lot in (sources.alertes(db, voisins), sources.propositions(maintenant),
                sources.doh(maintenant - FENETRE_INFECTION, voisins)):
        signaux.extend(lot or [])
    for s in signaux:
        if not s.mac and s.type != "intrusion":
            s.mac = voisins.get(s.ip)
    signaux = [s for s in signaux if maintenant - FENETRE_INFECTION <= s.ts <= maintenant + 300]

    couples = list(voisins.items()) + [(s.ip, s.mac) for s in signaux if s.type != "intrusion"]
    appareils.mettre_a_jour(db, couples, sources.nommer, maintenant)
    for s in signaux:                      # MAC apprise plus tôt : même clé que celle des décisions
        if not s.mac and s.type != "intrusion":
            cle = appareils.cle_de(db, s.ip, None)
            s.mac = cle if appareils.est_mac(cle) else None
    for s in signaux:
        if s.type in FAMILLES:
            appareils.noter_signal(db, appareils.cle_de(db, s.ip, s.mac), s.ts)
    db.commit()

    bilan: Dict[str, int] = dict(_echeances(db, effets, notifs, maintenant))
    bilan["levees_reprises"] = _levees_en_cours(db, effets, maintenant, notifs)
    _suivre_adresses(db, effets, voisins, maintenant)

    actives = [Decision(m, c, mac, ip, mo, sg, de, fi)
               for _id, m, c, mac, ip, mo, sg, de, fi in _actives(db)]
    # Une levée en attente compte comme active : aucune nouvelle décision de même menace sur l'appareil.
    actives += [Decision(m, c, mac, ip, mo, sg, de, maintenant + 1) for m, c, mac, ip, mo, sg, de in db.execute(
        "SELECT menace, cible, mac, ip, motif, signe, debut FROM decisions WHERE etat='levee_en_cours'")]
    decisions, alertes = decider(signaux, actives, _liberations(db, maintenant), _recidives(db, maintenant),
                                 sources.protegees, reglages, maintenant)
    bilan.update(appliquees=0, echecs=0, signalees=0, bans=0)
    for d in decisions:
        _appliquer(db, d, signaux, voisins, effets, notifs, maintenant, bilan)
    db.commit()

    _alerte_masse(db, alertes, effets, notifs, maintenant)
    _resume_bans(db, reglages, notifs, maintenant)
    bilan["notifs"] = notifs.vider(db, reglages, maintenant)
    return bilan


def _appliquer(db, d: Decision, signaux, voisins, effets, notifs, maintenant, bilan) -> None:
    if d.menace == "signale":
        cle = appareils.cle_de(db, d.ip, d.mac) if d.signe != "intrusion" else d.ip
        repere = f"signale:{cle}:{d.signe}"
        if maintenant - _repere(db, repere) < HEURE:
            return
        _repere(db, repere, maintenant)
        nom = appareils.nom_de(db, cle) if d.signe != "intrusion" else d.ip
        _enregistrer(db, d, "echue", f"{nom} — {d.motif}")
        bilan["signalees"] += 1
        return
    if d.menace == "intrusion":
        r = effets.bannir(d.ip, d.fin - d.debut, d.motif)
        if not r.get("ok"):
            _alerte_une(db, effets, f"echec:{d.ip}:intrusion",
                        f"ban de {d.ip} non posé ({r.get('motif')}) : décision non enregistrée", maintenant)
            bilan["echecs"] += 1
            return
        motif = d.motif + (" (déjà banni ailleurs)" if r.get("deja") else "")
        _enregistrer(db, d, "active", motif)
        bilan["appliquees"] += 1
        bilan["bans"] += 1
        return

    # infection / évasion : l'appareil entier, chacune de ses adresses
    cle = appareils.cle_de(db, d.ip, d.mac)
    nom = appareils.nom_de(db, cle)
    connues = [r[0] for r in db.execute("SELECT ip FROM appareil_ips WHERE cle=?", (cle,))]
    adresses = sorted(set(appareils.adresses_actuelles(cle, voisins, connues)) | {d.ip})
    noms = sorted({_nom_fermable(s.domaine) for s in signaux if s.type in ("doh", "tunneling") and s.domaine
                   and appareils.cle_de(db, s.ip, s.mac) == cle} - {""})
    motif = f"{nom} — {d.motif}"
    if d.menace == "evasion" and not noms:     # rien de précis à fermer : signalé, sans effet ni alerte d'échec
        repere = f"signale:{cle}:{d.signe}"    # même limite horaire que les autres « signalé »
        if maintenant - _repere(db, repere) < HEURE:
            return
        _repere(db, repere, maintenant)
        _enregistrer(db, Decision("signale", cle, d.mac, d.ip, d.motif, d.signe, d.debut, d.debut),
                     "echue", f"{motif} (aucun nom à fermer)")
        bilan["signalees"] += 1
        return
    posees = [ip for ip in adresses if _poser(effets, d.menace, ip, d.mac, d.fin, noms, motif).get("ok")]
    if not posees:
        _alerte_une(db, effets, f"echec:{cle}:{d.menace}",
                    f"{nom} : {d.menace} non appliquée (aucune adresse posée) : décision non enregistrée", maintenant)
        bilan["echecs"] += 1
        return
    d.cible = cle
    d.ip = d.ip if d.ip in posees else posees[0]
    did = _enregistrer(db, d, "active", motif)
    db.executemany("INSERT OR IGNORE INTO adresses(decision_id, ip, fin) VALUES (?,?,?)",
                   [(did, ip, d.fin) for ip in posees])
    if noms:
        db.execute("INSERT OR REPLACE INTO decision_noms(decision_id, noms) VALUES (?,?)", (did, ",".join(noms)))
    db.commit()
    bilan["appliquees"] += 1
    quoi = "mis en quarantaine 24 h" if d.menace == "infection" else "accès DNS chiffré fermé 24 h"
    texte = f"SecuBox Garde : {nom} {quoi} ({d.motif})."
    notifs.mettre_en_file(db, "sms", cle, texte, maintenant)
    notifs.mettre_en_file(db, "courriel", cle, texte, maintenant)


def _alerte_masse(db, alertes: List[str], effets, notifs, maintenant: int) -> None:
    """Une seule alerte tant que la situation dure ; réarmée quand elle cesse."""
    deja = _repere(db, "alerte_masse")
    if not alertes:
        if deja:
            _repere(db, "alerte_masse", 0)
            db.commit()
        return
    if deja:
        return
    for a in alertes:
        effets.alerte(a)
        notifs.mettre_en_file(db, "sms", "masse", f"SecuBox Garde : {a}", maintenant)
        notifs.mettre_en_file(db, "courriel", "masse", f"SecuBox Garde : {a}", maintenant)
    _repere(db, "alerte_masse", maintenant)
    db.commit()


def _bans_depuis(db, depuis: int) -> int:
    return db.execute("SELECT COUNT(*) FROM decisions WHERE menace='intrusion' AND debut>?",
                      (depuis,)).fetchone()[0]


def _resume_bans(db, reglages: dict, notifs, maintenant: int) -> None:
    rafale = int(reglages.get("rafale_bans", 50))
    n10 = _bans_depuis(db, maintenant - FENETRE_RAFALE)
    if n10 > rafale:                        # un SMS par rafale ; réarmé quand elle cesse
        if not _repere(db, "rafale"):
            notifs.mettre_en_file(db, "sms", "rafale",
                                  f"SecuBox Garde : rafale d'intrusions, {n10} adresses bannies en 10 min.", maintenant)
            _repere(db, "rafale", maintenant)
    elif _repere(db, "rafale"):
        _repere(db, "rafale", 0)
    dernier = _repere(db, "resume_bans")
    if not dernier:                         # premier passage : les bans de ce passage entrent au premier résumé
        _repere(db, "resume_bans", maintenant - 1)
    elif maintenant - dernier >= HEURE:
        n = _bans_depuis(db, dernier)
        if n:
            texte = f"SecuBox Garde : {n} adresse(s) bannie(s) pour intrusion dans la dernière heure."
            notifs.mettre_en_file(db, "courriel", "resume_bans", texte, maintenant)
            if reglages.get("sms_bans"):
                notifs.mettre_en_file(db, "sms", "resume_bans", texte, maintenant)
        _repere(db, "resume_bans", maintenant)
    db.commit()


# -- démarrage

def rapprocher(db: sqlite3.Connection, effets, maintenant: int) -> dict:
    """Réapplique les décisions actives non échues (fin d'origine) ; les autres passent `echue`."""
    maintenant = int(maintenant)
    n = {"reappliquees": 0, "echues": 0}
    _levees_en_cours(db, effets, maintenant)
    for did, menace, cible, mac, ip, motif, signe, debut, fin in _actives(db):
        if fin <= maintenant:
            if _terminer(db, effets, did, menace, mac, f"{motif} — échue au démarrage", "rapprochement", maintenant):
                n["echues"] += 1
            continue
        if menace == "intrusion":
            reste = fin - maintenant
            if reste >= 3600:          # le WAF refuse moins d'une heure ; sinon le timeout nft court encore
                effets.bannir(ip, reste, motif)
        else:
            for a in _adresses(db, did) or [ip]:
                _poser(effets, menace, a, mac, fin, _noms(db, did), motif)
        n["reappliquees"] += 1
    db.commit()
    return n
