# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Corrélateur d'incidents (V2 § 8), #3721 : fenêtre glissante (30 min par défaut), passe toutes les 60 s.

Un incident est identifié par (règle, clé) tant qu'il n'est pas clos : une nouvelle preuve l'ÉTEND (preuves ajoutées,
`derniere_vue`, gravité recalculée, retour à `ouvert`), jamais un doublon. Gravité = maximum des preuves (échelle de
gk2), plus le cran de la règle. Sans nouvelle preuve depuis 6 h : `calme` ; depuis 7 j : `clos` (réglables). Titres
produits par le code, jamais par un texte de gk2. Les événements `local`, d'autotest ou des plages de documentation
(`exclu_correlation`) ne sont jamais ni incident ni preuve.
"""
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from veille import regles
from veille.regles import ECHELLE, Evt, iso, rang

FENETRE_S = 1800
CALME_S = 6 * 3600
CLOS_S = 7 * 86400
RETOUR_BAN_S = 7 * 86400      # fins de ban regardées en arrière (un ban dure au plus 7 j)
TITRES = {
    "multi_source": "Adresse {cle} vue par plusieurs sources",
    "multi_service": "Adresse {cle} sur plusieurs services",
    "bloc_mixte": "Bloc {cle} : familles sûres et d'attaque mêlées",
    "retour_apres_ban": "{cle} revenu après la fin d'un ban",
    "campagne_etendue": "Campagne {cle} aussi vue par sbx-authwatch",
    "leurre_puis_attaque": "{cle} : leurre puis tentative réelle",
    "garde_et_waf": "Adresse {cle} vue par la garde et le WAF",
}
# Bornes des réglages `[veille.correlation]` d'ai.toml (secondes). clos_s ≥ RETOUR_BAN_S : sinon un ban encore
# regardé en arrière serait la preuve d'un incident déjà clos.
BORNES = {"fenetre_s": (300, 86400), "calme_s": (600, 30 * 86400), "clos_s": (RETOUR_BAN_S, 365 * 86400)}
log = logging.getLogger("secubox-ai-veille")
_COLS = "id, source, horodatage, famille, sous_famille, gravite, ip_src, bloc24, service, vhost, attributs_json"


@dataclass
class Incident:
    id: str
    regle: str
    cle: str
    titre: str
    etat: str
    gravite: str
    sources: list
    campagne_id: object
    premiere_vue: str
    derniere_vue: str
    preuves: list


def reglages(cfg):
    """`[veille.correlation]` d'ai.toml → {fenetre_s, calme_s, clos_s} bornés (valeur hors bornes ramenée et dite)."""
    section = ((cfg or {}).get("veille") or {}).get("correlation") or {}
    out = {"fenetre_s": FENETRE_S, "calme_s": CALME_S, "clos_s": CLOS_S}
    for cle, (bas, haut) in BORNES.items():
        v = section.get(cle)
        if v is None:
            continue
        if not isinstance(v, int) or isinstance(v, bool):
            log.warning("veille.correlation.%s illisible : défaut %d gardé", cle, out[cle])
            continue
        if not bas <= v <= haut:
            log.warning("veille.correlation.%s = %d hors [%d, %d] : ramené", cle, v, bas, haut)
            v = min(max(v, bas), haut)
        out[cle] = v
    if out["calme_s"] >= out["clos_s"]:
        log.warning("veille.correlation.calme_s ≥ clos_s : calme_s ramené au défaut")
        out["calme_s"] = min(CALME_S, out["clos_s"] - 1)
    return out


def _evt(ligne):
    try:
        attributs = json.loads(ligne[10] or "{}")
    except ValueError:
        attributs = {}
    return Evt(*ligne[:10], attributs=attributs if isinstance(attributs, dict) else {})


def correlable(e: Evt) -> bool:
    a = e.attributs
    return not (a.get("exclu_correlation") or a.get("local") or a.get("autotest")) and bool(e.ip_src)


def _charger(db, debut, fin):
    """Événements corrélables de la fenêtre, SANS les requêtes servies par le leurre de la box (`REDIRIGES`) : elles
    ne sont preuve d'aucune règle (ni plusieurs sources, ni retour après ban : pas de boucle leurre → ban)."""
    evts = [_evt(x) for x in db.execute(
        f"SELECT {_COLS} FROM evenements WHERE horodatage >= ? AND horodatage <= ? ORDER BY horodatage, id",
        (debut, fin))]
    return [e for e in evts if correlable(e) and e.famille not in regles.REDIRIGES]


def _fin_ban(e: Evt):
    if e.source == "bans_actifs" and e.attributs.get("etat") == "disparu":
        return e.horodatage
    for k in ("exp", "expires_at", "fin"):
        v = e.attributs.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            try:
                return iso(datetime.fromtimestamp(v, timezone.utc))
            except (OverflowError, OSError, ValueError):
                return None
    return None


def _contexte(db, maintenant):
    """Faits de gk2 regardés au-delà de la fenêtre : fins de ban, membres des campagnes, blocs."""
    depuis = iso(maintenant - timedelta(seconds=RETOUR_BAN_S))
    fin = iso(maintenant)
    decisions = [e for e in (_evt(x) for x in db.execute(
        f"SELECT {_COLS} FROM evenements WHERE source IN ('bans', 'bans_actifs') AND horodatage >= ? "
        "AND horodatage <= ? ORDER BY horodatage, id", (depuis, fin))) if correlable(e)]
    fins, membres = {}, {}
    for e in decisions:
        f = _fin_ban(e)
        if f and f <= fin:
            fins.setdefault(e.ip_src, []).append((f, e))
        if e.famille == "campagne" and e.sous_famille:
            membres.setdefault(e.sous_famille, {}).setdefault(e.ip_src, e)
    blocs = {b: j for b, j in db.execute("SELECT bloc24, banni_jusqua FROM blocs WHERE banni_jusqua IS NOT NULL "
                                         "AND banni_jusqua >= ? AND banni_jusqua <= ?", (depuis, fin))}
    campagnes = {c for (c,) in db.execute("SELECT id FROM campagnes")}
    return {"fins_ban": fins, "membres_campagne": membres, "fins_bloc": blocs, "campagnes": campagnes}


def _gravite(preuves, cran):
    return ECHELLE[min(max(rang(e.gravite) for e in preuves) + cran, len(ECHELLE) - 1)]


def _ident(regle, cle, premiere):
    return str(uuid.UUID(hashlib.sha256(f"{regle}\x1f{cle}\x1f{premiere}".encode()).hexdigest()[:32]))


def _enregistrer(db, c, maintenant):
    """Crée ou étend l'incident (règle, clé) non clos ; rend l'Incident s'il a gagné des preuves, sinon None.

    Une preuve déjà rattachée à un incident CLOS de même (règle, clé) n'en ouvre pas un nouveau (sinon le même ban
    rouvrirait le même identifiant). Gravité, sources et bornes recalculées depuis l'état gardé + les seules preuves
    nouvelles. Une collision d'identifiant n'interrompt jamais la passe (INSERT OR IGNORE puis relecture)."""
    h = iso(maintenant)
    ligne = db.execute("SELECT id, gravite, sources_json FROM incidents WHERE regle = ? AND cle = ? AND etat != 'clos' "
                       "ORDER BY premiere_vue DESC LIMIT 1", (c.regle, c.cle)).fetchone()
    closes = {x for (x,) in db.execute(
        "SELECT p.evenement_id FROM incident_preuves p JOIN incidents i ON i.id = p.incident_id "
        "WHERE i.regle = ? AND i.cle = ? AND i.etat = 'clos'", (c.regle, c.cle))}
    candidats = {e.id: e for e in c.preuves if e.id not in closes}
    if not candidats:
        return None
    if ligne:
        iid, gravite, sources = ligne[0], ligne[1], json.loads(ligne[2] or "[]")
    else:
        if not any(e.observation for e in candidats.values()):
            return None
        premiere = min(e.horodatage for e in candidats.values())
        iid = _ident(c.regle, c.cle, premiere)
        db.execute("INSERT OR IGNORE INTO incidents(id, regle, cle, titre, etat, gravite, sources_json, campagne_id, "
                   "premiere_vue, derniere_vue, cree_le, maj_le) VALUES (?, ?, ?, ?, 'ouvert', 'info', '[]', ?, ?, ?, "
                   "?, ?)", (iid, c.regle, c.cle, TITRES[c.regle].format(cle=c.cle), c.campagne_id, premiere,
                             premiere, h, h))
        r = db.execute("SELECT gravite, sources_json FROM incidents WHERE id = ?", (iid,)).fetchone()
        gravite, sources = r[0], json.loads(r[1] or "[]")
    avant = db.total_changes
    db.executemany("INSERT OR IGNORE INTO incident_preuves(incident_id, evenement_id) VALUES (?, ?)",
                   [(iid, i) for i in candidats])
    if db.total_changes == avant:
        return None
    nouveaux = [e for e in candidats.values()
                if db.execute("SELECT 1 FROM incident_preuves WHERE incident_id = ? AND evenement_id = ?",
                              (iid, e.id)).fetchone()]
    gravite = ECHELLE[max(rang(gravite), rang(_gravite(nouveaux, c.cran)))]
    sources = sorted(set(sources) | {e.emetteur for e in nouveaux})
    db.execute("UPDATE OR IGNORE incidents SET etat = 'ouvert', gravite = ?, sources_json = ?, premiere_vue = MIN(premiere_vue, ?), "
               "derniere_vue = MAX(derniere_vue, ?), maj_le = ? WHERE id = ?",
               (gravite, json.dumps(sources), min(e.horodatage for e in nouveaux),
                max(e.horodatage for e in nouveaux), h, iid))
    return lire(db, iid)


def lire(db, iid):
    r = db.execute("SELECT id, regle, cle, titre, etat, gravite, sources_json, campagne_id, premiere_vue, "
                   "derniere_vue FROM incidents WHERE id = ?", (iid,)).fetchone()
    if r is None:
        return None
    preuves = [x for (x,) in db.execute("SELECT evenement_id FROM incident_preuves WHERE incident_id = ? "
                                        "ORDER BY evenement_id", (iid,))]
    return Incident(*r[:6], json.loads(r[6]), *r[7:], preuves)


def vieillir(db, maintenant, calme_s=CALME_S, clos_s=CLOS_S):
    """`ouvert` → `calme` après calme_s sans preuve, → `clos` après clos_s."""
    h = iso(maintenant)
    db.execute("UPDATE incidents SET etat = 'clos', maj_le = ? WHERE etat != 'clos' AND derniere_vue < ?",
               (h, iso(maintenant - timedelta(seconds=clos_s))))
    db.execute("UPDATE incidents SET etat = 'calme', maj_le = ? WHERE etat = 'ouvert' AND derniere_vue < ?",
               (h, iso(maintenant - timedelta(seconds=calme_s))))


def correler(db, maintenant, fenetre_s=FENETRE_S, calme_s=CALME_S, clos_s=CLOS_S):
    """Une passe : règles sur la fenêtre, incidents créés ou étendus (rendus), puis vieillissement. Une transaction."""
    if maintenant.tzinfo is None:
        raise ValueError("horodatage sans fuseau")
    db.execute("BEGIN IMMEDIATE")
    try:
        evts = _charger(db, iso(maintenant - timedelta(seconds=fenetre_s)), iso(maintenant))
        ctx = _contexte(db, maintenant)
        touches = []
        for regle in regles.REGLES:
            for c in regle(evts, ctx):
                inc = _enregistrer(db, c, maintenant)
                if inc:
                    touches.append(inc)
        vieillir(db, maintenant, calme_s, clos_s)
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return touches
