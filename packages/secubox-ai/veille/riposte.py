# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Riposte graduée DÉFENSIVE (spec 2026-11-19, #3723) : niveau du dossier et propositions, décidés par le CODE.

Rien n'est émis vers l'attaquant ; gk3 PROPOSE des gestes du catalogue V2 (exécutés plus tard par le seul chemin
audité de gk2, `ai-ban`). Le texte du modèle n'entre ni dans le niveau, ni dans une proposition, ni dans un motif.

Couches (signal `couches`), d'après les champs `source` / `famille` / émetteur des événements de veille.db :
  - `menaces` de sbx-authwatch → `auth` ; de sbxwaf → `waf` (familles SYN sans état → `nft`, `dpi` → `dpi`) ;
  - événement de leurre (familles `leurre` / `honeypot`, ou `essais` d'un leurre de service) → `leurres` ;
  - `dns` → `dns` ; `garde` → `garde` ; famille `dpi` d'une autre source → `dpi` ;
  - NE COMPTENT PAS (ni couche, ni tentative) : décisions de gk2 (`bans`, `bans_actifs`, `decisions`,
    `reevaluations`), avis ou faits dérivés (`actord`, `mesures`, `campagnes`, `posture`), familles NEUTRES (dont
    `leurre_redirige` : l'adresse est servie par le leurre de la box, la compter ferait boucler leurre → ban),
    événements exclus de la corrélation.
Dossier WEB SEUL : couches ⊆ {waf, leurres} ET tous les événements comptés viennent de sbxwaf (un leurre de service
porté par sbx-authwatch n'est pas du web : le leurre HTTP n'y servirait à rien).

Signaux (fenêtre `fenetre_s`, preuves postérieures au `plancher`) : `tentatives` (événements comptés), `couches`,
`fenetre_s` (première → dernière preuve), `campagne` (dossier de campagne ou membre d'une campagne), `recidive`
(preuve de `retour_apres_ban`), `critique` (preuve de gravité `critical`), `outil_nomme` (attribution ≥ 2 traits).
Niveau cible : `usager` si récidive, campagne avec tentatives ≥ n3, ou couches ≥ 3 ; sinon `contenir` si tentatives ≥
n2, couches ≥ 2 ou règle critique ; sinon `observer`. Le niveau MONTE dès que la cible le dépasse ; il ne descend
qu'après `calme_s` sans nouvelle preuve, et alors jusqu'à `observer` : les preuves antérieures sont SOLDÉES (plancher),
une remontée exige des preuves nouvelles. La redescente ne défait aucun geste (ils expirent seuls).

Propositions (`proposer`) : dossiers d'ACTEUR seulement (un dossier de campagne n'en fait aucune : ses membres ont
chacun leur dossier et leur niveau). Une seule proposition vivante par (geste, cible) ; jamais une cible protégée
(adresse non publique, adresse de la box vue en vhost, plages `protegees` de ai.toml dont gk2 et gk0) ; jamais de
levée (`unban`) ; plafonds de gk3 de la politique ; expiration `expiration_min` (une proposition expirée n'est
reproposée qu'avec de nouvelles preuves, quand le dossier est recalculé). Compatibilité avec gk2 (`_candidats`) :
IPv6 ni bannie ni partagée ; rien de neuf tant qu'un ban V2 est en vol ; ban V2 fait et actif → `prolonger` (champ
`reference`) et, seulement alors, `partager` ; retour après la fin d'un ban → nouveau ban, durée de récidive de gk2.
"""
import errno
import ipaddress
import json
import logging
import os
import sqlite3
import tomllib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from veille import cas_sur
from veille.collecte import _audit
from veille.politiques import lire_toml
from veille.regles import DECISIONS, NEUTRES, iso

log = logging.getLogger("secubox-ai-veille")

CHEMIN = "/etc/secubox/ai/riposte.toml"
AUDIT_LOG = "/var/log/secubox/audit.log"
NIVEAUX = ("observer", "contenir", "usager")
RANG = {n: i for i, n in enumerate(NIVEAUX)}
# Durées d'office (Global Constraints du plan V2 phases 4-7) : fixées par le code, gk2 borne de nouveau.
DUREE_BAN_S = 86400
FACTEUR_USAGER = 4
DUREE_MAX_S = 7 * 86400
DUREE_BAN_BLOC_S = 86400
DUREE_LIMITER_S = 6 * 3600
DUREE_LIMITER_MAX_S = 86400          # borne de gk2 (LIMITE_MAX_S) : limitation d'usager d'une adresse IPv6
DUREE_LEURRE_S = 86400
DUREE_PARTAGER_S = 7 * 86400
# Miroir de gestes_ia.duree_recidive (gk2, relu par le test) : un ban d'adresse D'OFFICE dure 24 h × 4 par ban ai-ban
# précédent de l'adresse, 7 j au plus (exposant borné à 8). gk2 impose cette durée en mode auto : gk3 affiche la même.
DUREE_AUTO_ADRESSE_S, FACTEUR_RECIDIVE, EXPOSANT_MAX = 86_400, 4, 8
EN_VOL = ("proposee", "approuvee", "envoyee")
SANS_COUCHE = frozenset({"actord", "mesures", "campagnes", "posture"}) | DECISIONS
SYN = frozenset({"syn_sans_etat", "syn_scan"})
WEB = frozenset({"waf", "leurres"})
# Motifs : gabarits du CODE, remplis de chiffres seulement (jamais un texte de gk2 ni du modèle).
MOTIFS = {
    "contenir_ban": "riposte contenir : ban {duree_h} h, adresse vue par {sources} source(s) sur {etapes} étape(s) "
                    "({tentatives} tentative(s), {couches} couche(s))",
    "contenir_limiter": "riposte contenir : limitation {duree_h} h, adresse vue par une source sur une étape "
                        "({tentatives} tentative(s), {couches} couche(s))",
    "usager_leurre": "riposte usager, dossier web seul : leurre {duree_h} h ({tentatives} tentative(s), "
                     "{couches} couche(s))",
    "usager_ban_long": "riposte usager : ban {duree_h} h ({tentatives} tentative(s), {couches} couche(s))",
    "usager_ban_recidive": "riposte usager : nouveau ban {duree_h} h après la fin d'un ban (retour après ban, "
                           "{bans} ban(s) V2 précédent(s))",
    "usager_ban_bloc": "riposte usager : ban du bloc {duree_h} h, cas sûr local (au moins {seuil} adresses du bloc "
                       "bannies, familles sûres)",
    "usager_prolonger": "riposte usager : prolonger le ban V2 actif de {duree_h} h ({bans} ban(s) V2 de la cible)",
    "usager_partager": "riposte usager : partage de l'indicateur {duree_h} h, cible bannie par V2 (campagne ou outil "
                       "identifié par au moins deux traits)",
    "contenir_limiter_v6": "riposte contenir : limitation {duree_h} h, adresse IPv6 (ni ban ni partage sur gk2) "
                           "({tentatives} tentative(s), {couches} couche(s))",
    "usager_limiter_v6": "riposte usager : limitation {duree_h} h, adresse IPv6 hors web (ni ban ni partage sur gk2) "
                         "({tentatives} tentative(s), {couches} couche(s))",
}


# ── seuils (riposte.toml) ──

@dataclass(frozen=True)
class Seuils:
    n2_tentatives: int = 20
    n3_tentatives: int = 100
    fenetre_s: int = 86400
    calme_s: int = 21600


SEUILS = Seuils()
BORNES = {"n2_tentatives": (1, 100_000), "n3_tentatives": (1, 1_000_000), "fenetre_s": (3600, 7 * 86400),
          "calme_s": (3600, 7 * 86400)}


def valider_seuils(brut) -> Seuils:
    """`version = 1`, `[seuils]` aux clés de BORNES ; toute clé inconnue, valeur hors bornes ou n3 < n2 : ValueError."""
    if not isinstance(brut, dict) or set(brut) - {"version", "seuils"} or brut.get("version") != 1:
        raise ValueError("riposte.toml : version = 1 et [seuils] seulement")
    s = brut.get("seuils", {})
    if not isinstance(s, dict) or set(s) - set(BORNES):
        raise ValueError("riposte.toml : [seuils] aux clés connues seulement")
    valeurs = asdict(SEUILS)
    for cle, (bas, haut) in BORNES.items():
        v = s.get(cle, valeurs[cle])
        if isinstance(v, bool) or not isinstance(v, int) or not bas <= v <= haut:
            raise ValueError(f"riposte.toml : {cle} dans [{bas}, {haut}]")
        valeurs[cle] = v
    if valeurs["n3_tentatives"] < valeurs["n2_tentatives"]:
        raise ValueError("riposte.toml : n3_tentatives < n2_tentatives")
    return Seuils(**valeurs)


def charger_seuils(chemin=CHEMIN, proprietaire: int = 0, precedents: Seuils = SEUILS) -> Seuils:
    """Seuils lus (mêmes contrôles de fichier que politiques.toml) ; absent : défauts ; invalide : `precedents`."""
    try:
        return valider_seuils(lire_toml(chemin, proprietaire))
    except FileNotFoundError:
        return SEUILS
    except (OSError, ValueError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:   # jamais fatal à la passe
        log.error("riposte.toml refusé (%s) : seuils précédents gardés", e.__class__.__name__)
        return precedents


# ── signaux et niveau ──

@dataclass
class Signaux:
    tentatives: int
    couches: int
    fenetre_s: int
    campagne: bool
    recidive: bool
    critique: bool = False
    outil_nomme: bool = False
    web_seul: bool = False
    noms_couches: tuple = ()
    derniere_preuve: Optional[str] = None

    def dict(self):
        d = asdict(self)
        d["noms_couches"] = list(self.noms_couches)
        return d


def couche(e) -> Optional[str]:
    """Couche d'un événement compté, ou None s'il ne compte pas (cf. docstring du module)."""
    if not e.observation or e.source in SANS_COUCHE or e.famille in NEUTRES:
        return None
    a = e.attributs
    if a.get("exclu_correlation") or a.get("local") or a.get("autotest") or not e.ip_src:
        return None
    if e.leurre:
        return "leurres"
    if e.source == "menaces":
        if e.emetteur == "authwatch":
            return "auth"
        if e.famille in SYN or a.get("syn_sans_etat") is True:
            return "nft"
        return "dpi" if e.famille == "dpi" else "waf"
    if e.source in ("dns", "garde"):
        return e.source
    return "dpi" if e.famille == "dpi" else None


def _comptes(dossier, maintenant, seuils):
    debut = iso(maintenant - timedelta(seconds=seuils.fenetre_s))
    fin = iso(maintenant)
    plancher = getattr(dossier, "plancher", None) or ""
    out = []
    for e in getattr(dossier, "evts", []) or []:
        if debut <= e.horodatage <= fin and e.horodatage > plancher:
            c = couche(e)
            if c:
                out.append((e, c))
    return out


def _outil_nomme(outils) -> bool:
    return any(isinstance(a, dict) and a.get("outil") and a.get("outil") != "inconnu"
               and len(a.get("traits_concordants") or []) >= 2 for a in outils or [])


def signaux(dossier, maintenant: datetime, seuils: Seuils = SEUILS) -> Signaux:
    """Signaux chiffrés du dossier (sans le modèle)."""
    comptes = _comptes(dossier, maintenant, seuils)
    noms = tuple(sorted({c for _, c in comptes}))
    heures = sorted(e.horodatage for e, _ in comptes)
    retours = set(getattr(dossier, "retours", []) or [])
    fenetre = 0
    if heures:
        fenetre = int((datetime.fromisoformat(heures[-1].replace("Z", "+00:00"))
                       - datetime.fromisoformat(heures[0].replace("Z", "+00:00"))).total_seconds())
    return Signaux(
        tentatives=len(comptes), couches=len(noms), fenetre_s=fenetre,
        campagne=dossier.type == "campagne" or bool(getattr(dossier, "campagnes", [])),
        recidive=any(e.id in retours for e, _ in comptes),
        critique=any(e.gravite == "critical" for e, _ in comptes),
        outil_nomme=_outil_nomme(dossier.outils),
        web_seul=bool(noms) and set(noms) <= WEB and all(e.emetteur == "waf" for e, _ in comptes),
        noms_couches=noms, derniere_preuve=heures[-1] if heures else None)


def niveau_cible(s: Signaux, seuils: Seuils = SEUILS) -> str:
    if s.recidive or (s.campagne and s.tentatives >= seuils.n3_tentatives) or s.couches >= 3:
        return "usager"
    if s.tentatives >= seuils.n2_tentatives or s.couches >= 2 or s.critique:
        return "contenir"
    return "observer"


def _calme(derniere: Optional[str], maintenant, seuils) -> bool:
    return not derniere or derniere < iso(maintenant - timedelta(seconds=seuils.calme_s))


def evaluer(db, dossier, maintenant: datetime, seuils: Seuils = SEUILS):
    """Recalcule signaux et niveau d'un dossier (appelé par dossiers._recalculer, dans sa transaction) ; met à jour
    `dossier` et la ligne. Un changement de niveau donne une ligne `audit_chaine` (`riposte_niveau`)."""
    courant, depuis, ancien = db.execute("SELECT niveau, niveau_depuis, signaux_json FROM dossiers WHERE id = ?",
                                         (dossier.id,)).fetchone()
    try:
        ancien = json.loads(ancien or "{}")
    except ValueError:
        ancien = {}
    dossier.plancher = ancien.get("plancher") if isinstance(ancien, dict) else None
    s = signaux(dossier, maintenant, seuils)
    cible = niveau_cible(s, seuils)
    nouveau = courant
    if RANG[cible] > RANG[courant]:
        nouveau = cible
    elif courant != "observer" and _calme(s.derniere_preuve, maintenant, seuils):
        nouveau = "observer"
    stocke = s.dict()
    stocke["plancher"] = dossier.plancher
    # Seuils qui ont fixé ce niveau (console #3724 : « tentatives N (seuil N3 : X) », jamais une valeur supposée).
    stocke["seuils"] = {"n2_tentatives": seuils.n2_tentatives, "n3_tentatives": seuils.n3_tentatives}
    if nouveau == "observer" and courant != "observer":
        stocke["plancher"] = max(filter(None, (s.derniere_preuve, dossier.plancher)), default=None)
    h = iso(maintenant)
    if nouveau != courant:
        depuis = h
        _audit(db, maintenant, dossier.id, {"de": courant, "vers": nouveau, "cible": cible,
                                            "tentatives": s.tentatives, "couches": s.couches,
                                            "recidive": s.recidive, "campagne": s.campagne},
               operation="riposte_niveau", resultat=nouveau, limiter=False)
    db.execute("UPDATE dossiers SET niveau = ?, niveau_depuis = ?, signaux_json = ? WHERE id = ?",
               (nouveau, depuis, json.dumps(stocke, sort_keys=True), dossier.id))
    dossier.niveau, dossier.niveau_depuis, dossier.signaux = nouveau, depuis, s
    return nouveau


def redescendre(db, maintenant: datetime, seuils: Seuils = SEUILS) -> int:
    """Dossiers sans nouvelle preuve depuis `calme_s` : retour à `observer`, preuves soldées (plancher). Aucun geste
    défait, aucune proposition touchée. Rend le nombre de dossiers redescendus."""
    limite = iso(maintenant - timedelta(seconds=seuils.calme_s))
    h = iso(maintenant)
    n = 0
    for did, niveau, brut in db.execute(
            "SELECT id, niveau, signaux_json FROM dossiers WHERE niveau != 'observer' "
            "AND COALESCE(json_extract(signaux_json, '$.derniere_preuve'), '') < ?", (limite,)).fetchall():
        try:
            sig = json.loads(brut or "{}")
        except ValueError:
            sig = {}
        sig = sig if isinstance(sig, dict) else {}
        sig["plancher"] = max(filter(None, (sig.get("derniere_preuve"), sig.get("plancher"))), default=None)
        db.execute("UPDATE dossiers SET niveau = 'observer', niveau_depuis = ?, signaux_json = ? WHERE id = ?",
                   (h, json.dumps(sig, sort_keys=True), did))
        _audit(db, maintenant, did, {"de": niveau, "vers": "observer", "cible": "calme"},
               operation="riposte_niveau", resultat="observer", limiter=False)
        n += 1
    return n


def appliquer_redescentes(db, maintenant: datetime) -> int:
    """Décisions humaines de redescente (#3724, table `redescentes`, écrites par l'API) : le dossier revient à
    `observer`, ses preuves ANTÉRIEURES À LA DÉCISION sont soldées (plancher), une remontée exige des preuves
    nouvelles. Aucun geste défait, aucune proposition touchée. Dans la transaction de l'appelant (dossiers.construire,
    avant les recalculs). Rend le nombre de dossiers redescendus. Sans la migration 0009 : rien (0)."""
    try:
        attente = db.execute("SELECT r.id, r.dossier_id, r.acteur, r.demandee_le, d.niveau, d.signaux_json "
                             "FROM redescentes r JOIN dossiers d ON d.id = r.dossier_id "
                             "WHERE r.appliquee_le IS NULL ORDER BY r.demandee_le").fetchall()
    except sqlite3.OperationalError:
        return 0
    h = iso(maintenant)
    n = 0
    for rid, did, acteur, demandee, niveau, brut in attente:
        if niveau == "observer":
            db.execute("UPDATE redescentes SET appliquee_le = ?, resultat = 'deja_observer' WHERE id = ?", (h, rid))
            continue
        try:
            sig = json.loads(brut or "{}")
        except ValueError:
            sig = {}
        sig = sig if isinstance(sig, dict) else {}
        sig["plancher"] = max(filter(None, (demandee, sig.get("derniere_preuve"), sig.get("plancher"))), default=None)
        db.execute("UPDATE dossiers SET niveau = 'observer', niveau_depuis = ?, signaux_json = ? WHERE id = ?",
                   (h, json.dumps(sig, sort_keys=True), did))
        db.execute("UPDATE redescentes SET appliquee_le = ?, resultat = 'appliquee' WHERE id = ?", (h, rid))
        _audit(db, maintenant, did, {"de": niveau, "vers": "observer", "cible": "humain", "acteur": acteur,
                                     "decision": rid}, operation="riposte_niveau", resultat="observer", limiter=False)
        n += 1
    return n


# ── propositions ──

@dataclass
class Proposition:
    id: str
    dossier_id: str
    geste: str
    cible: str
    duree_s: int
    mode: str
    niveau: str
    politique: str
    motif: str
    etat: str
    expire_le: str
    cree_le: str
    regle: str = ""
    valeurs: dict = field(default_factory=dict)
    version: int = 1
    reference: Optional[str] = None


def motifs_possibles(p: Proposition):
    """(gabarit, valeurs) d'où vient le motif d'une proposition : gabarit du code, valeurs entières."""
    return [(MOTIFS[p.regle], p.valeurs)]


def _protegee(n, protegees) -> bool:
    """Même règle que l'analyste (analyste._protegee) : forme mêlée, adresse non publique ou plage protégée."""
    if isinstance(n, ipaddress.IPv6Network) and n.network_address.ipv4_mapped is not None:
        return True
    if not n.is_global:
        return True
    return any(p.version == n.version and n.overlaps(p) for p in protegees)


def ecrire_audit_log(evenement: str, details: dict, chemin: Optional[str] = None) -> None:
    """Une ligne JSON en ajout seul dans /var/log/secubox/audit.log (jamais un jeton ni une clé). Échec : signalé au
    journal du service avec la ligne, jamais silencieux."""
    ligne = json.dumps({"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "type": "ai",
                        "evenement": evenement, **details}, ensure_ascii=True, sort_keys=True)
    try:
        fd = os.open(chemin or os.environ.get("SECUBOX_AI_AUDIT", AUDIT_LOG),
                     os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)   # jamais créé ici (compte secubox)
        try:
            os.write(fd, (ligne + "\n").encode())
        finally:
            os.close(fd)
    except OSError as e:
        log.warning("audit.log non écrit (%s) : %s", e.__class__.__name__, ligne)
        if e.errno in (errno.EACCES, errno.EPERM):
            from veille.executeur import _demander_acl   # rotation : ACL de la veille à reposer (#3723)
            _demander_acl()


def duree_recidive(n: int) -> int:
    """Durée d'un ban d'adresse d'office après `n` bans V2 précédents de l'adresse (miroir de gk2)."""
    return min(DUREE_MAX_S, DUREE_AUTO_ADRESSE_S * FACTEUR_RECIDIVE ** min(max(n, 0), EXPOSANT_MAX))


# Un ban V2 levé par une levée V2 faite (`unban`, `reference` = id du ban) ne compte plus, comme gk2 retire de la
# récidive les bans annulés (`_CAUSES_SANS_RECIDIVE`) ; un ban jamais posé (`echec`, `refusee_gk2`) n'est pas `faite`.
_NON_LEVE = ("NOT EXISTS (SELECT 1 FROM propositions u WHERE u.geste = 'unban' AND u.etat = 'faite' "
             "AND u.reference = propositions.id)")


def _bans_poses(db, geste, cible) -> int:
    """Bans V2 faits et non levés sur la cible (miroir du compte de gk2 : ses propres bans de la cible)."""
    return db.execute(f"SELECT COUNT(*) FROM propositions WHERE geste = ? AND cible = ? AND etat = 'faite' "
                      f"AND {_NON_LEVE}", (geste, cible)).fetchone()[0]


def _fin(maj, duree):
    try:
        return datetime.fromisoformat(maj.replace("Z", "+00:00")) + timedelta(seconds=int(duree or 0))
    except (ValueError, TypeError, AttributeError):
        return None


def _fin_prolongee(db, pid, fin):
    """Fin d'un ban V2 après ses prolongations FAITES (`prolonger` dont `reference` = le ban ou une prolongation de
    ce ban, en chaîne) : la plus tardive. gk2 ne raccourcit jamais."""
    vus, file = {pid}, [pid]
    while file:
        ref = file.pop()
        for qid, maj, duree in db.execute("SELECT id, maj_le, duree_s FROM propositions WHERE geste = 'prolonger' "
                                          "AND etat = 'faite' AND reference = ?", (ref,)).fetchall():
            f = _fin(maj, duree)
            if f is not None and (fin is None or f > fin):
                fin = f
            if qid not in vus:
                vus.add(qid)
                file.append(qid)
    return fin


def _cibles_ban(ip, bloc):
    return [("ban", ip)] + ([("ban_bloc", bloc)] if bloc else [])


def _ban_en_vol(db, ip, bloc) -> bool:
    """Un ban V2 de l'adresse ou de son bloc proposé, approuvé ou en cours d'envoi."""
    return any(db.execute("SELECT 1 FROM propositions WHERE geste = ? AND cible = ? AND etat IN (?, ?, ?)",
                          (g, c, *EN_VOL)).fetchone() for g, c in _cibles_ban(ip, bloc))


def _ban_vivant(db, ip, bloc, maintenant):
    """Ban V2 FAIT de l'adresse ou de son bloc dont la fin est à venir : (id, geste, cible, fin, prolongé) le plus
    tardif, ou
    None. Fin = passage à `faite` (`maj_le`) + `duree_s` (la tâche 7 tient `faite` à jour), repoussée par ses
    prolongations faites ; un ban levé par une levée V2 faite n'est plus vivant."""
    meilleur = None
    for g, c in _cibles_ban(ip, bloc):
        for pid, maj, duree in db.execute(f"SELECT id, maj_le, duree_s FROM propositions WHERE geste = ? AND cible = ? "
                                          f"AND etat = 'faite' AND {_NON_LEVE}", (g, c)).fetchall():
            origine = _fin(maj, duree)
            fin = _fin_prolongee(db, pid, origine)
            if fin is None:
                continue
            if fin > maintenant and (meilleur is None or fin > meilleur[3]):
                meilleur = (pid, g, c, fin, origine is None or fin > origine)
    return meilleur


def _candidats(db, d, s: Signaux, comptes, maintenant):
    """(geste, cible, durée, règle, valeurs, référence) du niveau atteint, par adresse du dossier.

    Compatibles avec gk2 (`/ai/ban` : IPv4 publique ou /24 exact) : une adresse IPv6 n'est jamais bannie ni partagée
    (contenir : limiter 6 h ; usager : leurre si web seul, sinon limiter 24 h). Une adresse dont un ban V2 (adresse ou
    bloc) est en vol n'a rien de nouveau (on attend) ; dont un ban V2 est FAIT et actif : `prolonger` ce ban (référence
    gardée), jamais de leurre, et `partager` si campagne ou outil. `partager` n'est proposé que sur un ban vivant : la
    passe suivante le proposera une fois le ban fait. Retour après la fin d'un ban : NOUVEAU ban (durée de récidive)."""
    par_ip = {}
    for e, _ in comptes:
        par_ip.setdefault(e.ip_src, []).append(e)
    etapes_de = {}
    for et in d.etapes:
        for i in et["preuves"]:
            etapes_de.setdefault(i, set()).add(et["etape"])
    retours = set(getattr(d, "retours", []) or [])
    base = {"tentatives": s.tentatives, "couches": s.couches}
    out = []
    for ip in sorted(par_ip):
        evs = par_ip[ip]
        try:
            v6 = ipaddress.ip_address(ip).version == 6
        except ValueError:
            continue
        if v6:
            if d.niveau == "contenir":
                out.append(("limiter", ip, DUREE_LIMITER_S, "contenir_limiter_v6", dict(base), None))
            elif s.web_seul:
                out.append(("leurre", ip, DUREE_LEURRE_S, "usager_leurre", dict(base), None))
            else:
                out.append(("limiter", ip, DUREE_LIMITER_MAX_S, "usager_limiter_v6", dict(base), None))
            continue
        bloc = next((e.bloc24 for e in evs if e.bloc24), None)
        if _ban_en_vol(db, ip, bloc):
            continue                                  # un ban V2 en vol : attendre son issue
        vivant = _ban_vivant(db, ip, bloc, maintenant)
        if d.niveau == "contenir":
            if vivant:
                continue                              # déjà contenue par un ban V2 actif
            sources = len({e.emetteur for e in evs})
            etapes = len({x for e in evs for x in etapes_de.get(e.id, ())})
            if sources >= 2 or etapes >= 2:
                out.append(("ban", ip, DUREE_BAN_S, "contenir_ban", {**base, "sources": sources, "etapes": etapes},
                            None))
            else:
                out.append(("limiter", ip, DUREE_LIMITER_S, "contenir_limiter", dict(base), None))
            continue
        if vivant:
            pid, g, c, fin, prolonge = vivant
            n = _bans_poses(db, g, c)
            duree = duree_recidive(n) if g == "ban" else DUREE_MAX_S
            # Une prolongation au plus tant qu'elle court ; gk2 ne raccourcit jamais (409 raccourcit).
            if not prolonge and maintenant + timedelta(seconds=duree) > fin:
                out.append(("prolonger", c, duree, "usager_prolonger", {"bans": n}, pid))
            if s.campagne or s.outil_nomme:
                out.append(("partager", ip, DUREE_PARTAGER_S, "usager_partager", {}, None))
            continue
        if s.web_seul:
            out.append(("leurre", ip, DUREE_LEURRE_S, "usager_leurre", dict(base), None))
            continue
        if any(e.id in retours for e in evs):
            n = _bans_poses(db, "ban", ip)
            out.append(("ban", ip, duree_recidive(n), "usager_ban_recidive", {"bans": n}, None))
        else:
            out.append(("ban", ip, min(DUREE_BAN_S * FACTEUR_USAGER, DUREE_MAX_S), "usager_ban_long", dict(base),
                        None))
        if bloc and cas_sur.bloc_sur(db, bloc, maintenant):
            out.append(("ban_bloc", bloc, DUREE_BAN_BLOC_S, "usager_ban_bloc", {"seuil": cas_sur.SEUIL_BLOC}, None))
    return out


def _plafond_atteint(db, politiques, geste, maintenant) -> bool:
    p = politiques.plafonds.get(geste)
    if p is None:
        return False
    for champ, recul in (("heure", 3600), ("jour", 86400)):
        n = db.execute("SELECT COUNT(*) FROM propositions WHERE geste = ? AND cree_le > ? "
                       "AND etat NOT IN ('expiree', 'refusee')",
                       (geste, iso(maintenant - timedelta(seconds=recul)))).fetchone()[0]
        if n >= p[champ]:
            return True
    return False


def expirer(db, maintenant: datetime) -> int:
    """Propositions non décidées au-delà de `expire_le` : `expiree` (elles libèrent leur place)."""
    h = iso(maintenant)
    avant = db.total_changes
    db.execute("UPDATE propositions SET etat = 'expiree', maj_le = ? WHERE etat = 'proposee' AND expire_le <= ?",
               (h, h))
    return db.total_changes - avant


def proposer(db, dossier, politiques, maintenant: datetime, protegees=(), seuils: Seuils = SEUILS,
             journal_audit=None) -> list:
    """Propositions admises pour le dossier (rendues) ; chacune : une ligne `audit_chaine` (dans la transaction) et
    une ligne `audit.log` (après validation). Une transaction courte ; appelée hors de la boucle (Veille.sql)."""
    if maintenant.tzinfo is None:
        raise ValueError("horodatage sans fuseau")
    journal_audit = ecrire_audit_log if journal_audit is None else journal_audit
    if politiques.mode != "hybride" or dossier.type != "acteur" or dossier.niveau not in ("contenir", "usager"):
        return []
    s = signaux(dossier, maintenant, seuils)
    comptes = _comptes(dossier, maintenant, seuils)
    h = iso(maintenant)
    expire = iso(maintenant + timedelta(minutes=politiques.expiration_min))
    # Adresses de la box vues en vhost (IP nue) : jamais visées.
    protegees = list(protegees)
    for e in getattr(dossier, "evts", []) or []:
        try:
            n = ipaddress.ip_network(e.vhost) if e.vhost else None
        except ValueError:
            n = None
        if n is not None:
            protegees.append(n)
    admises, ecartees = [], {}
    db.execute("BEGIN IMMEDIATE")
    try:
        expirer(db, maintenant)
        r = db.execute("SELECT id FROM analyses WHERE dossier_id = ? ORDER BY cree_le DESC, rowid DESC LIMIT 1",
                       (dossier.id,)).fetchone()
        analyse_id = r[0] if r else None
        incident_id = dossier.incidents[-1] if dossier.incidents else None
        vus = set()
        for geste, cible, duree, regle, valeurs, reference in _candidats(db, dossier, s, comptes, maintenant):
            if (geste, cible) in vus:
                continue
            vus.add((geste, cible))
            try:
                n = ipaddress.ip_network(cible, strict=True)
            except ValueError:
                ecartees["cible"] = ecartees.get("cible", 0) + 1
                continue
            if _protegee(n, protegees):
                ecartees["protegee"] = ecartees.get("protegee", 0) + 1
                continue
            if not politiques.admet(geste):
                ecartees["politique"] = ecartees.get("politique", 0) + 1
                continue
            if db.execute("SELECT 1 FROM propositions WHERE geste = ? AND cible = ? AND etat IN "
                          "('proposee', 'approuvee', 'envoyee')", (geste, cible)).fetchone():
                continue
            if _plafond_atteint(db, politiques, geste, maintenant):
                ecartees["plafond"] = ecartees.get("plafond", 0) + 1
                continue
            mode = politiques.mode_de(geste)
            if geste == "ban" and mode == "auto":
                # gk2 impose sa durée de récidive à un ban d'adresse d'office : gk3 propose et affiche la même.
                duree = duree_recidive(_bans_poses(db, "ban", cible))
            valeurs = {**valeurs, "duree_h": duree // 3600}
            p = Proposition(str(uuid.uuid4()), dossier.id, geste, cible, duree, mode, dossier.niveau,
                            f"gestes.{geste}", MOTIFS[regle].format(**valeurs), "proposee", expire, h, regle, valeurs,
                            reference=reference)
            db.execute("INSERT INTO propositions(id, version, dossier_id, incident_id, analyse_id, geste, cible, "
                       "duree_s, mode, niveau, reference, politique, motif, etat, expire_le, cree_le, maj_le) "
                       "VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposee', ?, ?, ?)",
                       (p.id, dossier.id, incident_id, analyse_id, geste, cible, duree, mode, p.niveau, reference,
                        p.politique, p.motif, expire, h, h))
            _audit(db, maintenant, p.id, _details(p), operation="riposte_proposition", resultat="admise",
                   limiter=False)
            admises.append(p)
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    if ecartees:
        log.info("riposte : propositions écartées %s", ecartees)
    for p in admises:
        journal_audit("ai-riposte-proposition", _details(p))
    return admises


def _details(p: Proposition) -> dict:
    return {"id": p.id, "dossier": p.dossier_id, "geste": p.geste, "cible": p.cible, "duree_s": p.duree_s,
            "mode": p.mode, "niveau": p.niveau, "politique": p.politique, "regle": p.regle, "reference": p.reference}
