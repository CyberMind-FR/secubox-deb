# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Dossiers d'attaquant et de campagne, étapes (complément corrélation § 2), #3795. Déterministe, sans IA.

Clé d'un dossier d'acteur : l'acteur d'actord (`ACT-nnnn`, champ `actor` des propositions, adresses dans `ips`) quand
une adresse lui est rattachée, sinon l'adresse. Une adresse rattachée plus tard rejoint le dossier de l'acteur (le
dossier par adresse est fondu). Une campagne réunit ≥ 2 dossiers d'acteur par règle écrite : `meme_outil` (signature
de campagne de gk2, outil nommé par gk2, ou outil identifié par la tâche 8), `meme_bloc` (même /24 dans la fenêtre),
`meme_cible` (même vhost attaqué à moins de `cible_s` d'écart). Seuls les événements CORRÉLABLES entrent (jamais
documentation, `local`, autotest : `correlation.correlable`).

Étapes, par règles nommées : `reperage` (balayage, cartographie, anomalie_hote, syn_sans_etat), `essais`
(sondes_produits_absents, leurre_touche, identifiants_tentes), `exploitation` (regle_waf_attaque,
risque_dpi_exploitation), `persistance` (retour_apres_ban — preuves de l'incident du corrélateur —, rotation_adresses).
Chaque étape garde ses règles, ses preuves (identifiants d'événements) et leurs heures. `outils_json` reste vide ici.
"""
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from veille import normaliser
from veille.correlation import _COLS, _charger, _evt, correlable
from veille.regles import ECHELLE, Evt, iso, rang

FENETRE_S = 86400              # événements nouveaux regardés à chaque passe (les liens déjà faits sont gardés)
CIBLE_S = 1800                 # même cible : deux acteurs à moins de 30 min d'écart
ORDRE = ("reperage", "essais", "exploitation", "persistance")
ACTEUR = re.compile(r"^ACT-[0-9]{1,12}$")
SYN_SANS_ETAT = frozenset({"syn_sans_etat", "syn_scan"})
DPI_EXPLOITATION = frozenset({"exploit", "exploitation", "rce", "shellcode", "code_execution"})


def _dpi(e: Evt):
    risque = e.attributs.get("risque")
    return e.famille == "dpi" and (e.sous_famille in DPI_EXPLOITATION or risque in DPI_EXPLOITATION)


# (étape, règle, prédicat) : la première règle qui s'applique à une observation lui donne son étape.
REGLES_ETAPES = (
    ("reperage", "balayage", lambda e: e.famille in ("scanners", "waf_fingerprint")),
    ("reperage", "cartographie", lambda e: e.famille == "recon_crawler"),
    ("reperage", "anomalie_hote", lambda e: e.famille == "host_anomaly"),
    ("reperage", "syn_sans_etat", lambda e: e.famille in SYN_SANS_ETAT or e.attributs.get("syn_sans_etat") is True),
    ("essais", "sondes_produits_absents", lambda e: e.famille == "product_absent_probes"),
    ("essais", "leurre_touche", lambda e: e.leurre),
    ("essais", "identifiants_tentes", lambda e: e.emetteur == "authwatch" or e.famille.startswith("auth_")),
    ("exploitation", "regle_waf_attaque", lambda e: e.source == "menaces" and e.emetteur == "waf" and e.attaque),
    ("exploitation", "risque_dpi_exploitation", _dpi),
)


@dataclass
class Dossier:
    id: str
    cle: str
    type: str
    gravite: str
    etapes: list
    outils: list
    premiere_vue: str
    derniere_vue: str
    maj_le: str
    evenements: list = field(default_factory=list)
    incidents: list = field(default_factory=list)
    adresses: list = field(default_factory=list)
    membres: dict = field(default_factory=dict)

    @property
    def enchainees(self) -> int:
        """Étapes successives : dans l'ordre reperage → … → persistance, chacune commencée après la précédente."""
        n, dernier = 0, ""
        for e in self.etapes:
            if e["debut"] >= dernier:
                n, dernier = n + 1, e["debut"]
        return n


def etape_de(e: Evt):
    if not e.observation:
        return None
    for etape, regle, pred in REGLES_ETAPES:
        if pred(e):
            return etape, regle
    return None


def _ident(cle):
    return str(uuid.UUID(hashlib.sha256(f"dossier\x1f{cle}".encode()).hexdigest()[:32]))


def _acteurs(db, evts):
    """adresse → acteur d'actord. Propositions d'actord (toutes celles gardées, la plus récente l'emporte), puis
    champ `actor` porté par un événement. Adresses illisibles ou exclues de la corrélation ignorées."""
    out = {}

    def _rattacher(acteur, ip):
        acteur = normaliser.texte(acteur, 32)
        if not acteur or not ACTEUR.match(acteur):
            return
        ip, _, marques = normaliser.adresse(ip)
        if ip and not marques:
            out[ip] = acteur

    for (attributs,) in db.execute("SELECT attributs_json FROM evenements WHERE source = 'actord' "
                                   "ORDER BY horodatage, id"):
        try:
            a = json.loads(attributs or "{}")
        except ValueError:
            continue
        if not isinstance(a, dict):
            continue
        ips = a.get("ips") if isinstance(a.get("ips"), list) else []
        for ip in ips + [a.get("ip")]:
            _rattacher(a.get("actor"), ip)
    for e in evts:
        if e.attributs.get("actor") and e.ip_src not in out:
            _rattacher(e.attributs.get("actor"), e.ip_src)
    return out


def _assurer(db, cle, type_, debut, h):
    did = _ident(cle)
    db.execute("INSERT OR IGNORE INTO dossiers(id, cle, type, gravite, premiere_vue, derniere_vue, maj_le) "
               "VALUES (?, ?, ?, 'info', ?, ?, ?)", (did, cle, type_, debut, debut, h))
    return did


def _lier(db, did, ids):
    avant = db.total_changes
    db.executemany("INSERT OR IGNORE INTO dossier_evenements(dossier_id, evenement_id) VALUES (?, ?)",
                   [(did, i) for i in ids])
    return db.total_changes > avant


def _lier_incidents(db, did):
    avant = db.total_changes
    db.execute("INSERT OR IGNORE INTO dossier_incidents(dossier_id, incident_id) SELECT DISTINCT ?, p.incident_id "
               "FROM incident_preuves p JOIN dossier_evenements d ON d.evenement_id = p.evenement_id "
               "WHERE d.dossier_id = ?", (did, did))
    return db.total_changes > avant


def _fondre(db, acteurs, h):
    """Dossier par adresse dont l'adresse est désormais rattachée à un acteur : ses liens passent à l'acteur."""
    touches = set()
    for ip, acteur in acteurs.items():
        r = db.execute("SELECT id FROM dossiers WHERE cle = ? AND type = 'acteur'", (ip,)).fetchone()
        if r is None:
            continue
        ids = [i for (i,) in db.execute("SELECT evenement_id FROM dossier_evenements WHERE dossier_id = ?", (r[0],))]
        debut = db.execute("SELECT premiere_vue FROM dossiers WHERE id = ?", (r[0],)).fetchone()[0]
        did = _assurer(db, acteur, "acteur", debut, h)
        _lier(db, did, ids)
        db.execute("DELETE FROM dossiers WHERE id = ?", (r[0],))
        touches.add(did)
    return touches


def _outils(db, did, evts):
    """Outils d'un dossier d'acteur : signature de campagne de gk2, outil nommé par gk2, outils de la tâche 8."""
    out = set()
    for e in evts:
        if e.famille == "campagne" and e.sous_famille:
            out.add(e.sous_famille)
        o = e.attributs.get("outil")
        if isinstance(o, str) and o:
            out.add(normaliser.texte(o, 64))
    r = db.execute("SELECT outils_json FROM dossiers WHERE id = ?", (did,)).fetchone()
    try:
        for o in json.loads(r[0] or "[]") if r else []:
            nom = o.get("outil") if isinstance(o, dict) else None
            if isinstance(nom, str) and nom and nom != "inconnu":
                out.add(nom)
    except ValueError:
        pass
    return out


def _campagnes(db, groupes, cible_s):
    """{cle de campagne: (règle, {cle d'acteur: dossier})} pour ≥ 2 acteurs."""
    par = {}

    def _ajouter(cle, regle, membre, did):
        par.setdefault(cle, (regle, {}))[1][membre] = did

    for membre, (did, g) in groupes.items():
        for outil in _outils(db, did, g):
            _ajouter(f"outil:{outil}", "meme_outil", membre, did)
        for bloc in {e.bloc24 for e in g if e.bloc24 and e.observation}:
            _ajouter(f"bloc:{bloc}", "meme_bloc", membre, did)
    # Même cible : attaques (pas les familles neutres) d'acteurs différents à moins de cible_s d'écart.
    cibles = {}
    for membre, (did, g) in groupes.items():
        for e in g:
            if e.vhost and e.observation and (e.attaque or etape_de(e)):
                cibles.setdefault(e.vhost, []).append((e.horodatage, membre, did))
    for vhost, vus in cibles.items():
        vus.sort()
        for i, (h1, m1, d1) in enumerate(vus):
            for h2, m2, d2 in vus[i + 1:]:
                if m2 != m1 and _ecart(h1, h2) <= cible_s:
                    _ajouter(f"cible:{vhost}", "meme_cible", m1, d1)
                    _ajouter(f"cible:{vhost}", "meme_cible", m2, d2)
    return {c: v for c, v in par.items() if len(v[1]) >= 2}


def _ecart(a, b):
    f = "%Y-%m-%dT%H:%M:%SZ"
    return abs((datetime.strptime(b, f) - datetime.strptime(a, f)).total_seconds())


def _evenements(db, did):
    lignes = db.execute(f"SELECT {', '.join('e.' + c.strip() for c in _COLS.split(','))} FROM evenements e "
                        "JOIN dossier_evenements d ON d.evenement_id = e.id WHERE d.dossier_id = ? "
                        "ORDER BY e.horodatage, e.id", (did,))
    return [_evt(x) for x in lignes]


def _etapes(db, did, type_, evts):
    par = {}

    def _noter(etape, regle, e):
        s = par.setdefault(etape, {"regles": set(), "preuves": {}})
        s["regles"].add(regle)
        s["preuves"][e.id] = e.horodatage

    for e in evts:
        r = etape_de(e)
        if r:
            _noter(*r, e)
    connus = {e.id: e for e in evts}
    retours = [i for (i,) in db.execute(
        "SELECT i.id FROM incidents i JOIN dossier_incidents d ON d.incident_id = i.id WHERE d.dossier_id = ? "
        "AND i.regle = 'retour_apres_ban'", (did,))]
    for iid in retours:
        for (eid,) in db.execute("SELECT evenement_id FROM incident_preuves WHERE incident_id = ?", (iid,)):
            e = connus.get(eid)
            if e is not None and e.observation:
                _noter("persistance", "retour_apres_ban", e)
    if type_ == "acteur":
        premiers, derniers = {}, {}
        for e in evts:
            if e.observation and e.ip_src:
                premiers.setdefault(e.ip_src, e)
                derniers[e.ip_src] = e.horodatage
        vues = sorted(premiers.values(), key=lambda e: (e.horodatage, e.id))
        for k, e in enumerate(vues[1:], 1):
            if all(derniers[p.ip_src] < e.horodatage for p in vues[:k]):
                _noter("persistance", "rotation_adresses", e)
    out = []
    for etape in ORDRE:
        s = par.get(etape)
        if not s:
            continue
        preuves = sorted(s["preuves"].items(), key=lambda x: (x[1], x[0]))
        out.append({"etape": etape, "regles": sorted(s["regles"]), "preuves": [p for p, _ in preuves],
                    "heures": [h for _, h in preuves], "debut": preuves[0][1], "fin": preuves[-1][1]})
    return out


def _recalculer(db, did, h):
    cle, type_, outils = db.execute("SELECT cle, type, outils_json FROM dossiers WHERE id = ?", (did,)).fetchone()
    evts = _evenements(db, did)
    if not evts:
        return None
    incidents = db.execute("SELECT i.id, i.gravite FROM incidents i JOIN dossier_incidents d ON d.incident_id = i.id "
                           "WHERE d.dossier_id = ? ORDER BY i.premiere_vue, i.id", (did,)).fetchall()
    etapes = _etapes(db, did, type_, evts)
    gravite = ECHELLE[max([rang(e.gravite) for e in evts] + [rang(g) for _, g in incidents])]
    premiere, derniere = evts[0].horodatage, max(e.horodatage for e in evts)
    db.execute("UPDATE dossiers SET gravite = ?, etapes_json = ?, premiere_vue = ?, derniere_vue = ?, maj_le = ? "
               "WHERE id = ?", (gravite, json.dumps(etapes), premiere, derniere, h, did))
    membres = {c: r for c, r in db.execute(
        "SELECT d.cle, m.regle FROM dossier_membres m JOIN dossiers d ON d.id = m.membre_id WHERE m.campagne_id = ? "
        "ORDER BY d.cle", (did,))}
    return Dossier(did, cle, type_, gravite, etapes, json.loads(outils or "[]"), premiere, derniere, h,
                   [e.id for e in evts], [i for i, _ in incidents], sorted({e.ip_src for e in evts if e.ip_src}),
                   membres)


def construire(db, maintenant, fenetre_s=FENETRE_S, cible_s=CIBLE_S):
    """Une passe : rattache les événements corrélables de la fenêtre aux dossiers, fond les dossiers par adresse dans
    leur acteur, relie les incidents, forme les campagnes ; rend les dossiers qui ont changé. Une transaction."""
    if maintenant.tzinfo is None:
        raise ValueError("horodatage sans fuseau")
    h = iso(maintenant)
    db.execute("BEGIN IMMEDIATE")
    try:
        evts = [e for e in _charger(db, iso(maintenant - timedelta(seconds=fenetre_s)), h) if correlable(e)]
        acteurs = _acteurs(db, evts)
        touches = _fondre(db, acteurs, h)
        groupes = {}
        for e in evts:
            groupes.setdefault(acteurs.get(e.ip_src, e.ip_src), []).append(e)
        actifs = {}
        for cle, g in groupes.items():
            did = _assurer(db, cle, "acteur", g[0].horodatage, h)
            if _lier(db, did, [e.id for e in g]):
                touches.add(did)
            actifs[cle] = (did, g)
        for did, _ in actifs.values():
            if _lier_incidents(db, did):
                touches.add(did)
        for cle, (regle, membres) in _campagnes(db, actifs, cible_s).items():
            debut = min(actifs[m][1][0].horodatage for m in membres)
            cid = _assurer(db, cle, "campagne", debut, h)
            avant = db.total_changes
            db.executemany("INSERT OR IGNORE INTO dossier_membres(campagne_id, membre_id, regle) VALUES (?, ?, ?)",
                           [(cid, did, regle) for did in membres.values()])
            change = db.total_changes > avant
            for m in membres:
                change |= _lier(db, cid, [e.id for e in actifs[m][1]])
            change |= _lier_incidents(db, cid)
            if change:
                touches.add(cid)
        out = [d for d in (_recalculer(db, did, h) for did in sorted(touches)) if d is not None]
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return sorted(out, key=lambda d: (d.type, d.cle))
