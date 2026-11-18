# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Dossiers d'attaquant et de campagne, étapes (complément corrélation § 2), #3795. Déterministe, sans IA.

Clé d'un dossier d'acteur : l'acteur d'actord (`ACT-nnnn` : propositions `actor`/`ips`, mesures `actor`/`ip` ; le
rattachement le plus récent l'emporte) quand une adresse lui est rattachée, sinon l'adresse. Une adresse rattachée plus
tard rejoint le dossier de l'acteur : le dossier par adresse est FONDU (son identifiant disparaît ; ses événements et
ses appartenances de campagne passent au dossier de l'acteur). Seuls les événements CORRÉLABLES entrent (jamais
documentation, `local`, autotest, mesures : `correlation.correlable`).

Campagnes, par vagues : `meme_cible` (`cible:<vhost>:<famille>:<début>`) et `meme_bloc` (`bloc:<x/24>:<famille>:<début>`)
ne comptent que des événements d'`essais` ou d'`exploitation` (jamais un balayage) de MÊME famille de règle, d'au
moins deux acteurs à moins de `cible_s` ; `meme_outil` (`outil:<signature>:<début>`) suit les signatures de campagne
de gk2. Une vague sans nouvel événement depuis `calme_s` est close : la suivante ouvre une nouvelle campagne.
Membres bornés (MAX_MEMBRES, dépassement journalisé).

Passe incrémentale : curseur `dossiers` (rowid d'evenements) dans `curseurs`, LOT_EVTS événements au plus ; dossiers
à recalculer marqués, MAX_RECALCUL recalculés par passe (le reste à la suivante).

Étapes, par règles nommées : `reperage` (balayage, cartographie, anomalie_hote, syn_sans_etat), `essais`
(sondes_produits_absents, leurre_touche, identifiants_tentes), `exploitation` (regle_waf_attaque,
risque_dpi_exploitation), `persistance` (retour_apres_ban — preuves de l'incident du corrélateur —, rotation_adresses).
Chaque étape garde ses règles, ses preuves (identifiants d'événements) et leurs heures. `outils_json` reste vide ici.
"""
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import timedelta

from veille import normaliser
from veille.correlation import _COLS, CALME_S, _evt, correlable
from veille.regles import ECHELLE, Evt, iso, rang

FENETRE_S = 86400              # événements nouveaux regardés à chaque passe (les liens déjà faits sont gardés)
CIBLE_S = 1800                 # même cible / même bloc : deux acteurs à moins de 30 min d'écart
LOT_EVTS = 5000                # événements lus par passe (curseur)
MAX_RECALCUL = 500             # dossiers recalculés par passe
MAX_MEMBRES = 200              # membres d'une campagne
log = logging.getLogger("secubox-ai-veille")
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

    # Propositions (`ips`) et mesures (`ip`, rangé dans ip_src) mêlées dans l'ordre du temps : le plus récent gagne.
    for attributs, ip_src in db.execute("SELECT attributs_json, ip_src FROM evenements "
                                        "WHERE source IN ('actord', 'mesures') ORDER BY horodatage, rowid"):
        try:
            a = json.loads(attributs or "{}")
        except ValueError:
            continue
        if not isinstance(a, dict):
            continue
        ips = a.get("ips") if isinstance(a.get("ips"), list) else []
        for ip in ips + [a.get("ip"), ip_src]:
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


def _fondre(db, acteurs, h):
    """Dossier par adresse dont l'adresse est désormais rattachée à un acteur : ses événements, incidents et
    appartenances de campagne passent au dossier de l'acteur ; le dossier par adresse (et son id) disparaît."""
    touches = set()
    for ip, acteur in acteurs.items():
        r = db.execute("SELECT id, premiere_vue FROM dossiers WHERE cle = ? AND type = 'acteur'", (ip,)).fetchone()
        if r is None:
            continue
        ancien, debut = r
        did = _assurer(db, acteur, "acteur", debut, h)
        db.execute("INSERT OR IGNORE INTO dossier_evenements(dossier_id, evenement_id) SELECT ?, evenement_id "
                   "FROM dossier_evenements WHERE dossier_id = ?", (did, ancien))
        db.execute("INSERT OR IGNORE INTO dossier_incidents(dossier_id, incident_id) SELECT ?, incident_id "
                   "FROM dossier_incidents WHERE dossier_id = ?", (did, ancien))
        db.execute("INSERT OR IGNORE INTO dossier_membres(campagne_id, membre_id, regle) SELECT campagne_id, ?, regle "
                   "FROM dossier_membres WHERE membre_id = ?", (did, ancien))
        campagnes = [c for (c,) in db.execute("SELECT campagne_id FROM dossier_membres WHERE membre_id = ?", (ancien,))]
        db.execute("DELETE FROM dossiers WHERE id = ?", (ancien,))
        touches.update([did] + campagnes)
    return touches


def _signaux(e: Evt):
    """(base de clé, famille, règle, recul) des campagnes qu'un événement peut nourrir."""
    out = []
    if e.famille == "campagne" and e.sous_famille:
        out.append((f"outil:{e.sous_famille}", "campagne", "meme_outil"))
    r = etape_de(e)
    if r and r[0] in ("essais", "exploitation"):
        if e.vhost:
            out.append((f"cible:{e.vhost}:{e.famille}", e.famille, "meme_cible"))
        if e.bloc24:
            out.append((f"bloc:{e.bloc24}:{e.famille}", e.famille, "meme_bloc"))
    return out


def _campagnes(db, nouveaux, acteurs, maintenant, cible_s, calme_s, h):
    """Ouvre ou étend les vagues nourries par les événements nouveaux ; rend les dossiers touchés."""
    touches = set()
    vus = set()
    for e in nouveaux:
        for base, famille, regle in _signaux(e):
            if base in vus:
                continue
            vus.add(base)
            recul = calme_s if regle == "meme_outil" else cible_s
            proches = [x for x in (_evt(y) for y in db.execute(
                f"SELECT {_COLS} FROM evenements WHERE famille = ? AND horodatage >= ? AND horodatage <= ? "
                "ORDER BY horodatage, id", (famille, iso(maintenant - timedelta(seconds=recul)), h)))
                if correlable(x) and any(b == base for b, _, _ in _signaux(x))]
            if not proches:
                continue
            membres = {}
            for x in proches:
                membres.setdefault(acteurs.get(x.ip_src, x.ip_src), []).append(x)
            ouverte = db.execute(
                "SELECT id FROM dossiers WHERE type = 'campagne' AND substr(cle, 1, ?) = ? AND derniere_vue >= ? "
                "ORDER BY premiere_vue DESC LIMIT 1",
                (len(base) + 1, base + ":", iso(maintenant - timedelta(seconds=calme_s)))).fetchone()
            if ouverte is None and len(membres) < 2:
                continue
            debut = proches[0].horodatage
            cid = ouverte[0] if ouverte else _assurer(db, f"{base}:{debut}", "campagne", debut, h)
            deja = {m for (m,) in db.execute("SELECT membre_id FROM dossier_membres WHERE campagne_id = ?", (cid,))}
            change, refuses = False, 0
            for cle, g in sorted(membres.items()):
                did = _assurer(db, cle, "acteur", g[0].horodatage, h)
                if did not in deja:
                    if len(deja) >= MAX_MEMBRES:
                        refuses += 1
                        continue
                    db.execute("INSERT OR IGNORE INTO dossier_membres(campagne_id, membre_id, regle) VALUES (?, ?, ?)",
                               (cid, did, regle))
                    deja.add(did)
                    change = True
                change |= _lier(db, cid, [x.id for x in g])
            if refuses:
                log.warning("campagne %s : %d membre(s) au-delà de %d ignoré(s)", base, refuses, MAX_MEMBRES)
            if change:
                db.execute("UPDATE dossiers SET derniere_vue = MAX(derniere_vue, ?) WHERE id = ?",
                           (proches[-1].horodatage, cid))
                touches.add(cid)
    return touches


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


def _curseur(db):
    r = db.execute("SELECT position, derniere_lecture FROM curseurs WHERE source = 'dossiers'").fetchone()
    pos = int(r[0]) if r and r[0] and str(r[0]).isdigit() else 0
    return pos, (r[1] if r else None)


def construire(db, maintenant, fenetre_s=FENETRE_S, cible_s=CIBLE_S, calme_s=CALME_S, lot=LOT_EVTS,
               max_recalcul=MAX_RECALCUL):
    """Une passe : lit les événements nouveaux (curseur), les rattache aux dossiers, fond les dossiers par adresse dans
    leur acteur, relie les incidents récents, ouvre ou étend les vagues de campagne, puis recalcule au plus
    max_recalcul dossiers marqués ; rend ceux recalculés. Une transaction courte."""
    if maintenant.tzinfo is None:
        raise ValueError("horodatage sans fuseau")
    h = iso(maintenant)
    limite = iso(maintenant - timedelta(seconds=fenetre_s))
    db.execute("BEGIN IMMEDIATE")
    try:
        pos, derniere = _curseur(db)
        lignes = db.execute(f"SELECT rowid, {_COLS} FROM evenements WHERE rowid > ? ORDER BY rowid LIMIT ?",
                            (pos, lot)).fetchall()
        if lignes:
            pos = lignes[-1][0]
        evts = sorted((e for e in (_evt(x[1:]) for x in lignes) if limite <= e.horodatage <= h and correlable(e)),
                      key=lambda e: (e.horodatage, e.id))
        acteurs = _acteurs(db, evts)
        touches = _fondre(db, acteurs, h)
        groupes = {}
        for e in evts:
            groupes.setdefault(acteurs.get(e.ip_src, e.ip_src), []).append(e)
        for cle, g in groupes.items():
            did = _assurer(db, cle, "acteur", g[0].horodatage, h)
            if _lier(db, did, [e.id for e in g]):
                touches.add(did)
        # Incidents créés ou étendus depuis la passe précédente (ou tous à la première).
        nouveaux_liens = db.execute(
            "SELECT DISTINCT d.dossier_id, p.incident_id FROM incidents i JOIN incident_preuves p ON p.incident_id = i.id "
            "JOIN dossier_evenements d ON d.evenement_id = p.evenement_id WHERE i.maj_le >= ? AND NOT EXISTS "
            "(SELECT 1 FROM dossier_incidents x WHERE x.dossier_id = d.dossier_id AND x.incident_id = p.incident_id)",
            (derniere or "",)).fetchall()
        db.executemany("INSERT OR IGNORE INTO dossier_incidents(dossier_id, incident_id) VALUES (?, ?)", nouveaux_liens)
        touches.update(d for d, _ in nouveaux_liens)
        touches |= _campagnes(db, evts, acteurs, maintenant, cible_s, calme_s, h)
        db.executemany("UPDATE dossiers SET a_recalculer = 1 WHERE id = ?", [(d,) for d in touches])
        ids = [d for (d,) in db.execute("SELECT id FROM dossiers WHERE a_recalculer = 1 ORDER BY id LIMIT ?",
                                        (max_recalcul,))]
        out = [d for d in (_recalculer(db, did, h) for did in ids) if d is not None]
        db.executemany("UPDATE dossiers SET a_recalculer = 0 WHERE id = ?", [(d,) for d in ids])
        db.execute("INSERT INTO curseurs(source, position, etat, derniere_lecture) VALUES ('dossiers', ?, 'ok', ?) "
                   "ON CONFLICT(source) DO UPDATE SET position = excluded.position, etat = 'ok', "
                   "derniere_lecture = excluded.derniere_lecture", (str(pos), h))
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return sorted(out, key=lambda d: (d.type, d.cle))
