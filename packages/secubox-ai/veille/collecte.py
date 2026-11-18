# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Collecte de la veille V2 (#3720) : une passe lit chaque source due, insère ses événements (idempotent par
empreinte), range ses faits (campagnes, blocs) et tient son curseur.

`curseurs.etat` : `ok` | `en_panne` | `suspendu`. Une panne garde la position (reprise sans perte). L'état de
reprise vit dans `derniere_erreur` (JSON : motif, échecs, prochain essai). Après un refus 401/403 : espacement
exponentiel (intervalle × 2^échecs) plafonné à 15 min, et UNE ligne d'audit (`audit_chaine`) par motif et par 10 min.
Transactions courtes : une par source.
"""
import hashlib
import json
import logging
from datetime import datetime, timedelta

from veille.client import ErreurGk2
from veille.normaliser import COLONNES, rfc3339
from veille.sources import ErreurSource

log = logging.getLogger("secubox-ai-veille")

PLAFOND_S = 900
AUDIT_FENETRE_S = 600
_INSERT = f"INSERT OR IGNORE INTO evenements({', '.join(COLONNES)}) VALUES ({', '.join('?' * len(COLONNES))})"


def _lire_curseur(db, nom):
    r = db.execute("SELECT position, etat, derniere_lecture, derniere_erreur FROM curseurs WHERE source = ?",
                   (nom,)).fetchone()
    if r is None:
        return None, None, None, {}
    try:
        erreur = json.loads(r[3]) if r[3] else {}
    except ValueError:
        erreur = {}
    return r[0], r[1], r[2], erreur if isinstance(erreur, dict) else {}


def _ecrire_curseur(db, nom, position, etat, lecture, erreur, lus):
    db.execute("INSERT INTO curseurs(source, position, etat, derniere_lecture, derniere_erreur, lus_total) "
               "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(source) DO UPDATE SET position = excluded.position, "
               "etat = excluded.etat, derniere_lecture = COALESCE(excluded.derniere_lecture, derniere_lecture), "
               "derniere_erreur = excluded.derniere_erreur, lus_total = lus_total + ?",
               (nom, position, etat, lecture, json.dumps(erreur, ensure_ascii=False) if erreur else None, lus, lus))


def _audit(db, maintenant, motif, details):
    """Une ligne d'audit par motif et par fenêtre de 10 min ; chaînée sur la précédente."""
    limite = rfc3339(maintenant - timedelta(seconds=AUDIT_FENETRE_S))
    if db.execute("SELECT 1 FROM audit_chaine WHERE operation = 'collecte_refus' AND objet = ? AND horodatage > ?",
                  (motif, limite)).fetchone():
        return False
    prec = db.execute("SELECT empreinte FROM audit_chaine ORDER BY id DESC LIMIT 1").fetchone()
    prec = prec[0] if prec else None
    h = rfc3339(maintenant)
    d = json.dumps(details, ensure_ascii=False, sort_keys=True)
    emp = hashlib.sha256("\x1f".join([prec or "", h, "secubox-ai-veille", "collecte_refus", motif, d]).encode()).hexdigest()
    db.execute("INSERT INTO audit_chaine(horodatage, acteur, operation, objet, objet_id, resultat, details_json, "
               "empreinte_prec, empreinte) VALUES (?, 'secubox-ai-veille', 'collecte_refus', ?, NULL, 'refus', ?, ?, ?)",
               (h, motif, d, prec, emp))
    log.warning("collecte refusée par gk2 (%s) : %s", motif, d)
    return True


def _due(source, lecture, erreur, maintenant):
    prochain = erreur.get("prochain")
    if prochain:
        return rfc3339(maintenant) >= prochain
    if not lecture:
        return True
    try:
        derniere = datetime.fromisoformat(lecture.replace("Z", "+00:00"))
    except ValueError:
        return True
    return (maintenant - derniere).total_seconds() >= source.intervalle_s


def _transaction(db, fonction):
    db.execute("BEGIN IMMEDIATE")
    try:
        resultat = fonction()
        db.execute("COMMIT")
        return resultat
    except BaseException:
        db.execute("ROLLBACK")
        raise


def _ranger_faits(db, faits, h):
    for c in faits.get("campagnes") or []:
        db.execute("INSERT INTO campagnes(id, outil, attaquants, sondes, haute_valeur, premiere_vue, derniere_vue) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET outil = excluded.outil, "
                   "attaquants = excluded.attaquants, sondes = excluded.sondes, haute_valeur = excluded.haute_valeur, "
                   "derniere_vue = excluded.derniere_vue",
                   (c["id"], c.get("outil"), c.get("attaquants"), c.get("sondes"), c.get("haute_valeur"),
                    c.get("premiere_vue") or h, c.get("derniere_vue") or h))
    for b in faits.get("blocs") or []:
        db.execute("INSERT INTO blocs(bloc24, banni_jusqua, origine, vu_le) VALUES (?, ?, ?, ?) "
                   "ON CONFLICT(bloc24) DO UPDATE SET banni_jusqua = excluded.banni_jusqua, origine = excluded.origine, "
                   "vu_le = excluded.vu_le", (b["bloc24"], b.get("banni_jusqua"), b.get("origine"), h))


async def _en_ligne(fonction):
    return fonction()


async def passe(db, client, sources, maintenant, suspendu=False, faits=None, sql=_en_ligne):
    """Lit chaque source due ; rend {source: état}. `faits` (dict, optionnel) reçoit les faits de chaque source.
    `sql(f)` exécute une fonction sans argument touchant la base (le service passe par Veille.sql : hors de la
    boucle, une écriture à la fois)."""
    h = rfc3339(maintenant)
    etats = {}
    for source in sources:
        position, etat, lecture, erreur = await sql(lambda: _lire_curseur(db, source.nom))
        if suspendu:
            await sql(lambda: _transaction(db, lambda: _ecrire_curseur(db, source.nom, position, "suspendu", None,
                                                                    erreur, 0)))
            etats[source.nom] = "suspendu"
            continue
        if not _due(source, lecture, erreur, maintenant):
            etats[source.nom] = etat or "ok"
            continue
        try:
            lot = await source.lire(client, position)
        except (ErreurGk2, ErreurSource) as e:
            code = getattr(e, "code", None)
            echecs = int(erreur.get("echecs") or 0) + 1
            motif = f"refus_{code}" if code in (401, 403) else (f"http_{code}" if code else
                                                                  str(getattr(e, "motif", e))[:64])
            nouvelle = {"motif": motif, "echecs": echecs, "le": h}
            if code in (401, 403):
                delai = min(source.intervalle_s * 2 ** echecs, PLAFOND_S)
                nouvelle["prochain"] = rfc3339(maintenant + timedelta(seconds=delai))

                def _ecrire():
                    _ecrire_curseur(db, source.nom, position, "en_panne", None, nouvelle, 0)
                    _audit(db, maintenant, motif, {"source": source.nom, "echecs": echecs})
            else:
                def _ecrire():
                    _ecrire_curseur(db, source.nom, position, "en_panne", h, nouvelle, 0)
            await sql(lambda: _transaction(db, _ecrire))
            log.info("source %s en panne (%s), position gardée", source.nom, motif)
            etats[source.nom] = "en_panne"
            continue

        def _inserer():
            n = 0
            for e in lot.evenements:
                n += db.execute(_INSERT, e.ligne()).rowcount
            _ranger_faits(db, lot.faits, h)
            _ecrire_curseur(db, source.nom, lot.curseur, "ok", h, None, n)
            return n
        await sql(lambda: _transaction(db, _inserer))
        if faits is not None:
            faits[source.nom] = lot.faits
        etats[source.nom] = "ok"
    return etats


def rapprocher(db, par_categorie, depuis, jusqua):
    """Compare les menaces collectées sur [depuis, jusqua[ aux compteurs de `/waf/stats` (`by_category`).

    Rend {total_local, total_gk2, ecart (relatif), par_famille}. La catégorie de gk2 est ramenée à sa famille."""
    gk2 = {}
    for cat, n in par_categorie.items():
        fam = cat.split("|")[0].split(":")[0]
        gk2[fam] = gk2.get(fam, 0) + n
    local = dict(db.execute("SELECT famille, COUNT(*) FROM evenements WHERE source = 'menaces' AND horodatage >= ? "
                            "AND horodatage < ? GROUP BY famille", (rfc3339(depuis), rfc3339(jusqua))).fetchall())
    tl, tg = sum(local.values()), sum(gk2.values())
    return {"total_local": tl, "total_gk2": tg, "ecart": abs(tl - tg) / tg if tg else (0.0 if not tl else 1.0),
            "par_famille": {f: (local.get(f, 0), gk2.get(f, 0)) for f in sorted(set(local) | set(gk2))}}
