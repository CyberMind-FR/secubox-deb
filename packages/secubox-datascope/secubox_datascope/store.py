# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Index SQLite de DataScope : idempotent, borné, provenance obligatoire (#3853).

Une passe = une transaction BEGIN IMMEDIATE. Un relevé dont l'empreinte et l'état égalent ceux du curseur n'écrit
rien. Une entité absente d'un relevé n'est jamais supprimée : elle garde son last_seen (disparition visible).
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ENTITES_MAX = 5000
RELATIONS_MAX = 20000
RETENTION_JOURS = 30
BASE_MAX_OCTETS = 200 * 1024 * 1024
LOT_PURGE = 1000
VOISINS_NOEUDS_MAX = 500
VOISINS_ARETES_MAX = 1500
PAR_PAGE_DEFAUT = 50
PAR_PAGE_MAX = 200
PAGE_MAX = 100000

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"
_NOM = re.compile(r"^(\d{4})-[\w.-]+\.sql$")
_ID = re.compile(r"^(node|network|interface|device|ip|service):[A-Za-z0-9:._-]{1,128}$")
TYPES_RELATION = ("BELONGS_TO", "CONNECTS_TO", "HOSTED_ON", "OBSERVED_BY")
EVIDENCES = ("observed", "reported")
ETATS = ("ok", "inaccessible", "unknown")


@dataclass
class Releve:
    source: str
    etat: str
    empreinte: str
    motif: Optional[str] = None
    entites: List[Dict[str, Any]] = field(default_factory=list)
    relations: List[Dict[str, Any]] = field(default_factory=list)


def _ts_fin(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def ouvrir(chemin: Path) -> sqlite3.Connection:
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(chemin), timeout=5, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA busy_timeout = 5000")
    db.execute("PRAGMA foreign_keys = ON")
    _migrer(db)
    return db


def _migrer(db: sqlite3.Connection) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, appliquee_le TEXT NOT NULL)")
    faites = {r[0] for r in db.execute("SELECT version FROM schema_migrations")}
    maintenant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for f in sorted(MIGRATIONS.iterdir()):
        m = _NOM.match(f.name)
        if not m or int(m.group(1)) in faites:
            continue
        script = ("BEGIN IMMEDIATE;\n" + f.read_text(encoding="utf-8") +
                  f"\nINSERT OR IGNORE INTO schema_migrations(version, appliquee_le) "
                  f"VALUES ({int(m.group(1))}, '{maintenant}');\nCOMMIT;")
        try:
            db.executescript(script)
        except sqlite3.Error:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise


def _valider(releve: Releve) -> None:
    if releve.etat not in ETATS:
        raise ValueError(f"état inconnu : {releve.etat!r}")
    if releve.etat != "ok":
        return
    for e in releve.entites:
        if not isinstance(e.get("id"), str) or not _ID.match(e["id"]):
            raise ValueError(f"identifiant invalide : {e.get('id')!r}")
    for r in releve.relations:
        for cle in ("src", "dst"):
            if not isinstance(r.get(cle), str) or not _ID.match(r[cle]):
                raise ValueError(f"identifiant invalide : {r.get(cle)!r}")
        if r.get("type") not in TYPES_RELATION:
            raise ValueError(f"type de relation invalide : {r.get('type')!r}")
        if r.get("evidence_type") not in EVIDENCES:
            raise ValueError(f"evidence_type refusé : {r.get('evidence_type')!r}")
        j = r.get("justification")
        if not isinstance(j, str) or not j.strip():
            raise ValueError("justification obligatoire")
        c = r.get("confidence")
        if isinstance(c, bool) or not isinstance(c, (int, float)) or not 0 <= c <= 1:
            raise ValueError("confidence hors [0, 1]")


def _taille(db: sqlite3.Connection) -> int:
    pages = db.execute("PRAGMA page_count").fetchone()[0] - db.execute("PRAGMA freelist_count").fetchone()[0]
    return pages * db.execute("PRAGMA page_size").fetchone()[0]


def _json(v: Any) -> str:
    return json.dumps(v or {}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def appliquer(db: sqlite3.Connection, releve: Releve, maintenant: str) -> Dict[str, Any]:
    _valider(releve)
    res: Dict[str, Any] = {"ecrites": 0, "inchangees": 0, "refusees": 0, "plafond": False}
    cur = db.execute("SELECT empreinte, etat FROM curseurs WHERE source = ?", (releve.source,)).fetchone()
    if cur and cur["empreinte"] == releve.empreinte and cur["etat"] == releve.etat:
        res["inchangees"] = len(releve.entites) + len(releve.relations)
        return res
    db.execute("BEGIN IMMEDIATE")
    try:
        if releve.etat == "ok":
            _ecrire(db, releve, maintenant, res)
        # Passe partielle : l'empreinte n'est pas posée, le même relevé sera rejoué (les refus seront retentés).
        empreinte = "" if res["refusees"] else releve.empreinte
        db.execute(
            "INSERT INTO curseurs(source, empreinte, etat, motif, vu_le) VALUES (?,?,?,?,?) "
            "ON CONFLICT(source) DO UPDATE SET empreinte=excluded.empreinte, etat=excluded.etat, "
            "motif=excluded.motif, vu_le=excluded.vu_le",
            (releve.source, empreinte, releve.etat, releve.motif, maintenant))
        db.execute("COMMIT")
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return res


def _ecrire(db: sqlite3.Connection, releve: Releve, maintenant: str, res: Dict[str, Any]) -> None:
    n_ent = db.execute("SELECT count(*) FROM entities").fetchone()[0]
    n_rel = db.execute("SELECT count(*) FROM relationships").fetchone()[0]
    plein = _taille(db) >= BASE_MAX_OCTETS
    for e in releve.entites:
        attrs = _json(e.get("attributes"))
        label = str(e.get("label") or "")
        ex = db.execute("SELECT type, label, attributes_json, last_seen FROM entities WHERE id = ?",
                        (e["id"],)).fetchone()
        if ex is None:
            if plein or n_ent >= ENTITES_MAX:
                res["refusees"] += 1
                res["plafond"] = True
                continue
            db.execute("INSERT INTO entities(id, type, label, attributes_json, source_module, first_seen, last_seen)"
                       " VALUES (?,?,?,?,?,?,?)",
                       (e["id"], e["id"].split(":", 1)[0], label, attrs, releve.source, maintenant, maintenant))
            db.execute("INSERT INTO observations(entity_id, source_module, observed_at, attributes_json) "
                       "VALUES (?,?,?,?)", (e["id"], releve.source, maintenant, attrs))
            n_ent += 1
            res["ecrites"] += 1
        elif ex["label"] == label and ex["attributes_json"] == attrs and ex["last_seen"] == maintenant:
            res["inchangees"] += 1
        else:
            if ex["label"] != label or ex["attributes_json"] != attrs:
                db.execute("INSERT INTO observations(entity_id, source_module, observed_at, attributes_json) "
                           "VALUES (?,?,?,?)", (e["id"], releve.source, maintenant, attrs))
            db.execute("UPDATE entities SET label=?, attributes_json=?, last_seen=? WHERE id=?",
                       (label, attrs, maintenant, e["id"]))
            res["ecrites"] += 1
    for r in releve.relations:
        ex = db.execute("SELECT id, evidence_type, confidence, justification, last_seen FROM relationships "
                        "WHERE src=? AND dst=? AND type=? AND source_module=?",
                        (r["src"], r["dst"], r["type"], releve.source)).fetchone()
        ok = db.execute("SELECT count(*) FROM entities WHERE id IN (?,?)", (r["src"], r["dst"])).fetchone()[0]
        if ok < len({r["src"], r["dst"]}):
            res["refusees"] += 1  # extrémité absente (entité refusée ou inconnue)
            continue
        if ex is None:
            if plein or n_rel >= RELATIONS_MAX:
                res["refusees"] += 1
                res["plafond"] = True
                continue
            db.execute("INSERT INTO relationships(src, dst, type, source_module, first_seen, last_seen, "
                       "evidence_type, confidence, justification) VALUES (?,?,?,?,?,?,?,?,?)",
                       (r["src"], r["dst"], r["type"], releve.source, maintenant, maintenant,
                        r["evidence_type"], float(r["confidence"]), r["justification"].strip()))
            n_rel += 1
            res["ecrites"] += 1
        elif (ex["evidence_type"], ex["confidence"], ex["justification"], ex["last_seen"]) == (
                r["evidence_type"], float(r["confidence"]), r["justification"].strip(), maintenant):
            res["inchangees"] += 1
        else:
            db.execute("UPDATE relationships SET evidence_type=?, confidence=?, justification=?, last_seen=? "
                       "WHERE id=?", (r["evidence_type"], float(r["confidence"]), r["justification"].strip(),
                                      maintenant, ex["id"]))
            res["ecrites"] += 1


def purger(db: sqlite3.Connection, maintenant: str) -> int:
    limite = (_ts_fin(maintenant) - timedelta(days=RETENTION_JOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    total = 0
    while True:
        cur = db.execute("DELETE FROM observations WHERE id IN "
                         "(SELECT id FROM observations WHERE observed_at < ? LIMIT ?)", (limite, LOT_PURGE))
        total += cur.rowcount
        if cur.rowcount < LOT_PURGE:
            return total


def _entite(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    d["attributes"] = json.loads(d.pop("attributes_json") or "{}")
    return d


def lister_entites(db: sqlite3.Connection, type: Optional[str], q: Optional[str], page: int,
                   par_page: int) -> Tuple[List[Dict[str, Any]], int]:
    page = max(1, min(int(page), PAGE_MAX))
    par_page = max(1, min(int(par_page), PAR_PAGE_MAX))
    where, args = [], []
    if type:
        where.append("type = ?")
        args.append(type)
    if q:
        motif = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(id LIKE ? ESCAPE '\\' OR label LIKE ? ESCAPE '\\')")
        args += [motif, motif]
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total = db.execute("SELECT count(*) FROM entities" + clause, args).fetchone()[0]
    rows = db.execute("SELECT * FROM entities" + clause + " ORDER BY id LIMIT ? OFFSET ?",
                      args + [par_page, (page - 1) * par_page]).fetchall()
    return [_entite(r) for r in rows], total


def entite(db: sqlite3.Connection, id: str) -> Optional[Dict[str, Any]]:
    r = db.execute("SELECT * FROM entities WHERE id = ?", (id,)).fetchone()
    return _entite(r) if r else None


def voisins(db: sqlite3.Connection, id: str, max_noeuds: int = VOISINS_NOEUDS_MAX,
            max_aretes: int = VOISINS_ARETES_MAX) -> Dict[str, Any]:
    max_noeuds = max(1, min(max_noeuds, VOISINS_NOEUDS_MAX))
    max_aretes = max(1, min(max_aretes, VOISINS_ARETES_MAX))
    centre = entite(db, id)
    if centre is None:
        return {"noeuds": [], "aretes": [], "tronque": False}
    aretes = [dict(r) for r in db.execute(
        "SELECT * FROM relationships WHERE src = ? OR dst = ? ORDER BY id", (id, id))]
    ids: List[str] = []
    vus = set()
    for a in aretes:
        autre = a["dst"] if a["src"] == id else a["src"]
        if autre != id and autre not in vus:
            vus.add(autre)
            ids.append(autre)
    tronque = len(ids) + 1 > max_noeuds
    ids = ids[:max_noeuds - 1]
    gardes = set(ids) | {id}
    retenues = [a for a in aretes if a["src"] in gardes and a["dst"] in gardes]
    if len(retenues) < len(aretes):
        tronque = True
    if len(retenues) > max_aretes:
        retenues = retenues[:max_aretes]
        tronque = True
    noeuds = [centre] + [e for e in (entite(db, i) for i in ids) if e]
    return {"noeuds": noeuds, "aretes": retenues, "tronque": tronque}


def etat_sources(db: sqlite3.Connection) -> List[Dict[str, Any]]:
    return [dict(r) for r in db.execute("SELECT source, etat, motif, empreinte, vu_le FROM curseurs ORDER BY source")]
