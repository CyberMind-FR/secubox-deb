# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API de DataScope (#3853) sur /run/secubox/datascope.sock — lecture seule, aucune route mutante.

Routes : /health (publique), /status, /overview, /sources (require_lecture), /entities, /entities/{id},
/entities/{id}/context, /entities/{id}/neighbors, /graph (require_jwt). Base ouverte en lecture seule par requête.
Les lectures de fichier passent par `asyncio.to_thread` : jamais d'E/S bloquante sur la boucle.
"""
from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

from secubox_datascope import VERSION, config, store  # noqa: E402

CFG = config.charger()
router = APIRouter(prefix="/api/v1/datascope")


def _etat(cfg: config.Config) -> Dict[str, Any]:
    try:
        st = cfg.base.stat()
    except OSError:
        return {"module": "datascope", "base": "absente", "derniere_passe": None}
    # Battement verifie_le d'overview.json (réécrit à chaque passe qui atteint ses sources) ; la base n'est plus
    # réécrite quand rien ne change, son mtime n'est qu'un repli.
    passe: Optional[str] = None
    ov = _lire_cache("overview.json", cfg)
    if ov is not None and _epoch(ov.get("verifie_le")) is not None:
        passe = ov["verifie_le"]
    if passe is None:
        passe = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"module": "datascope", "base": "ok", "derniere_passe": passe}


def status() -> Dict[str, Any]:
    return _etat(CFG)


@router.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "module": "datascope", "version": VERSION}


@router.get("/status", dependencies=[Depends(require_lecture)])
async def status_route() -> Dict[str, Any]:
    return await asyncio.to_thread(status)


PERIME_S = 180
TYPES = ("node", "network", "interface", "device", "ip", "service")
# Module propriétaire d'une entité (source_module) -> source du curseur ; défaut : identité.
SOURCE_DU_MODULE = {"nac": "network"}
_MODULE = re.compile(r"[a-z0-9_-]{1,64}")
NON_LIVRE = "non livré en V0.1"


def _ro(base: Path) -> sqlite3.Connection:
    """Connexion en lecture seule, par requête ; jamais de création ni de migration."""
    db = sqlite3.connect(f"file:{base}?mode=ro", uri=True, timeout=5, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout = 5000")
    db.execute("PRAGMA temp_store = MEMORY")  # table temporaire du graphe filtré : jamais de fichier temporaire
    return db


def _lire_base(fn):
    """Exécute fn(db) sur la base en lecture seule ; base absente ou illisible => 503 JSON."""
    try:
        db = _ro(CFG.base)
    except sqlite3.Error:
        raise HTTPException(status_code=503, detail="base DataScope indisponible")
    try:
        return fn(db)
    except sqlite3.Error:
        raise HTTPException(status_code=503, detail="base DataScope illisible")
    finally:
        db.close()


def _etats(db: sqlite3.Connection) -> Dict[str, str]:
    return {s["source"]: s["etat"] for s in store.etat_sources(db)}


def _etat_de(e: Dict[str, Any], etats: Dict[str, str]) -> str:
    sm = e.get("source_module") or ""
    return etats.get(SOURCE_DU_MODULE.get(sm, sm), "unknown")


def _surcouche(e: Dict[str, Any], etats: Dict[str, str]) -> Dict[str, Any]:
    """etat_source sur toute entité ; hors « ok », overall d'un service rendu « unknown » (jamais la valeur stockée)."""
    e = dict(e)
    etat = _etat_de(e, etats)
    e["etat_source"] = etat
    if etat != "ok" and e.get("type") == "service":
        attrs = dict(e.get("attributes") or {})
        attrs["overall"] = "unknown"
        e["attributes"] = attrs
        if "overall" in e:
            e["overall"] = "unknown"
    return e


def _valider_id(id: str) -> str:
    if not store.id_valide(id):
        raise HTTPException(status_code=400, detail="identifiant invalide")
    return id


def _epoch(s: Any) -> Optional[float]:
    if not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _lire_cache(nom: str, cfg: Optional[config.Config] = None) -> Optional[Dict[str, Any]]:
    try:
        d = json.loads((Path((cfg or CFG).cache) / nom).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def _overview() -> Dict[str, Any]:
    d = _lire_cache("overview.json")
    if d is None:
        return {"disponible": False, "motif": "relevé absent ou illisible"}
    t = _epoch(d.get("verifie_le")) or _epoch(d.get("genere_le"))
    d = dict(d)
    d["disponible"] = True
    d["perime"] = t is None or datetime.now(timezone.utc).timestamp() - t > PERIME_S
    return d


def _liens(e: Dict[str, Any]) -> List[Dict[str, str]]:
    """Liens seulement vers la page du module propriétaire ; aucune action en V0.1."""
    if e["type"] == "device":
        return [{"libelle": "Ouvrir dans le NAC", "href": "/nac/"}]
    if e["type"] == "service":
        mod = e["id"].split(":", 1)[1]
        if not _MODULE.fullmatch(mod):
            return []
        return [{"libelle": f"Ouvrir le module {mod}", "href": f"/{mod}/"}]
    return []


@router.get("/overview", dependencies=[Depends(require_lecture)])
async def overview() -> Dict[str, Any]:
    return await asyncio.to_thread(_overview)


@router.get("/sources", dependencies=[Depends(require_lecture)])
async def sources() -> Dict[str, Any]:
    def lire(db):
        return [{k: v for k, v in s.items() if k != "empreinte"} for s in store.etat_sources(db)]
    return {"sources": await asyncio.to_thread(_lire_base, lire)}


@router.get("/entities", dependencies=[Depends(require_jwt)])
async def entities(type: Optional[str] = Query(None, max_length=16), q: Optional[str] = Query(None, max_length=128),
                   page: int = Query(1, ge=1, le=store.PAGE_MAX),
                   par_page: int = Query(store.PAR_PAGE_DEFAUT, ge=1, le=store.PAR_PAGE_MAX)) -> Dict[str, Any]:
    if type is not None and type not in TYPES:
        raise HTTPException(status_code=400, detail="type inconnu")

    def lire(db):
        liste, total = store.lister_entites(db, type, q, page, par_page)
        etats = _etats(db)
        return {"entites": [_surcouche(e, etats) for e in liste], "total": total, "page": page,
                "par_page": par_page}
    return await asyncio.to_thread(_lire_base, lire)


def _fiche(id: str) -> Dict[str, Any]:
    def lire(db):
        e = store.entite(db, id)
        if e is None:
            raise HTTPException(status_code=404, detail="entité inconnue")
        return _surcouche(e, _etats(db))
    return _lire_base(lire)


@router.get("/entities/{id}", dependencies=[Depends(require_jwt)])
async def entity(id: str) -> Dict[str, Any]:
    return await asyncio.to_thread(_fiche, _valider_id(id))


def _voisins(id: str) -> Dict[str, Any]:
    def lire(db):
        if store.entite(db, id) is None:
            raise HTTPException(status_code=404, detail="entité inconnue")
        v = store.voisins(db, id)
        etats = _etats(db)
        return {"noeuds": [_surcouche(n, etats) for n in v["noeuds"]], "aretes": v["aretes"],
                "tronque": v["tronque"]}
    return _lire_base(lire)


@router.get("/entities/{id}/neighbors", dependencies=[Depends(require_jwt)])
async def neighbors(id: str) -> Dict[str, Any]:
    return await asyncio.to_thread(_voisins, _valider_id(id))


def _contexte(id: str) -> Dict[str, Any]:
    def lire(db):
        e = store.entite(db, id)
        if e is None:
            raise HTTPException(status_code=404, detail="entité inconnue")
        etats = _etats(db)
        ent = _surcouche(e, etats)
        v = store.voisins(db, id)
        sms = {e["source_module"]} | {a["source_module"] for a in v["aretes"]}
        prov = []
        for sm in sorted(sms):
            src = SOURCE_DU_MODULE.get(sm, sm)
            prov.append({"source_module": sm, "source": src, "etat_source": etats.get(src, "unknown")})
        return {
            "entity": ent,
            "summary": {"type": ent["type"], "label": ent["label"], "first_seen": ent["first_seen"],
                        "last_seen": ent["last_seen"], "relations": len(v["aretes"]),
                        "voisins": len(v["noeuds"]) - 1, "tronque": v["tronque"]},
            "relationships": v["aretes"],
            "recent_events": None,
            "history": None,
            "motifs": {"recent_events": NON_LIVRE, "history": NON_LIVRE},
            "available_actions": _liens(ent),
            "source_provenance": prov,
        }
    return _lire_base(lire)


@router.get("/entities/{id}/context", dependencies=[Depends(require_jwt)])
async def context(id: str) -> Dict[str, Any]:
    return await asyncio.to_thread(_contexte, _valider_id(id))


def _borner_cache(g: Dict[str, Any], etats: Dict[str, str]) -> Dict[str, Any]:
    """Bornes défensives sur graph.json : 500 nœuds, 1 500 arêtes entre nœuds retenus."""
    n_cache, a_cache = g.get("noeuds"), g.get("aretes")
    if not isinstance(n_cache, list) or not isinstance(a_cache, list):
        return {"disponible": False, "motif": "graph.json de forme inattendue"}
    brut_n = [n for n in n_cache if isinstance(n, dict) and isinstance(n.get("id"), str)]
    brut_a = [a for a in a_cache if isinstance(a, dict) and isinstance(a.get("src"), str)
              and isinstance(a.get("dst"), str)]
    noeuds = brut_n[:store.VOISINS_NOEUDS_MAX]
    ids = {n["id"] for n in noeuds}
    aretes = [a for a in brut_a if a["src"] in ids and a["dst"] in ids]
    tronque = bool(g.get("tronque")) or len(brut_n) < len(n_cache) or len(brut_a) < len(a_cache) \
        or len(noeuds) < len(brut_n) or len(aretes) < len(brut_a)
    if len(aretes) > store.VOISINS_ARETES_MAX:
        aretes = aretes[:store.VOISINS_ARETES_MAX]
        tronque = True
    out = dict(g)
    out.update({"disponible": True, "noeuds": [_surcouche(n, etats) for n in noeuds], "aretes": aretes,
                "tronque": tronque})
    return out


def _aretes_entre(db: sqlite3.Connection, ids: List[str]) -> List[Dict[str, Any]]:
    """Arêtes dont src ET dst sont dans ids : SQL borné (LIMIT 1501), par paquets de 900 paramètres au plus."""
    if not ids:
        return []
    db.execute("CREATE TEMP TABLE IF NOT EXISTS _sel(id TEXT PRIMARY KEY)")
    db.execute("DELETE FROM _sel")
    for i in range(0, len(ids), 900):
        lot = ids[i:i + 900]
        db.execute("INSERT OR IGNORE INTO _sel(id) VALUES " + ",".join("(?)" for _ in lot), lot)
    return [dict(r) for r in db.execute(
        "SELECT src, dst, type, evidence_type, confidence, source_module, last_seen FROM relationships "
        "WHERE src IN (SELECT id FROM _sel) AND dst IN (SELECT id FROM _sel) "
        "ORDER BY src, dst, type, source_module LIMIT ?", (store.VOISINS_ARETES_MAX + 1,))]


def _graphe(type: Optional[str]) -> Dict[str, Any]:
    def lire(db):
        etats = _etats(db)
        if type is None:
            g = _lire_cache("graph.json")
            if g is None:
                return {"disponible": False, "motif": "relevé absent ou illisible"}
            return _borner_cache(g, etats)
        noeuds = [dict(r) for r in db.execute(
            "SELECT id, type, label, source_module, first_seen, last_seen FROM entities WHERE type = ? "
            "ORDER BY id LIMIT ?", (type, store.VOISINS_NOEUDS_MAX + 1))]
        tronque = len(noeuds) > store.VOISINS_NOEUDS_MAX
        noeuds = noeuds[:store.VOISINS_NOEUDS_MAX]
        aretes = _aretes_entre(db, [n["id"] for n in noeuds])
        if len(aretes) > store.VOISINS_ARETES_MAX:
            aretes = aretes[:store.VOISINS_ARETES_MAX]
            tronque = True
        return {"disponible": True, "noeuds": [_surcouche(n, etats) for n in noeuds], "aretes": aretes,
                "tronque": tronque}
    return _lire_base(lire)


@router.get("/graph", dependencies=[Depends(require_jwt)])
async def graph(type: Optional[str] = Query(None, max_length=16)) -> Dict[str, Any]:
    if type is not None and type not in TYPES:
        raise HTTPException(status_code=400, detail="type inconnu")
    return await asyncio.to_thread(_graphe, type)


app = FastAPI(title="SecuBox DataScope", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
