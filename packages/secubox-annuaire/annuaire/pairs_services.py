# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — cache fichier des services publics offerts par les AUTRES nœuds du maillage.

webos le sert sans appeler l'API de l'Annuaire (qui exige un jeton). Tout ce qui vient du journal est tenu pour
hostile : un endpoint n'est retenu que s'il est en https, sans identifiants ni port, et si son nom d'hôte
appartient au domaine ddns que le fournisseur a lui-même déclaré.
"""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

CACHE_PATH = Path("/var/lib/secubox/annuaire/services-pairs.json")
VERSION = 1
MAX_PAIRS = 32
MAX_SERVICES = 64

_HOTE = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
_DOMAINE = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
_CTRL = re.compile(r"[\x00-\x20\x7f\\]")


def _texte(v: Any, taille: int) -> str:
    """Texte d'affichage : sans caractères de contrôle, tronqué."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", v if isinstance(v, str) else "").strip()[:taille]


def _endpoint_valide(endpoint: Any, ddns: str) -> bool:
    if not isinstance(endpoint, str) or len(endpoint) > 512 or _CTRL.search(endpoint):
        return False
    try:
        u = urlsplit(endpoint)
        port = u.port
    except ValueError:
        return False
    if u.scheme != "https" or u.username is not None or u.password is not None or port is not None:
        return False
    hote = (u.hostname or "").lower()
    if "@" in u.netloc or ":" in u.netloc or not _HOTE.fullmatch(hote):
        return False
    return hote.endswith("." + ddns) and len(hote) > len(ddns) + 1


def construire(journal: Any, did_local: str) -> Dict[str, Any]:
    """Relève dans le journal les offres `service` des autres nœuds, vérifiées contre leur domaine ddns."""
    from annuaire.verbs import _get_nodes, _get_offers  # noqa: PLC0415
    noeuds: Dict[str, Dict[str, Any]] = {}
    for n in _get_nodes(journal):
        ddns = n.get("ddns")
        ddns = ddns.strip().lower().strip(".") if isinstance(ddns, str) else ""
        if n.get("did") and ddns and _DOMAINE.fullmatch(ddns):
            noeuds[n["did"]] = {"did": n["did"], "boxname": _texte(n.get("boxname"), 64), "domaine": ddns,
                                "mesh_ip": _texte(n.get("mesh_ip"), 64), "services": []}
    for o in _get_offers(journal):
        if o.get("kind") != "service" or o.get("provider") == did_local:
            continue
        pair = noeuds.get(o.get("provider"))
        if pair is None or not _endpoint_valide(o.get("endpoint"), pair["domaine"]):
            continue
        nom = _texte(o.get("name"), 64)
        if nom:
            pair["services"].append({"nom": nom, "endpoint": o["endpoint"], "description": _texte(o.get("description"), 200)})
    pairs: List[Dict[str, Any]] = []
    for pair in noeuds.values():
        if pair["did"] == did_local or not pair["services"]:
            continue
        pair["services"].sort(key=lambda s: (s["nom"], s["endpoint"]))
        pair["services"] = pair["services"][:MAX_SERVICES]
        pairs.append(pair)
    pairs.sort(key=lambda p: (p["boxname"], p["did"]))
    return {"version": VERSION, "genere": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pairs": pairs[:MAX_PAIRS]}


def ecrire(donnees: Dict[str, Any], chemin: Path = CACHE_PATH) -> None:
    """Écriture atomique (.tmp puis os.replace), mode 0644."""
    chemin = Path(chemin)
    tmp = chemin.with_name(chemin.name + ".tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(donnees, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, chemin)
    finally:
        if tmp.exists():
            tmp.unlink()


def lire(chemin: Path = CACHE_PATH) -> Optional[Dict[str, Any]]:
    """Le cache, ou None s'il est absent, illisible ou d'une autre version."""
    try:
        d = json.loads(Path(chemin).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) and d.get("version") == VERSION else None
