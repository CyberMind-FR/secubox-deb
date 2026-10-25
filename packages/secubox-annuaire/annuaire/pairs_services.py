# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3133 — cache fichier des services publics offerts par les AUTRES nœuds du maillage.

webos le sert sans appeler l'API de l'Annuaire (qui exige un jeton). Tout ce qui vient du journal est tenu pour
hostile : un endpoint n'est retenu que s'il est en https, sans identifiants ni port, et si son nom d'hôte
appartient au domaine ddns que le fournisseur a lui-même déclaré.
"""
import ipaddress
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
# Politique de domaine (#3146) : un pair ne fait afficher que des liens sous <un libellé>.<parent>. Liste blanche facultative.
PARENTS = ("secubox.in",)
BLANCHE_PATH = Path("/etc/secubox/annuaire/domaines-pairs.txt")

_HOTE = re.compile(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?")
_LIBELLE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_BOXNAME = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
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


def _domaine(v: Any) -> str:
    """Le ddns en minuscules s'il a au moins deux libellés valides, sinon chaîne vide."""
    if not isinstance(v, str):
        return ""
    d = v.strip().lower().rstrip(".")
    libelles = d.split(".")
    return d if len(d) <= 253 and len(libelles) >= 2 and all(_LIBELLE.fullmatch(lib) for lib in libelles) else ""


def domaines_blancs(chemin: Path = BLANCHE_PATH) -> frozenset:
    """Domaines supplémentaires admis (un par ligne, `#` = commentaire). Fichier absent ou illisible : aucun."""
    try:
        lignes = Path(chemin).read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError):
        return frozenset()
    return frozenset(d for d in (_domaine(ligne.split("#", 1)[0]) for ligne in lignes) if d)


def _admis(d: str, parents: Any, blancs: Any) -> bool:
    """`<un libellé>.<parent>` exactement (jamais un niveau de plus), ou un domaine de la liste blanche."""
    if d in blancs:
        return True
    return any(d.endswith("." + p) and "." not in d[: -len(p) - 1] for p in parents)


def construire(journal: Any, did_local: str, parents: Any = None, blancs: Any = None) -> Dict[str, Any]:
    """Relève dans le journal les offres `service` des autres nœuds, vérifiées contre leur domaine ddns.

    `parents` (défaut `PARENTS`) et `blancs` (défaut : le fichier de liste blanche) fixent les domaines admis."""
    parents = PARENTS if parents is None else parents
    blancs = domaines_blancs() if blancs is None else blancs
    from annuaire.verbs import _get_nodes, _get_offers  # noqa: PLC0415
    # Le ddns déclaré par un pair est hostile lui aussi : il doit être un vrai domaine (deux libellés au moins),
    # propre à ce seul DID, ni celui de la box locale (ni son parent), ni le parent ambigu du ddns d'un autre nœud.
    declares: List[Dict[str, Any]] = []
    for n in _get_nodes(journal):
        d = _domaine(n.get("ddns"))
        if n.get("did") and d:
            declares.append({"n": n, "ddns": d})
    local = next((x["ddns"] for x in declares if x["n"]["did"] == did_local), "")
    noeuds: Dict[str, Dict[str, Any]] = {}
    for x in declares:
        n, d = x["n"], x["ddns"]
        if n["did"] == did_local:
            continue
        if not _admis(d, parents, blancs):
            continue
        if any(y["ddns"] == d and y["n"]["did"] != n["did"] for y in declares):
            continue
        if local and (d == local or local.endswith("." + d)):
            continue
        if any(y["n"]["did"] != n["did"] and y["ddns"].endswith("." + d) for y in declares):
            continue
        try:
            ip = ipaddress.ip_address(n.get("mesh_ip"))
        except ValueError:
            continue
        if ip.version != 4:
            continue
        boxname = n.get("boxname") if isinstance(n.get("boxname"), str) and _BOXNAME.fullmatch(n["boxname"]) else ""
        noeuds[n["did"]] = {"did": n["did"], "boxname": boxname, "domaine": d,
                            "mesh_ip": str(ip), "services": []}
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
