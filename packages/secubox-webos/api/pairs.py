# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — services offerts par les autres box du maillage (#3133).

Lit le cache fichier écrit par l'annuaire. Le cache vient de données publiées par
d'autres nœuds : il est traité comme une entrée non fiable (bornes, types,
https seulement) et tout élément malformé est écarté sans faire échouer la lecture.
"""
import ipaddress
import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional

CACHE = Path("/var/lib/secubox/annuaire/services-pairs.json")

MAX_OCTETS = 1_000_000
MAX_PAIRS = 32
MAX_SERVICES = 64
MAX_NOM = 63
MAX_ENDPOINT = 255
MAX_CHAMP = 255
MAX_DESCRIPTION = 255


_LIBELLE = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOTE = rf"{_LIBELLE}(?:\.{_LIBELLE})+"
# https + nom d'hôte en minuscules (sans port ni identifiant) + chemin facultatif sans ? ni #.
_ENDPOINT = re.compile(rf"https://{_HOTE}(?:/[A-Za-z0-9._~/%-]*)?")
_HOTE_RE = re.compile(_HOTE)
_DID = re.compile(r"did:plc:[0-9a-f]{32}")


def _vide() -> Dict[str, Any]:
    return {"pairs": [], "genere": None, "disponible": False}


def _texte(v: Any, borne: int) -> Optional[str]:
    """Chaîne bornée, sinon None."""
    if isinstance(v, str) and len(v) <= borne \
            and not any(unicodedata.category(c) in ("Cc", "Cf") for c in v):
        return v
    return None


def _service(brut: Any) -> Optional[Dict[str, str]]:
    if not isinstance(brut, dict):
        return None
    nom = _texte(brut.get("nom"), MAX_NOM)
    ep = _texte(brut.get("endpoint"), MAX_ENDPOINT)
    if not nom or not ep or not _ENDPOINT.fullmatch(ep):
        return None
    desc = _texte(brut.get("description"), MAX_DESCRIPTION)
    return {"nom": nom, "endpoint": ep, "description": desc or ""}


def _pair(brut: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(brut, dict):
        return None
    did = brut.get("did")
    if not isinstance(did, str) or not _DID.fullmatch(did):
        return None
    domaine = _texte(brut.get("domaine"), 253)
    ip = brut.get("mesh_ip")
    try:
        ip_ok = str(ipaddress.IPv4Address(ip)) if isinstance(ip, str) else ""
    except ValueError:
        ip_ok = ""
    champs: Dict[str, str] = {
        "did": did,
        "boxname": _texte(brut.get("boxname"), MAX_CHAMP) or "",
        "domaine": domaine if domaine and _HOTE_RE.fullmatch(domaine) else "",
        "mesh_ip": ip_ok,
    }
    brut_svc = brut.get("services")
    services: List[Dict[str, str]] = []
    if isinstance(brut_svc, list):
        for s in brut_svc[:MAX_SERVICES]:
            ok = _service(s)
            if ok:
                services.append(ok)
    return {**champs, "services": services}


def lire_cache(chemin: Optional[Path] = None) -> Dict[str, Any]:
    """Cache des services des pairs, assaini ; jamais d'exception."""
    chemin = chemin or CACHE  # résolu à l'appel (CACHE substituable en test)
    try:
        with open(chemin, "rb") as fh:
            octets = fh.read(MAX_OCTETS + 1)
        if len(octets) > MAX_OCTETS:
            return _vide()
        doc = json.loads(octets.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        return _vide()
    if not isinstance(doc, dict) or type(doc.get("version")) is not int or doc["version"] != 1:
        return _vide()
    brut = doc.get("pairs")
    if not isinstance(brut, list):
        return _vide()
    pairs: List[Dict[str, Any]] = []
    for p in brut[:MAX_PAIRS]:
        ok = _pair(p)
        if ok:
            pairs.append(ok)
    return {"pairs": pairs, "genere": _texte(doc.get("genere"), 64), "disponible": True}
