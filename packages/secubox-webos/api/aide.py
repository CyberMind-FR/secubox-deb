# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: webos — AIDE DES CARTES DU HALL (#1664).

Une seule source (aide_cartes.json) pour trois lecteurs : la bulle ❓ du Hall,
la vue Aide, et ZIA/Lexie. Chaque carte y dit ce qu'elle est (rôle), comment
s'en servir (usage), et OÙ lire ses chiffres (métriques déclarées).

LES CHIFFRES SONT LUS EN VISITEUR. Le serveur interroge le nginx du Hall en
boucle locale en se présentant comme un client WAN (X-Forwarded-For d'une
adresse de documentation, RFC 5737) : real_ip en fait l'adresse du client, le
verdict LAN tombe, aucun cookie n'est présenté. Ce qu'il lit, n'importe quel
visiteur peut déjà le lire — aucune donnée gardée ne fuit par l'aide. Une
métrique marquée `session` n'est pas calculée ici : la bulle du Hall la
complète dans le navigateur, avec les droits de la personne.

On ne rend que des AGRÉGATS (un nombre, un titre), jamais la liste lue.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Optional

SOURCE = Path(__file__).with_name("aide_cartes.json")
# Adresse de documentation (TEST-NET-1) : jamais LAN, jamais routée.
XFF_VISITEUR = "192.0.2.1"
PORT_HALL = 9080
CACHE_S = 30.0
DELAI_S = 4.0

_JETON = re.compile(r"^([^\[\]]*)(?:\[([^\]=]*)(?:=([^\]]*))?\])?$")


def charger(chemin: Path = SOURCE) -> dict:
    """{id: carte} depuis la source ; une source illisible → {} (jamais 500)."""
    try:
        cartes = json.loads(chemin.read_text(encoding="utf-8")).get("cartes") or []
    except (OSError, ValueError):
        return {}
    return {c["id"]: c for c in cartes if isinstance(c, dict) and c.get("id")}


def _egal(v: Any, attendu: str) -> bool:
    if isinstance(v, bool):
        return attendu.lower() == ("true" if v else "false")
    return str(v) == attendu


def _pas(x: Any, jeton: str) -> Any:
    """Un pas de chemin : `nom`, `nom[k=v]` (filtre), `nom[]` (chaque élément),
    `[k=v]` sur la racine, ou un indice numérique."""
    m = _JETON.match(jeton)
    if not m:
        return None
    nom, cle, val = m.group(1), m.group(2), m.group(3)
    if nom:
        if isinstance(x, list) and nom.isdigit():
            i = int(nom)
            x = x[i] if i < len(x) else None
        elif isinstance(x, dict):
            x = x.get(nom)
        else:
            return None
    if cle is None:
        return x
    if not isinstance(x, list):
        return None
    if cle == "" and val is None:          # nom[] : la liste telle quelle
        return x
    return [e for e in x if isinstance(e, dict) and _egal(e.get(cle), val or "")]


def extraire(donnee: Any, chemin: str) -> Any:
    """Suit un chemin pointé. Un filtre suivi d'un champ prend le premier
    élément retenu ; `liste[].champ` rend la liste des champs."""
    x = donnee
    jetons = chemin.split(".") if chemin else []
    for k, j in enumerate(jetons):
        suite = k + 1 < len(jetons)
        x = _pas(x, j)
        if x is None:
            return None
        if suite and isinstance(x, list) and not jetons[k + 1].isdigit():
            if j.endswith("[]"):
                reste = ".".join(jetons[k + 1:])
                return [extraire(e, reste) for e in x]
            x = x[0] if x else None
            if x is None:
                return None
    return x


def valeur(metrique: dict, donnee: Any) -> Any:
    """La valeur d'une métrique sur la réponse lue — nombre ou texte court."""
    if "compte" in metrique:
        cible = extraire(donnee, metrique["compte"]) if metrique["compte"] else donnee
        return len(cible) if isinstance(cible, (list, dict)) else None
    if "somme" in metrique:
        vals = extraire(donnee, metrique["somme"])
        if not isinstance(vals, list):
            return None
        return sum(v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool))
    v = extraire(donnee, metrique.get("chemin", ""))
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return v
    if metrique.get("format") == "texte" and isinstance(v, str):
        return v.strip()[:120] or None
    return None


def publique(carte: dict) -> dict:
    """La carte telle qu'on la rend : sans les url internes des métriques."""
    out = {k: carte.get(k) for k in ("id", "ic", "nom", "role", "usage", "acces", "service")}
    out["metriques"] = [{"libelle": m.get("libelle", ""), "format": m.get("format", "nombre"),
                         "session": bool(m.get("session")), "url": m.get("url") if m.get("session") else None,
                         **{k: m[k] for k in ("chemin", "compte", "somme") if m.get("session") and k in m}}
                        for m in carte.get("metriques") or []]
    return out


class Lecteur:
    """Lit les métriques en visiteur, avec un cache court par carte."""

    def __init__(self, domaine: str, port: int = PORT_HALL, _get=None):
        self.domaine = domaine
        self.port = port
        self._get = _get
        self._cache: dict[str, tuple[float, list]] = {}

    async def _lire(self, hote: str, url: str) -> Any:
        if self._get:
            return await self._get(hote, url)
        import httpx
        async with httpx.AsyncClient(timeout=DELAI_S) as cli:
            r = await cli.get(f"http://127.0.0.1:{self.port}{url}",
                              headers={"Host": hote, "X-Forwarded-For": XFF_VISITEUR,
                                       "X-Forwarded-Proto": "https", "Accept": "application/json"})
            if r.status_code != 200:
                return None
            return r.json()

    async def metriques(self, carte: dict) -> list:
        cid = carte.get("id", "")
        now = time.monotonic()
        if cid in self._cache and now - self._cache[cid][0] < CACHE_S:
            return self._cache[cid][1]
        decl = carte.get("metriques") or []
        sources: dict[tuple, Any] = {}
        a_lire = {(m.get("hote") or "hall", m["url"]) for m in decl if m.get("url") and not m.get("session")}

        async def une(cle):
            hote = f"{cle[0]}.{self.domaine}" if self.domaine else cle[0]
            try:
                sources[cle] = await self._lire(hote, cle[1])
            except Exception:
                sources[cle] = None

        await asyncio.gather(*(une(c) for c in a_lire))
        out = []
        for m in decl:
            v = None
            if not m.get("session") and m.get("url"):
                d = sources.get((m.get("hote") or "hall", m["url"]))
                v = valeur(m, d) if d is not None else None
            out.append({"libelle": m.get("libelle", ""), "valeur": v,
                        "format": m.get("format", "nombre"), "session": bool(m.get("session"))})
        self._cache[cid] = (now, out)
        return out


def phrase(carte: dict, metriques: list) -> str:
    """La carte dite en une ou deux phrases — ce que ZIA écrit et Lexie lit."""
    txt = f"{carte.get('nom', '')} : {carte.get('role', '')}".strip()
    # « libellé : valeur » — jamais « 1 auditeurs » : l'accord ne se devine pas.
    chiffres = [f"{m['libelle']} : {_fmt(m)}" for m in metriques if m.get("valeur") is not None]
    if chiffres:
        txt += " En ce moment — " + " ; ".join(chiffres) + "."
    return txt


def _fmt(m: dict) -> str:
    v = m.get("valeur")
    if m.get("format") == "octets" and isinstance(v, (int, float)):
        for u in ("o", "Ko", "Mo", "Go", "To"):
            if v < 1024:
                return f"{v:.0f} {u}" if u == "o" else f"{v:.1f} {u}"
            v /= 1024
        return f"{v:.1f} Po"
    if isinstance(v, float):
        return f"{v:.1f}"
    if isinstance(v, int):
        return f"{v:,}".replace(",", " ")
    return str(v)


def trouver(cartes: dict, texte: str) -> Optional[dict]:
    """La carte que désigne un texte libre (id, nom, ou mot du nom)."""
    t = _norm(texte)
    if not t:
        return None
    for c in cartes.values():
        if _norm(c.get("id", "")) == t or _norm(c.get("nom", "")) == t:
            return c
    def dans(mot: str) -> bool:
        return bool(mot) and re.search(r"(?<![a-z0-9])" + re.escape(mot) + r"(?![a-z0-9+])", t) is not None
    meilleurs = [c for c in cartes.values()
                 if dans(_norm(c.get("nom", ""))) or dans(_norm(c.get("id", "")))]
    # le nom le plus long gagne (« cloud + » avant « cloud »)
    meilleurs.sort(key=lambda c: -len(c.get("nom", "")))
    return meilleurs[0] if meilleurs else None


def _norm(s: str) -> str:
    import unicodedata
    s = unicodedata.normalize("NFKD", str(s or "")).encode("ascii", "ignore").decode().lower()
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9+ ]", " ", s)).strip()
