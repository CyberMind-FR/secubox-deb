# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Connecteur « paysage » (#3921) : relevé des populations du WAF (`populations.json`) vers un graphe typé.

Fonction pure, sans réseau : le fichier est lu une fois, borné (MAX_OCTETS). Tout champ du producteur
(`secubox-waf-ng`, api/populations.py) peut manquer ou être d'un mauvais type : il est alors ignoré, jamais une
exception. L'identifiant d'une population est opaque. Aucune adresse IP n'entre dans le graphe : toute chaîne qui en
contient une est écartée (nœud, étiquette ou valeur). Les identifiants de nœud sont assainis selon `ID_NOEUD`.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

MAX_OCTETS = 8 * 1024 * 1024
MAX_POPULATIONS = 12
MAX_ASN_PAR_POP = 8
MAX_CIBLES = 60
MAX_CVES = 20
MAX_NOEUDS = 400
MAX_SERIE = 31
ID_NOEUD = re.compile(r"^[a-z_]+:[A-Za-z0-9:._-]{1,160}$")
_HORS_ID = re.compile(r"[^A-Za-z0-9:._-]+")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_SIGNATURE = re.compile(r"^[0-9A-Za-z_-]{1,64}$")
_PAYS = re.compile(r"^[A-Z]{2}$")
_HOTE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")
_CLASSE = re.compile(r"^[a-z_]{1,40}$")
_IPV4 = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_JETON = re.compile(r"[0-9A-Fa-f:.]{2,}")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_EPOCH_MAX = 253402300799  # 9999-12-31


@dataclass
class Paysage:
    epoch: float
    partiel: bool
    graphe: dict
    compteurs: dict


def _contient_ip(s: str) -> bool:
    """Vrai si la chaîne (400 premiers caractères) contient une IPv4 ou une IPv6, même collée à d'autres caractères."""
    s = s[:400]
    if _IPV4.search(s):
        return True
    for m in _JETON.findall(s):
        groupes = m.split(":")
        if len(groupes) < 2:
            continue
        for i in range(len(groupes)):                 # toute fenêtre de groupes consécutifs (une IPv6 en a 9 au plus)
            for j in range(i + 2, min(len(groupes), i + 9) + 1):
                try:
                    ipaddress.ip_address(":".join(groupes[i:j]))
                    return True
                except ValueError:
                    continue
    return False


def _suffixe(v: Any) -> Optional[str]:
    """Partie d'identifiant assainie (caractères permis seulement, 160 max) ; None si vide, ou porteuse d'une IP."""
    if not isinstance(v, str) or _contient_ip(v):
        return None
    s = _HORS_ID.sub("_", v.strip())[:160].strip("_")
    if _contient_ip(s):
        return None
    return s or None


def _texte(v: Any, n: int = 80) -> str:
    """Étiquette libre : chaîne sans caractère de contrôle, tronquée ; vide si elle porte une IP."""
    if not isinstance(v, str) or _contient_ip(v):
        return ""
    return _CTRL.sub(" ", v).strip()[:n]


def _entier(v: Any, maxi: int = 10 ** 12) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        return 0
    return max(0, min(v, maxi))


def _liste(v: Any) -> list:
    return v if isinstance(v, list) else []


def _dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _epoch(v: Any) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if isinstance(v, float) and not math.isfinite(v):
        return None
    return float(v) if 0 <= v <= _EPOCH_MAX else None


def _charger(chemin: Path) -> Any:
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb", closefd=False) as f:
            brut = f.read(MAX_OCTETS + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(brut) > MAX_OCTETS:
        return None
    try:
        return json.loads(brut.decode("utf-8"))
    except (ValueError, RecursionError):
        return None


class _Graphe:
    def __init__(self) -> None:
        self.noeuds: Dict[str, dict] = {}
        self.aretes: Dict[Tuple[str, str, str], int] = {}

    def noeud(self, ident: str, typ: str, libelle: str, **extra: Any) -> str:
        if ident not in self.noeuds:
            n: Dict[str, Any] = {"id": ident, "type": typ, "libelle": libelle or ident.split(":", 1)[1]}
            n.update({k: v for k, v in extra.items() if v})
            n["metriques"] = extra.get("metriques") or {}
            self.noeuds[ident] = n
        return ident

    def arete(self, de: str, vers: str, typ: str, poids: int = 1) -> None:
        k = (de, vers, typ)
        self.aretes[k] = self.aretes.get(k, 0) + poids


def _metriques(p: dict) -> Dict[str, Any]:
    m: Dict[str, Any] = {k: _entier(p.get(k)) for k in ("adresses", "reseaux", "une", "le3", "bans",
                                                          "actives_24h", "bannies_24h")}
    m["serie"] = [_entier(x) for x in _liste(p.get("serie"))[-MAX_SERIE:] if not isinstance(x, bool)
                  and isinstance(x, int)]
    for k in ("premier", "dernier"):
        e = _epoch(p.get(k))
        if e is not None:
            m[k] = int(e)
    m["rotation"] = p.get("rotation") is True
    etat = p.get("etat")
    if etat in ("observee", "bannie", "inactive"):
        m["etat"] = etat
    m["classes"] = {c: _entier(v, 100) for c, v in list(_dict(p.get("classes")).items())[:12]
                    if isinstance(c, str) and _CLASSE.match(c)}
    return m


def _cible(v: Any) -> Optional[str]:
    if not isinstance(v, str):
        return None
    h = v.strip().lower()
    return h if _HOTE.match(h) and not _contient_ip(h) else None


def _reseaux(p: dict) -> List[Tuple[int, str, str, int]]:
    """(asn, org, classe, adresses) valides, plus gros d'abord."""
    res: List[Tuple[int, str, str, int]] = []
    vus: set = set()
    for r in _liste(p.get("reseaux_top")):
        if not isinstance(r, dict):
            continue
        asn = r.get("asn")
        if isinstance(asn, bool) or not isinstance(asn, int) or not 0 < asn < 2 ** 32 or asn in vus:
            continue
        vus.add(asn)
        cl = r.get("classe")
        cl = cl if isinstance(cl, str) and _CLASSE.match(cl) else "inconnu"
        res.append((asn, _texte(r.get("org")), cl, _entier(r.get("adresses"))))
    res.sort(key=lambda x: (-x[3], x[0]))
    return res


def lire(chemin: Path, hote: str) -> Optional[Paysage]:
    """Le paysage du relevé `chemin`, ou None (absent, illisible, trop gros, sans `genere_le` valide)."""
    d = _charger(Path(chemin))
    if not isinstance(d, dict):
        return None
    epoch = _epoch(d.get("genere_le"))
    if epoch is None:
        return None
    # Un relevé qui ne dit pas expressément « complet » est traité comme partiel.
    partiel = d.get("complet") is not True

    pops: List[Tuple[str, dict]] = []
    vus: set = set()
    for p in _liste(d.get("populations")):
        if not isinstance(p, dict):
            continue
        s = _suffixe(p.get("id"))
        if s is None or s in vus:
            continue
        vus.add(s)
        pops.append((s, p))

    cibles_tot: set = set()
    cves_tot: set = set()
    c = {"populations": len(pops), "rotation": 0, "reseaux": 0, "adresses": 0, "cibles": 0, "bans": 0, "cves": 0}
    for _, p in pops:
        c["rotation"] += p.get("rotation") is True
        c["reseaux"] += _entier(p.get("reseaux"))
        c["adresses"] += _entier(p.get("adresses"))
        c["bans"] += _entier(p.get("bans"))
        cibles_tot |= {h for h in map(_cible, _liste(p.get("cibles"))) if h}
        cves_tot |= {v for v in _liste(p.get("cves")) if isinstance(v, str) and _CVE.match(v)}
    c["cibles"], c["cves"] = len(cibles_tot), len(cves_tot)

    g = _Graphe()
    hote_s = _suffixe(hote)
    cibles_gardees: set = set()
    cves_gardees: set = set()
    for s, p in pops[:MAX_POPULATIONS]:
        fam = _texte(p.get("famille"), 40)
        pid = g.noeud(f"pop:{s}", "population", _texte(p.get("nom_cible")) or s, famille=fam,
                      metriques=_metriques(p))
        sig = p.get("campagne_actord")
        if isinstance(sig, str) and _SIGNATURE.match(sig):
            g.arete(g.noeud(f"camp:{sig}", "campagne", sig, famille=fam), pid, "MEMBRE_DE")
        reseaux = _reseaux(p)
        for asn, org, cl, n in reseaux[:MAX_ASN_PAR_POP]:
            g.arete(g.noeud(f"asn:{asn}", "reseau_source", org or f"AS{asn}", classe=cl), pid, "SOURCE_DE", n)
        replies: Dict[str, int] = {}
        for _, _, cl, n in reseaux[MAX_ASN_PAR_POP:]:
            replies[cl] = replies.get(cl, 0) + n
        for cl, n in sorted(replies.items()):
            g.arete(g.noeud(f"classe:{s}:{cl}"[:200], "classe_reseau", cl, classe=cl), pid, "SOURCE_DE", n)
        for h in map(_cible, _liste(p.get("cibles"))):
            if not h:
                continue
            if h not in cibles_gardees and len(cibles_gardees) >= MAX_CIBLES:
                continue
            cibles_gardees.add(h)
            cid = g.noeud(f"cible:{h}"[:200], "cible", h)
            if not ID_NOEUD.match(cid):
                continue
            g.arete(pid, cid, "VISE")
            if hote_s:
                g.arete(cid, g.noeud(f"infra:{hote_s}", "infra", hote_s), "HEBERGE")
        for v in _liste(p.get("cves")):
            if not isinstance(v, str) or not _CVE.match(v):
                continue
            if v not in cves_gardees and len(cves_gardees) >= MAX_CVES:
                continue
            cves_gardees.add(v)
            g.arete(pid, g.noeud(f"cve:{v}", "cve", v), "EXPLOITE")
        for e in _liste(p.get("pays_top")):
            if isinstance(e, list) and len(e) == 2 and isinstance(e[0], str) and _PAYS.match(e[0]):
                g.arete(pid, g.noeud(f"pays:{e[0]}", "pays", e[0]), "ORIGINE", _entier(e[1], 100))
    reste = len(pops) - MAX_POPULATIONS
    if reste > 0:
        g.noeud("autres:populations", "autres", f"+ {reste} autres", metriques={"repliees": reste})

    return Paysage(epoch=epoch, partiel=partiel, graphe=_finir(g), compteurs=c)


def _finir(g: _Graphe) -> dict:
    noeuds = [n for n in g.noeuds.values() if ID_NOEUD.match(n["id"])]
    if len(noeuds) > MAX_NOEUDS:
        coupes = len(noeuds) - (MAX_NOEUDS - 1)
        noeuds = noeuds[:MAX_NOEUDS - 1]
        noeuds.append({"id": "autres:noeuds", "type": "autres", "libelle": f"+ {coupes} autres",
                       "metriques": {"repliees": coupes}})
    ids = {n["id"] for n in noeuds}
    aretes = [{"de": de, "vers": vers, "type": t, "poids": w} for (de, vers, t), w in g.aretes.items()
              if de in ids and vers in ids]
    return {"noeuds": noeuds, "aretes": aretes}
