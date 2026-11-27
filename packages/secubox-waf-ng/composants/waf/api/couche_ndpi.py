# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Couche nDPI des populations (#4014, suite de #4010).

nDPId/sbxdpi tiennent, par adresse SOURCE externe, les services visés (protocole L7/port), les risques nDPI et l'empreinte
JA4 du ClientHello. Ce module les rapproche des populations du WAF PAR ADRESSE, dans le calcul seulement : aucune adresse
n'est rendue, seulement des parts, des services, des risques et la FORME tronquée du JA4 (`t13d1516h2`, sans ses hachages).

Sources, dans l'ordre (la première fraîche et lisible gagne) :

1. `/var/cache/secubox/dpi/couches-menaces.json` — relevé de l'API ndpid (`couches_menaces.py`), qui porte déjà le verdict
   d'agent (UA déclaré au WAF ↔ forme du JA4) ;
2. `/run/secubox/sbxdpi/couches-menaces.json` — relevé brut de sbxdpi (0640, groupe secubox), sans UA : la forme du JA4
   seule (« client de bibliothèque » au plus, jamais « faux navigateur »).

Le calcul des populations tourne sous l'utilisateur `secubox` (processus lancé par l'API), membre du groupe `secubox` : il lit
les deux fichiers sans droit nouveau.

Absent, illisible ou périmé (plus de `PERIME_S`) : la population est calculée SANS ces champs et le relevé porte
`ndpi: "indisponible"`. Ce n'est pas une source manquante du relevé (il reste `complet`), comme la base ASN : sans DPI,
les comptes du WAF restent justes. Tout ce qui vient de la forme du JA4 est un INDICE, jamais un motif de ban.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

CACHE_NDPID = "/var/cache/secubox/dpi/couches-menaces.json"
RELEVE_SBXDPI = "/run/secubox/sbxdpi/couches-menaces.json"
PERIME_S = 3600                  # au-delà, le relevé ne décrit plus le présent
MAX_SOURCES = 100_000            # garde-fou de lecture
MAX_MEMOIRE = 50_000             # adresses gardées par couche de ruptures
MEMOIRE_S = 8 * 86400            # 7 j de ruptures + la fenêtre précédente partielle
MEMOIRE = "ndpi-premieres.json"  # dans la réserve des populations (0640, adresses : jamais rendue)
MIN_VUES = 10                    # sous ce nombre d'adresses vues par nDPI, pas de phrase
TOP = 4

VIA_WAF = {("HTTP", 80), ("TLS", 443), ("HTTP", 443), ("QUIC", 443)}
BRUIT = {"Known Proto on Non Std Port", "TCP Connection Issues", "Missing SNI TLS Extn", "Error Code", "Unidirectional Traffic"}
OUTIL = ("outil_probable", "client_bibliotheque")
_JA4 = re.compile(r"^([tqd])(1[0-3]|s[23]|00)([di])(\d{2})(\d{2})([0-9a-z]{2})_")
_SERVICE = re.compile(r"^[A-Za-z0-9._ -]{1,40}/[0-9]{1,5}$")


def forme_ja4(ja4: Any) -> str:
    """La partie « forme » du JA4 (avant le premier `_`) : version, SNI, nombres, ALPN. Les hachages sont tus."""
    m = _JA4.match(ja4 or "") if isinstance(ja4, str) else None
    return ja4.split("_", 1)[0] if m else ""


def famille_ja4(ja4: Any) -> str:
    """Même règle que `profil_ja4` de ndpid : « nav », « lib » ou « aut » ; "" si illisible."""
    m = _JA4.match(ja4 or "") if isinstance(ja4, str) else None
    if not m:
        return ""
    ver, sni, suites, exts, alpn = m.group(2), m.group(3) == "d", int(m.group(4)), int(m.group(5)), m.group(6)
    if ver == "13" and sni and alpn in ("h2", "h3") and suites >= 8 and exts >= 12:
        return "nav"
    if sni and (alpn in ("00", "h1") or suites < 8 or exts < 8):
        return "lib"
    return "aut"


def hors_waf(service: str) -> bool:
    proto, _, port = service.rpartition("/")
    try:
        return (proto, int(port)) not in VIA_WAF
    except ValueError:
        return True


def _entier(v: Any) -> int:
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return 0


def _services(d: Any) -> List[str]:
    return [k for k in (d or {}) if isinstance(k, str) and _SERVICE.match(k)] if isinstance(d, (dict, list)) else []


def _norm_ndpid(s: dict) -> dict:
    ja4 = s.get("ja4") if isinstance(s.get("ja4"), str) else ""
    return {"hors_http": sorted(k for k in _services(s.get("hors_waf")) if hors_waf(k)),
            "risques": sorted(k for k in (s.get("risques_notables") or []) if isinstance(k, str) and k not in BRUIT)[:20],
            "forme": forme_ja4(ja4), "famille": s.get("ja4_famille") if s.get("ja4_famille") in ("nav", "lib", "aut") else famille_ja4(ja4),
            "ua": s.get("ua_famille") if isinstance(s.get("ua_famille"), str) else "absent",
            "agent": s.get("agent") if isinstance(s.get("agent"), str) else "indetermine",
            "premier": _entier(s.get("premier"))}


def _norm_sbxdpi(s: dict) -> dict:
    ja4s = s.get("ja4") if isinstance(s.get("ja4"), dict) else {}
    ja4 = max(sorted(ja4s), key=lambda k: _entier(ja4s[k])) if ja4s else ""
    fam = famille_ja4(ja4)
    return {"hors_http": sorted(k for k in _services(s.get("services")) if hors_waf(k)),
            "risques": sorted(k for k in (s.get("risques") or {}) if isinstance(k, str) and k not in BRUIT)[:20],
            "forme": forme_ja4(ja4), "famille": fam, "ua": "absent",
            "agent": "client_bibliotheque" if fam == "lib" else "indetermine", "premier": _entier(s.get("premier"))}


def lire(maintenant: float, chemins: Tuple[str, str] = (CACHE_NDPID, RELEVE_SBXDPI)) -> Tuple[Optional[Dict[str, dict]], Dict[str, Any]]:
    """(sources adresse → champs normalisés, état). Sources None = indisponible (absent, illisible ou périmé)."""
    raisons = []
    for chemin, norm, nom in ((chemins[0], _norm_ndpid, "ndpid"), (chemins[1], _norm_sbxdpi, "sbxdpi")):
        try:
            d = json.loads(Path(chemin).read_text(encoding="utf-8"))
        except FileNotFoundError:
            raisons.append(nom + " absent")
            continue
        except (OSError, ValueError):
            raisons.append(nom + " illisible")
            continue
        src = d.get("sources") if isinstance(d, dict) else None
        if not isinstance(src, dict):
            raisons.append(nom + " illisible")
            continue
        genere = _entier(d.get("genere"))
        if maintenant - genere > PERIME_S:
            raisons.append(nom + " périmé")
            continue
        sources = {}
        for ip, s in src.items():
            if len(sources) >= MAX_SOURCES:
                break
            if isinstance(ip, str) and isinstance(s, dict):
                sources[ip] = norm(s)
        etat = {"etat": "disponible" if d.get("complet") else "partiel", "source": nom, "genere": genere,
                "sources": len(sources)}
        return sources, etat
    return None, {"etat": "indisponible", "raison": ", ".join(raisons)}


def _tri(d: Dict[str, int], n: int) -> List[List[Any]]:
    return [[k, round(100 * v / n)] for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP]] if n else []


def par_population(adresses: Iterable[str], sources: Optional[Dict[str, dict]]) -> Optional[Dict[str, Any]]:
    """Ce que nDPI dit des adresses d'une population, en parts. None sans relevé nDPI. Aucune adresse dans la sortie."""
    if sources is None:
        return None
    total = vues = hors = avec_ja4 = lib = outil = nav_declares = faux_nav = 0
    services: Dict[str, int] = {}
    risques: Dict[str, int] = {}
    formes: Dict[str, int] = {}
    familles: Dict[str, str] = {}
    for ip in adresses:
        total += 1
        s = sources.get(ip)
        if s is None:
            continue
        vues += 1
        if s["hors_http"]:
            hors += 1
            for k in s["hors_http"]:
                services[k] = services.get(k, 0) + 1
        for k in s["risques"]:
            risques[k] = risques.get(k, 0) + 1
        if s["forme"]:
            avec_ja4 += 1
            formes[s["forme"]] = formes.get(s["forme"], 0) + 1
            familles[s["forme"]] = s["famille"]
            lib += s["famille"] == "lib"
            if s["ua"] == "navigateur":
                nav_declares += 1
                faux_nav += s["agent"] == "outil_probable"
        outil += s["agent"] in OUTIL
    return {
        "adresses_vues": vues, "part_vues": round(100 * vues / total) if total else 0,
        "part_hors_http": round(100 * hors / total) if total else 0, "adresses_hors_http": hors,
        "services_hors_http": _tri(services, vues), "risques": _tri(risques, vues),
        "empreintes": [[f, p, familles.get(f, "")] for f, p in _tri(formes, avec_ja4)],
        "avec_ja4": avec_ja4, "part_bibliotheque": round(100 * lib / avec_ja4) if avec_ja4 else 0,
        "part_outil_probable": round(100 * outil / vues) if vues else 0,
        "navigateurs_declares": nav_declares, "part_faux_navigateur": round(100 * faux_nav / nav_declares) if nav_declares else 0,
    }


def _noms(services: List[List[Any]]) -> str:
    noms: List[str] = []
    for k, _ in services:
        n = k.rpartition("/")[0] or k
        if n not in noms:
            noms.append(n)
    return " ou ".join(noms[:2]) if len(noms) <= 2 else ", ".join(noms[:2]) + " ou " + noms[2]


def lecture(n: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Phrases par règles, chacune adossée à un chiffre. Celles tirées de la forme du JA4 portent `indice: True`."""
    res: List[Dict[str, Any]] = []
    if not n or n["adresses_vues"] < MIN_VUES:
        return res
    if n["adresses_hors_http"] >= MIN_VUES and n["part_hors_http"] >= 20 and n["services_hors_http"]:
        res.append({"code": "ndpi_hors_http", "valeur": n["part_hors_http"], "source": "ndpi",
                    "texte": f"Hors HTTP : {n['part_hors_http']} % de ses adresses visent aussi {_noms(n['services_hors_http'])}."})
    if n["risques"] and n["risques"][0][1] >= 30:
        r, p = n["risques"][0]
        res.append({"code": "ndpi_risque", "valeur": p, "source": "ndpi",
                    "texte": f"Risque nDPI dominant : « {r} » pour {p} % des adresses vues par nDPI."})
    if n["navigateurs_declares"] >= MIN_VUES and n["part_faux_navigateur"] >= 50:
        res.append({"code": "ndpi_faux_navigateur", "valeur": n["part_faux_navigateur"], "source": "ndpi", "indice": True,
                    "texte": f"Faux navigateur probable : {n['part_faux_navigateur']} % des empreintes TLS de ses navigateurs "
                             "déclarés sont celles d'une bibliothèque (indice)."})
    elif n["avec_ja4"] >= MIN_VUES and n["part_bibliotheque"] >= 80:
        res.append({"code": "ndpi_bibliotheque", "valeur": n["part_bibliotheque"], "source": "ndpi", "indice": True,
                    "texte": f"Client de bibliothèque : {n['part_bibliotheque']} % des empreintes TLS ont la forme d'une "
                             "bibliothèque (indice)."})
    return res


# ── ruptures : premières vues des sources hors HTTP et « outil probable », gardées dans la réserve ───────────────

def memoriser(chemin: str, sources: Optional[Dict[str, dict]], maintenant: float) -> Dict[str, Any]:
    """Fusionne les premières vues du relevé courant dans la mémoire (fichier interne, adresses : jamais rendu) et la rend.
    Sans relevé nDPI, la mémoire est lue telle quelle (rien n'est effacé)."""
    try:
        m = json.loads(Path(chemin).read_text(encoding="utf-8"))
        if not isinstance(m, dict) or not all(isinstance(m.get(k), dict) for k in ("hors_http", "outil")):
            raise ValueError
    except (OSError, ValueError):
        m = {"debut": None, "hors_http": {}, "outil": {}}
    if sources is None:
        return m
    limite = maintenant - MEMOIRE_S
    for k in ("hors_http", "outil"):
        m[k] = {ip: t for ip, t in m[k].items() if isinstance(t, (int, float)) and t >= limite}
    for ip, s in sources.items():
        t = s["premier"] or maintenant
        for k, oui in (("hors_http", bool(s["hors_http"])), ("outil", s["agent"] in OUTIL)):
            if oui and (ip in m[k] or len(m[k]) < MAX_MEMOIRE) and (ip not in m[k] or t < m[k][ip]):
                m[k][ip] = t
    if not isinstance(m.get("debut"), (int, float)):
        m["debut"] = maintenant
    try:
        fd, tmp = tempfile.mkstemp(prefix=".tmp-ndpi-", dir=os.path.dirname(chemin) or ".")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o640)
            json.dump(m, f, separators=(",", ":"))
        os.replace(tmp, chemin)
    except OSError:
        pass                                              # la mémoire n'est qu'un historique : son absence rend « insuffisant »
    return m


def couches(memoire: Optional[Dict[str, Any]], fin: int, quart: int, rodage_q: int, couche) -> List[Dict[str, Any]]:
    """Deux couches de ruptures (1 h / 8 h / 1 j / 7 j) : sources nDPI hors HTTP neuves, sources « outil probable » neuves."""
    if not memoire or not isinstance(memoire.get("debut"), (int, float)):
        return []
    debut = int(memoire["debut"] // quart) + rodage_q

    def series(d: Dict[str, float]) -> Dict[int, int]:
        q: Dict[int, int] = {}
        for t in d.values():
            q[int(t // quart)] = q.get(int(t // quart), 0) + 1
        return q
    return [couche("ndpi_hors_http", "Sources nDPI hors HTTP neuves", "ndpi", series(memoire["hors_http"]), fin, debut, 0.5),
            couche("ndpi_outil", "Sources « outil probable » neuves (indice)", "ndpi", series(memoire["outil"]), fin, debut, 0.5)]

