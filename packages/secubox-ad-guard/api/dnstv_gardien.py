# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: résumé « Guardian » (#2287) — le tableau de bord du réseau domestique.

Tout vient de compteurs RÉELS : le magasin DNS par jour (`dnstv_counts`), le classifieur de services d'ad-guard, le parc du NAC (lecture seule). Rien n'est estimé ni
inventé : une période sans donnée vaut zéro, une source absente vaut `None` — la page dit alors « indisponible », elle ne montre pas un zéro rassurant.

PÉRIODES : les tuiles comptent AUJOURD'HUI (jour UTC du magasin) et donnent hier ; la courbe, les types, les services et les appareils portent sur 7 jours. Le magasin ne garde
le détail horaire que quelques heures : une courbe « 24 h » serait presque vide.
"""
from __future__ import annotations

import datetime
import sqlite3
import time
from typing import Callable, Dict, List, Optional, Tuple

JOURS = 7
JOURS_COURTS = ["lun", "mar", "mer", "jeu", "ven", "sam", "dim"]
COULEURS_TYPES = ["bleu", "rouge", "orange", "cyan"]
LIBELLES_TYPE = {
    "publicite": "Publicité", "mesure_audience": "Mesure d'audience", "analytique": "Analytique", "qualite_video": "Qualité vidéo",
    "systeme": "Système", "contenu": "Contenu", "inconnu": "Autres",
}
ICONES_NAC = {"tv": "tv", "phone": "tel", "smartphone": "tel", "tablet": "tel", "computer": "pc", "laptop": "pc", "pc": "pc", "console": "console", "game_console": "console"}


def _jour(ts: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _libelle_type(t: Optional[str]) -> str:
    if not t:
        return "Autres"
    return LIBELLES_TYPE.get(t) or t.replace("_", " ").capitalize()


def _parts(valeurs: List[int]) -> List[int]:
    """Pourcentages entiers qui somment EXACTEMENT 100 (méthode du plus fort reste)."""
    total = sum(valeurs)
    if total <= 0:
        return [0] * len(valeurs)
    brut = [100 * v / total for v in valeurs]
    base = [int(b) for b in brut]
    for i in sorted(range(len(valeurs)), key=lambda i: brut[i] - base[i], reverse=True)[:100 - sum(base)]:
        base[i] += 1
    return base


def nac_resume(chemin: str, maintenant: int, fenetre_s: int = 900) -> Optional[dict]:
    """Le parc vu par le NAC, en lecture seule : appareils connectés (vus dans les 15 dernières minutes) et connus, SANS les conteneurs LXC ; type par adresse. None si illisible."""
    try:
        cx = sqlite3.connect(f"file:{chemin}?mode=ro", uri=True, timeout=2)
        try:
            lignes = cx.execute("SELECT ip, device_type, last_seen, COALESCE(interface,''), mac FROM devices").fetchall()
        finally:
            cx.close()
    except sqlite3.Error:
        return None
    parc = [l for l in lignes if not ((l[0] or "").startswith("10.100.") or "lxc" in l[3].lower() or (l[4] or "").lower().startswith("00:16:3e"))]
    return {"connectes": sum(1 for l in parc if (l[2] or 0) >= maintenant - fenetre_s), "total": len(parc),
            "par_ip": {l[0]: (l[1] or "unknown") for l in parc if l[0]}}


def _couleur_taux(pct: int) -> str:
    return "rouge" if pct >= 25 else "orange" if pct >= 10 else "vert"


def resume(magasin, *, now: int, sources: Dict[str, dict], classer: Callable[[str], Tuple[Optional[str], Optional[str]]], nac: Optional[dict]) -> dict:
    jours = [_jour(now - i * 86400) for i in range(JOURS - 1, -1, -1)]
    aujourd_hui, hier = jours[-1], _jour(now - 86400)
    with magasin._cx() as cx:
        par_jour = {(j, d): h for j, d, h in cx.execute("SELECT jour, decision, SUM(hits) FROM dnstv_counts WHERE jour>=? GROUP BY jour, decision", (jours[0],))}
        bloques = cx.execute("SELECT domaine, SUM(hits) FROM dnstv_counts WHERE jour>=? AND decision='BLOCKED' GROUP BY domaine", (jours[0],)).fetchall()
        clients = cx.execute("SELECT client, SUM(CASE WHEN decision IN ('ALLOWED','BLOCKED') THEN hits ELSE 0 END), SUM(CASE WHEN decision='BLOCKED' THEN hits ELSE 0 END) "
                             "FROM dnstv_counts WHERE jour>=? GROUP BY client", (jours[0],)).fetchall()
    v = lambda j, d: int(par_jour.get((j, d)) or 0)
    req_j, blq_j = v(aujourd_hui, "ALLOWED") + v(aujourd_hui, "BLOCKED"), v(aujourd_hui, "BLOCKED")
    req_h = v(hier, "ALLOWED") + v(hier, "BLOCKED")
    serie = [{"x": JOURS_COURTS[datetime.date.fromisoformat(j).weekday()], "a": v(j, "ALLOWED"), "b": v(j, "BLOCKED")} for j in jours]

    # types de domaines bloqués : les trois plus gros + « Autres » (le reste et ce que le classifieur ne connaît pas)
    par_type: Dict[str, int] = {}
    par_service: Dict[str, int] = {}
    for domaine, h in bloques:
        service, typ = classer(domaine)
        lib = _libelle_type(typ)
        par_type[lib] = par_type.get(lib, 0) + int(h)
        par_service[service or "Autres (non classés)"] = par_service.get(service or "Autres (non classés)", 0) + int(h)
    total_bloque = sum(par_type.values())
    nommes = sorted(((k, h) for k, h in par_type.items() if k != "Autres"), key=lambda x: -x[1])
    garde, reste = nommes[:3], nommes[3:]
    autres = par_type.get("Autres", 0) + sum(h for _, h in reste)
    lignes = garde + ([("Autres", autres)] if autres else [])
    pcts = _parts([h for _, h in lignes])
    types = [{"nom": n, "pct": p, "c": COULEURS_TYPES[i % len(COULEURS_TYPES)]} for i, ((n, _), p) in enumerate(zip(lignes, pcts))]

    # Les services CONNUS d'abord (les plus bloqués en tête, cinq au plus), puis « Autres (non classés) » en dernier : un bloc de noms inconnus, même énorme, ne masque pas ce qu'on sait nommer.
    inconnus = par_service.pop("Autres (non classés)", 0)
    services = sorted(par_service.items(), key=lambda x: -x[1])[:5] + ([("Autres (non classés)", inconnus)] if inconnus else [])
    cats = [{"nom": n, "pct": round(100 * h / total_bloque) if total_bloque else 0, "c": "gris" if n.startswith("Autres") else "rouge" if i == 0 else "cyan" if i == 1 else "bleu"}
            for i, (n, h) in enumerate(services)]

    par_client = {c: (int(r or 0), int(b or 0)) for c, r, b in clients}
    top = []
    for cle, s in (sources or {}).items():
        req = sum(par_client.get(ip, (0, 0))[0] for ip in s.get("ips", []))
        blq = sum(par_client.get(ip, (0, 0))[1] for ip in s.get("ips", []))
        if not req:
            continue
        pct = round(100 * blq / req)
        brut = next(((nac or {}).get("par_ip", {}).get(ip) for ip in s.get("ips", []) if (nac or {}).get("par_ip", {}).get(ip)), None)
        top.append({"nom": s.get("nom") or cle, "type": ICONES_NAC.get(str(brut).lower(), "objet"), "req": req, "blq": blq, "pct": pct, "c": _couleur_taux(pct)})
    top.sort(key=lambda a: -a["req"])

    return {
        "genere_le": now, "actif": True,
        "appareils": {"connectes": nac["connectes"], "total": nac["total"]} if nac else None,
        "dns": {"requetes": req_j, "bloquees": blq_j, "taux": round(100 * blq_j / req_j) if req_j else 0, "libelle": "Requêtes DNS (aujourd'hui)",
                "sous": f"hier : {req_h:,}".replace(",", " ")},
        "menaces": None, "serie": serie, "types": types, "cats": cats, "top": top[:4],
        "periodes": {"tuiles": "aujourd'hui", "courbe": f"{JOURS} jours", "types": f"{JOURS} jours", "appareils": f"{JOURS} jours"},
    }
