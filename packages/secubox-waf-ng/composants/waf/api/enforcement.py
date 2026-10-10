# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Actor Intelligence 2.0, phase 1 (#2240) : les bans de sbxwaf vus comme des ACTIONS DÉFENSIVES, et ses états comme des DÉCISIONS.

Rien n'est dupliqué : la source reste le journal de bans append-only de sbxwaf (`bans.jsonl`) et les états `actor-ban-etat.json` /
`campagne-ban-etat.json` qu'il écrit déjà. Ce module ne FAIT que les relire en fonctions pures, sans E/S, pour que l'API et les tests parlent
du même objet. Vocabulaire des modes (point 11 et 12 du brief) :

    PASSIVE_ONLY : aucun état de ban publié (sbxwaf en `off`) — observation seule ;
    SIMULATION   : `propose` — les candidats sont écrits, rien n'est appliqué (décision WOULD_BLOCK) ;
    ACTIVE       : `auto` — les bans sont posés (décision BLOCKED).
"""
import hashlib
from typing import Dict, List, Optional, Set

FRAICHEUR_ETAT_S = 15 * 60          # un état plus vieux : sbxwaf arrêté ou figé, on n'en tire aucune décision
_MODES = {"propose": "SIMULATION", "auto": "ACTIVE"}
_ORDRE_MODE = {"PASSIVE_ONLY": 0, "SIMULATION": 1, "ACTIVE": 2}


def identifiant(ip: str, cree_a: int) -> str:
    """Identifiant stable d'une action : le journal est append-only, (adresse, date de pose) est unique."""
    return hashlib.sha1(f"{ip}|{cree_a}".encode()).hexdigest()[:12]


def _action(r: dict, now: int, actifs: Set[str]) -> Optional[dict]:
    ip, at, exp = r.get("ip") or "", int(r.get("at") or 0), int(r.get("exp") or 0)
    if not ip or r.get("action") != "ban" or not at:
        return None
    if exp and exp <= now:
        statut = "expired"
    elif ip in actifs:
        statut = "active"
    else:
        statut = "released"          # absent du set nft avant l'échéance : levé à la main ou par un autre mécanisme
    cat = r.get("cat") or ""
    return {"id": identifiant(ip, at), "type": "nft_ban", "target": ip, "reason": cat, "source_decision": cat, "severity": r.get("sev") or "",
            "duration_s": (exp - at) if exp else 0, "created_at": at, "expires_at": exp, "status": statut,
            "rollback": {"available": statut == "active", "method": "unban"}}


def actions(lignes: List[dict], now: int, actifs: Set[str], limite: int = 200) -> List[dict]:
    """Actions défensives, la plus récente d'abord. `actifs` : adresses réellement présentes dans le set nft."""
    sortie = [a for a in (_action(r, now, actifs) for r in lignes) if a]
    sortie.sort(key=lambda a: a["created_at"], reverse=True)
    return sortie[:max(1, limite)]


def trouver(lignes: List[dict], now: int, actifs: Set[str], ident: str) -> Optional[dict]:
    for a in actions(lignes, now, actifs, limite=10**9):
        if a["id"] == ident:
            return a
    return None


def _etat_frais(etat: Optional[dict], now: int) -> Optional[dict]:
    if not etat or now - int(etat.get("genere_le") or 0) > FRAICHEUR_ETAT_S:
        return None
    return etat


def _decision(source: str, c: dict, mode: str) -> dict:
    d = c.get("decision") or ""
    niveau, verdict = "OBSERVE", "OBSERVE"
    if d == "banni":
        niveau, verdict = "BLOCK", "BLOCKED"
    elif d == "a_bannir":
        niveau, verdict = "BLOCK", "WOULD_BLOCK"
    if source == "campagne":
        preuve = {"sondes": c.get("sondes", 0), "haute_valeur": c.get("haute_valeur", 0), "signature": c.get("signature", "")}
        raison = (f"campagne {preuve['signature']} : {preuve['sondes']} sondes dont {preuve['haute_valeur']} de haute valeur"
                  if niveau == "BLOCK" else d.replace("ecarte:", "écartée : "))
    else:
        preuve = {"actor": c.get("actor", ""), "recommandation": c.get("mode", ""), "sanctions_locales": c.get("deja_bans", 0)}
        raison = (f"acteur {preuve['actor']} ({preuve['recommandation']}), {preuve['sanctions_locales']} sanction(s) locale(s)"
                  if niveau == "BLOCK" else d.replace("ecarte:", "écarté : "))
    if niveau == "OBSERVE" and d.startswith("ecarte:"):
        raison = f"{d} — {raison}"
    return {"source": source, "target": c.get("ip", ""), "level": niveau, "decision": verdict, "mode": _MODES.get(mode, "PASSIVE_ONLY"),
            "reason": raison, "evidence": preuve, "duration_s": c.get("duree_s", 0)}


def decisions(etats: Dict[str, Optional[dict]], now: int) -> List[dict]:
    out: List[dict] = []
    for cle, source in (("campagnes", "campagne"), ("acteurs", "acteur")):
        e = _etat_frais(etats.get(cle), now)
        if not e:
            continue
        for c in e.get("candidats") or []:
            out.append(_decision(source, c, e.get("mode", "")))
    return out


def mode_global(etats: Dict[str, Optional[dict]], now: int) -> dict:
    detail = {}
    for cle in ("campagnes", "acteurs"):
        e = _etat_frais(etats.get(cle), now)
        detail[cle] = _MODES.get((e or {}).get("mode", ""), "PASSIVE_ONLY")
    return {"mode": max(detail.values(), key=_ORDRE_MODE.get), "detail": detail}
