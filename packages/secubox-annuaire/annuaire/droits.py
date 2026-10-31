# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: secubox-annuaire :: droits du maillage (#3305)

Un service du maillage n'est rendu à une box que si son abonnement est ACTIF et que sa formule l'INCLUT.

Côté fournisseur (le maître, qui héberge Auto-Load) : `droits-maillage.json` (projection root 0644 d'autoloadctl) dit, par pair du
maillage (nom + empreinte de `p2p-public/pairs-enroles.json`), quels services lui sont rendus. L'adresse source de la requête
(`X-Real-IP` posé par l'écouteur wg-mesh, WireGuard ne laisse passer d'un pair que sa propre adresse) désigne le pair.
- Pas de projection : cette box n'est pas le maître, aucune politique ici, tout est rendu comme avant.
- Projection illisible : FERMÉ (aucun service).
- Pair abonné : services de sa formule (aucun s'il est suspendu, révoqué ou échu ; empreinte posée et différente : refus).
- Pair sans abonnement (ou adresse inconnue) : services rendus jusqu'à la fin de la grâce (5 jours après la première migration), puis rien.

Côté box (client) : `droits-self.json` garde la dernière réponse de `GET :8799/…/droits/self` d'un pair qui a une politique ; sans le
droit `bans-waf` (ou réponse de plus de 48 h), seules les bans publiées par la box elle-même sont appliquées.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SERVICES = ("annuaire-offres", "bans-waf", "openpgp", "macro")
DROITS_DEFAUT = Path("/var/lib/secubox/autoload-public/droits-maillage.json")
PAIRS_DEFAUT = Path("/var/lib/secubox/p2p-public/pairs-enroles.json")
SELF_DEFAUT = Path("/var/lib/secubox/annuaire/droits-self.json")
VALIDITE_SELF_S = 48 * 3600
MAX_OCTETS = 1024 * 1024
# Opérations du journal portées par chaque service (réplication /log/export) ; le reste (nœuds, configs, identités, assistance) est le socle.
OPERATIONS = {"bans-waf": "ban_", "annuaire-offres": "service_"}


def _lire_json(chemin: Path) -> Any:
    with open(chemin, "rb") as f:
        brut = f.read(MAX_OCTETS + 1)
    if len(brut) > MAX_OCTETS:
        raise ValueError("trop gros")
    return json.loads(brut)


def _pair(ip: str, pairs_chemin: Path) -> Optional[Dict[str, str]]:
    try:
        doc = _lire_json(pairs_chemin)
        for p in doc.get("pairs", []) if isinstance(doc, dict) else []:
            if isinstance(p, dict) and p.get("mesh_ip") == ip:
                return {"nom": str(p.get("name") or ""), "empreinte": str(p.get("fingerprint") or "")}
    except (OSError, ValueError):
        pass
    return None


def _services_du(ip: str, droits_chemin: Path, pairs_chemin: Path, maintenant: float) -> Tuple[Optional[List[str]], str]:
    """(services rendus, raison) ; (None, "sans-politique") si cette box n'a pas de projection."""
    try:
        doc = _lire_json(droits_chemin)
    except FileNotFoundError:
        return None, "sans-politique"
    except (OSError, ValueError):
        return [], "politique illisible"
    if not isinstance(doc, dict) or not isinstance(doc.get("pairs"), list):
        return [], "politique illisible"
    pair = _pair(ip, pairs_chemin)
    ligne = None
    if pair:
        ligne = next((x for x in doc["pairs"] if isinstance(x, dict) and x.get("nom") == pair["nom"]), None)
    if ligne is None:
        grace = doc.get("grace_jusqu_a")
        if isinstance(grace, int) and not isinstance(grace, bool) and maintenant < grace:
            return list(SERVICES), "grace"
        return [], "sans abonnement"
    if ligne.get("empreinte") and ligne.get("empreinte") != pair["empreinte"]:
        return [], "empreinte inattendue"
    if ligne.get("statut") != "actif":
        return [], f"abonnement {ligne.get('statut')}"
    services = ligne.get("services") if isinstance(ligne.get("services"), list) else []
    return [s for s in SERVICES if s in services], "abonnement"


def decider(ip: str, service: str, droits_chemin: Path = DROITS_DEFAUT, pairs_chemin: Path = PAIRS_DEFAUT,
            maintenant: Optional[float] = None) -> Tuple[bool, str]:
    if service not in SERVICES:
        raise ValueError(f"service inconnu : {service}")
    services, raison = _services_du(ip, Path(droits_chemin), Path(pairs_chemin), time.time() if maintenant is None else maintenant)
    if services is None:
        return True, raison
    if service in services:
        return True, raison
    return False, ("service non inclus" if raison == "abonnement" else raison)


def droits_de(ip: str, droits_chemin: Path = DROITS_DEFAUT, pairs_chemin: Path = PAIRS_DEFAUT, maintenant: Optional[float] = None) -> Dict:
    """Réponse de `droits/self` : `politique` faux si cette box n'en a pas (le client cherche alors un autre pair)."""
    services, _ = _services_du(ip, Path(droits_chemin), Path(pairs_chemin), time.time() if maintenant is None else maintenant)
    return {"politique": False, "services": list(SERVICES)} if services is None else {"politique": True, "services": services}


def operations_exclues(ip: str, droits_chemin: Path = DROITS_DEFAUT, pairs_chemin: Path = PAIRS_DEFAUT,
                       maintenant: Optional[float] = None) -> Tuple[str, ...]:
    services = droits_de(ip, droits_chemin, pairs_chemin, maintenant)["services"]
    return tuple(op for svc, op in OPERATIONS.items() if svc not in services)


def filtrer(entrees: Iterable[Dict[str, Any]], exclues: Tuple[str, ...]) -> List[Dict[str, Any]]:
    return [e for e in entrees if not exclues or not str(e.get("op", "")).startswith(exclues)]


def noter_droits_self(reponse: Dict, chemin: Path = SELF_DEFAUT, maintenant: Optional[float] = None) -> None:
    """Garde la réponse d'un pair qui a une politique (écriture atomique, 0644)."""
    if not isinstance(reponse, dict) or reponse.get("politique") is not True:
        return
    services = [s for s in SERVICES if s in (reponse.get("services") or [])]
    chemin = Path(chemin)
    tmp = chemin.with_name(f".{chemin.name}.{os.getpid()}.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"services": services, "verifie_le": int(time.time() if maintenant is None else maintenant)}, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, chemin)


def bans_a_appliquer(bans: List[Dict[str, Any]], moi: Optional[str], chemin: Path = SELF_DEFAUT,
                     maintenant: Optional[float] = None) -> List[str]:
    """Union fédérée si `bans-waf` est accordé (ou si aucune politique n'a jamais répondu) ; sinon les seules bans de la box."""
    now = time.time() if maintenant is None else maintenant
    tout = sorted({b["ip"] for b in bans})
    try:
        doc = _lire_json(Path(chemin))
    except FileNotFoundError:
        return tout
    except (OSError, ValueError):
        doc = {}
    verifie = doc.get("verifie_le") if isinstance(doc, dict) else None
    if isinstance(verifie, int) and now - verifie <= VALIDITE_SELF_S and "bans-waf" in (doc.get("services") or []):
        return tout
    return sorted({b["ip"] for b in bans if moi and b.get("publisher") == moi})
