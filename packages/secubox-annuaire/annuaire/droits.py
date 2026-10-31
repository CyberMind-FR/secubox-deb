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
import secrets
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SERVICES = ("annuaire-offres", "bans-waf")              # openpgp et macro : à ajouter quand leur fournisseur sera câblé
DROITS_DEFAUT = Path("/var/lib/secubox/autoload-public/droits-maillage.json")
PAIRS_DEFAUT = Path("/var/lib/secubox/p2p-public/pairs-enroles.json")
SELF_DEFAUT = Path("/var/lib/secubox/annuaire/droits-self.json")
AUTOLOAD_DIR = Path("/var/lib/secubox/autoload")         # présent : cette box héberge Auto-Load, donc DOIT avoir une projection (fail-closed)
AUDIT_DEFAUT = Path("/var/log/secubox/audit.log")
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


def _services_du(ip: str, droits_chemin: Path, pairs_chemin: Path, maintenant: float,
                 autoload_dir: Path = AUTOLOAD_DIR) -> Tuple[Optional[List[str]], str]:
    """(services rendus, raison) ; (None, "sans-politique") si cette box n'a pas de projection et n'héberge pas Auto-Load."""
    try:
        doc = _lire_json(droits_chemin)
    except FileNotFoundError:
        if Path(autoload_dir).is_dir():
            return [], "politique absente"
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
            maintenant: Optional[float] = None, autoload_dir: Path = AUTOLOAD_DIR) -> Tuple[bool, str]:
    if service not in SERVICES:
        raise ValueError(f"service inconnu : {service}")
    services, raison = _services_du(ip, Path(droits_chemin), Path(pairs_chemin), time.time() if maintenant is None else maintenant,
                                    autoload_dir)
    if services is None:
        return True, raison
    if service in services:
        return True, raison
    return False, ("service non inclus" if raison == "abonnement" else raison)


def droits_de(ip: str, droits_chemin: Path = DROITS_DEFAUT, pairs_chemin: Path = PAIRS_DEFAUT, maintenant: Optional[float] = None,
              autoload_dir: Path = AUTOLOAD_DIR) -> Dict:
    """Réponse de `droits/self` : `politique` faux si cette box n'en a pas."""
    services, _ = _services_du(ip, Path(droits_chemin), Path(pairs_chemin), time.time() if maintenant is None else maintenant,
                               autoload_dir)
    return {"politique": False, "services": list(SERVICES)} if services is None else {"politique": True, "services": services}


def operations_exclues(ip: str, droits_chemin: Path = DROITS_DEFAUT, pairs_chemin: Path = PAIRS_DEFAUT,
                       maintenant: Optional[float] = None, autoload_dir: Path = AUTOLOAD_DIR) -> Tuple[str, ...]:
    services = droits_de(ip, droits_chemin, pairs_chemin, maintenant, autoload_dir)["services"]
    return tuple(op for svc, op in OPERATIONS.items() if svc not in services)


def filtrer(entrees: Iterable[Dict[str, Any]], exclues: Tuple[str, ...]) -> List[Dict[str, Any]]:
    return [e for e in entrees if not exclues or not str(e.get("op", "")).startswith(exclues)]


def noter_droits_self(reponse: Dict, chemin: Path = SELF_DEFAUT, maintenant: Optional[float] = None) -> None:
    """Garde la réponse du maître (0644) : fichier temporaire O_EXCL|O_NOFOLLOW à suffixe aléatoire, fsync, renommage atomique
    (un lien à la place du fichier est remplacé, jamais suivi)."""
    if not isinstance(reponse, dict) or reponse.get("politique") is not True:
        return
    services = [s for s in SERVICES if s in (reponse.get("services") or [])]
    chemin = Path(chemin)
    donnees = json.dumps({"services": services, "verifie_le": int(time.time() if maintenant is None else maintenant)}).encode()
    tmp = chemin.with_name(f".{chemin.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(donnees)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _auditer(audit: Path, action: str, detail: str) -> None:
    try:
        with open(audit, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "module": "annuaire", "action": action,
                                "detail": detail[:300]}, ensure_ascii=False) + "\n")
    except OSError:
        pass


def bans_a_appliquer(bans: List[Dict[str, Any]], moi: Optional[str], chemin: Path = SELF_DEFAUT,
                     maintenant: Optional[float] = None, audit: Path = AUDIT_DEFAUT) -> List[str]:
    """Union fédérée si le dernier droit connu inclut `bans-waf` (ou si aucune politique n'a jamais répondu) ; sinon les seules bans
    de la box. Une réponse de plus de 48 h reste valable (maître injoignable : on ne réduit pas la protection), mais c'est audité."""
    now = time.time() if maintenant is None else maintenant
    tout = sorted({b["ip"] for b in bans})
    try:
        doc = _lire_json(Path(chemin))
    except FileNotFoundError:
        return tout
    except (OSError, ValueError):
        doc = {}
    verifie = doc.get("verifie_le") if isinstance(doc, dict) else None
    if not isinstance(verifie, int):
        return sorted({b["ip"] for b in bans if moi and b.get("publisher") == moi})
    if now - verifie > VALIDITE_SELF_S:
        _auditer(Path(audit), "droits_self_perimes", f"dernier droit du maître relevé il y a {int((now - verifie) // 3600)} h, conservé")
    if "bans-waf" in (doc.get("services") or []):
        return tout
    return sorted({b["ip"] for b in bans if moi and b.get("publisher") == moi})
