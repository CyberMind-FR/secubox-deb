# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Signaux de l'analyse PHP de sbxwaf (#3273, tâche 9) : décompte, sur 24 h, des lignes du journal des menaces
que portent les signatures PHP (php2shell, roundcube, nextcloud, php_requete) et leurs étiquettes d'outil.

Calcul PUR et coûteux (balayage du journal) : il n'est appelé que par la tâche de fond de l'API, qui en écrit le
résultat dans un cache fichier ; la route ne lit jamais le journal. Ne sort que des compteurs : jamais un corps, une
valeur de paramètre, un chemin ni une adresse privée (sbxwaf journalise déjà celles-ci sous « local », R12)."""
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

FENETRE_H = 24
# Au-delà, le relevé du cache n'est plus celui de la tâche de fond (arrêtée ou bloquée) : état « perime ».
AGE_MAX_S = 600
FAMILLES = ("php2shell", "roundcube", "nextcloud", "php_requete")
# Gravité des lignes d'état (multipart-*, capture-concurrence) : un fait sur le moteur, pas un signal d'attaque.
GRAVITE_ETAT = "audit"
PREFIXE_OUTIL = "outil:"
# Bornes de ce qu'on rend : l'hôte et la règle viennent du journal, donc de l'extérieur.
MAX_VHOSTS = 100
MAX_ADRESSES = 100
MAX_REGLES = 200
_HOTE = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")
_REGLE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def _horodatage(valeur: Any) -> Optional[datetime]:
    """Lit l'horodatage RFC 3339 de sbxwaf (ou un entier Unix) ; sans fuseau, UTC."""
    try:
        if isinstance(valeur, (int, float)):
            return datetime.fromtimestamp(valeur, tz=timezone.utc)
        d = datetime.fromisoformat(str(valeur).replace("Z", "+00:00"))
    except (ValueError, TypeError, OverflowError, OSError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _adresse_publique(ip: Any) -> Optional[str]:
    """L'adresse si elle est publique ; None pour « local », une adresse privée ou illisible."""
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    # is_global et non is_private : le CGNAT (100.64.0.0/10) et la plage de test 198.18.0.0/15 ne sont
    # pas « privés » pour ipaddress, mais ce ne sont pas des adresses publiques non plus.
    if not a.is_global:
        return None
    return str(a)


def _hote(valeur: Any) -> Optional[str]:
    h = str(valeur or "").strip().lower()
    if h.startswith("["):          # [::1]:443 : jamais un nom de vhost
        return None
    h = h.rsplit(":", 1)[0] if h.count(":") == 1 else h
    return h if _HOTE.match(h) else None


def _plus_gros(d: Dict[str, int], n: int) -> Dict[str, int]:
    return dict(sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:n])


def calculer(lignes: Iterable[str], maintenant: datetime) -> Dict[str, Any]:
    """Décompte les signaux PHP des `lignes` du journal sur les FENETRE_H dernières heures."""
    debut = maintenant - timedelta(hours=FENETRE_H)
    familles = {f: 0 for f in FAMILLES}
    familles["outil"] = 0
    regles: Dict[str, int] = {}
    vhosts: Dict[str, int] = {}
    adresses: Dict[str, Dict[str, int]] = {}
    for brut in lignes:
        brut = brut.strip()
        if not brut:
            continue
        try:
            e = json.loads(brut)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        cat = e.get("category")
        if cat not in FAMILLES or e.get("severity") == GRAVITE_ETAT:
            continue
        t = _horodatage(e.get("timestamp"))
        if t is None or t < debut or t > maintenant + timedelta(minutes=5):
            continue
        familles[cat] += 1
        traits = e.get("behavior_traits")
        avec_outil = isinstance(traits, list) and any(
            isinstance(x, str) and x.startswith(PREFIXE_OUTIL) for x in traits)
        if avec_outil:
            familles["outil"] += 1
        regle = str(e.get("rule_id") or "")
        if _REGLE.match(regle):
            regles[regle] = regles.get(regle, 0) + 1
        h = _hote(e.get("host"))
        if h:
            vhosts[h] = vhosts.get(h, 0) + 1
        ip = _adresse_publique(e.get("client_ip"))
        if ip:
            par = adresses.setdefault(ip, {})
            par[cat] = par.get(cat, 0) + 1
            if avec_outil:
                par["outil"] = par.get("outil", 0) + 1
    meilleures = sorted(adresses, key=lambda a: (-sum(v for k, v in adresses[a].items() if k != "outil"), a))
    return {
        "fenetre_h": FENETRE_H,
        "calcule_a": maintenant.timestamp(),
        "etat": "ok",
        "familles": familles,
        "regles": _plus_gros(regles, MAX_REGLES),
        "vhosts": _plus_gros(vhosts, MAX_VHOSTS),
        "adresses": {a: adresses[a] for a in meilleures[:MAX_ADRESSES]},
    }


def lignes_du_journal(chemin: Path) -> Iterable[str]:
    """Journal courant puis sa rotation non compressée, en flux (jamais chargé d'un bloc)."""
    for p in (Path(str(chemin) + ".1"), Path(chemin)):
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                yield from f
        except OSError:
            continue


def ecrire_cache(chemin: Path, etat: Dict[str, Any]) -> None:
    """Écriture atomique : un lecteur ne voit jamais un fichier à moitié écrit."""
    chemin.parent.mkdir(parents=True, exist_ok=True)
    tmp = chemin.with_name(chemin.name + ".tmp")
    tmp.write_text(json.dumps(etat, separators=(",", ":")))
    tmp.replace(chemin)


def appliquer_fraicheur(releve: Dict[str, Any], maintenant: float) -> Dict[str, Any]:
    """Le relevé, avec `etat: "perime"` si `calcule_a` a plus de AGE_MAX_S secondes (ou n'est pas une date).
    Les compteurs restent rendus : un relevé vieux vaut mieux que rien, tant qu'on dit qu'il est vieux."""
    calcule = releve.get("calcule_a")
    if isinstance(calcule, bool) or not isinstance(calcule, (int, float)) or maintenant - calcule > AGE_MAX_S:
        return {**releve, "etat": "perime"}
    return releve


def lire_cache(chemin: Path) -> Optional[Dict[str, Any]]:
    """Le dernier relevé, ou None s'il manque ou est illisible : l'état est alors « inconnu »."""
    try:
        d = json.loads(Path(chemin).read_text())
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) and isinstance(d.get("familles"), dict) else None
