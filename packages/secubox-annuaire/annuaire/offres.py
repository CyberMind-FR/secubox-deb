# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Offres de services RÉELLES du nœud (#3021).

Les offres de l'Annuaire étaient publiées à la main (`annuairectl offer`) : sur gk2, trois démonstrations de juin
2026 que rien ne reliait aux services rendus. Ici, deux temps :

1. `collecter_faits()` — EN ROOT (l'unité `secubox-annuaire-offres`), lit ce que la box offre vraiment :
   · les services onion de Tor (`/var/lib/tor/hidden_services/<nom>/hostname`, lisible par root seul) ;
   · la curation du Hall (`FEATURED` de `/usr/share/secubox/www/hall/index.html`) : les cartes SANS `auth:true` sont
     les services ouverts au public (radio, podcasts, vidéos, forums…) ; celles avec `auth:true` sont des vues
     d'administration et ne sont pas des offres ;
   · le dépôt apt, si `secubox-repo` est installé et qu'un vhost `apt.` est déclaré dans `haproxy.toml`.
   Le résultat est posé dans `offres-reelles.json`, lisible par `secubox`.
2. `synchroniser()` — EN `secubox` (le propriétaire de la clé du nœud et du journal) : publie les offres manquantes,
   révoque celles que ce nœud avait publiées avec `scope.source == "sync"` et qui n'existent plus. Les offres posées à la
   main (`annuairectl offer`) ne sont jamais touchées ; `annuairectl revoke-offer` sert à les retirer.

Aucun appel réseau, aucun jeton : des fichiers, que root lit, puis une signature, que secubox pose.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SOURCE = "sync"
FAITS_PATH = Path("/var/lib/secubox/annuaire/offres-reelles.json")
TOR_HIDDEN = Path("/var/lib/tor/hidden_services")
HALL_INDEX = Path("/usr/share/secubox/www/hall/index.html")
HAPROXY_TOML = Path("/etc/secubox/haproxy.toml")
REPO_MARQUEUR = Path("/usr/lib/secubox/repo")

# Une ligne de FEATURED : {id:"radio", label:"Radio", icon:"📻", color:"#…", url:"radio.gk2.secubox.in", …}
_CARTE = re.compile(r'\{\s*id:\s*"(?P<id>[a-z0-9_-]+)"\s*,\s*label:\s*"(?P<label>[^"]*)"(?P<reste>[^}]*)\}')
_URL = re.compile(r'url:\s*"(?P<url>[^"]+)"')
_AUTH = re.compile(r'auth:\s*true')
_ONION = re.compile(r'^[a-z2-7]{56}\.onion$')
_HOTE = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$')


def _offre(name: str, kind: str, endpoint: str, description: str = "", **scope: Any) -> Dict[str, Any]:
    return {"name": name, "kind": kind, "endpoint": endpoint, "description": description,
            "scope": {"source": SOURCE, **{k: v for k, v in scope.items() if v not in (None, "")}}}


def onions(tor_dir: Path = TOR_HIDDEN) -> List[Dict[str, Any]]:
    """Un service onion par dossier `hidden_services/<nom>/hostname` ; dossier illisible ou absent : aucun."""
    out: List[Dict[str, Any]] = []
    try:
        dossiers = sorted(p for p in tor_dir.iterdir() if p.is_dir())
    except OSError:
        return out
    for d in dossiers:
        try:
            onion = (d / "hostname").read_text(encoding="ascii").strip().lower()
        except OSError:
            continue
        if not _ONION.match(onion):
            continue
        out.append(_offre(f"{d.name} (onion)", "onion", f"http://{onion}/",
                          f"Service onion « {d.name} » de cette box", channel="tor", onion=onion, service=d.name))
    return out


def cartes_du_hall(html: str) -> List[Dict[str, Any]]:
    """Les cartes FEATURED sans `auth:true` et avec une `url` : les services publics que le Hall met en avant."""
    out: List[Dict[str, Any]] = []
    bloc = html.split("const FEATURED", 1)
    if len(bloc) < 2:
        return out
    texte = bloc[1].split("];", 1)[0]
    # Les commentaires `// …` peuvent contenir des accolades : on les retire ligne à ligne — sans toucher au `//`
    # d'un `https://` (précédé de `:`, pas d'un blanc ni d'un début de ligne).
    texte = "\n".join(re.sub(r"(^|\s)//.*$", r"\1", ligne) for ligne in texte.splitlines())
    vus = set()
    for m in _CARTE.finditer(texte):
        reste = m.group("reste")
        if _AUTH.search(reste):
            continue
        u = _URL.search(reste)
        if not u:
            continue
        hote = u.group("url").strip().lower()
        hote = re.sub(r"^https?://", "", hote).split("/", 1)[0]
        # Une carte sans `auth:true` mais servie par l'hôte d'administration (DevWatch → admin.<box>/devwatch/)
        # n'est pas une offre publique : l'hôte admin reste derrière la session.
        if not _HOTE.match(hote) or hote in vus or hote.startswith("admin."):
            continue
        vus.add(hote)
        out.append(_offre(m.group("label") or m.group("id"), "app", f"https://{hote}/",
                          f"Service « {m.group('label') or m.group('id')} » du Hall", channel="public", module=m.group("id")))
    return out


def depot_apt(haproxy_toml: Path = HAPROXY_TOML, marqueur: Path = REPO_MARQUEUR) -> List[Dict[str, Any]]:
    """Le dépôt apt de la box : module `secubox-repo` installé ET un vhost `apt.<domaine>` déclaré."""
    if not marqueur.exists():
        return []
    try:
        texte = haproxy_toml.read_text(encoding="utf-8")
    except OSError:
        return []
    m = re.search(r'^domain\s*=\s*"(apt\.[a-z0-9.-]+)"', texte, flags=re.M)
    if not m:
        return []
    return [_offre("Dépôt apt", "repo", f"https://{m.group(1)}/", "Paquets SecuBox-DEB de cette box", channel="public")]


def collecter_faits(*, tor_dir: Path = TOR_HIDDEN, hall_index: Path = HALL_INDEX,
                    haproxy_toml: Path = HAPROXY_TOML, repo_marqueur: Path = REPO_MARQUEUR) -> List[Dict[str, Any]]:
    """Tout ce que la box offre vraiment, dans un ordre stable. Chaque source manquante donne simplement rien."""
    try:
        html = hall_index.read_text(encoding="utf-8")
    except OSError:
        html = ""
    faits = onions(tor_dir) + cartes_du_hall(html) + depot_apt(haproxy_toml, repo_marqueur)
    return sorted(faits, key=lambda f: (f["kind"], f["endpoint"]))


def ecrire_faits(faits: Iterable[Dict[str, Any]], chemin: Path = FAITS_PATH) -> None:
    chemin.parent.mkdir(parents=True, exist_ok=True)
    tmp = chemin.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"version": 1, "offres": list(faits)}, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(chemin)


def lire_faits(chemin: Path = FAITS_PATH) -> Optional[List[Dict[str, Any]]]:
    """None si le fichier manque ou est illisible : on ne révoque RIEN sur une collecte absente."""
    try:
        d = json.loads(chemin.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    offres = d.get("offres") if isinstance(d, dict) else None
    return [o for o in offres if isinstance(o, dict) and o.get("kind") and o.get("endpoint")] if isinstance(offres, list) else None


def _cle(o: Dict[str, Any]) -> tuple:
    return (str(o.get("kind")), str(o.get("endpoint")))


def synchroniser(journal, priv: bytes, did: str, faits: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aligne les offres `source=sync` de CE nœud sur les faits. Rend {publies, revoques, inchangees}."""
    from annuaire.verbs import _get_offers, offer_service, revoke_offer  # noqa: PLC0415

    vivantes = {}
    for o in _get_offers(journal):
        if o.get("provider") == did and (o.get("scope") or {}).get("source") == SOURCE:
            vivantes[_cle(o)] = o
    voulues = {_cle(f): f for f in faits}
    publies, revoques = [], []
    for cle, f in voulues.items():
        if cle in vivantes:
            continue
        offre = offer_service(journal, priv, did, name=f["name"], kind=f["kind"], endpoint=f["endpoint"],
                              scope=dict(f.get("scope") or {"source": SOURCE}), approval_mode="auto",
                              description=f.get("description", ""))
        publies.append({"service_id": offre.service_id, "name": offre.name, "kind": offre.kind, "endpoint": offre.endpoint})
    for cle, o in vivantes.items():
        if cle in voulues:
            continue
        revoke_offer(journal, priv, did, o["service_id"])
        revoques.append({"service_id": o["service_id"], "name": o.get("name"), "kind": o.get("kind"), "endpoint": o.get("endpoint")})
    return {"publies": publies, "revoques": revoques,
            "inchangees": len([c for c in voulues if c in vivantes])}
