# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Recherche et liste des moteurs auprès du SearXNG du conteneur (#3581), sur le modèle du relais du POC de gk0.

La réponse de SearXNG est une entrée NON FIABLE (elle recopie des pages tierces) : taille lue plafonnée, JSON vérifié,
au plus 20 résultats, chaînes tronquées, et une URL de résultat n'est gardée que si elle est http ou https."""
from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable

DELAI_RECHERCHE = 8.0
DELAI_MOTEURS = 2.0
MAX_RESULTATS = 20
MAX_OCTETS = 4 * 1024 * 1024
LONGUEURS = {"titre": 300, "url": 2048, "extrait": 600, "moteur": 64}

_OUVREUR = urllib.request.build_opener(urllib.request.ProxyHandler({}))
# Moteurs restés sans réponse lors des dernières recherches (SearXNG ne publie pas ses suspensions sans enable_metrics).
_SANS_REPONSE: dict[str, Any] = {"releve": None, "moteurs": []}
_VERROU = threading.Lock()


class ErreurRecherche(Exception):
    """Échec côté SearXNG, avec le code HTTP que l'API doit rendre (503 injoignable, 504 délai, 502 réponse invalide)."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _lire_json(url: str, delai: float, ouvrir: Callable | None = None) -> Any:
    ouvrir = ouvrir or _OUVREUR.open
    try:
        with ouvrir(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=delai) as r:
            if getattr(r, "status", 200) != 200:
                raise ErreurRecherche(502, f"SearXNG a répondu {r.status}")
            corps = r.read(MAX_OCTETS + 1)
    except ErreurRecherche:
        raise
    except urllib.error.HTTPError as e:
        raise ErreurRecherche(502, f"SearXNG a répondu {e.code}") from e
    except (TimeoutError, socket.timeout) as e:
        raise ErreurRecherche(504, f"SearXNG n'a pas répondu en {delai:g} s") from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, (TimeoutError, socket.timeout)):
            raise ErreurRecherche(504, f"SearXNG n'a pas répondu en {delai:g} s") from e
        raise ErreurRecherche(503, "SearXNG injoignable (conteneur ou service arrêté)") from e
    except OSError as e:
        raise ErreurRecherche(503, "SearXNG injoignable (conteneur ou service arrêté)") from e
    if len(corps) > MAX_OCTETS:
        raise ErreurRecherche(502, "réponse de SearXNG trop volumineuse")
    try:
        return json.loads(corps.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise ErreurRecherche(502, "réponse de SearXNG illisible (JSON attendu)") from e


def url_sure(valeur: Any) -> str | None:
    """L'URL telle quelle si elle est http(s) avec un hôte, sinon None (javascript:, data:, relative…)."""
    if not isinstance(valeur, str) or not valeur or len(valeur) > LONGUEURS["url"]:
        return None
    if any(ord(c) < 33 or ord(c) == 127 for c in valeur):
        return None
    try:
        u = urllib.parse.urlsplit(valeur)
    except ValueError:
        return None
    if u.scheme.lower() not in ("http", "https") or not u.hostname:
        return None
    return valeur


def _texte(v: Any, cle: str) -> str:
    s = v if isinstance(v, str) else ""
    s = "".join(c if c >= " " or c in "\t" else " " for c in s).strip()
    return s[: LONGUEURS[cle]]


def nettoyer(donnees: Any) -> dict:
    if not isinstance(donnees, dict) or not isinstance(donnees.get("results", []), list):
        raise ErreurRecherche(502, "réponse de SearXNG inattendue")
    resultats, ecartes = [], 0
    for r in donnees.get("results", []):
        if len(resultats) >= MAX_RESULTATS:
            break
        if not isinstance(r, dict):
            ecartes += 1
            continue
        url = url_sure(r.get("url"))
        if url is None:
            ecartes += 1
            continue
        resultats.append({"titre": _texte(r.get("title"), "titre") or url[:LONGUEURS["titre"]], "url": url,
                          "extrait": _texte(r.get("content"), "extrait"), "moteur": _texte(r.get("engine"), "moteur")})
    sans_reponse = []
    for m in donnees.get("unresponsive_engines", []) or []:
        if isinstance(m, (list, tuple)) and m:
            sans_reponse.append({"moteur": _texte(m[0], "moteur"), "raison": _texte(m[1] if len(m) > 1 else "", "extrait")[:120]})
        if len(sans_reponse) >= 20:
            break
    return {"resultats": resultats, "ecartes": ecartes, "moteurs_sans_reponse": sans_reponse}


def rechercher(cfg: dict, q: str, page: int = 1, *, ouvrir: Callable | None = None, delai: float = DELAI_RECHERCHE) -> dict:
    ip, port = cfg["lxc"]["ip"], cfg["searxng"]["port"]
    params = urllib.parse.urlencode({"q": q, "format": "json", "language": cfg["searxng"]["langue"], "pageno": page})
    sortie = nettoyer(_lire_json(f"http://{ip}:{port}/search?{params}", delai, ouvrir))
    with _VERROU:
        _SANS_REPONSE["releve"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _SANS_REPONSE["moteurs"] = sortie["moteurs_sans_reponse"]
    return {"q": q, "page": page, "nombre": len(sortie["resultats"]), **sortie}


def moteurs(cfg: dict, *, ouvrir: Callable | None = None, delai: float = DELAI_MOTEURS) -> dict:
    """Moteurs ACTIFS d'après /config de SearXNG ; à défaut, ce que dit la configuration. Ne lève jamais."""
    ip, port = cfg["lxc"]["ip"], cfg["searxng"]["port"]
    desactives = list(cfg["searxng"]["moteurs_desactives"])
    try:
        d = _lire_json(f"http://{ip}:{port}/config", delai, ouvrir)
        liste = d.get("engines") if isinstance(d, dict) else None
        if not isinstance(liste, list):
            raise ErreurRecherche(502, "liste des moteurs absente de /config")
    except ErreurRecherche as e:
        return {"source": "configuration", "erreur": e.message, "actifs": None, "desactives": desactives}
    actifs = []
    for m in liste[:500]:
        if isinstance(m, dict) and m.get("enabled") and isinstance(m.get("name"), str):
            cats = [_texte(c, "moteur") for c in (m.get("categories") or []) if isinstance(c, str)][:8]
            actifs.append({"nom": _texte(m["name"], "moteur"), "categories": cats})
    actifs.sort(key=lambda x: x["nom"])
    return {"source": "searxng", "actifs": actifs, "desactives": desactives}


def sans_reponse_recente() -> dict:
    """Moteurs signalés sans réponse par la DERNIÈRE recherche (suspension probable : ban_time_on_fail)."""
    with _VERROU:
        return {"releve": _SANS_REPONSE["releve"], "moteurs": list(_SANS_REPONSE["moteurs"])}
