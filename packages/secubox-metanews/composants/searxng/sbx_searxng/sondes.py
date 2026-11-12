# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Sondes SANS PRIVILÈGE et BORNÉES de l'état de SearXNG (#3581), et leur cache court.

Leçon de YaCy sur gk2 : `yacyctl status|components|access --json` sondait en série (curl 3 s, puis `sudo -n lxc-info`
refusé…) et dépassait les 15 s de l'API, qui rendait 500. Ici :
  * aucune sonde ne demande root : le conteneur se juge par le réseau br-lxc (une connexion TCP refusée = l'hôte répond,
    donc le conteneur tourne, mais pas SearXNG ; un délai dépassé = conteneur arrêté), SearXNG par son /healthz ;
  * chaque sonde a son délai (≤ 2 s), elles partent EN PARALLÈLE et le relevé entier est borné (DELAI_TOTAL < 5 s) :
    une sonde qui ne rend pas la main à temps vaut « unknown », jamais une exception ;
  * le relevé est gardé quelques secondes (mémoire + fichier) : /status et /components appelés ensemble ne sondent qu'une fois.
"""
from __future__ import annotations

import concurrent.futures as cf
import errno
import json
import logging
import os
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import VERSION

log = logging.getLogger("secubox.searxng.sondes")

DELAI_TCP = 1.0
DELAI_SANTE = 1.8
DELAI_SYSTEMCTL = 1.5
DELAI_TOTAL = 4.0
ETATS_BONS = ("running",)

_POOL = cf.ThreadPoolExecutor(max_workers=8, thread_name_prefix="sonde-searxng")
# Pas de mandataire, quoi que dise l'environnement : la cible est un conteneur local.
_OUVREUR = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def sonde_tcp(ip: str, port: int, delai: float = DELAI_TCP) -> str:
    """« ouvert » (SearXNG écoute), « refuse » (l'hôte répond, rien n'écoute), « injoignable » (rien ne répond)."""
    try:
        with socket.create_connection((ip, port), timeout=delai):
            return "ouvert"
    except ConnectionRefusedError:
        return "refuse"
    except OSError as e:
        if getattr(e, "errno", None) == errno.ECONNREFUSED:
            return "refuse"
        return "injoignable"


def sonde_sante(ip: str, port: int, delai: float = DELAI_SANTE) -> bool:
    """/healthz de SearXNG rend 200 « OK » quand l'application est chargée."""
    try:
        with _OUVREUR.open(f"http://{ip}:{port}/healthz", timeout=delai) as r:
            return r.status == 200 and r.read(64).strip().upper().startswith(b"OK")
    except (OSError, urllib.error.URLError, ValueError):
        return False


def sonde_unite(unite: str = "secubox-searxng.service", delai: float = DELAI_SYSTEMCTL) -> str:
    """État de l'API hôte vu par systemd (CLI seulement ; dans l'API, elle se sait en marche)."""
    try:
        p = subprocess.run(["systemctl", "is-active", unite], capture_output=True, text=True, timeout=delai, check=False)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return "running" if p.stdout.strip() == "active" else "stopped"


def dossier_conteneur(cfg: dict) -> bool:
    """Le conteneur existe-t-il ? (stat seul, /data/lxc est traversable : pas besoin de root)."""
    return os.path.isdir(os.path.join(cfg["lxc"]["path"], cfg["lxc"]["name"]))


def releve(cfg: dict, api: str | Callable[[], str] = "running", *, tcp: Callable = sonde_tcp,
           sante: Callable = sonde_sante, dossier: Callable = dossier_conteneur, delai_total: float = DELAI_TOTAL) -> dict:
    """Un relevé complet, borné par `delai_total` quoi que fassent les sondes. Ne lève jamais."""
    debut = time.monotonic()
    ip, port = cfg["lxc"]["ip"], cfg["searxng"]["port"]
    taches = {
        "tcp": _POOL.submit(tcp, ip, port),
        "sante": _POOL.submit(sante, ip, port),
        "dossier": _POOL.submit(dossier, cfg),
    }
    if callable(api):
        taches["api"] = _POOL.submit(api)
    cf.wait(list(taches.values()), timeout=delai_total)
    res: dict[str, Any] = {}
    for nom, f in taches.items():
        if not f.done():
            f.cancel()
            res[nom] = None
            continue
        try:
            res[nom] = f.result(timeout=0)
        except Exception as e:  # noqa: BLE001 — une sonde qui lève vaut « inconnu », et c'est journalisé
            log.warning("sonde %s en échec : %s", nom, e.__class__.__name__)
            res[nom] = None
    api_etat = (res.get("api") if callable(api) else api) or "unknown"
    return composer(cfg, res["tcp"], res["sante"], res["dossier"], api_etat,
                    duree_ms=int((time.monotonic() - debut) * 1000))


def composer(cfg: dict, tcp: str | None, sante: bool | None, dossier: bool | None, api: str, duree_ms: int = 0) -> dict:
    if tcp in ("ouvert", "refuse") or sante:
        conteneur = "running"
    elif tcp == "injoignable":
        conteneur = "stopped" if dossier else ("absent" if dossier is False else "unknown")
    else:
        conteneur = "unknown"
    if sante:
        service = "running"
    elif sante is None and tcp is None:
        service = "unknown"
    elif tcp == "ouvert":
        service = "degraded"            # le port répond, l'application non
    else:
        service = "stopped"
    etats = (conteneur, service, api)
    if all(e == "running" for e in etats):
        global_ = "green"
    elif conteneur == "running" or "unknown" in etats:
        global_ = "yellow"
    else:
        global_ = "red"
    lxc, sx = cfg["lxc"], cfg["searxng"]
    return {
        "module": "searxng",
        "version": VERSION,
        "overall": global_,
        "conteneur": conteneur,
        "service": service,
        "api": api,
        "adresse": f"{lxc['ip']}:{sx['port']}",
        "duree_ms": duree_ms,
        "releve": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def vue_status(r: dict) -> dict:
    return {k: r[k] for k in ("module", "version", "overall", "conteneur", "service", "api", "adresse", "releve", "duree_ms")}


def vue_components(r: dict, cfg: dict) -> dict:
    lxc, sx = cfg["lxc"], cfg["searxng"]
    return {
        "module": "searxng",
        "version": r["version"],
        "releve": r["releve"],
        "components": [
            {"name": "lxc", "state": r["conteneur"],
             "detail": f"{lxc['name']} @ {lxc['ip']} sur {lxc['bridge']}" + (" — « searxngctl install »" if r["conteneur"] == "absent" else "")},
            {"name": "searxng", "state": r["service"], "detail": f"SearXNG, port {sx['port']} (adresse du conteneur seulement)"},
            {"name": "host-api", "state": r["api"], "detail": "secubox-searxng.service (uvicorn @ /run/secubox/searxng.sock)"},
        ],
    }


class Cache:
    """Cache court : mémoire d'abord, puis fichier (survit à un redémarrage de l'API), sinon calcul sous verrou.

    Écriture atomique (fichier temporaire puis os.replace, 0640). Un fichier illisible ou trop vieux est recalculé ;
    une écriture impossible est journalisée, le relevé est rendu quand même."""

    def __init__(self, fichier: Path | str | None, ttl: float):
        self.fichier = Path(fichier) if fichier else None
        self.ttl = ttl
        self._verrou = threading.Lock()
        self._memoire: tuple[float, Any] | None = None

    def _frais(self, horodatage: float) -> bool:
        return 0 <= time.time() - horodatage < self.ttl

    def _lire_fichier(self) -> Any:
        if self.fichier is None:
            return None
        try:
            with open(self.fichier, encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and self._frais(float(d.get("horodatage", -1))):
                return d.get("donnees")
        except (OSError, ValueError, TypeError):
            return None
        return None

    def _ecrire_fichier(self, donnees: Any) -> None:
        if self.fichier is None:
            return
        tmp = self.fichier.with_name(self.fichier.name + f".{os.getpid()}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"horodatage": time.time(), "donnees": donnees}, f)
            os.replace(tmp, self.fichier)
        except OSError as e:
            log.warning("cache %s non écrit : %s", self.fichier, e.__class__.__name__)
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def obtenir(self, calcul: Callable[[], Any]) -> Any:
        m = self._memoire
        if m and self._frais(m[0]):
            return m[1]
        with self._verrou:
            m = self._memoire
            if m and self._frais(m[0]):
                return m[1]
            d = self._lire_fichier()
            if d is None:
                d = calcul()
                self._ecrire_fichier(d)
            self._memoire = (time.time(), d)
            return d

    def oublier(self) -> None:
        with self._verrou:
            self._memoire = None
            if self.fichier is not None:
                try:
                    self.fichier.unlink()
                except FileNotFoundError:
                    pass
                except OSError as e:
                    log.warning("cache %s non retiré : %s", self.fichier, e.__class__.__name__)
