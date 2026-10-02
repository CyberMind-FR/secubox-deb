# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: health-doctor — test dynamique du WAF (sbxwaf)
CyberMind — https://cybermind.fr

Une unité « active » ne prouve pas que le WAF bloque. Ce test l'établit :
  1. sbxwaf écoute sur 127.0.0.1:8085 ;
  2. une requête témoin saine n'est PAS bloquée (pas de faux positif) ;
  3. des charges canari (XSS, injection SQL, traversée de chemin, exécution de
     commande) venant d'une IP externe simulée (TEST-NET-2, RFC 5737) sont
     refusées en 403.
Les requêtes vont directement à sbxwaf avec le Host d'un vhost public réel de la table
de routes (jamais admin.* ni git.*, que sbxwaf n'inspecte pas) : aucune n'atteint un service (le WAF répond avant l'amont). L'IP
simulée n'est jamais routable ; le User-Agent identifie le test dans les journaux.
Un tour complet toutes les 5 minutes au plus : le résultat est gardé entre deux.
"""
from __future__ import annotations

import http.client
import json
import time
from pathlib import Path
from typing import Callable

WAF_ADDR = ("127.0.0.1", 8085)
ROUTES = Path("/etc/secubox/waf/haproxy-routes.json")
IP_SIMULEE = "198.51.100.77"                    # TEST-NET-2 : jamais routée
UA = "SecuBox-WAF-SelfTest/1 (health-doctor)"
VALIDITE_S = 300

TEMOIN = ("temoin", "requête saine", "/robots.txt")
CANARIS = (
    ("xss", "Cross-Site Scripting", "/?q=%3Cscript%3Ealert(1)%3C/script%3E"),
    ("sqli", "Injection SQL", "/?id=1%27%20UNION%20SELECT%20password%20FROM%20users--"),
    ("lfi", "Traversée de chemin", "/?f=../../../../etc/passwd"),
    ("rce", "Exécution de commande", "/?c=;cat%20/etc/passwd"),
)

CACHE = Path("/var/cache/secubox/health-doctor-waf-selftest.json")
# Fichier, pas memoire : le runner est relance toutes les 60 s par un timer.


# vhosts que sbxwaf n'inspecte pas (liste en dur du binaire : services authentifiés) :
# les tester donnerait un faux échec.
NON_INSPECTES = ("admin.", "git.")


def choisir_host(routes: dict) -> str | None:
    """Un vhost PUBLIC réel : hall.* de préférence, sinon le premier nom inspecté."""
    noms = sorted(h for h in routes
                  if "." in h and not h.replace(".", "").isdigit() and not h.startswith(NON_INSPECTES))
    for h in noms:
        if h.startswith("hall."):
            return h
    return noms[0] if noms else None


def _requete(host: str, chemin: str, timeout: float = 5.0) -> int:
    c = http.client.HTTPConnection(*WAF_ADDR, timeout=timeout)
    try:
        c.request("GET", chemin, headers={"Host": host, "X-Forwarded-For": IP_SIMULEE,
                                          "User-Agent": UA, "Connection": "close"})
        return c.getresponse().status
    finally:
        c.close()


def executer(host: str, requete: Callable[[str, str], int] = _requete) -> dict:
    """Joue le témoin puis les canaris ; ne lève jamais."""
    tests = []
    for cle, libelle, chemin in (TEMOIN, *CANARIS):
        attendu_bloque = cle != "temoin"
        t0 = time.time()
        try:
            code = requete(host, chemin)
            bloque = code in (403, 429)
            ok = bloque if attendu_bloque else not bloque
            tests.append({"id": cle, "libelle": libelle, "attendu": "bloqué" if attendu_bloque else "non bloqué",
                          "code": code, "ok": ok, "ms": int((time.time() - t0) * 1000)})
        except OSError as e:
            tests.append({"id": cle, "libelle": libelle, "attendu": "bloqué" if attendu_bloque else "non bloqué",
                          "code": None, "ok": False, "erreur": str(e)[:80], "ms": int((time.time() - t0) * 1000)})
    return {"host": host, "tests": tests, "ok": all(t["ok"] for t in tests)}


def _lire_cache(cache: Path) -> dict | None:
    try:
        return json.loads(cache.read_text())
    except (OSError, ValueError):
        return None


def verifier(maintenant: float | None = None,
             requete: Callable[[str, str], int] = _requete,
             ecoute: Callable[[], bool] | None = None,
             cache: Path | None = None) -> tuple[bool, dict]:
    """Interface du registre health-doctor : (ok, détails). Résultat gardé 5 min."""
    now = maintenant if maintenant is not None else time.time()
    cache = cache or CACHE
    prec = _lire_cache(cache)
    if prec and isinstance(prec.get("ts"), (int, float)) and 0 <= now - prec["ts"] < VALIDITE_S:
        prec["age_s"] = int(now - prec["ts"])
        prec["en_cache"] = True
        return bool(prec.get("ok")), prec

    if ecoute is None:
        import socket

        def ecoute() -> bool:
            try:
                with socket.create_connection(WAF_ADDR, timeout=2):
                    return True
            except OSError:
                return False

    if not ecoute():
        res = {"ok": False, "ecoute": False, "tests": [], "erreur": "sbxwaf n'écoute pas sur 127.0.0.1:8085"}
    else:
        try:
            host = choisir_host(json.loads(ROUTES.read_text()))
        except (OSError, ValueError):
            host = None
        if not host:
            res = {"ok": False, "ecoute": True, "tests": [], "erreur": "aucun vhost dans la table de routes du WAF"}
        else:
            res = {"ecoute": True, **executer(host, requete)}
    res["ts"] = now
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(res))
    except OSError:
        pass                         # sans cache, le test rejoue à chaque tour : acceptable
    out = dict(res)
    out["age_s"] = 0
    out["en_cache"] = False
    return out["ok"], out
