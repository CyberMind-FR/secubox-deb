# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: état en direct (#2706).

Ce que la bande d'état de la page /ad-guard/ affiche : résolveur, puits DNS, listes de blocage, capteur DNS d'Actor Intelligence, flux de compteurs
et appareils actifs. LECTURE SEULE, aucun secret. Une valeur qu'on ne sait pas lire est `None` (la page affiche « inconnu » ou « — »), JAMAIS un faux « OK »
ni un zéro. Les lectures systemd passent par `systemctl is-active`, qui ne demande aucun privilège.
"""
from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Optional

SINKHOLE_STATUS = Path("/var/lib/secubox/ad-guard/sinkhole-status.json")
DROPIN_PUITS = Path("/etc/unbound/unbound.conf.d/95-secubox-adblock.conf")
ETAT_CAPTEUR = Path("/var/lib/secubox/ad-guard/dnstv/dnssensor-etat.json")
UNITE_RESOLVEUR = "unbound.service"
UNITE_CAPTEUR = "secubox-ad-guard-dnssensor.timer"
UNITE_FLUX = "secubox-ad-guard-dnsfeed.service"
PEREMPTION_LISTES_S = 9 * 86400          # la synchronisation est hebdomadaire (minuterie du dimanche) : au-delà de neuf jours, une exécution a manqué
ACTIF_CLIENT_S = 300                     # « client actif » : une requête dans les 5 dernières minutes
CACHE_S = 5

_verrou = threading.Lock()
_cache: dict = {}


def unite_active(unite: str, lancer: Optional[Callable] = None) -> Optional[bool]:
    """True si active, False si arrêtée ou en échec, None si on ne peut pas le dire."""
    lancer = lancer or subprocess.run
    try:
        r = lancer(["systemctl", "is-active", unite], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    sortie = (r.stdout or "").strip()
    if sortie == "active":
        return True
    if sortie in ("inactive", "failed", "deactivating"):
        return False
    return None


def _json(chemin: Path) -> Optional[dict]:
    try:
        d = json.loads(chemin.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _entier(v) -> Optional[int]:
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0 else None


def _mtime(chemin: Path) -> Optional[int]:
    try:
        return int(chemin.stat().st_mtime)
    except OSError:
        return None


def puits_et_listes(statut: Optional[dict], mtime_dropin: Optional[int]) -> tuple:
    """(puits, listes) d'après sinkhole-status.json. Fichier absent : tout est inconnu."""
    if statut is None:
        return ({"actif": None, "ok": None, "erreur": None, "recharge": None},
                {"domaines": None, "maj_ts": mtime_dropin, "peremption_s": PEREMPTION_LISTES_S})
    ok = statut.get("ok") if isinstance(statut.get("ok"), bool) else None
    enabled = statut.get("enabled") if isinstance(statut.get("enabled"), bool) else None
    erreur = statut.get("error")
    puits = {"actif": enabled, "ok": ok, "erreur": str(erreur)[:200] if erreur else None,
             "recharge": statut.get("reloaded") if isinstance(statut.get("reloaded"), bool) else None}
    # Date de la dernière mise à jour RÉUSSIE : le ts du statut seulement si la synchronisation a réussi, sinon l'âge du fichier de règles posé.
    maj = _entier(statut.get("ts")) if ok else mtime_dropin
    return puits, {"domaines": _entier(statut.get("blocked")), "maj_ts": maj, "peremption_s": PEREMPTION_LISTES_S}


def capteur(actif: Optional[bool], etat: Optional[dict], now: int) -> dict:
    """Le capteur DNS : minuterie active ? combien de constats émis sur 24 h ? Le fichier d'état ne bouge que lorsqu'un constat nouveau sort."""
    emis = etat.get("emis") if isinstance(etat, dict) and isinstance(etat.get("emis"), dict) else None
    ts = [t for t in (emis or {}).values() if isinstance(t, (int, float)) and not isinstance(t, bool)]
    return {"actif": actif, "constats_24h": sum(1 for t in ts if now - t <= 86400) if emis is not None else None,
            "dernier_constat_ts": int(max(ts)) if ts else None}


def etat_direct(now: Optional[int] = None, *, magasin=None, lancer: Optional[Callable] = None) -> dict:
    """Le relevé complet ; `magasin` : le magasin de compteurs DNS (api.dnstv.Magasin) ou None s'il est illisible."""
    now = int(now if now is not None else time.time())
    puits, listes = puits_et_listes(_json(SINKHOLE_STATUS), _mtime(DROPIN_PUITS))
    dernier, actifs, vus = None, None, None
    if magasin is not None:
        try:
            recents = magasin.recents(None, now - 86400, 1)
            dernier = int(recents[0]["ts"]) if recents else None
            clients = magasin.par_client()
            vus = len(clients)
            actifs = sum(1 for c in clients if now - c["derniere_vue"] <= ACTIF_CLIENT_S)
        except Exception:
            dernier = actifs = vus = None
    return {"maintenant": now,
            "resolveur": {"actif": unite_active(UNITE_RESOLVEUR, lancer)},
            "puits": puits, "listes": listes,
            "capteur": capteur(unite_active(UNITE_CAPTEUR, lancer), _json(ETAT_CAPTEUR), now),
            "flux": {"actif": unite_active(UNITE_FLUX, lancer), "dernier_evenement_ts": dernier},
            "clients": {"actifs_5min": actifs, "vus": vus}}


def etat_direct_cache(magasin_fabrique: Callable) -> dict:
    """Le même relevé, mis en cache 5 s : plusieurs onglets ouverts ne multiplient pas les lectures."""
    with _verrou:
        vu = _cache.get("v")
        if vu and time.time() - vu[0] < CACHE_S:
            return vu[1]
        try:
            magasin = magasin_fabrique()
        except Exception:
            magasin = None
        r = etat_direct(magasin=magasin)
        _cache["v"] = (time.time(), r)
        return r
