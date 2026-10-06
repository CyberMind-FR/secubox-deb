# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Éphéméride — API de la cardlet du Hall (socket /run/secubox/ephemeride.sock).

  GET    /                       les données du jour (lecture gardée : require_lecture)
  GET    /observations           l'historique des observations
  POST   /observations           ajouter            (administrateur : require_jwt)
  PUT    /observations/{id}      modifier           (administrateur)
  DELETE /observations/{id}      supprimer          (administrateur)
  GET    /health                 vivacité (publique)

Tout ce qui dépend de l'astronomie, du calendrier et des saints est calculé ICI, sans réseau. Seules la météo et la qualité de
l'air interrogent un fournisseur, par un cache : jamais à chaque rafraîchissement, et la carte reste complète sans Internet.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from fastapi import Depends, FastAPI, HTTPException

from secubox_core.auth import require_jwt, require_lecture

from . import astro, calendrier, config as conf, fournisseurs as F, observations as O, saints as S
from .modeles import EphemerideData, ObservationEntree, ObservationModele

log = logging.getLogger("ephemeride")

app = FastAPI(title="SecuBox Éphéméride", version="0.1.0")

_etat = {"cfg": (0.0, None), "obs": None, "cache": None, "saints": {}}
_verrou = threading.Lock()
_en_cours: set = set()
TTL_CONFIG_S = 30.0
NOTES_DANS_LES_DONNEES = 5


# ── points d'injection (remplacés par les tests) ─────────────────────────────────────────────────────────────────────

def _config() -> conf.Config:
    t, c = _etat["cfg"]
    if c is None or time.monotonic() - t > TTL_CONFIG_S:
        c = conf.charger()
        _etat["cfg"] = (time.monotonic(), c)
    return c


def _maintenant() -> datetime:
    return datetime.now(timezone.utc).astimezone(_config().fuseau())


def _observations() -> O.Observations:
    with _verrou:
        if _etat["obs"] is None:
            _etat["obs"] = O.Observations()
        return _etat["obs"]


def _cache() -> F.Cache:
    with _verrou:
        if _etat["cache"] is None:
            _etat["cache"] = F.Cache()
        return _etat["cache"]


def _fournisseur_meteo() -> Optional[F.WeatherProvider]:
    return None if _config().meteo.provider == "none" else F.OpenMeteoMeteo()


def _fournisseur_air() -> Optional[F.AirQualityProvider]:
    return None if _config().air.provider == "none" else F.OpenMeteoAir()


def _fournisseur_saints(cfg: conf.Config) -> S.SaintProvider:
    return S.fournisseur(Path(cfg.saint.fichier))


def _arriere_plan(tache: Callable[[], None]) -> None:
    threading.Thread(target=tache, daemon=True, name="ephemeride-rafraichir").start()


# ── assemblage ───────────────────────────────────────────────────────────────────────────────────────────────────────

def _decalage(m: datetime) -> tuple:
    minutes = int(m.utcoffset().total_seconds() // 60)
    if minutes == 0:
        return "UTC", 0
    signe, absolu = ("+" if minutes > 0 else "-"), abs(minutes)
    h, mi = divmod(absolu, 60)
    return f"UTC{signe}{h}" + (f":{mi:02d}" if mi else ""), minutes


def _donnee(cle: str, fonction: conf.Fonction, fournisseur, lieu: conf.Lieu):
    """(données | None, état) pour la météo ou l'air : le cache d'abord, le réseau seulement si rien n'est connu."""
    if not fonction.enabled or fournisseur is None:
        return None, {"etat": "desactive", "maj": None}
    cache, ttl = _cache(), fonction.ttl_s
    fetch = lambda: F.vers_dict(fournisseur.obtenir(lieu.latitude, lieu.longitude))        # noqa: E731
    lu = cache.lire(cle, ttl)
    if lu.etat == "indisponible":
        lu = cache.obtenir(cle, ttl, fetch)                     # premier appel : on attend le fournisseur (délai borné)
    elif lu.etat == "perime":
        with _verrou:
            lance = cle not in _en_cours
            _en_cours.add(cle)
        if lance:
            def tache():
                try:
                    cache.obtenir(cle, ttl, fetch)
                finally:
                    with _verrou:
                        _en_cours.discard(cle)
            _arriere_plan(tache)
    return lu.donnees, {"etat": lu.etat, "maj": lu.ts}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "module": "ephemeride"}


@app.get("/", response_model=EphemerideData)
def donnees(user=Depends(require_lecture)):
    cfg = _config()
    now = _maintenant()
    lieu = cfg.lieu()
    cal = calendrier.infos(now, lieu.latitude)
    sol = astro.soleil(now, lieu.latitude, lieu.longitude)
    lun = astro.lune(now, lieu.latitude, lieu.longitude)
    phase = astro.prochaine_phase(now)
    saints = []
    if cfg.saint.enabled:
        saints = [vars(s) for s in _fournisseur_saints(cfg).pour(now.date())]
    meteo, meteo_etat = _donnee("meteo", cfg.meteo, _fournisseur_meteo(), lieu)
    air, air_etat = _donnee("air", cfg.air, _fournisseur_air(), lieu)
    notes = [vars(o) for o in _observations().lister(NOTES_DANS_LES_DONNEES)] if cfg.observations.enabled else []
    decal, minutes = _decalage(now)
    return {
        "maintenant": now, "serveur_epoch_ms": int(now.timestamp() * 1000),
        "fuseau": {"nom": cfg.fuseau().key, "decalage": decal, "decalage_minutes": minutes},
        "lieu": {"nom": lieu.nom, "latitude": lieu.latitude, "longitude": lieu.longitude, "approximatif": lieu.approximatif},
        "calendrier": vars(cal),
        "soleil": {"lever": sol.lever, "coucher": sol.coucher, "duree_s": int(sol.duree.total_seconds()),
                   "progression": sol.progression, "etat": sol.etat},
        "lune": {**{k: getattr(lun, k) for k in ("nom", "illumination", "age_jours", "croissante", "lever", "coucher", "elongation")},
                 "prochaine_phase": {"nom": phase.nom, "quand": phase.quand}},
        "saints": saints, "meteo": meteo, "meteo_etat": meteo_etat, "air": air, "air_etat": air_etat,
        "observations": notes, "reglages": {"format_24h": cfg.format_24h, "observations": cfg.observations.enabled},
    }


# ── observations ─────────────────────────────────────────────────────────────────────────────────────────────────────

def _observations_actives() -> O.Observations:
    if not _config().observations.enabled:
        raise HTTPException(404, "observations désactivées")
    return _observations()


@app.get("/observations")
def lister_observations(limite: int = 20, user=Depends(require_lecture)) -> dict:
    if not _config().observations.enabled:
        return {"observations": []}
    return {"observations": [vars(o) for o in _observations().lister(limite)]}


@app.post("/observations", status_code=201, response_model=ObservationModele)
def ajouter_observation(corps: ObservationEntree, user=Depends(require_jwt)):
    try:
        return vars(_observations_actives().ajouter(corps.texte))
    except O.ObservationInvalide as e:
        raise HTTPException(422, str(e)) from None


@app.put("/observations/{ident}", response_model=ObservationModele)
def modifier_observation(ident: int, corps: ObservationEntree, user=Depends(require_jwt)):
    try:
        o = _observations_actives().modifier(ident, corps.texte)
    except O.ObservationInvalide as e:
        raise HTTPException(422, str(e)) from None
    if o is None:
        raise HTTPException(404, "observation introuvable")
    return vars(o)


@app.delete("/observations/{ident}")
def supprimer_observation(ident: int, user=Depends(require_jwt)) -> dict:
    if not _observations_actives().supprimer(ident):
        raise HTTPException(404, "observation introuvable")
    return {"ok": True}
