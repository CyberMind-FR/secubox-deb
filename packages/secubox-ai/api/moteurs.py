# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Moteurs d'inférence de secubox-ai : local (llama-server sur socket Unix) et distant (#3583).

Le moteur local est piloté par un contrôleur root : le module dépose une demande
`$SECUBOX_AI_RUN/demandes/<action>.demande` (jamais de systemctl). Le moteur distant n'est utilisé que si
`config()["distant"]["url"]` est déclarée ET si la clé `$SECUBOX_AI_CLE` est lisible et non vide ; sans clé,
aucune requête n'est émise vers l'adresse distante. La clé n'apparaît ni dans les journaux, ni dans les
exceptions, ni dans `etat()`, ni dans `repr(Moteur)`.
"""
import asyncio
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Callable, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException

from secubox_core.auth import require_jwt

from api import reglages

log = logging.getLogger("secubox.ai.moteurs")

RUN_DEFAUT = "/run/secubox-ai"
CLE_DEFAUT = "/etc/secubox/secrets/ai/distant.key"
ACTIONS = ("demarrer", "arreter", "redemarrer")
CTX_AUTO_MIN = 4096
DELAI_SONDE_S = 2.0       # sonde /health du moteur distant
CACHE_SONDE_S = 10.0      # une sonde récente évite de re-sonder à chaque requête
DELAI_DEMARRAGE_S = 180
PAS_ATTENTE_S = 1.0       # pas d'attente du redémarrage (réduit par les tests)

# Point d'injection des tests : fabrique(nom) -> transport httpx (ou None = transport réel).
FABRIQUE_TRANSPORT: Callable[[str], httpx.AsyncBaseTransport | None] | None = None
_cache_sonde: dict = {}


def run_dir() -> Path:
    return Path(os.environ.get("SECUBOX_AI_RUN", RUN_DEFAUT))


def _lire_cle() -> str | None:
    """Clé distante lue à l'appel ; None si absente, vide ou illisible."""
    try:
        cle = Path(os.environ.get("SECUBOX_AI_CLE", CLE_DEFAUT)).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return cle or None


def _url_distante() -> str:
    url = reglages.config().get("distant", {}).get("url")
    return url.strip().rstrip("/") if isinstance(url, str) else ""


def deposer_demande(action: str) -> None:
    """Dépose une demande au contrôleur root. Idempotent et sûr en concurrence : fichier temporaire
    unique dans le même dossier, puis os.replace (la dernière écriture gagne, un seul fichier reste).
    Dépôt absent : HTTPException(503) « contrôleur non préparé »."""
    if action not in ACTIONS:
        raise ValueError(f"action inconnue : {action}")
    dossier = run_dir() / "demandes"
    # Jamais créé ici : c'est secubox-aictl preparer (root:secubox-ai 1770) ; absent = 503 clair, pas une erreur 500.
    try:
        fd, tmp = tempfile.mkstemp(dir=dossier, prefix=f".{action}.", suffix=".tmp")
    except FileNotFoundError:
        log.warning("dépôt des demandes absent : contrôleur non préparé")
        raise HTTPException(503, "contrôleur non préparé : lancer secubox-ai-preparer.service") from None
    try:
        os.close(fd)
        os.replace(tmp, dossier / f"{action}.demande")
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Moteur:
    """Un moteur choisi : `nom` vaut "local" ou "distant"."""

    def __init__(self, nom: str, url: str = "", cle: str | None = None):
        self.nom = nom
        self._url = url
        self._cle = cle

    def __repr__(self) -> str:
        return f"Moteur({self.nom!r})"

    def client(self, delai: float = 300) -> httpx.AsyncClient:
        transport = FABRIQUE_TRANSPORT(self.nom) if FABRIQUE_TRANSPORT else None
        if self.nom == "local":
            if transport is None:
                transport = httpx.AsyncHTTPTransport(uds=str(run_dir() / "moteur.sock"))
            return httpx.AsyncClient(transport=transport, base_url="http://moteur", timeout=delai,
                                     trust_env=False)
        if not self._cle:
            raise HTTPException(503, "moteur distant non configuré")
        return httpx.AsyncClient(transport=transport, base_url=self._url, timeout=delai, trust_env=False,
                                 headers={"Authorization": f"Bearer {self._cle}"})


def _local() -> Moteur:
    return Moteur("local")


def _distant() -> Moteur | None:
    """Le moteur distant, ou None s'il n'est pas déclaré ou si la clé manque."""
    url, cle = _url_distante(), _lire_cle()
    return Moteur("distant", url, cle) if url and cle else None


async def _sonde(m: Moteur, delai: float) -> bool:
    """/health = 200 ? Utilisé pour le moteur local et pour l'attente du démarrage."""
    try:
        async with m.client(delai) as c:
            return (await c.get("/health")).status_code == 200
    except (httpx.HTTPError, HTTPException):
        return False


async def _statut_distant(m: Moteur, contourner_cache: bool = False) -> str:
    """Sonde `GET /health` (2 s) : "pret" (200), "endormi" (503 : entrée vivante, moteur endormi ou en
    chargement), "refuse" (401/403 : clé refusée), "injoignable" (réseau, délai, autre code).
    Résultat gardé 10 s, sauf si `contourner_cache`."""
    maintenant = time.monotonic()
    vu = _cache_sonde.get(m._url)
    if vu and not contourner_cache and maintenant - vu[0] < CACHE_SONDE_S:
        return vu[1]
    try:
        async with m.client(DELAI_SONDE_S) as c:
            code = (await c.get("/health")).status_code
        statut = {200: "pret", 503: "endormi", 401: "refuse", 403: "refuse"}.get(code, "injoignable")
        if statut == "refuse":
            log.warning("moteur distant : clé refusée (HTTP %s)", code)
    except httpx.HTTPError as e:
        statut = "injoignable"
        log.warning("moteur distant injoignable (%s)", type(e).__name__)
    _cache_sonde[m._url] = (maintenant, statut)
    return statut


def _invalider(m: Moteur) -> None:
    _cache_sonde.pop(m._url, None)


async def _selection(force: str | None, contourner_cache: bool = False) -> tuple[Moteur, str | None]:
    """(moteur choisi, statut distant sondé ou None si le local est retenu sans sonde)."""
    force = force or reglages.lire_prefs()["moteur"]["force"]
    if force == "local":
        return _local(), None
    distant = _distant()
    if force == "distant":
        if distant is None:
            raise HTTPException(503, "moteur distant non configuré")
        return distant, await _statut_distant(distant, contourner_cache)
    if distant is not None:
        statut = await _statut_distant(distant, contourner_cache)
        if statut in ("pret", "endormi"):
            return distant, statut
    return _local(), None


async def choisir(force: str | None = None) -> Moteur:
    """Moteur à utiliser. `force` : auto/local/distant, sinon la préférence `moteur.force`.
    Auto : distant si sa sonde répond 200 (prêt) ou 503 (endormi, à réveiller), sinon local."""
    return (await _selection(force))[0]


def _etat_local() -> dict | None:
    try:
        d = json.loads((run_dir() / "moteur-etat.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) else None


def _echec_controleur(depuis: float) -> str | None:
    """Message d'échec du contrôleur (refus mémoire, erreur) postérieur à `depuis`, sinon None."""
    d = _etat_local()
    if not d or d.get("etat") not in ("refus_memoire", "erreur"):
        return None
    h = d.get("horodatage")
    if isinstance(h, bool) or not isinstance(h, (int, float)) or h <= depuis:
        return None
    return str(d.get("message") or "le moteur local a refusé de démarrer")[:300]


async def attendre_moteur(m: Moteur, delai: float = DELAI_DEMARRAGE_S, pas: float = 1.0,
                          depuis: float | None = None) -> bool:
    """Attend /health 200. Local : échoue aussitôt (503 + message) si le contrôleur signale un refus
    ou une erreur postérieurs à `depuis`."""
    limite = time.monotonic() + delai
    while True:
        if await _sonde(m, 5):
            return True
        if m.nom == "local" and depuis is not None:
            message = _echec_controleur(depuis)
            if message:
                raise HTTPException(503, message)
        if time.monotonic() >= limite:
            return False
        await asyncio.sleep(pas)


async def _assurer_local(delai: float, pas: float) -> Moteur:
    m = _local()
    if await _sonde(m, 5):
        return m
    depuis = time.time()
    await asyncio.to_thread(deposer_demande, "demarrer")
    if not await attendre_moteur(m, delai, pas, depuis):
        raise HTTPException(503, "le moteur local n'a pas démarré")
    return m


def local_lit_images() -> bool:
    """Le moteur local lit-il les images ? Non à l'étape 1 (aucun projecteur `--mmproj` configuré) ;
    crochet pour les tâches suivantes."""
    return False


def _redemarrage_vu(depuis: float) -> bool:
    """Le contrôleur a-t-il signalé (R9) un démarrage ou un moteur prêt postérieur à `depuis` ?"""
    d = _etat_local()
    if not d or d.get("etat") not in ("demarrage", "pret"):
        return False
    h = d.get("horodatage")
    return not isinstance(h, bool) and isinstance(h, (int, float)) and h > depuis


async def changer_modele_local(delai: float = DELAI_DEMARRAGE_S, pas: float | None = None) -> Moteur:
    """Redémarre le moteur local sur le modèle des préférences et attend qu'il réponde : tant que le contrôleur n'a
    pas signalé le redémarrage (ou que l'ancien moteur répond encore), rien ne part vers l'ancien modèle.
    Échoue aussitôt (503 + message du contrôleur) sur refus mémoire ou erreur."""
    pas = PAS_ATTENTE_S if pas is None else pas
    m = _local()
    depuis = time.time()
    await asyncio.to_thread(deposer_demande, "redemarrer")
    limite = time.monotonic() + delai
    while not _redemarrage_vu(depuis):
        message = _echec_controleur(depuis)
        if message:
            raise HTTPException(503, message)
        if not await _sonde(m, 2):          # l'ancien moteur ne répond plus : le redémarrage est en cours
            break
        if time.monotonic() >= limite:
            raise HTTPException(503, "le moteur local n'a pas redémarré")
        await asyncio.sleep(pas)
    if not await attendre_moteur(m, max(0.0, limite - time.monotonic()), pas, depuis):
        raise HTTPException(503, "le moteur local n'a pas démarré")
    return m


async def _reveiller_distant(m: Moteur) -> str | None:
    """Demande le démarrage du moteur distant. None si accepté, sinon un motif sans clé."""
    try:
        async with m.client(10) as c:
            r = await c.post("/moteur/demarrer")
    except httpx.HTTPError as e:
        log.warning("moteur distant : démarrage impossible, injoignable (%s)", type(e).__name__)
        return "moteur distant injoignable"
    if r.status_code in (401, 403):
        log.warning("moteur distant : démarrage refusé, clé refusée (HTTP %s)", r.status_code)
        return "moteur distant : clé refusée"
    if r.status_code >= 400:
        log.warning("moteur distant : démarrage refusé (HTTP %s)", r.status_code)
        return f"moteur distant : démarrage refusé (HTTP {r.status_code})"
    return None


async def assurer_moteur(delai: float = DELAI_DEMARRAGE_S, pas: float = 1.0, force: str | None = None) -> Moteur:
    """Choisit le moteur (sonde fraîche, jamais le cache), le démarre au besoin et attend qu'il réponde.
    En auto, un distant en échec (sonde, réveil) est écarté et on se rabat sur le local.
    `force` (auto/local/distant) remplace la préférence `moteur.force` pour cet appel."""
    force = force or reglages.lire_prefs()["moteur"]["force"]
    m, statut = await _selection(force, contourner_cache=True)
    if m.nom == "local":
        return await _assurer_local(delai, pas)
    if statut == "pret":
        return m
    motif = {"refuse": "moteur distant : clé refusée", "injoignable": "moteur distant injoignable"}.get(statut)
    if motif is None:  # endormi : on le réveille
        motif = await _reveiller_distant(m)
        if motif is None:
            if await attendre_moteur(m, delai, pas):
                return m
            motif = "le moteur distant n'a pas démarré"
            if force == "distant":
                raise HTTPException(503, motif)
            _invalider(m)
            return await _assurer_local(delai, pas)
    _invalider(m)
    if force == "distant":
        raise HTTPException(503, motif)
    return await _assurer_local(delai, pas)


async def props(m: Moteur) -> dict:
    """`GET /props` du moteur en marche (llama-server)."""
    async with m.client(10) as c:
        r = await c.get("/props")
        r.raise_for_status()
    return r.json()


def contexte_de(p: dict) -> int:
    """Le contexte lu dans `/props`, sinon la préférence, sinon le minimum automatique."""
    return int(p["default_generation_settings"]["n_ctx"]) or reglages.lire_prefs()["moteur"]["contexte"] or CTX_AUTO_MIN


def modele_de(m: Moteur, p: dict) -> str:
    """Nom du modèle qui répond : la préférence pour le local, le `model_path` de `/props` pour le distant."""
    if m.nom == "local":
        return reglages.lire_prefs()["moteur"]["modele"]
    chemin = p.get("model_path") if isinstance(p, dict) else None
    return chemin.replace("\\", "/").rsplit("/", 1)[-1] if isinstance(chemin, str) and chemin.strip() else "distant (gk0)"


async def contexte_reel(m: Moteur | None = None) -> int:
    """Le contexte du moteur EN MARCHE : des préférences changées ne s'appliquent qu'à son redémarrage."""
    return contexte_de(await props(m or await choisir()))


async def compter_tokens(texte: str, m: Moteur | None = None) -> int:
    m = m or await choisir()
    async with m.client(20) as c:
        r = await c.post("/tokenize", json={"content": texte})
        r.raise_for_status()
    return len(r.json()["tokens"])


async def etat() -> dict:
    """Résumé sans secret. `choisi` : moteur retenu ; `actif` : le moteur qui répond réellement
    (None si le moteur retenu ne répond pas). Ne lève jamais."""
    force = reglages.lire_prefs()["moteur"]["force"]
    url, cle = _url_distante(), _lire_cle()
    distant = _distant()
    statut = await _statut_distant(distant) if distant else None
    local_pret = await _sonde(_local(), 2)
    if force == "local" or (force == "auto" and statut not in ("pret", "endormi")):
        choisi, actif = "local", ("local" if local_pret else None)
    elif force == "distant" and distant is None:
        choisi, actif = None, None
    else:
        choisi, actif = "distant", ("distant" if statut == "pret" else None)
    return {"force": force, "choisi": choisi, "actif": actif,
            "local": {"pret": local_pret},
            "distant": {"declare": bool(url), "configure": bool(url and cle), "statut": statut,
                        "joignable": statut in ("pret", "endormi")}}


routeur = APIRouter(prefix="")


@routeur.get("/moteur", dependencies=[Depends(require_jwt)])
async def get_moteur():
    return await etat()


@routeur.post("/moteur/{choix}", dependencies=[Depends(require_jwt)])
async def post_moteur(choix: Literal["local", "distant", "auto"]):
    prefs = reglages.valider({"moteur": {"force": choix}})
    reglages.ecrire_prefs(prefs)
    return await etat()
