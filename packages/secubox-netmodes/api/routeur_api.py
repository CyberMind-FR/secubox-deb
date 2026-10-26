# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Routes du mode routeur durable (#3189) : tout passe par netmodesctl (root, sudo -n), jamais par netplan.

Routes `def` (pool de threads) : elles appellent subprocess. L'acteur est le `sub` du jeton vérifié.
#3190 : appliquer et retour partent en tâche de fond (202, une bascule peut dépasser le délai d'HAProxy) et leur
dernier résultat se lit sur /routeur/derniere ; /routeur/etat sert au lecteur anonyme une copie expurgée, en cache 5 s."""
from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from ipaddress import IPv4Interface, IPv6Address, ip_address
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from secubox_core.auth import adresse_client, require_jwt, require_lecture
from secubox_core.logger import get_logger

from .routeur_config import ErreurConfig, depuis_dict
from .routeur_rendu import rendre

CTL = "/usr/sbin/netmodesctl"
DELAI_CTL = 150                                 # le contrôleur peut passer 120 s par commande
DELAI_ETAT = 30                                 # routeur-etat : quatre lectures brèves
# appliquer et retour en tâche de fond : au-delà du pire cas du contrôleur (deux relances d'Unbound de 900 s au plus,
# bascule puis retour) ; un délai plus court déclarerait en échec une bascule lente qui aboutit
DELAI_FOND = 2400
ACTEUR_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
CLES_CONFIG = ("adresse", "dhcp_debut", "dhcp_fin", "bail", "ports")      # #3190 : plus `wan`, le contrôleur garde eth2
REFUS_WAN = "le WAN ne se configure pas ici : il reste eth2, jamais relancé à distance (clé « wan » refusée)"
MODELES = (Path("/proc/device-tree/model"), Path("/sys/firmware/devicetree/base/model"))
AVERTISSEMENT = ("Vous appliquez depuis le LAN actuel : vous perdrez la connexion ; "
                 "confirmez depuis la nouvelle adresse sous 3 minutes.")
TTL_ETAT = 5.0
# Lecteur anonyme (mode tableau de bord, sans `sub`) : liste blanche, jamais l'acteur ni le nom de la sauvegarde
CLES_ANONYMES = ("etat", "depuis", "erreur", "config", "minuteur_actif", "echeance", "bascule_en_cours", "dhcp_actif",
                 "adresses_pont", "ports_coupes")
_DERNIERE_VIDE = {"verbe": None, "code": None, "sortie": None, "fini": True, "debut": None, "fin": None}

log = get_logger("netmodes")
router = APIRouter(prefix="/routeur")

_monotone = time.monotonic                      # horloge du cache (remplacée en test)
_cache_anonyme: dict[str, Any] = {}
_verrou_cache = threading.Lock()
_derniere: dict[str, Any] = dict(_DERNIERE_VIDE)
_verrou_derniere = threading.Lock()
_fil: threading.Thread | None = None


def est_mochabin() -> bool:
    """Même test que detect_board : modèle du device tree. Fermé par défaut (#3190) : aucun modèle lisible ⇒ vrai, les
    anciens chemins netplan (qui réécriraient tout netplan et relanceraient le WAN mvpp2) restent refusés."""
    for chemin in MODELES:
        try:
            modele = chemin.read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        return any(m in modele for m in ("MOCHAbin", "mochabin", "7040"))
    return True


def _acteur(user: Any) -> str:
    sub = str(user.get("sub") or "") if isinstance(user, dict) else ""
    if not ACTEUR_RE.fullmatch(sub):
        raise HTTPException(400, "identité de l'administrateur invalide")
    return sub


def _anonyme(user: Any) -> bool:
    return not (isinstance(user, dict) and user.get("sub"))


def _ctl(verbe: str, *args: str, entree: str | None = None, delai: float = DELAI_CTL) -> dict:
    """argv exact du sudoers : verbe, puis ses arguments déjà validés (aucun pour routeur-etat ; l'acteur ; le port et
    l'acteur pour les verbes de port)."""
    argv = ["sudo", "-n", CTL, verbe, *args]
    try:
        r = subprocess.run(argv, input=entree, capture_output=True,
                           text=True, timeout=delai, check=False)
    except subprocess.TimeoutExpired:
        raise HTTPException(502, "le contrôleur réseau n'a pas répondu à temps")
    except OSError as e:
        raise HTTPException(502, f"contrôleur réseau injoignable : {e}")
    try:
        sortie = json.loads(r.stdout)
        if not isinstance(sortie, dict):
            raise ValueError
    except ValueError:
        raise HTTPException(502, "réponse illisible du contrôleur réseau")
    if r.returncode == 0:
        return sortie
    msg = str(sortie.get("erreur") or "échec du contrôleur réseau")
    if r.returncode == 3:
        raise HTTPException(409, msg)
    if r.returncode == 4:
        raise HTTPException(409, "une application est déjà en cours")
    if r.returncode == 2:
        raise HTTPException(400, msg)
    raise HTTPException(502, msg)


def _config(corps: dict) -> dict:
    if not isinstance(corps, dict):
        raise HTTPException(400, "corps JSON attendu")
    if "wan" in corps:
        raise HTTPException(400, REFUS_WAN)
    return {k: corps[k] for k in CLES_CONFIG if k in corps}


def _valider(cfg: dict):
    try:
        return depuis_dict(cfg)
    except ErreurConfig as e:
        raise HTTPException(400, str(e))


def adresses_client(request: Request) -> list:
    """Adresses du poste, lues : X-Real-IP (posé par nginx) et celle que retient secubox_core (droite de
    X-Forwarded-For, sauts locaux écartés, sinon request.client.host). Toutes comptent : un avertissement ou un refus de
    trop vaut mieux qu'un accès coupé. IPv4 dans IPv6 ramenée à IPv4 ; illisible : écartée."""
    vues = []
    for brute in (request.headers.get("x-real-ip", ""), adresse_client(request)):
        try:
            ip = ip_address(brute.strip())
        except ValueError:
            continue
        if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip not in vues:
            vues.append(ip)
    return vues


# --- dernier résultat d'une bascule en tâche de fond ---------------------------------------------------------------------

def _maintenant() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _reinitialiser() -> None:
    """Remet le dernier résultat et le cache anonyme à vide (tests)."""
    global _fil
    with _verrou_derniere:
        _derniere.clear()
        _derniere.update(_DERNIERE_VIDE)
        _fil = None
    with _verrou_cache:
        _cache_anonyme.clear()


def bascule_lancee() -> bool:
    """Une bascule lancée par cette API est-elle encore en cours ?"""
    with _verrou_derniere:
        return _derniere["verbe"] is not None and not _derniere["fini"]


def _en_fond(verbe: str, acteur: str, entree: str | None) -> None:
    try:
        code, sortie = 200, _ctl(verbe, acteur, entree=entree, delai=DELAI_FOND)
    except HTTPException as e:
        code, sortie = e.status_code, {"erreur": e.detail}
    except Exception as e:  # noqa: BLE001 — filet : le dernier résultat ne reste jamais « en cours »
        log.exception("%s : échec inattendu du fil d'arrière-plan", verbe)
        code, sortie = 500, {"erreur": f"échec inattendu : {e.__class__.__name__}"}
    if code != 200:
        log.warning("%s par %s : %s (%s)", verbe, acteur, sortie["erreur"], code)
    with _verrou_derniere:
        _derniere.update(code=code, sortie=sortie, fini=True, fin=_maintenant())


def _lancer(verbe: str, acteur: str, entree: str | None = None) -> dict:
    """Lance le verbe dans un fil d'arrière-plan (le contrôleur survit à un redémarrage de l'API : KillMode=process) ;
    une seule bascule à la fois, de l'API à la fin du fil."""
    global _fil
    with _verrou_derniere:
        if _derniere["verbe"] is not None and not _derniere["fini"]:
            raise HTTPException(409, "une bascule est déjà en cours")
        fil = threading.Thread(target=_en_fond, args=(verbe, acteur, entree), name=f"netmodes-{verbe}", daemon=True)
        _derniere.update(verbe=verbe, code=None, sortie=None, fini=False, debut=_maintenant(), fin=None)
        try:
            fil.start()
        except RuntimeError as e:
            _derniere.update(code=503, sortie={"erreur": "fil d'arrière-plan impossible à lancer"}, fini=True,
                             fin=_maintenant())
            raise HTTPException(503, "fil d'arrière-plan impossible à lancer : rien n'a été appliqué") from e
        _fil = fil
    log.info("%s lancé en tâche de fond par %s", verbe, acteur)
    return {"lancee": True}


# --- état ------------------------------------------------------------------------------------------------------------------

def _etat_anonyme() -> dict:
    """Copie expurgée (CLES_ANONYMES), au plus un sudo par TTL_ETAT, panne comprise ; jamais servie à un
    administrateur, qui n'est jamais servi depuis ce cache."""
    with _verrou_cache:
        t = _cache_anonyme.get("t")
        if t is None or _monotone() - t >= TTL_ETAT:
            try:
                valeur: dict | HTTPException = {k: v for k, v in _ctl("routeur-etat", delai=DELAI_ETAT).items()
                                                 if k in CLES_ANONYMES}
            except HTTPException as e:
                valeur = e
            _cache_anonyme.update(t=_monotone(), valeur=valeur)
        valeur = _cache_anonyme["valeur"]
    if isinstance(valeur, HTTPException):
        raise HTTPException(valeur.status_code, valeur.detail)
    return dict(valeur)


@router.get("/etat")
def etat(user=Depends(require_lecture)):
    if _anonyme(user):                              # lecteur du LAN sans jeton : ni acteur, ni un sudo par requête
        return _etat_anonyme()
    return _ctl("routeur-etat", delai=DELAI_ETAT)


@router.get("/derniere")
def derniere(user=Depends(require_jwt)):
    with _verrou_derniere:
        return dict(_derniere)


# --- aperçu, application, confirmation, retour ---------------------------------------------------------------------------

def _avertissement(request: Request, nouveau) -> str | None:
    """Le poste est dans le réseau actuel de br-lan et le réseau demandé en diffère : il perdra la connexion."""
    try:
        actuel = _ctl("routeur-etat", delai=DELAI_ETAT)
    except HTTPException as e:                      # l'avertissement est facultatif : l'aperçu reste servi
        log.warning("routeur-etat indisponible, avertissement omis : %s", e.detail)
        return None
    try:
        reseaux = [IPv4Interface(a).network for a in actuel.get("adresses_pont") or []]
    except ValueError:
        return None
    if nouveau in reseaux:
        return None
    if any(ip in r for ip in adresses_client(request) for r in reseaux):
        return AVERTISSEMENT
    return None


@router.post("/apercu")
def apercu(corps: dict, request: Request, user=Depends(require_jwt)):
    cfg = _valider(_config(corps))                  # 400 avant tout sudo
    res: dict[str, Any] = {"fichiers": rendre(cfg)}
    avertissement = _avertissement(request, cfg.adresse.network)
    if avertissement:
        res["avertissement"] = avertissement
    return res


@router.post("/appliquer", status_code=202)
def appliquer(corps: dict, user=Depends(require_jwt)):
    if not isinstance(corps, dict) or corps.get("confirmer") != "routeur":
        raise HTTPException(400, 'confirmation requise : "confirmer": "routeur"')
    acteur = _acteur(user)
    cfg = _config(corps)
    _valider(cfg)                                   # tout refus local avant le lancement
    return _lancer("routeur-appliquer", acteur, json.dumps(cfg))


@router.post("/confirmer")
def confirmer(user=Depends(require_jwt)):
    return _ctl("routeur-confirmer", _acteur(user))


@router.post("/retour", status_code=202)
def retour(corps: dict, user=Depends(require_jwt)):
    if not isinstance(corps, dict) or corps.get("confirmer") != "retour":
        raise HTTPException(400, 'confirmation requise : "confirmer": "retour"')
    return _lancer("routeur-retour", _acteur(user))
