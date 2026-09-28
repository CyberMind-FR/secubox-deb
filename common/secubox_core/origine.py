# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: GARDE D'ORIGINE des écritures authentifiées par cookie (#1607)
CyberMind — https://cybermind.fr

LE COOKIE DE SESSION VOYAGE TOUT SEUL. Il est posé sur le domaine parent
(SSO-lite, #400) et en SameSite=None sous TLS (cadres du Hall) : le navigateur
le joint à toute requête vers *.<domaine>, quelle que soit la page qui la
formule. Un jeton porteur (`Authorization: Bearer`), lui, n'est jamais joint
par le navigateur : seule une page qui le détient peut l'envoyer. La règle
ci-dessous ne concerne donc QUE les requêtes dont la session vient du cookie.

LA RÈGLE. Une méthode qui écrit (tout sauf GET, HEAD, OPTIONS), authentifiée
par le cookie, doit venir d'une page de la box :

  - en-tête `Origin` présent : son hôte est l'hôte de la requête, le domaine
    de la box, ou un sous-domaine de celui-ci. `Origin: null` ne désigne
    aucune page : refusé. Un hôte qui, sous le domaine, sert le contenu d'un
    AUTRE site (le relais de surf du BiB : surf-<site>.<domaine>) n'est pas
    une page de la box : refusé lui aussi. Un nom du domaine n'est admis
    qu'en https (port libre). Si le navigateur atteste
    `Sec-Fetch-Site: same-origin`, la requête est admise même quand un relais
    a réécrit Host (le concentrateur de l'agrégateur relaie vers localhost) ;
  - `Origin` absent : `Sec-Fetch-Site` vaut `same-origin` ou `none`, ou il
    est absent lui aussi — un client hors navigateur, qui ne porte pas de
    cookie ambiant. `same-site` est refusé : il couvre les autres box du
    même domaine enregistré (secubox.in).

TROIS MODES, `[securite] garde_origine` dans /etc/secubox/secubox.conf :

  - "journal"  : observe et consigne, ne bloque rien. DÉFAUT de cette
                 version — on relit les refus sur une box réelle avant
                 d'appliquer ;
  - "applique" : 403 « Origine refusée » ;
  - "inactif"  : ne regarde pas.

Une valeur inconnue vaut "applique" : une faute de frappe ne doit pas ouvrir
les écritures. `SECUBOX_GARDE_ORIGINE` surcharge, pour les tests et la mise au
point.

LA CONFIGURATION N'EST PAS RELUE À CHAQUE REQUÊTE. `get_config` garde le
fichier en mémoire au premier appel : changer de mode demande de redémarrer
les services, comme pour `[tableau_de_bord]`.

LE RELEVÉ. Le journal système d'une box chargée ne garde parfois que quelques
minutes : chaque observation est AUSSI ajoutée, en une ligne JSON, à
/var/log/secubox/garde-origine.log (`[securite] garde_origine_releve`, vide =
pas de relevé). Borné en taille, tourné par la règle logrotate commune de
/var/log/secubox/*.log. Un service qui ne peut pas y écrire (autre compte que
secubox ou root) garde la ligne du journal système : le relevé ne bloque
jamais une requête.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import HTTPException, status

from .config import get_config
from .logger import get_logger

log = get_logger("origine")

#: Méthodes qui ne modifient rien : jamais gardées.
METHODES_SURES = frozenset({"GET", "HEAD", "OPTIONS"})

MODES = ("journal", "applique", "inactif")
#: Le mode quand rien n'est configuré. On observe avant d'appliquer.
MODE_DEFAUT = "journal"
#: Le mode d'une valeur qu'on ne reconnaît pas : fermé.
MODE_INCONNU = "applique"

ENV_MODE = "SECUBOX_GARDE_ORIGINE"
ENV_RELEVE = "SECUBOX_GARDE_ORIGINE_RELEVE"
RELEVE_DEFAUT = "/var/log/secubox/garde-origine.log"
#: Au-delà, le relevé cesse d'être alimenté jusqu'à sa rotation : la carte SD
#: ne doit pas se remplir parce qu'une page insiste.
RELEVE_PLAFOND = 5 * 1024 * 1024

#: Valeurs de Sec-Fetch-Site admises quand Origin est absent.
SITES_ADMIS = frozenset({"same-origin", "none"})

#: Débuts de premier label des hôtes qui, sous le domaine de la box, servent
#: le contenu d'AUTRES sites : le relais de surf (secubox-surf, une origine
#: `surf-<site aplati>.<domaine>` par site relayé). Jamais admis.
#: `[securite] garde_origine_tiers` peut en AJOUTER, jamais en retirer.
PREFIXES_TIERS = ("surf-",)

_CHAMP_MAX = 200


def _section() -> dict:
    try:
        sec = get_config("securite")
    except (OSError, ValueError):
        # Config illisible : on retombe sur les défauts de cette version.
        return {}
    return sec if isinstance(sec, dict) else {"garde_origine": None}


def mode() -> str:
    """Le mode de la garde : "journal", "applique" ou "inactif"."""
    forcage = os.environ.get(ENV_MODE, "").strip()
    valeur: Any = forcage if forcage else _section().get("garde_origine", MODE_DEFAUT)
    if not isinstance(valeur, str):
        return MODE_INCONNU
    valeur = valeur.strip().lower()
    return valeur if valeur in MODES else MODE_INCONNU


def prefixes_tiers() -> tuple:
    """`PREFIXES_TIERS`, plus ceux que la configuration ajoute."""
    extra = _section().get("garde_origine_tiers", [])
    if isinstance(extra, str):
        extra = [extra]
    if not isinstance(extra, (list, tuple)):
        extra = []
    return PREFIXES_TIERS + tuple(x.strip().lower() for x in extra
                                  if isinstance(x, str) and x.strip())


def _chemin_releve() -> str:
    if ENV_RELEVE in os.environ:
        return os.environ[ENV_RELEVE].strip()
    valeur = _section().get("garde_origine_releve", RELEVE_DEFAUT)
    return valeur.strip() if isinstance(valeur, str) else RELEVE_DEFAUT


def hote_de(valeur: Optional[str]) -> str:
    """L'hôte d'un en-tête Host (« nom[:port] », « [v6]:port »), en minuscules.
    Chaîne vide s'il n'en désigne aucun."""
    if not valeur:
        return ""
    try:
        return (urlsplit("//" + valeur.strip()).hostname or "").lower()
    except ValueError:
        return ""


def _decoupe_origine(origin: str) -> tuple:
    """(schéma, hôte, port) d'un en-tête Origin ; ("", "", None) s'il ne
    désigne aucune page web (`null`, schéma inconnu, valeur mal formée)."""
    try:
        p = urlsplit(origin.strip())
        if p.scheme not in ("https", "http"):
            return ("", "", None)
        return (p.scheme, (p.hostname or "").lower(), p.port)
    except ValueError:
        return ("", "", None)


def hote_origine(origin: str) -> str:
    """L'hôte d'un en-tête Origin, ou "" s'il ne désigne aucune page web
    (`null`, schéma inconnu, valeur mal formée)."""
    return _decoupe_origine(origin)[1]


def _sous_domaine(h: str, domaine: str) -> bool:
    return bool(domaine) and (h == domaine or h.endswith("." + domaine))


def admise(origin: Optional[str], sec_fetch_site: Optional[str],
           hote: str, domaine: str, tiers: tuple = PREFIXES_TIERS) -> bool:
    """Le verdict, sans effet de bord. `hote` = hôte de la requête, `domaine`
    = domaine de la box sans point initial ("" s'il n'est pas configuré),
    `tiers` = débuts de premier label des hôtes qui servent un autre site."""
    site = (sec_fetch_site or "").strip().lower()
    if origin is not None and origin.strip():
        schema, h, _port = _decoupe_origine(origin)
        if not h:
            return False
        if h.split(".", 1)[0].startswith(tuple(tiers)):
            return False
        # Le navigateur atteste lui-même la même origine, en-tête qu'une page
        # ne peut pas poser : il fait foi quand un relais a réécrit Host
        # (concentrateur de l'agrégateur, qui relaie vers « localhost »).
        if site == "same-origin":
            return True
        sous_domaine = _sous_domaine(h, domaine)
        # Un nom du domaine de la box n'est servi qu'en TLS (certificat du
        # domaine) : une page en clair sous ce nom n'est pas l'une des nôtres.
        # Le port reste libre : le frontal d'administration LAN sert le même
        # certificat sur 9443.
        if sous_domaine and schema != "https":
            return False
        if hote and h == hote:
            return True
        return sous_domaine
    if not site:
        return True
    return site in SITES_ADMIS


def garde(request: Any, sub: Optional[str], domaine: str) -> None:
    """Applique la règle à une requête dont la session vient du COOKIE.

    Ne fait rien pour une méthode sûre, ni en mode "inactif". En "journal",
    consigne un refus sans bloquer ; en "applique", le consigne puis lève 403.
    """
    methode = str(getattr(request, "method", "") or "").upper()
    if methode in METHODES_SURES:
        return
    m = mode()
    if m == "inactif":
        return
    entetes = getattr(request, "headers", None) or {}
    origin = entetes.get("origin")
    site = entetes.get("sec-fetch-site")
    hote = hote_de(entetes.get("host"))
    if admise(origin, site, hote, domaine, prefixes_tiers()):
        return
    _consigne(m, methode, request, origin, site, hote, sub)
    if m == "applique":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Origine refusée")


# ── Relevé ────────────────────────────────────────────────────────────────

_UNITE: Optional[str] = None


def _unite() -> str:
    """Le service qui répond, lu une fois dans le cgroup du processus."""
    global _UNITE
    if _UNITE is None:
        nom = ""
        try:
            for ligne in Path("/proc/self/cgroup").read_text().splitlines():
                dernier = ligne.rsplit("/", 1)[-1]
                if dernier.endswith(".service"):
                    nom = dernier
                    break
        except OSError:
            pass
        _UNITE = nom or os.path.basename(sys.argv[0] if sys.argv else "") or "?"
    return _UNITE


def _borne(v: Any) -> Any:
    return v[:_CHAMP_MAX] if isinstance(v, str) else v


def _consigne(m: str, methode: str, request: Any, origin: Optional[str],
              site: Optional[str], hote: str, sub: Optional[str]) -> None:
    url = getattr(request, "url", None)
    # LE CHEMIN SEUL : la chaîne de requête peut porter un jeton.
    chemin = getattr(url, "path", "") if url is not None else ""
    doc = {
        "ts": int(time.time()),
        "garde": "origine",
        "mode": m,
        "verdict": "refuse" if m == "applique" else "observe",
        "unite": _unite(),
        "methode": methode,
        "chemin": _borne(chemin),
        "origin": _borne(origin),
        "sec_fetch_site": _borne(site),
        "hote": _borne(hote),
        "sub": _borne(sub),
    }
    ligne = json.dumps(doc, ensure_ascii=False)
    log.warning("garde_origine %s", ligne)
    _ajoute_releve(ligne)


def _ajoute_releve(ligne: str) -> None:
    """Une ligne au relevé. Jamais d'exception : le relevé est un témoin."""
    chemin = _chemin_releve()
    if not chemin:
        return
    try:
        fd = _ouvre_releve(chemin)
    except OSError:
        return
    try:
        st = os.fstat(fd)
        # Un fichier ordinaire, à un seul nom, et sous le plafond.
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > RELEVE_PLAFOND:
            return
        os.write(fd, (ligne + "\n").encode("utf-8"))
    except OSError:
        pass
    finally:
        os.close(fd)


def _ouvre_releve(chemin: str) -> int:
    drapeaux = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(chemin, drapeaux | os.O_CREAT | os.O_EXCL, 0o640)
    except FileExistsError:
        return os.open(chemin, drapeaux)
    # CRÉÉ PAR NOUS. Un service root qui ouvre le relevé le premier le rend au
    # propriétaire du répertoire (secubox) : sans cela, les services du compte
    # secubox ne pourraient plus y écrire jusqu'à la rotation.
    if os.geteuid() == 0:
        try:
            parent = os.stat(os.path.dirname(chemin) or ".")
            os.fchown(fd, parent.st_uid, parent.st_gid)
        except OSError:
            pass
    return fd
