# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: WebOS — délégation d'accès pour les cartes
CyberMind — https://cybermind.fr

CE QUE CE MODULE REFUSE DE FAIRE, D'ABORD.

Il ne demande jamais de mot de passe. Une carte vit dans un cadre : n'importe
quelle page encadrée peut en dessiner un identique, et la personne qui regarde
n'a aucun moyen de vérifier qui demande. Un champ mot de passe dans une carte,
c'est un formulaire de hameçonnage avec notre logo dessus.

Il ne capture ni ne rejoue de témoin de session. Le registre RGPD du pare-feu
ne garde qu'une empreinte, et c'est ce qui le rend inoffensif : le jour où il
garderait des valeurs rejouables, il deviendrait la cible la plus rentable de
la box — un seul fichier, toutes les sessions.

CE QU'IL FAIT À LA PLACE.

Une carte sans accès dépose une DEMANDE. La demande attend dans la console
d'administration — hors du cadre, en pleine page, là où la barre d'adresse est
visible et où l'on peut donc savoir à qui l'on parle. L'opérateur valide, et
c'est seulement alors qu'un flux de délégation démarre.

Pour Nextcloud, ce flux existe et il est fait pour ça : le Login Flow v2. La
personne approuve DANS Nextcloud, sur sa vraie page ; nous recevons un mot de
passe d'application — pas le sien — révocable depuis Nextcloud sans nous
demander notre avis.

Pour les services sans flux de délégation (Roundcube, Dovecot), l'identifiant
dédié est saisi dans la console d'administration. Le secret transite alors une
fois, vers une page authentifiée que l'on a choisi d'ouvrir — et non depuis une
vignette anonyme. C'est la différence entre confier une clé et la laisser sur
le paillasson.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

# 0700 : le dossier lui-même ne se liste pas. Un secret dont on connaît
# l'existence est déjà à moitié trouvé.
RACINE = Path(os.environ.get("SECUBOX_WEBOS_ACCES", "/etc/secubox/secrets/webos-acces"))
DEMANDES = RACINE / "demandes.json"

# Liste FERMÉE. Une demande porte un nom de service : sans cette liste, elle
# porterait n'importe quoi, et l'on écrirait des fichiers dont le nom vient de
# l'extérieur.
SERVICES: dict[str, dict[str, str]] = {
    "nextcloud": {"nom": "Cloud", "hote": "nc.gk2.secubox.in", "flux": "nextcloud"},
    "mail": {"nom": "Mail", "hote": "webmail.gk2.secubox.in", "flux": "manuel"},
}

# Au-delà, ce n'est plus une file d'attente mais un déni de service : la
# demande est publique par nature — une carte doit pouvoir la déposer — donc
# elle doit être bornée.
MAX_DEMANDES = 20


def _assure() -> None:
    RACINE.mkdir(parents=True, exist_ok=True)
    os.chmod(RACINE, 0o700)


def _lit(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _ecrit(p: Path, d: Any, mode: int = 0o600) -> None:
    _assure()
    # On écrit à côté puis on remplace : une coupure au milieu d'une écriture
    # laisserait sinon un fichier de secret tronqué, donc inutilisable ET
    # illisible à réparer.
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(p)


def _fichier(svc: str) -> Path:
    return RACINE / (svc + ".json")


def a_acces(svc: str) -> bool:
    """Un accès existe-t-il pour ce service ? On ne rend JAMAIS le secret."""
    if svc not in SERVICES:
        return False
    d = _lit(_fichier(svc))
    return bool(d and d.get("secret"))


def demandes() -> list[dict]:
    return _lit(DEMANDES) or []


def etat(svc: str) -> dict:
    """Ce qu'une CARTE a le droit de savoir : y a-t-il un accès, et une demande
    est-elle déjà en attente. Rien d'autre — surtout pas le secret."""
    en_attente = any(d.get("svc") == svc for d in demandes())
    return {"svc": svc, "acces": a_acces(svc), "demande": en_attente,
            "nom": SERVICES.get(svc, {}).get("nom", svc)}


def depose(svc: str, origine: str = "") -> dict:
    """Déposer une demande. Publique — une carte doit pouvoir le faire — donc
    elle ne fait RIEN d'autre qu'inscrire une ligne dans une file bornée."""
    if svc not in SERVICES:
        return {"ok": False, "detail": "service inconnu"}
    if a_acces(svc):
        return {"ok": True, "detail": "acces deja accorde"}
    l = demandes()
    if any(d.get("svc") == svc for d in l):
        return {"ok": True, "detail": "demande deja en attente"}
    if len(l) >= MAX_DEMANDES:
        return {"ok": False, "detail": "file pleine"}
    l.append({"svc": svc, "nom": SERVICES[svc]["nom"], "quand": int(time.time()),
              "origine": origine[:120]})
    _ecrit(DEMANDES, l, 0o600)
    return {"ok": True, "detail": "demande deposee"}


def retire(svc: str) -> None:
    _ecrit(DEMANDES, [d for d in demandes() if d.get("svc") != svc], 0o600)


def revoque(svc: str) -> dict:
    """Oublier l'accès de notre côté.

    ON NE PRÉTEND PAS RÉVOQUER CHEZ L'AUTRE. Le mot de passe d'application
    reste valide dans Nextcloud tant que personne ne l'y supprime : le dire
    est plus honnête que de laisser croire à une révocation complète.
    """
    f = _fichier(svc)
    try:
        f.unlink()
    except FileNotFoundError:
        pass
    retire(svc)
    return {"ok": True, "detail": "oublie ici ; a revoquer aussi dans le service"}


# ── Nextcloud Login Flow v2 ─────────────────────────────────────────────────
#
# Le mot de passe n'entre JAMAIS ici. On demande une URL, l'opérateur
# l'ouvre, la personne approuve dans Nextcloud, et l'on récupère un mot de
# passe d'APPLICATION en interrogeant le jeton de scrutation.

async def flux_demarre(svc: str) -> dict:
    c = SERVICES.get(svc)
    if not c or c["flux"] != "nextcloud":
        return {"ok": False, "detail": "pas de flux de delegation pour ce service"}
    url = "https://%s/index.php/login/v2" % c["hote"]
    try:
        async with httpx.AsyncClient(verify=False, timeout=12) as cli:
            r = await cli.post(url, headers={"User-Agent": "SecuBox WebOS"})
            r.raise_for_status()
            d = r.json()
    except (httpx.HTTPError, ValueError) as e:
        return {"ok": False, "detail": "flux indisponible : %s" % type(e).__name__}
    # Le jeton de scrutation est un secret de courte vie : il vaut le mot de
    # passe d'application tant que personne ne l'a consommé.
    _ecrit(RACINE / (svc + ".flux.json"),
           {"poll": d.get("poll"), "quand": int(time.time())}, 0o600)
    return {"ok": True, "login": d.get("login")}


async def flux_sonde(svc: str) -> dict:
    f = _lit(RACINE / (svc + ".flux.json"))
    if not f or not f.get("poll"):
        return {"ok": False, "detail": "aucun flux en cours"}
    # Dix minutes : au-delà, on ne sait plus si l'approbation a eu lieu, et
    # garder un jeton vivant sans savoir pourquoi est une dette.
    if int(time.time()) - int(f.get("quand", 0)) > 600:
        (RACINE / (svc + ".flux.json")).unlink(missing_ok=True)
        return {"ok": False, "detail": "flux expire"}
    p = f["poll"]
    try:
        async with httpx.AsyncClient(verify=False, timeout=12) as cli:
            r = await cli.post(p["endpoint"], data={"token": p["token"]})
    except httpx.HTTPError as e:
        return {"ok": False, "detail": "injoignable : %s" % type(e).__name__}
    # 404 = pas encore approuvé. Ce n'est pas une erreur, c'est de l'attente.
    if r.status_code == 404:
        return {"ok": False, "attente": True, "detail": "en attente d'approbation"}
    try:
        d = r.json()
    except ValueError:
        return {"ok": False, "detail": "reponse illisible"}
    if not d.get("appPassword"):
        return {"ok": False, "detail": "pas de mot de passe d'application rendu"}
    _ecrit(_fichier(svc), {
        "svc": svc, "serveur": d.get("server"), "compte": d.get("loginName"),
        "secret": d["appPassword"], "cree": int(time.time()), "voie": "login-flow-v2",
    }, 0o600)
    (RACINE / (svc + ".flux.json")).unlink(missing_ok=True)
    retire(svc)
    return {"ok": True, "compte": d.get("loginName")}


def pose_manuel(svc: str, compte: str, secret: str) -> dict:
    """Identifiant dédié, saisi dans la console — pour les services sans flux.

    LE SECRET NE PASSE PAS PAR UNE CARTE : cette fonction n'est appelée que
    depuis une route protégée par jeton, c'est-à-dire depuis une page que l'on
    a authentifiée.
    """
    if svc not in SERVICES:
        return {"ok": False, "detail": "service inconnu"}
    if not compte or not secret:
        return {"ok": False, "detail": "compte et secret requis"}
    _ecrit(_fichier(svc), {"svc": svc, "compte": compte, "secret": secret,
                           "cree": int(time.time()), "voie": "manuel"}, 0o600)
    retire(svc)
    return {"ok": True, "compte": compte}
