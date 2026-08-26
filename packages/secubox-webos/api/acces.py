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

# UN AVATAR RASSEMBLE PLUSIEURS IDENTITES, ET C'EST LA CLE DU RANGEMENT.
#
# Les accès sont donc classés par PERSONNE, pas par service : /<qui>/<svc>.json.
# Deux habitants du même foyer ont chacun leur Nextcloud, et l'avatar de l'un ne
# rejoue pas l'identité de l'autre.
#
# `qui` VIENT DU JETON, JAMAIS DU CLIENT. Un profil annoncé par la page serait
# déclaratif : n'importe qui écrirait « je suis gandalf » et rejouerait ses
# accès. Le nom de dossier est donc assaini — un identifiant venu d'un jeton
# reste un identifiant venu du réseau.
_QUI_OK = "abcdefghijklmnopqrstuvwxyz0123456789._-"


def qui_sur(sub: str) -> str:
    q = "".join(c for c in str(sub or "").lower() if c in _QUI_OK)[:64]
    return q or "_"

# Liste FERMÉE. Une demande porte un nom de service : sans cette liste, elle
# porterait n'importe quoi, et l'on écrirait des fichiers dont le nom vient de
# l'extérieur.
SERVICES: dict[str, dict[str, str]] = {
    "nextcloud": {"nom": "Cloud", "hote": "nc.gk2.secubox.in", "flux": "nextcloud"},
    "mail": {"nom": "Mail", "hote": "webmail.gk2.secubox.in", "flux": "manuel"},
    "mastodon": {"nom": "Social", "hote": "social.gk2.secubox.in", "flux": "mastodon"},
    "photoprism": {"nom": "Photos", "hote": "photoprism.gk2.secubox.in", "flux": "manuel"},
}

# Où Mastodon renvoie après approbation. Un `urn:…:oob` obligerait à recopier un
# code à la main : recopier un secret est une occasion de le perdre, et une
# invitation à le taper ailleurs.
RETOUR = os.environ.get("SECUBOX_WEBOS_RETOUR", "https://hall.gk2.net/acces.html")

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
    p.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(p.parent, 0o700)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(p)


def _fichier(qui: str, svc: str) -> Path:
    return RACINE / qui / (svc + ".json")


def a_acces(qui: str, svc: str) -> bool:
    """Un accès existe-t-il pour CETTE personne et ce service ?

    ON NE REND JAMAIS LE SECRET — cette fonction répond par oui ou par non, et
    c'est tout ce qu'une carte a besoin de savoir.
    """
    if svc not in SERVICES:
        return False
    d = _lit(_fichier(qui, svc))
    return bool(d and d.get("secret"))


def secret_de(qui: str, svc: str) -> dict | None:
    """Le secret, pour un usage SERVEUR uniquement.

    Aucune route ne rend ce que cette fonction retourne. Elle existe pour que
    les cartes puissent LIRE le service au nom de la personne — jamais pour
    qu'un client reçoive la clé.
    """
    return _lit(_fichier(qui, svc))


def demandes() -> list[dict]:
    return _lit(DEMANDES) or []


def etat(qui: str, svc: str) -> dict:
    """Ce qu'une CARTE a le droit de savoir : y a-t-il un accès pour cette
    personne, et une demande est-elle déjà en attente. Rien d'autre."""
    en_attente = any(d.get("svc") == svc and d.get("qui") == qui for d in demandes())
    return {"svc": svc, "acces": a_acces(qui, svc), "demande": en_attente,
            "nom": SERVICES.get(svc, {}).get("nom", svc)}


def depose(qui: str, svc: str, origine: str = "") -> dict:
    """Déposer une demande. Publique — une carte doit pouvoir le faire — donc
    elle ne fait RIEN d'autre qu'inscrire une ligne dans une file bornée."""
    if svc not in SERVICES:
        return {"ok": False, "detail": "service inconnu"}
    if a_acces(qui, svc):
        return {"ok": True, "detail": "acces deja accorde"}
    l = demandes()
    if any(d.get("svc") == svc and d.get("qui") == qui for d in l):
        return {"ok": True, "detail": "demande deja en attente"}
    if len(l) >= MAX_DEMANDES:
        return {"ok": False, "detail": "file pleine"}
    l.append({"svc": svc, "qui": qui, "nom": SERVICES[svc]["nom"],
              "quand": int(time.time()), "origine": origine[:120]})
    _ecrit(DEMANDES, l, 0o600)
    return {"ok": True, "detail": "demande deposee"}


def retire(qui: str, svc: str) -> None:
    _ecrit(DEMANDES, [d for d in demandes()
                      if not (d.get("svc") == svc and d.get("qui") == qui)], 0o600)


def revoque(qui: str, svc: str) -> dict:
    """Oublier l'accès de notre côté.

    ON NE PRÉTEND PAS RÉVOQUER CHEZ L'AUTRE. Le mot de passe d'application
    reste valide dans Nextcloud tant que personne ne l'y supprime : le dire
    est plus honnête que de laisser croire à une révocation complète.
    """
    f = _fichier(qui, svc)
    try:
        f.unlink()
    except FileNotFoundError:
        pass
    retire(qui, svc)
    return {"ok": True, "detail": "oublie ici ; a revoquer aussi dans le service"}


# ── Nextcloud Login Flow v2 ─────────────────────────────────────────────────
#
# Le mot de passe n'entre JAMAIS ici. On demande une URL, l'opérateur
# l'ouvre, la personne approuve dans Nextcloud, et l'on récupère un mot de
# passe d'APPLICATION en interrogeant le jeton de scrutation.

async def flux_demarre(qui: str, svc: str) -> dict:
    c = SERVICES.get(svc)
    if not c:
        return {"ok": False, "detail": "service inconnu"}
    if c["flux"] == "mastodon":
        return await flux_mastodon(qui, svc)
    if c["flux"] != "nextcloud":
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
    _ecrit(RACINE / qui / (svc + ".flux.json"),
           {"poll": d.get("poll"), "quand": int(time.time())}, 0o600)
    return {"ok": True, "login": d.get("login")}


async def flux_sonde(qui: str, svc: str) -> dict:
    f = _lit(RACINE / qui / (svc + ".flux.json"))
    if not f or not f.get("poll"):
        return {"ok": False, "detail": "aucun flux en cours"}
    # Dix minutes : au-delà, on ne sait plus si l'approbation a eu lieu, et
    # garder un jeton vivant sans savoir pourquoi est une dette.
    if int(time.time()) - int(f.get("quand", 0)) > 600:
        (RACINE / qui / (svc + ".flux.json")).unlink(missing_ok=True)
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
    _ecrit(_fichier(qui, svc), {
        "svc": svc, "qui": qui, "serveur": d.get("server"), "compte": d.get("loginName"),
        "secret": d["appPassword"], "cree": int(time.time()), "voie": "login-flow-v2",
    }, 0o600)
    (RACINE / qui / (svc + ".flux.json")).unlink(missing_ok=True)
    retire(qui, svc)
    return {"ok": True, "compte": d.get("loginName")}


# ── Mastodon : OAuth2 ───────────────────────────────────────────────────────
#
# L'ENREGISTREMENT DE L'APPLICATION EST UN ARTEFACT DE BOX, pas de personne :
# `client_id` et `client_secret` identifient SecuBox auprès de Mastodon, et
# valent pour tous les habitants. On les range donc à part, une seule fois —
# réenregistrer à chaque demande créerait une application de plus à chaque clic
# dans l'administration de Mastodon.

async def _app_mastodon(hote: str) -> dict | None:
    f = RACINE / ("app-" + hote + ".json")
    d = _lit(f)
    if d and d.get("client_id"):
        return d
    try:
        async with httpx.AsyncClient(verify=False, timeout=12) as cli:
            r = await cli.post("https://%s/api/v1/apps" % hote, data={
                "client_name": "SecuBox WebOS",
                "redirect_uris": RETOUR,
                "scopes": "read",
                "website": "https://cybermind.fr",
            })
            r.raise_for_status()
            d = r.json()
    except (httpx.HTTPError, ValueError):
        return None
    if not d.get("client_id"):
        return None
    _ecrit(f, {"client_id": d["client_id"], "client_secret": d.get("client_secret"),
               "hote": hote, "cree": int(time.time())}, 0o600)
    return d


async def flux_mastodon(qui: str, svc: str) -> dict:
    c = SERVICES[svc]
    app = await _app_mastodon(c["hote"])
    if not app:
        return {"ok": False, "detail": "enregistrement de l'application refuse"}
    from urllib.parse import urlencode
    q = urlencode({
        "client_id": app["client_id"], "redirect_uri": RETOUR,
        "response_type": "code", "scope": "read",
        # `state` porte le service ET la personne : au retour, la page doit
        # savoir quoi finir, et le serveur pour QUI. Sans lui, un retour
        # d'autorisation serait anonyme.
        "state": svc + ":" + qui,
    })
    return {"ok": True, "login": "https://%s/oauth/authorize?%s" % (c["hote"], q),
            "retour": True}


async def flux_echange(qui: str, svc: str, code: str) -> dict:
    """Echanger le code d'autorisation contre un jeton.

    LE CODE EST A USAGE UNIQUE et de courte vie : il ne vaut rien une fois
    consomme, ce qui est precisement pourquoi Mastodon le fait transiter par
    l'URL de retour plutot que de nous confier un mot de passe.
    """
    c = SERVICES.get(svc)
    if not c or c["flux"] != "mastodon":
        return {"ok": False, "detail": "pas de flux OAuth pour ce service"}
    app = _lit(RACINE / ("app-" + c["hote"] + ".json"))
    if not app:
        return {"ok": False, "detail": "application non enregistree"}
    try:
        async with httpx.AsyncClient(verify=False, timeout=12) as cli:
            r = await cli.post("https://%s/oauth/token" % c["hote"], data={
                "grant_type": "authorization_code", "code": code,
                "client_id": app["client_id"], "client_secret": app.get("client_secret"),
                "redirect_uri": RETOUR, "scope": "read",
            })
            r.raise_for_status()
            d = r.json()
    except (httpx.HTTPError, ValueError) as e:
        return {"ok": False, "detail": "echange refuse : %s" % type(e).__name__}
    jeton = d.get("access_token")
    if not jeton:
        return {"ok": False, "detail": "pas de jeton rendu"}
    # On demande QUI l'on est devenu : un acces qu'on ne sait pas nommer ne se
    # revoque pas en connaissance de cause.
    compte = ""
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as cli:
            v = await cli.get("https://%s/api/v1/accounts/verify_credentials" % c["hote"],
                              headers={"Authorization": "Bearer " + jeton})
            if v.status_code == 200:
                compte = (v.json() or {}).get("acct") or ""
    except (httpx.HTTPError, ValueError):
        compte = ""
    _ecrit(_fichier(qui, svc), {"svc": svc, "qui": qui, "compte": compte,
                                "secret": jeton, "cree": int(time.time()),
                                "voie": "oauth2"}, 0o600)
    retire(qui, svc)
    return {"ok": True, "compte": compte}


def pose_manuel(qui: str, svc: str, compte: str, secret: str) -> dict:
    """Identifiant dédié, saisi dans la console — pour les services sans flux.

    LE SECRET NE PASSE PAS PAR UNE CARTE : cette fonction n'est appelée que
    depuis une route protégée par jeton, c'est-à-dire depuis une page que l'on
    a authentifiée.
    """
    if svc not in SERVICES:
        return {"ok": False, "detail": "service inconnu"}
    if not compte or not secret:
        return {"ok": False, "detail": "compte et secret requis"}
    _ecrit(_fichier(qui, svc), {"svc": svc, "qui": qui, "compte": compte,
                                "secret": secret, "cree": int(time.time()),
                                "voie": "manuel"}, 0o600)
    retire(qui, svc)
    return {"ok": True, "compte": compte}
