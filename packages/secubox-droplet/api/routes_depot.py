# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Droplet — l'espace de dépôt (#1026)

CyberMind — https://cybermind.fr

Le module droplet PUBLIE des fichiers ; ces routes-ci en RECOIVENT. Publier
suppose un auteur authentifié qui choisit une adresse ; déposer suppose un
inconnu qui laisse quelque chose et s'en va. Les deux ne se ressemblent qu'en
surface, et la seconde est de très loin la plus exposée.

TROIS REGLES, AUCUNE NEGOCIABLE :

  1. RIEN DE CE QUI EST DEPOSE N'EST JAMAIS RESERVI. Les fichiers vivent hors
     de tout docroot et aucune route ne rend leur contenu. Un dépôt public
     qu'on peut relire est un hébergement anonyme gratuit — il sera trouvé, et
     il servira.
  2. LE NOM FOURNI NE TOUCHE JAMAIS UN CHEMIN. Le chemin vient d'un identifiant
     que NOUS choisissons ; le nom du déposant ne sert qu'à l'affichage.
  3. LE DEBIT EST BORNE PAR ORIGINE. Sans cela, un seul client remplit `/data`
     en une nuit, et la board tombe pour une raison qui n'a rien à voir avec la
     sécurité.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from fastapi import (APIRouter, BackgroundTasks, Depends, File, Form, HTTPException,
                     Request, UploadFile)
from fastapi.responses import JSONResponse
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Relatif d'abord : sous l'agregateur, seul le repertoire PARENT de api/ est
# sur sys.path, donc `import depot` en absolu n'y resout rien. En execution
# autonome, les deux marchent.
try:
    from . import alerte as _alerte  # type: ignore
    from .depot import (Depot, DepotRefuse, Limiteur, Recu, ecris_flux,  # type: ignore
                        identifiant, nom_affichable)
except ImportError:
    import alerte as _alerte  # type: ignore
    from depot import (Depot, DepotRefuse, Limiteur, Recu, ecris_flux,  # type: ignore
                       identifiant, nom_affichable)

log = logging.getLogger("droplet")
router = APIRouter()


def _conf() -> dict:
    return get_config("droplet") or {}


def _c(cle: str, defaut):
    v = _conf().get(cle, defaut)
    return defaut if v is None else v


def _reglages() -> dict:
    """Les réglages sont relus à CHAQUE dépôt, pas figés au démarrage.

    Un plafond qu'il faut redémarrer le service pour changer se change en
    pratique jamais — et c'est précisément le jour d'un abus qu'on veut
    pouvoir le baisser sans couper le service.
    """
    return {
        "actif": bool(_c("depot_actif", True)),
        "dossier": Path(_c("depots_dir", "/data/secubox/droplet")),
        "a": _c("alerte_a", "gk2@secubox.in"),
        "de": _c("alerte_de", "droplet@secubox.in"),
        "smtp_hote": _c("smtp_hote", "10.100.0.10"),
        "smtp_port": int(_c("smtp_port", 25)),
        # 2 Gio par fichier. PAS « sans limite » : la borne du COURRIER a été
        # levée parce qu'un refus à la porte y est pire que tout, mais un point
        # de dépôt public sans plafond est une invitation à remplir le disque
        # d'un inconnu. Les deux décisions n'ont pas le même sujet.
        "taille_max": int(_c("taille_max", 2 << 30)),
        "fichiers_max": int(_c("fichiers_max", 20)),
        # Au-delà, l'alerte porte le manifeste et le chemin, pas les octets.
        "joindre_max": int(_c("joindre_max", 100 << 20)),
        "quota_octets": int(_c("quota_octets_par_heure", 4 << 30)),
        "quota_depots": int(_c("quota_depots_par_heure", 30)),
    }


_limiteur: Limiteur | None = None


def _limite(r: dict) -> Limiteur:
    global _limiteur
    if _limiteur is None:
        _limiteur = Limiteur(r["quota_octets"], r["quota_depots"])
    else:
        _limiteur.octets_par_heure = r["quota_octets"]
        _limiteur.depots_par_heure = r["quota_depots"]
    return _limiteur


def origine(r: Request) -> str:
    """L'adresse du déposant, telle que la chaîne nous la transmet.

    `X-Forwarded-For` EST FALSIFIABLE PAR LE CLIENT, et c'est pourquoi son seul
    usage ici est de borner un débit et de renseigner une alerte. Aucune
    décision d'autorisation n'en dépend : qui le fait varier contourne le
    limiteur mais ne gagne aucun droit — il déplace un seau, il n'ouvre pas une
    porte.
    """
    xff = r.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()[:64]
    return (r.client.host if r.client else "inconnu")[:64]


@router.get("/depot/reglages")
async def reglages_publics():
    """Ce que le déposant a besoin de savoir AVANT d'envoyer.

    Découvrir un plafond en se le prenant après dix minutes de téléversement
    est la pire façon de l'apprendre. La page les lit et le dit d'avance.
    """
    r = _reglages()
    return {"actif": r["actif"], "taille_max": r["taille_max"],
            "fichiers_max": r["fichiers_max"]}


@router.post("/depot")
async def deposer(request: Request,
                  arriere_plan: BackgroundTasks,
                  fichiers: list[UploadFile] = File(...),
                  mot: str = Form("")):
    """Reçoit un dépôt. PUBLIC — c'est la raison d'être de cet espace."""
    r = _reglages()
    if not r["actif"]:
        raise HTTPException(503, "l'espace de dépôt est fermé")
    if not fichiers:
        raise HTTPException(400, "aucun fichier")
    if len(fichiers) > r["fichiers_max"]:
        raise HTTPException(400, f"au plus {r['fichiers_max']} fichiers par dépôt")

    ip = origine(request)
    # LE JETON EST PRIS AVANT L'ECRITURE, sur la taille annoncée. Le prendre
    # après reviendrait à écrire d'abord et compter ensuite — c'est-à-dire à
    # n'avoir aucune limite pour le premier dépôt venu.
    try:
        annonce = int(request.headers.get("content-length", 0))
    except ValueError:
        annonce = 0
    limiteur = _limite(r)
    try:
        limiteur.autorise(ip, annonce)
    except DepotRefuse as e:
        raise HTTPException(429, str(e))
    limiteur.oublie_les_vieux()

    ident = identifiant()
    dossier = r["dossier"] / ident
    d = Depot(identifiant=ident, recu_le=int(time.time()), origine=ip,
              dossier=dossier, mot=(mot or "")[:2000])

    try:
        dossier.mkdir(parents=True, exist_ok=False)
        os.chmod(dossier, 0o750)
        for i, f in enumerate(fichiers):
            nom = nom_affichable(f.filename or "", f"fichier-{i + 1}.bin")
            # LE CHEMIN VIENT DE L'INDICE, PAS DU NOM. Deux fichiers homonymes
            # dans un même dépôt ne s'écrasent donc pas, et aucun nom fourni ne
            # peut désigner autre chose que ce qu'on a décidé.
            cible = dossier / f"{i:02d}.bin"
            # HORS DE LA BOUCLE D'EVENEMENTS, IMPERATIVEMENT.
            #
            # Ces routes sont servies EN PROCESSUS par l'agregateur, qui porte
            # la centaine de modules de la board sur une seule boucle. Recopier
            # deux gigaoctets de facon synchrone y bloquerait TOUT — pas le
            # depot : la board entiere, qui repondrait 502 pendant la duree du
            # televersement. C'est le mode de panne connu de l'agregateur, et
            # il serait ici declenchable par n'importe quel inconnu.
            taille, empreinte = await asyncio.to_thread(
                ecris_flux, f.file, cible, r["taille_max"])
            d.fichiers.append(Recu(nom=nom, taille=taille, sha256=empreinte,
                                   chemin=cible))
    except DepotRefuse as e:
        _nettoie(dossier)
        limiteur.rembourse(ip, annonce)
        raise HTTPException(413, str(e))
    except OSError as e:
        log.error("dépôt %s : %s", ident, e)
        _nettoie(dossier)
        limiteur.rembourse(ip, annonce)
        raise HTTPException(500, "le dépôt n'a pas pu être écrit")

    await asyncio.to_thread(_ecris_manifeste, d)

    # LE DEPOT EST ACQUIS QUAND LES OCTETS SONT SUR LE DISQUE, PAS QUAND LE
    # COURRIER PART (#1030).
    #
    # L'alerte partait AVANT la reponse : sur un depot de 22 Mio, l'envoi SMTP
    # de la piece jointe pesait l'essentiel des 116 secondes mesurees. HAProxy
    # (30 s) et sbxwaf (10 s) abandonnaient bien avant, le deposant voyait un
    # 504 — et le serveur, lui, TERMINAIT le travail. Chaque essai deposait donc
    # a nouveau : trois depots et trois courriers de 30 Mio pour une seule
    # intention. Sur un point d'entree public, un delai mal regle devenait un
    # amplificateur du volume depose.
    #
    # On rend la main des que le fichier est ecrit et le manifeste pose. Le
    # courrier suit en tache de fond ; s'il echoue il est journalise, et le
    # manifeste reste a cote des octets — le depot, lui, a eu lieu.
    arriere_plan.add_task(
        _alerte_sans_bruit, d, de=r["de"], a=r["a"], hote=r["smtp_hote"],
        port=r["smtp_port"], plafond_joint=r["joindre_max"])

    return {"ok": True, "depot": ident, "taille": d.taille,
            "fichiers": [{"nom": f.nom, "taille": f.taille, "sha256": f.sha256}
                         for f in d.fichiers],
            # `null` et non `true` : on ne SAIT pas encore si le courrier
            # partira. Annoncer un succes qu'on n'a pas constate est exactement
            # ce que ce module s'interdit partout ailleurs.
            "alerte": {"ok": None, "detail": "envoi en cours", "en_cours": True}}


def _alerte_sans_bruit(d: Depot, **kw) -> None:
    """Envoie l'alerte en tache de fond, sans jamais laisser filer d'exception.

    `_alerte.envoie` attrape deja les pannes de courrier attendues — socket
    fermee, serveur qui refuse. Cette enveloppe attrape LE RESTE : un depot mal
    forme, un encodage inattendu, un bogue chez nous. Une tache de fond qui leve
    remonte dans les entrailles du serveur, ou elle n'apprend rien a personne et
    salit le journal d'une trace sans rapport avec la requete, laquelle a de
    toute facon deja repondu.

    LE DEPOT A EU LIEU. C'est la seule chose qui compte a ce stade : les octets
    sont ecrits, le manifeste est pose a cote d'eux, et il survit a l'alerte.
    """
    try:
        _alerte.envoie(d, **kw)
    except Exception as e:  # noqa: BLE001 — voir la docstring
        log.error("alerte du depot %s : %s", d.identifiant, e)


def _nettoie(dossier: Path) -> None:
    """Efface un dépôt avorté : un dossier à demi écrit n'est rattaché à rien."""
    try:
        for p in dossier.iterdir():
            p.unlink(missing_ok=True)
        dossier.rmdir()
    except OSError:
        pass


def _ecris_manifeste(d: Depot) -> None:
    """Pose à côté des octets ce qu'on sait d'eux.

    LE MANIFESTE SURVIT A L'ALERTE. Le courrier peut se perdre, la boîte peut
    être vidée ; le dossier doit se suffire à lui-même — sans quoi on se
    retrouve avec des `00.bin` dont plus personne ne connaît le nom d'origine.
    """
    doc = {
        "depot": d.identifiant,
        "recu_le": d.recu_le,
        "origine": d.origine,
        "mot": d.mot,
        "fichiers": [{"nom": f.nom, "taille": f.taille, "sha256": f.sha256,
                      "sur_disque": f.chemin.name} for f in d.fichiers],
    }
    try:
        (d.dossier / "manifeste.json").write_text(
            json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    except OSError as e:
        log.warning("manifeste du dépôt %s non écrit : %s", d.identifiant, e)


@router.get("/depots", dependencies=[Depends(require_jwt)])
async def liste_depots(borne: int = 50):
    """L'inventaire de ce qu'on a reçu. RESERVE.

    ON REND LES MANIFESTES, JAMAIS LES OCTETS. Aucune route ne sert le contenu
    d'un dépôt : le jour où l'on en ajouterait une, ce module deviendrait la
    fonction d'hébergement anonyme qu'il refuse d'être.
    """
    r = _reglages()
    borne = max(1, min(borne, 500))
    out = []
    try:
        dossiers = sorted((p for p in r["dossier"].iterdir() if p.is_dir()),
                          reverse=True)[:borne]
    except OSError:
        dossiers = []
    for p in dossiers:
        try:
            out.append(json.loads((p / "manifeste.json").read_text()))
        except (OSError, json.JSONDecodeError):
            # UN MANIFESTE ILLISIBLE EST SIGNALE, jamais sauté : un dépôt qu'on
            # n'inventorie pas est un dépôt qu'on oublie.
            out.append({"depot": p.name, "erreur": "manifeste illisible"})
    return {"depots": out, "total": len(out)}


@router.get("/depot/sante")
async def sante_depot():
    """La santé REPOSE SUR UNE ECRITURE, pas sur l'existence du dossier.

    Un volume monté en lecture seule, ou plein, se présente comme parfaitement
    normal à `exists()` — et le premier dépôt échoue.
    """
    r = _reglages()
    try:
        r["dossier"].mkdir(parents=True, exist_ok=True)
        sonde = r["dossier"] / ".sonde"
        sonde.write_text("")
        sonde.unlink()
        return {"status": "ok", "depots_dir": str(r["dossier"])}
    except OSError as e:
        return JSONResponse({"status": "degraded", "detail": str(e)},
                            status_code=503)
