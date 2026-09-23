# packages/secubox-metablogizer/api/routers/publish.py
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""MetaBlogizer publisher wizard: upload -> version -> route -> cert -> backup."""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

from publish.content import extract_archive, ContentError
from publish.routing import apply_route
from publish.certs import provision_cert, is_wildcard_domain
from publish.backup import export_site, import_site
from webhook import git_commit_push

# Derive sites_root from config the same way api/main.py does (importing from
# main would be circular since main imports this router).
_config = get_config("metablogizer")
SITES_ROOT = Path(_config.get("sites_root", "/srv/metablogizer/sites") if _config else "/srv/metablogizer/sites")
# Mirror the literal constants owned by api/main.py (kept in sync intentionally).
DEFAULT_DOMAIN_SUFFIX = ".gk2.secubox.in"
BASE_PORT = 8900

router = APIRouter()

# api/main.py DEPOSE ICI son générateur nginx, juste après l'avoir défini.
# L'importer serait circulaire — main importe ce routeur au chargement. Le
# crochet reste None dans les tests, qui n'ont pas de nginx à régénérer.
regenerer_nginx = None


def enregistre_domaine(site: Path, domaine: str) -> dict:
    """Écrit le domaine dans `site.json` (#1023).

    LE GENERATEUR NE LIT QUE LE DISQUE. `load_sites()` déduit le domaine de
    `site.json`, à défaut de `<nom>.gk2.secubox.in`. L'assistant acceptait un
    domaine en formulaire sans jamais l'écrire : il servait le temps d'une
    requête, puis disparaissait à la première régénération. Un réglage qu'on
    saisit et qui s'évapore est pire que pas de réglage du tout.
    """
    fichier = site / "site.json"
    doc = {}
    if fichier.exists():
        try:
            doc = json.loads(fichier.read_text())
            if not isinstance(doc, dict):
                doc = {}
        except (json.JSONDecodeError, OSError):
            # ON N'ECRASE PAS UN FICHIER QU'ON N'A PAS SU LIRE. Repartir d'un
            # document vide perdrait titre, version et catégorie du site.
            return {"ok": False, "detail": "site.json illisible, domaine non enregistré"}
    if doc.get("domain") == domaine:
        return {"ok": True, "detail": "déjà enregistré"}
    doc["domain"] = domaine
    doc.setdefault("name", site.name)
    try:
        tmp = fichier.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        tmp.replace(fichier)
    except OSError as e:
        return {"ok": False, "detail": f"écriture site.json : {e}"}
    return {"ok": True, "detail": domaine}


def marque_publie(site: Path, publie: bool) -> dict:
    """Écrit `published` dans `site.json` selon le VERDICT de l'assistant.

    Le schéma exige la clé, et c'est l'action publish/unpublish qui la pilote
    (site_schema.CHAMPS_EDITABLES l'exclut de l'édition). L'assistant, qui EST
    l'action publish, ne l'écrivait pas : chaque site publié par lui violait le
    schéma (« 'published' is a required property » à chaque scan) et se
    présentait sans état. Même prudence qu'`enregistre_domaine` : un fichier
    illisible n'est pas écrasé.
    """
    fichier = site / "site.json"
    doc = {}
    if fichier.exists():
        try:
            doc = json.loads(fichier.read_text())
            if not isinstance(doc, dict):
                doc = {}
        except (json.JSONDecodeError, OSError):
            return {"ok": False, "detail": "site.json illisible, état non enregistré"}
    if doc.get("published") is publie:
        return {"ok": True, "detail": "déjà à jour"}
    doc["published"] = publie
    doc.setdefault("name", site.name)
    try:
        tmp = fichier.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
        tmp.replace(fichier)
    except OSError as e:
        return {"ok": False, "detail": f"écriture site.json : {e}"}
    return {"ok": True, "detail": "published" if publie else "unpublished"}


def publie_vhost(domaine: str) -> dict:
    """Régénère la configuration nginx pour que le domaine soit SERVI (#1023).

    L'ETAPE MANQUANTE. L'assistant déposait le contenu, écrivait la route WAF,
    demandait le certificat — et s'arrêtait là. Aucun bloc `server` n'était créé.
    Or les 163 sites partagent le port 8900 et se distinguent par `server_name` :
    un domaine sans bloc ne tombe pas en erreur, il tombe sur LE PREMIER BLOC DU
    PORT. C'est ainsi que `www.gk2.secubox.in` a servi le site d'un voisin —
    chaque étape se déclarait réussie, et l'adresse montrait autre chose.
    """
    if regenerer_nginx is None:
        return {"ok": False, "detail": "générateur nginx indisponible"}
    try:
        ok, nombre, message = regenerer_nginx()
    except Exception as e:  # le générateur touche /etc et systemctl
        return {"ok": False, "detail": f"régénération nginx : {e}"}
    if not ok:
        return {"ok": False, "detail": message}
    return {"ok": True, "detail": message, "sites": nombre}


def _site_dir(name: str) -> Path:
    if not name.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "invalid site name")
    d = SITES_ROOT / name
    return d


# ── L'ASSISTANT REND COMPTE PENDANT QU'IL TRAVAILLE (#1323) ────────────────
#
# CE QU'ON VOYAIT. « Publication… », puis plus rien. L'assistant dépose le
# contenu, versionne, enregistre le domaine, régénère nginx, pose la route WAF
# et demande le certificat — sur la board, des dizaines de secondes à plusieurs
# minutes. Tout cela dans UNE requête dont la réponse n'arrive qu'à la fin : la
# page restait figée, sans un mot, et l'on ne pouvait ni savoir où l'on en
# était, ni distinguer un travail en cours d'un blocage.
#
# LES ÉTAPES EXISTAIENT POURTANT, mais seulement dans le compte rendu final, et
# la page n'en affichait que quatre sur six. `vhost` — qui décide pourtant du
# verdict — n'était montré nulle part : une publication refusée par `nginx -t`
# affichait quatre pastilles vertes et aucune rouge.
#
# CE QU'ON FAIT. La séquence devient un GÉNÉRATEUR : chaque étape est rendue
# dès qu'elle est finie. Deux emballages s'en servent — la réponse JSON d'hier,
# inchangée pour les appelants existants (le hub de publication, les tests), et
# un flux NDJSON quand le client le demande, une ligne par étape. La page
# allume ses pastilles au fil de l'eau.
#
# L'ORDRE N'EST PAS LIBRE : le domaine s'enregistre AVANT la régénération, sans
# quoi le générateur relit le disque et retombe sur `<nom>.gk2.secubox.in`.

# Les étapes, dans l'ordre, avec leur libellé. La page n'a plus à les deviner :
# une étape ajoutée ici apparaît d'elle-même à l'écran.
# Entre deux battements. Bien en-deçà des 30 s d'HAProxy, assez espacé pour ne
# pas noyer le flux.
BATTEMENT_SEC = 8.0

ETAPES_ASSISTANT = [
    ("content", "Contenu"),
    ("version", "Version"),
    ("domaine", "Domaine"),
    ("vhost", "Service"),
    ("route", "Route"),
    ("cert", "Certificat"),
]


async def _sequence_publication(name: str, domain: str, data: bytes, nom_fichier: str):
    """Déroule la publication en rendant chaque étape DÈS qu'elle est finie."""
    site = _site_dir(name)
    docroot = site / "public"
    docroot.mkdir(parents=True, exist_ok=True)

    try:
        contenu = extract_archive(docroot, data, nom_fichier or "index.html")
    except ContentError as e:
        raise HTTPException(400, f"unsafe upload: {e}")
    yield "content", contenu

    # Chaque étape ci-dessous shelle un sous-processus (git, nginx, publishctl).
    # On les DÉCHARGE sur des threads (`to_thread`) : sinon elles bloquent la
    # boucle asyncio pendant des minutes — la requête 504 au délai amont et TOUT
    # le reste de l'API (dont /deploys du panneau, /sites) pendouille (#1105).
    yield "version", await asyncio.to_thread(git_commit_push, site,
                                             f"publish {name} via wizard")
    yield "domaine", enregistre_domaine(site, domain)
    yield "vhost", await asyncio.to_thread(publie_vhost, domain)
    yield "route", await asyncio.to_thread(apply_route, domain, BASE_PORT)
    yield "cert", await _cert_step(domain)


def etat_etape(cle: str, res: dict) -> tuple[str, str]:
    """L'état d'une étape, et ce qu'on en dit à l'écran.

    C'EST AU SERVEUR DE TRANCHER, PAS À LA PAGE. Chaque étape rend une forme
    qui lui est propre — `index_present`, `route_ok`, `ok`, `mode`… La page
    marquait donc `version` et `cert` réussies EN DUR, quelle qu'ait été leur
    issue : un `git push` refusé s'affichait en vert. Une pastille qui ment est
    pire qu'une pastille absente, parce qu'on la croit.

    Trois états, et le troisième compte : `encours` pour un certificat custom
    que certbot obtient en tâche de fond. Le peindre en vert serait mentir, en
    rouge serait alarmer pour rien.
    """
    res = res or {}
    if cle == "content":
        ok = bool(res.get("index_present"))
        return ("ok" if ok else "echec",
                "" if ok else "aucun index.html dans l'archive")
    if cle == "version":
        if res.get("committed") or res.get("pushed"):
            return "ok", res.get("commit", "")
        return "echec", res.get("reason", "rien n'a été versionné")
    if cle == "route":
        ok = bool(res.get("route_ok"))
        return ("ok" if ok else "echec", "" if ok else str(res.get("detail", "")))
    if cle == "cert":
        if res.get("mode") == "provisioning":
            return "encours", str(res.get("detail", ""))
        return "ok", str(res.get("mode", ""))
    # `domaine` et `vhost` disent tous deux `ok` / `detail`.
    ok = bool(res.get("ok"))
    return ("ok" if ok else "echec", str(res.get("detail", "")))


def _verdict(steps: dict) -> bool:
    """`ok` EXIGE QUE LE DOMAINE SOIT SERVI. Le compte rendu d'origine se
    satisfaisait du contenu et de la route — un domaine sans bloc `server`
    passait donc pour publié alors qu'il montrait le site du voisin. Une étape
    qui n'entre pas dans le verdict ne protège de rien."""
    return (bool(steps.get("content", {}).get("index_present"))
            and bool(steps.get("route", {}).get("route_ok"))
            and bool(steps.get("vhost", {}).get("ok")))


@router.post("/publish/wizard")
async def publish_wizard(
    name: str = Form(...),
    domain: str = Form(None),
    file: UploadFile = File(...),
    flux: int = 0,
    user=Depends(require_jwt),
):
    domain = domain or f"{name}{DEFAULT_DOMAIN_SUFFIX}"
    data = await file.read()
    nom_fichier = file.filename or "index.html"
    site = _site_dir(name)

    if not flux:
        steps: dict = {}
        async for nom, res in _sequence_publication(name, domain, data, nom_fichier):
            steps[nom] = res
        ok = _verdict(steps)
        # L'état écrit suit le verdict, pas l'intention : un assistant qui a
        # échoué ne marque pas le site publié.
        steps["etat"] = marque_publie(site, ok)
        return {"ok": ok, "domain": domain, "steps": steps}

    # FLUX NDJSON : une ligne par étape, la dernière portant le verdict. On
    # n'attend pas la fin pour parler — c'est tout l'objet du correctif.
    async def lignes():
        steps: dict = {}
        yield json.dumps({"type": "debut", "domain": domain,
                          "etapes": [{"cle": c, "libelle": l}
                                     for c, l in ETAPES_ASSISTANT]}) + "\n"

        # LE FLUX DOIT BATTRE PENDANT UNE ÉTAPE LONGUE.
        #
        # HAProxy coupe à 30 s D'INACTIVITÉ (`timeout server`, section
        # `defaults`). Or régénérer nginx pour cent soixante-trois sites, ou
        # pousser un dépôt git, peut dépasser cela sans émettre un octet : la
        # connexion tomberait au milieu, et la page croirait à un plantage
        # alors que la publication, elle, se poursuit côté serveur.
        #
        # On émet donc un battement régulier tant qu'une étape travaille. Il
        # tient la connexion ouverte ET il dit la vérité : « toujours en cours
        # sur cette étape-là », ce qu'aucune barre de progression inventée ne
        # saurait faire honnêtement.
        file: asyncio.Queue = asyncio.Queue()

        async def travaille():
            try:
                async for nom, res in _sequence_publication(name, domain, data, nom_fichier):
                    await file.put(("etape", nom, res))
            except HTTPException as e:
                await file.put(("echec", None, str(e.detail)))
            except Exception as e:  # noqa: BLE001 — l'appelant doit savoir, pas deviner
                await file.put(("echec", None, f"{type(e).__name__}: {e}"))
            finally:
                await file.put(("fini", None, None))

        tache = asyncio.create_task(travaille())
        rate = False
        motif = ""
        while True:
            try:
                genre, nom, charge = await asyncio.wait_for(file.get(), BATTEMENT_SEC)
            except asyncio.TimeoutError:
                yield json.dumps({"type": "attente"}) + "\n"
                continue
            if genre == "fini":
                break
            if genre == "echec":
                rate, motif = True, charge
                continue
            steps[nom] = charge
            etat, detail = etat_etape(nom, charge)
            yield json.dumps({"type": "etape", "cle": nom, "etat": etat,
                              "detail": detail, "res": charge},
                             default=str) + "\n"
        await tache
        if rate:
            # Le flux a déjà commencé : on ne peut plus changer le code HTTP.
            # On dit donc l'échec DANS le flux — sans quoi la page attendrait
            # une suite qui ne viendrait jamais.
            yield json.dumps({"type": "fin", "ok": False, "detail": motif}) + "\n"
            return
        ok = _verdict(steps)
        steps["etat"] = marque_publie(site, ok)
        yield json.dumps({"type": "fin", "ok": ok, "domain": domain,
                          "steps": steps}, default=str) + "\n"

    return StreamingResponse(lignes(), media_type="application/x-ndjson",
                             # Sans cela, nginx tamponne la réponse et la rend
                             # d'un bloc à la fin : le flux existerait sans que
                             # personne ne le voie passer.
                             headers={"X-Accel-Buffering": "no",
                                      "Cache-Control": "no-store"})


class RouteRequest(BaseModel):
    domain: str
    port: int = BASE_PORT


async def _cert_step(domain: str) -> dict:
    """Provisionne le certificat SANS bloquer la requête (#1105).

    Un `*.gk2.secubox.in` réutilise le wildcard : c'est instantané, on l'attend
    (sur un thread) pour rendre un état exact. Un domaine CUSTOM passe par
    certbot HTTP-01, lent : on le lance en TÂCHE DE FOND et on rend la main tout
    de suite — le certificat s'obtient pendant que la requête a déjà répondu, au
    lieu de la faire 504. La boucle n'est jamais bloquée dans les deux cas."""
    if is_wildcard_domain(domain):
        return await asyncio.to_thread(provision_cert, domain)
    asyncio.create_task(asyncio.to_thread(provision_cert, domain))
    return {"mode": "provisioning",
            "detail": "certbot en cours (domaine hors *.gk2) — le certificat arrive en tâche de fond"}


@router.post("/publish/route")
async def publish_route(req: RouteRequest, user=Depends(require_jwt)):
    """Route an already-created site's domain through the WAF and provision its
    cert, WITHOUT a content upload. Used by the secubox-publish hub so it never
    writes /etc/nginx or /etc/haproxy itself (it runs unprivileged)."""
    route = await asyncio.to_thread(apply_route, req.domain, req.port)
    cert = await _cert_step(req.domain)
    return {"ok": bool(route.get("route_ok")), "route": route, "cert": cert}


@router.get("/publish/export/{name}")
async def publish_export(name: str, user=Depends(require_jwt)):
    site = _site_dir(name)
    if not site.exists():
        raise HTTPException(404, "site not found")
    manifest = {"name": name, "domain": f"{name}{DEFAULT_DOMAIN_SUFFIX}",
                "base_port": BASE_PORT}
    out = Path(tempfile.mkdtemp())
    art = export_site(site, manifest, out)
    return FileResponse(
        str(art), filename=art.name, media_type="application/octet-stream",
        background=BackgroundTask(shutil.rmtree, str(out), True),
    )


@router.post("/publish/import")
async def publish_import(file: UploadFile = File(...), user=Depends(require_jwt)):
    data = await file.read()
    tmp = Path(tempfile.mkdtemp())
    art = tmp / "upload.sbxsite"
    art.write_bytes(data)
    try:
        manifest = import_site(art, SITES_ROOT)
    except Exception as e:  # noqa: BLE001 — surface a clean 400
        raise HTTPException(400, f"import failed: {e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return JSONResponse({"ok": True, "manifest": manifest})
