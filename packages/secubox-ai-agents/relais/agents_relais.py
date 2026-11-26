# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Branchement de secubox-ai-agents dans le relais du POC gk0 (#3986, tranche A).

Copié dans ~/poc-secubox-ai/relais/ ; relais.py l'appelle par deux lignes en fin de fichier :

    import agents_relais  # noqa: E402
    agents_relais.brancher(app, _local)

- `GET /jarvis` : la page de conversation ; `/api/v1/ai/jarvis/<chemin>` : relayé vers le socket Unix du
  service, réponse en flux (SSE) ;
- LOCAL SEULEMENT : `_local` du relais (Host 127.0.0.1:8098 / localhost:8098) ; le nom public et la ZIA n'ont
  pas ces routes (le middleware du relais ne laisse passer que ROUTES_PUBLIQUES / ROUTES_ZIA, qui ne les
  contiennent pas) ;
- le relais pose le jeton local du service (fichier 0600 du compte) : le navigateur ne le voit jamais.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

import httpx
from fastapi import BackgroundTasks, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse

SOCKET = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "secubox-ai-agents/agents.sock"
JETON = Path.home() / ".config/secubox-ai-jeton/jeton"
PAGE = Path(__file__).parent / "agents.html"
CHEMIN_RE = re.compile(r"^[A-Za-z0-9/_-]{1,120}$")
CORPS_MAX = 256 * 1024
API = "/api/v1/ai/jarvis"   # PAS /agents : le POC sert déjà POST /api/v1/ai/agents/{nom} (relais.py l.3163)


def _jeton() -> str:
    st = JETON.lstat()
    if st.st_mode & 0o077 or not JETON.is_file():
        raise HTTPException(503, "jeton du service mal protégé")
    return JETON.read_text(encoding="utf-8").strip()


MODELES = Path.home() / "poc-secubox-ai/models"
LIMITES = Path(__file__).parent / "limites.toml"
ENV_EVAL = Path.home() / ".config/secubox-ai-eval/modele.env"
UNITE_EVAL = "secubox-ai-eval-moteur.service"
SOCKET_EVAL = SOCKET.parent.parent / "secubox-ai-eval/moteur.sock"
NOM_MODELE_RE = re.compile(r"^[A-Za-z0-9._-]{1,160}\.gguf$")
MARGE_RAM_O = 1536 * 1024 ** 2      # le second moteur ne démarre que s'il reste cette marge après chargement
API2 = "/api/v1/ai/jarvis-moteur2"
API3 = "/api/v1/ai/jarvis-medias"
IMAGE_MAX = 8 * 1024 * 1024         # corps de POST /image (image en base64)


def _relais():
    """Le module du relais (déjà chargé par uvicorn) : ses fonctions de téléchargement et de projecteur."""
    m = sys.modules.get("relais")
    if m is None:
        raise HTTPException(503, "relais introuvable")
    return m


def _modele_actif() -> str:
    import tomllib
    try:
        return str(tomllib.loads(LIMITES.read_text(encoding="utf-8")).get("moteur", {}).get("modele", ""))
    except (OSError, ValueError):
        return ""


def _ram_disponible() -> int:
    for ligne in Path("/proc/meminfo").read_text().splitlines():
        if ligne.startswith("MemAvailable:"):
            return int(ligne.split()[1]) * 1024
    return 0


def modeles_eval() -> list[dict]:
    """Modèles installés utilisables en second moteur : ni l'actif, ni un projecteur (mmproj), ni un .part."""
    actif, libre = _modele_actif(), _ram_disponible()
    sortie = []
    for f in sorted(MODELES.glob("*.gguf")):
        if f.name == actif or f.name.startswith("mmproj") or not NOM_MODELE_RE.match(f.name) or not f.is_file():
            continue
        taille = f.stat().st_size
        sortie.append({"nom": f.name, "taille_mo": taille // 1024 ** 2,
                       "tient": taille + MARGE_RAM_O <= libre, "ram_disponible_mo": libre // 1024 ** 2})
    return sortie


def _systemctl(*args: str) -> int:
    import subprocess
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, timeout=30, check=False).returncode


def brancher(app, local) -> None:
    transport = httpx.AsyncHTTPTransport(uds=str(SOCKET))

    # --- second moteur d'évaluation (#3992) : démarré/arrêté ICI, le service des agents n'a pas ce pouvoir ---
    @app.get(API2 + "/etat")
    def eval_etat(request: Request):
        local(request)
        modele = ""
        if ENV_EVAL.is_file():
            modele = Path(ENV_EVAL.read_text(encoding="utf-8").partition("=")[2].strip()).name
        return {"actif": _systemctl("is-active", "--quiet", UNITE_EVAL) == 0, "pret": SOCKET_EVAL.is_socket(),
                "modele": modele, "modeles": modeles_eval()}

    @app.post(API2 + "/demarrer")
    def eval_demarrer(corps: dict, request: Request):
        local(request)
        nom = str(corps.get("modele", ""))
        choix = {m["nom"]: m for m in modeles_eval()}
        if nom not in choix:
            raise HTTPException(404, "modèle inconnu (ni l'actif, ni un projecteur)")
        if not choix[nom]["tient"]:
            raise HTTPException(409, f"mémoire insuffisante : {choix[nom]['taille_mo']} Mo à charger, "
                                     f"{choix[nom]['ram_disponible_mo']} Mo disponibles (marge 1,5 Go)")
        ENV_EVAL.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = ENV_EVAL.with_suffix(".tmp")
        tmp.write_text(f"MODELE={MODELES / nom}\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, ENV_EVAL)                       # double tampon
        if _systemctl("restart", UNITE_EVAL) != 0:
            raise HTTPException(503, "second moteur : démarrage refusé par systemd")
        return {"demarre": nom}

    @app.post(API2 + "/arreter")
    def eval_arreter(request: Request):
        local(request)
        _systemctl("stop", UNITE_EVAL)
        return {"arrete": True}

    # --- projecteur vision (#3995) : téléchargé PAR LE RELAIS, empreinte SHA-256 de Hugging Face vérifiée ---
    # Le relais refuse d'installer un fichier annexe seul (POST /modeles) ; ici, seul un `mmproj-…` dont le nom
    # contient la racine d'un modèle INSTALLÉ est accepté, puis la fonction `telecharger` du relais fait le travail
    # (taille bornée, empreinte, en-tête GGUF, journal). Le relais l'associe ensuite au modèle (`projecteur()`).
    @app.get(API3 + "/projecteur")
    def projecteur_etat(request: Request):
        local(request)
        r = _relais()
        actif = _modele_actif()
        p = r.projecteur(actif)
        return {"modele": actif, "projecteur": p.name if p else None,
                "telechargements": {k: v for k, v in r.telechargements.items() if "mmproj" in k.lower()}}

    @app.post(API3 + "/projecteur")
    async def projecteur_telecharger(corps: dict, request: Request, taches: BackgroundTasks):
        local(request)
        r = _relais()
        depot, nom = str(corps.get("depot", "")), str(corps.get("fichier", ""))
        if not r.DEPOT.match(depot) or not NOM_MODELE_RE.match(nom) or not nom.lower().startswith("mmproj-"):
            raise HTTPException(422, "dépôt ou fichier invalide (mmproj-….gguf attendu)")
        installes = [f.name for f in MODELES.glob("*.gguf") if not f.name.lower().startswith("mmproj")]
        if not any(re.sub(r"[-._](Q\d\w*|IQ\d\w*|f16|bf16)$", "", Path(m).stem, flags=re.I).lower() in nom.lower()
                   for m in installes):
            raise HTTPException(422, "ce projecteur ne correspond à aucun modèle installé")
        if (MODELES / nom).exists() or nom in r.telechargements and "erreur" not in r.telechargements[nom]:
            raise HTTPException(409, "déjà présent ou en cours")
        infos = await r.modeles_depot(depot)
        choix = next((f for f in infos["fichiers"] if f["nom"] == nom), None)
        if not choix or not choix["sha256"] or not choix["taille"]:
            raise HTTPException(422, "fichier absent du dépôt, ou sans empreinte vérifiable")
        if infos["restreint"]:
            raise HTTPException(403, "dépôt réservé : conditions à accepter chez l'éditeur")
        if shutil.disk_usage(MODELES).free - choix["taille"] < r.PLANCHER_DISQUE:
            raise HTTPException(507, "place insuffisante")
        r.telechargements[nom] = {"recu": 0, "total": choix["taille"]}
        taches.add_task(r.telecharger, depot, nom, choix["sha256"], choix["taille"], infos["licence"])
        return {"telechargement": nom, "sha256": choix["sha256"], "taille": choix["taille"], "licence": infos["licence"]}

    @app.get("/jarvis")
    def page_agents(request: Request):
        local(request)
        return FileResponse(PAGE, headers={"Cache-Control": "no-store"})

    @app.api_route(API + "/{chemin:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def relayer(chemin: str, request: Request):
        local(request)
        if not CHEMIN_RE.match(chemin) or ".." in chemin:
            raise HTTPException(404, "introuvable")
        corps = await request.body()
        if len(corps) > (IMAGE_MAX if chemin == "image" else CORPS_MAX):
            raise HTTPException(413, "trop long")
        if not SOCKET.is_socket():
            raise HTTPException(503, "secubox-ai-agents arrêté")
        client = httpx.AsyncClient(transport=transport, base_url="http://agents", timeout=httpx.Timeout(600, connect=5))
        entetes = {"Authorization": f"Bearer {_jeton()}"}
        if request.headers.get("content-type"):
            entetes["Content-Type"] = request.headers["content-type"]
        req = client.build_request(request.method, "/" + chemin, params=request.query_params, content=corps,
                                   headers=entetes)
        try:
            rep = await client.send(req, stream=True)
        except httpx.TransportError as exc:
            await client.aclose()
            raise HTTPException(503, "secubox-ai-agents injoignable") from exc

        async def suite():
            try:
                async for bloc in rep.aiter_raw():
                    yield bloc
            finally:
                await rep.aclose()
                await client.aclose()

        garder = {k: v for k, v in rep.headers.items() if k.lower() in ("content-type", "cache-control")}
        return StreamingResponse(suite(), status_code=rep.status_code, headers=garder)
