# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Service `secubox-ai-emissions` (#4058, Task 14) : FastAPI sur socket Unix, unité utilisateur de gk0.

    uvicorn --factory emissions.app:creer_app --uds %t/secubox-ai-emissions/emissions.sock

Toutes les routes (sauf /health) exigent le jeton local (`Authorization: Bearer`, fichier 0600 du compte,
`SECUBOX_AI_EMISSIONS_JETON`) : seul le relais du POC le lit et le pose (`relais/emissions_relais.py`), et le
relais n'ouvre ces routes qu'au Host local. Le navigateur ne voit jamais le jeton.
"""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from . import capture, gpu, production, reglages
from .magasin import Magasin
from .sources import Sources, jeton_fichier

JETON_DEFAUT = Path.home() / ".config/secubox-ai-jeton/jeton"
FICHIER_RE = re.compile(r"^(emission\.mp3|emission\.mp4|diapos/[0-9]{2}-[A-Za-z0-9_-]{1,80}\.png"
                        r"|captures/[A-Za-z0-9_-]{1,64}\.png)$")
TYPES = {".mp3": "audio/mpeg", ".mp4": "video/mp4", ".png": "image/png"}


def lire_jeton(chemin: Path) -> str:
    st = os.lstat(chemin)
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid != os.getuid():
        raise RuntimeError("jeton local : fichier ordinaire 0600 du compte requis")
    j = Path(chemin).read_text(encoding="utf-8").strip()
    if len(j) < 32:
        raise RuntimeError("jeton local : 32 caractères au moins")
    return j


class Produire(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sources: List[str]
    format: str = "sujet"


class Texte(BaseModel):
    model_config = ConfigDict(extra="forbid")
    texte: str = Field(min_length=1, max_length=2000)


class Entete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    titre: str = Field(min_length=1, max_length=140)
    chapeau: str = Field(default="", max_length=400)


class Capture(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=8, max_length=300)
    zone: Optional[str] = Field(default=None, max_length=200)
    rang: Optional[int] = Field(default=None, ge=0, le=10000)


class Accord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    accord: bool


def _outils_reels(base: Path) -> production.Outils:
    r = reglages.lire(base)
    return production.Outils(sources=Sources(r["gk2_base"], jeton_fichier()), magasin=Magasin(base / "magasin.sqlite"),
                             reglages=lambda: reglages.lire(base))


def _apercu(sujet: Dict[str, Any], dernier: Optional[Dict[str, Any]], ecart: float) -> int:
    """Pastille « évolutions » sans relire chaque dossier : nouveau sujet, nombre de vagues changé, bans en écart."""
    if dernier is None:
        return 1
    n = 0
    if isinstance(sujet.get("vagues"), int) and sujet["vagues"] != len(dernier.get("vagues") or []):
        n += 1
    a, b = (dernier.get("chiffres") or {}).get("bans_90j"), sujet.get("bans_90j")
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and a != b and (not a or abs(b - a) / a >= ecart):
        n += 1
    return n


def creer_app(base: Optional[Path] = None, outils: Optional[production.Outils] = None,
              jeton: Optional[Path] = None) -> FastAPI:
    base = Path(base or reglages.etat_dir())
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    attendu = lire_jeton(Path(jeton or os.environ.get("SECUBOX_AI_EMISSIONS_JETON") or JETON_DEFAUT)).encode()
    o = outils or _outils_reels(base)
    file = production.File(base, o)

    async def garde(request: Request) -> None:
        schema, _, j = request.headers.get("authorization", "").partition(" ")
        if schema.lower() != "bearer" or not hmac.compare_digest(j.strip().encode(), attendu):
            raise HTTPException(401, "jeton requis", headers={"WWW-Authenticate": "Bearer"})

    @contextlib.asynccontextmanager
    async def cycle(_app):
        # Verrou de voix orphelin (service tué pendant une voix GPU) : Gemma relancé AVANT toute production.
        with contextlib.suppress(Exception):
            await gpu.par_relais().reparer()
        file.demarrer()
        await file.reprendre_au_demarrage()
        yield
        await file.arreter()

    app = FastAPI(title="secubox-ai-emissions", lifespan=cycle, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.file = file
    G = [Depends(garde)]

    def _etat(ident: str) -> Dict[str, Any]:
        try:
            return production.lire_etat(base, ident)
        except ValueError:
            raise HTTPException(404, "brouillon introuvable")
        except FileNotFoundError:
            raise HTTPException(404, "brouillon introuvable")

    @app.get("/health")
    def sante():
        return {"ok": True}

    @app.get("/etat", dependencies=G)
    def etat_service():
        r = o.reglages()
        return {"en_cours": file.en_cours, "attente": file.attente(), "voix_gpu": r["voix_gpu"],
                "voix_en_cours": gpu.VERROU.exists(), "llm_pret": Path(os.environ.get(
                    "SECUBOX_AI_AGENTS_MOTEUR", Path.home() / "poc-secubox-ai/run/llama.sock")).is_socket()}

    @app.get("/sources", dependencies=G)
    async def sources():
        try:
            sujets = await o.sources.lister()
        except Exception as e:  # noqa: BLE001 — gk2 injoignable : le panneau le dit, sans détail
            raise HTTPException(502, f"gk2 injoignable ({type(e).__name__})")
        ecart = float(o.reglages()["ecart"])
        out = []
        for s in sujets:
            cle = s.get("cle") or f"{s.get('genre')}/{s.get('id')}"
            out.append({**{k: s.get(k) for k in ("genre", "id", "nom", "bans_90j", "vagues", "recurrences")},
                        "cle": cle, "evolutions": _apercu(s, o.magasin.dernier_valide(cle), ecart)})
        return {"sujets": out}

    @app.get("/evolutions", dependencies=G)
    async def evolutions_completes():
        """Évolutions complètes de chaque sujet (relit chaque dossier) : pour l'hebdomadaire."""
        from .evolutions import evolutions
        ecart = float(o.reglages()["ecart"])
        out: Dict[str, List[Dict[str, Any]]] = {}
        for s in await o.sources.lister():
            cle = s.get("cle") or f"{s.get('genre')}/{s.get('id')}"
            rep = await o.sources.dossier(s["genre"], s["id"])
            d = rep.get("dossier") if isinstance(rep.get("dossier"), dict) else rep
            out[cle] = evolutions(d, o.magasin.dernier_valide(cle), o.maintenant(), seuil_chiffre=ecart)
        return {"sujets": out}

    @app.post("/produire", dependencies=G)
    async def lancer(corps: Produire):
        try:
            e = production.creer(base, corps.sources, corps.format, o.maintenant())
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        await file.mettre(e["id"])
        return {"id": e["id"], "attente": file.attente()}

    @app.get("/brouillons", dependencies=G)
    def brouillons():
        return {"brouillons": production.lister(base)}

    @app.get("/reglages", dependencies=G)
    def lire_reglages():
        return o.reglages()

    @app.post("/reglages", dependencies=G)
    def changer_reglages(corps: Dict[str, Any]):
        try:
            return reglages.modifier(corps, base)
        except ValueError as exc:
            raise HTTPException(422, str(exc))

    @app.get("/{ident}", dependencies=G)
    def lire(ident: str):
        e = _etat(ident)
        e["captures"] = capture._lire(production.dossier(base, ident))
        e["verification"] = production.resume_verification(e["repliques"])
        e["en_file"] = ident in file.attente()
        return e

    @app.post("/{ident}/entete", dependencies=G)
    def entete(ident: str, corps: Entete):
        e = _etat(ident)
        e["titre"], e["chapeau"] = " ".join(corps.titre.split()), " ".join(corps.chapeau.split())
        production.ecrire_etat(base, e)
        return {"titre": e["titre"], "chapeau": e["chapeau"]}

    @app.post("/{ident}/replique/{rang}", dependencies=G)
    async def replique(ident: str, rang: int, corps: Texte):
        _etat(ident)
        try:
            r = production.modifier_replique(base, ident, rang, corps.texte)
        except KeyError:
            raise HTTPException(404, "réplique introuvable")
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(409, str(exc))
        await file.mettre(ident)                       # seule sa voix est refaite, puis le montage
        return r

    @app.post("/{ident}/replique/{rang}/reecrire", dependencies=G)
    async def reecrire(ident: str, rang: int):
        _etat(ident)
        try:
            return await production.reecrire(base, ident, rang, o)
        except KeyError:
            raise HTTPException(404, "réplique introuvable")
        except Exception as exc:  # noqa: BLE001 — moteur indisponible (voix GPU en cours, arrêté…)
            raise HTTPException(503, f"réécriture impossible ({type(exc).__name__})")

    @app.post("/{ident}/capture", dependencies=G)
    async def prendre_capture(ident: str, corps: Capture):
        _etat(ident)
        d = production.dossier(base, ident)
        cid = f"c{int(time.time())}{os.urandom(2).hex()}"
        try:
            res = await capture.capturer(corps.url, corps.zone, d / "captures" / f"{cid}.png")
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        capture.enregistrer_capture(d, cid, res)
        reg = capture._lire(d)
        reg[cid]["rang"] = corps.rang
        capture._ecrire(d, reg)
        return {"id": cid, **reg[cid]}

    @app.post("/{ident}/capture/{cid}/valider", dependencies=G)
    async def valider(ident: str, cid: str, corps: Accord):
        _etat(ident)
        try:
            etat = capture.valider_capture(production.dossier(base, ident), cid, corps.accord)
        except KeyError:
            raise HTTPException(404, "capture introuvable")
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        production.rouvrir_montage(base, ident)        # la diapo change, pas les voix
        if production.lire_etat(base, ident)["etapes"][-1]["etat"] == "a_faire":
            await file.mettre(ident)
        return {"id": cid, "etat": etat}

    @app.post("/{ident}/mp4", dependencies=G)
    async def mp4(ident: str):
        e = _etat(ident)
        if e.get("statut") != "pret":
            raise HTTPException(409, "montage non fait")
        await file.mettre(ident, "mp4")
        return {"mp4": "en file"}

    @app.post("/{ident}/reprendre", dependencies=G)
    async def reprendre(ident: str):
        _etat(ident)
        await file.mettre(ident)
        return {"attente": file.attente()}

    @app.delete("/{ident}", dependencies=G)
    def supprimer(ident: str):
        _etat(ident)
        if file.en_cours == ident:
            raise HTTPException(409, "brouillon en production")
        production.supprimer(base, ident)
        return {"supprime": ident}

    @app.get("/{ident}/fichier/{chemin:path}", dependencies=G)
    def fichier(ident: str, chemin: str):
        _etat(ident)
        if not FICHIER_RE.match(chemin):
            raise HTTPException(404, "introuvable")
        f = production.dossier(base, ident) / chemin
        if not f.is_file() or f.is_symlink():
            raise HTTPException(404, "introuvable")
        return FileResponse(f, media_type=TYPES[f.suffix], headers={"Cache-Control": "no-store"})

    app.state.base = base
    app.state.outils = o
    return app


def _reparer() -> int:
    """`python -m emissions.app --reparer` (ExecStartPre) : relance Gemma si un verrou de voix est resté orphelin."""
    return 0 if asyncio.run(gpu.par_relais().reparer()) is not None else 1


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--reparer"]:
        with contextlib.suppress(Exception):
            _reparer()
        raise SystemExit(0)
    raise SystemExit("usage : python -m emissions.app --reparer")
