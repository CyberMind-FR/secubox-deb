# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Publication d'une émission sur les billets (#4058, Task 17) — SEULEMENT sur le clic « Publier » du propriétaire.

1. refus si le brouillon n'est pas prêt, si une capture attend sa validation (ou n'est pas validée et figure au
   diaporama), ou si le BALAYAGE FINAL trouve quoi que ce soit (titre, chapeau, répliques dites, chronologie, images
   par OCR) : `Refus(motifs)`, AUCUNE requête vers les billets ;
2. envoi par l'API d'administration (`Authorization: Bearer` = jeton de l'auteur `emissions`, fichier 0600) : billet en
   brouillon, MP3, PNG dans l'ordre des diapositives (rang `diapo` de la chronologie), MP4 s'il a été produit, puis
   chronologie + passage en `published` ; un échec en route supprime le billet distant (rien de partiel en ligne) ;
3. succès : les répliques dites entrent au magasin des lectures évolutives (`verifiee` / `ia_seule` → hypothèse) et le
   brouillon est marqué `publie`.
"""
from __future__ import annotations

import contextlib
import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

from . import capture
from .balayage import balayer, lire_noms_internes

JETON_DEFAUT = Path.home() / ".config/secubox-ai-jeton/billets-emissions"
TYPES = {".mp3": "audio/mpeg", ".png": "image/png", ".mp4": "video/mp4"}
DELAI_S = 120.0


class Refus(Exception):
    def __init__(self, motifs: List[Dict[str, str]]) -> None:
        super().__init__("publication refusée")
        self.motifs = motifs


class EchecBillets(RuntimeError):
    pass


def _etat(brouillon: Path) -> Dict[str, Any]:
    return json.loads((Path(brouillon) / "etat.json").read_text(encoding="utf-8"))


def _ecrire_etat(brouillon: Path, e: Dict[str, Any]) -> None:
    e["maj_le"] = int(time.time())
    f = Path(brouillon) / "etat.json"
    tmp = f.with_name(".etat.json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(e, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, f)


def _dites(e: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in e.get("repliques") or [] if r.get("statut") != "retiree"]


def corps_billet(e: Dict[str, Any]) -> str:
    return f"## {e.get('titre') or 'Émission'}\n\n{e.get('chapeau') or ''}".strip()


def controle(brouillon: Path, *, ocr: Optional[Callable[[Path], str]] = None,
             noms_internes: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """Tout ce qui empêche la publication ; liste vide = publiable. Le texte trouvé n'est jamais recopié."""
    d = Path(brouillon)
    e = _etat(d)
    motifs: List[Dict[str, str]] = []
    if e.get("statut") not in ("pret",):
        motifs.append({"ou": "brouillon", "motif": "non_pret"})
    if not e.get("chronologie") or not (d / "emission.mp3").is_file():
        motifs.append({"ou": "montage", "motif": "montage_absent"})
    caps = capture._lire(d)
    for cid, c in caps.items():
        if isinstance(c, dict) and c.get("etat") == "a_valider":
            motifs.append({"ou": f"capture:{cid}", "motif": "capture_non_validee"})
    for img in e.get("images") or []:
        if img.startswith("captures/") and Path(img).name not in capture.captures_validees(d):
            motifs.append({"ou": f"image:{Path(img).name}", "motif": "capture_non_validee"})
    textes = [e.get("titre") or "", e.get("chapeau") or "", corps_billet(e)]
    textes += [r.get("texte") or "" for r in _dites(e)]
    textes += [str(c.get("replique") or "") for c in e.get("chronologie") or []]
    images = [d / i for i in e.get("images") or []]
    motifs += balayer(textes, images, noms_internes if noms_internes is not None else lire_noms_internes(), ocr=ocr)
    return motifs


async def _verifier(r: httpx.Response, quoi: str) -> Dict[str, Any]:
    if r.status_code >= 400:
        raise EchecBillets(f"billets : {quoi} refusé (HTTP {r.status_code})")
    try:
        return r.json()
    except ValueError:
        return {}


async def publier(brouillon: Path, billets: str, jeton: Callable[[], str], *, client: Optional[httpx.AsyncClient] = None,
                  ocr: Optional[Callable[[Path], str]] = None, noms_internes: Optional[List[str]] = None,
                  magasin: Any = None) -> Dict[str, Any]:
    d = Path(brouillon)
    motifs = controle(d, ocr=ocr, noms_internes=noms_internes)
    if motifs:
        raise Refus(motifs)
    e = _etat(d)
    base = billets.rstrip("/")
    entetes = {"Authorization": f"Bearer {jeton()}"}
    propre = client is None
    c = client or httpx.AsyncClient(trust_env=False, timeout=httpx.Timeout(DELAI_S, connect=10.0))
    billet = None
    try:
        b = await _verifier(await c.post(base + "/admin/api/billets", headers=entetes,
                                         json={"body": corps_billet(e), "status": "draft"}), "création")
        billet = b.get("id")
        if not isinstance(billet, str) or not billet:
            raise EchecBillets("billets : identifiant absent")
        fichiers = [d / "emission.mp3"] + [d / i for i in e.get("images") or []]
        if (d / "emission.mp4").is_file():
            fichiers.append(d / "emission.mp4")                # le MP4 seulement s'il a été demandé et produit
        for f in fichiers:
            await _verifier(await c.post(f"{base}/admin/api/billets/{billet}/media", headers=entetes,
                                         files={"file": (f.name, f.read_bytes(), TYPES[f.suffix])}), f"envoi {f.name}")
        fin = await _verifier(await c.put(f"{base}/admin/api/billets/{billet}", headers=entetes, json={
            "body": corps_billet(e), "status": "published", "chronologie": e["chronologie"]}), "publication")
    except BaseException:
        if billet:
            with contextlib.suppress(Exception):
                await c.delete(f"{base}/admin/api/billets/{billet}", headers=entetes)
        raise
    finally:
        if propre:
            await c.aclose()
    if magasin is not None:
        faits = json.loads((d / "faits.json").read_text(encoding="utf-8"))
        gardees = [{"texte": r["texte"], "statut": "hypothese" if r.get("statut") == "ia_seule" else "verifiee"}
                   for r in _dites(e)]
        for sujet, dossier in faits.items():
            magasin.retenir(sujet, dossier, gardees)
    e["statut"] = "publie"
    e["publication"] = {"billet": billet, "url": fin.get("url") or fin.get("permalien"), "quand": int(time.time())}
    _ecrire_etat(d, e)
    return {"billet": billet, "url": e["publication"]["url"]}
