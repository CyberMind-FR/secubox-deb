# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Journal d'audit du module (#3583) : `<etat>/journal.jsonl`, une ligne JSON par événement.

Règle du POC : ni question, ni réponse, ni titre de document, ni adresse lue, ni nom de dépôt, ni clé. Les champs
interdits sont refusés par `ValueError` (le code appelant est en faute, jamais de repli silencieux).
"""
import asyncio
import datetime as dt
import json
import os
import re
import threading

from fastapi import APIRouter, Depends

from api import reglages
from secubox_core.auth import require_jwt

INTERDITS = frozenset({"question", "reponse", "texte", "titre", "url", "depot", "cle", "contenu"})
ACTION = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
VALEUR_MAX = 200
LECTURE_MAX = 256 * 1024      # fin du fichier lue pour la page : jamais le journal entier
LIGNES_PAGE = 60
_verrou = threading.Lock()


def fichier_journal():
    return reglages.etat_dir() / "journal.jsonl"


def _valeur(v):
    if isinstance(v, str):
        return v[:VALEUR_MAX]
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, (list, tuple)):
        return [_valeur(x) for x in v][:50]
    return str(v)[:VALEUR_MAX]


def journal(action, **champs):
    """Ajoute un événement. ValueError si l'action est mal formée ou si un champ est interdit."""
    if not isinstance(action, str) or not ACTION.match(action):
        raise ValueError("action de journal invalide")
    interdits = sorted(INTERDITS & set(champs))
    if interdits:
        raise ValueError("champ interdit dans le journal : " + ", ".join(interdits))
    ligne = {"quand": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "action": action,
             **{c: _valeur(v) for c, v in champs.items() if c not in ("quand", "action")}}
    f = fichier_journal()
    f.parent.mkdir(parents=True, exist_ok=True)
    with _verrou:
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as sortie:
            sortie.write(json.dumps(ligne, ensure_ascii=False) + "\n")


def lire(n=LIGNES_PAGE):
    """Les `n` dernières lignes valides, la plus récente d'abord."""
    f = fichier_journal()
    try:
        with open(f, "rb") as src:
            taille = src.seek(0, os.SEEK_END)
            src.seek(max(0, taille - LECTURE_MAX))
            brut = src.read()
    except OSError:
        return []
    lignes = brut.decode("utf-8", errors="replace").splitlines()
    if taille > LECTURE_MAX:
        lignes = lignes[1:]                      # première ligne probablement coupée
    sortie = []
    for x in lignes[-n:]:
        try:
            d = json.loads(x)
        except ValueError:
            continue
        if isinstance(d, dict):
            sortie.append(d)
    return sortie[::-1]


routeur = APIRouter(prefix="")


@routeur.get("/journal", dependencies=[Depends(require_jwt)])
async def get_journal():
    return {"lignes": await asyncio.to_thread(lire)}
