# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Créer des images (#3995) : côté service, file d'attente, filtre de contenu et journal.

Le service des agents ne génère rien lui-même (il n'a ni carte graphique, ni réseau) : il dépose une demande
dans la file du travailleur `secubox-ai-images` (`$SECUBOX_AI_IMAGES_FILE`, dossier partagé du compte), qui
lance stable-diffusion.cpp, une génération à la fois.

- Filtre de contenu ACTIF par défaut : une demande qui touche à la sexualité, aux mineurs dans un contexte
  sexuel, à la violence explicite, ou qui vise une personne réelle nommée est refusée avant la file ; le refus
  est journalisé. Ce filtre est une liste de mots (français et anglais) : il est grossier, et il est écrit ainsi.
- Journal (`journal.jsonl`, 0600) : date, identifiant, modèle, taille, verdict du filtre, durée ; jamais le
  texte de la demande (seulement sa longueur et une empreinte), comme les autres journaux du module.
- Bornes : 20 demandes en attente au plus ; tailles et modèles en liste fermée.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
import unicodedata
from pathlib import Path

MODELES = {
    "sd15": {"tailles": (512,), "etapes": 20, "cfg": 7.0},
    "sdxl-turbo": {"tailles": (512, 1024), "etapes": 4, "cfg": 1.0},
    "sd-turbo": {"tailles": (512,), "etapes": 1, "cfg": 1.0},
    "z-image-turbo": {"tailles": (512, 1024), "etapes": 8, "cfg": 1.0},
}
FILE_MAX = 20
INTERDITS = (
    # sexualité et nudité
    "nu", "nue", "nus", "nues", "nudite", "nude", "naked", "nsfw", "sexe", "sexuel", "sexuelle", "sex", "sexual",
    "porn", "porno", "pornographique", "erotique", "erotic", "hentai", "seins", "breasts", "lingerie", "strip",
    # mineurs (tout contexte de corps ou de nudité est déjà refusé ci-dessus ; ces mots rendent le refus certain)
    "enfant nu", "child nude", "loli", "shota",
    # violence explicite
    "gore", "decapite", "decapitation", "mutile", "mutilation", "torture", "cadavre", "corpse", "massacre",
    "suicide", "sang qui gicle",
    # haine
    "nazi", "swastika", "croix gammee",
)
PERSONNES = re.compile(r"\b(photo|portrait|image|deepfake)\s+(de|of)\s+[A-Z][a-zé]+\s+[A-Z][a-zé]+")


def _norm(t: str) -> str:
    t = unicodedata.normalize("NFKD", t.lower())
    return "".join(c for c in t if not unicodedata.combining(c))


def filtrer(prompt: str) -> str | None:
    """Raison du refus, ou None. Mots entiers seulement (« nu » ne bloque pas « menu »)."""
    n = _norm(prompt)
    mots = set(re.findall(r"[a-z0-9]+", n))
    for interdit in INTERDITS:
        if (" " in interdit and interdit in n) or interdit in mots:
            return "contenu refusé par le filtre (sexualité, violence explicite ou haine)"
    if PERSONNES.search(prompt):
        return "contenu refusé par le filtre (image d'une personne réelle nommée)"
    return None


class Creations:
    def __init__(self, racine: Path) -> None:
        self.racine = racine
        for d in ("file", "en_cours", "fait", "echec"):
            (racine / d).mkdir(mode=0o700, parents=True, exist_ok=True)
        self.journal_f = racine / "journal.jsonl"

    def journal(self, **champs) -> None:
        ligne = json.dumps({"quand": time.strftime("%Y-%m-%dT%H:%M:%S"), **champs}, ensure_ascii=False)
        fd = os.open(self.journal_f, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(ligne + "\n")

    def demander(self, prompt: str, modele: str, taille: int, negatif: str = "", graine: int | None = None) -> dict:
        prompt, negatif = prompt.strip()[:500], negatif.strip()[:300]
        if modele not in MODELES or taille not in MODELES[modele]["tailles"]:
            raise ValueError("modèle ou taille non pris en charge")
        empreinte = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        raison = filtrer(prompt)   # le prompt négatif n'est pas filtré : « nude » y sert justement à l'éviter
        if raison:
            self.journal(evenement="refus", modele=modele, taille=taille, longueur=len(prompt), empreinte=empreinte,
                         raison=raison)
            raise PermissionError(raison)
        if len(list((self.racine / "file").glob("*.json"))) >= FILE_MAX:
            raise OverflowError(f"file pleine ({FILE_MAX} demandes)")
        ident = time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(4)
        m = MODELES[modele]
        demande = {"id": ident, "modele": modele, "prompt": prompt, "negatif": negatif, "largeur": taille,
                   "hauteur": taille, "etapes": m["etapes"], "cfg": m["cfg"],
                   "graine": graine if graine is not None else secrets.randbelow(2**31), "demande_le": time.time()}
        tmp = self.racine / "file" / f".{ident}.tmp"
        tmp.write_text(json.dumps(demande, ensure_ascii=False), encoding="utf-8")
        tmp.rename(self.racine / "file" / f"{ident}.json")     # le travailleur ne voit que des demandes complètes
        self.journal(evenement="demande", id=ident, modele=modele, taille=taille, longueur=len(prompt),
                     empreinte=empreinte)
        return {"id": ident, "etat": "en_attente"}

    def lister(self, n: int = 30) -> list[dict]:
        sortie = []
        for etat in ("en_cours", "file", "fait", "echec"):
            for f in (self.racine / etat).glob("*.json"):
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                d["etat"] = {"file": "en_attente"}.get(etat, etat)
                sortie.append(d)
        sortie.sort(key=lambda d: d.get("demande_le", 0), reverse=True)
        return sortie[:n]

    def fichier(self, ident: str) -> Path | None:
        if not re.fullmatch(r"\d{8}T\d{6}-[0-9a-f]{8}", ident):
            return None
        f = self.racine / "fait" / f"{ident}.png"
        return f if f.is_file() else None

    def annuler(self, ident: str) -> bool:
        if not re.fullmatch(r"\d{8}T\d{6}-[0-9a-f]{8}", ident):
            return False
        f = self.racine / "file" / f"{ident}.json"
        try:
            f.rename(self.racine / "echec" / f"{ident}.json")
        except FileNotFoundError:
            return False
        self.journal(evenement="annulee", id=ident)
        return True
