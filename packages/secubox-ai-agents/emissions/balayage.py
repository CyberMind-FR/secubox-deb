# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Balayage final bloquant avant publication (#4058, Task 12).

Tout ce qui part sur les billets (titre, chapeau, répliques dites, chronologie, diapositives et captures) passe ici.
Un seul constat → publication refusée. Motifs : `ipv4`, `ipv6`, `nom_interne`, `jeton`, `ocr_echec` (une image que
l'OCR ne sait pas lire n'est jamais publiée : on ne publie pas ce qu'on n'a pas pu relire). Le texte trouvé n'est
JAMAIS recopié dans le résultat : seulement où (`texte[3]`, `image:diapo-02.png`) et quel motif.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

NOMS_INTERNES = Path(os.environ.get("SECUBOX_AI_EMISSIONS_NOMS")
                     or Path.home() / ".config/secubox-ai-emissions/noms-internes.txt")
NOMS_DEFAUT = [f"gk{i}" for i in range(8)] + [".lan", ".local", ".internal", ".home.arpa"]

_V4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.]*\d)")
_V6 = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w+)?(?![0-9A-Za-z:])")
_JETON = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}|\bsk-[A-Za-z0-9_-]{8,}|\bghp_[A-Za-z0-9]{8,}"
                    r"|(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9+/=_-])")


def lire_noms_internes(chemin: Path = NOMS_INTERNES) -> List[str]:
    """Un nom par ligne (`#` = commentaire) ; un nom qui commence par « . » est un suffixe de domaine local."""
    try:
        lignes = Path(chemin).read_text(encoding="utf-8").splitlines()
    except OSError:
        return list(NOMS_DEFAUT)
    noms = [x.split("#", 1)[0].strip() for x in lignes]
    return [x for x in noms if x] or list(NOMS_DEFAUT)


def _ipv4(t: str) -> bool:
    for m in _V4.findall(t):
        try:
            ipaddress.IPv4Address(m)
            return True
        except ValueError:
            continue
    return False


def _ipv6(t: str) -> bool:
    for m in _V6.findall(t):
        if m.count(":") < 2:
            continue
        try:
            ipaddress.IPv6Address(m.split("%", 1)[0])
            return True
        except ValueError:
            continue
    return False


def _motif_nom(nom: str) -> re.Pattern:
    if nom.startswith("."):
        return re.compile(r"[\w-]" + re.escape(nom) + r"(?![\w-])", re.I)
    return re.compile(r"(?<![\w-])" + re.escape(nom) + r"(?![\w-])", re.I)


def motifs_texte(texte: str, noms_internes: Iterable[str]) -> List[str]:
    t = texte or ""
    vu: List[str] = []
    # l'OCR lit parfois « 192,0.2.7 » ou des espaces autour des points : on relit aussi la forme recollée
    variantes = (t, re.sub(r"\s*[.,]\s*(?=\d)", ".", t))
    if any(_ipv4(v) for v in variantes):
        vu.append("ipv4")
    if _ipv6(t):
        vu.append("ipv6")
    if any(_motif_nom(n).search(t) for n in noms_internes if n):
        vu.append("nom_interne")
    if _JETON.search(t):
        vu.append("jeton")
    return vu


def ocr_tesseract(image: Path) -> str:
    """Texte lu par `tesseract -l fra+eng`. Lève RuntimeError si l'outil manque ou échoue."""
    exe = shutil.which("tesseract")
    if not exe:
        raise RuntimeError("tesseract absent")
    r = subprocess.run([exe, str(image), "stdout", "-l", "fra+eng"], capture_output=True, timeout=120, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"tesseract rc {r.returncode}")
    return r.stdout.decode("utf-8", "replace")


def balayer(textes: List[str], images: List[Path], noms_internes: List[str],
            ocr: Optional[Callable[[Path], str]] = None) -> List[Dict[str, str]]:
    """`[{"ou", "motif"}]` ; vide = publiable. `ocr` remplaçable (tests) ; par défaut tesseract."""
    lire = ocr or ocr_tesseract
    sortie: List[Dict[str, str]] = []
    for i, t in enumerate(textes):
        sortie += [{"ou": f"texte[{i}]", "motif": m} for m in motifs_texte(t, noms_internes)]
    for img in images:
        ou = f"image:{Path(img).name}"
        try:
            lu = lire(Path(img))
        except Exception:  # noqa: BLE001 — toute erreur de lecture bloque : on ne publie pas l'illisible
            lu = None
        if lu is None:
            sortie.append({"ou": ou, "motif": "ocr_echec"})
            continue
        sortie += [{"ou": ou, "motif": m} for m in motifs_texte(lu, noms_internes)]
    return sortie
