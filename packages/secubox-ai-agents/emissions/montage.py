# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Montage de l'émission (#4058, Task 11) : voix des répliques dites → un MP3, et la chronologie du diaporama.

Chaque voix est coupée à sa durée décodée puis suivie de 0,45 s de silence (sauf la dernière) : la
chronologie est donc exacte par construction. Puis `loudnorm` I=−16 LUFS, MP3 128k mono 44,1 kHz. Le format de la
chronologie est celui des billets (#4058, Task 1, `api/models.py:Replique`) : `diapo` = rang parmi les IMAGES du
billet, `replique` = texte dit (≤ 500 caractères). La vidéo n'est faite QUE par `video()`, sur demande.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

PAUSE_S = 0.45
LUFS = -16
REPLIQUE_MAX = 500          # borne du modèle des billets
DELAI_S = 600


def _ff(args: List[str]) -> None:
    r = subprocess.run(["ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y", *args],
                       capture_output=True, text=True, timeout=DELAI_S)
    if r.returncode:
        raise RuntimeError("ffmpeg a échoué : " + (r.stderr.strip().splitlines() or ["?"])[-1])


def duree(fichier: Path) -> float:
    """Durée DÉCODÉE (nombre d'échantillons à 44,1 kHz), pas celle du conteneur : un MP3 sans étiquette sans blanc
    annonce son remplissage d'encodeur (1,056 s pour 1,0 s), ce qui décalerait la chronologie."""
    r = subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-i", str(fichier), "-vn", "-ac", "1", "-ar", "44100",
                        "-f", "s16le", "-"], capture_output=True, timeout=DELAI_S, check=True)
    d = len(r.stdout) / 2 / 44100
    if not d > 0:
        raise RuntimeError(f"durée nulle : {Path(fichier).name}")
    return d


def _dites(repliques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted((r for r in repliques if r.get("statut") != "retiree"), key=lambda r: r["rang"])


def _ordre_images(dites: List[Dict[str, Any]], diapos: Dict[int, str]) -> Dict[str, int]:
    ordre: Dict[str, int] = {}
    for r in dites:
        g = diapos.get(r["rang"])
        if g is not None and g not in ordre:
            ordre[g] = len(ordre)
    return ordre


def ordre_images(repliques: List[Dict[str, Any]], diapos: Dict[int, str]) -> List[str]:
    """Les ids de graphiques dans l'ordre où les images doivent être jointes au billet (rang `diapo`)."""
    return list(_ordre_images(_dites(repliques), diapos))


def _atomique(sortie: Path, suffixe: str):
    sortie.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=sortie.parent, prefix=".montage-", suffix=suffixe)
    os.close(fd)
    return Path(tmp)


def monter(fichiers: List[Path], repliques: List[Dict[str, Any]], diapos: Dict[int, str],
           sortie: Path) -> Tuple[Path, List[Dict[str, Any]]]:
    dites = _dites(repliques)
    if len(fichiers) != len(dites) or not dites:
        raise ValueError(f"{len(fichiers)} fichiers voix pour {len(dites)} répliques dites")
    ordre = _ordre_images(dites, diapos)
    durees = [duree(f) for f in fichiers]
    filtres, chrono, t, diapo = [], [], 0.0, 0
    for i, (r, d) in enumerate(zip(dites, durees)):
        pause = f",apad=pad_dur={PAUSE_S}" if i < len(dites) - 1 else ""
        filtres.append(f"[{i}:a]aresample=44100,aformat=sample_fmts=fltp:channel_layouts=mono,"
                       f"atrim=duration={d:.6f}{pause}[a{i}]")
        diapo = ordre.get(diapos.get(r["rang"]), diapo)
        chrono.append({"debut_s": round(t, 3), "fin_s": round(t + d, 3), "diapo": diapo,
                       "replique": " ".join(str(r["texte"]).split())[:REPLIQUE_MAX]})
        t += d + PAUSE_S
    graphe = ";".join(filtres) + ";" + "".join(f"[a{i}]" for i in range(len(dites))) \
        + f"concat=n={len(dites)}:v=0:a=1,loudnorm=I={LUFS}:TP=-1.5:LRA=11[s]"
    tmp = _atomique(Path(sortie), ".mp3")
    try:
        _ff([x for f in fichiers for x in ("-i", str(f))] + ["-filter_complex", graphe, "-map", "[s]",
            "-c:a", "libmp3lame", "-b:a", "128k", "-ac", "1", "-ar", "44100", str(tmp)])
        os.chmod(tmp, 0o600)
        os.replace(tmp, sortie)
    finally:
        tmp.unlink(missing_ok=True)
    return Path(sortie), chrono


def video(mp3: Path, chronologie: List[Dict[str, Any]], images: List[Path], sortie: Path) -> Path:
    """MP4 (H.264 + AAC) : chaque image tenue du début de sa réplique au début de la suivante. Sur demande seulement."""
    if not chronologie:
        raise ValueError("chronologie vide")
    if any(not 0 <= e["diapo"] < len(images) for e in chronologie):
        raise ValueError("diapo hors des images fournies")
    total = duree(mp3)
    plages: List[List[Any]] = []
    for k, e in enumerate(chronologie):
        debut = 0.0 if k == 0 else e["debut_s"]
        fin = chronologie[k + 1]["debut_s"] if k + 1 < len(chronologie) else total
        if plages and plages[-1][0] == e["diapo"]:
            plages[-1][2] = fin
        else:
            plages.append([e["diapo"], debut, fin])
    tmp = _atomique(Path(sortie), ".mp4")
    liste = _atomique(Path(sortie), ".txt")
    try:
        lignes = ["ffconcat version 1.0"]
        for d, a, b in plages:
            lignes += [f"file '{Path(images[d]).resolve()}'", f"duration {max(b - a, 0.04):.3f}"]
        lignes.append(f"file '{Path(images[plages[-1][0]]).resolve()}'")
        liste.write_text("\n".join(lignes) + "\n", encoding="utf-8")
        _ff(["-f", "concat", "-safe", "0", "-i", str(liste), "-i", str(mp3), "-map", "0:v", "-map", "1:a",
             "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2,fps=25,format=yuv420p", "-c:v", "libx264",
             "-preset", "veryfast", "-tune", "stillimage", "-c:a", "aac", "-b:a", "128k", "-shortest",
             "-movflags", "+faststart", str(tmp)])
        os.chmod(tmp, 0o600)
        os.replace(tmp, sortie)
    finally:
        tmp.unlink(missing_ok=True)
        liste.unlink(missing_ok=True)
    return Path(sortie)
