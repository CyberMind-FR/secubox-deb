# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: Voice — commandes courantes reconnues sur la box (#1656).

Avant la transcription complète (whisper, 6-15 s), /asr essaie une GRAMMAIRE
FERMÉE avec Vosk : « mets la radio en pause », « ouvre atelier »… reconnus en
~0,7 s sur gk2. Si le résultat est exactement une commande, il part tel quel ;
sinon on retombe sur whisper. Le modèle (petit, français) reste chargé : 2 s
de chargement une fois, ~150 Mo de mémoire.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

LISTE = Path("/usr/share/secubox/voice/commandes.json")
MODELE = Path("/usr/share/secubox/voice/modeles/vosk-fr")
BIBLIO = "/usr/lib/secubox/voice-moteur/python"

_verrou = threading.Lock()
_modele = None


def phrases(liste: dict) -> list[str]:
    esp = list(liste.get("espaces", {}))
    return (list(liste.get("media", {})) + list(liste.get("ferme", [])) + esp
            + [f"{p} {e}" for p in liste.get("prefixes_espace", []) for e in esp])


def _norme(s: str) -> str:
    return " ".join(s.replace("[unk]", " ").lower().split())


def charge_liste(p: Path = LISTE) -> list[str]:
    try:
        return phrases(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return []


def disponible() -> bool:
    return MODELE.is_dir() and Path(BIBLIO, "vosk").is_dir() and bool(charge_liste())


def _vosk():
    global _modele
    with _verrou:
        if _modele is None:
            if BIBLIO not in sys.path:
                sys.path.insert(0, BIBLIO)
            import vosk                                         # noqa: PLC0415
            vosk.SetLogLevel(-1)
            _modele = (vosk, vosk.Model(str(MODELE)))
        return _modele


def reconnait(audio: bytes, delai_s: int = 10) -> Optional[str]:
    """Le texte si l'audio est EXACTEMENT une commande de la liste, sinon None.
    Toute erreur (modèle absent, audio illisible) → None : whisper prendra le relais."""
    liste = charge_liste()
    if not liste or not disponible():
        return None
    try:
        pcm = subprocess.run(
            ["ffmpeg", "-nostdin", "-loglevel", "error", "-i", "pipe:0", "-t", "10",
             "-ar", "16000", "-ac", "1", "-f", "s16le", "pipe:1"],
            input=audio, capture_output=True, timeout=delai_s, check=True).stdout
        vosk, modele = _vosk()
        r = vosk.KaldiRecognizer(modele, 16000, json.dumps(liste + ["[unk]"]))
        r.AcceptWaveform(pcm)
        texte = _norme(json.loads(r.FinalResult()).get("text", ""))
    except Exception:  # noqa: BLE001
        return None
    return texte if texte in liste else None
