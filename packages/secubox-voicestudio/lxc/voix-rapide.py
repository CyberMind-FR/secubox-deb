#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: VoiceStudio — voix rapide (#1917).

Petit serveur DANS le LXC, à côté du moteur : une voix française légère (Piper, via sherpa-onnx déjà installé pour
le moteur) qui parle en moins d'une seconde là où le grand modèle prend 110 à 140 s sur le processeur de la box.
Même contrat que le moteur (POST /v1/audio/speech, Bearer), pour que le module n'ait qu'à choisir l'adresse.

Sécurité : n'écoute que sur l'IP du LXC ; exige la clé d'API du moteur (comparaison à temps constant) ; texte borné ;
aucune écriture sur disque (l'audio est encodé par un tube ffmpeg).
"""
from __future__ import annotations

import hmac
import io
import json
import os
import subprocess
import threading
import wave
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODELE = os.environ.get("VOIX_RAPIDE_MODELE", "/opt/voix-rapide/modele")
HOTE = os.environ["VOIX_RAPIDE_HOTE"]
PORT = int(os.environ.get("VOIX_RAPIDE_PORT", "3901"))
CLE = os.environ.get("OMNIVOICE_API_KEY", "")
TEXTE_MAX = 4000
CORPS_MAX = 65536
FORMATS = {"wav": ("audio/wav", None), "mp3": ("audio/mpeg", "mp3"), "opus": ("audio/ogg", "ogg")}

_tts = None
_verrou = threading.Lock()       # un calcul à la fois (4 cœurs partagés avec le reste de la box)


def _charge():
    import sherpa_onnx
    nom = next(f for f in sorted(os.listdir(MODELE)) if f.endswith(".onnx"))
    vits = sherpa_onnx.OfflineTtsVitsModelConfig(
        model=os.path.join(MODELE, nom), tokens=os.path.join(MODELE, "tokens.txt"),
        data_dir=os.path.join(MODELE, "espeak-ng-data"))
    return sherpa_onnx.OfflineTts(sherpa_onnx.OfflineTtsConfig(
        model=sherpa_onnx.OfflineTtsModelConfig(vits=vits, num_threads=3, provider="cpu")))


def synthetiser(texte: str, format_: str) -> bytes:
    global _tts
    with _verrou:
        if _tts is None:
            _tts = _charge()
        a = _tts.generate(texte, sid=0, speed=1.0)
        taux = a.sample_rate
        pcm = bytearray()
        for x in a.samples:
            v = max(-1.0, min(1.0, x))
            pcm += int(v * 32767).to_bytes(2, "little", signed=True)
    tampon = io.BytesIO()
    with wave.open(tampon, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(taux)
        w.writeframes(bytes(pcm))
    wav = tampon.getvalue()
    codec = FORMATS[format_][1]
    if codec is None:
        return wav
    r = subprocess.run(["ffmpeg", "-loglevel", "error", "-f", "wav", "-i", "pipe:0", "-f", codec, "pipe:1"],
                       input=wav, capture_output=True, timeout=60, check=False)
    if r.returncode != 0 or not r.stdout:
        raise RuntimeError("encodage audio impossible")
    return r.stdout


class Poignee(BaseHTTPRequestHandler):
    server_version = "voix-rapide"

    def log_message(self, *_a) -> None:        # pas de journal par requête : le texte dit n'est jamais écrit
        return

    def _rep(self, code: int, corps: bytes, type_: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", type_)
        self.send_header("Content-Length", str(len(corps)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(corps)

    def _autorise(self) -> bool:
        h = self.headers.get("Authorization", "")
        return bool(CLE) and h.startswith("Bearer ") and hmac.compare_digest(h[7:].encode(), CLE.encode())

    def do_GET(self) -> None:                  # noqa: N802
        if self.path == "/health":
            self._rep(200, b'{"status":"ok","voix":"fr"}')
        else:
            self._rep(404, b'{"detail":"inconnu"}')

    def do_POST(self) -> None:                 # noqa: N802
        if self.path != "/v1/audio/speech":
            return self._rep(404, b'{"detail":"inconnu"}')
        if not self._autorise():
            return self._rep(401, b'{"detail":"API key required"}')
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if not 0 < n <= CORPS_MAX:
                return self._rep(413, b'{"detail":"corps invalide"}')
            d = json.loads(self.rfile.read(n))
            texte = str(d.get("input", "")).strip()
            format_ = str(d.get("response_format", "mp3"))
        except (ValueError, TypeError):
            return self._rep(400, b'{"detail":"JSON attendu"}')
        if not texte or len(texte) > TEXTE_MAX or format_ not in FORMATS:
            return self._rep(422, b'{"detail":"texte ou format invalide"}')
        try:
            audio = synthetiser(texte, format_)
        except Exception:                      # noqa: BLE001 — jamais de trace ni de texte dans la réponse
            return self._rep(500, b'{"detail":"synthese impossible"}')
        self._rep(200, audio, FORMATS[format_][0])


if __name__ == "__main__":
    ThreadingHTTPServer((HOTE, PORT), Poignee).serve_forever()
