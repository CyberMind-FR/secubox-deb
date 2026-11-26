# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Écoute de Jarvis (#3999) : gardes de la route et transcription réelle si whisper.cpp est installé."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "relais"))
import agents_relais  # noqa: E402

HOTE = "127.0.0.1:8098"


def _local(request: Request):
    if request.headers.get("host") != HOTE:
        raise HTTPException(404, "introuvable")


@pytest.fixture()
def client():
    app = FastAPI()
    agents_relais.brancher(app, _local)
    return TestClient(app, base_url=f"http://{HOTE}")


URL = agents_relais.API3 + "/ecoute"


def test_hote_public_refuse(client):
    r = client.post(URL, content=b"x" * 2000, headers={"Host": "ai.gk0.secubox.in", "Content-Type": "audio/webm",
                                                         "X-SBX-Geste": "1"})
    assert r.status_code == 404


def test_geste_obligatoire(client):
    r = client.post(URL, content=b"x" * 2000, headers={"Content-Type": "audio/webm"})
    assert r.status_code == 403


def test_type_audio_obligatoire(client):
    r = client.post(URL, content=b"x" * 2000, headers={"Content-Type": "text/plain", "X-SBX-Geste": "1"})
    assert r.status_code == 415


def test_audio_trop_long(client, monkeypatch):
    monkeypatch.setattr(agents_relais, "AUDIO_MAX", 5000)
    if not (agents_relais.WHISPER.is_file() and agents_relais.WHISPER_MODELE.is_file()):
        pytest.skip("whisper.cpp non installé")
    r = client.post(URL, content=b"x" * 6000, headers={"Content-Type": "audio/webm", "X-SBX-Geste": "1"})
    assert r.status_code == 413


def test_transcription_reelle(client, tmp_path):
    piper = Path.home() / "AI/venv-piper/bin/piper"
    voix = Path.home() / "AI/models/piper/fr_FR-siwis-medium.onnx"
    if not (agents_relais.WHISPER.is_file() and agents_relais.WHISPER_MODELE.is_file() and piper.is_file()
            and shutil.which("ffmpeg")):
        pytest.skip("whisper.cpp, Piper ou ffmpeg absent")
    wav = tmp_path / "q.wav"
    subprocess.run([str(piper), "-m", str(voix), "-f", str(wav)], input="Bonjour Jarvis, quel est l'état du pare-feu sur la box ?".encode(),
                   check=True, capture_output=True)
    r = client.post(URL, content=wav.read_bytes(), headers={"Content-Type": "audio/wav", "X-SBX-Geste": "1"})
    assert r.status_code == 200, r.text
    texte = r.json()["texte"].lower()
    assert "jarvis" in texte and "pare-feu" in texte
