# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""ai-gateway :: entrées multimodales (#3571) — validation, bornes et souveraineté."""
import base64
import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location("mm", Path(__file__).parent.parent / "api" / "multimodal.py")
mm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mm)

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\0" * 32).decode()


def _msg(*parties):
    return [{"role": "user", "content": [{"type": "text", "text": "décris"}, *parties]}]


def _image(url):
    return {"type": "image_url", "image_url": {"url": url}}


def test_texte_seul_aucune_modalite():
    assert mm.modalites([{"role": "user", "content": "bonjour"}]) == set()
    assert mm.texte_de([{"type": "text", "text": "a"}, _image("x"), {"type": "text", "text": "b"}]) == "a\nb"


def test_image_data_acceptee():
    assert mm.modalites(_msg(_image(f"data:image/png;base64,{PNG}"))) == {"image"}


@pytest.mark.parametrize("url", [
    "https://exemple.org/chat.png",          # la box ne télécharge rien pour un client
    "file:///etc/secubox/users.json",        # ni ne lit ses propres fichiers
    "/etc/shadow",
    f"data:image/svg+xml;base64,{PNG}",      # type hors liste
    "data:image/png;base64,@@@",             # base64 illisible
])
def test_image_refusee(url):
    with pytest.raises(mm.MediaRefuse):
        mm.modalites(_msg(_image(url)))


def test_image_trop_grosse():
    gros = base64.b64encode(b"\0" * (mm.MAX_OCTETS_MEDIA + 1)).decode()
    with pytest.raises(mm.MediaRefuse, match="Mo au plus"):
        mm.modalites(_msg(_image(f"data:image/png;base64,{gros}")))


def test_trop_de_parties():
    parties = [_image(f"data:image/png;base64,{PNG}")] * (mm.MAX_PARTIES_MEDIA + 1)
    with pytest.raises(mm.MediaRefuse, match="parties au plus"):
        mm.modalites(_msg(*parties))


def test_audio_donnees_seulement():
    ok = {"type": "input_audio", "input_audio": {"data": PNG, "format": "wav"}}
    assert mm.modalites(_msg(ok)) == {"audio"}
    for mauvais in ({"data": PNG, "format": "ogg"},
                    {"url": "file:///etc/passwd", "format": "wav"},
                    {"data": PNG, "url": "https://exemple.org/a.wav", "format": "wav"}):
        with pytest.raises(mm.MediaRefuse):
            mm.modalites(_msg({"type": "input_audio", "input_audio": mauvais}))


@pytest.mark.parametrize("cle", ["input_video", "video_url"])
def test_video_data_acceptee(cle):
    assert mm.modalites(_msg({"type": cle, cle: {"url": f"data:video/mp4;base64,{PNG}"}})) == {"video"}


@pytest.mark.parametrize("url", ["https://exemple.org/v.mp4", "file:///data/videos/v.mp4",
                                 f"data:video/x-flv;base64,{PNG}"])
def test_video_refusee(url):
    with pytest.raises(mm.MediaRefuse):
        mm.modalites(_msg({"type": "input_video", "input_video": {"url": url}}))


def test_type_de_partie_inconnu_refuse():
    with pytest.raises(mm.MediaRefuse):
        mm.modalites(_msg({"type": "file", "file": {}}))


def test_modalites_moteur_rien_suppose():
    assert mm.modalites_moteur({}) == {"text": True, "image": False, "audio": False, "video": False}
    assert mm.modalites_moteur({"modalities": {"vision": True, "video": True}}) == \
        {"text": True, "image": True, "audio": False, "video": True}
