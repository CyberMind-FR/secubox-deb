# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Task 11 (#4058) : montage, chronologie, MP4 à la demande — sur de VRAIS petits MP3 produits par ffmpeg."""
import json
import shutil
import subprocess
import sys

import pytest

from conftest import RACINE

pytestmark = pytest.mark.skipif(not (shutil.which("ffmpeg") and shutil.which("ffprobe")),
                                reason="ffmpeg/ffprobe absents : montage non testé")

from emissions.montage import PAUSE_S, duree, monter, video  # noqa: E402

REPLIQUES = [{"rang": 0, "voix": 1, "texte": "Bonjour.", "statut": "verifiee"},
             {"rang": 1, "voix": 2, "texte": "Chiffre inventé.", "statut": "retiree"},
             {"rang": 2, "voix": 2, "texte": "1 204 bans.", "statut": "verifiee"},
             {"rang": 3, "voix": 1, "texte": "Et ensuite ?", "statut": "ia_seule"}]
DIAPOS = {0: "g-phases", 2: "g-bans", 3: "g-phases"}


def _mp3(chemin, secondes, freq):
    subprocess.run(["ffmpeg", "-nostdin", "-loglevel", "error", "-f", "lavfi", "-i",
                    f"sine=frequency={freq}:duration={secondes}:sample_rate=24000", "-c:a", "libmp3lame",
                    "-b:a", "64k", str(chemin)], check=True)
    return chemin


@pytest.fixture
def voix(tmp_path):
    d = tmp_path / "voix"
    d.mkdir()
    return [_mp3(d / "0-a.mp3", 1.0, 440), _mp3(d / "2-b.mp3", 1.5, 660), _mp3(d / "3-c.mp3", 0.7, 550)]


def _sonde(p):
    r = subprocess.run(["ffprobe", "-v", "error", "-show_streams", "-show_format", "-of", "json", str(p)],
                       capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def test_chronologie_sans_retiree(tmp_path, voix):
    _, chrono = monter(voix, REPLIQUES, DIAPOS, tmp_path / "emission.mp3")
    assert [e["replique"] for e in chrono] == ["Bonjour.", "1 204 bans.", "Et ensuite ?"]
    assert all("inventé" not in e["replique"] for e in chrono)
    assert [e["diapo"] for e in chrono] == [0, 1, 0]          # rang des images : ordre de première apparition


def test_pauses_045(tmp_path, voix):
    mp3, chrono = monter(voix, REPLIQUES, DIAPOS, tmp_path / "emission.mp3")
    for a, b in zip(chrono, chrono[1:]):
        assert abs(b["debut_s"] - a["fin_s"] - 0.45) <= 0.02
    for e, f in zip(chrono, voix):
        assert abs((e["fin_s"] - e["debut_s"]) - duree(f)) <= 0.02
    assert abs(duree(mp3) - chrono[-1]["fin_s"]) <= 0.1
    assert PAUSE_S == 0.45


def test_chronologie_acceptee_par_billets(tmp_path, voix):
    _, chrono = monter(voix, REPLIQUES, DIAPOS, tmp_path / "emission.mp3")
    sys.path.insert(0, str(RACINE / "packages/secubox-billets"))
    try:
        from api.models import valider_chronologie
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"modèle des billets non importable : {exc}")
    finally:
        sys.path.pop(0)
    assert valider_chronologie(json.dumps(chrono)) == chrono


def test_mp3_format(tmp_path, voix):
    mp3, _ = monter(voix, REPLIQUES, DIAPOS, tmp_path / "emission.mp3")
    s = _sonde(mp3)["streams"][0]
    assert s["codec_name"] == "mp3" and s["channels"] == 1 and s["sample_rate"] == "44100"
    assert 120000 <= int(s.get("bit_rate") or _sonde(mp3)["format"]["bit_rate"]) <= 136000


def test_mp4_seulement_a_la_demande(tmp_path, voix):
    mp3, chrono = monter(voix, REPLIQUES, DIAPOS, tmp_path / "emission.mp3")
    assert not list(tmp_path.rglob("*.mp4"))
    images = []
    for i, couleur in enumerate(("red", "blue")):
        p = tmp_path / f"d{i}.png"
        subprocess.run(["ffmpeg", "-nostdin", "-loglevel", "error", "-f", "lavfi", "-i",
                        f"color=c={couleur}:s=321x181:d=1", "-frames:v", "1", str(p)], check=True)
        images.append(p)
    mp4 = video(mp3, chrono, images, tmp_path / "emission.mp4")
    s = _sonde(mp4)
    assert {x["codec_type"] for x in s["streams"]} == {"audio", "video"}
    assert abs(float(s["format"]["duration"]) - duree(mp3)) <= 0.3


def test_nombre_de_fichiers_incoherent(tmp_path, voix):
    with pytest.raises(ValueError):
        monter(voix[:2], REPLIQUES, DIAPOS, tmp_path / "emission.mp3")
