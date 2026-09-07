# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""Freebox TV — parsing de la playlist M3U (variante standard uniquement)."""
from api.main import parse_playlist

SAMPLE = """#EXTM3U
#EXTINF:0,2 - France 2 (auto)
rtsp://mafreebox.freebox.fr/fbxtv_pub/stream?namespace=1&service=201&flavour=auto
#EXTINF:0,2 - France 2 (HD)
rtsp://mafreebox.freebox.fr/fbxtv_pub/stream?namespace=1&service=201&flavour=hd
#EXTINF:0,2 - France 2 (standard)
rtsp://mafreebox.freebox.fr/fbxtv_pub/stream?namespace=1&service=201&flavour=sd
#EXTINF:0,5 - France 5 (standard)
rtsp://mafreebox.freebox.fr/fbxtv_pub/stream?namespace=1&service=205&flavour=sd
#EXTINF:0,650 - France 24 (HD)
rtsp://mafreebox.freebox.fr/fbxtv_pub/stream?namespace=1&service=650&flavour=hd
"""


def test_ne_garde_que_standard():
    ch = parse_playlist(SAMPLE)
    # France 2 (3 variantes) → une seule entrée (sd) ; France 5 (sd) ; France 24 (HD) exclue.
    assert set(ch.keys()) == {"201", "205"}
    assert ch["201"]["name"] == "France 2" and ch["201"]["lcn"] == 2
    assert ch["201"]["url"].endswith("flavour=sd")
    assert ch["205"]["name"] == "France 5" and ch["205"]["lcn"] == 5
    assert "650" not in ch          # seulement en HD → écartée


def test_ignore_lignes_non_rtsp_et_vides():
    assert parse_playlist("#EXTM3U\n\n# commentaire\n") == {}
    # EXTINF sans URL rtsp derrière → ignorée.
    assert parse_playlist("#EXTINF:0,1 - X (standard)\nhttp://pas-rtsp/\n") == {}


def test_id_est_le_service():
    ch = parse_playlist(SAMPLE)
    assert ch["201"]["id"] == "201"
