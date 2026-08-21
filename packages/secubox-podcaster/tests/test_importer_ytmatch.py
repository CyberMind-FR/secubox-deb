# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""#1101 — une URL YouTube collée dans « ajouter un flux » doit être reconnue
comme un import (yt-dlp), pas parsée en RSS."""
from api.importer import is_youtube_url


def test_playlist_is_youtube():
    assert is_youtube_url("https://www.youtube.com/playlist?list=PLOM3KtkUpYg")


def test_watch_is_youtube():
    assert is_youtube_url("https://youtube.com/watch?v=dQw4w9WgXcQ")


def test_youtu_be_is_youtube():
    assert is_youtube_url("https://youtu.be/dQw4w9WgXcQ")


def test_mobile_is_youtube():
    assert is_youtube_url("https://m.youtube.com/watch?v=dQw4w9WgXcQ")


def test_rss_feed_is_not_youtube():
    assert not is_youtube_url("https://radiofrance.fr/podcasts/rss.xml")


def test_garbage_is_not_youtube():
    assert not is_youtube_url("pas une url")


def test_lookalike_host_is_not_youtube():
    # un domaine qui CONTIENT youtube.com sans en être : pas d'import à tort.
    assert not is_youtube_url("https://youtube.com.evil.example/watch?v=x")
