# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "lxc" / "app"))
from ytid import video_id

def test_watch():
    assert video_id("https://www.youtube.com/watch?v=dQw4w9WgXcQ") == "dQw4w9WgXcQ"

def test_youtu_be():
    assert video_id("https://youtu.be/dQw4w9WgXcQ?t=10") == "dQw4w9WgXcQ"

def test_shorts():
    assert video_id("https://www.youtube.com/shorts/dQw4w9WgXcQ") == "dQw4w9WgXcQ"

def test_non_youtube():
    assert video_id("https://vimeo.com/12345") is None

def test_garbage():
    assert video_id("pas une url") is None
