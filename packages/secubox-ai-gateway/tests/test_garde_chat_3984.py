# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3984 : le relais de conversation n'est jamais ouvert sans session."""
import re
from pathlib import Path

SRC = (Path(__file__).resolve().parents[1] / "api" / "main.py").read_text()


def test_chat_completions_garde_jwt():
    assert re.search(r'@app\.post\("/v1/chat/completions", dependencies=\[Depends\(require_jwt\)\]\)', SRC)


def test_toute_route_ecrivante_est_gardee():
    for ligne in re.findall(r"@app\.(?:post|put|delete)\([^\n]*", SRC):
        assert "require_jwt" in ligne, ligne
