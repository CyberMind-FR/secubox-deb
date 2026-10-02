# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#1871 : robots.txt explicite du Hall — public lisible, privé exclu."""
from pathlib import Path

R = Path(__file__).resolve().parents[1]


def _regles():
    out = {"allow": [], "disallow": []}
    for l in (R / "www" / "hall" / "robots.txt").read_text(encoding="utf8").splitlines():
        l = l.split("#", 1)[0].strip()
        if l.lower().startswith("allow:"):
            out["allow"].append(l.split(":", 1)[1].strip())
        elif l.lower().startswith("disallow:"):
            out["disallow"].append(l.split(":", 1)[1].strip())
    return out


def test_le_public_se_lit_et_le_prive_est_exclu():
    r = _regles()
    assert "/" in r["allow"] and "/api/v1/webos/public/" in r["allow"]
    for prive in ("/api/", "/i/", "/vault/", "/coffre/", "/__console/", "/login.html"):
        assert prive in r["disallow"], prive
    assert "/" not in r["disallow"]                    # jamais « tout interdit » ni « tout ouvert au privé »


def test_nginx_sert_robots_txt_et_le_paquet_l_installe():
    assert "location = /robots.txt" in (R / "nginx" / "hall.vhost.conf").read_text(encoding="utf8")
    assert "robots.txt" in (R / "debian" / "rules").read_text(encoding="utf8")
