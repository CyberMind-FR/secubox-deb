# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.cardlets import radio_cardlet, radio_cardlet_safe


def _fake_get(sock, path):
    if path.endswith("/current"):
        return {"silence": False, "offset_ms": 1000,
                "piste": {"titre": "Sade - No Ordinary Love", "auteur": "Sade", "coeurs": 1}}
    if path.endswith("/stats"):
        return {"auditeurs": 2, "pistes": 55, "visites": 52}
    return {}


def test_radio_cardlet_normalizes():
    c = radio_cardlet(_get=_fake_get)
    assert c["kind"] == "radio-now-playing"
    assert c["status"] == "online"
    assert c["content"]["title"] == "Sade - No Ordinary Love"
    assert c["content"]["subtitle"] == "Sade"
    m = {x["id"]: x["value"] for x in c["metrics"]}
    assert m["listeners"] == 2 and m["tracks"] == 55


def test_radio_cardlet_silence():
    def g(sock, path):
        return {"silence": True, "piste": {}} if path.endswith("/current") else {}
    c = radio_cardlet(_get=g)
    assert c["silence"] is True
    assert "silence" in c["content"]["title"].lower()


def test_radio_cardlet_safe_offline_when_unreachable():
    def boom(sock, path):
        raise OSError("no radio")
    c = radio_cardlet_safe(_get=boom)
    assert c["status"] == "offline"
    assert c["id"] == "radio"
