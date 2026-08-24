# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — jointure id↔domaine (api.idmap.resolve)."""
from api.idmap import resolve


def test_same_origin():
    assert resolve({"id": "radio", "same_origin": True}) == (None, True)


def test_explicit_domain():
    assert resolve({"id": "nc", "domain": "nextcloud.gk2.secubox.in"}) == (
        "nextcloud.gk2.secubox.in",
        False,
    )


def test_graceful_fallback_convention():
    assert resolve({"id": "waf"}) == ("waf.gk2.secubox.in", False)
