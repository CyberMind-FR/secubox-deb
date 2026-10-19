# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.classement import zone_suggeree


def test_table_de_correspondance_exacte_de_la_spec():
    assert zone_suggeree("freebox_pop") == "lan_allowed"
    assert zone_suggeree("freebox_wifi") == "lan_allowed"
    assert zone_suggeree("printer") == "lan_allowed"
    assert zone_suggeree("networking_device") == "lan_allowed"
    assert zone_suggeree("television") == "guest"
    assert zone_suggeree("multimedia_device") == "guest"
    assert zone_suggeree("workstation") is None
    assert zone_suggeree("laptop") is None
    assert zone_suggeree("smartphone") is None
    assert zone_suggeree("type_jamais_vu") is None
