# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Suggestions de classement (#2940, spec section 4) : table figée host_type -> zone.

Jamais appliqué automatiquement — une suggestion, montrée au propriétaire."""

_ZONE_PAR_HOST_TYPE = {
    "freebox_pop": "lan_allowed",
    "freebox_wifi": "lan_allowed",
    "printer": "lan_allowed",
    "networking_device": "lan_allowed",
    "television": "guest",
    "multimedia_device": "guest",
}


def zone_suggeree(host_type):
    return _ZONE_PAR_HOST_TYPE.get(host_type)
