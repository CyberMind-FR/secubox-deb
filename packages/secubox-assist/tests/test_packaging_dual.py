# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_nft_covers_ephemeral_iface_mesh_only():
    nft = (ROOT / "nft" / "secubox-assist.nft").read_text()
    assert 'iifname "wg-mesh"' in nft
    assert 'iifname "wg-ephemeral"' in nft
    assert "0.0.0.0" not in nft
    assert "policy drop" not in nft  # never a standalone drop table
