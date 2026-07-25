# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "secubox-annuaire"))
import pytest
from assist import escalate as esc


def test_ephemeral_identity_flagged_and_unique():
    a = esc.mint_ephemeral_identity()
    b = esc.mint_ephemeral_identity()
    assert a["ephemeral"] is True
    assert a["did"].startswith("did:plc:") and len(a["did"]) == 40
    assert a["did"] != b["did"]
    assert len(bytes.fromhex(a["priv_hex"])) == 32


def test_peer_ip_must_be_in_ephemeral_range():
    argv = esc.add_ephemeral_peer("PUBKEY=", "1.2.3.4:51820", "10.11.0.7")
    assert isinstance(argv, list) and "10.11.0.7" in argv
    assert not any(";" in a for a in argv)  # never a shell string
    with pytest.raises(esc.EscalateError):
        esc.add_ephemeral_peer("PUBKEY=", "1.2.3.4:51820", "10.99.1.5")  # wrong range


def test_teardown_returns_argv_lists():
    cmds = esc.teardown("10.11.0.7", "did:plc:" + "a" * 32)
    assert cmds and all(isinstance(c, list) for c in cmds)
