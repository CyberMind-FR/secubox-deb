# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from assist import token


def test_mint_returns_token_and_64hex_hash():
    tok, h = token.mint()
    assert len(tok) >= 32
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)
    assert token.hash_token(tok) == h


def test_verify_roundtrip_and_reject():
    tok, h = token.mint()
    assert token.verify_token(tok, h)
    assert not token.verify_token("wrong", h)


def test_two_mints_differ():
    assert token.mint()[0] != token.mint()[0]
