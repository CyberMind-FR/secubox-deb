# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from assist import joinlink as jl


def test_mint_join_shape_and_hash_only():
    j = jl.mint_join(ref="match:abc", ttl_s=900, base_url="https://assist.gk2.example")
    assert j["url"].startswith("https://assist.gk2.example/assist/join/")
    assert j["url"].endswith(j["token"])
    assert len(j["token_hash"]) == 64
    # the URL carries the secret; the hash is what you journal — and they differ
    assert j["token"] not in j["token_hash"]
    assert jl.verify_join(j["token"], j["token_hash"])
    assert not jl.verify_join("bogus", j["token_hash"])


def test_expiry():
    assert jl.is_expired("2026-07-25T10:00:00Z", now_ts="2026-07-25T11:00:00Z")
    assert not jl.is_expired("2026-07-25T12:00:00Z", now_ts="2026-07-25T11:00:00Z")
