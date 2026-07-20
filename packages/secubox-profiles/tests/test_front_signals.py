# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests signaux du front
CyberMind — https://cybermind.fr
"""
from __future__ import annotations


def test_vhost_signals_computes_age_and_passes_conns():
    from api.front_signals import vhost_signals
    raw = {"a.gk2": {"last_request_ts": 100.0, "active_conns": 0},
           "b.gk2": {"last_request_ts": None, "active_conns": 3}}
    sig = vhost_signals(reader=lambda: raw, now=lambda: 250.0)
    assert sig["a.gk2"].last_request_age == 150.0
    assert sig["a.gk2"].active_conns == 0
    assert sig["b.gk2"].last_request_age is None   # unknown ts stays unknown
    assert sig["b.gk2"].active_conns == 3


def test_unknown_conns_stay_none():
    from api.front_signals import vhost_signals
    raw = {"a.gk2": {"last_request_ts": 10.0}}   # no active_conns key
    sig = vhost_signals(reader=lambda: raw, now=lambda: 10.0)
    assert sig["a.gk2"].active_conns is None
