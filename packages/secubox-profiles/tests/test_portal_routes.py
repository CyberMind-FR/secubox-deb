# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — tests mémoire durable des routes portail
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import json


def test_remember_then_recall_roundtrips(tmp_path):
    from api import portal_routes as pr
    store = tmp_path / "portal-routes.json"
    pr.remember("yacy.gk2.secubox.in", ["192.168.1.200", 9080], path=store)
    assert pr.recall("yacy.gk2.secubox.in", path=store) == ["192.168.1.200", 9080]


def test_recall_unknown_domain_is_none(tmp_path):
    from api import portal_routes as pr
    store = tmp_path / "portal-routes.json"
    assert pr.recall("nope.gk2", path=store) is None


def test_remember_none_is_noop(tmp_path):
    from api import portal_routes as pr
    store = tmp_path / "portal-routes.json"
    pr.remember("d.gk2", None, path=store)
    assert not store.exists()


def test_remember_upserts_without_clobbering_others(tmp_path):
    from api import portal_routes as pr
    store = tmp_path / "portal-routes.json"
    pr.remember("a.gk2", ["10.0.0.1", 80], path=store)
    pr.remember("b.gk2", ["10.0.0.2", 81], path=store)
    pr.remember("a.gk2", ["10.0.0.1", 9080], path=store)  # re-remember with new port
    data = json.loads(store.read_text())
    assert data == {"a.gk2": ["10.0.0.1", 9080], "b.gk2": ["10.0.0.2", 81]}


def test_recall_tolerates_corrupt_or_nondict_file(tmp_path):
    from api import portal_routes as pr
    store = tmp_path / "portal-routes.json"
    store.write_text("not json {{{")
    assert pr.recall("a.gk2", path=store) is None
    store.write_text('["a", "list", "not", "a", "dict"]')
    assert pr.recall("a.gk2", path=store) is None


def test_remembered_file_is_0644(tmp_path):
    from api import portal_routes as pr
    import stat
    store = tmp_path / "portal-routes.json"
    pr.remember("a.gk2", ["10.0.0.1", 80], path=store)
    assert stat.S_IMODE(store.stat().st_mode) == 0o644
