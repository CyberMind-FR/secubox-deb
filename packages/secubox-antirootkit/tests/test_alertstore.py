# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

from api import alertstore


def setup_function(_fn):
    alertstore.clear()


def teardown_function(_fn):
    alertstore.clear()


def test_append_and_recent_most_recent_first():
    alertstore.append({"exe": "/tmp/a"})
    alertstore.append({"exe": "/tmp/b"})
    assert [a["exe"] for a in alertstore.recent()] == ["/tmp/b", "/tmp/a"]


def test_recent_respects_limit():
    for i in range(5):
        alertstore.append({"exe": f"/tmp/{i}"})
    assert len(alertstore.recent(limit=2)) == 2


def test_store_is_capped_at_max_alerts():
    for i in range(alertstore.MAX_ALERTS + 10):
        alertstore.append({"exe": f"/tmp/{i}"})
    all_alerts = alertstore.recent(limit=alertstore.MAX_ALERTS + 10)
    assert len(all_alerts) == alertstore.MAX_ALERTS
    # oldest entries were dropped; the most recent one is still present
    assert all_alerts[0]["exe"] == f"/tmp/{alertstore.MAX_ALERTS + 9}"


def test_clear_empties_the_store():
    alertstore.append({"exe": "/tmp/a"})
    alertstore.clear()
    assert alertstore.recent() == []
