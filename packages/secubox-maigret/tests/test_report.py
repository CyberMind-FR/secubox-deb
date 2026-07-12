# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""maigret PDF report generator — build a valid, styled PDF from a lookup record."""
import json

import pytest

fpdf = pytest.importorskip("fpdf")  # skip cleanly if fpdf2 isn't in the env
from api import report  # noqa: E402


def _rec(raw, **kw):
    base = {"id": "01ab23cd", "username": "torvalds", "status": "completed",
            "started_at": "2026-07-12T13:00:00Z", "finished_at": "2026-07-12T13:02:00Z",
            "results": {"raw": raw if isinstance(raw, str) else json.dumps(raw)}}
    base.update(kw)
    return base


SAMPLE = {
    "GitHub": {"url_user": "https://github.com/torvalds", "rank": 10,
               "status": {"status": "Claimed", "tags": ["coding"],
                          "ids": {"name": "Linus Torvalds", "company": "Linux Foundation"}}},
    "Instagram": {"url_user": "https://instagram.com/torvalds/", "rank": 5,
                  "status": {"status": "Claimed", "tags": ["social"], "ids": {}}},
    "NotFound": {"status": {"status": "Available"}},
}


def test_build_pdf_is_valid_pdf():
    pdf = report.build_pdf(_rec(SAMPLE))
    assert pdf[:4] == b"%PDF" and len(pdf) > 1000


def test_only_claimed_accounts_counted():
    data = report._parse(_rec(SAMPLE)["results"])
    claimed = report._claimed(data)
    assert {a["site"] for a in claimed} == {"GitHub", "Instagram"}   # 'Available' dropped
    gh = next(a for a in claimed if a["site"] == "GitHub")
    assert gh["category"] == "coding" and "Linus Torvalds" in gh["details"]


def test_empty_and_malformed_never_crash():
    assert report.build_pdf(_rec(""))[:4] == b"%PDF"            # no results
    assert report.build_pdf(_rec("not json{"))[:4] == b"%PDF"   # malformed
    assert report.build_pdf({"username": "x"})[:4] == b"%PDF"   # no results key


def test_unicode_in_profile_data_is_safe():
    data = {"Medium": {"url_user": "https://medium.com/@x", "rank": 1,
                       "status": {"status": "Claimed", "tags": ["blog"],
                                  "ids": {"name": "José Ñoño 日本語"}}}}
    assert report.build_pdf(_rec(data))[:4] == b"%PDF"          # latin-1 sanitised, no crash
