# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: toolbox :: bundle builder tests (#620)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secubox_toolbox import bundle  # noqa: E402


def test_build_bundle_shape_and_failopen_level():
    b = bundle.build_bundle("abc123", is_wg=False)
    assert b["v"] == 1
    assert b["client_id"] == "abc123"
    assert b["level"] in ("r0", "r1", "r2", "r3", "r4")   # fail-open default r1
    assert b["report_url"] == bundle.REPORT_URL_CAPTIVE
    assert isinstance(b["tracker_patterns"], list) and b["tracker_patterns"]


def test_build_bundle_wg_report_url():
    b = bundle.build_bundle("deadbeef", is_wg=True)
    assert b["report_url"] == bundle.REPORT_URL_PUBLIC + "?mh=deadbeef"


def test_build_bundle_no_pin_when_absent(monkeypatch):
    monkeypatch.setattr(bundle, "PIN_FILE", bundle.Path("/nonexistent/pin.json"))
    assert bundle.build_bundle("x").get("pin") == ""


def test_get_bundle_caches(monkeypatch):
    calls = {"n": 0}
    real = bundle.build_bundle

    def counting(cid, is_wg=False):
        calls["n"] += 1
        return real(cid, is_wg)

    monkeypatch.setattr(bundle, "build_bundle", counting)
    bundle._cache.clear()
    bundle.get_bundle("cli", False)
    bundle.get_bundle("cli", False)
    assert calls["n"] == 1            # second call served from cache


def test_loader_js_is_served_string():
    # Initial render must NOT depend on a load/DOMContentLoaded event — it uses
    # currentScript + ready() polling so it works even when injected mid-stream.
    # (#653: the popstate listener is for SPA re-assert, not initial render, so a
    # blanket "no addEventListener" ban is too broad — assert the real intent.)
    assert "DOMContentLoaded" not in bundle.LOADER_JS
    assert 'addEventListener("load"' not in bundle.LOADER_JS
    assert "__toolbox/bundle" in bundle.LOADER_JS   # fetch retained as fallback
    assert bundle.LOADER_JS.strip().startswith("(function()")
