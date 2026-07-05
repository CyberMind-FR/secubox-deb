# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox-Deb :: toolbox :: inline (SW-immune) banner script tests (#662).

The inline banner survives sites with a SERVICE WORKER (leparisien, cnn…): the
engine bakes the bundle + mh/wg/csp as JS literals so there is NO same-origin
fetch the SW can hijack. These tests pin that contract:
  * a valid baked `var bundle = {...}` (JSON), mh/wg/csp literals,
  * the 🔓 proof gated by csp,
  * NO currentScript (the #653 null-in-async bug) and NO fetch(,
  * `</script>` is escaped (no inline-script breakout),
  * get_bundle is called with (mh, bool(wg)).
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secubox_toolbox import api, bundle  # noqa: E402


def _baked_bundle(script: str) -> dict:
    """Extract + parse the baked `var bundle = {...};` JSON from an inline script.
    Undoes the `</` → `<\\/` breakout escaping before parsing as JSON."""
    m = re.search(r"var bundle = (\{.*?\});\n", script, re.S)
    assert m, "no baked `var bundle = {...};` in inline script"
    return json.loads(m.group(1).replace("<\\/", "</"))


def test_inline_bakes_valid_bundle_json():
    s = bundle.inline_script("x", wg=True, csp=True)
    b = _baked_bundle(s)
    assert b["v"] == 1
    assert b["client_id"] == "x"
    # wg=True → public report URL (proves get_bundle was called with wg=True)
    assert b["report_url"] == bundle.REPORT_URL_PUBLIC + "?mh=x"
    assert isinstance(b["tracker_patterns"], list) and b["tracker_patterns"]


def test_inline_bakes_mh_wg_csp_literals():
    s = bundle.inline_script("deadbeef", wg=True, csp=True)
    assert 'var mh = "deadbeef";' in s
    assert 'var wg = "1";' in s
    assert 'var csp = "1";' in s
    s0 = bundle.inline_script("deadbeef", wg=False, csp=False)
    assert 'var wg = "0";' in s0
    assert 'var csp = "0";' in s0


def test_inline_csp_literal_and_proof_logic():
    # The 🔓 literal lives in the shared render core, gated at runtime by
    # csp === "1". csp=1 → var csp = "1" so render shows the proof.
    s1 = bundle.inline_script("x", wg=False, csp=True)
    assert "\U0001f513" in s1            # 🔓 present in the render logic
    assert 'var csp = "1";' in s1        # runtime gate ON
    # csp=0 → gate OFF (no proof rendered), even though the literal is in core.
    s0 = bundle.inline_script("x", wg=False, csp=False)
    assert 'var csp = "0";' in s0


def test_inline_has_no_currentscript_no_fetch():
    # #653 root cause: document.currentScript is null in an async context. The
    # inline script MUST NOT read it, and MUST NOT fetch the BUNDLE at load time
    # (a SW would hijack a same-origin /__toolbox/bundle fetch → no banner). The
    # bundle is baked inline instead. (#740 toggle handlers DO fetch /set-level
    # etc., but only on a user click — not a load-time SW-hijackable resource.)
    s = bundle.inline_script("x", wg=True, csp=True)
    assert "currentScript" not in s
    assert "/__toolbox/bundle" not in s


def test_inline_keeps_guards_and_spa_hooks():
    s = bundle.inline_script("x", wg=True, csp=True)
    assert "window.__SBX_LOADER__" in s   # single-run guard
    assert 'getElementById("sbx-banner")' in s  # element-id guard
    assert "dismissed" in s
    assert "pushState" in s and "replaceState" in s and "popstate" in s
    assert "setInterval(ensure, 2000)" in s
    assert "countTrackers" in s


def test_inline_no_innerhtml_trusted_types_invariant():
    # #740 hard invariant: the client renderer is built ENTIRELY via mk() (DOM
    # API). NO innerHTML anywhere → not a Trusted-Types sink → renders on strict
    # CSP / Trusted-Types sites without any bypass. Do NOT regress this.
    s = bundle.inline_script("x", wg=True, csp=True)
    assert "innerHTML" not in s


def test_inline_arcade_hud_ids_and_toggles_preserved():
    # #620 redesign keeps every interactive control + live-count node id.
    s = bundle.inline_script("x", wg=True, csp=True)
    assert 'id:"sbx-lvl"' in s and 'cls:"sbx-lvl"' in s   # R0..R4 rank switch
    assert '"data-lvl"' in s and "/__toolbox/set-level" in s
    assert 'id:"sbx-tor"' in s and "/__toolbox/set-tor" in s      # Tor toggle
    assert 'id:"sbx-adg"' in s and "/__toolbox/set-adguard" in s  # Ad-Guard toggle
    assert 'id:"sbx-trk"' in s and "trackers" in s   # live tracker count node
    assert 'id:"sbx-ck"' in s and "cookies" in s     # live cookie count node
    # updateCounts still writes the exact text into the same ids (live 2s poll).
    assert '"🛰️ " + countTrackers' in s
    assert '"🍪 " + countCookies()' in s


def test_inline_three_cluster_responsive_fix():
    # The bug fix is structural: LEFT + RIGHT clusters are flex:0 0 auto (never
    # shrink); the MIDDLE evidence cluster is flex:1 1 auto; min-width:0;
    # overflow-x:auto (scrolls instead of pushing) → the close ✕ is ALWAYS on
    # screen. box-sizing:border-box keeps padding from overflowing the width.
    s = bundle.inline_script("x", wg=True, csp=True)
    assert "box-sizing:border-box" in s
    assert "flex:0 0 auto" in s      # pinned clusters
    assert "flex:1 1 auto" in s      # middle grows
    assert "min-width:0" in s        # middle can shrink to nothing
    assert "overflow-x:auto" in s    # middle scrolls
    # the dismiss control sits in the RIGHT pinned cluster (built just before it).
    right = s[s.index("flex:0 0 auto;display:flex;align-items:center;gap:8px"):]
    assert 'aria-label":"dismiss"' in right   # ✕ lives in the right-pinned cluster


def test_inline_escapes_script_breakout():
    # A bundle value that literally contains </script> must NOT close the inline
    # <script> — it must be escaped to <\/script>.
    orig = bundle._read_pin
    bundle._read_pin = lambda: "</script><img src=x onerror=alert(1)>"
    bundle._cache.clear()
    try:
        s = bundle.inline_script("z", wg=False, csp=False)
    finally:
        bundle._read_pin = orig
        bundle._cache.clear()
    # The IIFE close is the only legitimate "})();"; nothing before the final
    # close should contain a raw "</script>".
    head = s[: s.rfind("})();")]
    assert "</script>" not in head
    assert "<\\/script>" in head  # escaped form present


def test_inline_get_bundle_called_with_bool_wg(monkeypatch):
    seen = {}

    def fake_get_bundle(mh, is_wg=False):
        seen["args"] = (mh, is_wg)
        return {"v": 1, "client_id": mh, "level": "r1", "pin": "",
                "report_url": "http://x", "tracker_patterns": ["doubleclick"],
                "ts": 0}

    monkeypatch.setattr(bundle, "get_bundle", fake_get_bundle)
    bundle.inline_script("abc", wg=1, csp=0)  # wg passed as truthy int
    assert seen["args"] == ("abc", True)      # coerced to bool


def test_legacy_loader_still_intact():
    # The src-loader must keep working: it reads currentScript + data-attrs and
    # fetch()es the bundle (the inline path supersedes it in the live engine, but
    # the /__toolbox/loader.js route still serves it).
    assert "currentScript" in bundle.LOADER_JS
    assert "fetch(" in bundle.LOADER_JS
    assert "function render" in bundle.LOADER_JS
    assert "window.__SBX_LOADER__" in bundle.LOADER_JS


def test_inline_route_returns_javascript_body():
    import asyncio
    resp = asyncio.run(api.toolbox_inline(mh="abc", wg=1, csp=1))
    assert resp.status_code == 200
    assert "javascript" in resp.media_type
    assert "no-store" in resp.headers.get("Cache-Control", "")
    body = resp.body.decode("utf-8")
    assert "window.__SBX_LOADER__" in body
    assert "currentScript" not in body
    assert "/__toolbox/bundle" not in body  # bundle baked inline, not fetched (#740 toggles fetch /set-* on click only)
    assert 'var mh = "abc";' in body
    assert 'var csp = "1";' in body
