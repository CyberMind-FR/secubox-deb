# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: toolbox :: per-client decision bundle (#620 phase 1)
CyberMind — https://cybermind.fr

The bundle holds ONLY per-host cosmetic decisions (client level, shared pin,
report URL, tracker patterns, cosmetic block selectors) — never page content.
It is what `loader.js` fetches client-side so the heavy banner/ad work leaves
the proxy critical path (TTFB-first design, see issue #620 spec).

Cheap to build (one pin.json read + one indexed SQLite lookup); cached per
client with a short TTL so repeated requests don't rebuild. Fail-open: any
error yields a minimal safe bundle, never an exception.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict

try:
    from . import store
except Exception:  # pragma: no cover - store optional in unit tests
    store = None

PIN_FILE = Path("/run/secubox/pin.json")
REPORT_URL_CAPTIVE = "http://10.99.0.1:8088/report/me/html"
REPORT_URL_PUBLIC = "https://kbin.gk2.secubox.in/report/me/html"
BUNDLE_TTL = 10.0  # seconds

# Tracker substrings — mirrors inject_banner._TRACKER_PATTERNS so the client-side
# loader can count trackers from Resource Timing instead of a server body scan.
TRACKER_PATTERNS = [
    "doubleclick", "googlesyndication", "googleadservices", "googletagmanager",
    "google-analytics", "googletagservices", "facebook.com/tr",
    "connect.facebook.net", "scorecardresearch", "chartbeat", "hotjar",
    "mixpanel", "amplitude", "segment.com", "segment.io", "criteo", "adnxs",
    "rubiconproject", "taboola", "outbrain", "smartadserver", "optimizely",
    "fullstory", "newrelic", "datadog", "sentry", "amazon-adsystem", "adsrvr",
    "yieldlove", "moatads", "adservice.google", "adsystem", "adserver",
]

_cache: Dict[tuple, tuple] = {}   # (client_id, is_wg) -> (built_at, bundle)


def _read_pin() -> str:
    try:
        data = json.loads(PIN_FILE.read_text(encoding="utf-8"))
        return str(data.get("text", ""))[:80]
    except Exception:
        return ""


def _level_for(client_id: str) -> str:
    if not client_id or store is None:
        return "r1"
    try:
        return store.get_client_level(client_id)
    except Exception:
        return "r1"


def _report_url(client_id: str, is_wg: bool) -> str:
    if is_wg and client_id:
        return f"{REPORT_URL_PUBLIC}?mh={client_id}"
    return REPORT_URL_CAPTIVE


def build_bundle(client_id: str, is_wg: bool = False) -> dict:
    """Build the per-client cosmetic decision bundle (pure given inputs + pin file)."""
    return {
        "v": 1,
        "client_id": client_id or "",
        "level": _level_for(client_id),
        "pin": _read_pin(),
        "report_url": _report_url(client_id, is_wg),
        "tracker_patterns": TRACKER_PATTERNS,
        "ts": int(time.time()),
    }


def get_bundle(client_id: str, is_wg: bool = False) -> dict:
    """Return the cached bundle for a client, rebuilding past the TTL. Fail-open."""
    try:
        now = time.time()
        key = (client_id or "", bool(is_wg))
        hit = _cache.get(key)
        if hit and (now - hit[0]) < BUNDLE_TTL:
            return hit[1]
        bundle = build_bundle(client_id, is_wg)
        _cache[key] = (now, bundle)
        return bundle
    except Exception:
        # Minimal safe bundle — never break the loader.
        return {"v": 1, "client_id": client_id or "", "level": "r1",
                "pin": "", "report_url": REPORT_URL_CAPTIVE,
                "tracker_patterns": TRACKER_PATTERNS, "ts": int(time.time())}


# Cosmetic client-side loader. Served static + cached; applies the transparency
# banner from the bundle off the page's critical render path. Per-page stats
# (trackers, cookies) are derived in-browser (Resource Timing / document.cookie),
# so the proxy never scans the body. Self-guarded, dismissible, fail-silent.
LOADER_JS = r"""(function(){
  "use strict";
  if (window.__SBX_LOADER__) return; window.__SBX_LOADER__ = 1;
  var s = document.currentScript || {};
  var ds = s.dataset || {};
  var mh = ds.mh || "", wg = ds.wg || "0";
  // #662 CONSENTED-DEMONSTRATION: the engine relaxed this page's CSP so this
  // loader could run even under a strict policy, and stamped data-csp="1" on our
  // <script>. When set, the banner shows a 🔓 as VISIBLE proof the page's CSP was
  // bypassed to inject. Absent → no proof emoji (page had no CSP to bypass).
  var csp = ds.csp || "";
  // SPA support (#662): cache the bundle + remember an explicit dismiss, so the
  // banner can be re-asserted after client-side navigation / DOM re-renders
  // (cnn, youtube… swap content without reloading → the one-shot loader would
  // otherwise vanish). Re-assert never fights a user who clicked ✕.
  var bundle = null, dismissed = false;
  function ready(fn){ if (document.body) { fn(); } else { setTimeout(function(){ready(fn);}, 30); } }
  function esc(t){ return String(t).replace(/[&<>"]/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]; }); }
  function countTrackers(pats){
    try {
      var seen = {};
      (performance.getEntriesByType("resource") || []).forEach(function(e){
        var u = e.name || "";
        (pats || []).forEach(function(p){ if (u.indexOf(p) >= 0) seen[p] = 1; });
      });
      return Object.keys(seen).length;
    } catch (_) { return 0; }
  }
  function render(b){
    if (dismissed) return;
    if (document.getElementById("sbx-banner")) return;
    var trk = countTrackers(b.tracker_patterns);
    var ck = 0;
    try { ck = document.cookie ? document.cookie.split(";").filter(function(x){return x.indexOf("=")>=0;}).length : 0; } catch (_) {}
    var bar = document.createElement("div");
    bar.id = "sbx-banner";
    bar.setAttribute("style", "position:fixed;left:0;right:0;top:0;z-index:2147483647;"
      + "font:12px/1.4 system-ui,-apple-system,sans-serif;background:#0A0E14;color:#E8E6E0;"
      + "border-bottom:2px solid #148C66;padding:6px 12px;display:flex;gap:14px;align-items:center;"
      + "box-shadow:0 2px 12px rgba(0,0,0,.4)");
    var pin = b.pin ? "<span title=\"pinned\">📌 " + esc(b.pin) + "</span>" : "";
    // #662 — 🔓 proof: the engine relaxed this page's CSP to inject this banner.
    var cspProof = (csp === "1")
      ? "<span title=\"CSP contourné par SecuBox (démonstration)\">🔓</span>" : "";
    bar.innerHTML = "<b style=\"color:#148C66\">SecuBox</b>"
      + cspProof
      + "<span>" + esc((b.level || "r1").toUpperCase()) + "</span>"
      + "<span>🛰️ " + trk + " trackers</span>"
      + "<span>🍪 " + ck + " cookies</span>"
      + pin
      + "<a href=\"" + esc(b.report_url || "#") + "\" style=\"margin-left:auto;color:#2C70C0;text-decoration:none\">report ▸</a>"
      + "<button aria-label=\"dismiss\" style=\"background:none;border:0;color:#8A9AA8;cursor:pointer;font-size:14px\">✕</button>";
    document.body.appendChild(bar);
    try { document.body.style.paddingTop = (bar.offsetHeight || 34) + "px"; } catch (_) {}
    var btn = bar.querySelector("button");
    if (btn) btn.onclick = function(){ dismissed = true; try { document.body.style.paddingTop = ""; } catch (_) {} bar.remove(); };
  }
  // ensure(): (re)render the banner if it's absent and the bundle is loaded and
  // the user hasn't dismissed it. Cheap (a getElementById guard inside render).
  function ensure(){ if (bundle && !dismissed) ready(function(){ render(bundle); }); }
  fetch("/__toolbox/bundle?mh=" + encodeURIComponent(mh) + "&wg=" + encodeURIComponent(wg), {credentials:"omit"})
    .then(function(r){ return r.json(); })
    .then(function(b){ bundle = b; ensure(); })
    .catch(function(){});
  // SPA re-assert: wrap history nav + popstate (defer so the framework settles),
  // plus a light 2s poll as a catch-all for DOM re-renders that drop the banner.
  ["pushState","replaceState"].forEach(function(m){
    var o = history[m];
    if (typeof o === "function") {
      try { history[m] = function(){ var r = o.apply(this, arguments); setTimeout(ensure, 150); return r; }; } catch (_) {}
    }
  });
  window.addEventListener("popstate", function(){ setTimeout(ensure, 150); });
  setInterval(ensure, 2000);
})();
"""
