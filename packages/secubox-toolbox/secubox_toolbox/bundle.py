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


def _tor_mode() -> bool:
    """kbin Tor egress on? (#683) Read from filters; fail-safe to off."""
    try:
        from .filters import get_filters
        return bool(get_filters().get("tor_mode", False))
    except Exception:
        return False


def _ad_guard() -> bool:
    """Master ad-block switch on? (#740) Read from filters; default on."""
    try:
        from .filters import get_filters
        return bool(get_filters().get("ad_guard", True))
    except Exception:
        return True


def build_bundle(client_id: str, is_wg: bool = False) -> dict:
    """Build the per-client cosmetic decision bundle (pure given inputs + pin file)."""
    return {
        "v": 1,
        "client_id": client_id or "",
        "level": _level_for(client_id),
        "pin": _read_pin(),
        "report_url": _report_url(client_id, is_wg),
        "tracker_patterns": TRACKER_PATTERNS,
        "tor_mode": _tor_mode(),
        "ad_guard": _ad_guard(),
        "ts": int(time.time()),
    }


def invalidate(client_id: str) -> None:
    """#724 — drop a client's cached bundle (both wg variants) so a level switch
    is reflected on the next banner render without waiting for the TTL."""
    cid = client_id or ""
    for k in ((cid, True), (cid, False)):
        _cache.pop(k, None)


def invalidate_all() -> None:
    """#740 — drop ALL cached bundles after a GLOBAL filter change (ad_guard /
    tor_mode toggled from the banner) so every client picks up the new state."""
    _cache.clear()


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


# ── shared banner JS body (#662) ─────────────────────────────────────────────
#
# The render + SPA-re-assert + dismiss + countTrackers + 🔓 cspProof logic is
# IDENTICAL between the legacy src-loader (LOADER_JS, fetched as
# /__toolbox/loader.js → fetch()es /__toolbox/bundle) and the new INLINE banner
# (inline_script(), baked into the page by the Go engine at inject time). To
# avoid drift, that logic lives ONCE in _BANNER_CORE; each caller differs only in
# its PRELUDE — how `bundle`, `mh`, `wg`, `csp`, `dismissed` are obtained:
#
#   * LOADER_JS → reads data-mh/data-wg/data-csp off document.currentScript and
#                 fetch()es the bundle (legacy; kept working for the
#                 /__toolbox/loader.js route).
#   * inline    → mh/wg/csp/bundle are baked as JS LITERALS (no currentScript,
#                 no fetch) so a site's SERVICE WORKER has nothing same-origin to
#                 hijack (leparisien, cnn… run a SW that 404s our assets).
#
# _BANNER_CORE assumes `mh`, `wg`, `csp`, `bundle`, `dismissed` are already
# declared by the prelude and runs render/SPA off them.

# render + SPA-re-assert + dismiss + countTrackers + 🔓 cspProof. Shared verbatim
# by both preludes. References `mh`, `wg`, `csp`, `bundle`, `dismissed` from the
# enclosing prelude scope. Defines ensure() + installs the history/popstate hooks
# + 2s poll; the prelude calls ensure() (inline) or sets `bundle` then ensure()s
# (src-loader).
_BANNER_CORE = r"""
  // #752 — top-frame ONLY: never render inside an embedded sub-frame (3rd-party
  // video players e.g. geo.dailymotion.com, ad/consent iframes). A same-origin
  // iframe trips window.top !== window.self; a cross-origin one throws on the
  // access → both bail. The transparency banner belongs on the top document,
  // once. Returns from the IIFE before any function runs (ensure() is appended
  // after this block by both the inline and src-loader preludes).
  try { if (window.top !== window.self) return; } catch (_) { return; }
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
  function countCookies(){
    try { return document.cookie ? document.cookie.split(";").filter(function(x){return x.indexOf("=")>=0;}).length : 0; } catch (_) { return 0; }
  }
  // #683 — counts are taken at render time, but resources + cookies keep loading
  // AFTER the banner appears (early render → stuck at 0). Re-count live on the
  // 2s poll so trackers/cookies climb to their real values.
  function updateCounts(b){
    var t = document.getElementById("sbx-trk");
    if (t) t.textContent = "🛰️ " + countTrackers((b || {}).tracker_patterns) + " trackers";
    var c = document.getElementById("sbx-ck");
    if (c) c.textContent = "🍪 " + countCookies() + " cookies";
  }
  // #724 — inline R0..R3 level switch. Shows the real current level (highlighted)
  // and lets the client change it: GET /__toolbox/set-level (same-origin, the Go
  // engine reverse-proxies it to the portal), then reload so the new tier applies.
  // #740 — mk(): build an element via DOM API only. textContent / setAttribute are
  // NOT Trusted Types sinks (unlike innerHTML), so the banner renders on EVERY site
  // — incl. strict-CSP/Trusted-Types ones (franceinfo, leparisien, 20minutes, cnn,
  // x/twitter) — with ZERO CSP/TT bypass. This is the robust, permanent fix.
  function mk(tag, opts){
    var e = document.createElement(tag);
    opts = opts || {};
    if (opts.id) e.id = opts.id;
    if (opts.cls) e.className = opts.cls;
    if (opts.title) e.title = opts.title;
    if (opts.text != null) e.textContent = opts.text;
    if (opts.style) e.setAttribute("style", opts.style);
    if (opts.attrs) for (var k in opts.attrs) if (Object.prototype.hasOwnProperty.call(opts.attrs, k)) e.setAttribute(k, opts.attrs[k]);
    return e;
  }
  var BTN = "border-radius:3px;padding:0 5px;margin:0 2px;font:inherit;font-size:11px;cursor:pointer";
  function lvlSwitch(b){
    var cur = String(b.level || "r1").toLowerCase();
    // #736 — R4 = analyst / reverse-catcher tier (deepest): everything MITM'd +
    // media URLs caught for cloning. Reconciled into the #740 DOM-API switch.
    var lv = ["r0","r1","r2","r3","r4"];
    var span = mk("span", {id:"sbx-lvl", title:"Niveau d'analyse — R4 = analyste/capteur média, clique pour changer"});
    for (var i=0;i<lv.length;i++){ var on = lv[i]===cur;
      span.appendChild(mk("button", {cls:"sbx-lvl", text:lv[i].toUpperCase(), attrs:{"data-lvl":lv[i]},
        style:"background:"+(on?"#148C66":"transparent")+";color:"+(on?"#0A0E14":"#8A9AA8")
          +";border:1px solid #148C66;"+BTN}));
    }
    return span;
  }
  function wireLevels(bar, b){
    var els = bar.querySelectorAll(".sbx-lvl");
    for (var i=0;i<els.length;i++){ (function(el){
      el.onclick = function(){
        var lvl = el.getAttribute("data-lvl");
        var who = (typeof mh !== "undefined" && mh) ? mh : (b.client_id || "");
        if (!who) return;
        el.textContent = "…";
        fetch("/__toolbox/set-level?mh=" + encodeURIComponent(who) + "&level=" + lvl,
              {credentials:"omit", cache:"no-store"})
          .then(function(r){ if (r && r.ok) { location.reload(); } else { el.textContent = lvl.toUpperCase(); } })
          .catch(function(){ el.textContent = lvl.toUpperCase(); });
      };
    })(els[i]); }
  }
  function render(b){
    if (dismissed) return;
    if (document.getElementById("sbx-banner")) return;
    var trk = countTrackers(b.tracker_patterns);
    var ck = countCookies();
    var bar = document.createElement("div");
    bar.id = "sbx-banner";
    // #740 — !important on the visibility-critical props makes the banner IMMUNE
    // to any stylesheet cosmetic hide (inline !important outranks author
    // stylesheet !important): it stays ABOVE everything and visible, always.
    bar.setAttribute("style", "position:fixed!important;left:0;right:0;top:0;z-index:2147483647!important;"
      + "display:flex!important;visibility:visible!important;opacity:1!important;"
      + "font:12px/1.4 system-ui,-apple-system,sans-serif;background:#0A0E14;color:#E8E6E0;"
      + "border-bottom:2px solid #148C66;padding:6px 12px;gap:14px;align-items:center;"
      + "box-shadow:0 2px 12px rgba(0,0,0,.4)");
    // #740 — built entirely with DOM API (no innerHTML → not a Trusted Types
    // sink), so the banner renders identically on every site, strict-CSP/TT
    // included, without touching the page's CSP.
    bar.appendChild(mk("b", {text:"SecuBox", style:"color:#148C66"}));
    if (csp === "1") bar.appendChild(mk("span", {text:"🔓", title:"CSP contourné par SecuBox (démonstration)"}));
    bar.appendChild(mk("button", {id:"sbx-tor", text:"🧅 " + (b.tor_mode?"ON":"OFF"),
      title:"Tor du tunnel toolbox — clique pour basculer",
      style:"background:"+(b.tor_mode?"#3D2A6B":"transparent")+";color:"+(b.tor_mode?"#C9B8FF":"#8A9AA8")+";border:1px solid #6E40C9;"+BTN}));
    bar.appendChild(lvlSwitch(b));
    bar.appendChild(mk("button", {id:"sbx-adg", text:"🛡️ " + (b.ad_guard===false?"OFF":"ON"),
      title:"Ad-Guard (blocage pub) — clique pour basculer",
      style:"background:"+(b.ad_guard===false?"transparent":"#148C66")+";color:"+(b.ad_guard===false?"#8A9AA8":"#0A0E14")+";border:1px solid #148C66;"+BTN}));
    bar.appendChild(mk("span", {id:"sbx-trk", text:"🛰️ " + trk + " trackers"}));
    bar.appendChild(mk("span", {id:"sbx-ck", text:"🍪 " + ck + " cookies"}));
    if (b.pin) bar.appendChild(mk("span", {text:"📌 " + b.pin, title:"pinned"}));
    bar.appendChild(mk("a", {text:"report ▸", style:"margin-left:auto;color:#2C70C0;text-decoration:none", attrs:{href: b.report_url || "#"}}));
    bar.appendChild(mk("button", {text:"✕", title:"dismiss",
      style:"background:none;border:0;color:#8A9AA8;cursor:pointer;font-size:14px", attrs:{"aria-label":"dismiss"}}));
    document.body.appendChild(bar);
    try { document.body.style.paddingTop = (bar.offsetHeight || 34) + "px"; } catch (_) {}
    wireLevels(bar, b);
    // #740 — 🛡️ Ad-Guard + 🧅 Tor quick-toggles (mirror the level switch wiring).
    var adg = bar.querySelector("#sbx-adg");
    if (adg) adg.onclick = function(){ var on = b.ad_guard!==false; adg.textContent="…";
      fetch("/__toolbox/set-adguard?on=" + (on?"0":"1"), {credentials:"omit",cache:"no-store"})
        .then(function(r){ if(r&&r.ok) location.reload(); else adg.textContent="🛡️ "+(on?"ON":"OFF"); })
        .catch(function(){ adg.textContent="🛡️ "+(on?"ON":"OFF"); }); };
    var tg = bar.querySelector("#sbx-tor");
    if (tg) tg.onclick = function(){ var on = !!b.tor_mode; tg.textContent="…";
      fetch("/__toolbox/set-tor?on=" + (on?"0":"1"), {credentials:"omit",cache:"no-store"})
        .then(function(r){ if(r&&r.ok) location.reload(); else tg.textContent="🧅 "+(on?"ON":"OFF"); })
        .catch(function(){ tg.textContent="🧅 "+(on?"ON":"OFF"); }); };
    var btn = bar.querySelector("button[aria-label=\"dismiss\"]");
    if (btn) btn.onclick = function(){ dismissed = true; try { document.body.style.paddingTop = ""; } catch (_) {} bar.remove(); };
  }
  // ensure(): (re)render the banner if it's absent and the bundle is loaded and
  // the user hasn't dismissed it. Cheap (a getElementById guard inside render).
  function ensure(){ if (bundle && !dismissed) ready(function(){ if (document.getElementById("sbx-banner")) updateCounts(bundle); else render(bundle); }); }
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
"""


def _js_str(value: str) -> str:
    """JS string LITERAL for an arbitrary string. json.dumps yields a valid JS
    string; we additionally escape ``</`` → ``<\\/`` so a value can never close
    the surrounding inline <script> (e.g. a value of "</script>")."""
    return json.dumps(value).replace("</", "<\\/")


def _js_json(obj) -> str:
    """JS object LITERAL for a JSON-serialisable object, hardened against a
    ``</script>`` breakout: json.dumps is valid JS, and escaping ``</`` → ``<\\/``
    means no nested string (pin, report_url…) can terminate the inline script."""
    return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")


def inline_script(mh: str, wg: bool, csp: bool) -> str:
    """Build the COMPLETE self-contained inline banner script BODY (#662).

    Service-worker survival: sites like leparisien / cnn register a SW that
    intercepts every same-origin request — so the legacy
    ``<script src="/__toolbox/loader.js">`` + its ``fetch("/__toolbox/bundle")``
    are hijacked by the SW (404 / app-shell) before reaching our MITM engine, and
    the banner never appears. The fix is to bake EVERYTHING as JS literals so the
    inline script makes NO same-origin request the SW can touch:

      * ``bundle`` is ``get_bundle(mh, wg)`` baked as a JSON literal (not fetched),
      * ``mh`` / ``wg`` / ``csp`` are baked as string literals (NOT data-attrs /
        currentScript — the null-currentScript-in-async bug killed #653),
      * NO ``document.currentScript``, NO ``fetch()``.

    Returns an IIFE string suitable for ``<script>…</script>``. The single-run
    guard (``window.__SBX_LOADER__``), the ``#sbx-banner`` element-id guard, the
    dismissed flag, the history pushState/replaceState/popstate hooks + 2s poll,
    and the 🔓 proof when ``csp`` is set are all preserved (from _BANNER_CORE).
    """
    bundle_obj = get_bundle(mh, bool(wg))
    prelude = (
        "(function(){\n"
        '  "use strict";\n'
        "  if (window.__SBX_LOADER__) return; window.__SBX_LOADER__ = 1;\n"
        # Baked literals — no currentScript / dataset, no fetch (SW-immune).
        "  var mh = " + _js_str(mh or "") + ";\n"
        "  var wg = " + _js_str("1" if wg else "0") + ";\n"
        # csp=="1" → the engine relaxed a real CSP to inject; render the 🔓 proof.
        "  var csp = " + _js_str("1" if csp else "0") + ";\n"
        "  var bundle = " + _js_json(bundle_obj) + ";\n"
        "  var dismissed = false;\n"
    )
    # Inline path renders on the first tick — the bundle is already present (no
    # async fetch to wait on), so ensure() can run immediately.
    return prelude + _BANNER_CORE + "  ensure();\n})();"


# Cosmetic client-side loader. Served static + cached; applies the transparency
# banner from the bundle off the page's critical render path. Per-page stats
# (trackers, cookies) are derived in-browser (Resource Timing / document.cookie),
# so the proxy never scans the body. Self-guarded, dismissible, fail-silent.
#
# Legacy src-loader (#620): kept working for the /__toolbox/loader.js route. The
# INLINE path (inline_script) supersedes it in the live engine inject path because
# a site service-worker hijacks the same-origin src + fetch (#662).
_LOADER_PRELUDE = r"""(function(){
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
"""

# The legacy src-loader fetches the bundle (same-origin), then ensure()s. The
# render + SPA logic is the SAME _BANNER_CORE the inline path uses (no drift).
LOADER_JS = _LOADER_PRELUDE + _BANNER_CORE + r"""
  fetch("/__toolbox/bundle?mh=" + encodeURIComponent(mh) + "&wg=" + encodeURIComponent(wg), {credentials:"omit"})
    .then(function(r){ return r.json(); })
    .then(function(b){ bundle = b; ensure(); })
    .catch(function(){});
})();
"""
