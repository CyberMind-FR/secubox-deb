// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox Companion — YouTube PO-token hook (runs in the PAGE/main world).
// Wraps fetch + XHR to spot YouTube's streaming requests, which carry the
// `pot` (PO token) query param. Relays it (+ visitor_data from ytcfg) to the
// content script via window.postMessage. EXPERIMENTAL + YouTube-fragile.
(function () {
  "use strict";
  let lastSent = "";

  function visitorData() {
    try {
      if (window.ytcfg && typeof window.ytcfg.get === "function") {
        return window.ytcfg.get("VISITOR_DATA") || "";
      }
      if (window.ytcfg && window.ytcfg.data_) return window.ytcfg.data_.VISITOR_DATA || "";
    } catch (e) { /* ignore */ }
    return "";
  }

  function grab(url) {
    if (!url) return;
    try {
      const u = new URL(url, location.href);
      if (!/(googlevideo\.com|youtube\.com)/.test(u.hostname)) return;
      const pot = u.searchParams.get("pot");
      if (pot && pot.length > 20 && pot !== lastSent) {
        lastSent = pot;
        window.postMessage(
          { __secubox: "yt-pot", po_token: pot, visitor_data: visitorData() }, "*");
      }
    } catch (e) { /* ignore */ }
  }

  try {
    const origFetch = window.fetch;
    if (origFetch) {
      window.fetch = function (input) {
        try { grab(typeof input === "string" ? input : (input && input.url)); } catch (e) {}
        return origFetch.apply(this, arguments);
      };
    }
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      try { grab(url); } catch (e) {}
      return origOpen.apply(this, arguments);
    };
  } catch (e) { /* ignore */ }
})();
