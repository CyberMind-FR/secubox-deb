// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox ToolBoX :: content-script transparency banner (#655)
//
// Runs in the extension's ISOLATED WORLD, so the page's CSP cannot block it —
// this is the reliable banner channel for nonce-CSP / SPA sites (YouTube, etc.)
// the mitm-injected loader can't reach. It is a FALLBACK: it defers ~800 ms to
// let the mitm banner (#sbx-banner) appear where it works, and only renders its
// own (#sbx-cs-banner, in a style-isolated shadow root) when that's absent.
// SPA-aware via history hooks. Reads R3 level from the toolbox host through the
// extension's host_permissions (CSP-immune cross-origin fetch).
(function () {
  "use strict";
  if (window.__SBX_CS__) return; window.__SBX_CS__ = 1;

  var TOOLBOX = "https://kbin.gk2.secubox.in";     // covered by host_permissions
  var MITM_ID = "sbx-banner";                       // the in-page mitm banner
  var CS_ID = "sbx-cs-banner";                       // ours
  // Compact tracker-domain list for a live per-page count (performance API).
  var TRACKERS = ["doubleclick.net", "google-analytics.com", "googletagmanager.com",
    "googlesyndication.com", "connect.facebook.net", "facebook.com/tr", "scorecardresearch.com",
    "adnxs.com", "criteo.", "taboola.com", "outbrain.com", "hotjar.com", "segment.",
    "mixpanel.com", "amplitude.com", "branch.io", "sentry.io", "fullstory.com",
    "clarity.ms", "bat.bing.com", "analytics.tiktok.com", "ads-twitter.com"];

  function esc(t) {
    return String(t).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" }[c];
    });
  }
  function countTrackers() {
    try {
      var seen = {};
      (performance.getEntriesByType("resource") || []).forEach(function (e) {
        var u = e.name || "";
        TRACKERS.forEach(function (t) { if (u.indexOf(t) >= 0) seen[t] = 1; });
      });
      return Object.keys(seen).length;
    } catch (_) { return 0; }
  }
  function cookieCount() {
    try {
      return document.cookie
        ? document.cookie.split(";").filter(function (x) { return x.indexOf("=") >= 0; }).length
        : 0;
    } catch (_) { return 0; }
  }

  var ctx = { level: "r3", report: TOOLBOX + "/" };
  function fetchCtx(cb) {
    try {
      fetch(TOOLBOX + "/wg/r3-check", { credentials: "omit" })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (j) {
            if (j.level) ctx.level = String(j.level);
            if (j.report_url) ctx.report = String(j.report_url);
          }
          cb();
        })
        .catch(function () { cb(); });
    } catch (_) { cb(); }
  }

  function present() {
    return !!(document.getElementById(MITM_ID) || document.getElementById(CS_ID));
  }
  function render() {
    if (present()) return;                       // mitm banner won, or ours exists
    var anchor = document.body || document.documentElement;
    if (!anchor) return;
    var trk = countTrackers(), ck = cookieCount();
    var host = document.createElement("div");
    host.id = CS_ID;
    host.style.cssText = "all:initial";          // isolate host from page styles
    var root = host.attachShadow ? host.attachShadow({ mode: "open" }) : host;
    root.innerHTML =
      '<div style="position:fixed;left:0;right:0;top:0;z-index:2147483647;' +
      'font:12px/1.4 system-ui,-apple-system,sans-serif;background:#0A0E14;color:#E8E6E0;' +
      'border-bottom:2px solid #148C66;padding:6px 12px;display:flex;gap:14px;align-items:center;' +
      'box-shadow:0 2px 12px rgba(0,0,0,.4)">' +
      '<b style="color:#148C66">SecuBox</b>' +
      '<span>' + esc(ctx.level.toUpperCase()) + '</span>' +
      '<span>🛰️ ' + trk + ' trackers</span>' +
      '<span>🍪 ' + ck + ' cookies</span>' +
      '<span style="opacity:.65" title="rendered by the SecuBox browser extension">ext</span>' +
      '<a href="' + esc(ctx.report) + '" target="_blank" rel="noreferrer noopener" ' +
      'style="margin-left:auto;color:#2C70C0;text-decoration:none">report ▸</a>' +
      '<button id="x" aria-label="dismiss" style="background:none;border:0;color:#8A9AA8;' +
      'cursor:pointer;font-size:14px">✕</button>';
    anchor.appendChild(host);
    var btn = root.querySelector ? root.querySelector("#x") : null;
    if (btn) btn.onclick = function () { try { host.remove(); } catch (_) {} };
  }
  function ensure() { if (!present()) render(); }

  // Initial: fetch context, then defer ~800 ms so the (faster) mitm banner wins
  // where it works; we fill in only where it didn't.
  fetchCtx(function () { setTimeout(ensure, 800); });

  // SPA re-assert: wrap history nav + popstate. ensure() is idempotent.
  ["pushState", "replaceState"].forEach(function (m) {
    var o = history[m];
    if (typeof o === "function") {
      try {
        history[m] = function () { var r = o.apply(this, arguments); setTimeout(ensure, 120); return r; };
      } catch (_) { /* frozen history — ignore */ }
    }
  });
  window.addEventListener("popstate", function () { setTimeout(ensure, 120); });
})();
