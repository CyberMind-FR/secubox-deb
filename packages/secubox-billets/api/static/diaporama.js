// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Diaporama des médias d'un billet (#4049) : défilement automatique (sauf prefers-reduced-motion), pause au survol, au focus, au
// toucher et hors écran ; flèches, points, clavier (← →). Les clics de navigation ne remontent pas à la carte (pas de théâtre).
(function () {
  "use strict";
  var PAS = 5000;
  var calme = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var io = "IntersectionObserver" in window ? new IntersectionObserver(function (es) {
    es.forEach(function (e) { var s = e.target._dz; if (s) { s.vu = e.isIntersecting; s.armer(); } });
  }) : null;

  function monter(el) {
    if (el._dz) return;
    var dz = el.querySelectorAll(".dz"), pts = el.querySelectorAll("[data-dz-i]");
    var s = { i: 0, t: null, pause: false, vu: !io };
    el._dz = s;
    if (dz.length < 2) return;
    function aller(n) {
      s.i = (n + dz.length) % dz.length;
      for (var k = 0; k < dz.length; k++) {
        var on = k === s.i;
        dz[k].classList.toggle("on", on);
        if (on) dz[k].removeAttribute("aria-hidden"); else dz[k].setAttribute("aria-hidden", "true");
        if (pts[k]) { if (on) pts[k].setAttribute("aria-current", "true"); else pts[k].removeAttribute("aria-current"); }
      }
      var img = dz[(s.i + 1) % dz.length].querySelector("img");   // précharger la suivante
      if (img && img.loading === "lazy") img.loading = "eager";
    }
    s.armer = function () {
      clearInterval(s.t); s.t = null;
      if (!calme && !s.pause && s.vu && !document.hidden) s.t = setInterval(function () { aller(s.i + 1); }, PAS);
    };
    function pause(v) { s.pause = v; s.armer(); }
    el.addEventListener("click", function (e) {
      var b = e.target.closest("[data-dz],[data-dz-i]");
      if (!b) return;
      e.preventDefault(); e.stopPropagation();
      aller(b.hasAttribute("data-dz") ? s.i + Number(b.getAttribute("data-dz")) : Number(b.getAttribute("data-dz-i")));
      s.armer();
    });
    el.addEventListener("keydown", function (e) {
      if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        e.preventDefault(); e.stopPropagation();
        aller(s.i + (e.key === "ArrowLeft" ? -1 : 1)); s.armer();
      }
    });
    el.addEventListener("mouseenter", function () { pause(true); });
    el.addEventListener("mouseleave", function () { pause(false); });
    el.addEventListener("focusin", function () { pause(true); });
    el.addEventListener("focusout", function () { pause(false); });
    var tt = null;
    el.addEventListener("touchstart", function () { pause(true); clearTimeout(tt); tt = setTimeout(function () { pause(false); }, 8000); }, { passive: true });
    if (io) io.observe(el);
    s.armer();
  }
  function tout(racine) { (racine || document).querySelectorAll("[data-diapo]").forEach(monter); }
  document.addEventListener("visibilitychange", function () {
    document.querySelectorAll("[data-diapo]").forEach(function (el) { if (el._dz && el._dz.armer) el._dz.armer(); });
  });
  function go() {
    tout();
    // le fil ajoute des cartes (défilement infini, /feed/maj) : les monter à leur arrivée
    new MutationObserver(function (ms) {
      ms.forEach(function (m) { m.addedNodes.forEach(function (n) { if (n.nodeType === 1) { if (n.matches("[data-diapo]")) monter(n); tout(n); } }); });
    }).observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", go); else go();
})();
