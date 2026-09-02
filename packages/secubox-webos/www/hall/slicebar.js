/*
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

  SecuBox #1352 — comportement de la BARRE DE SLICES partagée (« double bullet »).

  window.SBXSliceBar(container, opts) construit une barre de pied et gère la
  rotation entre slices. Le cardlet reste maître de SON contenu : il fournit la
  liste des slices et reçoit onShow(i) pour n'afficher que la slice courante.

    opts.slices : [{ label, host, tone, href, open }]
        label — libellé de la slice (affiché au centre)
        host  — hôte du service (pastille cliquable à droite) ; optionnel
        tone  — teinte de la puce au repos (nom de variable CSS, ex. "coral")
        open  — fonction appelée au clic sur la pastille ; à défaut, href est
                envoyé au Hall par postMessage {sbx:'voir', url:href}
    opts.onShow(i, slice) — appelé à chaque changement de slice
    opts.autoMs — période de rotation auto (défaut 9000, RALENTI ; 0 = pas de
                  rotation ; jamais de rotation sous prefers-reduced-motion)

  Rotation AUTO par défaut (puces bleues) ; un clic sur une puce passe en MANUEL
  (puces vertes) et fige le choix. Le survol de TOUTE la cardlet (pas seulement
  la barre) met la rotation en pause — on lit sans que ça tourne sous les yeux.
  Le Hall peut aussi pauser à distance (souris au-dessus de la carte) via
  postMessage {sbx:'survol'} / {sbx:'quitte'}.
*/
(function () {
  "use strict";
  function E(t, c) { var e = document.createElement(t); if (c) e.className = c; return e; }

  window.SBXSliceBar = function (container, opts) {
    opts = opts || {};
    var slices = opts.slices || [];
    var i = 0, mode = "auto", timer = null;

    // Mémoire du mode entre rafraîchissements ET visites (localStorage, par
    // cardlet). Une PAUSE manuelle (puce figée) doit survivre ; le survol, non.
    var KEY = "sbx-slice:" + (opts.key || (location && location.pathname) || "");
    function persist() {
      try { localStorage.setItem(KEY, JSON.stringify({ mode: mode, i: i })); } catch (e) {}
    }

    var bar  = E("div", "sbx-bar");
    var dots = E("div", "sbx-dots auto");
    var lab  = E("span", "sbx-lab");
    var host = E("button", "sbx-host"); host.type = "button";
    var info = E("span", "sbx-info");
    bar.appendChild(dots); bar.appendChild(lab); bar.appendChild(host); bar.appendChild(info);

    slices.forEach(function (s, k) {
      var b = E("button"); b.type = "button";
      b.setAttribute("aria-label", s.label || ("Slice " + (k + 1)));
      b.title = s.label || ("Slice " + (k + 1));
      if (s.tone) b.style.background = "var(--" + s.tone + ")";
      b.addEventListener("click", function () { manual(k); });
      dots.appendChild(b);
    });

    host.addEventListener("click", function () {
      var s = slices[i]; if (!s) return;
      if (typeof s.open === "function") { s.open(); return; }
      if (s.href) { try { parent.postMessage({ sbx: "voir", url: s.href }, "*"); } catch (e) {} }
    });

    function paint() {
      Array.prototype.forEach.call(dots.children, function (b, k) { b.classList.toggle("on", k === i); });
      var s = slices[i] || {};
      lab.textContent = s.label || "";
      host.textContent = s.host || "";
      host.style.display = s.host ? "" : "none";
      host.title = s.host ? ("Ouvrir " + s.host) : "";
      if (typeof opts.onShow === "function") opts.onShow(i, s);
    }
    function show(k) { if (!slices.length) return; i = ((k % slices.length) + slices.length) % slices.length; paint(); }
    // Un clic sur une puce FIGE le choix (MANUEL, puces vertes) et met la
    // rotation en PAUSE. Recliquer sur la MÊME puce déjà sélectionnée REPREND la
    // rotation auto. Le mode (et la slice figée) est mémorisé (persist()).
    function manual(k) {
      if (mode === "manuel" && k === i) { reprendreAuto(); return; }
      mode = "manuel"; dots.className = "sbx-dots manuel"; stop(); show(k); persist();
    }
    function reprendreAuto() {
      mode = "auto"; dots.className = "sbx-dots auto"; persist();
      if (!hovered) start();
    }
    function tick() { if (mode === "auto" && !hovered) show(i + 1); }
    // Rotation RALENTIE (défaut 9 s) et jamais sous prefers-reduced-motion.
    var reduce = false;
    try { reduce = matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) {}
    function start() {
      if (reduce || opts.autoMs === 0 || slices.length <= 1) return;
      stop(); timer = setInterval(tick, opts.autoMs || 9000);
    }
    function stop() { if (timer) { clearInterval(timer); timer = null; } }

    // PAUSE AU SURVOL DE TOUTE LA CARDLET (pas seulement la barre) : on lit sans
    // que ça tourne. `hovered` gèle aussi un tick déjà programmé. Le Hall peut
    // pauser à distance quand la souris est AU-DESSUS de la carte (postMessage).
    var hovered = false;
    function enter() { hovered = true; stop(); }
    function leave() { hovered = false; if (mode === "auto") start(); }
    var root = document.documentElement;
    root.addEventListener("mouseenter", enter);
    root.addEventListener("mouseleave", leave);
    root.addEventListener("focusin", enter);
    bar.addEventListener("mouseenter", enter);
    bar.addEventListener("mouseleave", function () { /* le survol carte gère la reprise */ });
    addEventListener("message", function (ev) {
      var d = ev && ev.data; if (!d || !d.sbx) return;
      if (d.sbx === "survol" || d.sbx === "pause") enter();
      else if (d.sbx === "quitte" || d.sbx === "reprend") leave();
    });

    container.appendChild(bar);
    // Restauration : une PAUSE manuelle survit aux refresh et aux visites. On
    // reprend la slice figée sans relancer la rotation ; sinon, mode auto normal.
    var saved = null;
    try { saved = JSON.parse(localStorage.getItem(KEY) || "null"); } catch (e) {}
    if (saved && saved.mode === "manuel" && typeof saved.i === "number"
        && saved.i >= 0 && saved.i < slices.length) {
      mode = "manuel"; dots.className = "sbx-dots manuel"; show(saved.i);
    } else {
      show(0); start();
    }

    return {
      el: bar,
      show: show,
      manual: manual,
      count: function () { return slices.length; },
      current: function () { return i; },
      setInfo: function (html) { info.innerHTML = html || ""; }
    };
  };
})();
