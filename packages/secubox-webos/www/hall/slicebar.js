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
    opts.autoMs — période de rotation auto (défaut 6000 ; 0 = pas de rotation)

  Rotation AUTO par défaut (puces bleues) ; un clic sur une puce passe en MANUEL
  (puces vertes) et fige le choix. Le survol met la rotation en pause — on lit
  sans que ça tourne sous les yeux.
*/
(function () {
  "use strict";
  function E(t, c) { var e = document.createElement(t); if (c) e.className = c; return e; }

  window.SBXSliceBar = function (container, opts) {
    opts = opts || {};
    var slices = opts.slices || [];
    var i = 0, mode = "auto", timer = null;

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
    function manual(k) { mode = "manuel"; dots.className = "sbx-dots manuel"; stop(); show(k); }
    function tick() { if (mode === "auto") show(i + 1); }
    function start() { if (opts.autoMs !== 0 && slices.length > 1) { stop(); timer = setInterval(tick, opts.autoMs || 6000); } }
    function stop() { if (timer) { clearInterval(timer); timer = null; } }

    bar.addEventListener("mouseenter", stop);
    bar.addEventListener("mouseleave", function () { if (mode === "auto") start(); });

    container.appendChild(bar);
    show(0); start();

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
