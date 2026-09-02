/*
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  SecuBox #1360 — AIDE REVERSE-DESIGN partagée des cardlets — LES DEUX à la fois :
    1. IN-CARD : anneaux + pastilles numérotées posés sur le contenu réel, SANS
       voile — le contenu reste visible (on annote, on ne cache pas).
    2. RAPPORT : {sbx:'aide-zones'} envoyé au Hall pour la BULLE de légendes
       (mêmes numéros). Rafraîchi périodiquement → suit la slice active.

  Déclenché par le Hall au clic sur ❓ (postMessage {sbx:'aide',on:true/false}).
  window.SBXAide(opts) : opts.root, opts.slice(), opts.zones()=[{el,label}].
*/
(function () {
  "use strict";
  if (window.SBXAide) return;
  var CSS = ''
    + '.sbxaide-ring{position:absolute;border:2px solid var(--cyan,#0a91c8);border-radius:8px;z-index:41;'
    + 'box-shadow:0 0 0 3px color-mix(in srgb,var(--cyan,#0a91c8) 20%,transparent);pointer-events:none;transition:.18s}'
    + '.sbxaide-pin{position:absolute;transform:translate(-50%,-50%);min-width:18px;height:18px;border-radius:10px;z-index:42;'
    + 'background:var(--cyan,#0a91c8);color:#04202a;font-weight:800;font-size:.66rem;display:grid;place-items:center;'
    + 'padding:0 5px;box-shadow:0 2px 6px rgba(0,0,0,.45);pointer-events:none}'
    + '@media(prefers-reduced-motion:reduce){.sbxaide-ring{transition:none}}';
  function injectCSS() { if (document.getElementById('sbxaide-css')) return;
    var s = document.createElement('style'); s.id = 'sbxaide-css'; s.textContent = CSS;
    (document.head || document.documentElement).appendChild(s); }
  function post(m) { if (window.parent !== window) { try { window.parent.postMessage(m, '*'); } catch (e) {} } }
  function autoZones(root) {
    var out = [], seen = [];
    function add(sel, label) { var e = root.querySelector(sel);
      if (e && seen.indexOf(e) < 0) { seen.push(e); out.push({ el: e, label: label }); } }
    add('.h, .head, header, .clh', 'En-tête — le service et son état (live / démo)');
    add('.kpis', 'Indicateurs clés — l’essentiel chiffré');
    add('form.paste, .vb-saisie, form, .msg', 'Saisie — coller un lien / une commande');
    add('.slice.actif, .slices, .stage, .vue, .np, .mlist, .list, #slices', 'Contenu vivant — la tranche affichée');
    add('#slbar, .sbx-bar, .dots, .footbar, .pied', 'Barre du bas — bullets pour changer de tranche');
    return out;
  }
  window.SBXAide = function (opts) {
    opts = opts || {}; injectCSS();
    var root = opts.root || document.querySelector('.mw') || document.body;
    if (getComputedStyle(root).position === 'static') root.style.position = 'relative';
    var on = false, tmr = null, nodes = [];
    function zones() { try { if (typeof opts.zones === 'function') { var z = opts.zones(); if (z && z.length) return z; } } catch (e) {}
      return autoZones(root); }
    function sliceName() { try { if (typeof opts.slice === 'function') return opts.slice() || ''; } catch (e) {}
      var d = root.querySelector('.sbx-dots .on, .dots .on'); return d ? (d.getAttribute('aria-label') || '') : ''; }
    function clear() { for (var i = 0; i < nodes.length; i++) nodes[i].remove(); nodes = []; }
    function draw() {
      clear(); var rr = root.getBoundingClientRect(), Z = zones();
      Z.forEach(function (x, k) {
        if (!x.el) return; var r = x.el.getBoundingClientRect(); if (r.width < 2 || r.height < 2) return;
        var ring = document.createElement('div'); ring.className = 'sbxaide-ring';
        ring.style.left = (r.left - rr.left - 2) + 'px'; ring.style.top = (r.top - rr.top - 2) + 'px';
        ring.style.width = (r.width + 4) + 'px'; ring.style.height = (r.height + 4) + 'px'; root.appendChild(ring); nodes.push(ring);
        var pin = document.createElement('div'); pin.className = 'sbxaide-pin'; pin.textContent = (k + 1);
        pin.style.left = (r.left - rr.left + 10) + 'px'; pin.style.top = (r.top - rr.top) + 'px'; root.appendChild(pin); nodes.push(pin);
      });
      report(rr, Z);
    }
    function report(rr, Z) { rr = rr || root.getBoundingClientRect(); Z = Z || zones();
      post({ sbx: 'aide-zones', slice: sliceName(), vw: rr.width, vh: rr.height,
        zones: Z.map(function (x) { if (!x.el) return null; var r = x.el.getBoundingClientRect();
          if (r.width < 2 || r.height < 2) return null;
          return { label: String(x.label || ''), x: r.left - rr.left, y: r.top - rr.top, w: r.width, h: r.height };
        }).filter(Boolean) }); }
    function show(v) { on = v; if (v) { draw(); if (tmr) clearInterval(tmr); tmr = setInterval(draw, 500); }
      else { if (tmr) { clearInterval(tmr); tmr = null; } clear(); } }
    window.addEventListener('message', function (ev) { var d = ev.data; if (!d) return;
      if (d.sbx === 'aide') show(!!d.on); else if (d.sbx === 'aide?') report(); });
    window.addEventListener('resize', function () { if (on) draw(); });
    return { show: show, refresh: function () { if (on) draw(); }, report: report };
  };
})();
