// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SCRIPT EXTERNE, MEME RAISON QUE LA FEUILLE (#1271) : `script-src 'self'`
// bloquait le <script> en ligne, la rotation ne demarrait jamais et la carte
// restait sur « aucun fil » alors que les fils etaient bien dans la page.
(function () {
  "use strict";
  var fils = [];
  try { fils = JSON.parse(document.getElementById('fils').getAttribute('data-fils') || '[]'); } catch (e) {}
  var i = 0, enPause = false;
  var el = function (id) { return document.getElementById(id); };
  var esc = function (t) { return String(t == null ? '' : t).replace(/[&<>"]/g, function (c) {
      return ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' })[c]; }); };
  function depuis(sec) {
    var s = Math.max(0, Date.now() / 1000 - Number(sec || 0));
    if (s < 3600) return Math.round(s / 60) + ' min';
    if (s < 86400) return Math.round(s / 3600) + ' h';
    return Math.round(s / 86400) + ' j';
  }
  function montre() {
    if (!fils.length) { el('pouls').style.animation = 'none'; return; }
    var f = fils[i % fils.length], img = el('une-img');
    // Vignette seulement si le fil en a une ET que c'est une image : poser
    // l'URL d'un média audio dans un <img> afficherait l'icône de fichier cassé.
    if (f.vignette) { img.src = f.vignette; img.classList.remove('cache'); }
    else { img.removeAttribute('src'); img.classList.add('cache'); }
    el('une').href = f.url || '/';
    el('une-t').textContent = f.titre || '—';
    el('une-q').textContent = (f.auteur ? f.auteur + ' · ' : '')
      + (f.posts ? f.posts + ' message' + (f.posts > 1 ? 's' : '') + ' · ' : '')
      + depuis(f.maj);
    var suite = [], k;
    for (k = 1; k <= 3 && k < fils.length; k++) suite.push(fils[(i + k) % fils.length]);
    el('top').innerHTML = '<div class="tt">↻ en rotation</div>' + suite.map(function (g) {
      return '<a href="' + esc(g.url) + '" target="_top" title="' + esc(g.titre) + '">'
        + '<span class="nm">' + esc(g.titre) + '</span>'
        + '<span class="c">' + esc(depuis(g.maj)) + '</span></a>';
    }).join('');
    el('rang').textContent = ((i % fils.length) + 1) + '/' + fils.length;
    el('n').textContent = fils.length + ' fils';
  }
  document.addEventListener('mouseenter', function () { enPause = true; }, true);
  document.addEventListener('mouseleave', function () { enPause = false; }, true);
  montre();
  setInterval(function () { if (!enPause && fils.length) { i++; montre(); } }, 7000);
  (function () {
    var t = new URLSearchParams(location.search).get('theme');
    if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t);
  })();

  // RESTER DANS LE HALL (#1266). Un lien de cardlet en target="_top" REMPLACE
  // le Hall par le service : on perd la mosaique, la barre media et tout ce
  // qui joue. Encadre, on demande donc au Hall d'embarquer la page ; hors
  // cadre, le lien fonctionne normalement — la carte reste une page valide,
  // et c'est ce repli qui autorise a garder target="_top" dans le HTML.
  document.addEventListener('click', function (ev) {
    if (parent === window) return;
    var a = ev.target && ev.target.closest ? ev.target.closest('a[href]') : null;
    if (!a || ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey) return;
    ev.preventDefault();
    try { parent.postMessage({ sbx: 'ouvre', id: 'bbs', url: a.href }, '*'); } catch (e) {}
  }, true);

  addEventListener('message', function (ev) {
    var d = ev.data;
    if (!d || d.sbx !== 'theme') return;
    if (d.theme === 'dark' || d.theme === 'light') {
      document.documentElement.setAttribute('data-theme', d.theme);
    }
  });
})();
