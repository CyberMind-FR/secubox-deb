// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SCRIPT EXTERNE, MEME RAISON QUE LA FEUILLE (#1295) : `script-src 'self'`
// bloquait ce bloc en ligne — le navigateur le signalait a CHAQUE affichage
// de la carte, et la rotation ne demarrait jamais.
  // Le thème d'ARRIVÉE vient du paramètre ; les bascules ensuite arrivent par
  // message, jamais par rechargement du cadre — recharger perdrait la position.
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
    try { parent.postMessage({ sbx: 'ouvre', id: 'billets', url: a.href }, '*'); } catch (e) {}
  }, true);

  // ROTATION SUR LES DERNIERS (#1285). Un billet figé ne dit pas qu'il y en a
  // d'autres ; c'est le défilement qui montre qu'un blog vit. Le survol
  // suspend — on ne lit pas un titre qui s'échappe.
  (function () {
    var l = [];
    try { l = JSON.parse(document.getElementById('rot').getAttribute('data-billets') || '[]'); }
    catch (e) { return; }
    if (l.length < 2) { pose(0); return; }
    var i = 0, pause = false;
    function pose(n) {
      var b = l[n % l.length], img = document.getElementById('une-img');
      document.getElementById('une').href = b.permalink;
      document.getElementById('une-t').textContent = b.title;
      document.getElementById('une-d').textContent = b.quand;
      if (b.vignette) { img.src = b.vignette; img.classList.remove('cache'); }
      else { img.removeAttribute('src'); img.classList.add('cache'); }
    }
    document.addEventListener('mouseenter', function () { pause = true; }, true);
    document.addEventListener('mouseleave', function () { pause = false; }, true);
    pose(0);
    setInterval(function () { if (!pause) { i++; pose(i); } }, 7000);
  })();

  addEventListener('message', function (ev) {
    var d = ev.data;
    if (!d || d.sbx !== 'theme') return;
    if (d.theme === 'dark' || d.theme === 'light') {
      document.documentElement.setAttribute('data-theme', d.theme);
    }
  });
