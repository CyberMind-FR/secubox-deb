/* SPDX-License-Identifier: LicenseRef-CMSD-1.0 · Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   live.secubox.in (#3351) : lit /api/v1/live/etat toutes les 20 s et construit la page par textContent / createElement
   (jamais de HTML construit à partir des données). Une donnée absente (null) affiche « — » ou « indisponible », jamais une valeur inventée. */
(function () {
  'use strict';
  var SVG = 'http://www.w3.org/2000/svg';
  var PREC = {};
  function $(id) { return document.getElementById(id); }
  function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
  function sv(tag, a) { var e = document.createElementNS(SVG, tag); for (var k in a) e.setAttribute(k, a[k]); return e; }
  function vider(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function fmt(n) { return n == null ? '—' : Number(n).toLocaleString('fr-FR'); }
  function texte(id, v) { $(id).textContent = v == null ? '—' : v; }
  function duree(s) { if (s == null) return '—'; var j = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600); return (j ? j + ' j ' : '') + h + ' h'; }

  function jauge(v, couleur) {
    var d = el('div', 'jauge'), i = el('i'), s = el('span');
    if (v != null) { s.style.width = Math.max(0, Math.min(100, v)) + '%'; s.style.background = couleur; }
    i.appendChild(s); d.appendChild(i); d.appendChild(el('span', null, v == null ? '—' : v + ' %')); return d;
  }

  function noeuds(liste) {
    var tb = $('noeuds'); vider(tb);
    if (!liste) { var tr = el('tr'), td = el('td', 'vide', 'Relevé des nœuds indisponible.'); td.colSpan = 7; tr.appendChild(td); tb.appendChild(tr); return; }
    liste.forEach(function (n) {
      var tr = el('tr'), p = el('span', 'pastille ' + (n.etat === 'hors ligne' ? 'p-ko' : n.etat === 'interface distante' ? 'p-leger' : 'p-ok'), n.etat), tdE = el('td');
      tdE.appendChild(p);
      var c = el('td'); c.appendChild(jauge(n.cpu, '#22d3ee'));
      var m = el('td'); m.appendChild(jauge(n.memoire, '#a78bfa'));
      [el('td', 'mono', n.nom), el('td', null, n.role || '—'), el('td', null, n.materiel || '—'), tdE, c, m, el('td', 'mono', duree(n.uptime_s))]
        .forEach(function (x) { tr.appendChild(x); });
      tb.appendChild(tr);
    });
  }

  function waf(min) {
    var s = $('waf'); vider(s);
    if (!min) { $('waf-note').textContent = 'Journal du WAF indisponible.'; return; }
    var max = Math.max.apply(null, min.map(function (p) { return p.bloquees; }).concat([1]));
    var pts = min.map(function (p, i) { return (i * 300 / 59).toFixed(1) + ',' + (100 - 90 * p.bloquees / max).toFixed(1); }).join(' ');
    s.appendChild(sv('polyline', { points: pts, fill: 'none', stroke: '#f87171', 'stroke-width': '2' }));
    var tot = min.reduce(function (a, p) { return a + p.bloquees; }, 0);
    $('waf-note').textContent = fmt(tot) + ' requête(s) bloquée(s) sur la dernière heure · pic ' + fmt(max) + '/min';
  }

  function monde(idSvg, idNote, pays, couleur, vide) {
    var s = $(idSvg); vider(s);
    var defs = sv('defs', {}), g = sv('radialGradient', { id: idSvg + '-g' });
    g.appendChild(sv('stop', { offset: '0', 'stop-color': couleur, 'stop-opacity': '.95' }));
    g.appendChild(sv('stop', { offset: '1', 'stop-color': couleur, 'stop-opacity': '0' }));
    defs.appendChild(g); s.appendChild(defs);
    s.appendChild(sv('rect', { width: '120', height: '60', fill: 'rgba(6,13,27,.5)' }));
    TERRE.split('|').forEach(function (l, j) {
      var cur = l.charAt(0) === '1', x = 0;
      l.slice(1).split(',').forEach(function (n) { n = +n; if (cur) for (var i = 0; i < n; i++) s.appendChild(sv('circle', { cx: x + i + .5, cy: j + .5, r: '.42', fill: '#33507f' })); x += n; cur = !cur; });
    });
    if (!pays) { $(idNote).textContent = 'Source indisponible.'; return; }
    var max = Math.max.apply(null, pays.map(function (p) { return p.n; }).concat([1])), prec = PREC[idSvg] || null, cur = {};
    pays.forEach(function (p) {
      var c = CENTRE[p.code]; cur[p.code] = p.n; if (!c) return;
      var cx = ((c[1] + 180) / 3).toFixed(1), cy = ((90 - c[0]) / 3).toFixed(1);
      var o = sv('circle', { cx: cx, cy: cy, r: (1.4 + 3.4 * Math.sqrt(p.n / max)).toFixed(1), fill: 'url(#' + idSvg + '-g)' });
      var t = sv('title', {}); t.textContent = p.code + ' : ' + fmt(p.n); o.appendChild(t); s.appendChild(o);
      if (prec && (prec[p.code] == null || p.n > prec[p.code])) s.appendChild(sv('circle', { 'class': 'ping', cx: cx, cy: cy, r: '3', stroke: couleur }));
    });
    PREC[idSvg] = cur;
    $(idNote).textContent = pays.length ? pays.slice(0, 5).map(function (p) { return p.code + ' ' + fmt(p.n); }).join(' · ') : vide;
  }

  function histo(h, prod) {
    var s = $('histo'); vider(s);
    var dep = prod && prod.depuis, hd = prod && prod.historique_depuis;
    $('prod').textContent = dep ? ('en production depuis le ' + dep + (hd && hd !== dep ? ' · historique détaillé depuis le ' + hd : '')) : (hd ? 'historique détaillé depuis le ' + hd : '');
    var jours = dep ? Math.max(1, Math.round((Date.now() - Date.parse(dep)) / 864e5)) : null;
    texte('c-jours', jours);
    if (!h || !h.length) { s.appendChild(sv('text', { x: '450', y: '120', fill: '#94a3b8', 'text-anchor': 'middle' })).textContent = 'Historique indisponible.'; return; }
    var som = function (k) { return h.every(function (x) { return x[k] == null; }) ? null : h.reduce(function (a, x) { return a + (x[k] || 0); }, 0); };
    texte('c-visites', fmt(som('visites'))); texte('c-attaques', fmt(som('attaques'))); texte('c-bans', fmt(som('bans')));
    var max = Math.max.apply(null, h.map(function (x) { return (x.visites || 0) + (x.attaques || 0) + (x.bans || 0); }).concat([1]));
    var larg = 850 / h.length, cum = 0, totA = som('attaques') || 1, pts = [];
    h.forEach(function (x, i) {
      var X = 40 + i * larg, y = 200, g = sv('g', {}), t = sv('title', {});
      [['visites', '#22d3ee'], ['attaques', '#f87171'], ['bans', '#fbbf24']].forEach(function (k) {
        var hh = 180 * (x[k[0]] || 0) / max; y -= hh;
        g.appendChild(sv('rect', { x: X.toFixed(1), y: y.toFixed(1), width: Math.max(1, larg - 2).toFixed(1), height: hh.toFixed(1), fill: k[1] }));
      });
      t.textContent = x.jour + ' — visites ' + fmt(x.visites) + ', attaques ' + fmt(x.attaques) + ', bans ' + fmt(x.bans);
      g.appendChild(t); s.appendChild(g);
      cum += x.attaques || 0; pts.push((X + larg / 2).toFixed(1) + ',' + (200 - 180 * cum / totA).toFixed(1));
    });
    s.appendChild(sv('polyline', { points: pts.join(' '), fill: 'none', stroke: '#e6edf7', 'stroke-width': '2', 'stroke-dasharray': '5 4' }));
    s.appendChild(sv('line', { x1: '40', y1: '200', x2: '890', y2: '200', stroke: 'rgba(148,163,184,.5)' }));
    var a = sv('text', { x: '40', y: '222', fill: '#94a3b8', 'font-size': '12' }); a.textContent = h[0].jour; s.appendChild(a);
    var b = sv('text', { x: '890', y: '222', fill: '#94a3b8', 'font-size': '12', 'text-anchor': 'end' }); b.textContent = h[h.length - 1].jour; s.appendChild(b);
  }

  function barres(id, liste, cle, couleurs, suffixe, vide) {
    var d = $(id); vider(d);
    if (!liste || !liste.length) { d.appendChild(el('p', 'vide', vide)); return; }
    var tot = liste.reduce(function (a, x) { return a + (x[cle] || 0); }, 0) || 1;
    liste.forEach(function (x, i) {
      var p = suffixe === '%' ? x[cle] : Math.round(100 * x[cle] / tot);
      var b = el('div', 'barre'), l = el('div', 'l'), f = el('div', 'f'), s = el('span');
      l.appendChild(el('span', null, x.nom || x.categorie)); l.appendChild(el('span', null, suffixe === '%' ? p + ' %' : fmt(x[cle]) + ' · ' + p + ' %'));
      s.style.width = Math.min(100, p) + '%'; s.style.background = couleurs[i % couleurs.length]; f.appendChild(s);
      b.appendChild(l); b.appendChild(f); d.appendChild(b);
    });
  }

  function dev(d) {
    var box = $('d-dernieres'); vider(box);
    if (!d) { texte('d-fusions', null); texte('d-issues', null); texte('d-ci', null); box.appendChild(el('p', 'vide', 'GitHub injoignable pour le moment.')); return; }
    texte('d-fusions', fmt(d.fusions_7j)); texte('d-issues', fmt(d.issues_ouvertes));
    var ci = $('d-ci'); ci.textContent = d.ci_master === 'success' ? 'verte' : d.ci_master === 'failure' ? 'rouge' : (d.ci_master || '—');
    ci.className = d.ci_master === 'success' ? 'vert' : d.ci_master === 'failure' ? 'rouge' : '';
    (d.dernieres || []).forEach(function (f) {
      var l = el('div', 'ligne'); l.appendChild(el('span', 'n', '#' + f.num)); l.appendChild(el('span', 't', f.titre));
      l.appendChild(el('span', 'faible', f.le ? f.le.slice(0, 10) : '')); box.appendChild(l);
    });
  }

  function route(r) {
    var d = $('route'); vider(d);
    (r || []).forEach(function (x) { var l = el('div', 'ligne'); l.appendChild(el('span', 't', x.nom)); l.appendChild(el('span', 'faible', x.etat)); d.appendChild(l); });
  }

  function rendre(e) {
    var g = $('global'), t = e.tuiles || {};
    g.className = 'global ' + (e.etat_global || '');
    texte('global-texte', e.etat_global === 'ok' ? 'Tous les nœuds sont en ligne' : e.etat_global === 'degrade' ? 'Service partiellement dégradé' : 'État inconnu');
    texte('global-age', '· relevé à ' + new Date(e.genere_le * 1000).toLocaleTimeString('fr-FR'));
    texte('t-noeuds', t.noeuds_total == null ? null : t.noeuds_en_ligne + ' / ' + t.noeuds_total);
    texte('t-requetes', fmt(t.requetes_24h)); texte('t-menaces', fmt(t.menaces_24h));
    texte('t-bloquees', t.bloquees_24h == null ? 'bloquées : —' : 'bloquées : ' + fmt(t.bloquees_24h));
    texte('t-bans', fmt(t.bans_actifs)); texte('t-sites', fmt(t.sites_publies));
    noeuds(e.noeuds); waf(e.waf_heure);
    var c = e.cartes || {};
    monde('monde-att', 'monde-att-note', c.attaques, '#ff4d5e', 'aucune attaque géolocalisée');
    monde('monde-vis', 'monde-vis-note', c.visiteurs, '#29b6f6', 'aucune visite géolocalisée');
    histo(e.histo, e.production);
    barres('menaces', e.menaces, 'n', ['#f87171', '#fb923c', '#fbbf24', '#a78bfa', '#f472b6', '#22d3ee'], 'n', 'Journal du WAF indisponible.');
    barres('dpi', e.dpi, 'pct', ['#22d3ee', '#a78bfa', '#34d399', '#67e8f9', '#fbbf24', '#94a3b8'], '%', 'DPI indisponible.');
    dev(e.dev); route(e.feuille_de_route);
  }

  function charger() {
    fetch('/api/v1/live/etat', { cache: 'no-store', credentials: 'omit' })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(rendre)
      .catch(function () { $('global').className = 'global'; texte('global-texte', 'Données momentanément indisponibles'); });
  }
  charger();
  setInterval(function () { if (document.visibilityState !== 'hidden') charger(); }, 20000);
})();
