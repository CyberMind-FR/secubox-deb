/* SPDX-License-Identifier: LicenseRef-CMSD-1.0 · Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
   live.secubox.in (#3351, refonte #3933) : lit /etat.json toutes les 20 s et met la page à jour EN PLACE (chaque élément
   garde son identité : focus, infobulle ouverte, carte choisie et défilement survivent au relevé).
   Données posées par textContent / setAttribute, jamais de HTML construit, style par CSSOM seulement (CSP stricte).
   Une donnée absente ou aberrante affiche « — » ou une phrase, jamais 0 ni une valeur inventée. */
(function () {
  'use strict';
  var SVG = 'http://www.w3.org/2000/svg', RACINE = document.documentElement;
  var PERIODE = 20000, VIEUX_S = 300, L_JOUR = 864e5;

  // ---------------------------------------------------------------------------------------------- ambiance
  // Exécuté dans l'en-tête, avant le premier affichage : nuit par défaut, quel que soit le système.
  function lireAmbiance() { try { return localStorage.getItem('live-ambiance'); } catch (e) { return null; } }
  function poserAmbiance(jour) {
    if (jour) RACINE.setAttribute('data-ambiance', 'jour'); else RACINE.removeAttribute('data-ambiance');
  }
  function estJour() { return RACINE.getAttribute('data-ambiance') === 'jour'; }
  poserAmbiance(lireAmbiance() === 'jour');

  // ---------------------------------------------------------------------------------------------- utilitaires
  function $(id) { return document.getElementById(id); }
  function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
  function attrs(n, a) { for (var k in a) { var v = String(a[k]); if (n.getAttribute(k) !== v) n.setAttribute(k, v); } return n; }
  function sv(tag, a, txt) { var e = attrs(document.createElementNS(SVG, tag), a); if (txt != null) e.textContent = txt; return e; }
  function vider(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function dire(n, t) { if (n.textContent !== t) n.textContent = t; }
  function montrer(n, oui) { if (n.hasAttribute('hidden') === oui) n.toggleAttribute('hidden', !oui); }   // attribut : un <svg> n'a pas la propriété hidden
  function phrase(id, t) { var n = $(id); dire(n, t || ''); montrer(n, !!t); }
  function objet(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }
  function liste(v) { return Array.isArray(v) ? v.filter(function (x) { return x && typeof x === 'object' && !Array.isArray(x); }) : null; }
  function nb(v) { return typeof v === 'number' && isFinite(v) && v >= 0 ? v : null; }
  function mot(v, max) { return typeof v === 'string' && v.trim() ? Array.from(v.trim()).slice(0, max || 80).join('') : null; }
  function f(v) { v = nb(v); return v == null ? '—' : Math.round(v).toLocaleString('fr-FR'); }
  function pct(v) { v = nb(v); return v == null || v > 101 ? null : Math.min(100, Math.round(v)); }
  function pc(v) { return v == null ? '—' : v + ' %'; }
  function s(n, sing, plur) { return n != null && n < 2 ? sing : plur; }
  function sommet(l, cle) { return l.reduce(function (m, x) { var v = nb(x[cle]); return v != null && v > m ? v : m; }, 0); }
  function propre(o, k) { return Object.prototype.hasOwnProperty.call(o, k) ? o[k] : null; }
  function jourTs(j) { return typeof j === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(j) && !isNaN(Date.parse(j)) ? Date.parse(j) : null; }
  // Les jours du relevé sont des jours UTC : affichés en UTC, sinon la veille s'affiche à l'ouest de Greenwich.
  function dateJour(j, o) { var t = jourTs(j); if (t == null) return '—'; o.timeZone = 'UTC'; return new Date(t).toLocaleDateString('fr-FR', o); }
  function essai(quoi, fn) { try { fn(); } catch (e) { console.warn('secubox-live : ' + quoi, e); } }

  // Met `parent` en accord avec `items` sans recréer ce qui existe déjà (une clé = un élément).
  var ENFANTS = new WeakMap();
  function accorder(parent, items, cle, creer, maj) {
    var avant = ENFANTS.get(parent) || new Map(), apres = new Map(), actif = document.activeElement, ref;
    items.forEach(function (x, i) {
      var k = String(cle(x, i));
      while (apres.has(k)) k += '+';
      var n = avant.get(k) || creer(x, i);
      n.setAttribute('data-k', k);
      maj(n, x, i);
      apres.set(k, n);
    });
    avant.forEach(function (n, k) { if (apres.get(k) !== n) n.remove(); });
    ref = parent.firstChild;
    apres.forEach(function (n) { if (n === ref) ref = ref.nextSibling; else parent.insertBefore(n, ref); });
    ENFANTS.set(parent, apres);
    if (actif && actif !== document.activeElement && actif.isConnected && parent.contains(actif)) actif.focus({ preventScroll: true });
    return apres;
  }

  var noms = null;
  try { noms = new Intl.DisplayNames(['fr'], { type: 'region' }); } catch (e) { noms = null; }
  function codeOk(c) { return typeof c === 'string' && /^[A-Z]{2}$/.test(c); }
  function pays(c) { try { return (noms && noms.of(c)) || c; } catch (e) { return c; } }
  function drap(c) { return String.fromCodePoint(127397 + c.charCodeAt(0), 127397 + c.charCodeAt(1)); }

  // ---------------------------------------------------------------------------------------------- infobulle
  // Une seule, par délégation : tout élément `data-b` en a une (survol, focus, toucher ; Échap la ferme).
  var cible = null, parPointeur = false;
  function placer(x, y) {
    var b = $('bulle'), w = b.offsetWidth, h = b.offsetHeight, haut = y - h - 14;
    b.style.left = Math.max(8, Math.min(document.documentElement.clientWidth - w - 8, x)) + 'px';
    b.style.top = (haut < 8 ? Math.min(window.innerHeight - h - 8, y + 22) : haut) + 'px';
  }
  function placerSurCible() {
    var r = cible.getBoundingClientRect();
    placer(r.left + r.width / 2, r.top + Math.min(20, r.height / 2));
  }
  function ouvrir(n, ev) {
    var t = n.getAttribute('data-b');
    if (!t) return;
    cible = n; parPointeur = !!ev;
    dire($('bulle'), t); montrer($('bulle'), true);
    if (ev) placer(ev.clientX + 14, ev.clientY); else placerSurCible();
  }
  function fermer() { cible = null; montrer($('bulle'), false); }
  function rafraichirBulle() {
    if (!cible) return;
    var t = cible.isConnected ? cible.getAttribute('data-b') : null;
    if (t) dire($('bulle'), t); else fermer();
  }
  function porteur(n) { return n && n.closest ? n.closest('[data-b]') : null; }
  function bulles() {
    document.addEventListener('pointerover', function (e) { var n = porteur(e.target); if (n && e.pointerType === 'mouse') ouvrir(n, e); });
    document.addEventListener('pointermove', function (e) { if (cible && parPointeur && e.pointerType === 'mouse' && porteur(e.target) === cible) placer(e.clientX + 14, e.clientY); });
    document.addEventListener('pointerout', function (e) { if (cible && parPointeur && e.pointerType === 'mouse' && porteur(e.relatedTarget) !== cible) fermer(); });
    document.addEventListener('focusin', function (e) { var n = porteur(e.target); if (n && n === e.target) ouvrir(n, null); });
    document.addEventListener('focusout', function (e) { if (e.target === cible) fermer(); });
    document.addEventListener('click', function (e) { var n = porteur(e.target); if (n) ouvrir(n, e); else if (cible) fermer(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && cible) fermer(); });
    document.addEventListener('scroll', function () { if (!cible) return; if (parPointeur) fermer(); else placerSurCible(); }, { passive: true, capture: true });
  }

  // ---------------------------------------------------------------------------------------------- ville
  var L_TOUR = 118, SOL = 330, calques = null;
  function humeur(n) {
    var c = pct(n.cpu);
    if (n.etat === 'hors ligne') return ['😴', 'dort'];
    if (n.etat === 'interface distante') return ['📡', 'à distance'];
    if (n.etat !== 'en ligne') return ['❔', 'état inconnu'];
    if (c == null) return ['🙂', 'en ligne'];
    return c >= 80 ? ['🥵', 'à fond'] : c >= 50 ? ['💪', 'au travail'] : ['😎', 'tranquille'];
  }
  function decor(large) {
    var svg = $('skyline'), k, z, etroit = window.innerWidth < 600;
    if (!calques) {
      calques = { fond: sv('g', { 'aria-hidden': 'true' }), tours: sv('g', {}), sol: sv('g', { 'aria-hidden': 'true' }) };
      svg.appendChild(calques.fond); svg.appendChild(calques.sol); svg.appendChild(calques.tours);
    }
    if (calques.large === large) return;
    calques.large = large;
    attrs(svg, { viewBox: '0 0 ' + large + ' 400' });
    svg.style.setProperty('--large', large + 'px');
    vider(calques.fond); vider(calques.sol);
    var averse = sv('g', { 'class': 'averse', stroke: 'var(--cyan)', 'stroke-width': 1, opacity: .22 });
    for (z = 0; z < (etroit ? 60 : 150); z++) {
      var rx = (z * 173) % large, ry = (z * 97) % 330 - 46;
      averse.appendChild(sv('line', { x1: rx, y1: ry, x2: rx - 4, y2: ry + 20 }));
    }
    calques.fond.appendChild(averse);
    [['flotte', 62, 'var(--ambre)'], ['flotte b', 104, 'var(--rose)'], ['flotte c', 34, 'var(--cyan)']].forEach(function (v) {
      var g = sv('g', { 'class': v[0] });
      g.appendChild(sv('rect', { x: -70, y: v[1] - 1, width: 70, height: 2, fill: v[2], opacity: .35 }));
      g.appendChild(sv('ellipse', { cx: 0, cy: v[1], rx: 9, ry: 3.5, fill: v[2] }));
      calques.fond.appendChild(g);
    });
    for (k = 0; k * 46 < large; k++) {
      var bw = 24 + ((k * 37) % 40), bh = 60 + ((k * 53) % 130);
      calques.fond.appendChild(sv('rect', { x: k * 46 - 10, y: SOL - bh, width: bw, height: bh, fill: 'var(--tour)', opacity: .5 }));
    }
    calques.sol.appendChild(sv('rect', { x: 0, y: SOL + 1, width: large, height: 69, fill: 'var(--nuit)', opacity: .86 }));
    calques.sol.appendChild(sv('line', { x1: 0, y1: SOL + 1, x2: large, y2: SOL + 1, stroke: 'var(--cyan)', 'stroke-width': 2 }));
    calques.sol.appendChild(sv('text', { x: large - 8, y: 396, 'text-anchor': 'end', 'font-size': 12 }, '📐 hauteur = mémoire · fenêtres = processeur'));
  }
  function tour(g, n, i, pas) {
    var nom = mot(n.nom, 40) || '—', hu = humeur(n);
    var connu = n.etat === 'en ligne' || n.etat === 'interface distante';   // sinon : aucun chiffre, tour éteinte
    var cpu = connu ? pct(n.cpu) : null, mem = connu ? pct(n.memoire) : null;
    var etat = mot(n.etat, 40) || 'état inconnu', marche = connu ? mot(n.marche, 60) : null;
    var detail = nom + ' (' + (mot(n.role, 40) || '—') + ') · ' + (mot(n.materiel, 80) || 'matériel inconnu') + ' · ' + etat +
      (connu ? ' · processeur ' + pc(cpu) + ', mémoire ' + pc(mem) + (marche ? ' · ' + marche : '') : ' · pas de mesure en ce moment');
    attrs(g, { 'aria-label': detail, 'data-b': hu[0] + ' ' + detail });
    var sign = [nom, hu[1], cpu, mem, connu, i, pas].join('|');
    if (g.getAttribute('data-s') === sign) return;
    attrs(g, { 'data-s': sign });
    vider(g);
    var H = 110 + 1.35 * (mem == null ? 25 : mem), W = Math.min(112, pas - 34), x = i * pas + (pas - W) / 2, y = SOL - H;
    g.appendChild(sv('rect', { 'class': 'mur', x: x, y: y, width: W, height: H, rx: 5, fill: connu ? 'var(--tour2)' : 'var(--eteint)', stroke: connu ? 'var(--violet)' : 'var(--trait)', 'stroke-width': 1.5 }));
    g.appendChild(sv('line', { x1: x + W / 2, y1: y, x2: x + W / 2, y2: y - 22, stroke: connu ? 'var(--rose)' : 'var(--trait)', 'stroke-width': 2 }));
    if (connu) g.appendChild(sv('circle', { cx: x + W / 2, cy: y - 24, r: 4, fill: 'var(--rose)' }));
    var C = 5, tot = C * Math.floor((H - 26) / 17), allume = cpu == null ? 0 : Math.round(tot * cpu / 100), cw = (W - 20) / C, q;
    for (q = 0; q < tot; q++) {
      var a = (q * 7919 + i * 31) % tot < allume;
      g.appendChild(sv('rect', { x: x + 10 + (q % C) * cw + 2, y: y + 14 + Math.floor(q / C) * 17, width: cw - 5, height: 9, rx: 1.5,
        fill: a ? (q % 4 ? 'var(--ambre)' : 'var(--cyan)') : connu ? 'var(--eteint)' : 'var(--tour)', opacity: a ? .95 : .75 }));
    }
    g.appendChild(sv('text', { x: x + W / 2, y: y - 34, 'text-anchor': 'middle', 'font-size': 24 }, hu[0]));
    g.appendChild(sv('text', { 'class': 'nom', x: x + W / 2, y: 358, 'text-anchor': 'middle', 'font-size': 17, 'font-weight': 600 }, nom.length > 11 ? nom.slice(0, 10) + '…' : nom));
    g.appendChild(sv('text', { x: x + W / 2, y: 379, 'text-anchor': 'middle', 'font-size': 13 }, connu ? hu[1] + ' · ' + pc(cpu) : hu[1]));
  }
  function ville(brut) {
    var N = liste(brut) || [], large = Math.max(1180, N.length * L_TOUR), pas = large / Math.max(1, N.length);
    decor(large);
    accorder(calques.tours, N, function (n, i) { return mot(n.nom, 40) || 'sans nom ' + i; },
      function () { return sv('g', { 'class': 'tour', tabindex: 0, role: 'img' }); },
      function (g, n, i) { tour(g, n, i, pas); });
    phrase('ville-note', N.length ? '' : liste(brut) ? 'Aucun boîtier publié.' : faute('Relevé des boîtiers indisponible.'));
  }

  // ---------------------------------------------------------------------------------------------- ouverture et billets
  function ouverture(e, t) {
    var b = nb(t.bloquees_24h), m = nb(t.menaces_24h), si = nb(t.sites_publies), h = [];
    montrer($('h-stop'), b != null);
    dire($('h-stop'), b == null ? '' : f(b));
    dire($('h-suite'), b == null ? 'Le compteur fait une pause' : s(b, 'attaque stoppée net', 'attaques stoppées net'));
    if (b == null) h.push('Le nombre d’attaques stoppées n’est pas mesuré en ce moment.');
    if (m != null) h.push('En 24 heures, ' + f(m) + s(m, ' requête louche a frappé à la porte.', ' requêtes louches ont frappé à la porte.'));
    if (si != null) h.push((m != null ? 'Pendant ce temps, ' : '') + f(si) + s(si, ' site restait derrière le pare-feu.', ' sites restaient derrière le pare-feu.'));
    dire($('h-phrase'), h.join(' '));
    var on = nb(t.noeuds_en_ligne), tot = nb(t.noeuds_total), et = e.etat_global, txt = [];
    if (on != null && tot != null) txt.push(f(on) + s(on, ' tour allumée sur ', ' tours allumées sur ') + f(tot));
    txt.push(et === 'ok' ? 'réseau au complet' : et === 'degrade' ? 'réseau incomplet' : 'état du réseau inconnu');
    var ts = instant(e);
    if (ts) txt.push('relevé à ' + ts.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }));
    dire($('h-etat'), txt.join(' · '));
    $('pouls').classList.toggle('ok', et === 'ok');
    $('pouls').classList.toggle('degrade', et === 'degrade');
    dire($('t-sites'), f(si)); dire($('t-requetes'), f(t.requetes_24h)); dire($('t-menaces'), f(m)); dire($('t-bans'), f(t.bans_actifs));
    dire($('t-noeuds'), on == null || tot == null ? '—' : f(on) + ' / ' + f(tot));
  }

  // ---------------------------------------------------------------------------------------------- carte
  var carte = 'attaques', mondeCalques = null, dernieres = {};
  function terre() {
    var d = '';
    if (typeof TERRE !== 'string') return d;
    TERRE.split('|').forEach(function (l, j) {
      var cur = l.charAt(0) === '1', x = 0;
      l.slice(1).split(',').forEach(function (n) { n = +n; if (cur) for (var i = 0; i < n; i++) d += 'M' + (x + i + .5) + ',' + (j + .5) + 'h0'; x += n; cur = !cur; });
    });
    return d;
  }
  function monde() {
    var svg = $('monde'), att = carte === 'attaques', coul = att ? 'var(--rose)' : 'var(--cyan)', quoi = att ? 'attaque' : 'visite';
    attrs($('m-att'), { 'aria-pressed': att }); attrs($('m-vis'), { 'aria-pressed': !att });
    attrs(svg, { 'aria-label': 'Carte du monde des ' + (att ? 'attaques' : 'visites') + ' par pays ; flèches du clavier pour passer d’un pays à l’autre' });
    if (!mondeCalques) {
      svg.appendChild(sv('path', { d: terre(), fill: 'none', stroke: 'var(--terre)', 'stroke-width': .72, 'stroke-linecap': 'round', 'aria-hidden': 'true' }));
      mondeCalques = { ondes: sv('g', { 'aria-hidden': 'true' }), points: sv('g', {}) };
      svg.appendChild(mondeCalques.ondes); svg.appendChild(mondeCalques.points);
      mondeCalques.points.addEventListener('keydown', flecher);
    }
    var brut = liste(objet(dernieres.cartes)[carte]);
    var l = (brut || []).filter(function (p) { return codeOk(p.code) && nb(p.n) != null; }).slice(0, 60);
    var max = Math.max(1, sommet(l, 'n'));
    var places = l.filter(function (p) { return typeof CENTRE === 'object' && propre(CENTRE, p.code); })
      .map(function (p) { var c = CENTRE[p.code]; return { code: p.code, n: p.n, x: (c[1] + 180) / 3, y: (90 - c[0]) / 3, r: .7 + 2.3 * Math.sqrt(p.n / max) }; });
    accorder(mondeCalques.ondes, places.slice(0, 6), function (p) { return p.code; },
      function () { return sv('circle', { 'class': 'onde', r: 6 }); },
      function (o, p, i) { attrs(o, { cx: p.x, cy: p.y, stroke: coul }); o.style.animationDelay = (i * .4) + 's'; });
    accorder(mondeCalques.points, places, function (p) { return p.code; },
      function () {
        var g = sv('g', { 'class': 'point', role: 'img', tabindex: -1 });
        g.appendChild(sv('circle', { 'class': 'touche', fill: 'transparent' }));
        g.appendChild(sv('circle', { 'class': 'rond', 'fill-opacity': .82, stroke: 'var(--nuit)', 'stroke-width': .2 }));
        return g;
      },
      function (g, p) {
        var t = pays(p.code) + ' : ' + f(p.n) + ' ' + s(p.n, quoi, quoi + 's');
        attrs(g, { 'aria-label': t, 'data-b': drap(p.code) + ' ' + t });
        attrs(g.firstChild, { cx: p.x, cy: p.y, r: p.r + .8 });
        attrs(g.lastChild, { cx: p.x, cy: p.y, r: p.r, fill: coul });
      });
    var pts = Array.from(mondeCalques.points.children), un = pts.indexOf(document.activeElement);
    pts.forEach(function (g, i) { attrs(g, { tabindex: i === Math.max(0, un) ? 0 : -1 }); });
    accorder($('top'), l.slice(0, 6), function (p) { return p.code; }, function () { return el('li'); },
      function (li, p) { dire(li, drap(p.code) + ' ' + pays(p.code) + ' · ' + f(p.n)); });
    phrase('monde-note', !brut ? faute('Source indisponible.') : l.length ? '' : att ? 'Aucune attaque géolocalisée.' : 'Aucune visite géolocalisée.');
  }
  function flecher(e) {
    var pts = Array.from(mondeCalques.points.children), i = pts.indexOf(document.activeElement), j;
    if (i < 0) return;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') j = (i + 1) % pts.length;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') j = (i + pts.length - 1) % pts.length;
    else if (e.key === 'Home') j = 0;
    else if (e.key === 'End') j = pts.length - 1;
    else return;
    e.preventDefault();
    attrs(pts[i], { tabindex: -1 }); attrs(pts[j], { tabindex: 0 });
    pts[j].focus({ preventScroll: true });
  }

  // ---------------------------------------------------------------------------------------------- portes
  var PORTES = {
    host_anomaly: ['👻', 'Adresses fantômes', 'Un nom de site qui n’existe pas ici'],
    aspirateur_ua: ['🌀', 'Aspirateurs', 'Copient des sites entiers à la chaîne'],
    robots: ['🤖', 'Robots curieux', 'Indexent sans demander'],
    recon_crawler: ['🔦', 'Éclaireurs', 'Font le tour avant de frapper'],
    leurre: ['🍯', 'Tombés dans le pot de miel', 'Ont touché un faux service'],
    leurre_redirige: ['🪤', 'Guidés vers le piège', 'Redirigés vers un leurre'],
    scanners: ['📡', 'Scanners', 'Cherchent une faille au hasard'],
    waf_fingerprint: ['🔎', 'Détectives', 'Essaient d’identifier le pare-feu']
  };
  function portes(brut) {
    var l = liste(brut), M = (l || []).slice(0, 20), max = sommet(M, 'n');
    accorder($('portes'), M, function (m, i) { return mot(m.categorie, 40) || 'sans catégorie ' + i; },
      function () {
        var d = el('div', 'porte'), em = el('em'), u = el('u');
        em.setAttribute('aria-hidden', 'true'); u.appendChild(el('i'));
        [em, el('span'), el('b'), el('small'), u].forEach(function (x) { d.appendChild(x); });
        return d;
      },
      function (d, m) {
        var cat = mot(m.categorie, 40), k = (cat && propre(PORTES, cat)) || ['👾', cat ? cat.replace(/_/g, ' ') : 'Catégorie inconnue', 'Autre tentative notée par le pare-feu'];
        var n = nb(m.n), c = d.children;
        dire(c[0], k[0]); dire(c[1], k[1]); dire(c[2], f(n)); dire(c[3], k[2]);
        c[4].firstChild.style.width = (n ? Math.max(1.5, 100 * n / max) : 0) + '%';
      });
    phrase('portes-note', !l ? faute('Journal du pare-feu indisponible.') : M.length ? '' : 'Aucune tentative relevée sur 24 h.');
  }

  // ---------------------------------------------------------------------------------------------- heure (égaliseur)
  var heureCalques = null;
  function heure(brut, vieux) {
    var svg = $('heure'), l = liste(brut), W = (l || []).slice(-60), dec = 60 - W.length;
    if (!heureCalques) {
      heureCalques = { grille: sv('g', {}), barres: sv('g', {}), g: sv('text', { x: 28, y: 250, 'font-size': 12 }), d: sv('text', { x: 476, y: 250, 'text-anchor': 'end', 'font-size': 12 }) };
      ['grille', 'barres', 'g', 'd'].forEach(function (k) { svg.appendChild(heureCalques[k]); });
    }
    montrer(svg, W.length > 0);
    phrase('heure-vide', W.length ? '' : faute('Journal du pare-feu indisponible.'));
    if (!W.length) { dire($('heure-note'), ''); return; }
    var mes = W.filter(function (p) { return nb(p.bloquees) != null; }), max = sommet(W, 'bloquees');
    var tot = mes.reduce(function (a, p) { return a + p.bloquees; }, 0), niveaux = Math.max(1, Math.min(24, Math.ceil(max))), u = 205 / niveaux;
    var lignes = max ? [max, Math.round(max / 2)].filter(function (v, i, t) { return v > 0 && t.indexOf(v) === i; }) : [];
    accorder(heureCalques.grille, lignes, function (v, i) { return i; },
      function () { var g = sv('g', {}); g.appendChild(sv('line', { x1: 34, x2: 480, stroke: 'var(--trait)' })); g.appendChild(sv('text', { x: 30, 'text-anchor': 'end', 'font-size': 11 })); return g; },
      function (g, v) {
        var y = 225 - 205 * v / max;
        attrs(g.firstChild, { y1: y, y2: y }); attrs(g.lastChild, { y: y + 4 });
        dire(g.lastChild, v >= 1000 ? v.toLocaleString('fr-FR', { notation: 'compact', maximumFractionDigits: 1 }) : String(v));
      });
    accorder(heureCalques.barres, W, function (p, i) { return dec + i; },
      function (p, i) {
        var g = sv('g', {}), x = 36 + (dec + i) * 7.4;
        g.appendChild(sv('line', { x1: x + 2.8, x2: x + 2.8, y1: 225, 'stroke-width': 5.6 }));
        g.appendChild(sv('rect', { x: x - .9, y: 10, width: 7.4, height: 218, fill: 'transparent' }));
        return g;
      },
      function (g, p, i) {
        var n = nb(p.bloquees), min = 59 - dec - i;
        // une brique = une requête tant que le pic tient en 24 briques, sinon une brique = pic / 24 ; hauteur arrondie
        // à la brique supérieure (une seule requête se voit), la valeur exacte est dans l'infobulle
        attrs(g.firstChild, n == null ? { y2: 222, stroke: 'var(--trait)', 'stroke-dasharray': 'none' }
          : { y2: max ? 225 - Math.ceil(n * niveaux / max - 1e-9) * u : 225, stroke: 'var(--rose)', 'stroke-dasharray': Math.max(.5, u - 2) + ' ' + Math.min(2, u - .5) });
        attrs(g, { 'data-b': (min ? 'il y a ' + min + ' min' : 'à l’instant') + (vieux ? ' (avant le relevé)' : '') + ' : ' + (n == null ? 'non mesuré' : f(n) + s(n, ' bloquée', ' bloquées')) });
      });
    dire(heureCalques.g, vieux ? '1 h avant le relevé' : 'il y a 1 h'); dire(heureCalques.d, vieux ? 'au relevé' : 'maintenant');
    var note = mes.length ? f(tot) + s(tot, ' bloquée', ' bloquées') + ' · pic ' + f(max) + '/min' : 'non mesurée';
    dire($('heure-note'), note);
    attrs(svg, { 'aria-label': 'Requêtes bloquées par minute sur la dernière heure : ' + note });
  }

  // ---------------------------------------------------------------------------------------------- atelier
  function cles(id, l) {
    accorder($(id), l, function (k, i) { return i; },
      function () { var d = el('div'); d.appendChild(el('b')); d.appendChild(el('span', 'note')); return d; },
      function (d, k) { dire(d.firstChild, k[0] + ' ' + k[1]); dire(d.lastChild, k[2]); });
  }
  var CI = { success: ['✅', 'verte'], failure: ['🔴', 'rouge'], cancelled: ['⚪', 'annulée'], in_progress: ['⏳', 'en cours'], queued: ['⏳', 'en attente'], pending: ['⏳', 'en attente'] };
  var OUTILS = { feat: '✨', fix: '🩹', docs: '📚', perf: '⚡', chore: '🧹' };
  function atelier(brut) {
    var d = objet(brut), ci = mot(d.ci_master, 30), c = ci ? propre(CI, ci) || ['⚪', ci] : ['⚪', '—'], l = liste(d.dernieres);
    cles('cles', [['🚀', f(d.fusions_7j), 'livraisons en 7 jours'], [c[0], c[1], 'chaîne de tests'], ['💡', f(d.issues_ouvertes), 'idées ouvertes']]);
    accorder($('term'), (l || []).slice(0, 5), function (p, i) { return nb(p.num) == null ? 'sans numéro ' + i : p.num; },
      function () { var x = el('div'), e = el('span'); e.setAttribute('aria-hidden', 'true'); [e, el('span', 'n'), el('span')].forEach(function (k) { x.appendChild(k); }); return x; },
      function (x, p) {
        var t = (mot(p.titre, 160) || 'sans titre').replace(/\s*\((ref|closes) [^)]*\)/g, ''), m = /^(\w+)(\([^)]*\))?!?:\s*/.exec(t);
        dire(x.children[0], (m && propre(OUTILS, m[1])) || '🔧');
        dire(x.children[1], nb(p.num) == null ? '—' : '#' + p.num);
        dire(x.children[2], m && t.slice(m[0].length) ? t.slice(m[0].length) : t);
      });
    phrase('term-note', brut == null ? faute('GitHub injoignable pour le moment.') : l && l.length ? '' : 'Aucune livraison récente à montrer.');
  }

  // ---------------------------------------------------------------------------------------------- histoire
  var BANDES = [['visites', '👋 visites', 'var(--cyan)', 0], ['attaques', '👾 attaques', 'var(--rose)', 118], ['bans', '⛔ bans', 'var(--ambre)', 236]];
  var histoCalques = null, defile = false;
  function mesures(H, k) { return H.filter(function (x) { return nb(x[k]) != null; }); }
  function suivreTitres() {
    // Les titres des bandes suivent le défilement : la frise commence à aujourd'hui sur un petit écran.
    var z = $('frise'), w = $('histo').getBoundingClientRect().width;
    if (!histoCalques || !w) return;
    var x = 50 + Math.max(0, z.scrollLeft) * 1100 / w;
    Array.from(histoCalques.titres.children).forEach(function (t) { attrs(t, { x: Math.round(x) }); });
  }
  function histoire(brut, prod, genere) {
    var svg = $('histo'), H = (liste(brut) || []).slice(-400), dep = objet(prod).depuis, hd = objet(prod).historique_depuis;
    var notes = [];
    if (jourTs(dep) != null) notes.push('en production depuis le ' + dateJour(dep, { day: 'numeric', month: 'long', year: 'numeric' }));
    if (jourTs(hd) != null && hd !== dep) notes.push('historique depuis le ' + dateJour(hd, { day: 'numeric', month: 'long', year: 'numeric' }));
    dire($('histo-note'), notes.join(' · '));
    var ref = genere ? genere.getTime() : Date.now(), jours = jourTs(dep) == null ? null : Math.round((ref - jourTs(dep)) / L_JOUR);
    var som = function (k) { var v = mesures(H, k); return v.length ? v.reduce(function (a, x) { return a + x[k]; }, 0) : null; };
    cles('cumuls', [['🎂', f(jours), s(nb(jours), 'jour debout', 'jours debout')], ['👋', f(som('visites')), 'visites mesurées'], ['👾', f(som('attaques')), 'attaques mesurées'], ['⛔', f(som('bans')), 'bans posés']]);
    montrer($('frise'), H.length > 0);
    phrase('histo-vide', H.length ? '' : faute('Historique indisponible.'));
    if (!H.length) return;
    if (!histoCalques) {
      histoCalques = { jours: sv('g', {}), titres: sv('g', {}), g: sv('text', { x: 50, y: 366, 'font-size': 12 }), d: sv('text', { x: 1090, y: 366, 'text-anchor': 'end', 'font-size': 12 }) };
      BANDES.forEach(function (b) { svg.appendChild(sv('line', { x1: 50, x2: 1090, y1: b[3] + 104, y2: b[3] + 104, stroke: 'var(--trait)' })); });
      ['jours', 'titres', 'g', 'd'].forEach(function (k) { svg.appendChild(histoCalques[k]); });
      $('frise').addEventListener('scroll', suivreTitres, { passive: true });
      window.addEventListener('resize', suivreTitres);
    }
    var larg = 1040 / H.length, w = Math.max(1, larg - 2), maxi = {}, bref = { day: 'numeric', month: 'short' };
    var cours = genere ? genere.toISOString().slice(0, 10) : null;
    BANDES.forEach(function (b) { maxi[b[0]] = sommet(H, b[0]); });
    accorder(histoCalques.titres, BANDES, function (b) { return b[0]; },
      function (b) { return sv('text', { x: 50, y: b[3] + 16, 'font-size': 13, 'font-weight': 600 }); },
      function (t, b) { dire(t, b[1] + ' par jour · ' + (mesures(H, b[0]).length ? 'pic ' + f(maxi[b[0]]) : 'aucun jour mesuré')); });
    accorder(histoCalques.jours, H, function (x, i) { return jourTs(x.jour) == null ? 'jour ' + i : x.jour; },
      function () { var g = sv('g', { 'class': 'jour' }); BANDES.forEach(function () { g.appendChild(sv('rect', {})); }); g.appendChild(sv('rect', { y: 0, height: 345, fill: 'transparent' })); return g; },
      function (g, x, i) {
        var X = 50 + i * larg, q = function (v) { return nb(v) == null ? 'non mesuré' : f(v); };
        BANDES.forEach(function (b, j) {
          var v = nb(x[b[0]]), y0 = b[3] + 104, hh = v == null ? 8 : maxi[b[0]] ? 78 * v / maxi[b[0]] : 0;
          attrs(g.children[j], { x: X, y: y0 - hh, width: w, height: hh, rx: v == null ? 0 : Math.min(2, w / 2), fill: v == null ? 'var(--trait)' : b[2] });
        });
        attrs(g.lastChild, { x: X, width: larg });
        attrs(g, { 'data-b': dateJour(x.jour, { day: 'numeric', month: 'long' }) + (cours && x.jour === cours ? ' (journée en cours)' : '') + ' · visites ' + q(x.visites) + ' · attaques ' + q(x.attaques) + ' · bans ' + q(x.bans) });
      });
    dire(histoCalques.g, dateJour(H[0].jour, bref)); dire(histoCalques.d, dateJour(H[H.length - 1].jour, bref));
    attrs(svg, { 'aria-label': 'Par jour : ' + BANDES.map(function (b) { return b[0] + ' ' + f(som(b[0])) + (som(b[0]) == null ? ' (non mesuré)' : ''); }).join(', ') });
    if (!defile) { defile = true; $('frise').scrollLeft = $('frise').scrollWidth; }   // une seule fois : ensuite, le visiteur décide
    suivreTitres();
  }

  function route(brut) {
    var l = (liste(brut) || []).filter(function (x) { return mot(x.nom); });
    montrer($('bloc-route'), l.length > 0);
    accorder($('route'), l, function (x) { return x.nom; },
      function () { var li = el('li'); li.appendChild(el('span')); li.appendChild(el('span', 'note')); return li; },
      function (li, x) { dire(li.firstChild, mot(x.nom)); dire(li.lastChild, mot(x.etat, 40) || ''); });
  }

  // ---------------------------------------------------------------------------------------------- relevé
  var recu = false, enEchec = false, dernier = null, decalage = 0;
  function instant(e) {
    var g = nb(e.genere_le), d = g ? new Date(g * 1000) : null;
    return d && !isNaN(d.getTime()) ? d : null;
  }
  // Aucun relevé reçu : on ne sait pas QUELLE source manque, on ne l'accuse pas.
  function faute(t) { return recu ? t : 'Données indisponibles.'; }
  function annoncer(t) { dire($('annonce'), t); }
  function etiquette(g, vieux, age) {
    var n = $('releve'), quand = g ? g.toLocaleString('fr-FR', { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit' }) : null;
    n.classList.toggle('alerte', enEchec || vieux);
    dire(n, enEchec ? '⚠️ données momentanément indisponibles' + (quand ? ' · dernier relevé du ' + quand : '')
      : !quand ? 'heure du relevé inconnue'
      : vieux ? '⚠️ relevé ancien (' + duree(age) + ') · ' + quand : 'relevé du ' + quand);
  }
  function duree(sec) { return sec < 7200 ? Math.round(sec / 60) + ' min' : sec < 172800 ? Math.round(sec / 3600) + ' h' : Math.round(sec / 86400) + ' jours'; }
  function rendre(brut, maintenant) {
    var e = objet(brut), t = objet(e.tuiles), g = instant(e), age = g ? (maintenant - g.getTime()) / 1000 : 0, vieux = g != null && age > VIEUX_S;
    dernieres = e;
    essai('relevé', function () { etiquette(g, vieux, age); });
    essai('ouverture', function () { ouverture(e, t); });
    essai('ville', function () { ville(e.noeuds); });
    essai('carte', monde);
    essai('portes', function () { portes(e.menaces); });
    essai('heure', function () { heure(e.waf_heure, vieux); });
    essai('atelier', function () { atelier(e.dev); });
    essai('histoire', function () { histoire(e.histo, e.production, g); });
    essai('feuille de route', function () { route(e.feuille_de_route); });
    essai('pluie', motsPluie);
    if (!enEchec) annoncer(vieux ? 'Le relevé affiché est ancien.' : '');
    rafraichirBulle();
  }
  var encours = false;
  function charger() {
    if (encours) return;
    encours = true;
    var coupe = typeof AbortController === 'function' ? new AbortController() : null;
    var minuteur = setTimeout(function () { if (coupe) coupe.abort(); }, 15000);
    fetch('/etat.json', { cache: 'no-store', credentials: 'omit', signal: coupe ? coupe.signal : undefined })
      .then(function (r) {
        if (!r.ok) throw new Error(String(r.status));
        // L'âge du relevé se mesure à l'horloge du serveur : celle du visiteur peut être fausse.
        var d = Date.parse(r.headers.get('Date') || '');
        return r.json().then(function (j) {
          if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('relevé illisible');
          enEchec = false; recu = true; dernier = j;
          decalage = isNaN(d) ? 0 : d - Date.now();
          rendre(j, Date.now() + decalage);
        });
      })
      .catch(function () {
        enEchec = true;
        if (recu) {
          rendre(dernier, Date.now() + decalage);                   // dernier relevé gardé, vieillit à l'horloge du serveur
        } else {
          rendre({}, Date.now());
          dire($('h-suite'), 'Le relevé ne répond pas');
          dire($('h-phrase'), 'Données momentanément indisponibles. Nouvel essai dans quelques secondes.');
        }
        annoncer('Données momentanément indisponibles.');
      })
      .then(function () { clearTimeout(minuteur); encours = false; dernierEssai = Date.now(); });
  }
  var dernierEssai = 0;

  // ---------------------------------------------------------------------------------------------- pluie : les codes des pays qui attaquent
  var pluie = null, FIXES = ['403', 'BAN', 'WAF', '0x7F', 'OK'];
  function motsPluie() {
    if (!pluie) return;
    var l = (liste(objet(dernieres.cartes).attaques) || []).map(function (p) { return p.code; }).filter(codeOk).slice(0, 40);
    var m = l.concat(FIXES);
    if (m.join() === pluie.mots.join()) return;
    pluie.mots = m;
    if (pluie.fixe()) pluie.trace(0);
  }
  function lancerPluie() {
    var c = $('pluie'), x = c.getContext && c.getContext('2d');
    if (!x) return;
    var PAS = 26, col = [], avant = 0, minuteur = 0, couleur = '', calme = window.matchMedia ? matchMedia('(prefers-reduced-motion:reduce)') : { matches: false };
    function taille() {
      var memeLargeur = c.width === window.innerWidth;
      c.width = window.innerWidth; c.height = window.innerHeight;
      if (memeLargeur && col.length) return;                       // barre d'adresse du téléphone : seule la hauteur change
      col = [];
      for (var i = 0; i < c.width / PAS; i++) col.push({ y: (i * 197) % Math.max(1, c.height), v: 18 + (i * 31) % 46, m: i * 7 });
    }
    function teinte() { couleur = getComputedStyle(RACINE).getPropertyValue('--pluie'); }
    function trace(dt) {
      var n = pluie.mots.length;
      x.clearRect(0, 0, c.width, c.height); x.font = '600 12px "JetBrains Mono",monospace'; x.fillStyle = couleur;
      col.forEach(function (k, i) {
        k.y += k.v * dt; if (k.y > c.height + 150) k.y = -20;
        for (var q = 0; q < 7; q++) { x.globalAlpha = 1 - q / 7; x.fillText(pluie.mots[(k.m + q) % n], i * PAS, k.y - q * 18); }
      });
      x.globalAlpha = 1;
    }
    function boucle() {
      minuteur = 0;
      if (document.hidden || calme.matches) return;
      var t = Date.now();
      trace(Math.min(.2, (t - avant) / 1000)); avant = t;
      minuteur = setTimeout(function () { requestAnimationFrame(boucle); }, c.width < 600 ? 120 : 70);
    }
    function reprendre() {
      if (minuteur) { clearTimeout(minuteur); minuteur = 0; }
      if (document.hidden) return;
      if (calme.matches) trace(0); else { avant = Date.now(); boucle(); }
    }
    pluie = { mots: FIXES.slice(), trace: trace, fixe: function () { return calme.matches; }, teinte: function () { teinte(); if (calme.matches) trace(0); } };
    window.addEventListener('resize', function () { taille(); if (calme.matches) trace(0); });
    document.addEventListener('visibilitychange', reprendre);
    if (calme.addEventListener) calme.addEventListener('change', reprendre);
    taille(); teinte(); reprendre();
  }
  function pauserHorsEcran() {
    if (typeof IntersectionObserver !== 'function') return;
    var o = new IntersectionObserver(function (l) { l.forEach(function (x) { x.target.classList.toggle('pause', !x.isIntersecting); }); });
    [$('skyline'), $('monde'), $('pouls')].forEach(function (n) { o.observe(n); });
  }

  // ---------------------------------------------------------------------------------------------- départ
  function bouton() { dire($('ambiance'), estJour() ? '🌃 Passer à la nuit' : '☀️ Passer au jour'); }
  function depart() {
    bouton();
    $('ambiance').addEventListener('click', function () {
      var jour = !estJour();
      poserAmbiance(jour); bouton();
      try { localStorage.setItem('live-ambiance', jour ? 'jour' : 'nuit'); } catch (e) { /* stockage indisponible : choix gardé le temps de la page */ }
      if (pluie) pluie.teinte();
    });
    $('m-att').addEventListener('click', function () { carte = 'attaques'; monde(); fermer(); });
    $('m-vis').addEventListener('click', function () { carte = 'visiteurs'; monde(); fermer(); });
    bulles();
    essai('pluie', lancerPluie);
    essai('animations', pauserHorsEcran);
    charger();
    setInterval(function () { if (!document.hidden) charger(); }, PERIODE);
    document.addEventListener('visibilitychange', function () { if (!document.hidden && Date.now() - dernierEssai > PERIODE) charger(); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', depart); else depart();
})();
