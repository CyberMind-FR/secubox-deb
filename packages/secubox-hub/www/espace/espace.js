/* SPDX-License-Identifier: LicenseRef-CMSD-1.0 */
/* Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> */
(function () {
    'use strict';
    var LED = { ok: '🟢', warn: '🟠', warning: '🟠', error: '🔴', down: '🔴', checking: '🔵', unknown: '⚪' };
    function $(id) { return document.getElementById(id); }
    function el(t, c, x) { var e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; }
    async function json(u) { var r = await fetch(u, { credentials: 'same-origin' }); if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }
    async function charger() {
        var id = decodeURIComponent((location.hash || '').slice(1));
        try {
            var res = await Promise.all([json('/api/v1/hub/public/menu'), json('/api/v1/hub/public/health-batch').catch(function () { return {}; })]);
            var espace = (res[0].espaces || []).filter(function (e) { return e.id === id; })[0];
            if (!espace) throw new Error('espace inconnu : ' + (id || 'aucun'));
            var sante = (res[1] && res[1].modules) || res[1] || {};
            document.title = 'SecuBox · ' + espace.nom;
            $('titre').textContent = (espace.icone || '') + ' ' + espace.nom;
            var g = $('services'); g.textContent = '';
            espace.items.forEach(function (it) {
                var st = sante[it.id] || {}, a = el('a', 'carte ' + (it.active ? 'ok' : 'degrade')); a.href = it.path;
                a.appendChild(el('b', null, (it.icon || '') + ' ' + it.name));
                a.appendChild(el('span', 'n', (LED[st.status] || LED.unknown) + ' ' + (it.active ? 'actif' : 'à l’arrêt')));
                var pieces = [it.objet, st.msg].filter(Boolean);
                if (pieces.length) a.appendChild(el('small', null, pieces.join(' · ')));
                if (it.description) a.appendChild(el('small', null, it.description));
                g.appendChild(a);
            });
            $('nb').textContent = '(' + espace.items.length + ')';
            $('erreur').hidden = true;
        } catch (e) {
            $('erreur').hidden = false;
            $('erreur').textContent = 'Impossible d’afficher cet espace (' + e.message + ').';
        }
    }
    window.addEventListener('hashchange', charger);
    charger();
}());
