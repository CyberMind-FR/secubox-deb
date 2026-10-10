/* SPDX-License-Identifier: LicenseRef-CMSD-1.0 */
/* Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> */
(function () {
    'use strict';
    var API = '/api/v1/hub/apercu';
    var ETATS = { ok: 'Tout fonctionne', degrade: 'Quelque chose demande votre attention', critique: 'Ressources critiques', inconnu: 'État inconnu' };
    function $(id) { return document.getElementById(id); }
    function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
    function pct(v) { return v == null ? '—' : v.toFixed(0) + ' %'; }
    function duree(s) {
        if (s == null) return null;
        var j = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
        return (j ? j + ' j ' : '') + h + ' h ' + m + ' min';
    }
    function rendre(d) {
        var etat = $('etat');
        etat.className = 'etat ' + (ETATS[d.etat] ? d.etat : 'inconnu');
        $('etat-titre').textContent = ETATS[d.etat] || ETATS.inconnu;
        var up = duree(d.uptime);
        $('etat-sous').textContent = up ? 'En service depuis ' + up : '';
        var g = $('espaces'); g.textContent = '';
        (d.espaces || []).forEach(function (e) {
            var c = el('a', 'carte ' + e.etat); c.href = '#' + e.id;
            c.appendChild(el('b', null, (e.icone || '') + ' ' + e.nom));
            c.appendChild(el('span', 'n', e.actifs + ' / ' + e.total));
            c.appendChild(el('small', null, e.arretes.length ? 'À l’arrêt : ' + e.arretes.join(', ') : 'Tous les services actifs'));
            g.appendChild(c);
        });
        if (!(d.espaces || []).length) g.appendChild(el('p', 'vide', 'Menu en cours de préparation, réessayez dans un instant.'));
        var r = d.ressources || {}, rs = $('ressources'); rs.textContent = '';
        [['Processeur', pct(r.cpu)], ['Mémoire', pct(r.memoire)], ['Disque', pct(r.disque)],
         ['Charge', r.charge ? r.charge.map(function (x) { return x.toFixed(2); }).join(' · ') : '—']].forEach(function (p) {
            var c = el('div', 'carte'); c.appendChild(el('small', null, p[0])); c.appendChild(el('span', 'n', p[1])); rs.appendChild(c);
        });
        var a = d.alertes || { total: 0, recentes: [] }, ul = $('alertes'); ul.textContent = '';
        $('nb-alertes').textContent = a.total ? '(' + a.total + ')' : '';
        a.recentes.forEach(function (n) { ul.appendChild(el('li', null, n.title || n.message || n.id || 'Alerte')); });
        if (!a.recentes.length) ul.appendChild(el('li', 'vide', 'Aucune alerte.'));
        $('maj').textContent = 'Mis à jour à ' + new Date().toLocaleTimeString();
    }
    async function charger() {
        try {
            var token = null; try { token = localStorage.getItem('sbx_token'); } catch (e) { /* stockage indisponible */ }
            var r = await fetch(API, { headers: token ? { Authorization: 'Bearer ' + token } : {}, credentials: 'same-origin' });
            if (!r.ok) throw new Error('HTTP ' + r.status);
            $('erreur').hidden = true;
            rendre(await r.json());
        } catch (e) {
            $('erreur').hidden = false;
            $('erreur').textContent = 'Impossible de lire l’état de la box (' + e.message + ').';
        }
    }
    $('rafraichir').addEventListener('click', charger);
    charger();
    setInterval(charger, 30000);
}());
