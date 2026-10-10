/* SPDX-License-Identifier: LicenseRef-CMSD-1.0 */
/* Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> */
(function () {
    'use strict';
    var NAC = '/api/v1/nac';
    function $(id) { return document.getElementById(id); }
    function el(t, c, x) { var e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; }
    async function json(u) {
        var t = null; try { t = localStorage.getItem('sbx_token'); } catch (e) { /* stockage indisponible */ }
        var r = await fetch(u, { headers: t ? { Authorization: 'Bearer ' + t } : {}, credentials: 'same-origin' });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
    }
    function nom(d) { return d.custom_hostname || d.hostname || d.ip || d.mac; }
    function champ(g, libelle, v) { if (v === undefined || v === null || v === '') return; var c = el('div', 'carte'); c.appendChild(el('small', null, libelle)); c.appendChild(el('span', null, String(v))); g.appendChild(c); }
    async function liste() {
        $('fiche').hidden = true; $('liste').hidden = false; $('titre').textContent = '📱 Appareils';
        var d = await json(NAC + '/clients'), g = $('appareils'); g.textContent = '';
        (d.clients || []).forEach(function (c) {
            var a = el('a', 'carte ' + (c.online ? 'ok' : '')); a.href = '#' + encodeURIComponent(c.mac);
            a.appendChild(el('b', null, nom(c)));
            a.appendChild(el('span', 'n', c.online ? 'en ligne' : 'hors ligne'));
            a.appendChild(el('small', null, [c.zone_name, c.ip, c.device_type].filter(Boolean).join(' · ')));
            g.appendChild(a);
        });
        $('nb').textContent = '(' + (d.count != null ? d.count : (d.clients || []).length) + ')';
        if (!(d.clients || []).length) g.appendChild(el('p', 'vide', 'Aucun appareil connu pour l’instant.'));
    }
    async function fiche(mac) {
        $('liste').hidden = true; $('fiche').hidden = false;
        var d = await json(NAC + '/client/' + encodeURIComponent(mac)), g = $('detail'); g.textContent = '';
        $('titre').textContent = '📱 ' + nom(d);
        champ(g, 'Adresse MAC', d.mac); champ(g, 'Adresse IP', d.ip); champ(g, 'Zone', d.zone_name || d.zone);
        champ(g, 'Type', d.device_type); champ(g, 'Fabricant', d.vendor); champ(g, 'Risque', d.risk);
        champ(g, 'Première vue', d.first_seen); champ(g, 'Dernière vue', d.last_seen); champ(g, 'Notes', d.notes);
        var ul = $('events'); ul.textContent = '';
        (d.recent_events || []).forEach(function (e) { ul.appendChild(el('li', null, (e.timestamp || '') + ' — ' + (e.event || ''))); });
        if (!(d.recent_events || []).length) ul.appendChild(el('li', 'vide', 'Aucun événement récent.'));
    }
    async function aller() {
        var mac = decodeURIComponent((location.hash || '').slice(1));
        try { await (mac ? fiche(mac) : liste()); $('erreur').hidden = true; }
        catch (e) { $('erreur').hidden = false; $('erreur').textContent = 'Impossible de lire les appareils (' + e.message + ').'; }
    }
    window.addEventListener('hashchange', aller);
    aller();
}());
