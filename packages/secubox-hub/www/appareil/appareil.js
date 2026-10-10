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
    // Les conteneurs LXC ne sont pas des appareils : pont br-lxc (10.100.0.0/16) ou adresse MAC attribuée par LXC (00:16:3e).
    function estConteneur(c) { return /^10\.100\./.test(c.ip || '') || /^00:16:3e:/i.test(c.mac || ''); }
    function nom(d) { return d.custom_hostname || d.hostname || d.ip || d.mac; }
    function champ(g, libelle, v) { if (v === undefined || v === null || v === '') return; var c = el('div', 'carte'); c.appendChild(el('small', null, libelle)); c.appendChild(el('span', null, String(v))); g.appendChild(c); }
    // Flux SANS DPI, déduits des requêtes DNS (ad-guard /flux) : services et domaines contactés, jamais de volumes — le DNS ne les voit pas.
    async function fluxDns(d) {
        var g = $('flux'), lim = $('flux-limite'); g.textContent = ''; lim.textContent = '';
        try {
            var f = await json('/api/v1/ad-guard/adblock-tv/flux?heures=6&source=' + encodeURIComponent(d.mac || d.ip));
            (f.services || []).slice(0, 8).forEach(function (s) {
                var c = el('div', 'carte ' + (s.bloquees ? 'degrade' : '')); c.appendChild(el('b', null, s.service || '(inconnu)'));
                c.appendChild(el('span', 'n', s.requetes + ' requêtes'));
                c.appendChild(el('small', null, [s.type, s.domaines + ' domaine(s)', s.bloquees ? s.bloquees + ' bloquée(s)' : null].filter(Boolean).join(' · ')));
                g.appendChild(c);
            });
            (f.domaines || []).slice(0, 10).forEach(function (x) {
                var c = el('div', 'carte'); c.appendChild(el('small', null, x.domaine));
                c.appendChild(el('span', null, x.requetes + ' requêtes' + (x.bloquees ? ' · ' + x.bloquees + ' bloquées' : '')));
                g.appendChild(c);
            });
            lim.textContent = f.limite || 'Déduit du DNS : pas de volumes.';
            if (!g.children.length) { lim.textContent = 'Aucune requête DNS vue pour cet appareil sur la période. ' + lim.textContent; }
        } catch (e) { lim.textContent = 'Flux DNS indisponibles (' + e.message + ').'; }
    }
    async function liste() {
        $('fiche').hidden = true; $('liste').hidden = false; $('titre').textContent = '📱 Appareils';
        var d = await json(NAC + '/clients'), g = $('appareils'); g.textContent = '';
        var tous = d.clients || [], clients = tous.filter(function (c) { return !estConteneur(c); }), masques = tous.length - clients.length;
        clients.forEach(function (c) {
            var a = el('a', 'carte ' + (c.online ? 'ok' : '')); a.href = '#' + encodeURIComponent(c.mac);
            a.appendChild(el('b', null, nom(c)));
            a.appendChild(el('span', 'n', c.online ? 'en ligne' : 'hors ligne'));
            a.appendChild(el('small', null, [c.zone_name, c.ip, c.device_type].filter(Boolean).join(' · ')));
            g.appendChild(a);
        });
        $('nb').textContent = '(' + clients.length + ')' + (masques ? ' · ' + masques + ' conteneurs LXC masqués' : '');
        if (!clients.length) g.appendChild(el('p', 'vide', 'Aucun appareil connu pour l’instant.'));
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
        fluxDns(d);
    }
    async function aller() {
        var mac = decodeURIComponent((location.hash || '').slice(1));
        try { await (mac ? fiche(mac) : liste()); $('erreur').hidden = true; }
        catch (e) { $('erreur').hidden = false; $('erreur').textContent = 'Impossible de lire les appareils (' + e.message + ').'; }
    }
    window.addEventListener('hashchange', aller);
    aller();
}());
