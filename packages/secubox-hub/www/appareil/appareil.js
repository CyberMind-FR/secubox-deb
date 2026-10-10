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
    function estConteneur(c) { return c.conteneur === true || /^10\.100\./.test(c.ip || '') || /^00:16:3e:/i.test(c.mac || ''); }
    var TYPES = { router: 'Routeur / passerelle', computer: 'Ordinateur', phone: 'Téléphone', tablet: 'Tablette', printer: 'Imprimante', smart_home: 'Objet connecté',
                  smart_speaker: 'Enceinte connectée', tv: 'Télévision', media_player: 'Lecteur multimédia', camera: 'Caméra', game_console: 'Console de jeu',
                  nas: 'Stockage réseau (NAS)', iot: 'Objet connecté (IoT)', unknown: 'Type non identifié' };
    // Type fin détecté par le NAC (smartphone, imprimante…), s'il apporte quelque chose de plus que le type général.
    function sousType(c) { return c.device_subtype && c.device_subtype !== c.device_type ? c.device_subtype : null; }
    function libelleType(t) { return TYPES[t] || (t ? t : TYPES.unknown); }
    // Matériel = fabricant (l'OUI de la MAC) + modèle + rôle connu du NAC ; « Unknown » n'est pas un fabricant.
    function materiel(c) {
        var v = c.oui_vendor && !/^unknown$/i.test(c.oui_vendor) ? c.oui_vendor : null;
        return [v, c.model, c.is_secubox ? 'SecuBox' : (c.is_openwrt ? 'OpenWrt' : null)].filter(Boolean).join(' · ');
    }
    // Système d'exploitation : le NAC ne le détecte pas. On le DÉDUIT, avec sa preuve, de deux indices seulement : le nom de l'appareil et les noms de domaine
    // que ses requêtes DNS ont demandés (tests de connectivité propres à chaque système). Rien d'indéduit n'est affiché.
    var REGLES_NOM = [[/^android|pixel|galaxy/i, 'Android'], [/iphone|ipad|ipod/i, 'iOS'], [/macbook|imac|mac-?mini|^mbp/i, 'macOS'], [/^desktop-|^laptop-|^win(dows)?[-_]?/i, 'Windows'],
                      [/raspberrypi|ubuntu|debian|fedora|archlinux/i, 'Linux'], [/tizen|samsung.*(tv|qled)/i, 'Tizen (Samsung)'], [/webos|lgwebos/i, 'webOS (LG)'],
                      [/chromecast/i, 'Google Cast'], [/^roku/i, 'Roku OS'], [/openwrt/i, 'OpenWrt (Linux)']];
    var REGLES_DNS = [[/(^|\.)connectivitycheck\.gstatic\.com$|(^|\.)android\.clients\.google\.com$|(^|\.)play\.googleapis\.com$/i, 'Android'],
                      [/(^|\.)captive\.apple\.com$|(^|\.)gsp\d*-ssl\.ls\.apple\.com$|(^|\.)mzstatic\.com$/i, 'Apple (iOS / macOS)'],
                      [/(^|\.)msftconnecttest\.com$|(^|\.)windowsupdate\.com$|(^|\.)msftncsi\.com$/i, 'Windows'],
                      [/(^|\.)samsungcloudsolution\.com$|(^|\.)samsungotn\.net$|(^|\.)samsungads\.com$/i, 'Tizen (Samsung)'],
                      [/(^|\.)lgtvsdp\.com$|(^|\.)lgappstv\.com$/i, 'webOS (LG)'], [/(^|\.)ping\.archlinux\.org$|(^|\.)deb\.debian\.org$|(^|\.)archive\.ubuntu\.com$/i, 'Linux']];
    function deduireOS(d, domaines) {
        if (d.os) return { nom: d.os, preuve: 'détecté par le NAC' + (d.os_source ? ' (' + d.os_source + ')' : '') };
        if (d.is_secubox) return { nom: 'Linux (SecuBox)', preuve: 'appareil SecuBox' };
        if (d.is_openwrt) return { nom: 'OpenWrt (Linux)', preuve: 'empreinte OpenWrt du NAC' };
        var h = d.custom_hostname || d.hostname || '';
        for (var i = 0; i < REGLES_NOM.length; i++) if (REGLES_NOM[i][0].test(h)) return { nom: REGLES_NOM[i][1], preuve: 'nom de l\u2019appareil « ' + h + ' »' };
        for (var j = 0; j < (domaines || []).length; j++) for (var k = 0; k < REGLES_DNS.length; k++)
            if (REGLES_DNS[k][0].test(domaines[j])) return { nom: REGLES_DNS[k][1], preuve: 'requête DNS vers ' + domaines[j] };
        return null;
    }
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
            var os = deduireOS(d, (f.domaines || []).map(function (x) { return x.domaine; })), carte = $('os-carte');
            if (os && carte) { carte.children[1].textContent = os.nom; carte.children[2].textContent = 'Déduit : ' + os.preuve; }
            lim.textContent = f.limite || 'Déduit du DNS : pas de volumes.';
            if (!g.children.length) { lim.textContent = 'Aucune requête DNS vue pour cet appareil sur la période. ' + lim.textContent; }
        } catch (e) { lim.textContent = 'Flux DNS indisponibles (' + e.message + ').'; }
    }
    async function liste() {
        $('fiche').hidden = true; $('liste').hidden = false; $('titre').textContent = '📱 Appareils';
        var d = await json(NAC + '/clients'), g = $('appareils'); g.textContent = '';
        var tous = d.clients || [], clients = tous.filter(function (c) { return !estConteneur(c); }), masques = tous.length - clients.length;
        clients.sort(function (x, y) { return nom(x).localeCompare(nom(y)); });
        clients.forEach(function (c) {
            var a = el('a', 'carte ' + (c.online ? 'ok' : '')); a.href = '#' + encodeURIComponent(c.mac);
            a.appendChild(el('b', null, nom(c)));
            a.appendChild(el('span', 'n', c.online ? 'en ligne' : 'hors ligne'));
            var os = deduireOS(c, []);
            a.appendChild(el('small', null, [libelleType(c.device_type), sousType(c), materiel(c), os && os.nom].filter(Boolean).join(' · ')));
            a.appendChild(el('small', null, [c.zone_name, c.ip].filter(Boolean).join(' · ')));
            g.appendChild(a);
        });
        $('nb').textContent = '(' + clients.length + ')' + (masques ? ' · ' + masques + ' conteneurs LXC masqués' : '');
        if (!clients.length) g.appendChild(el('p', 'vide', 'Aucun appareil connu pour l\u2019instant.'));
    }
    async function fiche(mac) {
        $('liste').hidden = true; $('fiche').hidden = false;
        var d = await json(NAC + '/client/' + encodeURIComponent(mac)), g = $('detail'); g.textContent = '';
        $('titre').textContent = '📱 ' + nom(d);
        champ(g, 'Adresse MAC', d.mac); champ(g, 'Adresse IP', d.ip); champ(g, 'Zone', d.zone_name || d.zone);
        champ(g, 'Type', libelleType(d.device_type)); champ(g, 'Type détaillé', sousType(d)); champ(g, 'Adresse MAC aléatoire', d.mac_random ? 'oui — le fabricant n\u2019est pas significatif' : null); champ(g, 'Fabricant', materiel({ oui_vendor: d.oui_vendor, is_secubox: 0, is_openwrt: 0 }));
        champ(g, 'Modèle', d.model); champ(g, 'Rôle', d.is_secubox ? 'SecuBox' : (d.is_openwrt ? 'OpenWrt' : (d.is_router ? 'Routeur' : null)));
        var os = deduireOS(d, []); var cos = el('div', 'carte'); cos.id = 'os-carte'; cos.appendChild(el('small', null, 'Système d\u2019exploitation'));
        cos.appendChild(el('span', null, os ? os.nom : 'non déterminé')); cos.appendChild(el('small', null, os ? 'Déduit : ' + os.preuve : 'Aucun indice (nom ni requêtes DNS)')); g.appendChild(cos);
        champ(g, 'Risque', d.risk_level || d.risk);
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
