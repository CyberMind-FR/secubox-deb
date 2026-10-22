// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: sbxos-audio-mood — panneau d'administration au profil Aurora (#3026, après #1371). Fichier à part :
// la CSP de la route (script-src 'self') refuse tout script en ligne. Mêmes appels que l'ancienne page :
// GET /api/mood/admin/etat, POST /api/mood/admin/reglages, POST /api/mood/admin/purge. Aucune bibliothèque.
(function () {
    'use strict';
    const q = new URLSearchParams(location.search);
    const EMBED = !!q.get('embed'), DEMO = !!q.get('demo');
    if (EMBED) document.body.classList.add('emb');
    if (!EMBED && !DEMO) { const s = document.createElement('script'); s.src = '/shared/sidebar.js'; document.body.appendChild(s); }
    const API = '/api/mood/admin';
    const $ = id => document.getElementById(id);
    const el = (tag, cls, texte) => { const e = document.createElement(tag); if (cls) e.className = cls; if (texte != null) e.textContent = texte; return e; };
    const svgEl = (n, attrs) => { const e = document.createElementNS('http://www.w3.org/2000/svg', n); Object.entries(attrs || {}).forEach(([k, v]) => e.setAttribute(k, v)); return e; };
    let SESSION = true, ETAT = null, saisie = false;

    // Le cockpit public : même box, hôte « mood. » à la place de « admin. ».
    $('cockpit').href = location.protocol + '//' + location.hostname.replace(/^admin\./, 'mood.') + '/';

    async function api(chemin, options) {
        const h = { 'Content-Type': 'application/json', Accept: 'application/json' };
        try { const t = localStorage.getItem('sbx_token'); if (t) h.Authorization = 'Bearer ' + t; } catch (e) { /* stockage bloqué */ }
        const r = await fetch(API + chemin, Object.assign({ credentials: 'same-origin', cache: 'no-store', headers: h }, options));
        const j = await r.json().catch(() => ({}));
        if (r.status === 401) { SESSION = false; throw new Error('Connexion requise'); }
        if (r.status === 403) { SESSION = false; throw new Error('Réservé aux administrateurs'); }
        if (!r.ok) throw new Error(j.erreur || ('HTTP ' + r.status));
        SESSION = true;
        return j;
    }
    function msg(id, texte, ok) { const m = $(id); m.textContent = texte || ''; m.className = 'msg ' + (texte ? (ok ? 'ok' : 'err') : ''); }

    const nombre = n => (n == null ? '—' : Number(n).toLocaleString('fr-FR'));
    function octets(n) {
        if (n == null) return '—';
        if (!n) return '0 o';
        const u = ['o', 'Ko', 'Mo', 'Go']; let i = 0;
        while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
        return n.toFixed(i ? 1 : 0).replace('.', ',') + ' ' + u[i];
    }
    function duree(s) {
        if (s < 3600) return Math.max(1, Math.round(s / 60)) + ' min';
        if (s < 86400) return Math.round(s / 3600) + ' h';
        return Math.round(s / 86400) + ' j';
    }
    const depuis = ts => ts ? 'il y a ' + duree(Date.now() / 1000 - ts) : '—';

    function kv(cible, lignes) {
        const c = $(cible); c.replaceChildren();
        lignes.forEach(([k, v, cls]) => { c.appendChild(el('span', 'k', k)); c.appendChild(el('span', 'v' + (cls ? ' ' + cls : ''), v)); });
    }

    // Barres 24 h en SVG : une seule échelle, graduations réelles, jamais de série inventée.
    function barres(h) {
        const svg = $('barres'); svg.replaceChildren();
        const W = 640, H = 140, g = { l: 30, r: 6, t: 8, b: 22 };
        const max = Math.max(1, ...h);
        [0, 0.5, 1].forEach(f => { const y = g.t + (1 - f) * (H - g.t - g.b);
            svg.appendChild(svgEl('line', { x1: g.l, x2: W - g.r, y1: y, y2: y, class: 'gr' }));
            const t = svgEl('text', { x: g.l - 4, y: y + 3, 'text-anchor': 'end' }); t.textContent = Math.round(max * f); svg.appendChild(t); });
        const n = h.length, pas = (W - g.l - g.r) / n;
        h.forEach((v, i) => { const hb = v ? Math.max(2, v / max * (H - g.t - g.b)) : 0;
            const r = svgEl('rect', { x: g.l + i * pas + 1, y: H - g.b - hb, width: Math.max(1, pas - 2), height: hb, rx: 2, fill: v ? '#29b6f6' : 'rgba(159,179,214,.16)', 'fill-opacity': v ? '.85' : '1' });
            if (!v) r.setAttribute('height', '1'), r.setAttribute('y', H - g.b - 1);
            const ti = svgEl('title'); ti.textContent = ((n - 1 - i) ? '−' + (n - 1 - i) + ' h' : 'heure en cours') + ' : ' + v + ' min'; r.appendChild(ti); svg.appendChild(r); });
        [['−24 h', g.l, 'start'], ['−12 h', g.l + (W - g.l - g.r) / 2, 'middle'], ['maintenant', W - g.r, 'end']].forEach(([txt, x, a]) => {
            const t = svgEl('text', { x, y: H - 6, 'text-anchor': a }); t.textContent = txt; svg.appendChild(t); });
    }

    function rendre() {
        $('demo').hidden = !DEMO;
        $('session').hidden = DEMO || SESSION;
        const e = ETAT, st = (e && e.stockage) || null, rg = (e && e.reglages) || null, g = (e && e.garanties) || null;
        const p = $('pastille');
        if (!e) { p.textContent = SESSION ? 'HORS LIGNE' : 'SESSION REQUISE'; p.className = 'etatp hors'; }
        else if (rg && rg.historique) { p.textContent = 'HISTORIQUE ' + rg.retention_jours + ' J'; p.className = 'etatp'; }
        else { p.textContent = 'SANS HISTORIQUE'; p.className = 'etatp warn'; }
        $('sousligne').textContent = e ? 'v' + e.version + ' · démarré ' + depuis(e.demarre) + ' · ' + (rg && rg.historique ? 'historique conservé ' + rg.retention_jours + ' j' : 'aucun historique conservé')
            : 'indices prosodiques, analysés localement · aucune émotion affirmée';
        $('tSessions').textContent = e ? nombre(e.sessions) : '—';
        $('tMinutes').textContent = st ? nombre(st.resumes) : '—';
        $('tArchivees').textContent = st ? nombre(st.sessions) : '—';
        $('tVoix').textContent = st ? nombre(st.references) : '—';
        $('tTaille').textContent = st ? octets(st.taille_octets) : '—';
        $('tAncien').textContent = st && st.plus_ancien ? duree(Date.now() / 1000 - st.plus_ancien) : '—';
        $('tAncienS').textContent = st && st.plus_ancien ? new Date(st.plus_ancien * 1000).toLocaleDateString('fr-FR') : (st ? 'aucun résumé' : '—');
        barres(st && Array.isArray(st.par_heure) && st.par_heure.length ? st.par_heure : new Array(24).fill(0));
        const lect = $('lectures'); lect.replaceChildren();
        const etats = st ? Object.entries(st.etats || {}).sort((a, b) => b[1] - a[1]) : [];
        const tot = etats.reduce((s, [, n]) => s + n, 0);
        if (!etats.length) lect.appendChild(el('div', 'vide', st ? 'Aucune lecture conservée sur 7 jours.' : '—'));
        etats.forEach(([k, n]) => { const l = el('div', 'ligne'); l.appendChild(el('span', 'n', k)); l.appendChild(el('span', null, Math.round(n / tot * 100) + ' %'));
            const b = el('span', 'barre'); const i = el('i'); i.style.width = (n / tot * 100).toFixed(1) + '%'; b.appendChild(i); l.appendChild(b); lect.appendChild(l); });
        $('iLectures').textContent = etats.length ? tot.toLocaleString('fr-FR') + ' lectures' : '';
        kv('garanties', g ? [
            ['Plafond de confiance', (g.plafond_confiance != null ? Number(g.plafond_confiance).toFixed(2) : '—'), 'ok'],
            ['Anonymat de la lecture commune', g.seuil_anonymat != null ? 'au moins ' + g.seuil_anonymat + ' voix' : '—', 'ok'],
            ['Audio écrit sur le disque', g.audio_sur_disque ? 'OUI' : 'jamais', g.audio_sur_disque ? 'warn' : 'ok'],
            ['Classifieur', g.classifieur || '—', 'mono'],
            ['Échantillonnage', g.echantillonnage ? nombre(g.echantillonnage) + ' Hz' : '—'],
            ['Réserve affichée', g.reserve || '—']] : [['—', '—']]);
        kv('purge', e ? [['Dernière purge', depuis(e.derniere_purge)], ['Rétention', rg ? rg.retention_jours + ' jours' : '—']] : [['—', '—']]);
        $('iPurge').textContent = e && e.derniere_purge ? '' : (e ? 'aucune purge depuis le démarrage' : '');
        kv('moteur', e ? [
            ["Base d'historique", e.historique_base ? 'ouverte' : 'aucune', e.historique_base ? 'ok' : 'warn'],
            ['Entrées son locales', (e.entrees_locales && e.entrees_locales.length) ? e.entrees_locales.join(', ') : 'aucune'],
            ['Pourquoi', e.entrees_motif || 'le micro vient du navigateur'],
            ['Inférence externe', e.inference || 'non (heuristique locale)']] : [['—', '—']]);
        $('iMoteur').textContent = e && !(e.entrees_locales && e.entrees_locales.length) ? 'micro du navigateur' : '';
        if (!saisie && rg) { $('r-historique').checked = !!rg.historique; $('r-memoire').checked = !!rg.memoire_voix; $('r-retention').value = rg.retention_jours; }
        $('heure').textContent = new Date().toLocaleString('fr-FR', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
        hauteur();
    }

    // ── démonstration : données réalistes annoncées par le bandeau, aucune écriture ──
    function DEMO_ETAT() {
        const now = Date.now() / 1000, ph = [];
        for (let i = 0; i < 24; i++) ph.push(i < 7 ? 0 : Math.round(6 + 18 * Math.abs(Math.sin(i / 3))));
        return { version: '0.10.7', demarre: now - 5 * 86400, sessions: 2,
            stockage: { resumes: 3184, sessions: 97, references: 11, taille_octets: 2.4 * 1024 * 1024, plus_ancien: now - 29 * 86400, par_heure: ph,
                etats: { 'posée': 412, 'animée': 266, 'tendue': 118, 'hésitante': 64, 'fatiguée': 40 } },
            reglages: { historique: true, memoire_voix: true, retention_jours: 30 },
            garanties: { plafond_confiance: 0.72, seuil_anonymat: 5, audio_sur_disque: false, classifieur: 'heuristique-prosodique-v1', echantillonnage: 48000, reserve: 'Indices acoustiques, pas un état intérieur constaté.' },
            derniere_purge: now - 3600 * 5, historique_base: true, entrees_locales: [], entrees_motif: '/dev/snd absent : le micro vient du navigateur', inference: 'non (heuristique locale)' };
    }

    async function charge() {
        const b = $('rafraichir'); b.disabled = true; $('erreur').hidden = true;
        try {
            if (DEMO) { ETAT = DEMO_ETAT(); rendre(); return; }
            try { ETAT = await api('/etat'); }
            catch (err) { if (SESSION) { $('erreur').textContent = 'Impossible de lire Audio Mood : ' + err.message; $('erreur').hidden = false; } else ETAT = null; rendre(); return; }
            rendre();
        } finally { b.disabled = false; }
    }

    $('rafraichir').addEventListener('click', charge);
    $('reglages').addEventListener('input', () => { saisie = true; });
    $('reglages').addEventListener('submit', async ev => {
        ev.preventDefault();
        const corps = { historique: $('r-historique').checked, memoire_voix: $('r-memoire').checked, retention_jours: parseInt($('r-retention').value, 10) };
        if (!(corps.retention_jours >= 1 && corps.retention_jours <= 90)) { msg('m-reglages', 'La rétention va de 1 à 90 jours.'); return; }
        if (DEMO) { msg('m-reglages', 'Démonstration : aucune écriture.'); return; }
        try {
            const r = await api('/reglages', { method: 'POST', body: JSON.stringify(corps) });
            saisie = false;
            msg('m-reglages', r.purges ? 'Enregistré — ' + r.purges + ' minute(s) au-delà de la rétention effacée(s)' : 'Enregistré', true);
            charge();
        } catch (e) { msg('m-reglages', e.message); }
    });
    async function purge(quoi, bouton) {
        if (DEMO) { msg('m-purge', 'Démonstration : aucune écriture.'); return; }
        bouton.disabled = true;
        try { const r = await api('/purge', { method: 'POST', body: JSON.stringify({ quoi }) }); msg('m-purge', r.efface + ' élément(s) effacé(s)', true); charge(); }
        catch (e) { msg('m-purge', e.message); }
        bouton.disabled = false;
    }
    document.querySelector('[data-purge="retention"]').addEventListener('click', ev => purge('retention', ev.currentTarget));
    $('b-tout').addEventListener('click', () => { $('c-tout').hidden = false; });
    $('c-tout-non').addEventListener('click', () => { $('c-tout').hidden = true; });
    $('c-tout-oui').addEventListener('click', ev => { $('c-tout').hidden = true; purge('tout', ev.currentTarget); });

    // ── hauteur annoncée à l'hôte (cadre, jamais le document) ──
    function hauteur() { if (window.parent !== window) { try { window.parent.postMessage({ sbxVue: Math.ceil($('cadre').getBoundingClientRect().bottom + scrollY), onglet: 'audio-mood' }, location.origin); } catch (e) {} } }
    window.addEventListener('load', hauteur); window.addEventListener('resize', hauteur);
    if (window.ResizeObserver) new ResizeObserver(hauteur).observe(document.body);

    charge();
    setInterval(() => { if (document.hidden || saisie || !$('c-tout').hidden) return; charge(); }, 30000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden && !saisie) charge(); });
})();
