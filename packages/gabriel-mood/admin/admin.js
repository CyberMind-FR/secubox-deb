// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: gabriel-mood — panneau d'administration (#1371). Fichier à
// part : la CSP de la route (script-src 'self') refuse tout script en ligne.
(function () {
    'use strict';
    const API = '/api/mood/admin';
    const $ = id => document.getElementById(id);
    const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
        c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    let dernier = null;          // cache client : la dernière réponse
    let saisie = false;          // ne pas écraser un formulaire en cours d'édition

    // Le cockpit public : même box, hôte « mood. » à la place de « admin. ».
    $('cockpit').href = location.protocol + '//' + location.hostname.replace(/^admin\./, 'mood.') + '/';

    function toast(msg) {
        const t = $('toast');
        t.className = 'toast show';
        t.textContent = msg;
        clearTimeout(toast.h);
        toast.h = setTimeout(() => { t.className = 'toast'; }, 3000);
    }
    function errorToast(msg) {
        const t = $('toast');
        clearTimeout(toast.h);
        t.className = 'toast show error';
        t.textContent = '';
        const s = document.createElement('span'); s.textContent = msg;
        const x = document.createElement('button'); x.type = 'button'; x.textContent = '✕';
        x.setAttribute('aria-label', 'Fermer');
        x.onclick = () => { t.className = 'toast'; };
        t.append(s, x);
    }

    async function api(chemin, options) {
        const h = { 'Content-Type': 'application/json' };
        let jeton = null;
        try { jeton = localStorage.getItem('sbx_token'); } catch (e) { /* stockage bloqué */ }
        if (jeton) h.Authorization = 'Bearer ' + jeton;
        const r = await fetch(API + chemin, Object.assign({ credentials: 'same-origin', headers: h }, options));
        const j = await r.json().catch(() => ({}));
        if (r.status === 401) throw new Error('🔒 Connexion requise');
        if (r.status === 403) throw new Error('🔒 Réservé aux administrateurs');
        if (!r.ok) throw new Error(j.erreur || ('HTTP ' + r.status));
        return j;
    }

    const nombre = n => (n || 0).toLocaleString('fr-FR');
    function octets(n) {
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

    function rend(e) {
        const st = e.stockage || {};
        const rg = e.reglages || {};
        $('subline').textContent = 'v' + e.version + ' · démarré ' + depuis(e.demarre)
            + ' · ' + (rg.historique ? 'historique conservé ' + rg.retention_jours + ' j' : 'aucun historique conservé');

        const cartes = [
            ['cyan', e.sessions, 'Sessions en cours'],
            ['green', nombre(st.resumes), 'Minutes conservées'],
            ['blue', nombre(st.sessions), 'Sessions archivées'],
            ['purple', nombre(st.references), 'Voix mémorisées'],
            ['orange', octets(st.taille_octets), 'Taille de la base'],
            ['cyan', st.plus_ancien ? duree(Date.now() / 1000 - st.plus_ancien) : '—', 'Plus ancien résumé'],
        ];
        $('stats').innerHTML = cartes.map(([c, v, l]) =>
            '<div class="stat-card ' + c + '"><div class="value">' + esc(v) + '</div><div class="label">' + esc(l) + '</div></div>').join('');

        const h = st.par_heure || new Array(24).fill(0);
        const max = Math.max(1, ...h);
        $('barres').innerHTML = h.map((n, i) =>
            '<i class="' + (n ? '' : 'vide') + '" style="height:' + (n ? Math.max(3, n / max * 100) : 1) + '%" title="'
            + esc((23 - i) ? '−' + (23 - i) + ' h' : 'heure en cours') + ' : ' + n + ' min"></i>').join('');

        const etats = Object.entries(st.etats || {}).sort((a, b) => b[1] - a[1]);
        const tot = etats.reduce((s, [, n]) => s + n, 0);
        $('etats').innerHTML = etats.length ? etats.map(([k, n]) =>
            '<div class="etat"><span>' + esc(k) + '</span><span class="jauge"><i style="width:' + (n / tot * 100).toFixed(1)
            + '%"></i></span><span class="n">' + Math.round(n / tot * 100) + ' %</span></div>').join('')
            : '<div class="note">Aucune lecture conservée sur 7 jours.</div>';

        const g = e.garanties || {};
        const ligne = (k, v, cls) => '<div class="row ' + (cls || '') + '"><span class="k">' + esc(k) + '</span><span class="v">' + esc(v) + '</span></div>';
        $('garanties').innerHTML =
            ligne('Plafond de confiance', (g.plafond_confiance || 0).toFixed(2), 'ok') +
            ligne('Anonymat de la lecture commune', 'au moins ' + g.seuil_anonymat + ' voix', 'ok') +
            ligne('Audio écrit sur le disque', g.audio_sur_disque ? 'OUI' : 'jamais', g.audio_sur_disque ? 'warn' : 'ok') +
            ligne('Classifieur', g.classifieur) +
            ligne('Échantillonnage', nombre(g.echantillonnage) + ' Hz') +
            ligne('Réserve affichée', g.reserve);

        $('purge-etat').innerHTML =
            ligne('Dernière purge', depuis(e.derniere_purge)) +
            ligne('Rétention', rg.retention_jours + ' jours');

        $('moteur').innerHTML =
            ligne('Base d\'historique', e.historique_base ? 'ouverte' : 'aucune', e.historique_base ? 'ok' : 'warn') +
            ligne('Entrées son locales', (e.entrees_locales && e.entrees_locales.length) ? e.entrees_locales.join(', ') : 'aucune') +
            ligne('Pourquoi', e.entrees_motif || 'le micro vient du navigateur') +
            ligne('Inférence externe', e.inference || 'non (heuristique locale)');

        if (!saisie) {
            $('r-historique').checked = !!rg.historique;
            $('r-memoire').checked = !!rg.memoire_voix;
            $('r-retention').value = rg.retention_jours;
        }
    }

    async function refresh() {
        try {
            dernier = await api('/etat');
            rend(dernier);
        } catch (e) {
            if (dernier) rend(dernier);
            errorToast(e.message);
            $('subline').textContent = e.message;
        }
    }

    $('reglages').addEventListener('input', () => { saisie = true; });
    $('reglages').addEventListener('submit', async ev => {
        ev.preventDefault();
        const corps = {
            historique: $('r-historique').checked,
            memoire_voix: $('r-memoire').checked,
            retention_jours: parseInt($('r-retention').value, 10),
        };
        if (!(corps.retention_jours >= 1 && corps.retention_jours <= 90)) {
            errorToast('La rétention va de 1 à 90 jours.');
            return;
        }
        try {
            const r = await api('/reglages', { method: 'POST', body: JSON.stringify(corps) });
            saisie = false;
            toast(r.purges ? 'Enregistré — ' + r.purges + ' minute(s) au-delà de la rétention effacée(s)' : 'Enregistré');
            refresh();
        } catch (e) { errorToast(e.message); }
    });

    document.addEventListener('click', async ev => {
        const b = ev.target.closest('[data-purge]');
        if (!b) return;
        const quoi = b.dataset.purge;
        if (quoi === 'tout' && !confirm('Effacer TOUT l\'historique de toutes les sessions et toutes les voix mémorisées ? Irréversible.')) return;
        b.disabled = true;
        try {
            const r = await api('/purge', { method: 'POST', body: JSON.stringify({ quoi }) });
            toast(r.efface + ' élément(s) effacé(s)');
            refresh();
        } catch (e) { errorToast(e.message); }
        b.disabled = false;
    });

    $('refresh').addEventListener('click', refresh);
    refresh();
    setInterval(() => { if (!document.hidden) refresh(); }, 30000);
})();
