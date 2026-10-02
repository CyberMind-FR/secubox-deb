// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: Hub Health Monitor — CyberMind https://cybermind.fr

(function () {
    'use strict';

    const BATCH = '/api/v1/hub/public/health-batch';
    const INFO = '/api/v1/hub/public/info';
    const REFRESH_MS = 15000;

    // Vital services — the security/serving spine; everything else is "common".
    const VITAL = ['waf', 'mitmproxy', 'haproxy', 'aggregator', 'hub',
        'system', 'vortex-dns', 'dns-guard', 'certs', 'wireguard', 'soc',
        'metrics', 'core'];
    const VITAL_SET = new Set(VITAL);

    const $ = (id) => document.getElementById(id);
    const esc = (s) => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    async function getJSON(u) {
        const r = await fetch(u, { headers: { 'Accept': 'application/json' }, cache: 'no-store' });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
    }

    // Status → emoji indicator (replaces the CSS LED dot).
    const EMOJI = { ok: '🟢', warn: '🟡', error: '🔴', unknown: '⚪' };
    const emo = (status) => EMOJI[status] || EMOJI.unknown;

    function chip(id, st) {
        const status = (st && st.status) || 'unknown';
        const msg = (st && st.msg) || '';
        return `<div class="svc ${status}" title="${esc(id)}: ${esc(msg)}">
            <span class="led">${emo(status)}</span>
            <span class="svc-name">${esc(id)}</span>
            <span class="svc-msg">${esc(msg)}</span>
        </div>`;
    }

    function render(modules) {
        const ids = Object.keys(modules).sort();
        let ok = 0, warn = 0, err = 0;
        ids.forEach((id) => {
            const s = (modules[id] || {}).status;
            if (s === 'ok') ok++; else if (s === 'error') err++; else warn++;
        });

        $('summary').innerHTML =
            `<div class="sum ok"><b>${ok}</b><span>🟢 healthy</span></div>` +
            `<div class="sum warn"><b>${warn}</b><span>🟡 degraded</span></div>` +
            `<div class="sum err"><b>${err}</b><span>🔴 down</span></div>` +
            `<div class="sum total"><b>${ids.length}</b><span>📊 services</span></div>`;

        const vital = ids.filter((id) => VITAL_SET.has(id));
        const common = ids.filter((id) => !VITAL_SET.has(id));
        // Sort each: errors first, then warn, then ok, so problems surface.
        const rank = (id) => ({ error: 0, warn: 1, unknown: 1, ok: 2 }[(modules[id] || {}).status] ?? 1);
        const bySeverity = (a, b) => rank(a) - rank(b) || a.localeCompare(b);

        $('vital').innerHTML = vital.sort(bySeverity).map((id) => chip(id, modules[id])).join('')
            || '<div class="empty">no vital services reported</div>';
        $('common').innerHTML = common.sort(bySeverity).map((id) => chip(id, modules[id])).join('')
            || '<div class="empty">none</div>';
        $('vitalCount').textContent = '(' + vital.length + ')';
        $('commonCount').textContent = '(' + common.length + ')';
    }

    // Test dynamique du WAF (health-doctor, #1883) : charges canari attendues en
    // 403 + témoin non bloqué. Section masquée si l'API n'est pas lisible.
    const DOCTOR = '/api/v1/health-doctor';

    function renderWaf(entry) {
        const d = (entry && entry.details) || {};
        const tests = d.tests || [];
        const tout = entry && entry.ok;
        const lignes = tests.map((t) => {
            const msg = (t.attendu || '') + ' · ' + (t.code == null ? (t.erreur || 'pas de réponse') : 'HTTP ' + t.code);
            return chip(t.libelle || t.id, { status: t.ok ? 'ok' : 'error', msg });
        });
        if (!tests.length) {
            lignes.push(chip('sbxwaf', { status: 'error', msg: d.erreur || 'test non exécuté' }));
        }
        const bilan = chip('WAF', { status: tout ? 'ok' : 'error',
            msg: tout ? 'bloque les attaques, laisse passer le trafic sain' : 'défaillant — voir le détail' });
        $('waf').innerHTML = bilan + lignes.join('');
        $('wafAge').textContent = d.age_s != null ? '(il y a ' + d.age_s + ' s)' : '';
        $('wafSection').hidden = false;
    }

    async function loadWaf() {
        try {
            const state = await getJSON(DOCTOR + '/checks');
            const e = state && state.checks && state.checks['waf-selftest'];
            if (e) renderWaf(e);
        } catch (e) { /* API non lisible : la section reste masquée */ }
    }

    async function rejouerWaf() {
        const b = $('wafRun');
        b.disabled = true;
        try {
            const token = localStorage.getItem('sbx_token');
            const r = await fetch(DOCTOR + '/waf-selftest/run', {
                method: 'POST',
                headers: token ? { 'Authorization': 'Bearer ' + token } : {},
            });
            if (!r.ok) throw new Error('HTTP ' + r.status);
            renderWaf(await r.json());
        } catch (e) {
            $('wafAge').textContent = '(échec : ' + e.message + ')';
        } finally {
            b.disabled = false;
        }
    }

    async function load() {
        try {
            const batch = await getJSON(BATCH);
            // health-batch returns {modules: {id: {status,msg}}, count: N}
            const modules = (batch && batch.modules) || batch || {};
            render(modules);
            loadWaf();
            $('updated').textContent = 'updated ' + new Date().toLocaleTimeString();
            $('loading').hidden = true; $('error').hidden = true; $('content').hidden = false;
            getJSON(INFO).then((i) => {
                if (i && i.hostname) $('ver').textContent = esc(i.hostname);
            }).catch(() => {});
        } catch (e) {
            $('error').hidden = false;
            $('error').textContent = 'Could not load health: ' + e.message;
            $('loading').hidden = true;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        $('refresh').addEventListener('click', load);
        $('wafRun').addEventListener('click', rejouerWaf);
        load();
        setInterval(load, REFRESH_MS);
    });
})();
