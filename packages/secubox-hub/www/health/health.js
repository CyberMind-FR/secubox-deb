// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: Hub Health Monitor — CyberMind https://cybermind.fr

(function () {
    'use strict';

    const BATCH = '/api/v1/hub/public/health-batch';
    const INFO = '/api/v1/hub/public/info';
    const REFRESH_MS = 15000;

    // Vital services — the security/serving spine; everything else is "common".
    const VITAL = ['waf', 'crowdsec', 'mitmproxy', 'haproxy', 'aggregator', 'hub',
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

    async function load() {
        try {
            const batch = await getJSON(BATCH);
            // health-batch returns {modules: {id: {status,msg}}, count: N}
            const modules = (batch && batch.modules) || batch || {};
            render(modules);
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
        load();
        setInterval(load, REFRESH_MS);
    });
})();
