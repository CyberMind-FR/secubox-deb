// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
//
// SecuBox-Deb :: Security Posture — dashboard
// CyberMind — https://cybermind.fr

(function () {
    'use strict';

    const API = '/api/v1/security-posture';
    const REFRESH_MS = 60000;
    const GAUGE_LEN = 251.3;            // arc length of the 80px-radius semicircle

    const $ = (id) => document.getElementById(id);
    const esc = (s) => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    async function fetchJSON(path) {
        const r = await fetch(API + path, { headers: { 'Accept': 'application/json' } });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
    }

    function statusClass(s) { return 'badge ' + (s || 'unknown'); }

    // ---- rendering ---------------------------------------------------------

    function renderGauge(overall) {
        const score = overall && typeof overall.score === 'number' ? overall.score : null;
        const fill = $('gaugeFill');
        if (score == null) {
            fill.style.strokeDashoffset = GAUGE_LEN;
            fill.style.stroke = 'var(--muted-dark)';
            $('score').textContent = '—';
        } else {
            fill.style.strokeDasharray = GAUGE_LEN;
            fill.style.strokeDashoffset = GAUGE_LEN * (1 - score / 100);
            fill.style.stroke = overall.color || 'var(--root-light)';
            $('score').textContent = Math.round(score);
        }
        $('defconEmoji').textContent = overall.emoji || '⚫';
        $('defconLevel').textContent = overall.level ? ('DEFCON ' + overall.level) : 'DEFCON —';
        $('defconName').textContent = overall.name || 'Unknown';
        const badge = $('defconBadge');
        badge.style.borderColor = overall.color || 'var(--border-dark)';
        badge.style.color = overall.color || 'var(--text-dark)';
        badge.classList.toggle('blink', !!overall.blink);
    }

    function ring(score, color) {
        // Inline conic-gradient ring for a domain score.
        const pct = score == null ? 0 : score;
        const c = color || 'var(--root-light)';
        const track = 'rgba(255,255,255,0.08)';
        const label = score == null ? '—' : Math.round(score);
        return `<div class="ring" style="background:conic-gradient(${c} ${pct * 3.6}deg, ${track} 0)">
                  <span>${label}</span></div>`;
    }

    function renderDomains(domains) {
        $('domains').innerHTML = (domains || []).map((d) => {
            const findings = (d.indicators || [])
                .filter((i) => i.status === 'warn' || i.status === 'crit')
                .slice(0, 2);
            const cov = Math.round((d.coverage || 0) * 100);
            const indCount = (d.indicators || []).length;
            const measured = (d.indicators || []).filter((i) => i.value != null).length;
            return `
            <article class="domain-card" style="--dc:${d.color}">
              <div class="dc-head">
                <span class="dc-icon">${d.icon || '📦'}</span>
                <div class="dc-title"><a href="${esc(d.link || '#')}">${esc(d.name)}</a>
                  <div class="dc-blurb">${esc(d.blurb || '')}</div></div>
                ${ring(d.score, d.color)}
              </div>
              <div class="dc-cov" title="${measured}/${indCount} indicators measured">
                coverage <b>${cov}%</b>
                <span class="cov-bar"><span style="width:${cov}%;background:${d.color}"></span></span>
              </div>
              ${findings.length ? '<ul class="dc-findings">' + findings.map((f) =>
                  `<li class="${f.status}"><span class="dot"></span>${esc(f.label)}
                     <em>${esc(f.detail)}</em></li>`).join('') + '</ul>'
                  : '<div class="dc-ok">no warnings</div>'}
            </article>`;
        }).join('');
    }

    function renderFindings(findings) {
        $('findingCount').textContent = findings && findings.length
            ? '(' + findings.length + ')' : '';
        if (!findings || !findings.length) {
            $('findings').innerHTML = '<div class="dc-ok big">✓ No active findings — every measured indicator is healthy.</div>';
            return;
        }
        $('findings').innerHTML = findings.map((f) => `
            <div class="finding ${f.severity}">
              <span class="sev">${f.severity === 'crit' ? '🔴' : '🟡'}</span>
              <div class="f-body">
                <div class="f-title">${esc(f.title)}
                  <a class="f-dom" href="${esc(f.link || '#')}">${esc(f.domain)}</a></div>
                ${f.detail ? `<div class="f-detail">${esc(f.detail)}</div>` : ''}
                ${f.remediation ? `<code class="f-fix" title="click to copy">${esc(f.remediation)}</code>` : ''}
              </div>
            </div>`).join('');
        document.querySelectorAll('.f-fix').forEach((el) => {
            el.addEventListener('click', () => navigator.clipboard &&
                navigator.clipboard.writeText(el.textContent).then(() => {
                    el.classList.add('copied'); setTimeout(() => el.classList.remove('copied'), 900);
                }));
        });
    }

    function renderAudit(tableId, pillId, report) {
        const pill = $(pillId);
        if (!report || report.score == null) {
            pill.textContent = report ? `${report.manual || 0} manual` : 'n/a';
            pill.className = 'pill unknown';
        } else {
            pill.textContent = `${report.score}% (${report.passed}/${report.scored})`;
            pill.className = 'pill ' + (report.score >= 80 ? 'ok' : report.score >= 50 ? 'warn' : 'crit');
        }
        const rows = (report && report.items ? report.items : []).map((i) => `
            <tr>
              <td class="mono">${esc(i.id)}</td>
              <td>${esc(i.title)}<div class="r-detail">${esc(i.detail || '')}</div></td>
              <td><span class="${statusClass(i.status)}">${esc(i.status)}</span></td>
            </tr>`).join('');
        $(tableId).innerHTML =
            '<thead><tr><th>ID</th><th>Requirement</th><th>Status</th></tr></thead><tbody>'
            + rows + '</tbody>';
    }

    function render(snap) {
        renderGauge(snap.overall || {});
        const cov = Math.round((snap.coverage || 0) * 100);
        $('coverageNote').innerHTML = `Real-signal coverage <b>${cov}%</b> across measured domains`;
        renderDomains(snap.domains);
        renderFindings(snap.findings);
        renderAudit('cspnTable', 'cspnPill', snap.cspn);
        renderAudit('tpnTable', 'tpnPill', snap.tpn);
        if (snap.timestamp) {
            const t = new Date(snap.timestamp);
            $('updated').textContent = 'updated ' + (isNaN(t) ? snap.timestamp : t.toLocaleTimeString());
        }
        $('loading').hidden = true;
        $('error').hidden = true;
        $('content').hidden = false;
    }

    async function load() {
        try {
            render(await fetchJSON('/overview'));
        } catch (e) {
            if (String(e).includes('503')) {            // still computing — retry shortly
                $('loading').hidden = false;
                setTimeout(load, 3000);
                return;
            }
            $('error').hidden = false;
            $('error').textContent = 'Could not load posture: ' + e.message;
            $('loading').hidden = true;
        }
    }

    async function refreshNow() {
        const btn = $('refresh');
        btn.disabled = true; btn.textContent = '↻ …';
        try { await fetch(API + '/refresh', { method: 'POST' }); await load(); }
        catch (_) { /* surfaced by load() */ }
        finally { btn.disabled = false; btn.textContent = '↻ Refresh'; }
    }

    document.addEventListener('DOMContentLoaded', () => {
        $('refresh').addEventListener('click', refreshNow);
        load();
        setInterval(load, REFRESH_MS);
    });
})();
