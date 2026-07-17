// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: system — health, resources, services (read).
//
// Routes below are verified live against packages/secubox-system/api/main.py:
//   /status  (JWT)  → { model, board, hostname, uptime_sec, cpu_count,
//                        mem_total_mb, mem_free_mb, services_sample, health, cached_at }
//   /metrics         → { cpu_percent, mem_percent, disk_percent, load_avg_1,
//                        cpu_temp, uptime_seconds, hostname, memory_used, memory_total }
//   /resources       → { cpu_percent, memory_percent, memory_used, memory_total,
//                        disk_percent, disk_used, disk_total, load_avg:[1,5,15] }
//   /health_score (JWT) → { score, max, issues:[name…], services:[{name,active,status,enabled}] }
//   /network         → { interfaces:[{name,addresses,up,speed}] }
//   /security        → { firewall, ssh_status, apparmor, crowdsec }  (plain status words)
// Each section is fetched independently so one failing route degrades to a
// small inline notice instead of blanking the whole module.
import { gauge, fmtUptime, fmtBytes } from '../../core/metrics.js';

export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, clear } = ui;

  const host = clear(root);
  host.append(el('p.muted', { text: 'Loading system health…' }));

  // /metrics is the one call the whole panel leans on (cpu/mem/disk/temp/
  // uptime/hostname in a single response) — if it fails there is nothing
  // meaningful to render, so that failure alone blanks the module.
  let m;
  try {
    m = await api.get(`${base}/metrics`);
  } catch (e) {
    clear(host).append(el('div.empty', { text: 'System metrics unavailable: ' + esc(e.message) }));
    return;
  }
  clear(host);
  if (m.__cached) host.append(el('div.badge.warn', { text: 'cached (offline)' }));

  // ── header: who / how long up ──────────────────────────────────
  host.append(el('div.panel-head', {}, [
    el('div', { style: 'font-size:1.6rem', text: '🖥️' }),
    el('div', {}, [
      el('h3', { style: 'margin:0', text: esc(m.hostname || 'SecuBox') }),
      el('div.muted', { style: 'font-size:.78rem', text: `up ${fmtUptime(m.uptime_seconds)}` }),
    ]),
  ]));

  // ── gauges: cpu / memory / disk / temp / load ──────────────────
  const g = el('div.grid');
  host.append(g);

  // disk byte totals aren't in /metrics — fetch /resources for the "N GB of
  // N GB" sub-line; the disk % gauge itself still renders if this fails.
  let res = null;
  try { res = await api.get(`${base}/resources`); } catch { /* degrade: percent-only gauges */ }

  g.append(gauge({ kind: 'cpu', label: 'CPU', percent: m.cpu_percent }));
  g.append(gauge({
    kind: 'mem', label: 'Memory', percent: m.mem_percent,
    sub: (m.memory_used != null && m.memory_total != null) ? `${fmtBytes(m.memory_used)} of ${fmtBytes(m.memory_total)} used` : undefined,
  }));
  g.append(gauge({
    kind: 'disk', label: 'Disk', percent: m.disk_percent,
    sub: (res && res.disk_used != null && res.disk_total != null) ? `${fmtBytes(res.disk_used)} of ${fmtBytes(res.disk_total)} used` : undefined,
  }));
  g.append(gauge({ kind: 'temp', label: 'Temperature', percent: m.cpu_temp, value: m.cpu_temp?.toFixed?.(1) ?? m.cpu_temp, unit: '°C' }));

  // Load average isn't a percent on its own — normalise against core count
  // from /status (JWT) when reachable; otherwise show the raw figure without
  // a false severity read (an un-normalised "3.4" means nothing alone).
  try {
    const st = await api.get(`${base}/status`);
    const cores = st.cpu_count;
    const loadPct = cores ? Math.min(100, (m.load_avg_1 / cores) * 100) : null;
    g.append(gauge({
      kind: 'load', label: `Load (1m, ${cores || '?'} cores)`,
      percent: loadPct, value: m.load_avg_1?.toFixed?.(2) ?? m.load_avg_1, unit: '',
    }));
  } catch {
    g.append(gauge({ kind: 'load', label: 'Load (1m)', percent: null, value: m.load_avg_1?.toFixed?.(2) ?? m.load_avg_1, unit: '' }));
  }

  // ── health score + services ─────────────────────────────────────
  try {
    const hs = await api.get(`${base}/health_score`);
    const services = hs.services || [];
    const scoreEmoji = hs.score >= 90 ? '🟢' : hs.score >= 70 ? '🟡' : '🔴';
    const card = el('div.card', {}, [
      el('h3', {}, [`${scoreEmoji} Health `, el('span.data', { text: `${hs.score ?? '—'}/${hs.max ?? 100}` })]),
    ]);
    if ((hs.issues || []).length) {
      card.append(el('div.muted', { style: 'margin-bottom:8px', text: '⚠️ ' + hs.issues.join(', ') + ' down' }));
    }
    for (const sv of services) {
      card.append(el('div.item', {}, [
        el('div.meta', {}, [
          el('b', { text: esc(sv.name) }),
          el('span', { text: sv.enabled ? 'enabled at boot' : 'not enabled at boot' }),
        ]),
        el('span.badge' + (sv.active ? '.ok' : '.err'), { text: sv.active ? '🟢 ' + (sv.status || 'active') : '🔴 ' + (sv.status || 'down') }),
      ]));
    }
    host.append(card);
  } catch (e) {
    host.append(el('div.card', {}, [el('div.muted', { text: 'Services/health unavailable: ' + esc(e.message) })]));
  }

  // ── network ──────────────────────────────────────────────────────
  try {
    const net = await api.get(`${base}/network`);
    const ifaces = net.interfaces || [];
    const card = el('div.card', {}, [el('h3', { text: `📡 Network (${ifaces.length})` })]);
    if (!ifaces.length) card.append(el('div.empty', { text: 'No interfaces reported.' }));
    for (const i of ifaces) {
      const addr = (i.addresses || []).join(', ') || 'no address';
      const speed = i.up && i.speed ? ` · ${i.speed} Mbps` : '';
      card.append(el('div.item', {}, [
        el('div.meta', {}, [
          el('b', { text: esc(i.name) }),
          el('span', { text: addr + speed }),
        ]),
        el('span.badge' + (i.up ? '.ok' : ''), { text: i.up ? '🟢 up' : '⚪ down' }),
      ]));
    }
    host.append(card);
  } catch (e) {
    host.append(el('div.card', {}, [el('div.muted', { text: 'Network unavailable: ' + esc(e.message) })]));
  }

  // ── security ─────────────────────────────────────────────────────
  try {
    const sec = await api.get(`${base}/security`);
    const good = (v) => ['Active', 'Running', 'Enabled'].includes(v);
    const bad = (v) => ['Stopped', 'Disabled'].includes(v);
    const row = (label, val) => el('div.item', {}, [
      el('div.meta', {}, [el('b', { text: label })]),
      el(`span.badge${good(val) ? '.ok' : bad(val) ? '.err' : '.warn'}`, { text: `${good(val) ? '🟢' : bad(val) ? '🔴' : '🟡'} ${val ?? '—'}` }),
    ]);
    host.append(el('div.card', {}, [
      el('h3', { text: '🛡️ Security' }),
      row('Firewall', sec.firewall),
      row('SSH', sec.ssh_status),
      row('AppArmor', sec.apparmor),
      row('CrowdSec', sec.crowdsec),
    ]));
  } catch (e) {
    host.append(el('div.card', {}, [el('div.muted', { text: 'Security status unavailable: ' + esc(e.message) })]));
  }
}
