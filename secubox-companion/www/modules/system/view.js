// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: system — health, resources, services (read).
export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, clear } = ui;

  const host = clear(root);
  host.append(el('p.muted', { text: 'Loading system health…' }));
  try {
    const s = await api.get(`${base}/status`);
    clear(host);
    const g = el('div.grid');
    const gauge = (label, val, unit = '') => g.append(el('div.card', { style: 'text-align:center' }, [
      el('div.data', { style: 'font-size:1.5rem;font-weight:700', text: (val ?? '—') + unit }),
      el('div.kicker', { text: label }),
    ]));
    gauge('CPU', s.cpu ?? s.cpu_percent, '%');
    gauge('Memory', s.mem ?? s.memory_percent ?? s.mem_percent, '%');
    gauge('Disk', s.disk ?? s.disk_percent, '%');
    gauge('Uptime', s.uptime_days ?? s.uptime, s.uptime_days ? 'd' : '');
    host.append(g);

    const svcs = await api.get(`${base}/services`).catch(() => null); // TODO(api): confirm services route
    if (svcs) {
      const items = svcs.services || svcs.items || [];
      const card = el('div.card', {}, [el('h3', { text: `Services (${items.length})` })]);
      for (const sv of items.slice(0, 60)) card.append(el('div.item', {}, [
        el('div.meta', {}, [el('b', { text: esc(sv.name || sv.unit) })]),
        el('span.badge' + (sv.active || sv.status === 'active' || sv.running ? '.ok' : '.err'), { text: sv.status || (sv.active ? 'active' : 'down') }),
      ]));
      host.append(card);
    }
  } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) })); }
}
