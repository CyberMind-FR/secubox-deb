// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: waf — sbxwaf traffic/threats + MITM filter list (read).
export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, clear } = ui;

  const host = clear(root);
  host.append(el('p.muted', { text: 'Loading WAF stats…' }));
  try {
    const s = await api.get(`${base}/stats`).catch(() => api.get(`${base}/status`)); // TODO(api): confirm stats route
    clear(host);
    const stat = (label, val) => el('div.card', { style: 'text-align:center' }, [
      el('div.data', { style: 'font-size:1.6rem;font-weight:700', text: String(val ?? '—') }),
      el('div.kicker', { text: label }),
    ]);
    host.append(el('div.grid', {}, [
      stat('Requests', s.requests ?? s.total ?? '—'),
      stat('Blocked', s.blocked ?? s.total_blocked ?? '—'),
      stat('Threats', s.threats ?? s.threats_count ?? '—'),
      stat('Backends', (s.backends || s.routes || []).length || s.backends_count || '—'),
    ]));
    // MITM filters (bypass/splice exclusion set)
    const filt = await api.get(`${base}/filters`).catch(() => null); // TODO(api): confirm Filtres MITM route
    if (filt) {
      const items = filt.filters || filt.items || filt.exclusions || [];
      const card = el('div.card', {}, [el('h3', { text: `MITM filters (${items.length})` })]);
      for (const f of items.slice(0, 40)) card.append(el('div.item', {}, [
        el('div.meta', {}, [el('b', { text: f.host || f.domain || f }), el('span', { text: f.mode || f.kind || '' })]),
        el('span.badge', { text: f.enabled === false ? 'off' : 'on' }),
      ]));
      host.append(card);
    }
  } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) })); }
}
