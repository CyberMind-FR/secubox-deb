// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: photoprism — AI photo library (overview + open).
//
// Minimal module: reads the box's /api/v1/photoprism/status (best-effort — the
// card degrades gracefully if the backend isn't present) and offers a deep link
// to the PhotoPrism instance. Follows the drop-in module contract (module.json
// + default mount()); no core change needed.
export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, clear } = ui;
  clear(root);

  const grid = el('div.grid');
  root.append(grid);

  let s = null;
  try { s = await api.get(`${base}/status`); } catch (e) { /* backend optional */ }

  const rows = s
    ? Object.entries(s).slice(0, 6).map(([k, v]) =>
        el('div.card', {}, [el('div.kicker', { text: k }),
          el('h3', { text: String(typeof v === 'object' ? JSON.stringify(v) : v) })]))
    : [el('div.card', {}, [el('div.kicker', { text: 'statut' }),
        el('h3', { text: 'backend injoignable' }),
        el('div.muted', { style: 'font-size:.78rem', text: 'Le module ouvre l’instance ; l’API de statut n’est pas exposée sur cette box.' })])];
  grid.append(...rows);

  root.append(el('div.row', { style: 'margin-top:14px' }, [
    el('a.btn', { href: 'https://photoprism.gk2.secubox.in', target: '_blank', rel: 'noopener', text: '📷 Ouvrir PhotoPrism ↗' }),
  ]));
}
