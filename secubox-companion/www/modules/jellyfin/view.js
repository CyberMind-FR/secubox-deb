// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: jellyfin — LXC-native media server (overview + open).
//
// Minimal module mirroring photoprism: reads the box's /api/v1/jellyfin/status
// (best-effort — the card degrades gracefully if the backend isn't present) and
// offers a deep link to the Jellyfin instance. Follows the drop-in module
// contract (module.json + default mount()); no core change needed.
export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el } = ui;
  ui.clear(root);

  const grid = el('div.grid');
  root.append(grid);

  let s = null;
  try { s = await api.get(`${base}/status`); } catch (e) { /* backend optional */ }

  const cards = [];
  if (s) {
    const state = String(s.status || s.lxc_state || '—');
    const ok = state === 'ok' || state === 'running';
    cards.push(el('div.card', {}, [
      el('div.kicker', { text: 'statut' }),
      el('h3', { text: ok ? 'en ligne' : state }),
    ]));
    cards.push(el('div.card', {}, [
      el('div.kicker', { text: 'bibliothèques' }),
      el('h3', { text: String(s.libraries != null ? s.libraries : '—') }),
    ]));
    cards.push(el('div.card', {}, [
      el('div.kicker', { text: 'flux actifs' }),
      el('h3', { text: String(s.sessions != null ? s.sessions : '—') }),
    ]));
    cards.push(el('div.card', {}, [
      el('div.kicker', { text: 'version' }),
      el('h3', { text: String(s.version || '—') }),
    ]));
    cards.push(el('div.card', {}, [
      el('div.kicker', { text: 'lxc' }),
      el('h3', { text: String(s.lxc_state || '—') }),
    ]));
  } else {
    cards.push(el('div.card', {}, [
      el('div.kicker', { text: 'statut' }),
      el('h3', { text: 'backend injoignable' }),
      el('div.muted', { style: 'font-size:.78rem', text: 'Le module ouvre l’instance ; l’API de statut n’est pas exposée sur cette box.' }),
    ]));
  }
  grid.append(...cards);

  root.append(el('div.row', { style: 'margin-top:14px' }, [
    el('a.btn', { href: 'https://jellyfin.gk2.secubox.in', target: '_blank', rel: 'noopener', text: '🍿 Ouvrir Jellyfin ↗' }),
  ]));
}
