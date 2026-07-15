// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: auth — identities & sessions (read).
export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, ago, clear } = ui;

  const host = clear(root);
  host.append(el('p.muted', { text: 'Loading identities…' }));
  try {
    const users = await api.get(`${base}/users`).catch(() => ({ users: [] })); // TODO(api): confirm users route
    const list = users.users || users.items || [];
    clear(host);
    const card = el('div.card', {}, [el('h3', { text: `Users (${list.length})` })]);
    if (!list.length) card.append(el('div.empty', { text: 'No users listed (auth users route may be admin-gated — TODO(api)).' }));
    for (const u of list) card.append(el('div.item', {}, [
      el('div.meta', {}, [
        el('b', { text: esc(u.username || u.name || u.id) }),
        el('span', { text: [u.role, u.admin && 'admin', u.totp && '2FA'].filter(Boolean).join(' · ') }),
      ]),
      u.master ? el('span.badge.ok', { text: 'master' }) : null,
    ]));
    host.append(card);

    const sess = await api.get(`${base}/sessions`).catch(() => null); // TODO(api): confirm sessions route
    if (sess) {
      const items = sess.sessions || sess.items || [];
      const sc = el('div.card', {}, [el('h3', { text: `Active sessions (${items.length})` })]);
      for (const s of items.slice(0, 30)) sc.append(el('div.item', {}, [
        el('div.meta', {}, [el('b', { text: esc(s.user || s.username || '?') }), el('span', { text: `${esc(s.ip || '')} · ${ago(s.created_at || s.ts)}` })]),
      ]));
      host.append(sc);
    }
  } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) })); }
}
