// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: auth — identities & sessions (read).
//
// The stub this replaces called `${base}/users` against api_base
// `/api/v1/auth`, which 404s — auth identity data actually lives under
// `/api/v1/users` (see module.json, updated alongside this file). Routes
// below are verified live against packages/secubox-users/api/main.py:
//   /users  (JWT) → { users:[{username,email,role,enabled,totp}], total }
//   /sessions (JWT) → { sessions:[{id,username,email,ip,user_agent,type,
//                        created_at,expires_at,last_active,current}], total }
//   /roles          → { roles:[{id,name,description,permissions,builtin,color}], total }
//   /groups (JWT)   → { groups:[{name,description,permissions,members,created}] }
// Each section is fetched independently so one failing route degrades to a
// small inline notice instead of blanking the whole module.
import { gauge } from '../../core/metrics.js';

// The 'master' concept isn't a stored field — the source (api/main.py,
// engine.py) consistently treats the single literal username "admin" as
// the master account (e.g. the only one synced to YaCy). Mirror that here.
const isMaster = (u) => u.username === 'admin';

// `created_at`/`expires_at` come from a JWT session file: sometimes a raw
// epoch (seconds OR the rarer ms), sometimes an ISO string, sometimes ''.
// ui.ago() assumes a bare number is already milliseconds, so seconds must
// be upscaled first or old sessions render as "1970".
function toMs(ts) {
  if (ts === '' || ts == null) return null;
  if (typeof ts === 'number') return ts < 1e12 ? ts * 1000 : ts;
  const p = Date.parse(ts);
  return Number.isNaN(p) ? null : p;
}
function until(ts) {
  const ms = toMs(ts);
  if (ms == null) return '—';
  const s = Math.floor((ms - Date.now()) / 1000);
  if (s <= 0) return 'expired';
  if (s < 3600) return `in ${Math.floor(s / 60)}m`;
  if (s < 86400) return `in ${Math.floor(s / 3600)}h`;
  return `in ${Math.floor(s / 86400)}d`;
}

// IP may be '' (pre-fix rows) or the literal string "unknown" (the API's
// own fallback when the key is absent entirely) — both read as "no data",
// so both collapse to the same neutral placeholder rather than leaking
// either raw form to the UI.
const ipOr = (ip) => (ip && ip !== 'unknown') ? ip : '—';

export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, ago, clear } = ui;

  const host = clear(root);
  host.append(el('p.muted', { text: 'Loading identities…' }));
  clear(host);

  host.append(el('div.panel-head', {}, [
    el('div', { style: 'font-size:1.6rem', text: '🔑' }),
    el('h3', { style: 'margin:0', text: 'Auth' }),
  ]));

  // ── sessions (prominent — who / IP / device / age / current) ────
  try {
    const d = await api.get(`${base}/sessions`);
    const items = d.sessions || [];
    const card = el('div.card', {}, [el('h3', { text: `🟢 Active sessions (${d.total ?? items.length})` })]);
    if (!items.length) card.append(el('div.empty', { text: 'No active sessions.' }));
    for (const s of items) {
      const device = s.user_agent || '—';
      card.append(el('div.item', {}, [
        el('div.meta', {}, [
          el('b', {}, [esc(s.username || '?'), s.current ? el('span.badge.ok', { style: 'margin-left:6px', text: '📍 this device' }) : null]),
          el('span', { text: `${ipOr(s.ip)} · ${esc(device)} · signed in ${ago(toMs(s.created_at) ?? undefined) || '—'}` }),
        ]),
        el('span.badge' + (until(s.expires_at) === 'expired' ? '.err' : ''), { text: '⏳ ' + until(s.expires_at) }),
      ]));
    }
    host.append(card);
  } catch (e) {
    host.append(el('div.card', {}, [el('div.muted', { text: 'Sessions unavailable: ' + esc(e.message) })]));
  }

  // ── identities ────────────────────────────────────────────────
  try {
    const d = await api.get(`${base}/users`);
    const list = d.users || [];
    const enabled = list.filter(u => u.enabled !== false).length;
    const disabled = list.length - enabled;
    const card = el('div.card', {}, [el('h3', { text: `👤 Identities (${d.total ?? list.length})` })]);
    if (list.length) {
      // Gauge on the *disabled* share, not enabled — severity() reads "higher
      // = worse", and a pile of locked-out accounts is the anomaly worth
      // flagging, not the (normal) state of everyone being enabled.
      card.append(gauge({ kind: 'default', label: 'Accounts disabled', percent: (disabled / list.length) * 100, value: `${enabled}/${list.length} enabled`, unit: '' }));
    } else {
      card.append(el('div.empty', { text: 'No users listed.' }));
    }
    for (const u of list) {
      const twofa = u.totp && u.totp.enabled;
      card.append(el('div.item', {}, [
        el('div.meta', {}, [
          el('b', {}, [esc(u.username), isMaster(u) ? el('span.badge.ok', { style: 'margin-left:6px', text: '★ master' }) : null]),
          el('span', { text: [u.role || (u.roles || []).join(',') || 'viewer', esc(u.email || ''), twofa ? '🔐 2FA' : null].filter(Boolean).join(' · ') }),
        ]),
        el('span.badge' + (u.enabled === false ? '.err' : '.ok'), { text: u.enabled === false ? '🔴 disabled' : '🟢 enabled' }),
      ]));
    }
    host.append(card);
  } catch (e) {
    host.append(el('div.card', {}, [el('div.muted', { text: 'Identities unavailable: ' + esc(e.message) })]));
  }

  // ── roles ─────────────────────────────────────────────────────
  try {
    const d = await api.get(`${base}/roles`);
    const roles = d.roles || [];
    const card = el('div.card', {}, [el('h3', { text: `🎭 Roles (${d.total ?? roles.length})` })]);
    if (!roles.length) card.append(el('div.empty', { text: 'No roles defined.' }));
    for (const r of roles) card.append(el('div.item', {}, [
      el('div.meta', {}, [
        el('b', { text: esc(r.name || r.id) }),
        el('span', { text: `${esc(r.description || '')} · ${(r.permissions || []).length} permissions` }),
      ]),
      r.builtin ? el('span.badge', { text: 'builtin' }) : null,
    ]));
    host.append(card);
  } catch (e) {
    host.append(el('div.card', {}, [el('div.muted', { text: 'Roles unavailable: ' + esc(e.message) })]));
  }

  // ── groups ────────────────────────────────────────────────────
  try {
    const d = await api.get(`${base}/groups`);
    const groups = d.groups || [];
    const card = el('div.card', {}, [el('h3', { text: `👥 Groups (${groups.length})` })]);
    if (!groups.length) card.append(el('div.empty', { text: 'No groups defined.' }));
    for (const g of groups) card.append(el('div.item', {}, [
      el('div.meta', {}, [
        el('b', { text: esc(g.name) }),
        el('span', { text: `${esc(g.description || '')} · ${(g.members || []).length} members` }),
      ]),
    ]));
    host.append(card);
  } catch (e) {
    host.append(el('div.card', {}, [el('div.muted', { text: 'Groups unavailable: ' + esc(e.message) })]));
  }
}
