// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: torrent — WebTorrent SAS (status + library overview + open).
//
// Read-only companion facet of the torrent SAS: shows engine status and the
// current library (kept vs ephemeral, download progress), and deep-links to the
// full player webui for streaming / keep / purge. Drop-in module contract
// (module.json + default mount()); the box proxies /api/v1/torrent/* to the LXC.
function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ['o', 'Ko', 'Mo', 'Go', 'To'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, clear } = ui;
  clear(root);

  const grid = el('div.grid');
  root.append(grid);

  // Engine status (best-effort — the card degrades if the LXC is unreachable).
  let s = null;
  try { s = await api.get(`${base}/status`); } catch (e) { /* optional */ }
  if (s) {
    grid.append(
      el('div.card', {}, [el('div.kicker', { text: 'actifs' }), el('h3', { text: String(s.active ?? '—') })]),
      el('div.card', {}, [el('div.kicker', { text: 'disque libre' }), el('h3', { text: fmtBytes(s.disk_free) })]),
      el('div.card', {}, [el('div.kicker', { text: 'WebRTC' }), el('h3', { text: s.webrtc ? '✓ activé' : '✕ BitTorrent seul' })]),
    );
  } else {
    grid.append(el('div.card', {}, [el('div.kicker', { text: 'statut' }),
      el('h3', { text: 'backend injoignable' }),
      el('div.muted', { style: 'font-size:.78rem', text: 'Le LXC torrent ne répond pas sur cette box.' })]));
  }

  // Library list (name · progress · kept/ephemeral).
  const listWrap = el('div', { style: 'margin-top:14px' });
  root.append(el('h3', { style: 'margin:16px 0 6px', text: 'Bibliothèque' }), listWrap);
  try {
    const rows = await api.get(`${base}/list`);
    if (Array.isArray(rows) && rows.length) {
      for (const r of rows) {
        const st = r.stats || {};
        const pct = Math.round((st.progress ?? (r.complete ? 1 : 0)) * 100);
        const tag = r.kept ? '📌 gardé'
          : (r.ephemeral_until ? '⏳ éphémère' : (r.complete ? '✓ complet' : '↓ en cours'));
        listWrap.append(el('div.card', { style: 'margin-bottom:8px' }, [
          el('div', { style: 'display:flex;justify-content:space-between;gap:10px' }, [
            el('strong', { style: 'font-size:.86rem;word-break:break-word', text: r.name || r.infohash || '—' }),
            el('span.badge', { text: tag }),
          ]),
          el('div.muted', { style: 'font-size:.76rem;margin-top:4px', text: `${pct}%${st.peers != null ? ' · ' + st.peers + ' pairs' : ''}` }),
        ]));
      }
    } else {
      listWrap.append(el('div.muted', { style: 'font-size:.82rem', text: 'Aucun torrent dans le SAS.' }));
    }
  } catch (e) {
    listWrap.append(el('div.muted', { style: 'font-size:.82rem', text: 'Liste indisponible (backend injoignable).' }));
  }

  root.append(el('div.row', { style: 'margin-top:14px' }, [
    el('a.btn', { href: 'https://torrent.gk2.secubox.in', target: '_blank', rel: 'noopener', text: '🧲 Ouvrir le SAS Torrent ↗' }),
  ]));
}
