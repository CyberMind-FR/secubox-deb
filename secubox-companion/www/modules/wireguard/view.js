// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: wireguard — tunnels & peers (read).
export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, toast, ago, clear } = ui;

  const host = clear(root);
  host.append(el('p.muted', { text: 'Loading tunnels…' }));
  try {
    const s = await api.get(`${base}/status`);
    const peers = await api.get(`${base}/peers`).catch(() => ({ peers: [] })); // TODO(api): confirm peers route
    clear(host);
    host.append(el('div.card', {}, [
      el('h3', { text: 'Status' }),
      el('div.mono-sm', { text: `interface: ${esc(s.interface || s.iface || '—')} · peers: ${(peers.peers || []).length}` }),
    ]));
    const list = peers.peers || peers.items || [];
    if (!list.length) return host.append(el('div.empty', { text: 'No peers (or peers API not exposed — TODO(api)).' }));
    for (const p of list) {
      const hs = p.latest_handshake || p.handshake;
      const online = hs && (Date.now() - (typeof hs === 'number' ? hs * 1000 : Date.parse(hs))) < 180000;
      host.append(el('div.item', {}, [
        el('div.meta', {}, [
          el('b', { text: p.name || p.public_key?.slice(0, 16) || 'peer' }),
          el('span', { text: `${esc(p.endpoint || p.allowed_ips || '')} · ↑${fmt(p.tx_bytes || p.transfer_tx)} ↓${fmt(p.rx_bytes || p.transfer_rx)}` }),
        ]),
        el('span.badge' + (online ? '.ok' : ''), { text: hs ? ago(typeof hs === 'number' ? hs * 1000 : hs) : 'never' }),
      ]));
    }
  } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) })); }

  function fmt(b) { b = +b || 0; const u = ['B', 'K', 'M', 'G']; let i = 0; while (b >= 1024 && i < 3) { b /= 1024; i++; } return b.toFixed(i ? 1 : 0) + u[i]; }
}
