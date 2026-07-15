// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: exposure — Punk Exposure (peek/poke/emancipate).
// Emancipate/revoke are outward-facing → confirm() before firing; the box
// journals every decision (OPAD).
export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, toast, clear, confirmAction } = ui;

  async function load() {
    const host = clear(root);
    host.append(el('p.muted', { text: 'Peeking at services…' }));
    try {
      const d = await api.get(`${base}/exposure`).catch(() => api.get(`${base}/services`)); // /api/v1/exposure/exposure (double-segment)
      const svcs = d.services || d.exposure || d.items || (Array.isArray(d) ? d : []);
      clear(host);
      if (d.__cached) host.append(el('div.badge.warn', { text: 'cached (offline)' }));
      if (!svcs.length) return host.append(el('div.empty', { text: 'No eligible services (only LAN/0.0.0.0 services are exposable).' }));
      for (const s of svcs) {
        const on = !!(s.exposed || s.tor || s.dns || s.mesh);
        host.append(el('div.item', {}, [
          el('div.meta', {}, [
            el('b', { text: `${esc(s.name || s.service)} :${s.port ?? '?'}` }),
            el('span', { text: [s.tor && 'Tor', s.dns && 'DNS', s.mesh && 'Mesh'].filter(Boolean).join(' · ') || (s.domain || 'not exposed') }),
          ]),
          el('div.actions', {}, [
            el(`button.btn.sm${on ? '.danger' : '.primary'}`, {
              text: on ? 'Revoke' : 'Emancipate',
              onclick: () => on ? act('revoke', s) : act('emancipate', s),
            }),
          ]),
        ]));
      }
    } catch (e) { clear(host).append(el('div.empty', { text: 'Failed: ' + esc(e.message) })); }
  }

  async function act(verb, s) {
    if (!confirmAction(`${verb} "${s.name || s.service}" (port ${s.port})? This changes the box's external exposure.`)) return;
    try {
      // TODO(api): confirm exact emancipate/revoke route + payload
      const r = await api.post(`${base}/${verb}`, { service: s.name || s.service, port: s.port, all: true });
      toast(r.queued ? `${verb} queued (offline)` : `${verb} ✓`);
      load();
    } catch (e) { toast(`${verb} failed: ` + e.message, 'err'); }
  }

  load();
}
