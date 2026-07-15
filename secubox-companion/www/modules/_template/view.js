// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: module template
//
// A module exports a default async mount(ctx). ctx = {
//   root,        // HTMLElement to render into
//   api,         // core API client: api.get(path), api.post(path,body), .put, .del
//   module,      // this module's manifest (module.json)
//   ui,          // { el, esc, toast, ago, clear, confirmAction }
//   base,        // module.api_base convenience
//   navigate,    // (hash) => void   e.g. navigate('#/m/billets/edit/123')
// }
// Every write goes through the box's real endpoints and is auto-queued offline.

export default async function mount(ctx) {
  const { root, api, base, ui } = ctx;
  const { el, esc, toast } = ui;

  root.append(el('div.card', {}, [
    el('h3', { text: 'Overview' }),
    el('p.muted', { text: `This module talks to ${esc(base)} on the box.` }),
    el('button.btn.primary', {
      text: 'Ping status',
      onclick: async () => {
        try { const s = await api.get(base + '/health'); toast(JSON.stringify(s).slice(0, 80)); }
        catch (e) { toast(e.message, 'err'); }
      },
    }),
  ]));
}
