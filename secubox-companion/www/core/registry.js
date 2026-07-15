// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: core/registry — module discovery + lazy loading
//
// A Companion module is a self-contained folder under www/modules/<id>/ with:
//   - module.json  (manifest: id, name, module, icon, colour, api, capabilities)
//   - view.js      (default export: async mount(ctx) → renders into ctx.root)
// modules/index.json lists the ids to load. Adding a module = drop a folder +
// add its id to index.json; the core is never touched.

export const CANONICAL = ['AUTH', 'WALL', 'BOOT', 'MIND', 'ROOT', 'MESH'];
const order = (m) => { const i = CANONICAL.indexOf((m || '').toUpperCase()); return i < 0 ? 99 : i; };

const _mods = new Map();   // id → manifest
const _views = new Map();  // id → mount()

export const registry = {
  /** Load modules/index.json and every referenced manifest. */
  async discover(base = './modules') {
    let ids = [];
    try { ids = (await (await fetch(`${base}/index.json`, { cache: 'no-cache' })).json()).modules || []; }
    catch (e) { console.warn('[registry] no modules index', e); }
    await Promise.all(ids.map(async (id) => {
      try {
        const m = await (await fetch(`${base}/${id}/module.json`, { cache: 'no-cache' })).json();
        m.id = m.id || id;
        m.module = (m.module || 'MESH').toUpperCase();
        m._path = `${base}/${id}`;
        _mods.set(m.id, m);
      } catch (e) { console.warn(`[registry] module ${id} failed`, e); }
    }));
    return this.all();
  },

  all() {
    return [..._mods.values()].sort((a, b) =>
      order(a.module) - order(b.module) || (a.name || '').localeCompare(b.name || ''));
  },
  get(id) { return _mods.get(id); },

  /** Lazy-import a module's view (mount function), cached after first load. */
  async view(id) {
    if (_views.has(id)) return _views.get(id);
    const m = _mods.get(id);
    if (!m) throw new Error('unknown module: ' + id);
    const mod = await import(`${m._path}/view.js`);
    const mount = mod.default || mod.mount;
    if (typeof mount !== 'function') throw new Error(`module ${id} has no default mount()`);
    _views.set(id, mount);
    return mount;
  },
};
