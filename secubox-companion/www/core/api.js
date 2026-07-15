// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: core/api — generic box API client
//
// One client for ALL modules. Outbound-only HTTPS to the paired box with a
// bearer token. GETs are cached (read works offline); writes are sent when
// online and otherwise QUEUED and replayed on reconnect — every write still
// goes through the box's real, journalled endpoints (OPAD-safe, no bypass).

import { store } from './store.js';

let BASE = '';        // e.g. https://box.example.in
let TOKEN = '';
const listeners = new Set();

function emit() { for (const fn of listeners) try { fn(state()); } catch {} }
function state() { return { online: navigator.onLine, base: BASE }; }

export const api = {
  /** Bind the client to the unlocked credentials. */
  init({ url, token }) {
    BASE = (url || '').replace(/\/+$/, '');
    TOKEN = token || '';
  },
  isReady() { return !!BASE && !!TOKEN; },
  onChange(fn) { listeners.add(fn); return () => listeners.delete(fn); },

  headers(extra = {}) {
    const h = { 'Accept': 'application/json', ...extra };
    if (TOKEN) h['Authorization'] = 'Bearer ' + TOKEN;
    return h;
  },

  /** GET with cache fallback. `path` is absolute on the box (e.g. /api/v1/billets/feed). */
  async get(path, { cache = true } = {}) {
    const url = BASE + path;
    try {
      const r = await fetch(url, { headers: this.headers(), credentials: 'omit' });
      if (r.status === 401) throw new ApiError('unauthorized', 401);
      if (!r.ok) throw new ApiError(await safeText(r), r.status);
      const data = await r.json().catch(() => ({}));
      if (cache) store.cachePut('GET ' + path, data).catch(() => {});
      return data;
    } catch (e) {
      if (cache && isNetworkError(e)) {
        const cached = await store.cacheGet('GET ' + path);
        if (cached !== undefined) return { ...cached, __cached: true };
      }
      throw e;
    }
  },

  post(path, body, opt) { return this._write('POST', path, body, opt); },
  put(path, body, opt) { return this._write('PUT', path, body, opt); },
  del(path, opt) { return this._write('DELETE', path, null, opt); },

  /** Send a write, or queue it if offline / the network drops.
   *  Returns { queued:true, id } when deferred, otherwise the parsed response. */
  async _write(method, path, body, { form = false } = {}) {
    const send = async () => {
      const headers = form ? this.headers() : this.headers({ 'Content-Type': 'application/json' });
      const r = await fetch(BASE + path, {
        method, headers, credentials: 'omit',
        body: body == null ? undefined : (form ? body : JSON.stringify(body)),
      });
      if (r.status === 401) throw new ApiError('unauthorized', 401);
      if (!r.ok) throw new ApiError(await safeText(r), r.status);
      return r.json().catch(() => ({}));
    };
    if (navigator.onLine) {
      try { return await send(); }
      catch (e) {
        if (!isNetworkError(e)) throw e;   // real 4xx/5xx surface; only queue on network loss
      }
    }
    // offline (or the request never left) → queue for replay. Forms aren't queued.
    if (form) throw new ApiError('offline: uploads cannot be queued', 0);
    const id = await store.enqueue({ method, path, body });
    document.body.classList.add('has-queue');
    return { queued: true, id };
  },

  /** Replay every queued write in order. Called on reconnect / app resume. */
  async flush() {
    if (!navigator.onLine || !this.isReady()) return { sent: 0, failed: 0 };
    const ops = await store.queued();
    let sent = 0, failed = 0;
    for (const op of ops.sort((a, b) => a.ts - b.ts)) {
      try {
        const r = await fetch(BASE + op.path, {
          method: op.method, headers: this.headers({ 'Content-Type': 'application/json' }),
          credentials: 'omit', body: op.body == null ? undefined : JSON.stringify(op.body),
        });
        if (r.ok || (r.status >= 400 && r.status < 500)) { await store.dequeue(op.id); sent++; }
        else failed++;
      } catch { failed++; }   // network still flaky → keep it queued
    }
    if ((await store.queued()).length === 0) document.body.classList.remove('has-queue');
    return { sent, failed };
  },

  async queueSize() { return (await store.queued()).length; },
};

export class ApiError extends Error {
  constructor(msg, status) { super(msg); this.name = 'ApiError'; this.status = status; }
}
function isNetworkError(e) { return e instanceof TypeError || (e instanceof ApiError && e.status === 0); }
async function safeText(r) { try { return (await r.text()).slice(0, 300); } catch { return 'HTTP ' + r.status; } }

// keep the offline banner + auto-flush in sync
window.addEventListener('online', () => { document.body.classList.remove('offline'); api.flush().then(emit); });
window.addEventListener('offline', () => { document.body.classList.add('offline'); emit(); });
if (!navigator.onLine) document.body.classList.add('offline');
